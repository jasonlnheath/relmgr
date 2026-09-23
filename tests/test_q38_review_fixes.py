"""Q38 review pass (2026-09-12) — bugs pinned RED against the post-JEMMA-REVIEW build.

Bugs found by reading app.py routes + templates (each class pins one bug):

R1. `_my_profile_html()` extraction was INCOMPLETE. The builder serves only
    GET /profile and POST /bio, but /cards/new, /cards/{id}/fields,
    /fields/new and /cards/{id}/photo each still hand-fork their own copy of
    the ~40-line render block — exactly the duplication class that caused bug
    #5. Consequence over HTTP: after ANY of those POSTs the header loses its
    scan stats again AND the duplicate-card-name error never renders
    (`new_card_error` is passed by /cards/new but no other route passes it —
    it silently drops).

R2. Bio over-limit contradicts B2 spec ("over-limit rejected"): POST /bio
    truncates to 2000 and SAVES the truncated bio with a 200. Spec: reject,
    don't write.

R3. Duplicate card name must be a "friendly 400 page" (B2 AC #6).
    /cards/new returns 200 with an (unrendered) error string.

R4. `seed_default_cards` hard-codes `WHERE handle='jasonheath'`, so every
    other owner gets zero cards. Spec §A1/B2: "the page lists Work + Personal
    seeded by boot" — the My Profile page is a lie for anyone else (no cards
    to curate). Product decision confirmed 2026-09-12 by Jason: seed ALL
    owner profiles at boot.

R5. `/owner/{token}` crashes with uncaught ValueError on a junk `?page=abc`
    (int()). Un-pinned by any test; trivially user-reachable 500.
"""
import io
import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


def _make_db(tmp_path: Path) -> Path:
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "555-1234", "visibility": "granted"}],
    })
    whitelist_db.seed_default_cards(conn)
    conn.close()
    return db


def _tok(payload="1"):
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", payload, expires_days=365)


# ============================================================
# R1 — every My Profile render site keeps the header scan stats
# ============================================================

class TestRenderBuilderDedup:
    """The builder-extraction refactor must cover ALL five render sites."""

    def _client_with_scans(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        for _ in range(4):
            whitelist_db.record_scan(conn, 1, None)
        conn.close()
        return TestClient(create_app(db)), db

    def test_get_profile_has_stats(self, tmp_path):
        client, _ = self._client_with_scans(tmp_path)
        html = client.get(f"/owner/{_tok()}/profile").text
        assert "4 visits (last 14 days)" in html

    def test_bio_post_keeps_stats(self, tmp_path):
        client, _ = self._client_with_scans(tmp_path)
        html = client.post(f"/owner/{_tok()}/bio", data={"bio": "hi"}).text
        assert "4 visits (last 14 days)" in html

    def test_card_fields_post_keeps_stats(self, tmp_path):
        client, db = self._client_with_scans(tmp_path)
        conn = whitelist_db.wl_connect(db)
        card_id = conn.execute("SELECT id FROM cards WHERE owner_profile_id=1 LIMIT 1").fetchone()[0]
        fid = conn.execute("SELECT id FROM profile_fields WHERE profile_id=1 LIMIT 1").fetchone()[0]
        conn.close()
        resp = client.post(f"/owner/{_tok()}/cards/{card_id}/fields", data={"field_ids": [fid]})
        assert resp.status_code == 200
        assert "4 visits (last 14 days)" in resp.text

    def test_new_field_post_keeps_stats(self, tmp_path):
        client, _ = self._client_with_scans(tmp_path)
        resp = client.post(f"/owner/{_tok()}/fields/new",
                           data={"field_type": "email", "field_value": "new@x.com", "visibility": "public"})
        assert resp.status_code == 200
        assert "4 visits (last 14 days)" in resp.text

    def test_duplicate_card_name_error_renders(self, tmp_path):
        """new_card_error must actually reach the page after a dup POST."""
        client, _ = self._client_with_scans(tmp_path)
        resp = client.post(f"/owner/{_tok()}/cards/new", data={"name": "Work"})
        assert "already exists" in resp.text, "dup-card error silently dropped (forked render block)"


# ============================================================
# R2 — over-limit bio is REJECTED, not truncated-and-saved (B2)
# ============================================================

class TestBioOverLimitRejected:
    # UX pass 2 (2026-09-22): the bio cap is 500 (was 2000).
    def test_over_limit_bio_not_saved(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        long_bio = "x" * 501
        resp = client.post(f"/owner/{_tok()}/bio", data={"bio": long_bio})
        assert resp.status_code == 400, f"over-limit bio got {resp.status_code}, spec says 400"
        conn = whitelist_db.wl_connect(db)
        stored = conn.execute("SELECT bio FROM profiles WHERE id=1").fetchone()["bio"]
        conn.close()
        assert stored in (None, ""), f"over-limit bio was SAVED ({len(stored) or 0} chars); spec says reject"

    def test_over_limit_redrafts_typed_text(self, tmp_path):
        """The rejected draft must come back intact so the user can trim it."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        long_bio = "z" * 2500
        resp = client.post(f"/owner/{_tok()}/bio", data={"bio": long_bio})
        assert long_bio in resp.text

    def test_limit_boundary_ok(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        exact = "y" * 500
        resp = client.post(f"/owner/{_tok()}/bio", data={"bio": exact})
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        stored = conn.execute("SELECT bio FROM profiles WHERE id=1").fetchone()["bio"]
        conn.close()
        assert stored == exact

    def test_over_limit_shows_error(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_tok()}/bio", data={"bio": "x" * 501})
        assert "500" in resp.text


# ============================================================
# R3 — duplicate card name -> friendly 400 (B2 AC #6)
# ============================================================

class TestDuplicateCardNameStatus:
    def test_dup_name_is_400(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_tok()}/cards/new", data={"name": "Work"})
        assert resp.status_code == 400, f"dup card name got {resp.status_code}, spec wants 400 page"

    def test_new_card_name_still_200(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_tok()}/cards/new", data={"name": "Field Sales"})
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        row = conn.execute("SELECT id FROM cards WHERE owner_profile_id=1 AND name='Field Sales'").fetchone()
        conn.close()
        assert row is not None


# ============================================================
# R4 — seed_default_cards seeds ALL profiles (product ruling 2026-09-12)
# ============================================================

class TestSeedAllOwners:
    def test_second_owner_gets_default_cards(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        conn.execute("INSERT INTO profiles (handle, display_name, verified_at) VALUES ('otherco','Other Co','2026-09-01')")
        conn.execute("INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (2,'email','o@x.com','public')")
        conn.execute("INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (2,'phone','555-9999','granted')")
        whitelist_db.seed_default_cards(conn)
        names = [r["name"] for r in conn.execute(
            "SELECT name FROM cards WHERE owner_profile_id=2").fetchall()]
        work_emails = conn.execute(
            "SELECT cf.field_id FROM card_fields cf JOIN cards c ON cf.card_id=c.id "
            "WHERE c.owner_profile_id=2 AND c.name='Work'").fetchall()
        conn.close()
        assert sorted(names) == ["Contact", "Work"], f"second owner cards: {names}"
        assert len(work_emails) == 1

    def test_seed_is_idempotent_for_two_owners(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        conn.execute("INSERT INTO profiles (handle, display_name, verified_at) VALUES ('otherco','Other Co','2026-09-01')")
        conn.execute("INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (2,'email','o@x.com','public')")
        whitelist_db.seed_default_cards(conn)
        whitelist_db.seed_default_cards(conn)
        count = conn.execute("SELECT COUNT(*) c FROM cards WHERE owner_profile_id=2").fetchone()["c"]
        conn.close()
        assert count == 1, "seed not idempotent for profile 2"

    def test_no_profiles_no_cards(self, tmp_path):
        db = tmp_path / "empty.db"
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        conn.execute("DELETE FROM profiles")
        whitelist_db.seed_default_cards(conn)
        count = conn.execute("SELECT COUNT(*) c FROM cards").fetchone()["c"]
        conn.close()
        assert count == 0


# ============================================================
# R5 — junk pagination param must not 500
# ============================================================

class TestPaginationParamHardening:
    def test_junk_page_param_no_crash(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db), raise_server_exceptions=False)
        resp = client.get(f"/owner/{_tok()}?page=abc")
        assert resp.status_code == 200, f"junk ?page= gave {resp.status_code}"

    def test_negative_page_clamps(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db), raise_server_exceptions=False)
        resp = client.get(f"/owner/{_tok()}?page=-5")
        assert resp.status_code == 200
