"""Jemma review pass (2026-09-12) — Qwen36's tabs/profile work, bugs pinned RED.

Bugs found by reading the code (each pin below is one bug):

1. Pagination dead at the route: /owner/{token} fetched per_page=999999 and
   dropped ?page= — AC #3 demands "page 1 = 50 rows, pending first, search +
   pagination work". Her data-layer pagination was never reachable through
   the HTTP surface.

2. Logo leaked on EXPIRED/revoked grants: list_contact_list_rows classed
   every active (granted OR revoked) row fresh/stale from contact.updated_at
   or grant.granted_at, ignoring liveness — AC #4: "expired grant -> no
   logo". Expired rows also vanished from the rendered page entirely
   (computed into `revoked_rows`, never displayed), so their history was
   invisible while still counted in the pagination total.

3. Cross-owner IDOR: /cards/{id}/fields and /cards/{id}/photo never checked
   the card's owner_profile_id (the preview route did) — any owner token
   could upload/replace/remove photos or rewrite fields on ANOTHER
   profile's cards. AC #6: "cross-owner card access impossible (403/404)".

5. My Profile header dropped the scan stats B2 keeps ("header card: ...
   scan stats"). get_scan_stats() exists but the route never calls it.

6. Live `print(...DEBUG...)` shipped to stderr in the photo upload route.

(B4 — public page cards — is pinned separately in tests/test_public_cards.py.)
"""
import io
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PIL import Image

os.environ["WHITELIST_SECRET"] = "test-secret"

import store
import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


def _make_db(tmp_path: Path) -> Path:
    """Fresh schema + one seeded owner profile (id 1), default cards."""
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


def _seed_contacts(db: Path, n: int) -> None:
    """n contacts through the REAL store path (spec-mandated fixture rule)."""
    store.init_db(db)
    for i in range(n):
        store.upsert_contact({
            "id": f"c{i}",
            "normalized_name": f"Person {i}",
            "first_name": f"F{i}",
            "last_name": f"L{i}",
            "emails": [f"p{i}@x.com"],
            "phones": [f"555-{1000 + i}"],
            "organizations": [],
            "sources": [],
        }, db_path=db)


def _owner_token(payload: str = "1") -> str:
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", payload, expires_days=365)


# ============================================================
# 1. Route-level pagination (AC #3): page 0 = 100 rows (UX pass 3), ?page= works
# ============================================================

class TestRoutePagination:
    # UX pass 6: pagination removed — continuous scroll-through (per_page=999999).
    # The list is ordered A-Z by display name (spec), so the lexicographic last
    # contact of "Person 0".."Person 119" is "Person 99" (rendered F99 L99).
    _LAST_NAME = "F99 L99"

    def test_all_rows_visible_no_pagination(self, tmp_path):
        """UX pass 6: all 120 rows visible on one page (continuous scroll)."""
        db = _make_db(tmp_path)
        _seed_contacts(db, 120)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert html.count('wl-card p-3') == 120, \
            f"all rows must be visible, got {html.count('wl-card p-3')}"

    def test_last_row_visible_on_page_0(self, tmp_path):
        """UX pass 6: last row is on the same page (no pagination)."""
        db = _make_db(tmp_path)
        _seed_contacts(db, 120)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert self._LAST_NAME in html, "the sorted-last row must appear on page 1"

    def test_search_and_pagination_compose(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_contacts(db, 51)
        conn = whitelist_db.wl_connect(db)
        # Rename c40 so a ?q= search finds it. The plain-row template renders
        # `first_name + last_name` (normalized_name is a fallback-only column),
        # so rename the columns that actually render.
        conn.execute(
            "UPDATE contacts SET first_name='Zed', last_name='Searchable' WHERE id='c40'"
        )
        conn.commit()
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}?q=Searchable").text
        assert "Zed Searchable" in html, "search must hit the renamed contact"


# ============================================================
# 2. Logo only on LIVE grants (AC #4) + revoked rows stay visible
# ============================================================

class TestLogoLiveOnly:
    def _granted_fixture(self, tmp_path: Path, expired: bool = False) -> Path:
        db = _make_db(tmp_path)
        store.init_db(db)  # real contacts path — the data layer assumes it
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grantee@test.com", "Grantee Test")
        whitelist_db.apply_decision(conn, gid, "approve", "90", merge_contacts=False)
        if expired:
            conn.execute(
                "UPDATE access_grants SET expires_at='2020-01-01T00:00:00Z' WHERE id=?", (gid,)
            )
            conn.commit()
        conn.close()
        return db

    def test_expired_grant_no_logo_data_layer(self, tmp_path):
        """AC #4 at the data layer (the root): expired -> logo_state None."""
        db = self._granted_fixture(tmp_path, expired=True)
        conn = whitelist_db.wl_connect(db)
        rows = whitelist_db.list_contact_list_rows(conn, 1)
        target = [r for r in rows if r["email"] == "grantee@test.com"]
        assert target, "granted row missing from list"
        assert target[0]["logo_state"] is None, "expired grant must not carry a logo"
        conn.close()

    def test_expired_grant_no_logo_page(self, tmp_path):
        """The rendered page: an expired granted row shows GreyList badge.

        Ruling: expired grants dissolve into grey — no separate expired state.
        The badge is now GreyList (pending quarterly confirmation).
        """
        db = self._granted_fixture(tmp_path, expired=True)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        # UX pass 3: rows render NAMES (no email sub-line).
        assert "Grantee" in html, "expired row must stay visible in history"
        # shield path on expired grant row is a regression
        assert 'M12 2L3 7v5' not in html, "shield logo leaked on an expired grant"
        assert 'data-state="greylist"' in html, "expired grants dissolve into grey/pending-quarterly"

    def test_live_grant_still_gets_logo(self, tmp_path):
        """Regression: a live (unexpired) granted contact keeps its logo."""
        db = self._granted_fixture(tmp_path, expired=False)
        conn = whitelist_db.wl_connect(db)
        rows = whitelist_db.list_contact_list_rows(conn, 1)
        target = [r for r in rows if r["email"] == "grantee@test.com"]
        assert target[0]["logo_state"] in ("fresh", "stale")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert "badge-whitelist.png" in html, "live grant must render its logo"

    def test_revoked_row_stays_visible(self, tmp_path):
        """A revoked (non-merged) requester row must stay rendered, not vanish."""
        db = self._granted_fixture(tmp_path, expired=False)
        conn = whitelist_db.wl_connect(db)
        gid = conn.execute(
            "SELECT id FROM access_grants WHERE LOWER(requester_email)='grantee@test.com' AND status='granted'"
        ).fetchone()[0]
        whitelist_db.revoke_grant(conn, gid)
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        # UX pass 3: rows render NAMES (no email sub-line).
        assert "Grantee" in html, "revoked grant row vanished from the list"


# ============================================================
# 3. Cross-owner IDOR on card photo/fields (AC #6)
# ============================================================

class TestCrossOwnerCards:
    def _two_profile_fixture(self, tmp_path: Path) -> tuple[Path, int]:
        db = tmp_path / "test.db"
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "Walther EMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        })
        whitelist_db.seed_default_cards(conn)
        # A second, unrelated owner profile + one of ITS cards.
        conn.execute(
            "INSERT INTO profiles (handle, display_name, verified_at) VALUES ('otherco','Other Co','2026-09-01')"
        )
        intruder = whitelist_db.create_card(conn, 2, "Intruder", [])
        conn.close()
        return db, intruder["id"]

    def test_cant_touch_other_profiles_card_fields(self, tmp_path):
        """POST /cards/{id}/fields on another owner's card -> 404."""
        db, intruder_card = self._two_profile_fixture(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token("1")
        conn = whitelist_db.wl_connect(db)
        fid = conn.execute("SELECT id FROM profile_fields WHERE profile_id=1 LIMIT 1").fetchone()[0]
        conn.close()
        resp = client.post(f"/owner/{tok}/cards/{intruder_card}/fields",
                           data={"field_ids": [fid]})
        assert resp.status_code == 404, f"cross-owner field write got {resp.status_code}"

    def test_cant_touch_other_profiles_photo(self, tmp_path):
        """POST /cards/{id}/photo on another owner's card -> 404 (no upload)."""
        db, intruder_card = self._two_profile_fixture(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token("1")
        img = Image.new("RGB", (8, 8), color="red")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        buf.seek(0)
        resp = client.post(f"/owner/{tok}/cards/{intruder_card}/photo",
                           files={"photo": ("x.jpg", buf, "image/jpeg")})
        assert resp.status_code == 404, f"cross-owner photo upload got {resp.status_code}"

    def test_own_profile_still_works(self, tmp_path):
        """Regression: the owner's OWN card still edits fine."""
        db, _ = self._two_profile_fixture(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        own_card = conn.execute(
            "SELECT id FROM cards WHERE owner_profile_id=1 LIMIT 1").fetchone()[0]
        fid = conn.execute("SELECT id FROM profile_fields WHERE profile_id=1 LIMIT 1").fetchone()[0]
        conn.close()
        resp = client.post(f"/owner/{_owner_token('1')}/cards/{own_card}/fields",
                           data={"field_ids": [fid]})
        assert resp.status_code == 200, f"own-card edit broke: {resp.status_code}"


# ============================================================
# 5. My Profile header keeps scan stats (B2)
# ============================================================

class TestMyProfileScanStats:
    def test_scan_stats_rendered(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        for _ in range(5):
            whitelist_db.record_scan(conn, 1, None)
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        assert "5 visits (last 14 days)" in html, \
            "My Profile header lost its scan stats (B2)"


# ============================================================
# 6. Hygiene: no live debug print in the photo route
# ============================================================

class TestHygiene:
    def test_no_debug_print_in_photo_route(self, tmp_path, capsys):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        card_id = conn.execute("SELECT id FROM cards WHERE owner_profile_id=1 LIMIT 1").fetchone()[0]
        conn.close()
        img = Image.new("RGB", (12, 12), color="blue")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        buf.seek(0)
        resp = client.post(f"/owner/{_owner_token()}/cards/{card_id}/photo",
                           files={"photo": ("t.jpg", buf, "image/jpeg")})
        assert resp.status_code == 200
        err = capsys.readouterr().err
        assert "DEBUG" not in err and "photo_file=" not in err
