"""Amber-box redesign (2026-09-26, captain ruling) — regression pins.

The dashboard's amber Requests box and the emailed /a/{token} review page
carry the SAME three-way decision:

1. WhiteList / GreyList / BlackList replace Approve/Deny.
2. The requester's bio shows on the request row when they have a profile
   with a bio; name + email remain the fallback.
3. BlackList acts INSTANTLY through the badge machinery (set_badge_state
   'blocked'): the requester joins the contact list under the round black
   badge, the pending request resolves, and everything stays SILENT — a
   re-request is quarantined with an indistinguishable success page.
4. WhiteList/GreyList open the choose-cards modal (dashboard) / checkbox
   rows (review page); 'Done' approves at the chosen list with EXACTLY
   the selected cards and lands back on the list (return_to=list).
   WhiteList = lifetime access, GreyList = the quarter marker.
5. At least one card is required for White/Grey; none for BlackList.
"""
import os
import sys
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app
from whitelist_db import (
    create_grant,
    find_contact_by_email,
    find_requester_profile,
    get_grant,
    is_grey,
    quarter_end_iso,
    wl_connect,
)

SECRET = b"test-secret"


def _make_db(tmp_path: Path, with_contacts: bool = False):
    db = tmp_path / "test.db"
    conn = wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "5551234567", "visibility": "granted"}],
    })
    whitelist_db.ensure_whitelist_schema(conn)  # seeds Personal+Work cards
    conn.commit()
    conn.close()
    if with_contacts:
        import store
        store.init_db(db)
    return db


def _owner_token(payload="1"):
    return wl_tokens.make_token(SECRET, "owner_dashboard", payload,
                                expires_days=365)


def _card_id(db: Path, name: str, owner: int = 1) -> int:
    conn = wl_connect(db)
    row = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = ? AND name = ?",
        (owner, name)).fetchone()
    conn.close()
    assert row is not None, f"card {name} missing"
    return row["id"]


def _add_profile_with_bio(conn, handle: str, name: str, email: str,
                          bio: str | None) -> int:
    """A profile with an email field, optionally carrying a bio."""
    conn.execute(
        "INSERT INTO profiles (handle, display_name, bio) VALUES (?, ?, ?)",
        (handle, name, bio))
    pid = conn.execute(
        "SELECT id FROM profiles WHERE handle = ?", (handle,)).fetchone()[0]
    conn.execute(
        "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)"
        " VALUES (?, 'email', ?, 'private')", (pid, email))
    conn.commit()
    return pid


# ============================================================
# 1. Requester bio on the amber request row
# ============================================================

class TestRequesterBio:
    def test_bio_shown_when_requester_has_profile(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        _add_profile_with_bio(conn, " requester ", "Rita Requester",
                              "rita@x.com", "We met at the Lakeside fair.")
        create_grant(conn, 1, "rita@x.com", "Rita Requester")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert "We met at the Lakeside fair." in html, \
            "the requester's bio introduces them on the request row"
        assert "Rita Requester" in html and "rita@x.com" in html

    def test_fallback_when_requester_has_no_profile(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        create_grant(conn, 1, "ghost@x.com", "Ghost Walker")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert "Ghost Walker" in html and "ghost@x.com" in html, \
            "graceful fallback: name + email"

    def test_empty_bio_treated_as_no_bio(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        _add_profile_with_bio(conn, "emptybio", "Nemo Nome", "nemo@x.com",
                              "   ")
        create_grant(conn, 1, "nemo@x.com", "Nemo Nome")
        conn.close()
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}")
        assert resp.status_code == 200


# ============================================================
# 2. Three actions replace approve/deny in the amber box
# ============================================================

class TestAmberBoxActions:
    def test_three_actions_render(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        create_grant(conn, 1, "trio@x.com", "Trio User")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert 'value="blacklist"' in html
        for label in ("WhiteList", "GreyList", "BlackList"):
            assert label in html
        assert 'value="deny"' not in html, "deny is retired here"
        assert "Choose cards to share" in html, "the modal ships with the box"
        assert 'data-cards-open' in html


# ============================================================
# 3. BlackList: instant, silent, joins the list under the black badge
# ============================================================

class TestBlackListDecision:
    def test_blacklist_resolves_pending_via_badge_machinery(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "bad@x.com", "Bad Actor")
        conn.close()
        client = TestClient(create_app(db))
        resp = client.post(
            f"/owner/{_owner_token()}/decision",
            data={"grant_id": gid, "decision": "blacklist",
                  "return_to": "list"},
            follow_redirects=False)
        assert resp.status_code == 303, "that's it — land back on the list"

        conn = wl_connect(db)
        grant = get_grant(conn, gid)
        conn.close()
        assert grant["status"] == "revoked", "blacklisted == revoked (one state)"

        html = client.get(f"/owner/{_owner_token()}").text
        assert "Bad Actor" in html, "they join the contact list"
        assert "var(--wl-amber-field)" not in html, \
            "the pending request is resolved (no amber box left)"
        assert "badge-blacklist.png" in html, "under the round black badge"

    def test_blacklist_is_silent_no_new_notification(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "silent@x.com", "Silent Sam")
        before = conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0]
        conn.close()
        client = TestClient(create_app(db))
        client.post(f"/owner/{_owner_token()}/decision",
                    data={"grant_id": gid, "decision": "blacklist"})
        conn = wl_connect(db)
        after = conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0]
        conn.close()
        assert after == before, "contacts are NEVER notified (silence rule)"

    def test_blacklisted_sender_rerequest_quarantined(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "again@x.com", "Repeat Offender")
        conn.close()
        client = TestClient(create_app(db))
        client.post(f"/owner/{_owner_token()}/decision",
                    data={"grant_id": gid, "decision": "blacklist"})
        resp = client.post("/p/jasonheath/request",
                           data={"name": "Repeat Offender",
                                 "email": "again@x.com"})
        assert resp.status_code == 200, "indistinguishable success page"
        conn = wl_connect(db)
        quarantined = conn.execute(
            "SELECT * FROM quarantined_requests WHERE email = 'again@x.com'"
        ).fetchall()
        grants = conn.execute(
            "SELECT * FROM access_grants WHERE requester_email = 'again@x.com'"
        ).fetchall()
        conn.close()
        assert len(quarantined) == 1, "re-request silently quarantined"
        assert len(grants) == 1, "no new pending grant"

    def test_blacklist_renders_outcome_page_without_return_to(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "page@x.com", "Page User")
        conn.close()
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/decision",
                           data={"grant_id": gid, "decision": "blacklist"})
        assert resp.status_code == 200
        assert "BlackListed" in resp.text


# ============================================================
# 4. WhiteList/GreyList: modal flow — approve with EXACTLY the cards
# ============================================================

class TestModalCardFlow:
    def test_whitelist_creates_lifetime_grant_with_cards(self, tmp_path):
        db = _make_db(tmp_path, with_contacts=True)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "white@x.com", "White User")
        conn.close()
        personal = _card_id(db, "Personal")
        client = TestClient(create_app(db))
        resp = client.post(
            f"/owner/{_owner_token()}/approve",
            data={"grant_id": gid, "decision": "approve",
                  "access": "lifetime", "card_ids": [personal],
                  "return_to": "list"},
            follow_redirects=False)
        assert resp.status_code == 303, "Done lands back on the list"

        conn = wl_connect(db)
        grant = get_grant(conn, gid)
        cards = [r["card_id"] for r in conn.execute(
            "SELECT card_id FROM grant_cards WHERE grant_id = ?", (gid,))]
        contact = find_contact_by_email(conn, "white@x.com",
                                        owner_profile_id=1)
        conn.close()
        assert grant["status"] == "granted"
        assert grant["expires_at"] is None, "WhiteList = lifetime"
        assert cards == [personal], "EXACTLY the selected cards"
        assert contact is not None, "whitelisted requesters are contacts"

    def test_greylist_creates_quarter_marker_grant_with_cards(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "grey@x.com", "Grey User")
        conn.close()
        work = _card_id(db, "Work")
        personal = _card_id(db, "Personal")
        client = TestClient(create_app(db))
        resp = client.post(
            f"/owner/{_owner_token()}/approve",
            data={"grant_id": gid, "decision": "approve",
                  "access": "quarter", "card_ids": [work, personal],
                  "return_to": "list"},
            follow_redirects=False)
        assert resp.status_code == 303

        conn = wl_connect(db)
        grant = get_grant(conn, gid)
        cards = sorted(r["card_id"] for r in conn.execute(
            "SELECT card_id FROM grant_cards WHERE grant_id = ?", (gid,)))
        conn.close()
        assert grant["status"] == "granted"
        assert grant["expires_at"] == quarter_end_iso(), \
            "grey keeps its quarter-marker semantics"
        assert is_grey(grant), "future marker is the grey STATE"
        assert cards == sorted([work, personal])

    def test_card_selection_required_for_modal_flow(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "nocards@x.com", "No Cards User")
        conn.close()
        client = TestClient(create_app(db))
        resp = client.post(
            f"/owner/{_owner_token()}/approve",
            data={"grant_id": gid, "decision": "approve",
                  "access": "lifetime", "return_to": "list"})
        assert resp.status_code == 400, "at least one card is required"
        conn = wl_connect(db)
        assert get_grant(conn, gid)["status"] == "pending"
        conn.close()

    def test_foreign_card_rejected(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "other@x.com", "Other User")
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('fo', 'Fo')")
        fo_id = conn.execute(
            "SELECT id FROM profiles WHERE handle = 'fo'").fetchone()[0]
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name) VALUES (?, 'Fo card')",
            (fo_id,))
        foreign_card = conn.execute(
            "SELECT id FROM cards WHERE name = 'Fo card'").fetchone()[0]
        conn.commit()
        conn.close()
        client = TestClient(create_app(db))
        resp = client.post(
            f"/owner/{_owner_token()}/approve",
            data={"grant_id": gid, "decision": "approve",
                  "access": "lifetime", "card_ids": [foreign_card],
                  "return_to": "list"})
        assert resp.status_code == 400, "ruling 2A: foreign cards rejected"
        conn = wl_connect(db)
        attached = conn.execute(
            "SELECT card_id FROM grant_cards WHERE grant_id = ?",
            (gid,)).fetchall()
        conn.close()
        assert attached == [], "the foreign card was never attached"

    def test_legacy_approve_without_return_to_renders_outcome(self, tmp_path):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        gid = create_grant(conn, 1, "legacy@x.com", "Legacy User")
        conn.close()
        personal = _card_id(db, "Personal")
        client = TestClient(create_app(db))
        resp = client.post(
            f"/owner/{_owner_token()}/approve",
            data={"grant_id": gid, "decision": "approve",
                  "access": "lifetime", "card_ids": [personal]})
        assert resp.status_code == 200, "old flow keeps its outcome page"


# ============================================================
# 5. The emailed /a/{token} review page: same three-way decision
# ============================================================

class TestReviewPage:
    def _client_with_grant(self, tmp_path, email="review@x.com",
                           name="Review User", requester_bio=None):
        db = _make_db(tmp_path)
        conn = wl_connect(db)
        if requester_bio is not None:
            _add_profile_with_bio(conn, "revreq", name, email, requester_bio)
        gid = create_grant(conn, 1, email, name)
        conn.close()
        client = TestClient(create_app(db))
        token = wl_tokens.make_token(SECRET, "grant_review", gid,
                                     expires_days=7)
        return client, db, gid, token

    def test_review_page_renders_trio_and_cards(self, tmp_path):
        client, db, gid, token = self._client_with_grant(tmp_path)
        resp = client.get(f"/a/{token}")
        assert resp.status_code == 200
        html = resp.text
        for value in ("whitelist", "greylist", "blacklist"):
            assert f'value="{value}"' in html
        assert 'name="card_ids"' in html, "checkbox card selection"
        assert "Personal" in html and "Work" in html, "ALL the owner's cards"
        assert 'name="expiry"' not in html, "the expiry select is retired"

    def test_review_page_shows_requester_bio(self, tmp_path):
        client, db, gid, token = self._client_with_grant(
            tmp_path, requester_bio="Old rowing friend.")
        html = client.get(f"/a/{token}").text
        assert "Old rowing friend." in html

    def test_review_whitelist_with_cards(self, tmp_path):
        client, db, gid, token = self._client_with_grant(tmp_path)
        work = _card_id(db, "Work")
        resp = client.post(f"/a/{token}/decision",
                           data={"decision": "whitelist",
                                 "card_ids": [work]})
        assert resp.status_code == 200
        conn = wl_connect(db)
        grant = get_grant(conn, gid)
        cards = [r["card_id"] for r in conn.execute(
            "SELECT card_id FROM grant_cards WHERE grant_id = ?", (gid,))]
        conn.close()
        assert grant["status"] == "granted"
        assert grant["expires_at"] is None
        assert cards == [work]

    def test_review_greylist_with_cards(self, tmp_path):
        client, db, gid, token = self._client_with_grant(tmp_path)
        personal = _card_id(db, "Personal")
        resp = client.post(f"/a/{token}/decision",
                           data={"decision": "greylist",
                                 "card_ids": [personal]})
        assert resp.status_code == 200
        conn = wl_connect(db)
        grant = get_grant(conn, gid)
        conn.close()
        assert grant["status"] == "granted"
        assert grant["expires_at"] == quarter_end_iso()
        assert is_grey(grant)

    def test_review_whitelist_requires_cards(self, tmp_path):
        client, db, gid, token = self._client_with_grant(tmp_path)
        resp = client.post(f"/a/{token}/decision",
                           data={"decision": "whitelist"})
        assert resp.status_code == 400
        conn = wl_connect(db)
        assert get_grant(conn, gid)["status"] == "pending"
        conn.close()

    def test_review_blacklist_without_cards(self, tmp_path):
        client, db, gid, token = self._client_with_grant(tmp_path)
        resp = client.post(f"/a/{token}/decision",
                           data={"decision": "blacklist"})
        assert resp.status_code == 200
        assert "BlackListed" in resp.text
        conn = wl_connect(db)
        grant = get_grant(conn, gid)
        conn.close()
        assert grant["status"] == "revoked", "silent badge machinery"

    def test_review_legacy_approve_deny_still_work(self, tmp_path):
        """Old emailed links / digest flows: approve+expiry without cards."""
        client, db, gid, token = self._client_with_grant(tmp_path)
        resp = client.post(f"/a/{token}/decision",
                           data={"decision": "approve", "expiry": "90"})
        assert resp.status_code == 200
        conn = wl_connect(db)
        grant = get_grant(conn, gid)
        conn.close()
        assert grant["status"] == "granted"
        assert grant["expires_at"] is not None, "90d expiry untouched"


# ============================================================
# 6. Data layer: find_requester_profile
# ============================================================

class TestFindRequesterProfile:
    def test_matches_by_email_case_insensitive(self, tmp_path):
        db = tmp_path / "t.db"
        conn = wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        _add_profile_with_bio(conn, "cap", "Cap owner", "Cap@X.com",
                              "I own things.")
        found = find_requester_profile(conn, "cap@x.com")
        conn.close()
        assert found is not None
        assert found["display_name"] == "Cap owner"

    def test_prefers_profile_with_bio(self, tmp_path):
        db = tmp_path / "t.db"
        conn = wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        _add_profile_with_bio(conn, "plain", "Plain", "shared@x.com", None)
        _add_profile_with_bio(conn, "writer", "Writer", "shared@x.com",
                              "The bio one.")
        found = find_requester_profile(conn, "shared@x.com")
        conn.close()
        assert found is not None
        assert found["display_name"] == "Writer"

    def test_none_on_unknown_or_blank_email(self, tmp_path):
        db = tmp_path / "t.db"
        conn = wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        assert find_requester_profile(conn, "nobody@x.com") is None
        assert find_requester_profile(conn, "   ") is None
        assert find_requester_profile(conn, "") is None
        conn.close()
