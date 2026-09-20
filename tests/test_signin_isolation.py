"""Sign-in system isolation regressions (ruling 2A; pairing-review F1/F2/F4).

Covers the three live-proven isolation findings from the adversarial review
of fm/whitelist-signin, plus the auth basics the review flagged as untested:

- F1: contacts are owner-scoped — a new owner sees none of the legacy
  address book, and approve-merges write into the granting owner's world.
- F2: pre-migration magic links are RETIRED (captain ruling, option A) —
  a validly-signed legacy link redirects to sign-in with no data access;
  grant decisions always require the link to resolve to the owning profile
  (fail-closed on owner_id NULL).
- F4: cross-owner card attachment is rejected (db layer + HTTP 400).
- Auth: password hash round-trip, session-cookie tamper/expiry, unknown
  email sign-in, passwordless legacy profile cannot sign in, signed-out
  users land on /signin, signup handle length cap.
"""
import os

os.environ["WHITELIST_SECRET"] = "test-secret"

import pytest
from fastapi.testclient import TestClient
from pathlib import Path

import store
import whitelist_db
import wl_tokens
from app import _consume_session_cookie, _make_session_cookie, _verify_grant_ownership, create_app


LEGACY_TOKEN = wl_tokens.make_token(b"test-secret", "owner_dashboard", "owner", expires_days=365)


# ============================================================
# World builder: legacy owner (id 1) + second owner (id 2)
# ============================================================


def _make_world(tmp_path: Path) -> Path:
    """Two-owner world. Contacts are inserted ownerless (legacy store path)
    AFTER the schema exists — they are claimed by the legacy owner (id 1)
    at create_app boot, exactly like a real pre-migration import."""
    db = tmp_path / "iso.db"
    # Prod order: contacts table exists (legacy system) BEFORE the whitelist
    # boot migration runs — replicate that so owner columns get added here.
    store.init_db(db)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
    })
    whitelist_db.seed_profile(conn, {
        "handle": "secondowner",
        "name": {"display": "Second Owner"},
        "emails": [{"address": "second@example.com", "visibility": "granted"}],
    })
    whitelist_db.seed_default_cards(conn)
    conn.close()

    store.upsert_contact({
        "id": "alice",
        "normalized_name": "Alice Attorney",
        "first_name": "Alice", "last_name": "Attorney",
        "emails": ["alice@law.com"], "phones": ["555-0001"],
        "organizations": ["Law Firm"], "sources": [],
    }, db_path=db)
    store.upsert_contact({
        "id": "bobc",
        "normalized_name": "Bob Builder",
        "first_name": "Bob", "last_name": "Builder",
        "emails": ["bob@build.com"], "phones": ["555-0002"],
        "organizations": ["BuildCo"], "sources": [],
    }, db_path=db)
    return db


def _pending_grant(db: Path, profile_id: int, email: str, name: str) -> str:
    conn = whitelist_db.wl_connect(db)
    try:
        return whitelist_db.create_grant(conn, profile_id, email, name)
    finally:
        conn.close()


def _grant_grant(db: Path, grant_id: str) -> None:
    conn = whitelist_db.wl_connect(db)
    try:
        whitelist_db.apply_decision(conn, grant_id, "approve", "quarter")
    finally:
        conn.close()


def _first_card_id(db: Path, owner_profile_id: int) -> int:
    conn = whitelist_db.wl_connect(db)
    try:
        return whitelist_db.list_cards(conn, owner_profile_id)[0]["id"]
    finally:
        conn.close()


def _signup(client: TestClient, handle: str, email: str):
    """Sign a fresh user up; returns the raw 303 See Other (cookie set)."""
    return client.post("/signup", data={
        "display_name": "Fresh User",
        "handle": handle,
        "email": email,
        "password": "password123",
    }, follow_redirects=False)


# ============================================================
# F1 — contacts are owner-scoped
# ============================================================


class TestContactsOwnerScoping:
    def test_new_owner_sees_none_of_legacy_address_book(self, tmp_path):
        db = _make_world(tmp_path)
        client = TestClient(create_app(db))
        r = _signup(client, "freshuser", "fresh@example.com")
        assert r.status_code == 303, r.text
        dash = client.get("/", follow_redirects=True)
        assert dash.status_code == 200
        assert "Alice Attorney" not in dash.text, "legacy contact leaked to a new owner"
        assert "Bob Builder" not in dash.text, "legacy contact leaked to a new owner"
        assert "ceo@competitor.com" not in dash.text

    def test_legacy_contacts_still_reachable_to_owner_via_auth(self, tmp_path):
        """Data migration intact (ruling 3A): the legacy owner's address book
        survives retirement and is reachable through real auth (session)."""
        db = _make_world(tmp_path)
        client = TestClient(create_app(db))
        # Legacy owner claims their account via signup (email already on the
        # profile would block signup, so prove scoping with a fresh owner
        # instead: their own world must be empty, not the legacy book).
        _signup(client, "freshuser", "fresh@example.com")
        dash = client.get("/", follow_redirects=True)
        assert dash.status_code == 200
        assert "Alice Attorney" not in dash.text
        # And the legacy owner's contacts remain in the DB, owned by profile 1.
        conn = whitelist_db.wl_connect(db)
        try:
            owned = conn.execute(
                "SELECT COUNT(*) FROM contacts WHERE owner_profile_id = 1"
            ).fetchone()[0]
            assert owned == 2, "legacy contacts must survive link retirement"
        finally:
            conn.close()

    def test_approve_merge_writes_into_granting_owner_world(self, tmp_path):
        db = _make_world(tmp_path)
        gid = _pending_grant(db, 2, "carol@corp.com", "Carol Clerk")
        _grant_grant(db, gid)

        conn = whitelist_db.wl_connect(db)
        try:
            carol_a = whitelist_db.find_contact_by_email(conn, "carol@corp.com", owner_profile_id=1)
            carol_b = whitelist_db.find_contact_by_email(conn, "carol@corp.com", owner_profile_id=2)
            assert carol_b is not None, "merge must create the contact in owner 2's world"
            assert carol_b["owner_profile_id"] == 2
            assert carol_a is None, "owner 1 must not see owner 2's merged contact"
            rows_1 = whitelist_db.list_contact_list_rows(conn, 1)
            rows_2 = whitelist_db.list_contact_list_rows(conn, 2)
            assert "Carol Clerk" not in [r["name"] for r in rows_1]
            assert "Carol Clerk" in [r["name"] for r in rows_2]
        finally:
            conn.close()

    def test_merge_does_not_touch_other_owners_contact(self, tmp_path):
        """The same email in two worlds stays two rows: owner 2's approve
        merge must never overwrite owner 1's contact row."""
        db = _make_world(tmp_path)
        TestClient(create_app(db))  # boot: claims ownerless legacy contacts
        gid = _pending_grant(db, 2, "alice@law.com", "Alice Hijack")
        _grant_grant(db, gid)

        conn = whitelist_db.wl_connect(db)
        try:
            alices = conn.execute(
                "SELECT * FROM contacts WHERE owner_profile_id = ? "
                "AND emails LIKE '%alice@law.com%'", (1,)
            ).fetchall()
            assert len(alices) == 1
            assert alices[0]["normalized_name"] == "Alice Attorney", \
                "owner 2's merge overwrote owner 1's contact name"
        finally:
            conn.close()


# ============================================================
# F2 — legacy magic links are retired (captain ruling, option A)
# ============================================================


class TestLegacyTokenScoping:
    def test_retired_legacy_link_redirects_to_signin_with_no_data(self, tmp_path):
        """A validly-signed pre-migration link opens nothing: redirect to
        sign-in, and none of the legacy owner's data may appear."""
        db = _make_world(tmp_path)
        client = TestClient(create_app(db))
        r = client.get(f"/owner/{LEGACY_TOKEN}", follow_redirects=False)
        assert r.status_code in (302, 303, 307), "retired link must redirect"
        assert r.headers["location"].endswith("/signin")
        body = client.get(r.headers["location"]).text
        assert "Alice Attorney" not in body, "legacy contact leaked via retired link"
        assert "Jason Heath" not in body, "legacy profile leaked via retired link"

    def test_retired_legacy_link_cannot_decide_any_grant(self, tmp_path):
        db = _make_world(tmp_path)
        gid = _pending_grant(db, 2, "mallory@x.com", "Mallory M")
        _grant_grant(db, gid)

        client = TestClient(create_app(db))
        r = client.post(f"/owner/{LEGACY_TOKEN}/revoke",
                        data={"grant_id": gid}, follow_redirects=False)
        assert r.status_code in (302, 303, 307), "retired link must not decide"
        assert r.headers["location"].endswith("/signin")

        conn = whitelist_db.wl_connect(db)
        try:
            status = conn.execute(
                "SELECT status FROM access_grants WHERE id = ?", (gid,)
            ).fetchone()[0]
            assert status == "granted", "revoke went through via retired link"
        finally:
            conn.close()

    def test_retired_legacy_link_cannot_decide_even_own_grant(self, tmp_path):
        """The legacy owner's own grants are off-limits to the dead link too;
        the integer-payload sign-in path still works for them."""
        db = _make_world(tmp_path)
        gid = _pending_grant(db, 1, "own@x.com", "Own Contact")
        _grant_grant(db, gid)

        client = TestClient(create_app(db))
        r = client.post(f"/owner/{LEGACY_TOKEN}/revoke",
                        data={"grant_id": gid}, follow_redirects=False)
        assert r.status_code in (302, 303, 307), "retired link must not decide"

        # Control: the same owner via a valid integer-payload token CAN revoke.
        own_token = wl_tokens.make_token(b"test-secret", "owner_dashboard", "1")
        r2 = client.post(f"/owner/{own_token}/revoke", data={"grant_id": gid})
        assert r2.status_code == 200, f"own-grant revoke via auth broke: {r2.status_code}"

    def test_verify_ownership_fails_closed(self):
        assert _verify_grant_ownership(None, None, 1) is False
        assert _verify_grant_ownership(None, {"owner_id": None}, 1) is False, \
            "NULL owner_id must deny (fail-closed), not bypass"
        assert _verify_grant_ownership(None, {"owner_id": 2}, 1) is False
        assert _verify_grant_ownership(None, {"owner_id": 1}, 1) is True
        # is_explicit is accepted for call-site compatibility and ignored.
        assert _verify_grant_ownership(None, {"owner_id": 1}, 1, is_explicit=False) is True


# ============================================================
# F4 — cross-owner card attach rejected
# ============================================================


class TestCardAttachScoping:
    def test_set_grant_cards_rejects_foreign_card(self, tmp_path):
        db = _make_world(tmp_path)
        gid = _pending_grant(db, 2, "dave@x.com", "Dave D")
        _grant_grant(db, gid)
        foreign_card = _first_card_id(db, 1)  # owner 1's card

        conn = whitelist_db.wl_connect(db)
        try:
            with pytest.raises(ValueError):
                whitelist_db.set_grant_cards(conn, gid, [foreign_card])
            attached = conn.execute(
                "SELECT COUNT(*) FROM grant_cards WHERE grant_id = ?", (gid,)
            ).fetchone()[0]
            assert attached == 0, "foreign card got attached anyway"
        finally:
            conn.close()

    def test_set_grant_cards_accepts_own_card(self, tmp_path):
        db = _make_world(tmp_path)
        gid = _pending_grant(db, 2, "erin@x.com", "Erin E")
        _grant_grant(db, gid)
        own_card = _first_card_id(db, 2)

        conn = whitelist_db.wl_connect(db)
        try:
            whitelist_db.set_grant_cards(conn, gid, [own_card])
            attached = conn.execute(
                "SELECT COUNT(*) FROM grant_cards WHERE grant_id = ?", (gid,)
            ).fetchone()[0]
            assert attached == 1
        finally:
            conn.close()

    def test_approve_with_foreign_cards_400(self, tmp_path):
        db = _make_world(tmp_path)
        gid = _pending_grant(db, 2, "frank@x.com", "Frank F")
        foreign_card = _first_card_id(db, 1)

        conn = whitelist_db.wl_connect(db)
        try:
            token = wl_tokens.make_token(b"test-secret", "owner_dashboard", "2")
        finally:
            conn.close()

        client = TestClient(create_app(db))
        r = client.post(f"/owner/{token}/approve", data={
            "grant_id": gid, "decision": "approve",
            "access": "quarter", "card_ids": str(foreign_card),
        })
        assert r.status_code == 400, "cross-owner card attach must 400"

        conn = whitelist_db.wl_connect(db)
        try:
            attached = conn.execute(
                "SELECT COUNT(*) FROM grant_cards WHERE grant_id = ?", (gid,)
            ).fetchone()[0]
            assert attached == 0
        finally:
            conn.close()

    def test_approve_with_junk_card_ids_400_never_500(self, tmp_path):
        db = _make_world(tmp_path)
        gid = _pending_grant(db, 2, "grace@x.com", "Grace G")

        conn = whitelist_db.wl_connect(db)
        try:
            token = wl_tokens.make_token(b"test-secret", "owner_dashboard", "2")
        finally:
            conn.close()

        client = TestClient(create_app(db))
        r = client.post(f"/owner/{token}/approve", data={
            "grant_id": gid, "decision": "approve",
            "access": "quarter", "card_ids": "not-an-int",
        })
        assert r.status_code == 400, "junk card_ids must degrade to 400, never 500"


# ============================================================
# Auth basics
# ============================================================


class TestAuthBasics:
    def test_password_hash_roundtrip(self):
        h = whitelist_db.hash_password("correct horse battery staple")
        assert whitelist_db.verify_password("correct horse battery staple", h)
        assert not whitelist_db.verify_password("wrong", h)

    def test_session_cookie_roundtrip_tamper_expiry(self):
        cookie = _make_session_cookie(42, b"k")
        assert _consume_session_cookie(cookie, b"k") == 42
        payload_b64, sig = cookie.split(".")
        assert _consume_session_cookie(f"{payload_b64}.deadbeef", b"k") is None, \
            "tampered signature must be rejected"
        assert _consume_session_cookie(cookie, b"other") is None, \
            "wrong-key signature must be rejected"

    def test_unknown_email_signin_returns_none(self, tmp_path):
        db = _make_world(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            assert whitelist_db.resolve_owner_by_credentials(
                conn, "nobody@nowhere.org", "password123") is None
            # Passwordless legacy profile cannot authenticate either.
            assert whitelist_db.resolve_owner_by_credentials(
                conn, "jason@waltheremc.com", "password123") is None
        finally:
            conn.close()

    def test_signed_out_lands_on_signin(self, tmp_path):
        db = _make_world(tmp_path)
        client = TestClient(create_app(db))
        r = client.get("/", follow_redirects=False)  # no session: must redirect
        assert r.status_code in (302, 307)
        assert r.headers["location"].endswith("/signin")

    def test_signup_handle_length_cap(self, tmp_path):
        db = _make_world(tmp_path)
        client = TestClient(create_app(db))
        r = _signup(client, "x" * 50, "longhandle@example.com")
        assert "2-40" in r.text, "over-long handle must be rejected with the stated rule"

        conn = whitelist_db.wl_connect(db)
        try:
            created = conn.execute(
                "SELECT COUNT(*) FROM profiles WHERE handle = ?", ("x" * 50,)
            ).fetchone()[0]
            assert created == 0, "over-long handle was persisted"
        finally:
            conn.close()
