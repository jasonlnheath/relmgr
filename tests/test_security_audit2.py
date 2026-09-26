"""Security audit 2 regression tests (2026-09-26, branch
fm/whitelist-security-audit-2) — one pin per fixed finding:

A1  GET /p/{handle}?e=… and /s/{bundle}?e=… write scan_events rows on
    surfaces the POST-only rate limiter never covers; the stored viewer
    email is now capped at _SCAN_EMAIL_MAX (320 = RFC max email length),
    so an unauthenticated GET can no longer park arbitrary-length junk in
    the DB at network speed.
A2  get_profiles_needing_verification interpolated ``days`` into SQL via
    f-string (constant callers only — not exploitable, but
    injection-shaped). Now bound as a datetime(?) parameter; int()
    coercion also rejects non-numeric input loudly.
A3  FastAPI's default /docs, /redoc and /openapi.json served the full
    route map to unauthenticated visitors — disabled at create_app.
A4  forward_card minted grants with owner_id = the profile itself, so a
    forward on a CURATED stub profile's public page produced a pending
    request the creating owner could see but never decide (every
    /owner/{token} decision route 404'd it). forward now carries the
    profile's owning account, exactly like the request path.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("WHITELIST_SECRET", "test-secret")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient

from app import create_app


SECRET = b"test-secret"


def _token(pid, days=7):
    return wl_tokens.make_token(SECRET, "owner_dashboard", str(pid),
                                expires_days=days)


def _make_db(tmp_path):
    db = tmp_path / "sec2.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.ensure_whitelist_schema(conn)
    conn.close()
    return db


def _setup_two_owners(tmp_path):
    """alice (profile 1) + mallory (profile 2), both with cards."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.create_owner_profile(
        conn, "alice", "Alice Owner", "alice@victim.example", "pw-alice-123")
    whitelist_db.create_owner_profile(
        conn, "mallory", "Mallory Attacker", "mallory@attacker.example",
        "pw-mallory-123")
    whitelist_db.seed_default_cards(conn)
    conn.close()
    return db


# ============================================================
# A1 — scan-event writes are bounded on unthrottled GET surfaces
# ============================================================

def test_a1_scan_email_capped_on_profile_view(tmp_path):
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    junk = "x" * 5000
    r = client.get(f"/p/alice?e={junk}")
    assert r.status_code == 200
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT LENGTH(viewer_email) AS n FROM scan_events "
        "ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert row["n"] == whitelist_db._SCAN_EMAIL_MAX, \
        "an oversized ?e= must be truncated before it reaches scan_events"


def test_a1_scan_email_stored_verbatim_under_the_cap(tmp_path):
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    who = "contact@example.com"
    assert client.get(f"/p/alice?e={who}").status_code == 200
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT viewer_email FROM scan_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert row["viewer_email"] == who, \
        "legitimate tracking emails must keep landing verbatim"


def test_a1_scan_email_capped_on_share_view(tmp_path):
    db = _setup_two_owners(tmp_path)
    conn = whitelist_db.wl_connect(db)
    cards = whitelist_db.list_cards(conn, 1)
    bundle = whitelist_db.create_share_bundle(conn, 1, [cards[0]["id"]])
    conn.close()
    client = TestClient(create_app(db))
    junk = "y" * 5000
    assert client.get(f"/s/{bundle['id']}?e={junk}").status_code == 200
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT LENGTH(viewer_email) AS n FROM scan_events "
        "ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert row["n"] == whitelist_db._SCAN_EMAIL_MAX


# ============================================================
# A2 — get_profiles_needing_verification is parameterized
# ============================================================

def test_a2_needing_verification_bound_parameter(tmp_path):
    db = _setup_two_owners(tmp_path)
    conn = whitelist_db.wl_connect(db)
    # Backdate profile 1's verified_at 30 days so the -0/-10/-90 boundaries
    # are deterministic (datetime('now') is second-granularity; a fresh
    # stamp could tie the comparison).
    conn.execute(
        "UPDATE profiles SET verified_at = datetime('now', '-30 days') "
        "WHERE id = 1")
    conn.commit()
    caught_0 = whitelist_db.get_profiles_needing_verification(conn, days=0)
    caught_90 = whitelist_db.get_profiles_needing_verification(conn, days=90)
    caught_10 = whitelist_db.get_profiles_needing_verification(conn, days=10)
    conn.close()
    assert any(p["id"] == 1 for p in caught_0), \
        "days=0 must catch a 30-day-old stamp (parameter reaches SQL)"
    assert any(p["id"] == 1 for p in caught_10), \
        "days=10 must catch a 30-day-old stamp"
    assert not any(p["id"] == 1 for p in caught_90), \
        "days=90 must not catch a 30-day-old stamp"


def test_a2_needing_verification_rejects_junk_days(tmp_path):
    db = _setup_two_owners(tmp_path)
    conn = whitelist_db.wl_connect(db)
    try:
        whitelist_db.get_profiles_needing_verification(conn, days="90; DROP TABLE profiles--")
        assert False, "a non-numeric days must raise, not reach SQL"
    except (ValueError, TypeError):
        pass
    conn.close()
    conn = whitelist_db.wl_connect(db)
    n = conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
    conn.close()
    assert n > 0, "the table must still exist after a junk-days attempt"


# ============================================================
# A3 — API docs surface is off
# ============================================================

def test_a3_docs_openapi_redoc_disabled(tmp_path):
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))
    for url in ("/docs", "/redoc", "/openapi.json"):
        r = client.get(url, follow_redirects=False)
        assert r.status_code == 404, f"{url} must not be served"


# ============================================================
# A4 — forwards on a curated stub are decidable by the creating owner
# ============================================================

def _stub_with_granted_forwarder(db):
    """alice creates stub 'Bob Stub'; a granted contact of the STUB's
    public page forwards a card — the minted grant must belong to alice."""
    conn = whitelist_db.wl_connect(db)
    stub = whitelist_db.create_contact_vcard(conn, 1, "Bob Stub",
                                             email="bob@stub.example")
    gid = whitelist_db.create_grant(conn, stub["id"], "friend@x.com", "Friend")
    whitelist_db.apply_decision(conn, gid, "approve", "lifetime",
                                merge_contacts=False)
    fwd_gid = whitelist_db.forward_card(
        conn, stub["id"], "friend@x.com", "Friend",
        "newperson@x.com", "New Person",
        owner_id=stub.get("owner_id") or stub["id"])
    conn.close()
    return stub, fwd_gid


def test_a4_forward_on_stub_grant_is_owner_scoped(tmp_path):
    db = _setup_two_owners(tmp_path)
    stub, fwd_gid = _stub_with_granted_forwarder(db)
    conn = whitelist_db.wl_connect(db)
    grant = whitelist_db.get_grant(conn, fwd_gid)
    conn.close()
    assert grant["owner_id"] == 1, \
        "a forward on alice's stub must mint a grant owned by ALICE"
    assert grant["status"] == "pending"


def test_a4_forward_on_stub_decidable_by_creating_owner(tmp_path):
    db = _setup_two_owners(tmp_path)
    stub, fwd_gid = _stub_with_granted_forwarder(db)
    client = TestClient(create_app(db))
    # alice decides the forwarded request from her dashboard → 200.
    r = client.post(f"/owner/{_token(1)}/decision",
                    data={"grant_id": fwd_gid, "decision": "approve",
                          "expiry": "quarter"})
    assert r.status_code == 200, \
        "the creating owner must be able to decide a stub forward"
    # mallory still cannot touch it (cross-owner IDOR stays shut).
    r2 = client.post(f"/owner/{_token(2)}/decision",
                     data={"grant_id": fwd_gid, "decision": "deny"})
    assert r2.status_code == 404


def test_a4_forward_route_passes_profile_owner(tmp_path):
    """The HTTP forward route itself must stamp the owning account —
    exercise POST /p/{stub handle}/forward as a granted contact."""
    db = _setup_two_owners(tmp_path)
    conn = whitelist_db.wl_connect(db)
    stub = whitelist_db.create_contact_vcard(conn, 1, "Bob Stub",
                                             email="bob@stub.example")
    gid = whitelist_db.create_grant(conn, stub["id"], "friend@x.com", "Friend")
    whitelist_db.apply_decision(conn, gid, "approve", "lifetime",
                                merge_contacts=False)
    conn.close()
    client = TestClient(create_app(db))
    r = client.post(f"/p/{stub['handle']}/forward", data={
        "forwarder_email": "friend@x.com",
        "recipient_email": "newperson@x.com",
        "recipient_name": "New Person",
    })
    assert r.status_code == 200
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT owner_id FROM access_grants "
        "WHERE requester_email = 'newperson@x.com'").fetchone()
    conn.close()
    assert row is not None and row["owner_id"] == 1, \
        "the route must pass the stub's owning account into forward_card"
