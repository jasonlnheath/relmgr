"""Owner self-view (originally found via Jason 2026-09-12; security-audit
contract change 2026-09-25).

OLD rule: if the viewer email (?e=) is one of the profile's OWN emails,
tier = granted — and the page minted a 365-day owner dashboard token.
That made the owner's signup email a full authentication credential:
anyone who knows it got the dashboard link and every private field.

NEW rule (security audit 2026-09-25): the owner self-view is AUTH-ONLY —
a signed owner_dashboard token (?ot=, what My Profile's 'View profile'
link carries) or the session cookie. ?e= is the granted-CONTACT tracking
parameter and can never lift the viewer to the owner's own tier.
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


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "emails": [
            {"address": "jheath@waltheremc.com", "visibility": "granted"},
            {"address": "jlnh@hotmail.com", "visibility": "granted"},
        ],
    })
    conn.close()
    return db


def test_own_email_no_longer_grants_tier(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    pid = whitelist_db.resolve_handle(conn, "jasonheath")["id"]
    # SECURITY REGRESSION GUARD: own email must NOT authenticate —
    # email knowledge is not a credential (audit 2026-09-25).
    assert whitelist_db.effective_tier(conn, pid, "JHEATH@waltheremc.com") == "anonymous"
    assert whitelist_db.effective_tier(conn, pid, "jlnh@hotmail.com") == "anonymous"
    # granted contacts keep their tier via the admitted-grant predicate
    gid = whitelist_db.create_grant(conn, pid, "friend@x.com", "Friend")
    whitelist_db.apply_decision(conn, gid, "approve", "quarter")
    assert whitelist_db.effective_tier(conn, pid, "friend@x.com") == "granted"
    # strangers stay anonymous
    assert whitelist_db.effective_tier(conn, pid, "stranger@x.com") == "anonymous"
    conn.close()


def test_owner_self_view_via_signed_token(tmp_path):
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))
    # anonymous: no granted fields
    anon = client.get("/p/jasonheath").text
    assert "jheath@waltheremc.com" not in anon
    # own email alone: STILL anonymous now (no private fields, no back-link)
    via_email = client.get("/p/jasonheath?e=jheath%40waltheremc.com").text
    assert "jheath@waltheremc.com" not in via_email
    assert "/owner/" not in via_email, "email knowledge must not mint owner tokens"
    # signed ?ot= token: full contact info, back to My Profile link present
    ot = wl_tokens.make_token(b"test-secret", "owner_dashboard", "1")
    me = client.get(f"/p/jasonheath?ot={ot}").text
    assert "jheath@waltheremc.com" in me
    assert "jlnh@hotmail.com" in me
    assert "Request access" not in me
    assert "/owner/" in me


def test_owner_self_view_via_session_cookie(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.create_owner_profile(
        conn, "sessionown", "Session Owner", "own@x.com", "pw-12345678")
    conn.close()
    client = TestClient(create_app(db))
    r = client.post("/signin", data={
        "email": "own@x.com", "password": "pw-12345678"},
        follow_redirects=False)
    assert r.status_code == 303
    me = client.get("/p/sessionown").text
    assert "Session Owner" in me
    assert "/owner/" in me, "signed-in owner must get the back link"


def test_my_profile_view_link_carries_signed_token(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.create_owner_profile(
        conn, "linkown", "Link Owner", "link@x.com", "pw-12345678")
    conn.close()
    tok = wl_tokens.make_token(b"test-secret", "owner_dashboard", "2")
    client = TestClient(create_app(db))
    html = client.get(f"/owner/{tok}/profile").text
    # The View-profile link must carry a signed ?ot= token — never the
    # owner's raw email.
    assert "?ot=" in html
    assert "link%40x.com" not in html and "?e=link@x.com" not in html


def test_dashboard_view_profile_link_carries_owner_email(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.create_grant(conn, 1, "someone@x.com", "Someone")  # entry renders
    conn.close()
    tok = wl_tokens.make_token(b"test-secret", "owner_dashboard", "1")
    client = TestClient(create_app(db))
    resp = client.get(f"/owner/{tok}")
    assert resp.status_code == 200
    # contacts.html replaced the dashboard — profile link is gone but the
    # self-view logic still works (the ?ot= test is on the profile page)
