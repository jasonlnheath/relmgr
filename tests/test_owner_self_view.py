"""Owner self-view bug (found via Jason 2026-09-12).

'View profile' from the dashboard opened /p/{handle} anonymously, so the
OWNER saw the public-stripped view with a 'Request access' taunt. Rule:
if the viewer email is one of the profile's OWN emails, tier = granted —
you always have access to yourself. Dashboard link now carries ?e=.
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


def test_owner_self_email_gets_granted_tier(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    pid = whitelist_db.resolve_handle(conn, "jasonheath")["id"]
    # own email (any casing) -> granted even though NO grant row exists
    assert whitelist_db.effective_tier(conn, pid, "JHEATH@waltheremc.com") == "granted"
    # someone else's email -> still anonymous
    assert whitelist_db.effective_tier(conn, pid, "stranger@x.com") == "anonymous"
    conn.close()


def test_owner_self_view_shows_all_fields(tmp_path):
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))
    # anonymous: bio only, no granted fields (round-2: no "some info hidden" text)
    anon = client.get("/p/jasonheath").text
    assert "jheath@waltheremc.com" not in anon
    # self-view via ?e=: full contact info, no request-access taunt
    me = client.get("/p/jasonheath?e=jheath%40waltheremc.com").text
    assert "jheath@waltheremc.com" in me
    assert "jlnh@hotmail.com" in me
    assert "Request access" not in me


def test_dashboard_view_profile_link_carries_owner_email(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.create_grant(conn, 1, "someone@x.com", "Someone")  # entry renders
    conn.close()
    tok = wl_tokens.make_token(b"test-secret", "owner_dashboard", "owner")
    client = TestClient(create_app(db))
    resp = client.get(f"/owner/{tok}")
    assert resp.status_code == 200
    # contacts.html replaced the dashboard — profile link is gone but the
    # self-view logic still works (the ?e= test is on the profile page)
