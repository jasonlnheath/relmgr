"""Context feature REMOVED from UI + routes per Jason ruling 2026-09-12.

What's gone: 'Add category' form, per-grant 'Context…/Set' dropdown and
badge on the owner dashboard; the /owner/{token}/categorize and
/owner/{token}/context routes (404 now — dead endpoints beat dormant ones).

What stays (intentional): DB columns + whitelist_db context functions and
their unit tests — no migration churn, historical data intact. If Jason
ever wants categories back it's UI work only.
"""

import os
import sys
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import wl_tokens
import whitelist_db
from fastapi.testclient import TestClient

from app import create_app


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "emails": [{"address": "j@w.com", "visibility": "public"}],
    })
    conn.close()
    return db


def _token(db):
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", "owner")


def test_dashboard_has_no_context_ui(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    gid = whitelist_db.create_grant(conn, 1, "x@y.com", "X")
    whitelist_db.set_grant_context(conn, gid, "sales-prospect")  # data exists in DB
    conn.close()
    client = TestClient(create_app(db))
    page = client.get(f"/owner/{_token(db)}").text
    assert "categorize" not in page.lower(), "context UI must be gone from dashboard"
    assert "add category" not in page.lower()
    assert "New context category" not in page
    # historical badge must NOT render even though the DB has one
    assert "sales-prospect" not in page


def test_context_routes_are_gone(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    gid = whitelist_db.create_grant(conn, 1, "x@y.com", "X")
    conn.close()
    from fastapi.testclient import TestClient
    client = TestClient(create_app(db))
    tok = _token(db)
    r1 = client.post(f"/owner/{tok}/categorize", data={"grant_id": gid, "category": "media"})
    assert r1.status_code == 404, f"/categorize must be gone, got {r1.status_code}"
    r2 = client.post(f"/owner/{tok}/context", data={"category": "fleet-client"})
    assert r2.status_code == 404, f"/context must be gone, got {r2.status_code}"


def test_dashboard_still_works_without_context(tmp_path):
    """The dashboard must not crash rendering grants with/without context values."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    gid1 = whitelist_db.create_grant(conn, 1, "plain@y.com", "Plain")
    gid2 = whitelist_db.create_grant(conn, 1, "ctx@y.com", "Ctx")
    whitelist_db.set_grant_context(conn, gid2, "vendor")
    whitelist_db.apply_decision(conn, gid2, "approve", "lifetime")
    conn.close()
    from fastapi.testclient import TestClient
    client = TestClient(create_app(db))
    resp = client.get(f"/owner/{_token(db)}")
    assert resp.status_code == 200
    assert "plain@y.com" in resp.text and "ctx@y.com" in resp.text
    assert "Permanent" in resp.text or "permanent" in resp.text.lower()  # status badge still renders
