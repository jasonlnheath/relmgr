"""Tests for tier logic and profile rendering in app.py."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import whitelist_db
from app import create_app


def _make_db(tmp_path: Path):
    """Create a fresh DB with whitelist tables and seed a profile."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    data = {
        "handle": "testuser",
        "name": {"display": "Test User"},
        "org": {"company": "TestCo", "title": "CTO"},
        "emails": [
            {"address": "public@testco.com", "visibility": "public"},
            {"address": "private@testco.com", "visibility": "connection"},
        ],
        "phones": [
            {"number": "+15551234567", "visibility": "holder"},
        ],
        "verified_at": "2026-09-10",
    }
    whitelist_db.seed_profile(conn, data)
    conn.close()
    return db


def _make_old_db(tmp_path: Path):
    """Create a DB with an old verified_at (>180 days)."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    data = {
        "handle": "olduser",
        "name": {"display": "Old User"},
        "org": {"company": "OldCo", "title": "CEO"},
        "emails": [
            {"address": "old@oldco.com", "visibility": "public"},
        ],
        "phones": [],
        "verified_at": "2025-01-01",  # >180 days ago
    }
    whitelist_db.seed_profile(conn, data)
    conn.close()
    return db


def test_anonymous_sees_public_only(tmp_path: Path):
    """Anonymous viewer (no ?e= param) sees only public fields."""
    db = _make_db(tmp_path)
    app = create_app(db)
    client = TestClient(app)
    resp = client.get("/p/testuser")
    assert resp.status_code == 200
    html = resp.text
    assert "public@testco.com" in html
    assert "private@testco.com" not in html
    assert "+15551234567" not in html


def test_granted_viewer_sees_all(tmp_path: Path):
    """A viewer with a granted access sees all fields."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    grant_id = whitelist_db.create_grant(
        conn, profile["id"], "viewer@example.com", "Viewer"
    )
    # Set the grant to granted with no expiry
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    whitelist_db.update_grant_status(conn, grant_id, "granted", granted_at=now, expires_at=None)
    conn.close()

    app = create_app(db)
    client = TestClient(app)
    resp = client.get("/p/testuser?e=viewer@example.com")
    assert resp.status_code == 200
    html = resp.text
    assert "private@testco.com" in html
    assert "+15551234567" in html
    assert "public@testco.com" in html


def test_expired_grant_renders_anonymous(tmp_path: Path):
    """A grey (lapsed quarter marker) grant KEEPS granted access.

    Superseded by the never-expire ruling (UX pass 2, 2026-09-22): a
    status='granted' grant never loses access — the lapsed marker only
    feeds the quarterly review prompt. This pin used to assert the viewer
    dropped to anonymous; it now pins the ruling: granted fields stay
    visible. Revoked/denied still render anonymous (see test_ux_pass2)."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    grant_id = whitelist_db.create_grant(
        conn, profile["id"], "expired@example.com", "Expired Viewer"
    )
    # Set a grant whose quarter marker lapsed 30+ days ago (grey cycle).
    old_date = "2026-08-01T00:00:00Z"
    whitelist_db.update_grant_status(
        conn, grant_id, "granted", granted_at=old_date, expires_at="2026-08-15T00:00:00Z"
    )
    conn.close()

    app = create_app(db)
    client = TestClient(app)
    resp = client.get("/p/testuser?e=expired@example.com")
    assert resp.status_code == 200
    html = resp.text
    assert "private@testco.com" in html, \
        "never-expire ruling: a lapsed-marker grey contact keeps granted view"
    assert "+15551234567" in html
    assert "public@testco.com" in html


def test_stale_marker_on_old_verification(tmp_path: Path):
    """A profile with verified_at >180 days shows stale marker."""
    db = _make_old_db(tmp_path)
    app = create_app(db)
    client = TestClient(app)
    resp = client.get("/p/olduser")
    assert resp.status_code == 200
    html = resp.text
    assert "stale" in html.lower() or "Stale" in html or "⚠" in html
