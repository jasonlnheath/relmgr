"""Tests for the request → approve/deny access grant loop."""

import os
os.environ["WHITELIST_SECRET"] = "test-secret"

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
import wl_tokens
import wl_env

import whitelist_db
from app import create_app


def _make_db(tmp_path: Path):
    """Create a fresh DB with whitelist tables and a seeded profile."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    data = {
        "handle": "testuser",
        "name": {"display": "Test User"},
        "org": {"company": "TestCo", "title": "CTO"},
        "emails": [
            {"address": "test@testco.com", "visibility": "public"},
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


def test_post_request_creates_pending_grant(tmp_path: Path):
    """POST /p/{handle}/request inserts a pending access_grant row."""
    db = _make_db(tmp_path)
    app = create_app(db)
    client = TestClient(app)

    resp = client.post("/p/testuser/request", data={
        "name": "Requester",
        "email": "requester@example.com",
    })
    assert resp.status_code == 200
    html = resp.text
    assert "Request Sent" in html

    # Verify grant is pending in DB
    conn = whitelist_db.wl_connect(db)
    try:
        grants = conn.execute(
            "SELECT * FROM access_grants WHERE requester_email='requester@example.com'"
        ).fetchall()
        assert len(grants) == 1
        assert grants[0]["status"] == "pending"
        assert grants[0]["requester_name"] == "Requester"
    finally:
        conn.close()


def test_approve_flips_to_granted(tmp_path: Path):
    """Approving a grant → status='granted', full view available."""
    db = _make_db(tmp_path)

    # Create a pending grant
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    grant_id = whitelist_db.create_grant(conn, profile["id"], "requester@example.com", "Requester")
    conn.close()

    # Create a token for this grant
    secret = b"test-secret"
    token = wl_tokens.make_token(secret, "grant_review", grant_id, expires_days=7)

    app = create_app(db)
    client = TestClient(app)

    # Visit admin review page
    resp = client.get(f"/a/{token}")
    assert resp.status_code == 200

    # Approve
    resp = client.post(f"/a/{token}/decision", data={"decision": "approve", "expiry": "90"})
    assert resp.status_code == 200
    assert "Approved" in resp.text

    # Verify grant is now granted
    conn = whitelist_db.wl_connect(db)
    grant = conn.execute("SELECT * FROM access_grants WHERE id=?", (grant_id,)).fetchone()
    assert grant["status"] == "granted"
    conn.close()

    # Now the requester should see all fields
    resp = client.get("/p/testuser?e=requester@example.com")
    assert resp.status_code == 200
    html = resp.text
    assert "private@testco.com" in html
    assert "+15551234567" in html


def test_deny_leaves_anonymous(tmp_path: Path):
    """Denying a grant → status='denied', viewer remains anonymous."""
    db = _make_db(tmp_path)

    # Create a pending grant, then deny it
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    grant_id = whitelist_db.create_grant(conn, profile["id"], "denier@example.com", "Denier")
    conn.close()

    secret = b"test-secret"
    token = wl_tokens.make_token(secret, "grant_review", grant_id, expires_days=7)

    app = create_app(db)
    client = TestClient(app)

    # Deny
    resp = client.post(f"/a/{token}/decision", data={"decision": "deny"})
    assert resp.status_code == 200
    assert "BlackListed" in resp.text

    # Verify grant is denied
    conn = whitelist_db.wl_connect(db)
    grant = conn.execute("SELECT * FROM access_grants WHERE id=?", (grant_id,)).fetchone()
    assert grant["status"] == "denied"
    conn.close()

    # Denier should see only public-facing content (F3 heal: legacy public
    # emails are 'granted' now; the public view pins on the company line).
    resp = client.get("/p/testuser?e=denier@example.com")
    assert resp.status_code == 200
    html = resp.text
    assert "private@testco.com" not in html
    assert "+15551234567" not in html
    assert "TestCo" in html
