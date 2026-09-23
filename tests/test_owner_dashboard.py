"""Tests for the owner dashboard (approve list) — P2-T1.

TDD vertical slices: RED→GREEN per test.
"""

import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import wl_tokens
import whitelist_db
from app import create_app
from fastapi.testclient import TestClient


def _make_db(tmp_path: Path):
    """Create a fresh DB with whitelist tables and seed two profiles."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)

    # Profile 1 (the one being requested)
    whitelist_db.seed_profile(conn, {
        "handle": "dana_reyes",
        "name": {"display": "Dana Reyes"},
        "org": {"company": "Northgate Freight", "title": "VP Logistics"},
        "emails": [
            {"address": "dana.reyes@northgatefreight.com", "visibility": "public"},
            {"address": "dana.r@northgatefreight.com", "visibility": "connection"},
        ],
        "phones": [{"number": "+131****1234", "visibility": "holder"}],
        "verified_at": "2026-09-01",
    })

    # Profile 2 (another profile, also with a pending request)
    whitelist_db.seed_profile(conn, {
        "handle": "marcus_chen",
        "name": {"display": "Marcus Chen"},
        "org": {"company": "Pacific Shield Insurance", "title": "Risk Manager"},
        "emails": [
            {"address": "mchen@pacificshield.com", "visibility": "holder"},
        ],
        "phones": [{"number": "+141****9876", "visibility": "connection"}],
        "verified_at": "2026-08-15",
    })

    # Create pending grants for dana (the owner a legacy dashboard link
    # opens). Ruling 2A: the dashboard shows THIS owner's world only, so all
    # asserted requesters must be dana's; marcus's requester is asserted
    # ABSENT below (cross-owner isolation).
    dana = whitelist_db.get_profile(conn, "dana_reyes")
    whitelist_db.create_grant(conn, dana["id"], "requester1@example.com", "Requester One")
    whitelist_db.create_grant(conn, dana["id"], "requester2@example.com", "Requester Two")

    # marcus's pending request lives in HIS world — never dana's dashboard.
    marcus = whitelist_db.get_profile(conn, "marcus_chen")
    whitelist_db.create_grant(conn, marcus["id"], "foreign@example.com", "Foreign Requester")

    conn.close()
    return db


def _owner_token():
    """Generate a valid owner_dashboard token (365-day expiry)."""
    secret = b"test-secret"
    return wl_tokens.make_token(secret, "owner_dashboard", "1", expires_days=365)


def _expired_owner_token():
    """Generate an expired owner_dashboard token."""
    secret = b"test-secret"
    return wl_tokens.make_token(secret, "owner_dashboard", "1", expires_days=-1)


def _tampered_token():
    """Return a mangled token string."""
    return _owner_token() + "x"


# ============================================================
# Test 1: Valid owner token renders pending requester email + name
# ============================================================
def test_valid_owner_token_shows_pending_requesters(tmp_path):
    """GET /owner/<token> renders the dashboard with pending requester names and emails."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))

    resp = client.get(f"/owner/{_owner_token()}")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:500]}"
    html = resp.text

    # Must show the pending requester names
    assert "Requester One" in html, "Dashboard must show pending requester name"
    assert "requester1@example.com" in html, "Dashboard must show pending requester email"
    assert "Requester Two" in html, "Dashboard must show all pending requesters"
    assert "requester2@example.com" in html

    # Ruling 2A: another profile's pending requesters must NOT leak in.
    assert "Foreign Requester" not in html, "cross-owner pending grant leaked"
    assert "foreign@example.com" not in html, "cross-owner pending grant leaked"


# ============================================================
# Test 2: Tampered or expired owner token → 403
# ============================================================
def test_tampered_owner_token_returns_403(tmp_path):
    """A tampered owner token must return 403."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))

    resp = client.get(f"/owner/{_tampered_token()}")
    assert resp.status_code == 403, f"Expected 403 for tampered token, got {resp.status_code}"


def test_expired_owner_token_returns_403(tmp_path):
    """An expired owner token must return 403."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))

    resp = client.get(f"/owner/{_expired_owner_token()}")
    assert resp.status_code == 403, f"Expected 403 for expired token, got {resp.status_code}"


# ============================================================
# Test 3: Approve flips grant to granted with real ISO Z timestamp
# ============================================================
def test_approve_via_dashboard_stores_iso_timestamp(tmp_path):
    """Approving via dashboard must store a real ISO-8601 Z timestamp, not '90d'."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))

    # Get the dashboard to find the grant_id from the page
    resp = client.get(f"/owner/{_owner_token()}")
    assert resp.status_code == 200
    html = resp.text

    # The dashboard should include the grant_id in the form — we need to extract it
    # For now, assert the page renders with form elements
    assert "form" in html.lower() or "Approve" in html or "approve" in html.lower()

    # We'll use the DB directly to get the grant_id, then POST the decision
    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")
    grants = whitelist_db.get_pending_grants_for_profile(conn, dana["id"])
    conn.close()

    assert len(grants) > 0, "Must have at least one pending grant"
    grant_id = grants[0]["id"]

    # POST the decision via the dashboard endpoint
    resp = client.post(f"/owner/{_owner_token()}/decision", data={
        "grant_id": grant_id,
        "decision": "approve",
        "expiry": "14",
    })
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:500]}"

    # Verify expires_at is a real ISO timestamp
    conn = whitelist_db.wl_connect(db)
    grant = whitelist_db.get_grant(conn, grant_id)
    conn.close()

    assert grant is not None, "Grant must exist"
    expires_at = grant["expires_at"]
    assert expires_at is not None, "expires_at must be set"
    assert expires_at != "90d", "Must NOT store literal '90d'"
    assert expires_at != "14d", "Must NOT store literal '14d'"

    # Must parse as ISO-8601
    parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None, "Must have timezone info"

    # Must be ~14 days in the future
    delta_days = (parsed - datetime.now(timezone.utc)).days
    assert 13 <= delta_days <= 15, f"Expected ~14d, got {delta_days}d: {expires_at}"


# ============================================================
# Test 4: effective_tier returns 'granted' after approve
# ============================================================
def test_approve_via_dashboard_grants_access(tmp_path):
    """After approving via dashboard, effective_tier must return 'granted'."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))

    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")
    grants = whitelist_db.get_pending_grants_for_profile(conn, dana["id"])
    grant_id = grants[0]["id"]
    requester_email = grants[0]["requester_email"]
    conn.close()

    # Approve via dashboard
    resp = client.post(f"/owner/{_owner_token()}/decision", data={
        "grant_id": grant_id,
        "decision": "approve",
        "expiry": "90",
    })
    assert resp.status_code == 200

    # Now the requester should see private fields
    resp = client.get(f"/p/dana_reyes?e={requester_email}")
    assert resp.status_code == 200
    html = resp.text
    assert "dana.r@northgatefreight.com" in html, "Private email must be visible after approval"
    assert "+131****1234" in html, "Private phone must be visible after approval"


# ============================================================
# Test 5: Deny via dashboard leaves tier anonymous
# ============================================================
def test_deny_via_dashboard_leaves_anonymous(tmp_path):
    """Denying via dashboard must leave the requester anonymous."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))

    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")
    grants = whitelist_db.get_pending_grants_for_profile(conn, dana["id"])
    grant_id = grants[0]["id"]
    requester_email = grants[0]["requester_email"]
    conn.close()

    # Deny via dashboard
    resp = client.post(f"/owner/{_owner_token()}/decision", data={
        "grant_id": grant_id,
        "decision": "deny",
    })
    assert resp.status_code == 200

    # Verify grant is denied
    conn = whitelist_db.wl_connect(db)
    grant = whitelist_db.get_grant(conn, grant_id)
    assert grant["status"] == "denied"
    conn.close()

    # Requester should see only public fields
    resp = client.get(f"/p/dana_reyes?e={requester_email}")
    assert resp.status_code == 200
    html = resp.text
    assert "dana.r@northgatefreight.com" not in html, "Private email must NOT be visible after denial"


# ============================================================
# Test 6: Empty state — no pending requests
# ============================================================
def test_empty_state_shows_no_pending(tmp_path):
    """Dashboard with no pending requests shows empty state message."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "empty_user",
        "name": {"display": "Empty User"},
        "org": {"company": "EmptyCo", "title": "CEO"},
        "emails": [{"address": "empty@emptyco.com", "visibility": "public"}],
        "phones": [],
        "verified_at": "2026-09-10",
    })
    conn.close()

    client = TestClient(create_app(db))
    resp = client.get(f"/owner/{_owner_token()}")
    assert resp.status_code == 200
    html = resp.text
    # round-2/verb-sweep: single-surface WhiteList uses "No WhiteList entries yet"
    assert "No WhiteList entries" in html or "no whitelist entries" in html.lower() or "✓" in html, \
        f"Empty state message not found. HTML: {html[:500]}"


# ============================================================
# Test 7: Dashboard shows active grants with expiry badges
# ============================================================
def test_dashboard_shows_active_grants_with_expiry(tmp_path):
    """Dashboard lists active grants with expiry info."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))

    # Create an active grant on dana
    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")
    active_id = whitelist_db.create_grant(conn, dana["id"], "active@example.com", "Active")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    future = (datetime.now(timezone.utc) + timedelta(days=76)).strftime("%Y-%m-%dT%H:%M:%SZ")
    whitelist_db.update_grant_status(conn, active_id, "granted",
                                     granted_at=now, expires_at=future)
    conn.close()

    resp = client.get(f"/owner/{_owner_token()}")
    assert resp.status_code == 200
    html = resp.text
    # UX pass 3: rows no longer carry an email sub-line — the requester
    # NAME is what the list renders.
    assert "Active" in html, "Dashboard must show active grant requester"


# ============================================================
# Test 8: Dashboard decision reuses same expiry math as /a/... path
# ============================================================
def test_dashboard_expiry_math_matches_admin_route(tmp_path):
    """Expiry math for '14' choice must produce timestamps within the same day-bucket."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))

    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")
    g1 = whitelist_db.create_grant(conn, dana["id"], "dash14@example.com", "Dash14")
    g2 = whitelist_db.create_grant(conn, dana["id"], "admin14@example.com", "Admin14")
    conn.close()

    # Approve via dashboard
    resp = client.post(f"/owner/{_owner_token()}/decision", data={
        "grant_id": g1, "decision": "approve", "expiry": "14",
    })
    assert resp.status_code == 200

    # Approve via admin route
    admin_token = wl_tokens.make_token(b"test-secret", "grant_review", g2, expires_days=7)
    resp = client.post(f"/a/{admin_token}/decision", data={
        "decision": "approve", "expiry": "14",
    })
    assert resp.status_code == 200

    # Compare timestamps — they should be within the same day
    conn = whitelist_db.wl_connect(db)
    dash_grant = whitelist_db.get_grant(conn, g1)
    admin_grant = whitelist_db.get_grant(conn, g2)
    conn.close()

    dash_date = datetime.fromisoformat(dash_grant["expires_at"].replace("Z", "+00:00"))
    admin_date = datetime.fromisoformat(admin_grant["expires_at"].replace("Z", "+00:00"))

    assert abs((dash_date - admin_date).days) <= 1, \
        f"Expiry timestamps must be within same day: {dash_grant['expires_at']} vs {admin_grant['expires_at']}"
