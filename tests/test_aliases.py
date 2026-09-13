"""Tests for profile aliases — P2-T2.

TDD vertical slices: RED before any fix.
"""

import os
import sys
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
from app import create_app
from fastapi.testclient import TestClient


def _make_db(tmp_path: Path):
    """Create a fresh DB with whitelist tables and seed two profiles."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)

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

    conn.close()
    return db


# ============================================================
# Test 1: Alias resolves to same profile, same tier behavior
# ============================================================
def test_alias_resolves_to_same_profile(tmp_path):
    """Adding an alias must resolve to the same profile_id and tier."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")

    result = whitelist_db.add_alias(conn, dana["id"], "dana-sales")
    assert result is not None, "add_alias must return the alias id"

    # resolve_handle must find dana via the alias
    resolved = whitelist_db.resolve_handle(conn, "dana-sales")
    assert resolved is not None, "resolve_handle must find profile by alias"
    assert resolved["id"] == dana["id"], "Alias must resolve to same profile id"
    assert resolved["handle"] == "dana_reyes", "Must return the canonical profile"

    # Grant via primary handle → alias sees same tier
    grant_id = whitelist_db.create_grant(conn, dana["id"], "viewer@example.com", "Viewer")
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    whitelist_db.update_grant_status(conn, grant_id, "granted",
                                     granted_at=now, expires_at=None)
    conn.close()

    app = create_app(db)
    client = TestClient(app)

    # Via primary handle
    resp1 = client.get("/p/dana_reyes?e=viewer@example.com")
    assert resp1.status_code == 200
    assert "dana.r@northgatefreight.com" in resp1.text

    # Via alias — must see the same fields
    resp2 = client.get("/p/dana-sales?e=viewer@example.com")
    assert resp2.status_code == 200
    assert "dana.r@northgatefreight.com" in resp2.text


def test_alias_granted_via_alias_works_for_primary(tmp_path):
    """Grant created via alias handle must also work for primary handle."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")

    whitelist_db.add_alias(conn, dana["id"], "dana-vip")
    conn.close()

    app = create_app(db)
    client = TestClient(app)

    # Request via alias
    resp = client.post("/p/dana-vip/request", data={
        "name": "Requester", "email": "vip-requester@example.com",
    })
    assert resp.status_code == 200

    # Approve via admin route
    conn = whitelist_db.wl_connect(db)
    grants = conn.execute(
        "SELECT id FROM access_grants WHERE requester_email='vip-requester@example.com'"
    ).fetchall()
    grant_id = grants[0]["id"]
    conn.close()

    import wl_tokens
    admin_token = wl_tokens.make_token(b"test-secret", "grant_review", grant_id, expires_days=7)
    resp = client.post(f"/a/{admin_token}/decision", data={
        "decision": "approve", "expiry": "90",
    })
    assert resp.status_code == 200

    # Now request via PRIMARY handle — must still see granted fields
    resp = client.get("/p/dana_reyes?e=vip-requester@example.com")
    assert resp.status_code == 200
    assert "dana.r@northgatefreight.com" in resp.text


# ============================================================
# Test 2: Case-insensitive collision
# ============================================================
def test_alias_collision_with_other_handle_rejected(tmp_path):
    """Alias equal to another profile's handle (any case) must be rejected."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")

    # Try to alias dana as "marcus_chen" (exact match with another profile)
    result = whitelist_db.add_alias(conn, dana["id"], "marcus_chen")
    assert result is None, "Alias must be rejected when colliding with another profile's handle"

    # Case-insensitive: try "Marcus_Chen"
    result = whitelist_db.add_alias(conn, dana["id"], "Marcus_Chen")
    assert result is None, "Alias must be rejected case-insensitively"

    conn.close()


def test_duplicate_alias_rejected(tmp_path):
    """Same alias added twice must be rejected on the second call."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    dana = whitelist_db.get_profile(conn, "dana_reyes")

    r1 = whitelist_db.add_alias(conn, dana["id"], "dana-fresh")
    assert r1 is not None, "First add must succeed"

    r2 = whitelist_db.add_alias(conn, dana["id"], "dana-fresh")
    assert r2 is None, "Duplicate alias must be rejected"

    # Also reject if different profile tries same alias
    marcus = whitelist_db.get_profile(conn, "marcus_chen")
    r3 = whitelist_db.add_alias(conn, marcus["id"], "dana-fresh")
    assert r3 is None, "Alias collision across profiles must be rejected"

    conn.close()


# ============================================================
# Test 3: Unknown handle still 404s
# ============================================================
def test_unknown_handle_still_404(tmp_path):
    """A handle that doesn't exist as primary or alias must return 404."""
    db = _make_db(tmp_path)
    app = create_app(db)
    client = TestClient(app)

    resp = client.get("/p/nonexistent_handle")
    assert resp.status_code == 404, "Unknown handle must return 404"

    resp = client.get("/p/nonexistent_alias")
    assert resp.status_code == 404, "Unknown alias must return 404"


# ============================================================
# Test 4: seed_demo idempotent — zero duplicate alias rows
# ============================================================
def test_seed_demo_adds_aliases_idempotent(tmp_path):
    """Running seed_demo twice must not create duplicate alias rows.

    Hermetic: points at a tmp DB (A2) — the old version ran seed_all() with
    default paths, mutating the LIVE contacts.db and appending a 1.9MB backup
    on every test run.
    """
    from scripts.seed_demo import seed_all

    db = _make_db(tmp_path)
    canonical = Path("/home/jason/profile/jason.heath.canonical.json")

    # First run
    seed_all(dry_run=False, db_path=db, canonical_path=canonical,
             exports_dir=tmp_path / "exports", make_backup=False)

    conn = whitelist_db.wl_connect(db)
    alias_count_1 = conn.execute(
        "SELECT count(*) FROM profile_aliases"
    ).fetchone()[0]
    conn.close()

    # Second run — must add nothing new
    seed_all(dry_run=False, db_path=db, canonical_path=canonical,
             exports_dir=tmp_path / "exports", make_backup=False)

    conn = whitelist_db.wl_connect(db)
    alias_count_2 = conn.execute(
        "SELECT count(*) FROM profile_aliases"
    ).fetchone()[0]
    n_profiles = conn.execute("SELECT count(*) FROM profiles").fetchone()[0]
    conn.close()

    assert alias_count_1 == 5, f"expected 5 aliases after seed, got {alias_count_1}"
    assert alias_count_2 == alias_count_1, \
        f"Alias count must be idempotent: {alias_count_1} vs {alias_count_2}"
    assert n_profiles == 5, f"expected 5 profiles (jason + 4 demo), got {n_profiles}"
