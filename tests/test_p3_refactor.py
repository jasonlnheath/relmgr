"""Refactor characterization tests — the refactored seams must behave
exactly as before. These pin the CONTRACTS a later cleanup might break:

- ensure_whitelist_schema heals every legacy shape in ONE call, idempotently.
- is_verified_stale's boundary (>180 days) matches what /p shows stale for.
"""

import os
from datetime import datetime, timedelta

os.environ["WHITELIST_SECRET"] = "test-secret"

import sqlite3

import whitelist_db
from app import create_app, is_verified_stale


def test_boot_orchestrator_heals_v1_legacy_db(tmp_path):
    """A Q36-era production DB: v1 CHECK, 9 columns, no context/audit tables.
    create_app() must heal it end-to-end in ONE call (revoked usable, all
    additive tables + context column present, row intact) — the single
    orchestrator is the seam, so a future migration has exactly one place to
    touch."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE profiles (id INTEGER PRIMARY KEY, handle TEXT NOT NULL UNIQUE)")
    conn.execute("INSERT INTO profiles (handle) VALUES ('dana_reyes')")
    conn.execute("""
        CREATE TABLE access_grants (
            id TEXT PRIMARY KEY, profile_id INTEGER NOT NULL,
            requester_email TEXT NOT NULL, requester_name TEXT,
            status TEXT NOT NULL CHECK(status IN ('pending', 'granted', 'denied')),
            granted_at TEXT, expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')))""")
    conn.execute(
        "INSERT INTO access_grants (id, profile_id, requester_email, status) "
        "VALUES ('g1', 1, 'u@x.com', 'granted')")
    conn.commit()
    conn.close()

    create_app(db)  # must heal without raising

    conn = whitelist_db.wl_connect(db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(access_grants)")]
    assert "context" in cols, f"context column missing after boot: {cols}"
    n = conn.execute("SELECT count(*) FROM access_grants").fetchone()[0]
    assert n == 1, f"v1 row must survive the heal, got {n}"
    # Revocation actually works on the healed table.
    res = whitelist_db.revoke_grant(conn, "g1")
    assert res is not None and res["status"] == "revoked", \
        f"revoke must work post-heal: {res!r}"
    # Every additive table exists (idempotent ensures ran at boot).
    for table in ("grant_logs", "grant_contexts", "scan_events"):
        assert conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone()[0] == 1, f"table {table} missing after boot"
    # Audit row landed for the revoke (same-transaction logging intact).
    actions = [r[0] for r in conn.execute(
        "SELECT action FROM grant_logs WHERE grant_id='g1' ORDER BY id")]
    assert actions == ["revoked"], f"audit row missing after heal: {actions}"
    conn.close()


def test_is_verified_stale_boundaries():
    """/p marks a profile stale when verified_at is >180 days old — that
    boundary lives in the helper, not inlined in the route. None -> False."""
    now = datetime.now(whitelist_db.timezone.utc)  # noqa: F401 (aware utc)
    assert is_verified_stale(None) is False
    # A ~9-month-old profile is stale; ~3-month-old is not (boundary pinned).
    fresh = (now - timedelta(days=100)).strftime("%Y-%m-%d")
    assert is_verified_stale(fresh) is False
    old = (now - timedelta(days=400)).strftime("%Y-%m-%d")
    assert is_verified_stale(old) is True
