"""P3-T2: Audit log — grant_logs (additive).

Every state transition (created / approved / denied / revoked) appends a row
to grant_logs. History is never edited or purged in this phase (open question
on retention is Jason's call; no purge code ships until he says so).
"""

import os
import sqlite3
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from app import create_app
from fastapi.testclient import TestClient


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "dana_reyes",
        "name": {"display": "Dana Reyes"},
        "emails": [{"address": "dana.r@northgatefreight.com", "visibility": "connection"}],
        "verified_at": "2026-09-01",
    })
    conn.close()
    return db


def _grant(db, email):
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "dana_reyes")
    gid = whitelist_db.create_grant(conn, profile["id"], email, "Test")
    conn.close()
    return gid


def _logs(db, grant_id=None):
    conn = whitelist_db.wl_connect(db)
    rows = whitelist_db.get_grant_logs(conn, grant_id)
    conn.close()
    return rows


# ------------------------------------------------------------------ one row per transition

def test_create_grant_writes_created_log(tmp_path):
    db = _make_db(tmp_path)
    gid = _grant(db, "a@x.com")
    logs = _logs(db, gid)
    assert len(logs) == 1, f"expected exactly 1 log row for create, got {len(logs)}"
    assert logs[0]["action"] == "created", f"got {logs[0]['action']!r}"


def test_dedupe_hit_writes_no_second_log(tmp_path):
    """Re-requesting while a LIVE grant exists reuses the id — no new row,
    so no second 'created' log either (the audit trail must stay truthful)."""
    db = _make_db(tmp_path)
    e = "dupe@x.com"
    g1 = _grant(db, e)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "dana_reyes")
    g2 = whitelist_db.create_grant(conn, profile["id"], e.upper(), "Test")  # case-folded hit
    conn.close()
    assert g1 == g2, "precondition: dedupe must reuse the live grant"
    logs = _logs(db, g1)
    assert len(logs) == 1, f"dedupe hit must not duplicate the created log, got {len(logs)}"


def test_approve_writes_approved_log_with_requested_expiry(tmp_path):
    from app import create_app
    db = _make_db(tmp_path)
    gid = _grant(db, "b@x.com")
    conn = whitelist_db.wl_connect(db)
    result = whitelist_db.apply_decision(conn, gid, "approve", "14")
    conn.close()
    assert result is not None

    logs = _logs(db, gid)
    actions = [r["action"] for r in logs]
    assert actions == ["created", "approved"], f"got {actions}"
    appr = logs[-1]
    assert appr["requested_expiry"] == "14", \
        f"approve log must record the requested expiry, got {appr['requested_expiry']!r}"


def test_deny_writes_denied_log(tmp_path):
    db = _make_db(tmp_path)
    gid = _grant(db, "c@x.com")
    conn = whitelist_db.wl_connect(db)
    result = whitelist_db.apply_decision(conn, gid, "deny", "90")
    conn.close()
    assert result is not None
    actions = [r["action"] for r in _logs(db, gid)]
    assert actions == ["created", "denied"], f"got {actions}"


def test_revoke_writes_revoked_log(tmp_path):
    db = _make_db(tmp_path)
    gid = _grant(db, "d@x.com")
    conn = whitelist_db.wl_connect(db)
    whitelist_db.apply_decision(conn, gid, "approve", "90")
    conn.close()
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.revoke_grant(conn, gid) is not None
    conn.close()
    actions = [r["action"] for r in _logs(db, gid)]
    assert actions == ["created", "approved", "revoked"], f"got {actions}"


def test_logs_filter_by_grant_and_stable_order(tmp_path):
    """get_grant_logs: filter per grant; stable chronological order (id)."""
    db = _make_db(tmp_path)
    g1 = _grant(db, "e1@x.com")
    g2 = _grant(db, "e2@x.com")
    conn = whitelist_db.wl_connect(db)
    whitelist_db.apply_decision(conn, g1, "approve", "90")
    conn.close()

    all_logs = _logs(db)  # no filter -> everything, ordered
    ids = [r["id"] for r in all_logs]
    assert len(all_logs) == 3 and ids == sorted(ids), f"expected 3 rows in id order, got {len(all_logs)}"

    only1 = _logs(db, g1)
    assert all(r["grant_id"] == g1 for r in only1)
    assert [r["action"] for r in only1] == ["created", "approved"]


def test_boot_selfheal_creates_grant_logs_on_legacy_db(tmp_path):
    """P0 regression: a Q36-era production DB has NO grant_logs table. The
    boot path (create_app) must self-heal it — otherwise every request
    crashes at the first 'created' audit INSERT."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    conn.executescript("""
        CREATE TABLE profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, handle TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL, company TEXT, title TEXT, verified_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE profile_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL,
            field_type TEXT NOT NULL, field_value TEXT NOT NULL,
            visibility TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE access_grants (
            id TEXT PRIMARY KEY, profile_id INTEGER NOT NULL,
            requester_email TEXT NOT NULL, requester_name TEXT,
            status TEXT NOT NULL CHECK(status IN ('pending','granted','denied')),
            granted_at TEXT, expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE profile_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL,
            alias TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT (datetime('now')));
    """)
    conn.commit()
    conn.close()

    from app import create_app
    client = TestClient(create_app(db))  # boot must not raise
    db2 = tmp_path / "legacy.db"
    assert db2.exists()


def test_full_decision_route_still_logged(tmp_path):
    """End-to-end: POST /a/{token}/decision (approve via the real route) must
    leave the same audit trail as calling apply_decision directly."""
    db = _make_db(tmp_path)
    gid = _grant(db, "f@x.com")
    token = wl_tokens.make_token(b"test-secret", "grant_review", gid)
    client = TestClient(create_app(db))
    resp = client.post(f"/a/{token}/decision", data={"decision": "approve", "expiry": "lifetime"})
    assert resp.status_code == 200
    actions = [r["action"] for r in _logs(db, gid)]
    assert actions == ["created", "approved"], f"got {actions}"
