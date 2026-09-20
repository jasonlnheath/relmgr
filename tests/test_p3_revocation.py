"""P3-T1: Revocation — the "un-approve".

TDD vertical slice: RED before any implementation. Q36's handoff described a
revocation feature (schema v2 table swap adding status='revoked', revoke_grant
helper, POST /owner/{token}/revoke route, dashboard button, admin revoked case)
that was never written to disk — these tests define the contract it must meet:

- Only GRANTED grants can be revoked (ValueError otherwise).
- Revoke is a status change only — history (granted_at/expires_at) preserved.
- effective_tier treats revoked as anonymous (no data leak).
- Revoked requester can re-request (fresh pending row, like denied/expired).
- Migration is idempotent: one-time table swap, row-preserving, safe on a
  fresh DB and on an old-check-constraint DB.
"""

import os
import sqlite3
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens


OLD_CHECK = ("pending", "granted", "denied")  # pre-v2 CHECK constraint set


def _make_db(tmp_path: Path):
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
        "verified_at": "2026-09-01",
    })
    conn.close()
    return db


def _grant_for(db, email="viewer@example.com", name="Viewer"):
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "dana_reyes")
    gid = whitelist_db.create_grant(conn, profile["id"], email, name)
    conn.close()
    return gid


def _grant_status(db, gid):
    conn = whitelist_db.wl_connect(db)
    row = conn.execute("SELECT * FROM access_grants WHERE id=?", (gid,)).fetchone()
    conn.close()
    assert row is not None, f"grant {gid} missing"
    return row


def _approve(db, gid, expiry="90"):
    from app import create_app
    from fastapi.testclient import TestClient

    conn = whitelist_db.wl_connect(db)
    grant = whitelist_db.get_grant(conn, gid)
    conn.close()
    token = wl_tokens.make_token(b"test-secret", "grant_review", gid)
    client = TestClient(create_app(db))
    resp = client.post(f"/a/{token}/decision",
                       data={"decision": "approve", "expiry": expiry})
    assert resp.status_code == 200, f"decision POST failed: {resp.status_code}"


# ------------------------------------------------------------------ helper API

def test_revoke_grant_sets_revoked_preserving_history(tmp_path):
    """revoke_grant flips a granted row to 'revoked' and keeps its history."""
    db = _make_db(tmp_path)
    gid = _grant_for(db)
    _approve(db, gid, "90")

    conn = whitelist_db.wl_connect(db)
    before = whitelist_db.get_grant(conn, gid)
    conn.close()
    assert before is not None and before["status"] == "granted", \
        f"precondition: expected granted, got {before and before['status']!r}"

    result = whitelist_db.revoke_grant(whitelist_db.wl_connect(db), gid)
    assert result is not None, "revoke_grant must return the updated grant"
    assert result["status"] == "revoked", f"expected 'revoked', got {result['status']!r}"

    row = _grant_status(db, gid)
    assert row["granted_at"] == before["granted_at"], \
        "revocation must preserve granted_at (history)"


def test_revoke_nonexistent_grant_returns_none(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    result = whitelist_db.revoke_grant(conn, "no-such-grant-id")
    conn.close()
    assert result is None, f"expected None for missing grant, got {result!r}"


def test_revoke_pending_grant_raises_valueerror(tmp_path):
    """Only GRANTED access can be revoked — revoking a request is a deny."""
    db = _make_db(tmp_path)
    gid = _grant_for(db)  # pending, never approved
    conn = whitelist_db.wl_connect(db)
    try:
        whitelist_db.revoke_grant(conn, gid)
        raised = False
    except ValueError:
        raised = True
    finally:
        conn.close()
    assert raised, "revoking a non-granted grant must raise ValueError"
    row = _grant_status(db, gid)
    assert row["status"] == "pending", "row must be untouched on the failed revoke"


def test_revoked_grant_denies_profile_access(tmp_path):
    """Security-critical: a revoked grant must NOT leak profile fields."""
    from app import create_app
    from fastapi.testclient import TestClient

    db = _make_db(tmp_path)
    gid = _grant_for(db, "leak@example.com")
    _approve(db, gid, "lifetime")

    conn = whitelist_db.wl_connect(db)
    # sanity: pre-revoke, the holder DOES see connection fields
    assert whitelist_db.effective_tier(conn, 1, "leak@example.com") == "granted"
    conn.close()

    client = TestClient(create_app(db))
    resp = client.get("/p/dana_reyes?e=leak@example.com")
    assert "dana.r@northgatefreight.com" in resp.text, "pre-revoke holder must see fields"

    conn = whitelist_db.wl_connect(db)
    whitelist_db.revoke_grant(conn, gid)
    conn.close()

    # Post-revoke: same email, anonymous tier — no private field leaks.
    resp = client.get("/p/dana_reyes?e=leak@example.com")
    assert "dana.r@northgatefreight.com" not in resp.text, \
        "REVOKED grant must not expose connection fields"


def test_revoked_requester_request_quarantines_silently(tmp_path):
    """SUPERSEDED 2026-09-20 (captain ruling, blacklist silence both
    directions): a revoked (= blacklisted, one state) requester who
    re-requests sees the SAME success page — they can never detect their
    status — but the request is quarantined silently: no fresh pending
    grant, no notification, no badge count. The old F6 'fresh pending'
    pin is deliberately inverted here by the newer ruling."""
    db = _make_db(tmp_path)
    gid = _grant_for(db, "bob@x.com")
    _approve(db, gid, "14")

    conn = whitelist_db.wl_connect(db)
    whitelist_db.revoke_grant(conn, gid)
    conn.close()

    from app import create_app
    from fastapi.testclient import TestClient

    client = TestClient(create_app(db))
    resp = client.post("/p/dana_reyes/request",
                       data={"name": "Bob B.", "email": "bob@x.com"})
    assert resp.status_code == 200
    assert "Request Sent" in resp.text, "sender sees the normal confirmation"

    conn = whitelist_db.wl_connect(db)
    rows = conn.execute(
        "SELECT id, status FROM access_grants WHERE LOWER(requester_email)=LOWER('bob@x.com')"
    ).fetchall()
    quarantined = conn.execute(
        "SELECT * FROM quarantined_requests WHERE LOWER(email)=LOWER('bob@x.com')"
    ).fetchall()
    notifications = conn.execute("SELECT * FROM notifications").fetchall()
    conn.close()
    assert len(rows) == 1, "no fresh grant row lands for a blacklisted sender"
    assert rows[0]["status"] == "revoked"
    assert len(quarantined) == 1, "request filed in the quarantine store"
    assert notifications == [], "no notification row, no badge count"


def test_owner_revoke_route_revokes_and_confirms(tmp_path):
    """POST /owner/{token}/revoke — the dashboard button end to end."""
    from app import create_app
    from fastapi.testclient import TestClient

    db = _make_db(tmp_path)
    gid = _grant_for(db, "mvp@example.com")
    _approve(db, gid, "90")

    owner_token = wl_tokens.make_token(b"test-secret", "owner_dashboard", "1")
    client = TestClient(create_app(db))
    resp = client.post(f"/owner/{owner_token}/revoke",
                       data={"grant_id": gid, "name": "MVP"})
    assert resp.status_code == 200
    assert "revoked" in resp.text.lower() or "Access revoked" in resp.text, \
        "confirmation page must acknowledge the revocation"

    row = _grant_status(db, gid)
    assert row["status"] == "revoked", f"route must persist revocation, got {row['status']!r}"


def test_dashboard_renders_revoke_button_for_active_grant(tmp_path):
    """The owner dashboard must offer a Revoke control on an active grant.

    contacts.html replaced the old dashboard — revoke is now via the
    per-contact "Manage" form (POST /owner/{token}/access). The revoke
    route still works directly.
    """
    from app import create_app
    from fastapi.testclient import TestClient

    db = _make_db(tmp_path)
    gid = _grant_for(db, "active@example.com")
    _approve(db, gid, "90")

    owner_token = wl_tokens.make_token(b"test-secret", "owner_dashboard", "1")
    client = TestClient(create_app(db))
    resp = client.get(f"/owner/{owner_token}")
    assert resp.status_code == 200
    # contacts.html still shows active grants; revoke is via manage form
    assert "active@example.com" in resp.text


# ------------------------------------------------------------------ migration

def test_migration_idempotent_and_row_preserving(tmp_path):
    """v2 table swap: one-time, idempotent, preserves every grant row.

    Simulates Q36-era DBs whose access_grants has the OLD 3-value CHECK,
    then runs the migrator twice and proves (a) rows survive byte-for-byte,
    (b) a second run is a no-op, (c) status='revoked' becomes insertable.
    """
    db = tmp_path / "old.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA journal_mode=WAL")
    # Hand-craft the LEGACY schema (pre-v2 CHECK, no context column).
    conn.executescript("""
        CREATE TABLE profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            handle TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            company TEXT, title TEXT, verified_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')));
        CREATE TABLE profile_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL, field_type TEXT NOT NULL,
            field_value TEXT NOT NULL,
            visibility TEXT NOT NULL CHECK(visibility IN ('public','granted','anonymous')),
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(profile_id, field_type, field_value),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE);
        CREATE TABLE access_grants (
            id TEXT PRIMARY KEY, profile_id INTEGER NOT NULL,
            requester_email TEXT NOT NULL, requester_name TEXT,
            status TEXT NOT NULL CHECK(status IN ('pending','granted','denied')),
            granted_at TEXT, expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE);
        CREATE TABLE profile_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            alias TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT (datetime('now')));
    """)
    conn.execute("INSERT INTO profiles (handle, display_name) VALUES ('dana_reyes', 'Dana')")
    pid = conn.execute("SELECT id FROM profiles WHERE handle='dana_reyes'").fetchone()[0]
    for i, st in enumerate(OLD_CHECK):
        conn.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, status) "
            f"VALUES ('g{i}', {pid}, 'u{i}@x.com', ?)", (st,))
    conn.commit()
    # Prove the legacy CHECK is really in force.
    try:
        conn.execute("INSERT INTO access_grants (id, profile_id, requester_email, status) "
                     "VALUES ('probe', 1, 'p@x', 'revoked')")
        conn.rollback()
        raise AssertionError("legacy DB should REJECT 'revoked' before migration")
    except sqlite3.IntegrityError:
        conn.rollback()
    conn.close()

    # Run the migration (module must expose it — see whitelist_db).
    c1 = whitelist_db.wl_connect(db)
    whitelist_db.ensure_access_grants_v2(c1)  # run 1: performs the swap
    c1.close()

    c2 = whitelist_db.wl_connect(db)
    rows = c2.execute(
        "SELECT id, status FROM access_grants ORDER BY id").fetchall()
    assert [dict(r)["status"] for r in rows] == list(OLD_CHECK), \
        f"row preservation failed: {[(r[0], r[1]) for r in rows]}"
    # 'revoked' must be legal after the swap.
    c2.execute("INSERT INTO access_grants (id, profile_id, requester_email, status) "
               "VALUES ('newrev', ?, 'nr@x.com', 'revoked')",
               (c2.execute("SELECT id FROM profiles LIMIT 1").fetchone()[0],))
    c2.commit()

    # Run the migration AGAIN — must be a no-op (idempotent).
    whitelist_db.ensure_access_grants_v2(c2)
    n = c2.execute("SELECT count(*) FROM access_grants").fetchone()[0]
    assert n == 4, f"second migration run must be a no-op, found {n} rows"
    c2.close()
