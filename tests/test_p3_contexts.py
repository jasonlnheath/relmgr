"""P3-T3: Context categories — organize requests by type (additive).

The requester is tagged with a category before/during review so the owner
knows *why* someone asked for access. Built-ins are seeded; custom
categories are an open question for Jason, so the registry table stays
open (INSERT rows) but no UI ships for it yet.
"""

import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from app import create_app
from fastapi.testclient import TestClient


CATEGORIES = ["sales-prospect", "partner", "vendor", "media", "personal", "other"]


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


# ------------------------------------------------------------------ registry

def test_builtin_categories_seeded_idempotent(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    rows = whitelist_db.list_contexts(conn)
    cats = [r["category"] for r in rows]
    assert cats == CATEGORIES, f"expected {CATEGORIES}, got {cats}"
    # second boot: no duplicates
    whitelist_db.ensure_grant_contexts(conn)
    again = whitelist_db.list_contexts(conn)
    assert len(again) == len(CATEGORIES), f"seed not idempotent: {len(again)} rows"
    conn.close()


def test_set_context_updates_grant(tmp_path):
    db = _make_db(tmp_path)
    gid = _grant(db, "a@x.com")
    conn = whitelist_db.wl_connect(db)
    result = whitelist_db.set_grant_context(conn, gid, "vendor")
    conn.close()
    assert result is not None, "set_grant_context must return the updated grant"
    conn = whitelist_db.wl_connect(db)
    g = whitelist_db.get_grant(conn, gid)
    conn.close()
    assert g["context"] == "vendor", f"context not stored: {g['context']!r}"


def test_unknown_category_rejected(tmp_path):
    """A category not in the registry must be refused — free-text context is
    exactly the mess the categories are for."""
    db = _make_db(tmp_path)
    gid = _grant(db, "b@x.com")
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.set_grant_context(conn, gid, "alien-invasion") is None
    g = whitelist_db.get_grant(conn, gid)
    assert g["context"] is None, f"bogus category must not be stored: {g['context']!r}"
    conn.close()


def test_unknown_grant_rejected(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.set_grant_context(conn, "no-such-grant", "vendor") is None
    conn.close()


# ------------------------------------------------------------------ route + UI

# NOTE 2026-09-12: Jason cut the context feature from the product. The route
# tests below (/categorize, dashboard badge) were deleted with the routes;
# DB-layer functions remain (data preserved) and their unit tests stay above.


def test_boot_selfheal_adds_missing_context_column(tmp_path):
    """v2-era DB (exactly the production state) has 'revoked' in its DDL but
    NO context column — ensure_access_grants_v2 is a no-op on it, so boot
    must additively ADD the column or set_grant_context crashes with
    'no such column' on first use."""
    import sqlite3 as _sq

    db = tmp_path / "v2nocontext.db"
    conn = _sq.connect(str(db))
    conn.execute("CREATE TABLE profiles (id INTEGER PRIMARY KEY, handle TEXT NOT NULL UNIQUE, display_name TEXT)")
    conn.execute("INSERT INTO profiles (handle, display_name) VALUES ('dana_reyes', 'Dana')")
    conn.execute("""
        CREATE TABLE access_grants (
            id TEXT PRIMARY KEY, profile_id INTEGER NOT NULL,
            requester_email TEXT NOT NULL, requester_name TEXT,
            status TEXT NOT NULL CHECK(status IN ('pending','granted','denied','revoked')),
            granted_at TEXT, expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')))""")
    conn.execute(
        "INSERT INTO access_grants (id, profile_id, requester_email, status) "
        "VALUES ('g1', 1, 'u@x.com', 'granted')")
    conn.commit()
    conn.close()

    # Boot must self-heal the missing column.
    client = TestClient(create_app(db))
    assert client is not None  # create_app ran the heal without raising

    conn = whitelist_db.wl_connect(db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(access_grants)")]
    assert "context" in cols, f"context column missing after boot: {cols}"
    n = conn.execute("SELECT count(*) FROM access_grants").fetchone()[0]
    assert n == 1, f"row must survive the ADD COLUMN, got {n}"
    # And the feature actually works on the healed table.
    result = whitelist_db.set_grant_context(conn, "g1", "vendor")
    conn.close()
    assert result is not None and result["context"] == "vendor", \
        f"set_grant_context must work post-heal: {result!r}"
