"""Tests for whitelist_db.py — table creation and idempotency."""

import sqlite3
from pathlib import Path

import pytest

import whitelist_db


@pytest.fixture
def tmp_db(tmp_path: Path):
    """Create a fresh SQLite file with a minimal contacts table."""
    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("""
        CREATE TABLE contacts (
            id TEXT PRIMARY KEY,
            normalized_name TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            emails TEXT DEFAULT '[]',
            phones TEXT DEFAULT '[]',
            organizations TEXT DEFAULT '[]',
            sources TEXT DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_duplicate INTEGER DEFAULT 0,
            merged_into TEXT
        )
    """)
    conn.execute(
        "INSERT INTO contacts VALUES ('c1','Smith, John','John','Smith','[]','[]','[]','[]','2026-01-01','2026-01-01',0,NULL)"
    )
    conn.commit()
    conn.close()
    return db


def test_tables_created(tmp_db: Path):
    """wl_init creates profiles, profile_fields, access_grants tables."""
    conn = whitelist_db.wl_connect(tmp_db)
    try:
        whitelist_db.wl_init(conn)
        tables = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('profiles','profile_fields','access_grants')"
            ).fetchall()
        }
        assert tables == {"profiles", "profile_fields", "access_grants"}
    finally:
        conn.close()


def test_idempotent(tmp_db: Path):
    """Calling wl_init twice does not error and tables still exist."""
    conn = whitelist_db.wl_connect(tmp_db)
    try:
        whitelist_db.wl_init(conn)
        whitelist_db.wl_init(conn)
        tables = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "profiles" in tables
        assert "profile_fields" in tables
        assert "access_grants" in tables
    finally:
        conn.close()


def test_existing_tables_untouched(tmp_db: Path):
    """contacts table still exists and has its data after wl_init."""
    conn = whitelist_db.wl_connect(tmp_db)
    try:
        whitelist_db.wl_init(conn)
        count = conn.execute("SELECT count(*) FROM contacts").fetchone()[0]
        assert count == 1
        row = conn.execute("SELECT normalized_name FROM contacts WHERE id='c1'").fetchone()
        assert row[0] == "Smith, John"
    finally:
        conn.close()
