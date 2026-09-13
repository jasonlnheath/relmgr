"""Tests for seed_profile — upsert logic and idempotency."""

import sqlite3
from pathlib import Path

import pytest

import whitelist_db


SAMPLE_DATA = {
    "handle": "testuser",
    "name": {"display": "Test User"},
    "org": {"company": "TestCo", "title": "CTO"},
    "emails": [
        {"address": "test@testco.com", "visibility": "public"},
        {"address": "test.personal@gmail.com", "visibility": "connection"},
    ],
    "phones": [
        {"number": "+15551234567", "visibility": "holder"},
    ],
    "verified_at": "2026-09-10",
}


@pytest.fixture
def db_with_seed(tmp_path: Path):
    """Fresh DB with whitelist tables and one seeded profile."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, SAMPLE_DATA)
    conn.close()
    return db


def test_seed_profile_and_fields(tmp_path: Path):
    """seed_profile creates a profile row and correct field rows."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, SAMPLE_DATA)

    profile = conn.execute(
        "SELECT * FROM profiles WHERE handle='testuser'"
    ).fetchone()
    assert profile is not None
    assert profile["display_name"] == "Test User"
    assert profile["company"] == "TestCo"
    assert profile["title"] == "CTO"
    assert profile["verified_at"] == "2026-09-10"

    fields = conn.execute(
        "SELECT * FROM profile_fields ORDER BY field_value"
    ).fetchall()
    assert len(fields) == 3

    # Public email
    pub_email = [f for f in fields if f["field_value"] == "test@testco.com"]
    assert len(pub_email) == 1
    assert pub_email[0]["field_type"] == "email"
    assert pub_email[0]["visibility"] == "public"

    # Connection email → granted
    conn_email = [f for f in fields if f["field_value"] == "test.personal@gmail.com"]
    assert len(conn_email) == 1
    assert conn_email[0]["visibility"] == "granted"

    # Holder phone → granted
    holder_phone = [f for f in fields if f["field_value"] == "+15551234567"]
    assert len(holder_phone) == 1
    assert holder_phone[0]["field_type"] == "phone"
    assert holder_phone[0]["visibility"] == "granted"

    conn.close()


def test_seed_idempotent(tmp_path: Path):
    """Calling seed_profile twice does not duplicate rows."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, SAMPLE_DATA)
    whitelist_db.seed_profile(conn, SAMPLE_DATA)

    profile_count = conn.execute(
        "SELECT count(*) FROM profiles WHERE handle='testuser'"
    ).fetchone()[0]
    assert profile_count == 1

    field_count = conn.execute(
        "SELECT count(*) FROM profile_fields"
    ).fetchone()[0]
    assert field_count == 3  # same 3 fields, no duplicates

    conn.close()
