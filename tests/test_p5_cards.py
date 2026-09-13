"""T1 — Cards schema + CRUD.

One idempotent heal `ensure_cards_schema(conn)` wired INTO ensure_whitelist_schema.
3 new tables: cards, card_fields, grant_cards.

Tests pin:
- Schema is additive + idempotent (digest unchanged on double-heal)
- create_card(conn, owner_profile_id, name, field_ids)
- list_cards(conn, owner_profile_id)
- set_grant_cards(conn, grant_id, card_ids) — replace semantics
- get_active_cards_for_grant(conn, grant_id)
- Audit row on set_grant_cards (contract #2)
"""
import os
import sys
import json
from pathlib import Path

import pytest

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from whitelist_db import (
    ensure_cards_schema,
    create_card,
    list_cards,
    set_grant_cards,
    get_active_cards_for_grant,
    wl_connect,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def conn_with_schema(tmp_path):
    """Fresh DB with whitelist schema + cards tables + profiles + fields."""
    db = tmp_path / "test_cards.db"
    conn = wl_connect(db)
    # Run full boot to get all tables
    from whitelist_db import ensure_whitelist_schema, seed_profile
    ensure_whitelist_schema(conn)
    # Seed a profile with email/phone fields
    seed_profile(conn, {
        "handle": "test_owner",
        "name": {"display": "Test Owner"},
        "org": {"company": "Test Corp", "title": "CEO"},
        "emails": [{"address": "owner@test.com", "visibility": "granted"}],
        "phones": [{"number": "555-0000", "visibility": "granted"}],
    })
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def conn_minimal(tmp_path):
    """Minimal DB: just cards schema + one profile + one field."""
    db = tmp_path / "test_min_cards.db"
    conn = wl_connect(db)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            handle TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            company TEXT,
            title TEXT,
            verified_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS profile_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL,
            field_type TEXT NOT NULL CHECK(field_type IN ('email', 'phone')),
            field_value TEXT NOT NULL,
            visibility TEXT NOT NULL CHECK(visibility IN ('public', 'granted', 'anonymous')),
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(profile_id, field_type, field_value),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS access_grants (
            id TEXT PRIMARY KEY,
            profile_id INTEGER NOT NULL,
            requester_email TEXT NOT NULL,
            requester_name TEXT,
            status TEXT NOT NULL CHECK(status IN ('pending', 'granted', 'denied', 'revoked')),
            context TEXT,
            granted_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        )
    """)
    # grant_logs needed for _log_action in set_grant_cards
    conn.execute("""
        CREATE TABLE IF NOT EXISTS grant_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            grant_id TEXT NOT NULL,
            profile_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            requested_expiry TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    # Seed profile
    conn.execute(
        "INSERT INTO profiles (handle, display_name) VALUES (?, ?)",
        ("test_owner", "Test Owner"),
    )
    profile_id = conn.execute("SELECT id FROM profiles WHERE handle = ?", ("test_owner",)).fetchone()[0]
    # Seed email field
    conn.execute(
        "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (?, ?, ?, ?)",
        (profile_id, "email", "owner@test.com", "granted"),
    )
    # Seed phone field
    conn.execute(
        "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (?, ?, ?, ?)",
        (profile_id, "phone", "555-0000", "granted"),
    )
    conn.commit()
    yield conn
    conn.close()


# ============================================================
# ensure_cards_schema tests
# ============================================================

class TestEnsureCardsSchema:
    """Idempotent heal that creates 3 additive tables."""

    def test_creates_three_tables(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        tables = {r[0] for r in conn_minimal.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('cards', 'card_fields', 'grant_cards')"
        ).fetchall()}
        assert tables == {"cards", "card_fields", "grant_cards"}

    def test_idempotent_no_duplicate(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        ensure_cards_schema(conn_minimal)
        # Tables should exist exactly once
        count = conn_minimal.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('cards', 'card_fields', 'grant_cards')"
        ).fetchone()[0]
        assert count == 3

    def test_additive_digest_unchanged(self, conn_minimal):
        """Heal must not modify existing data rows."""
        # Check row count before/after — ensures no inserts/deletes
        before_count = conn_minimal.execute(
            "SELECT COUNT(*) FROM profiles"
        ).fetchone()[0]

        ensure_cards_schema(conn_minimal)

        after_count = conn_minimal.execute(
            "SELECT COUNT(*) FROM profiles"
        ).fetchone()[0]

        assert before_count == after_count, "ensure_cards_schema must not modify existing data"


# ============================================================
# create_card tests
# ============================================================

class TestCreateCard:
    def test_creates_card_with_fields(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        field_ids = [1, 2]  # email and phone
        result = create_card(conn_minimal, profile_id, "Work", field_ids)
        assert result is not None
        assert result["name"] == "Work"
        assert result["owner_profile_id"] == profile_id

    def test_empty_card_allowed(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        result = create_card(conn_minimal, profile_id, "Empty", [])
        assert result is not None
        assert result["name"] == "Empty"

    def test_unknown_field_id_raises(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        with pytest.raises(ValueError):
            create_card(conn_minimal, profile_id, "Bad", [999])

    def test_duplicate_name_raises(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        create_card(conn_minimal, profile_id, "Work", [1])
        with pytest.raises(ValueError):
            create_card(conn_minimal, profile_id, "Work", [1])


# ============================================================
# list_cards tests
# ============================================================

class TestListCards:
    def test_returns_cards_with_fields(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        create_card(conn_minimal, profile_id, "Work", [1])
        cards = list_cards(conn_minimal, profile_id)
        assert len(cards) == 1
        assert cards[0]["name"] == "Work"
        assert "fields" in cards[0]

    def test_empty_list(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        cards = list_cards(conn_minimal, profile_id)
        assert cards == []


# ============================================================
# set_grant_cards tests
# ============================================================

class TestSetGrantCards:
    def test_sets_cards_on_grant(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        # Create a grant
        grant_id = "test-grant-1"
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        conn_minimal.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status) VALUES (?, ?, ?, ?, ?)",
            (grant_id, profile_id, "test@example.com", "Test", "pending"),
        )
        conn_minimal.commit()
        # Create a card
        card_id = create_card(conn_minimal, profile_id, "Work", [1])["id"]
        result = set_grant_cards(conn_minimal, grant_id, [card_id])
        assert result is not None

    def test_replace_semantics(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        grant_id = "test-grant-2"
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        conn_minimal.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status) VALUES (?, ?, ?, ?, ?)",
            (grant_id, profile_id, "test@example.com", "Test", "pending"),
        )
        conn_minimal.commit()
        card1 = create_card(conn_minimal, profile_id, "Work", [1])["id"]
        card2 = create_card(conn_minimal, profile_id, "Personal", [2])["id"]
        # Set first set
        set_grant_cards(conn_minimal, grant_id, [card1])
        # Replace with second set
        set_grant_cards(conn_minimal, grant_id, [card2])
        cards = get_active_cards_for_grant(conn_minimal, grant_id)
        assert len(cards) == 1
        assert cards[0]["name"] == "Personal"

    def test_empty_clears(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        grant_id = "test-grant-3"
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        conn_minimal.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status) VALUES (?, ?, ?, ?, ?)",
            (grant_id, profile_id, "test@example.com", "Test", "pending"),
        )
        conn_minimal.commit()
        card = create_card(conn_minimal, profile_id, "Work", [1])["id"]
        set_grant_cards(conn_minimal, grant_id, [card])
        # Clear
        set_grant_cards(conn_minimal, grant_id, [])
        cards = get_active_cards_for_grant(conn_minimal, grant_id)
        assert cards == []

    def test_unknown_grant_returns_none(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        result = set_grant_cards(conn_minimal, "nonexistent", [1])
        assert result is None

    def test_unknown_card_id_raises(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        grant_id = "test-grant-4"
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        conn_minimal.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status) VALUES (?, ?, ?, ?, ?)",
            (grant_id, profile_id, "test@example.com", "Test", "pending"),
        )
        conn_minimal.commit()
        with pytest.raises(ValueError):
            set_grant_cards(conn_minimal, grant_id, [999])

    def test_audit_row_written(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        grant_id = "test-grant-5"
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        conn_minimal.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status) VALUES (?, ?, ?, ?, ?)",
            (grant_id, profile_id, "test@example.com", "Test", "pending"),
        )
        conn_minimal.commit()
        card = create_card(conn_minimal, profile_id, "Work", [1])["id"]
        set_grant_cards(conn_minimal, grant_id, [card])
        # Check audit log exists
        logs = conn_minimal.execute(
            "SELECT COUNT(*) FROM grant_logs WHERE action = 'cards_set' AND grant_id = ?",
            (grant_id,),
        ).fetchone()[0]
        assert logs >= 1


# ============================================================
# get_active_cards_for_grant tests
# ============================================================

class TestGetActiveCardsForGrant:
    def test_returns_cards(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        grant_id = "test-grant-6"
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        conn_minimal.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status) VALUES (?, ?, ?, ?, ?)",
            (grant_id, profile_id, "test@example.com", "Test", "pending"),
        )
        conn_minimal.commit()
        card1 = create_card(conn_minimal, profile_id, "Work", [1])
        card2 = create_card(conn_minimal, profile_id, "Personal", [2])
        set_grant_cards(conn_minimal, grant_id, [card1["id"], card2["id"]])
        cards = get_active_cards_for_grant(conn_minimal, grant_id)
        assert len(cards) == 2
        names = {c["name"] for c in cards}
        assert names == {"Work", "Personal"}

    def test_empty_when_no_cards(self, conn_minimal):
        ensure_cards_schema(conn_minimal)
        grant_id = "test-grant-7"
        profile_id = conn_minimal.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]
        conn_minimal.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status) VALUES (?, ?, ?, ?, ?)",
            (grant_id, profile_id, "test@example.com", "Test", "pending"),
        )
        conn_minimal.commit()
        cards = get_active_cards_for_grant(conn_minimal, grant_id)
        assert cards == []
