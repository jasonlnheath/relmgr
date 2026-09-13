"""T0 — Identity join: find_contact_by_email + merge_requester_into_contacts.

Whitelist = source of truth. When approved, Whitelist info merges into
contacts table. No duplicates allowed.

Tests here are read-only for find_contact_by_email and write-only for
merge_requester_into_contacts (with digest verification).
"""
import json
import os
import sys
from pathlib import Path

import pytest

# Set env BEFORE importing app/whitelist_db
os.environ["WHITELIST_SECRET"] = "test-secret"

# Ensure relmgr is on sys.path for flat imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
from whitelist_db import find_contact_by_email, merge_requester_into_contacts


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def conn(tmp_path):
    """Fresh WAL connection with contacts table populated."""
    db = tmp_path / "test.db"
    # Copy from prod for realistic data
    import shutil
    shutil.copy(Path(__file__).parent.parent / "contacts.db", db)
    conn = whitelist_db.wl_connect(db)
    conn.execute("PRAGMA foreign_keys=ON")
    yield conn
    conn.close()


@pytest.fixture
def conn_minimal(tmp_path):
    """Minimal DB: contacts table with a few known rows."""
    db = tmp_path / "test_min.db"
    conn = whitelist_db.wl_connect(db)
    conn.execute("""
        CREATE TABLE contacts (
            id TEXT PRIMARY KEY,
            normalized_name TEXT,
            first_name TEXT,
            last_name TEXT,
            emails TEXT,
            phones TEXT,
            organizations TEXT,
            sources TEXT,
            created_at TEXT,
            updated_at TEXT,
            is_duplicate INTEGER,
            merged_into TEXT,
            contact_sources TEXT
        )
    """)
    # grant_logs needed for merge audit rows
    conn.execute("""
        CREATE TABLE grant_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            grant_id TEXT NOT NULL,
            profile_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            requested_expiry TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    # Use parameterized inserts to avoid SQL injection of Python None
    conn.executemany(
        "INSERT INTO contacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ('c1', 'Alice Smith', 'Alice', 'Smith',
             '[{"address": "alice@example.com", "type": "primary"}]',
             '[{"number": "555-0101", "type": "primary"}]',
             '[]', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, None, None),
            ('c2', 'Bob Jones', 'Bob', 'Jones',
             '[{"address": "bob@EXAMPLE.COM", "type": "primary"}]',
             '[]', '[]', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, None, None),
            ('c3', 'Empty Emails', '', '',
             '[]',
             '[{"number": "555-0202", "type": "primary"}]',
             '[]', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, None, None),
            ('c4', 'No Emails Col', '', '',
             '',
             '[]', '[]', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, None, None),
        ],
    )
    conn.commit()
    yield conn
    conn.close()


# ============================================================
# find_contact_by_email tests
# ============================================================

class TestFindContactByEmail:
    """find_contact_by_email(conn, email) -> Optional[dict]."""

    def test_returns_contact_when_email_matches(self, conn_minimal):
        result = find_contact_by_email(conn_minimal, "alice@example.com")
        assert result is not None
        assert result["id"] == "c1"
        assert result["normalized_name"] == "Alice Smith"

    def test_case_insensitive(self, conn_minimal):
        result = find_contact_by_email(conn_minimal, "BOB@EXAMPLE.COM")
        assert result is not None
        assert result["id"] == "c2"

    def test_case_insensitive_mixed(self, conn_minimal):
        result = find_contact_by_email(conn_minimal, "AlIcE@ExAmPlE.CoM")
        assert result is not None
        assert result["id"] == "c1"

    def test_empty_array_returns_none(self, conn_minimal):
        result = find_contact_by_email(conn_minimal, "anyone@example.com")
        assert result is None

    def test_empty_string_returns_none(self, conn_minimal):
        result = find_contact_by_email(conn_minimal, "anyone@example.com")
        assert result is None

    def test_unknown_email_returns_none(self, conn_minimal):
        result = find_contact_by_email(conn_minimal, "nobody@example.com")
        assert result is None

    def test_no_false_positives_subdomain(self, conn_minimal):
        """alice@example.com should NOT match alice@example.com.evil."""
        conn_minimal.execute(
            "INSERT INTO contacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ('c5', 'Evil Alice', '', '',
             '[{"address": "alice@example.com.evil", "type": "primary"}]',
             '[]', '[]', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0, None, None),
        )
        result = find_contact_by_email(conn_minimal, "alice@example.com")
        assert result is not None
        assert result["id"] == "c1"  # Should find real match, not evil one

    def test_no_writes_digest_unchanged(self, conn_minimal, tmp_path):
        """find_contact_by_email must not modify the database."""
        import hashlib
        # Read current row digest
        h = hashlib.sha256()
        for row in conn_minimal.execute("SELECT * FROM contacts ORDER BY rowid"):
            h.update(repr(row).encode())
        before = h.hexdigest()

        # Call function
        find_contact_by_email(conn_minimal, "alice@example.com")

        # Read again
        h2 = hashlib.sha256()
        for row in conn_minimal.execute("SELECT * FROM contacts ORDER BY rowid"):
            h2.update(repr(row).encode())
        after = h2.hexdigest()

        assert before == after, "find_contact_by_email must not write"


# ============================================================
# merge_requester_into_contacts tests
# ============================================================

class TestMergeRequesterIntoContacts:
    """merge_requester_into_contacts(conn, grant) — Whitelist = source of truth."""

    def test_existing_contact_overwrites_name(self, conn_minimal):
        """If contact exists, Whitelist name overwrites."""
        grant = {
            "requester_email": "alice@example.com",
            "requester_name": "Alice Whitelist",
        }
        result = merge_requester_into_contacts(conn_minimal, grant)
        assert result is not None
        assert result["normalized_name"] == "Alice Whitelist"
        # Original name was "Alice Smith"
        assert result["id"] == "c1"

    def test_new_contact_created(self, conn_minimal):
        """If no contact matches, create new row."""
        grant = {
            "requester_email": "newperson@example.com",
            "requester_name": "New Person",
        }
        result = merge_requester_into_contacts(conn_minimal, grant)
        assert result is not None
        assert result["normalized_name"] == "New Person"
        # Should be a new id
        assert result["id"] != "c1"

    def test_new_contact_source_whitelist_merge(self, conn_minimal):
        """New contacts have source whitelist-merge."""
        grant = {
            "requester_email": "newperson@example.com",
            "requester_name": "New Person",
        }
        result = merge_requester_into_contacts(conn_minimal, grant)
        sources = json.loads(result.get("sources", "[]"))
        assert any("whitelist-merge" in str(s) for s in sources)

    def test_no_duplicate_created(self, conn_minimal):
        """Calling merge twice on same email should not create duplicate."""
        grant = {
            "requester_email": "newperson@example.com",
            "requester_name": "New Person",
        }
        r1 = merge_requester_into_contacts(conn_minimal, grant)
        r2 = merge_requester_into_contacts(conn_minimal, grant)
        assert r1["id"] == r2["id"], "Same email should return same contact"

    def test_empty_email_does_nothing(self, conn_minimal):
        """Grant with no requester_email should not create a contact."""
        grant = {
            "requester_email": "",
            "requester_name": "No Email",
        }
        result = merge_requester_into_contacts(conn_minimal, grant)
        assert result is None

    def test_writes_audit_row(self, conn_minimal):
        """merge must commit state + audit row on same commit."""
        grant = {
            "requester_email": "newperson@example.com",
            "requester_name": "New Person",
        }
        merge_requester_into_contacts(conn_minimal, grant)
        # Should have at least one audit log
        logs = conn_minimal.execute(
            "SELECT COUNT(*) FROM grant_logs"
        ).fetchone()[0]
        assert logs >= 1  # At least one log entry from merge

    def test_digest_unchanged_for_empty_email(self, conn_minimal, tmp_path):
        """merge with empty email must not modify database."""
        import hashlib
        h = hashlib.sha256()
        for row in conn_minimal.execute("SELECT * FROM contacts ORDER BY rowid"):
            h.update(repr(row).encode())
        before = h.hexdigest()

        grant = {"requester_email": "", "requester_name": "No Email"}
        merge_requester_into_contacts(conn_minimal, grant)

        h2 = hashlib.sha256()
        for row in conn_minimal.execute("SELECT * FROM contacts ORDER BY rowid"):
            h2.update(repr(row).encode())
        after = h2.hexdigest()

        assert before == after

    def test_email_stored_in_contacts(self, conn_minimal):
        """New contact should have emails column populated from grant."""
        grant = {
            "requester_email": "newperson@example.com",
            "requester_name": "New Person",
        }
        result = merge_requester_into_contacts(conn_minimal, grant)
        emails = json.loads(result.get("emails", "[]"))
        assert any(e.get("address") == "newperson@example.com" for e in emails)
