"""SQLite persistence layer for RelMgr contacts."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import DB_PATH


def _connect(db_path: Path = None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path or DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path = None) -> None:
    """Initialize database schema (idempotent)."""
    conn = _connect(db_path)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS contacts (
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
            );

            CREATE TABLE IF NOT EXISTS contact_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id TEXT NOT NULL,
                source TEXT NOT NULL,
                source_id TEXT NOT NULL,
                raw_data TEXT,
                fetched_at TEXT NOT NULL,
                FOREIGN KEY (contact_id) REFERENCES contacts(id)
            );

            CREATE TABLE IF NOT EXISTS dedup_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                primary_contact_id TEXT NOT NULL,
                duplicate_contact_id TEXT NOT NULL,
                match_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                resolved_by TEXT DEFAULT 'auto',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sources_contact ON contact_sources(contact_id);
            CREATE INDEX IF NOT EXISTS idx_sources_source ON contact_sources(source);
            CREATE INDEX IF NOT EXISTS idx_dedup_primary ON dedup_log(primary_contact_id);
        """)
        conn.commit()
    finally:
        conn.close()


def upsert_contact(contact: dict, db_path: Path = None) -> str:
    """Insert or update a contact. Returns contact id."""
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        cid = contact.get("id", str(uuid.uuid4()))

        conn.execute(
            """INSERT INTO contacts
               (id, normalized_name, first_name, last_name, emails, phones,
                organizations, sources, created_at, updated_at, is_duplicate, merged_into)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   normalized_name=excluded.normalized_name,
                   first_name=excluded.first_name,
                   last_name=excluded.last_name,
                   emails=excluded.emails,
                   phones=excluded.phones,
                   organizations=excluded.organizations,
                   sources=excluded.sources,
                   updated_at=excluded.updated_at,
                   is_duplicate=excluded.is_duplicate,
                   merged_into=excluded.merged_into""",
            (
                cid,
                contact.get("normalized_name", ""),
                contact.get("first_name"),
                contact.get("last_name"),
                json.dumps(contact.get("emails", [])),
                json.dumps(contact.get("phones", [])),
                json.dumps(contact.get("organizations", [])),
                json.dumps(contact.get("sources", [])),
                contact.get("created_at", now),
                now,
                contact.get("is_duplicate", 0),
                contact.get("merged_into"),
            ),
        )

        # Upsert source records
        for src in contact.get("sources_list", []):
            conn.execute(
                """INSERT INTO contact_sources (contact_id, source, source_id, raw_data, fetched_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET
                       contact_id=excluded.contact_id,
                       raw_data=excluded.raw_data,
                       fetched_at=excluded.fetched_at""",
                (cid, src["source"], src["source_id"], json.dumps(src.get("raw_data", {})), now),
            )

        conn.commit()
        return cid
    finally:
        conn.close()


def get_contact(contact_id: str, db_path: Path = None) -> Optional[dict]:
    """Fetch a single contact by ID."""
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def find_by_email(email: str, db_path: Path = None) -> list[dict]:
    """Find contacts matching an email address (case-insensitive)."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM contacts WHERE emails LIKE ? AND is_duplicate = 0",
            (f"%{email}%",),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def find_duplicates(db_path: Path = None) -> list[dict]:
    """Return all contacts flagged as duplicates."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM contacts WHERE is_duplicate = 1"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_contacts(db_path: Path = None) -> list[dict]:
    """Return all non-duplicate contacts."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM contacts WHERE is_duplicate = 0 ORDER BY normalized_name"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def log_dedup(primary_id: str, duplicate_id: str, match_type: str, confidence: float, resolved_by: str = "auto", db_path: Path = None) -> None:
    """Log a deduplication event."""
    conn = _connect(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO dedup_log (primary_contact_id, duplicate_contact_id, match_type, confidence, resolved_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (primary_id, duplicate_id, match_type, confidence, resolved_by, now),
        )
        conn.commit()
    finally:
        conn.close()


def merge_contacts(primary_id: str, duplicate_id: str, db_path: Path = None) -> None:
    """Mark a contact as merged into another."""
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE contacts SET is_duplicate = 1, merged_into = ? WHERE id = ?",
            (primary_id, duplicate_id),
        )
        log_dedup(primary_id, duplicate_id, "manual", 1.0, "manual", db_path)
        conn.commit()
    finally:
        conn.close()
