#!/usr/bin/env python3
"""Merge Gmail + Outlook contacts, normalize, deduplicate."""

import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from normalizer import normalize_contact


def main():
    db_path = Path(__file__).parent.parent / "contacts.db"

    # Initialize DB
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
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
            FOREIGN KEY (contact_id) REFERENCES contacts(id),
            UNIQUE(contact_id, source, source_id)
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

    # Load Gmail contacts
    gmail_path = Path(__file__).parent.parent / "exports" / "gmail_contacts.jsonl"
    gmail_contacts = []
    with open(gmail_path) as f:
        for line in f:
            gmail_contacts.append(json.loads(line))
    print(f"Loaded {len(gmail_contacts)} Gmail contacts")

    # Load Outlook contacts
    outlook_path = Path(__file__).parent.parent / "exports" / "outlook_contacts.jsonl"
    outlook_contacts = []
    with open(outlook_path) as f:
        for line in f:
            outlook_contacts.append(json.loads(line))
    print(f"Loaded {len(outlook_contacts)} Outlook contacts")

    # Normalize all contacts (sanitize IDs for SQLite)
    all_contacts = []
    for c in gmail_contacts:
        normalized = normalize_contact(c, "google")
        if normalized.get("emails") or normalized.get("phones"):
            normalized["id"] = re.sub(r'[^a-zA-Z0-9_\-]', '_', normalized.get("id", ""))
            all_contacts.append(normalized)

    for c in outlook_contacts:
        normalized = normalize_contact(c, "outlook")
        if normalized.get("emails") or normalized.get("phones"):
            normalized["id"] = re.sub(r'[^a-zA-Z0-9_\-]', '_', normalized.get("id", ""))
            all_contacts.append(normalized)

    print(f"\nTotal normalized: {len(all_contacts)}")

    # Count unique emails
    all_emails = set()
    for c in all_contacts:
        for e in c.get("emails", []):
            if e.get("address"):
                all_emails.add(e["address"])
    print(f"Unique email addresses: {len(all_emails)}")

    # Insert all contacts into DB
    now = datetime.now(timezone.utc).isoformat()
    for contact in all_contacts:
        cid = contact.get("id", str(len(all_contacts)))
        conn.execute(
            """INSERT OR REPLACE INTO contacts
               (id, normalized_name, first_name, last_name, emails, phones,
                organizations, sources, created_at, updated_at, is_duplicate, merged_into)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)""",
            (
                cid,
                contact.get("normalized_name", ""),
                contact.get("first_name"),
                contact.get("last_name"),
                json.dumps(contact.get("emails", [])),
                json.dumps(contact.get("phones", [])),
                json.dumps(contact.get("organizations", [])),
                json.dumps(contact.get("sources", [])),
                now,
                now,
            ),
        )

        # Insert source records
        for src in contact.get("sources_list", []):
            conn.execute(
                """INSERT OR REPLACE INTO contact_sources (contact_id, source, source_id, raw_data, fetched_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (cid, src["source"], src["source_id"], json.dumps(src.get("raw_data", {})), now),
            )

    conn.commit()
    print("Contacts inserted into database")

    # Now run deduplication in-memory
    contacts = conn.execute("SELECT * FROM contacts WHERE is_duplicate = 0").fetchall()

     # Simple dedup: group by email, keep the one with most data
    email_map = {}  # email -> contact_id
    for c in contacts:
        row_dict = dict(c)
        emails = json.loads(row_dict["emails"]) if row_dict.get("emails") else []
        for e in emails:
            addr = e.get("address", "").lower().strip()
            if addr:
                if addr not in email_map:
                    email_map[addr] = []
                email_map[addr].append(row_dict["id"])

    # Find duplicates (same email)
    merged = 0
    flagged = 0
    for email, ids in email_map.items():
        if len(ids) > 1:
            # Keep the first one, mark others as duplicate
            primary_id = ids[0]
            for dup_id in ids[1:]:
                conn.execute(
                    "UPDATE contacts SET is_duplicate = 1, merged_into = ? WHERE id = ?",
                    (primary_id, dup_id),
                )
                conn.execute(
                    "INSERT INTO dedup_log (primary_contact_id, duplicate_contact_id, match_type, confidence, resolved_by, created_at) VALUES (?, ?, 'email', 1.0, 'auto', ?)",
                    (primary_id, dup_id, now),
                )
                merged += 1

    conn.commit()

    # Get final count
    final_count = conn.execute("SELECT COUNT(*) FROM contacts WHERE is_duplicate = 0").fetchone()[0]
    print(f"\nDedup results:")
    print(f"  Merged: {merged}")
    print(f"  Final unique contacts: {final_count}")

    # Save merged contacts to JSONL
    rows = conn.execute("SELECT * FROM contacts WHERE is_duplicate = 0 ORDER BY normalized_name").fetchall()
    output_path = Path(__file__).parent.parent / "exports" / "all_contacts.jsonl"
    with open(output_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")

    print(f"\nSaved {len(rows)} unique contacts to {output_path}")
    conn.close()


if __name__ == "__main__":
    main()
