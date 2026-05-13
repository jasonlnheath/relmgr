#!/usr/bin/env python3
"""Merge Gmail + Outlook + Apple contacts, normalize, deduplicate."""

import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    db_path = Path(__file__).parent.parent / "contacts.db"

    # Initialize DB (drop old tables for clean merge)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=OFF")  # Disable during schema rebuild
    conn.executescript("""
        DROP TABLE IF EXISTS contacts;
        DROP TABLE IF EXISTS contact_sources;
        DROP TABLE IF EXISTS dedup_log;

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
        );

        CREATE TABLE contact_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id TEXT NOT NULL,
            source TEXT NOT NULL,
            source_id TEXT NOT NULL,
            raw_data TEXT,
            fetched_at TEXT NOT NULL,
            FOREIGN KEY (contact_id) REFERENCES contacts(id),
            UNIQUE(contact_id, source, source_id)
        );

        CREATE TABLE dedup_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            primary_contact_id TEXT NOT NULL,
            duplicate_contact_id TEXT NOT NULL,
            match_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            resolved_by TEXT DEFAULT 'auto',
            created_at TEXT NOT NULL
        );

        CREATE INDEX idx_sources_contact ON contact_sources(contact_id);
        CREATE INDEX idx_sources_source ON contact_sources(source);
        CREATE INDEX idx_dedup_primary ON dedup_log(primary_contact_id);
    """)
    conn.execute("PRAGMA foreign_keys=ON")  # Re-enable after rebuild
    conn.commit()

    # Load all sources
    all_contacts = []

    # Gmail
    gmail_path = Path(__file__).parent.parent / "exports" / "gmail_contacts.jsonl"
    if gmail_path.exists():
        with open(gmail_path) as f:
            for line in f:
                c = json.loads(line)
                cid = re.sub(r'[^a-zA-Z0-9_\-]', '_', c.get("id", ""))
                emails = [{"address": e["value"], "type": e.get("type", "other")} for e in c.get("emails", [])]
                phones = [{"number": p["value"], "type": p.get("type", "other")} for p in c.get("phones", [])]
                orgs = [{"name": o.get("name", ""), "title": o.get("title", "")} for o in c.get("organizations", [])]
                all_contacts.append({
                    "id": cid,
                    "normalized_name": f"{c.get('first_name', '')} {c.get('last_name', '')}".strip(),
                    "first_name": c.get("first_name"),
                    "last_name": c.get("last_name"),
                    "emails": emails,
                    "phones": phones,
                    "organizations": orgs,
                    "sources": ["google"],
                })
        print(f"Loaded {sum(1 for _ in open(gmail_path))} Gmail contacts")

    # Outlook
    outlook_path = Path(__file__).parent.parent / "exports" / "outlook_contacts.jsonl"
    if outlook_path.exists():
        with open(outlook_path) as f:
            for line in f:
                c = json.loads(line)
                cid = re.sub(r'[^a-zA-Z0-9_\-]', '_', c.get("id", ""))
                emails = [{"address": e["value"], "type": e.get("type", "other")} for e in c.get("emails", [])]
                phones = [{"number": p["value"], "type": p.get("type", "other")} for p in c.get("phones", [])]
                orgs = [{"name": o.get("name", ""), "title": o.get("title", "")} for o in c.get("organizations", [])]
                all_contacts.append({
                    "id": cid,
                    "normalized_name": c.get("name", ""),
                    "first_name": c.get("first_name"),
                    "last_name": c.get("last_name"),
                    "emails": emails,
                    "phones": phones,
                    "organizations": orgs,
                    "sources": ["outlook"],
                })
        print(f"Loaded {sum(1 for _ in open(outlook_path))} Outlook contacts")

    # Apple
    apple_path = Path(__file__).parent.parent / "exports" / "apple_contacts.jsonl"
    if apple_path.exists():
        with open(apple_path) as f:
            for line in f:
                c = json.loads(line)
                cid = re.sub(r'[^a-zA-Z0-9_\-]', '_', c.get("id", ""))
                emails = [{"address": e["value"], "type": e.get("type", "other")} for e in c.get("emails", [])]
                phones = [{"number": p["value"], "type": p.get("type", "other")} for p in c.get("phones", [])]
                orgs = [{"name": o.get("name", ""), "title": o.get("title", "")} for o in c.get("organizations", [])]
                all_contacts.append({
                    "id": cid,
                    "normalized_name": c.get("name", ""),
                    "first_name": c.get("first_name"),
                    "last_name": c.get("last_name"),
                    "emails": emails,
                    "phones": phones,
                    "organizations": orgs,
                    "sources": ["apple"],
                })
        print(f"Loaded {sum(1 for _ in open(apple_path))} Apple contacts")

    print(f"\nTotal contacts to deduplicate: {len(all_contacts)}")

    # Count unique emails
    email_map = {}  # email -> list of contact_ids
    for c in all_contacts:
        for e in c.get("emails", []):
            addr = e.get("address", "").lower().strip()
            if addr:
                if addr not in email_map:
                    email_map[addr] = []
                email_map[addr].append(c["id"])
    print(f"Unique email addresses: {len(email_map)}")

    # Insert all into DB
    now = datetime.now(timezone.utc).isoformat()
    for contact in all_contacts:
        cid = contact["id"]
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
    for contact in all_contacts:
        cid = contact["id"]
        for src in contact.get("sources", []):
            conn.execute(
                """INSERT OR REPLACE INTO contact_sources (contact_id, source, source_id, raw_data, fetched_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (cid, src, f"{src}_{cid}", json.dumps(contact), now),
            )

    conn.commit()
    print("Contacts inserted into database")

    # Deduplicate by email
    merged = 0
    flagged = 0
    for email, ids in email_map.items():
        if len(ids) > 1:
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

    # Also check fuzzy name matches (same first+last, different sources)
    name_map = {}  # (first, last) -> list of contact_ids
    for row in conn.execute("SELECT * FROM contacts WHERE is_duplicate = 0").fetchall():
        rd = dict(row)
        key = (rd.get("first_name", "") or "").lower().strip(), (rd.get("last_name", "") or "").lower().strip()
        if key[0] and key[1]:
            if key not in name_map:
                name_map[key] = []
            name_map[key].append(rd)

    for (first, last), rows in name_map.items():
        if len(rows) > 1:
            # Check if they're from different sources
            sources = set()
            for r in rows:
                sources.update(json.loads(r["sources"]))
            if len(sources) > 1:
                # Potential duplicate across sources - keep the one with most data
                primary = max(rows, key=lambda r: len(r.get("emails", "[]")) + len(r.get("phones", "[]")))
                for r in rows:
                    if r["id"] != primary["id"]:
                        conn.execute(
                            "UPDATE contacts SET is_duplicate = 1, merged_into = ? WHERE id = ?",
                            (primary["id"], r["id"]),
                        )
                        conn.execute(
                            "INSERT INTO dedup_log (primary_contact_id, duplicate_contact_id, match_type, confidence, resolved_by, created_at) VALUES (?, ?, 'name', 0.85, 'auto', ?)",
                            (primary["id"], r["id"], now),
                        )
                        flagged += 1

    conn.commit()

    # Final stats
    total = conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
    unique = conn.execute("SELECT COUNT(*) FROM contacts WHERE is_duplicate = 0").fetchone()[0]
    dups = conn.execute("SELECT COUNT(*) FROM contacts WHERE is_duplicate = 1").fetchone()[0]

    print(f"\nDedup results:")
    print(f"  Email duplicates merged: {merged}")
    print(f"  Name duplicates merged: {flagged}")
    print(f"  Total contacts: {total}")
    print(f"  Unique (non-duplicate): {unique}")
    print(f"  Duplicates: {dups}")

    # Source breakdown of final contacts
    sources_count = {"google": 0, "outlook": 0, "apple": 0}
    for row in conn.execute("SELECT * FROM contacts WHERE is_duplicate = 0").fetchall():
        rd = dict(row)
        for src in json.loads(rd["sources"]):
            if src in sources_count:
                sources_count[src] += 1

    print(f"\nSource breakdown (unique contacts):")
    for src, count in sources_count.items():
        print(f"  {src}: {count}")

    # Save to JSONL
    rows = conn.execute("SELECT * FROM contacts WHERE is_duplicate = 0 ORDER BY normalized_name").fetchall()
    output_path = Path(__file__).parent.parent / "exports" / "all_contacts.jsonl"
    with open(output_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")

    print(f"\nSaved {len(rows)} unique contacts to {output_path}")
    conn.close()


if __name__ == "__main__":
    main()
