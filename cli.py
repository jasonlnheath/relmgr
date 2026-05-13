#!/usr/bin/env python3
"""RelMgr CLI — contact management for email intelligence."""

import argparse
import json
import sys
from pathlib import Path

from store import init_db, get_all_contacts, find_duplicates, log_dedup
from fetcher import fetch_all
from normalizer import normalize_contact
from deduplicator import resolve_duplicates


def cmd_sync(args):
    """Fetch contacts from all enabled sources and deduplicate."""
    print("=== RelMgr Sync ===\n")

    # Initialize DB
    init_db()

    # Fetch from all sources
    raw_contacts = fetch_all()
    if not raw_contacts:
        print("No contacts fetched. Check source configuration.")
        return

    # Normalize
    normalized = []
    for raw in raw_contacts:
        source = "unknown"
        if "google" in str(raw.get("id", "")).lower():
            source = "google"
        elif "apple" in str(raw.get("id", "")).lower():
            source = "apple"
        elif "outlook" in str(raw.get("id", "")).lower():
            source = "outlook"
        elif "android" in str(raw.get("id", "")).lower():
            source = "android"

        contact = normalize_contact(raw, source)
        normalized.append(contact)

    print(f"\nNormalized {len(normalized)} contacts")

    # Deduplicate
    result = resolve_duplicates(normalized)
    print(f"\nDedup results: {result['merged']} merged, {result['flagged']} flagged, {result['total']} total")


def cmd_list(args):
    """List all contacts."""
    init_db()
    contacts = get_all_contacts()

    if not contacts:
        print("No contacts found. Run 'sync' first.")
        return

    for c in contacts:
        emails = ", ".join(e["address"] for e in json.loads(c["emails"])) if c.get("emails") else ""
        phones = ", ".join(p["number"] for p in json.loads(c["phones"]) if p.get("number")) if c.get("phones") else ""
        orgs = ", ".join(o["name"] for o in json.loads(c["organizations"])) if c.get("organizations") else ""

        print(f"\n{c['normalized_name']}")
        if emails:
            print(f"  Emails: {emails}")
        if phones:
            print(f"  Phones: {phones}")
        if orgs:
            print(f"  Org: {orgs}")


def cmd_dedup(args):
    """Run deduplication on existing contacts."""
    init_db()
    contacts = get_all_contacts()

    if not contacts:
        print("No contacts to deduplicate.")
        return

    from deduplicator import find_duplicates
    dups = find_duplicates(contacts)

    if not dups:
        print("No duplicates found.")
        return

    print(f"\nFound {len(dups)} duplicate pairs:\n")
    for primary, duplicate, score, match_type in dups:
        print(f"  [{match_type}] {score:.2f}")
        print(f"    Primary:   {primary['normalized_name']}")
        print(f"    Duplicate: {duplicate['normalized_name']}")
        print()


def cmd_export(args):
    """Export contacts to VCF file."""
    init_db()
    contacts = get_all_contacts()

    if not contacts:
        print("No contacts to export.")
        return

    output = args.output or "exports/contacts.vcf"
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as f:
        for c in contacts:
            emails = json.loads(c["emails"]) if c.get("emails") else []
            phones = json.loads(c["phones"]) if c.get("phones") else []
            orgs = json.loads(c["organizations"]) if c.get("organizations") else []

            f.write("BEGIN:VCARD\nVERSION:3.0\n")
            f.write(f"FN:{c['normalized_name']}\n")
            if c.get("first_name"):
                f.write(f"N:{c['last_name']};{c['first_name']};;;\n")
            for e in emails:
                f.write(f"EMAIL:{e['address']}\n")
            for p in phones:
                if p.get("number"):
                    f.write(f"TEL:{p['number']}\n")
            for o in orgs:
                f.write(f"ORG:{o['name']}\n")
                if o.get("title"):
                    f.write(f"TITLE:{o['title']}\n")
            f.write("END:VCARD\n")

    print(f"Exported {len(contacts)} contacts to {output}")


def main():
    parser = argparse.ArgumentParser(description="RelMgr — Relationship Manager")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # sync
    sync_parser = subparsers.add_parser("sync", help="Fetch and deduplicate contacts from all sources")

    # list
    subparsers.add_parser("list", help="List all contacts")

    # dedup
    subparsers.add_parser("dedup", help="Run deduplication check")

    # export
    export_parser = subparsers.add_parser("export", help="Export contacts to VCF")
    export_parser.add_argument("-o", "--output", help="Output file path (default: exports/contacts.vcf)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    commands = {
        "sync": cmd_sync,
        "list": cmd_list,
        "dedup": cmd_dedup,
        "export": cmd_export,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
