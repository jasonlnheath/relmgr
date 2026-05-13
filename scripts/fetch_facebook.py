#!/usr/bin/env python3
"""Fetch Facebook profile data and merge into RelMgr contacts.db.

Usage:
    python fetch_facebook.py <profile_name_or_url> [--cookies /path/to/cookies.txt]
    python fetch_facebook.py --batch contacts_fb_urls.txt

The script uses kevinzg/facebook-scraper to extract profile data, then merges
it into the existing contacts.db by matching on name/email.
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure facebook_scraper is available
try:
    from facebook_scraper import get_profile
except ImportError:
    print("ERROR: facebook-scraper not installed. Run: pip install facebook-scraper")
    sys.exit(1)

DB_PATH = Path(__file__).parent.parent / "contacts.db"
FB_COOKIES_PATH = Path(__file__).parent.parent / ".fb_cookies.txt"


def normalize_name(name: str) -> tuple[str, str]:
    """Split a full name into first and last."""
    if not name:
        return "", ""
    parts = name.strip().split()
    if len(parts) == 0:
        return "", ""
    elif len(parts) == 1:
        return parts[0], ""
    else:
        return parts[0], " ".join(parts[1:])


def parse_contact_info(contact_info_raw) -> list[dict]:
    """Parse the Contact Info dict from FB into normalized email/phone lists."""
    emails = []
    phones = []
    if not contact_info_raw or not isinstance(contact_info_raw, dict):
        return emails, phones

    for key, value in contact_info_raw.items():
        key_lower = key.lower()
        if "email" in key_lower and isinstance(value, str) and "@" in value:
            emails.append({"address": value.strip(), "type": key})
        elif ("phone" in key_lower or "mobile" in key_lower) and isinstance(value, str):
            # Clean phone number
            cleaned = re.sub(r"[^\d+()-]", "", value.strip())
            if cleaned and len(cleaned) >= 7:
                phones.append({"number": cleaned, "type": key})
    return emails, phones


def parse_work_education(work_raw) -> list[dict]:
    """Parse Work/Education into organization records."""
    orgs = []
    if not work_raw or not isinstance(work_raw, list):
        return orgs

    for item in work_raw:
        if not isinstance(item, dict):
            continue
        text = item.get("text", "")
        xp_type = item.get("type", "")
        year = item.get("year", "")

        # Try to extract org name and title from the text
        org_name = ""
        title = ""

        if " at " in text:
            parts = text.split(" at ", 1)
            org_name = parts[0].strip()
            rest = parts[1].strip()
            if " as " in rest:
                title_parts = rest.split(" as ", 1)
                title = title_parts[0].strip()
            else:
                title = rest
        elif " as " in text:
            # Format: "Company Name as Job Title"
            parts = text.split(" as ", 1)
            org_name = parts[0].strip()
            title = parts[1].strip()
        elif xp_type:
            org_name = xp_type
        else:
            org_name = text

        if org_name:
            orgs.append({"name": org_name, "title": title, "year": year})

    return orgs


def parse_relationship(relationship_raw) -> str:
    """Parse relationship status into a readable string."""
    if not isinstance(relationship_raw, dict):
        return ""
    to = relationship_raw.get("to", "")
    rtype = relationship_raw.get("type", "")
    since = relationship_raw.get("since", "")

    parts = []
    if rtype:
        parts.append(f"{rtype}")
    if to:
        parts.append(f"with {to}")
    if since:
        parts.append(since)
    return " | ".join(parts) if parts else ""


def fetch_profile(account: str, cookies_path: str | None = None) -> dict | None:
    """Fetch a Facebook profile and return normalized data."""
    # Clean account name from URL if needed
    if "facebook.com/" in account:
        # Extract the username/ID from URL
        match = re.search(r'facebook\.com/([^/?&]+)', account)
        if match:
            account = match.group(1)

    print(f"Fetching Facebook profile: {account}")

    kwargs = {}
    if cookies_path:
        kwargs["credentials"] = None  # We'll use cookies param instead
        kwargs["cookies"] = cookies_path
    else:
        # Try default cookie path
        if FB_COOKIES_PATH.exists():
            kwargs["cookies"] = str(FB_COOKIES_PATH)

    try:
        profile = get_profile(account, **kwargs)
    except Exception as e:
        print(f"ERROR fetching profile: {e}")
        return None

    if not profile or "Name" not in profile:
        print("No profile data returned (profile may be private or scraper failed)")
        return None

    # Parse contact info
    contact_info = profile.get("Contact Info", {})
    if isinstance(contact_info, dict):
        emails, phones = parse_contact_info(contact_info)
    else:
        emails, phones = [], []

    # Parse work/education
    work_raw = profile.get("Work, Education")
    orgs = parse_work_education(work_raw) if isinstance(work_raw, list) else []

    # Parse relationship
    relationship = parse_relationship(profile.get("Relationship"))

    # Build normalized contact record
    first_name, last_name = normalize_name(profile.get("Name", ""))

    return {
        "source": "facebook",
        "fb_account": account,
        "name": profile.get("Name", ""),
        "first_name": first_name,
        "last_name": last_name,
        "emails": emails,
        "phones": phones,
        "organizations": orgs,
        "about": profile.get("About", ""),
        "relationship": relationship,
        "places_lived": profile.get("Places lived", []),
        "family_members": profile.get("Family Members", []),
        "friend_count": profile.get("Friend_count"),
        "follower_count": profile.get("Follower_count"),
        "profile_picture": profile.get("profile_picture"),
        "raw": profile,  # Keep raw data for reference
    }


def merge_into_db(contact: dict) -> dict:
    """Merge a Facebook contact into the existing contacts.db.

    Returns a summary of what was done.
    """
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    now = datetime.now(timezone.utc).isoformat()

    fb_account = contact["fb_account"]
    fb_id = f"fb_{re.sub(r'[^a-zA-Z0-9_-]', '_', fb_account)}"

    # Try to find matching contact by email first
    matched_contact = None
    match_type = None

    for email_rec in contact.get("emails", []):
        addr = email_rec.get("address", "").lower().strip()
        if not addr:
            continue
        row = conn.execute(
            "SELECT * FROM contacts WHERE is_duplicate = 0 AND emails LIKE ?",
            (f"%{addr}%",),
        ).fetchone()
        if row:
            matched_contact = dict(row)
            match_type = "email"
            break

    # If no email match, try name match
    if not matched_contact:
        first = (contact.get("first_name") or "").lower().strip()
        last = (contact.get("last_name") or "").lower().strip()
        if first and last:
            rows = conn.execute(
                "SELECT * FROM contacts WHERE is_duplicate = 0",
            ).fetchall()
            for row in rows:
                rd = dict(row)
                rn_first = (rd.get("first_name") or "").lower().strip()
                rn_last = (rd.get("last_name") or "").lower().strip()
                if rn_first == first and rn_last == last:
                    matched_contact = rd
                    match_type = "name"
                    break

    summary = {
        "fb_account": fb_account,
        "action": None,
        "contact_id": None,
        "match_type": match_type,
        "fields_added": [],
    }

    if matched_contact:
        # Update existing contact
        cid = matched_contact["id"]
        summary["action"] = "updated_existing"
        summary["contact_id"] = cid

        # Merge emails (add new ones)
        existing_emails = json.loads(matched_contact.get("emails", "[]"))
        existing_email_addrs = {e.get("address", "").lower() for e in existing_emails}
        for email_rec in contact.get("emails", []):
            addr = email_rec.get("address", "").lower()
            if addr and addr not in existing_email_addrs:
                existing_emails.append(email_rec)
                summary["fields_added"].append(f"email: {addr}")

        # Merge phones
        existing_phones = json.loads(matched_contact.get("phones", "[]"))
        existing_phone_nums = {p.get("number", "") for p in existing_phones}
        for phone_rec in contact.get("phones", []):
            num = phone_rec.get("number", "")
            if num and num not in existing_phone_nums:
                existing_phones.append(phone_rec)
                summary["fields_added"].append(f"phone: {num}")

        # Merge organizations (add new ones)
        existing_orgs = json.loads(matched_contact.get("organizations", "[]"))
        existing_org_names = {o.get("name", "").lower() for o in existing_orgs}
        for org_rec in contact.get("organizations", []):
            name = org_rec.get("name", "").lower()
            if name and name not in existing_org_names:
                existing_orgs.append(org_rec)
                summary["fields_added"].append(f"org: {org_rec.get('name')}")

        # Update sources
        existing_sources = json.loads(matched_contact.get("sources", "[]"))
        if "facebook" not in existing_sources:
            existing_sources.append("facebook")

        conn.execute(
            """UPDATE contacts SET
                emails = ?, phones = ?, organizations = ?,
                sources = ?, updated_at = ?
               WHERE id = ?""",
            (
                json.dumps(existing_emails),
                json.dumps(existing_phones),
                json.dumps(existing_orgs),
                json.dumps(existing_sources),
                now,
                cid,
            ),
        )

        # Add source record with raw FB data
        conn.execute(
            """INSERT OR REPLACE INTO contact_sources
               (contact_id, source, source_id, raw_data, fetched_at)
               VALUES (?, ?, ?, ?, ?)""",
            (cid, "facebook", fb_account, json.dumps(contact.get("raw", {})), now),
        )

    else:
        # Create new contact
        cid = f"fb_{re.sub(r'[^a-zA-Z0-9_-]', '_', fb_account)}"
        summary["action"] = "created_new"
        summary["contact_id"] = cid

        conn.execute(
            """INSERT INTO contacts
               (id, normalized_name, first_name, last_name, emails, phones,
                organizations, sources, created_at, updated_at, is_duplicate)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (
                cid,
                contact.get("name", ""),
                contact.get("first_name"),
                contact.get("last_name"),
                json.dumps(contact.get("emails", [])),
                json.dumps(contact.get("phones", [])),
                json.dumps(contact.get("organizations", [])),
                json.dumps(["facebook"]),
                now,
                now,
            ),
        )

        conn.execute(
            """INSERT INTO contact_sources
               (contact_id, source, source_id, raw_data, fetched_at)
               VALUES (?, ?, ?, ?, ?)""",
            (cid, "facebook", fb_account, json.dumps(contact.get("raw", {})), now),
        )

    conn.commit()
    conn.close()
    return summary


def main():
    parser = argparse.ArgumentParser(description="Fetch Facebook profile and merge into RelMgr")
    parser.add_argument("target", nargs="?", help="Facebook profile name/URL or --batch file")
    parser.add_argument("--cookies", "-c", help="Path to cookies.txt file")
    parser.add_argument("--batch", "-b", help="Path to file with one FB URL/name per line")
    args = parser.parse_args()

    if not args.target and not args.batch:
        parser.print_help()
        sys.exit(1)

    # If batch mode, read URLs from file
    targets = []
    if args.batch:
        batch_path = Path(args.batch)
        if not batch_path.exists():
            print(f"ERROR: Batch file not found: {args.batch}")
            sys.exit(1)
        with open(batch_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        print(f"Batch mode: {len(targets)} profiles to fetch")
    elif args.target:
        targets = [args.target]

    results = []
    for target in targets:
        contact = fetch_profile(target, args.cookies)
        if contact:
            summary = merge_into_db(contact)
            results.append(summary)
            print(f"  ✓ {contact['name']} ({contact.get('fb_account')})")
            print(f"    Action: {summary['action']} | Match: {summary['match_type']}")
            if summary["fields_added"]:
                for field in summary["fields_added"]:
                    print(f"    Added: {field}")
        else:
            print(f"  ✗ Failed to fetch: {target}")
            results.append({"fb_account": target, "action": "failed", "error": "no data"})

    # Summary
    created = sum(1 for r in results if r.get("action") == "created_new")
    updated = sum(1 for r in results if r.get("action") == "updated_existing")
    failed = sum(1 for r in results if r.get("action") == "failed")

    print(f"\n{'='*50}")
    print(f"Facebook merge complete:")
    print(f"  Created: {created}")
    print(f"  Updated: {updated}")
    print(f"  Failed:  {failed}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
