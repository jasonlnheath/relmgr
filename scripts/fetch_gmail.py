#!/usr/bin/env python3
"""Fetch contacts from Gmail/Google People API using existing OAuth token."""

import json
import os
import sys
from pathlib import Path

# Add parent dir to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


def fetch_contacts(credentials_path: str = None) -> list[dict]:
    if credentials_path is None:
        credentials_path = "/home/jason/.hermes/google_token.json"

    if not credentials_path or not os.path.exists(credentials_path):
        print("ERROR: No OAuth token found. Run Gmail onboarding first.")
        return []

    creds = Credentials.from_authorized_user_file(credentials_path)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh()
        else:
            print("ERROR: Token expired and cannot refresh. Re-authenticate.")
            return []

    service = build("people", "v1", credentials=creds)

    contacts = []
    page_token = None
    total_fetched = 0

    while True:
        result = service.people().connections().list(
            resourceName="people/me",
            pageSize=500,
            pageToken=page_token,
            personFields="names,emailAddresses,phoneNumbers,organizations,nicknames,metadata,birthdays,biographies,urls,imClients,addresses,genders",
        ).execute()

        people = result.get("connections", [])
        for person in people:
            contact = _parse_person(person)
            if contact and (contact.get("name") or contact.get("emails")):
                contacts.append(contact)
                total_fetched += 1

        page_token = result.get("nextPageToken")
        if not page_token:
            break

    print(f"Fetched {total_fetched} contacts from Google Contacts")
    return contacts


def _parse_person(person: dict) -> dict:
    """Parse a Google People API person into our normalized format."""
    # Name
    name = ""
    first_name = ""
    last_name = ""
    for n in person.get("names", []):
        if n.get("metadata", {}).get("primary"):
            name = n.get("displayName", "") or f"{n.get('givenName', '')} {n.get('familyName', '')}".strip()
            first_name = n.get("givenName", "")
            last_name = n.get("familyName", "")
            break
    if not name:
        names = person.get("names", [])
        if names:
            name = names[0].get("displayName", "")

    # Emails
    emails = []
    for e in person.get("emailAddresses", []):
        emails.append({
            "value": e.get("value", ""),
            "type": "primary" if e.get("metadata", {}).get("primary") else "other",
        })

    # Phones
    phones = []
    for p in person.get("phoneNumbers", []):
        phones.append({
            "value": p.get("value", ""),
            "type": "primary" if p.get("metadata", {}).get("primary") else "other",
        })

    # Organizations
    orgs = []
    for o in person.get("organizations", []):
        orgs.append({
            "name": o.get("name", ""),
            "title": o.get("title", ""),
        })

    # Nicknames
    nicknames = [n.get("displayName", "") for n in person.get("nicknames", [])]

    # URLs (social profiles, etc.)
    urls = [{"value": u.get("value", ""), "type": u.get("type", "other")} for u in person.get("urls", [])]

    # Addresses
    addresses = []
    for a in person.get("addresses", []):
        addresses.append({
            "formatted": a.get("formatted", ""),
            "type": a.get("metadata", {}).get("primary") and "primary" or "other",
        })

    return {
        "id": person.get("resourceName", ""),
        "name": name.strip() if name else "",
        "first_name": first_name,
        "last_name": last_name,
        "emails": emails,
        "phones": phones,
        "organizations": orgs,
        "nicknames": nicknames,
        "urls": urls,
        "addresses": addresses,
    }


def main():
    contacts = fetch_contacts()

    if not contacts:
        print("No contacts found in Google Contacts.")
        sys.exit(1)

    # Save to JSONL
    output_path = Path(__file__).parent.parent / "exports" / "gmail_contacts.jsonl"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        for c in contacts:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"Saved {len(contacts)} contacts to {output_path}")


if __name__ == "__main__":
    main()
