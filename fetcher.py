"""Contact fetching from multiple sources."""

import csv
import json
import os
from pathlib import Path
from typing import Optional


def fetch_google_contacts(credentials_path: str = None) -> list[dict]:
    """Fetch contacts from Google People API.

    Uses existing Gmail OAuth token if credentials_path not specified.
    """
    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        if credentials_path is None:
            # Try default location
            for p in [
                os.path.expanduser("~/.hermes/google_token.json"),
                os.path.expanduser("~/.config/gh/google_token.json"),
            ]:
                if os.path.exists(p):
                    credentials_path = p
                    break

        if not credentials_path or not os.path.exists(credentials_path):
            print("[google] No credentials found. Skipping.")
            return []

        creds = Credentials.from_authorized_user_file(credentials_path)
        service = build("people", "v1", credentials=creds)

        contacts = []
        page_token = None
        while True:
            result = service.people().connections().list(
                resourceName="me",
                pageSize=500,
                pageToken=page_token,
                personFields="names,emailAddresses,phoneNumbers,organizations,nicknames,metadata",
            ).execute()

            for person in result.get("connections", []):
                contact = _parse_google_person(person)
                if contact:
                    contacts.append(contact)

            page_token = result.get("nextPageToken")
            if not page_token:
                break

        print(f"[google] Fetched {len(contacts)} contacts")
        return contacts

    except ImportError as e:
        print(f"[google] Missing dependency: {e}")
        return []
    except Exception as e:
        print(f"[google] Error: {e}")
        return []


def _parse_google_person(person: dict) -> Optional[dict]:
    """Parse a Google People API person record into normalized format."""
    name = ""
    for n in person.get("names", []):
        if n.get("metadata", {}).get("primary"):
            name = n.get("displayName", "") or n.get("givenName", "") + " " + n.get("familyName", "")
            break
    if not name:
        names = person.get("names", [])
        if names:
            name = names[0].get("displayName", "")

    emails = []
    for e in person.get("emailAddresses", []):
        emails.append({"value": e.get("value", ""), "type": e.get("metadata", {}).get("primary", False) and "primary" or "other"})

    phones = []
    for p in person.get("phoneNumbers", []):
        phones.append({"value": p.get("value", ""), "type": p.get("metadata", {}).get("primary", False) and "primary" or "other"})

    orgs = []
    for o in person.get("organizations", []):
        orgs.append({
            "name": o.get("name", ""),
            "title": o.get("title", ""),
        })

    return {
        "id": person.get("resourceName", ""),
        "name": name,
        "emails": emails,
        "phones": phones,
        "organizations": orgs,
    }


def fetch_apple_contacts(csv_path: str = None) -> list[dict]:
    """Fetch contacts from Apple/iCloud via CSV or VCF export.

    Method 1: Export from iCloud.com → Contacts → Select All → Export vCard
    Method 2: CalDAV sync (requires carddav or cadaver)
    """
    if csv_path is None:
        # Try common export locations
        for p in [
            os.path.expanduser("~/Downloads/contacts.vcf"),
            os.path.expanduser("~/Desktop/contacts.vcf"),
            os.path.expanduser("~/Documents/contacts.vcf"),
        ]:
            if os.path.exists(p):
                csv_path = p
                break

    if not csv_path or not os.path.exists(csv_path):
        print("[apple] No VCF file found. Export from iCloud.com → Contacts → Export vCard.")
        return []

    contacts = _parse_vcf(csv_path)
    print(f"[apple] Fetched {len(contacts)} contacts from {csv_path}")
    return contacts


def fetch_outlook_contacts(client_id: str = None, tenant_id: str = None, client_secret: str = None) -> list[dict]:
    """Fetch contacts from Microsoft Graph API."""
    client_id = client_id or os.getenv("OUTLOOK_CLIENT_ID")
    tenant_id = tenant_id or os.getenv("OUTLOOK_TENANT_ID")
    client_secret = client_secret or os.getenv("OUTLOOK_CLIENT_SECRET")

    if not all([client_id, tenant_id]):
        print("[outlook] Missing credentials. Set OUTLOOK_CLIENT_ID and OUTLOOK_TENANT_ID env vars.")
        return []

    try:
        import msal
        import requests

        # Acquire token
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id, authority=authority, client_credential=client_secret
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

        if "access_token" not in result:
            print(f"[outlook] Auth failed: {result.get('error_description', 'unknown')}")
            return []

        token = result["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        contacts = []
        url = "https://graph.microsoft.com/v1.0/me/contacts?$top=500"
        while url:
            resp = requests.get(url, headers=headers)
            if resp.status_code != 200:
                print(f"[outlook] API error: {resp.status_code}")
                break

            data = resp.json()
            for person in data.get("value", []):
                contact = _parse_outlook_person(person)
                if contact:
                    contacts.append(contact)

            url = data.get("@odata.nextLink")

        print(f"[outlook] Fetched {len(contacts)} contacts")
        return contacts

    except ImportError as e:
        print(f"[outlook] Missing dependency: {e}")
        return []
    except Exception as e:
        print(f"[outlook] Error: {e}")
        return []


def _parse_outlook_person(person: dict) -> Optional[dict]:
    """Parse a Microsoft Graph contact record."""
    name = person.get("givenName", "") + " " + person.get("surname", "")
    name = name.strip() or person.get("displayName", "")

    emails = [{"value": e["address"], "type": e.get("type", "other")} for e in person.get("emailAddresses", [])]
    phones = [{"value": p["number"], "type": p.get("type", "other")} for p in person.get("phoneNumbers", [])]
    orgs = []
    if person.get("companyName"):
        orgs.append({"name": person["companyName"], "title": person.get("jobTitle", "")})

    return {
        "id": person.get("id", ""),
        "name": name,
        "emails": emails,
        "phones": phones,
        "organizations": orgs,
    }


def fetch_android_contacts(vcf_path: str = None, csv_path: str = None) -> list[dict]:
    """Fetch contacts from Android via exported VCF or CSV file.

    Export from phone: Contacts app → Settings → Import/Export → Export to storage
    """
    if vcf_path is None and csv_path is None:
        # Try common locations
        for p in [
            os.path.expanduser("~/Downloads/contacts.vcf"),
            os.path.expanduser("~/Documents/contacts.vcf"),
            os.path.expanduser("/sdcard/Download/contacts.vcf"),
        ]:
            if os.path.exists(p):
                vcf_path = p
                break

    if vcf_path and os.path.exists(vcf_path):
        contacts = _parse_vcf(vcf_path)
        print(f"[android] Fetched {len(contacts)} contacts from VCF")
        return contacts

    if csv_path and os.path.exists(csv_path):
        contacts = _parse_csv(csv_path)
        print(f"[android] Fetched {len(contacts)} contacts from CSV")
        return contacts

    print("[android] No VCF/CSV file found. Export from phone's Contacts app.")
    return []


def _parse_vcf(path: str) -> list[dict]:
    """Parse a VCF (vCard) file into contact dicts."""
    contacts = []
    current = {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n\r")

                # Handle line folding (continuation lines starting with space/tab)
                if line.startswith(" ") or line.startswith("\t"):
                    if current.get("_buffer"):
                        key = current.pop("_buffer")
                        current[key] += line[1:]
                    continue

                if line == "BEGIN:VCARD":
                    current = {}
                elif line == "END:VCARD":
                    contact = _vcf_to_contact(current)
                    if contact and contact.get("name"):
                        contacts.append(contact)
                    current = {}
                else:
                    if ":" in line:
                        key, _, value = line.partition(":")
                        # Handle parameters (e.g., TYPE=HOME;VALUE=uri)
                        params = {}
                        if ";" in key:
                            kparts = key.split(";")
                            key = kparts[0]
                            for p in kparts[1:]:
                                if "=" in p:
                                    pk, pv = p.split("=", 1)
                                    params[pk] = pv
                        current.setdefault(key, []).append(value)

    except Exception as e:
        print(f"[vcf] Parse error: {e}")

    return contacts


def _vcf_to_contact(vcard: dict) -> Optional[dict]:
    """Convert a VCF dict to our normalized contact format."""
    n_fields = vcard.get("N", [])
    fn_field = vcard.get("FN", [])

    # Build name from FN or N fields
    name = ""
    first_name = ""
    last_name = ""

    if fn_field:
        name = str(fn_field[0]) if isinstance(fn_field, list) else fn_field
    elif n_fields:
        n_parts = str(n_fields[0]).split(";") if isinstance(n_fields, list) else [str(n_fields)]
        if len(n_parts) >= 2:
            last_name = n_parts[-1] if n_parts[-1] else n_parts[0]
            first_name = n_parts[0] if len(n_parts) > 0 else ""
            name = f"{last_name}, {first_name}"

    emails = []
    for e in vcard.get("EMAIL", []):
        addr = str(e) if isinstance(e, str) else str(e.get("value", ""))
        emails.append({"value": addr, "type": "other"})

    phones = []
    for p in vcard.get("TEL", []):
        num = str(p) if isinstance(p, str) else str(p.get("value", ""))
        phones.append({"value": num, "type": "other"})

    orgs = []
    org = vcard.get("ORG", [])
    if org:
        org_name = str(org[0]) if isinstance(org, list) else org
        title = vcard.get("TITLE", [])[0] if vcard.get("TITLE") else ""
        orgs.append({"name": org_name, "title": str(title)})

    return {
        "id": str(vcard.get("UID", [""])[0]) if vcard.get("UID") else "",
        "name": name,
        "first_name": first_name,
        "last_name": last_name,
        "emails": emails,
        "phones": phones,
        "organizations": orgs,
    }


def _parse_csv(path: str) -> list[dict]:
    """Parse a CSV contact export (Android default format)."""
    contacts = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = ""
                first = row.get("First name", row.get("first_name", ""))
                last = row.get("Last name", row.get("last_name", ""))
                if first and last:
                    name = f"{last}, {first}"
                elif first:
                    name = first
                elif last:
                    name = last

                emails = []
                for i in range(1, 4):
                    email = row.get(f"Email {i}", row.get(f"email{i}"))
                    if email:
                        emails.append({"value": str(email), "type": "other"})

                phones = []
                for i in range(1, 5):
                    phone = row.get(f"Phone {i}", row.get(f"phone{i}"))
                    if phone:
                        phones.append({"value": str(phone), "type": "other"})

                contacts.append({
                    "id": f"android_{len(contacts)}",
                    "name": name,
                    "first_name": first,
                    "last_name": last,
                    "emails": emails,
                    "phones": phones,
                    "organizations": [],
                })
    except Exception as e:
        print(f"[csv] Parse error: {e}")

    return contacts


def fetch_all(sources: dict = None) -> list[dict]:
    """Fetch contacts from all enabled sources.

    Returns a flat list of normalized contact dicts.
    """
    if sources is None:
        from config import SOURCES
        sources = SOURCES

    all_contacts = []

    # Google
    if sources.get("google", {}).get("enabled"):
        creds = sources["google"].get("credentials_file")
        all_contacts.extend(fetch_google_contacts(creds))

    # Apple
    if sources.get("apple", {}).get("enabled"):
        csv_path = sources["apple"].get("csv_path")
        all_contacts.extend(fetch_apple_contacts(csv_path))

    # Outlook
    if sources.get("outlook", {}).get("enabled"):
        all_contacts.extend(fetch_outlook_contacts())

    # Android
    if sources.get("android", {}).get("enabled"):
        vcf = sources["android"].get("vcf_path")
        csv = sources["android"].get("csv_path")
        all_contacts.extend(fetch_android_contacts(vcf, csv))

    return all_contacts
