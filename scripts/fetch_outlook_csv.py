#!/usr/bin/env python3
"""Parse Outlook CSV export and normalize contacts."""

import csv
import json
import sys
from pathlib import Path


def parse_csv(path: str) -> list[dict]:
    contacts = []
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            first = (row.get("First Name", "") or "").strip()
            last = (row.get("Last Name", "") or "").strip()
            middle = (row.get("Middle Name", "") or "").strip()
            prefix = (row.get("Title", "") or "").strip()
            suffix = (row.get("Suffix", "") or "").strip()

            full_name = f"{prefix} {first} {middle} {last} {suffix}".strip()
            if not full_name:
                continue

            emails = []
            for i, key in enumerate(["E-mail Address", "E-mail 2 Address", "E-mail 3 Address"], 1):
                email = (row.get(key, "") or "").strip()
                if email:
                    emails.append({"value": email.lower(), "type": "primary" if i == 1 else "other"})

            phones = []
            phone_keys = [
                ("Home Phone", "home"),
                ("Business Phone", "work"),
                ("Mobile Phone", "mobile"),
                ("Home Phone 2", "home"),
                ("Business Phone 2", "work"),
                ("Car Phone", "car"),
                ("Other Phone", "other"),
                ("Primary Phone", "primary"),
                ("Pager", "pager"),
                ("Business Fax", "fax"),
                ("Home Fax", "fax"),
                ("Other Fax", "fax"),
            ]
            for key, ptype in phone_keys:
                phone = (row.get(key, "") or "").strip()
                if phone:
                    phones.append({"value": phone, "type": ptype})

            orgs = []
            company = (row.get("Company", "") or "").strip()
            title = (row.get("Job Title", "") or "").strip()
            if company:
                orgs.append({"name": company, "title": title})

            addr = (row.get("Business Street", "") or "").strip()
            city = (row.get("Business City", "") or "").strip()
            state = (row.get("Business State", "") or "").strip()
            zip_code = (row.get("Business Postal Code", "") or "").strip()
            country = (row.get("Business Country/Region", "") or "").strip()
            addresses = []
            if addr or city:
                full_addr = f"{addr}, {city}, {state} {zip_code}".strip(", ")
                if country and country != "United States":
                    full_addr += f", {country}"
                addresses.append({"formatted": full_addr, "type": "work"})

            contacts.append({
                "id": f"outlook_{len(contacts)}",
                "name": full_name,
                "first_name": first,
                "last_name": last,
                "emails": emails,
                "phones": phones,
                "organizations": orgs,
                "addresses": addresses,
            })

    return contacts


def main():
    csv_path = "/mnt/c/Users/jason/OneDrive/Documents/Contacts/contacts.csv"
    contacts = parse_csv(csv_path)
    print(f"Parsed {len(contacts)} contacts from Outlook CSV")

    output_path = Path(__file__).parent.parent / "exports" / "outlook_contacts.jsonl"
    with open(output_path, "w", encoding="utf-8") as f:
        for c in contacts:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"Saved to {output_path}")


if __name__ == "__main__":
    main()
