#!/usr/bin/env python3
"""Parse Apple/iCloud VCF export into normalized contact dicts."""

import csv
import json
import re
import sys
from pathlib import Path


def parse_vcf(path: str) -> list[dict]:
    """Parse a VCF file into a list of contact dicts."""
    contacts = []
    current = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n").rstrip("\r")

            # Handle line folding (continuation lines start with space/tab)
            if line and line[0] in (" ", "\t"):
                if "data" in current:
                    current["data"] += line[1:]
                continue

            if line == "BEGIN:VCARD":
                current = {"id": f"apple_{len(contacts)}"}
                continue

            if line == "END:VCARD":
                if "FN" in current or "N" in current:
                    contacts.append(_normalize(current))
                current = {}
                continue

            # Parse key:value pairs
            if ":" in line:
                key, _, value = line.partition(":")
                # Handle type params (e.g., TYPE=HOME;TYPE=VOICE)
                parts = key.split(";")
                base_key = parts[0]
                types = [p.split("=")[1] for p in parts[1:] if "=" in p and p.startswith("TYPE")]

                # Handle encoded values (e.g., FN=Name with =3D for =)
                value = value.replace("=3D", "=").replace("=3A", ":").replace("=2C", ",")

                if base_key == "N":
                    current["N"] = value
                elif base_key == "FN":
                    current["FN"] = value
                elif base_key == "EMAIL":
                    email_type = types[0].lower() if types else "other"
                    if "emails" not in current:
                        current["emails"] = []
                    current["emails"].append({"value": value.lower().strip(), "type": email_type})
                elif base_key == "TEL":
                    phone_type = types[0].lower() if types else "other"
                    if "phones" not in current:
                        current["phones"] = []
                    current["phones"].append({"value": value.strip(), "type": phone_type})
                elif base_key == "ORG":
                    if "orgs" not in current:
                        current["orgs"] = []
                    current["orgs"].append(value.strip())
                elif base_key == "TITLE":
                    current["title"] = value.strip()
                elif base_key == "ADR":
                    if "addresses" not in current:
                        current["addresses"] = []
                    parts_addr = [p.strip() for p in value.split(";")]
                    if len(parts_addr) >= 6:
                        street = f"{parts_addr[0]} {parts_addr[1]}".strip()
                        city = parts_addr[2]
                        state = parts_addr[3]
                        zip_code = parts_addr[4]
                        country = parts_addr[5]
                        full_addr = f"{street}, {city}, {state} {zip_code}".strip(", ")
                        if country and country != "United States":
                            full_addr += f", {country}"
                        current["addresses"].append({"formatted": full_addr, "type": phone_type if "phones" in current else "home"})

    return contacts


def _normalize(vcard: dict) -> dict:
    """Convert VCF fields to our normalized format."""
    # Parse N field: Last;First;Middle;Prefix;Suffix
    first = last = middle = prefix = suffix = ""
    if "N" in vcard:
        n_parts = [p.strip() for p in vcard["N"].split(";")]
        if len(n_parts) >= 5:
            suffix, middle, first, last, prefix = n_parts[4], n_parts[2], n_parts[1], n_parts[3], n_parts[0]
        elif len(n_parts) == 1:
            # Single name, try to split on spaces
            parts = n_parts[0].rsplit(" ", 1)
            last = parts[-1] if len(parts) > 1 else ""
            first = " ".join(parts[:-1]) if len(parts) > 1 else parts[0]

    full_name = vcard.get("FN", f"{prefix} {first} {middle} {last} {suffix}".strip())

    emails = []
    for e in vcard.get("emails", []):
        emails.append({"value": e["value"].lower(), "type": e["type"]})

    phones = []
    for p in vcard.get("phones", []):
        phones.append({"value": p["value"], "type": p["type"]})

    orgs = []
    for org_name in vcard.get("orgs", []):
        org_entry = {"name": org_name}
        if "title" in vcard:
            org_entry["title"] = vcard["title"]
        orgs.append(org_entry)

    addresses = []
    for addr in vcard.get("addresses", []):
        addresses.append(addr)

    return {
        "id": f"apple_{vcard.get('id', '')}",
        "name": full_name,
        "first_name": first,
        "last_name": last,
        "emails": emails,
        "phones": phones,
        "organizations": orgs,
        "addresses": addresses,
    }


def main():
    path = "/mnt/c/Users/jason/OneDrive/Documents/Contacts/Dr Nicholas Abbey and 806 others.vcf"
    contacts = parse_vcf(path)
    print(f"Parsed {len(contacts)} contacts from VCF")

    # Stats
    has_email = sum(1 for c in contacts if c.get("emails"))
    has_phone = sum(1 for c in contacts if c.get("phones"))
    has_org = sum(1 for c in contacts if c.get("organizations"))
    print(f"With email: {has_email}")
    print(f"With phone: {has_phone}")
    print(f"With org: {has_org}")

    # Save to JSONL
    output_path = Path(__file__).parent.parent / "exports" / "apple_contacts.jsonl"
    with open(output_path, "w", encoding="utf-8") as f:
        for c in contacts:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print(f"\nSaved to {output_path}")


if __name__ == "__main__":
    main()
