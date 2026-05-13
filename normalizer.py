"""Field normalization across contact sources."""

import re
from typing import Optional


def normalize_name(raw: str) -> tuple[str, str, str]:
    """Parse a raw name string into (normalized, first_name, last_name).

    Handles formats like:
      "Last, First"       → ("Last, First", "First", "Last")
      "First Last"        → ("Last, First", "First", "Last")
      "First M. Last"     → ("Last, First", "First", "Last")
      "Dr. First Last Jr." → ("Last, First", "First", "Last")
    """
    if not raw or not raw.strip():
        return ("", "", "")

    raw = raw.strip()

    # Remove title and suffix
    titles = {"dr", "prof", "mr", "mrs", "ms", "miss", "rev", "hon"}
    suffixes = {"jr", "sr", "ii", "iii", "iv", "v", "the 2nd", "the third"}

    # Check for "Last, First" format explicitly first
    if "," in raw:
        comma_idx = raw.index(",")
        last = raw[:comma_idx].strip().rstrip(".")
        rest = raw[comma_idx + 1:].strip()
        # Strip titles/suffixes from the rest
        while rest and rest.split()[0].lower() in titles:
            rest = " ".join(rest.split()[1:])
        while rest and rest.split()[-1].lower() in suffixes:
            rest = " ".join(rest.split()[:-1])
        first = rest.strip()
        return (f"{last}, {first}", first, last)

    # "First Last" or "First M. Last" format
    parts = re.split(r"\s+", raw)
    parts = [p.strip().strip(".") for p in parts if p.strip()]

    # Strip titles from front
    while parts and parts[0].lower() in titles:
        parts.pop(0)

    # Strip suffixes from end
    while parts and parts[-1].lower() in suffixes:
        parts.pop()

    if len(parts) == 0:
        return (raw, "", "")

    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    normalized = f"{last}, {first}" if last else first

    return (normalized, first, last)


def normalize_phone(raw: str) -> Optional[str]:
    """Normalize phone number to E.164 format if possible.

    Falls back to stripping non-digits if phonenumbers library unavailable.
    """
    if not raw or not raw.strip():
        return None

    raw = raw.strip()

    # Try using phonenumbers library for proper normalization
    try:
        import phonenumbers
        parsed = phonenumbers.parse(raw, "US")  # Default region
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except ImportError:
        pass  # phonenumbers not installed, fall through
    except Exception:
        pass  # Invalid number, fall through

    # Fallback: strip to digits, prepend +1 if US-looking
    digits = re.sub(r"[^\d]", "", raw)
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    return f"+{digits}" if digits else None


def normalize_email(raw) -> Optional[dict]:
    """Normalize an email address. Returns {address, type} or None."""
    if not raw:
        return None

    # Handle dict input (e.g., {"value": "...", "type": "work"})
    if isinstance(raw, dict):
        address = raw.get("value", raw.get("address", ""))
        email_type = raw.get("type", "other")
        if not address or "@" not in str(address):
            return None
        address = str(address).lower()
        domain = address.split("@")[-1] if "@" in address else ""
        personal_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "protonmail.com"}
        if domain in personal_domains:
            email_type = "personal"
        elif email_type == "other":
            email_type = "work"
        return {"address": address, "type": email_type}

    # Handle string input
    if isinstance(raw, str):
        email = raw.strip().lower()
        if not email or "@" not in email:
            return None
        email_type = "other"
        domain = email.split("@")[-1] if "@" in email else ""
        personal_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "protonmail.com"}
        if domain in personal_domains:
            email_type = "personal"
        elif email_type == "other":
            email_type = "work"
        return {"address": email, "type": email_type}

    return None


def normalize_phone_entry(raw) -> Optional[dict]:
    """Normalize a phone entry. Handles string or {number, type} dict."""
    if isinstance(raw, str):
        number = normalize_phone(raw)
        return {"number": number, "type": "other"} if number else None

    if isinstance(raw, dict):
        number = normalize_phone(raw.get("number", raw.get("value", "")))
        phone_type = raw.get("type", "other")
        return {"number": number, "type": phone_type} if number else None

    return None


def normalize_organization(raw) -> Optional[dict]:
    """Normalize an organization entry."""
    if isinstance(raw, str):
        return {"name": raw.strip(), "title": ""}

    if isinstance(raw, dict):
        return {
            "name": raw.get("name", raw.get("organization", "")).strip(),
            "title": raw.get("title", raw.get("position", "")).strip(),
        }

    return None


def normalize_contact(raw: dict, source: str = "unknown") -> dict:
    """Normalize a raw contact record from any source.

    Returns a standardized contact dict ready for store.py.
    """
    # Extract name
    raw_name = raw.get("name", raw.get("displayName", raw.get("display_name", "")))
    normalized_name, first_name, last_name = normalize_name(raw_name)

    # Extract emails
    raw_emails = raw.get("emails", raw.get("email_addresses", []))
    if isinstance(raw_emails, str):
        raw_emails = [{"value": raw_emails}]
    elif isinstance(raw_emails, dict):
        raw_emails = [raw_emails]
    emails = []
    for e in raw_emails:
        entry = normalize_email(e)
        if entry:
            emails.append(entry)

    # Extract phones
    raw_phones = raw.get("phones", raw.get("phone_numbers", []))
    if isinstance(raw_phones, str):
        raw_phones = [{"value": raw_phones}]
    elif isinstance(raw_phones, dict):
        raw_phones = [raw_phones]
    phones = []
    for p in raw_phones:
        entry = normalize_phone_entry(p)
        if entry:
            phones.append(entry)

    # Extract organizations
    raw_orgs = raw.get("organizations", raw.get("org", raw.get("company_name", [])))
    if isinstance(raw_orgs, str):
        raw_orgs = [{"name": raw_orgs}]
    elif isinstance(raw_orgs, dict):
        raw_orgs = [raw_orgs]
    orgs = []
    for o in raw_orgs:
        entry = normalize_organization(o)
        if entry and entry["name"]:
            orgs.append(entry)

    return {
        "id": raw.get("id", raw.get("source_id", "")),
        "normalized_name": normalized_name,
        "first_name": first_name,
        "last_name": last_name,
        "emails": emails,
        "phones": phones,
        "organizations": orgs,
        "sources": [source],
        "sources_list": [{"source": source, "source_id": raw.get("id", ""), "raw_data": raw}],
    }
