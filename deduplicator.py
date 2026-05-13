"""Multi-key contact deduplication engine."""

from config import DEDUP_EXACT, DEDUP_REVIEW, DEDUP_FUZZY_NAME_THRESHOLD
from store import log_dedup, merge_contacts


def _email_match(contact_a: dict, contact_b: dict) -> float:
    """Check if contacts share an email address. Returns 1.0 if exact match, 0.0 otherwise."""
    emails_a = {e["address"] for e in contact_a.get("emails", [])}
    emails_b = {e["address"] for e in contact_b.get("emails", [])}
    if emails_a & emails_b:
        return 1.0
    # Partial: one email of A matches one of B
    if emails_a and emails_b:
        for ea in emails_a:
            for eb in emails_b:
                if ea.split("@")[0] == eb.split("@")[0]:
                    return 0.85
    return 0.0


def _name_match(contact_a: dict, contact_b: dict) -> float:
    """Compare normalized names. Returns similarity score."""
    name_a = contact_a.get("normalized_name", "").lower().strip()
    name_b = contact_b.get("normalized_name", "").lower().strip()

    if not name_a or not name_b:
        return 0.0

    if name_a == name_b:
        return 1.0

    # Try fuzzy matching
    try:
        from rapidfuzz import fuzz, process
        score = fuzz.ratio(name_a, name_b) / 100.0
        if score >= DEDUP_FUZZY_NAME_THRESHOLD:
            return score
    except ImportError:
        pass

    # Simple substring check
    a_parts = set(name_a.split(",")[-1].split()) if "," in name_a else set(name_a.split())
    b_parts = set(name_b.split(",")[-1].split()) if "," in name_b else set(name_b.split())
    if a_parts and b_parts:
        overlap = len(a_parts & b_parts) / max(len(a_parts), len(b_parts))
        if overlap >= 0.8:
            return overlap

    return 0.0


def _phone_match(contact_a: dict, contact_b: dict) -> float:
    """Check if contacts share a phone number. Returns 1.0 if match."""
    phones_a = {p["number"] for p in contact_a.get("phones", []) if p.get("number")}
    phones_b = {p["number"] for p in contact_b.get("phones", []) if p.get("number")}
    if phones_a & phones_b:
        return 1.0
    # Partial: one phone of A matches one of B
    if phones_a and phones_b:
        for pa in phones_a:
            for pb in phones_b:
                if pa == pb:
                    return 0.9
    return 0.0


def _org_match(contact_a: dict, contact_b: dict) -> float:
    """Check if contacts share an organization."""
    orgs_a = {o["name"].lower() for o in contact_a.get("organizations", [])}
    orgs_b = {o["name"].lower() for o in contact_b.get("organizations", [])}
    if orgs_a & orgs_b:
        return 1.0
    return 0.0


def match_contacts(contact_a: dict, contact_b: dict) -> tuple[float, str]:
    """Compute match score between two contacts.

    Returns (score, match_type) where score is 0.0-1.0 and match_type explains the basis.
    """
    email_score = _email_match(contact_a, contact_b)
    name_score = _name_match(contact_a, contact_b)
    phone_score = _phone_match(contact_a, contact_b)
    org_score = _org_match(contact_a, contact_b)

    total = (
        0.4 * email_score +
        0.3 * name_score +
        0.2 * phone_score +
        0.1 * org_score
    )

    # Determine primary match type
    scores = {
        "email": email_score,
        "name": name_score,
        "phone": phone_score,
        "org": org_score,
    }
    primary = max(scores, key=scores.get)

    return (round(total, 3), primary)


def find_duplicates(contacts: list[dict]) -> list[tuple]:
    """Find all duplicate pairs in a contact list.

    Returns list of (primary_contact, duplicate_contact, score, match_type).
    """
    duplicates = []
    n = len(contacts)

    for i in range(n):
        for j in range(i + 1, n):
            score, match_type = match_contacts(contacts[i], contacts[j])
            if score >= DEDUP_REVIEW:
                duplicates.append((contacts[i], contacts[j], score, match_type))

    return duplicates


def resolve_duplicates(contacts: list[dict], db_path=None) -> dict:
    """Find and resolve all duplicates.

    Returns summary: {merged: int, flagged: int, total: int}.
    """
    from store import upsert_contact

    # First, ensure all contacts are in the DB
    for c in contacts:
        upsert_contact(c, db_path)

    duplicates = find_duplicates(contacts)
    merged = 0
    flagged = 0

    for primary, duplicate, score, match_type in duplicates:
        if score >= DEDUP_EXACT:
            merge_contacts(primary["id"], duplicate["id"], db_path)
            log_dedup(primary["id"], duplicate["id"], match_type, score, "auto", db_path)
            merged += 1
        elif score >= DEDUP_REVIEW:
            flagged += 1

    return {
        "merged": merged,
        "flagged": flagged,
        "total": len(contacts),
    }
