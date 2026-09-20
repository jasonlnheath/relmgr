"""Whitelist notification helpers — quarterly review digest.

Exports:
- quarter_end_iso(now) -> str  (re-exported from whitelist_db)
- is_current_quarter(value) -> bool  (re-exported from whitelist_db)
- build_quarterly_review(conn) -> Optional[str]
"""
import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path

# Ensure parent dir is on path for flat imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from whitelist_db import (
    wl_connect,
    wl_init,
    quarter_end_iso,
    is_current_quarter,
    get_all_grants_for_profile,
    get_profile_by_id,
    get_active_cards_for_grant,
    get_grey_contacts_by_owner,
    get_grey_contacts,
    _now_iso,
)
import mailer


def build_quarterly_review(conn) -> str | None:
    """Build the quarterly review digest for all grey contacts.

    Grey contacts are granted contacts whose quarter grant has expired
    and are awaiting a quarterly decision (make permanent, revoke, or punt).

    Returns:
        A plain-text digest string grouped by owner with:
        - Subject line: "WhiteList — quarter review: N grey contacts across M owners"
        - Per owner: their grey contacts with email, name, cards, expiry, status
        - Link to owner dashboard (placeholder URL)
        Returns None when there are no grey contacts.
    """
    grey_by_owner = get_grey_contacts_by_owner(conn)

    if not grey_by_owner:
        return None

    total_contacts = sum(len(contacts) for contacts in grey_by_owner.values())
    total_owners = len(grey_by_owner)

    # Build a map of grant_id -> cards
    grant_cards: dict[str, list[str]] = {}
    for g in get_grey_contacts(conn):
        cards = get_active_cards_for_grant(conn, g["id"])
        grant_cards[g["id"]] = [c["name"] for c in cards]

    # Build digest
    lines = []
    lines.append(f"WhiteList — quarter review: {total_contacts} grey contacts across {total_owners} owners")
    lines.append("")
    lines.append("=" * 60)
    lines.append("")

    for profile_id, contacts in sorted(grey_by_owner.items()):
        profile = get_profile_by_id(conn, profile_id)
        profile_name = profile["display_name"] if profile else f"Profile {profile_id}"
        lines.append(f"Owner: {profile_name} (profile_id={profile_id})")
        lines.append("-" * 40)

        for contact in contacts:
            qs = contact.get("quarter_status", "unknown")
            status_label = "pending review" if qs == "pending_review" else qs
            lines.append(f"  {contact['requester_name'] or contact['requester_email']} <{contact['requester_email']}>")
            lines.append(f"    Status: {status_label}")
            lines.append(f"    Granted: {contact.get('granted_at', 'N/A')}")
            lines.append(f"    Expires: {contact.get('expires_at', 'N/A')}")
            cards = grant_cards.get(contact["id"], [])
            if cards:
                lines.append(f"    Cards: {', '.join(cards)}")
            lines.append("")

        lines.append("")

    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Review at: {mailer.app_base_url()}/dashboard")
    lines.append("")

    return "\n".join(lines)


def main():
    """CLI entry point for manual review digest."""
    parser = argparse.ArgumentParser(description="Whitelist quarterly review digest")
    parser.add_argument("--review", action="store_true", help="Print quarterly review digest")
    args = parser.parse_args()

    if not args.review:
        parser.print_help()
        sys.exit(0)

    db_path = Path(__file__).parent / "contacts.db"
    if not db_path.exists():
        print("No contacts.db found.", file=sys.stderr)
        sys.exit(1)

    conn = wl_connect(db_path)
    wl_init(conn)

    digest = build_quarterly_review(conn)
    if digest is None:
        print("No temporary grants to review.")
    else:
        print(digest)

    conn.close()


if __name__ == "__main__":
    main()
