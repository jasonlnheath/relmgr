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
    _now_iso,
)


def build_quarterly_review(conn) -> str | None:
    """Build the quarterly review digest for all live temporary grants.

    Returns:
        A plain-text digest string with:
        - Subject line: "WhiteList — quarter review: N temporary contacts"
        - Each row: email, name, cards, expiry
        - Link to owner dashboard (placeholder URL)
        Returns None when there are no temporary grants.
    """
    # Find all profiles that have grants
    profiles = conn.execute(
        "SELECT * FROM profiles ORDER BY display_name"
    ).fetchall()

    # Build a map of grant_id -> requested_expiry from grant_logs
    log_rows = conn.execute(
        "SELECT grant_id, requested_expiry FROM grant_logs WHERE action = 'approved'"
    ).fetchall()
    grant_expiry = {r["grant_id"]: r["requested_expiry"] for r in log_rows}

    temp_grants = []
    for prof in profiles:
        p = dict(prof)
        grants = get_all_grants_for_profile(conn, p["id"])
        for g in grants:
            gdict = dict(g)
            # Only live temp grants: status=granted, expiry via grant_logs
            requested = grant_expiry.get(gdict["id"], "")
            if (gdict["status"] == "granted"
                    and gdict.get("expires_at")
                    and requested == "quarter"):
                cards = get_active_cards_for_grant(conn, gdict["id"])
                card_names = [c["name"] for c in cards]
                temp_grants.append({
                    "email": gdict["requester_email"],
                    "name": gdict["requester_name"] or gdict["requester_email"],
                    "cards": card_names,
                    "expires_at": gdict["expires_at"],
                })

    if not temp_grants:
        return None

    # Build digest
    lines = []
    lines.append(f"WhiteList — quarter review: {len(temp_grants)} temporary contacts")
    lines.append("")
    lines.append("=" * 60)
    lines.append("")

    for tg in temp_grants:
        lines.append(f"  {tg['name']} <{tg['email']}>")
        if tg["cards"]:
            lines.append(f"    Cards: {', '.join(tg['cards'])}")
        lines.append(f"    Expires: {tg['expires_at']}")
        lines.append("")

    lines.append("=" * 60)
    lines.append("")
    lines.append("Review at: https://whitelist.example.com/dashboard")
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
