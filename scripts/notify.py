#!/usr/bin/env python3
"""Notify script for whitelist — verification reminders and pending grant alerts.

Usage:
    python3 scripts/notify.py --what verify [--dry-run | --apply]
    python3 scripts/notify.py --what requests [--dry-run | --apply]
    python3 scripts/notify.py --what owner-link [--dry-run | --apply]

--what verify: Profiles with verified_at > 90 days old
--what requests: Pending access grants
--what owner-link: Dashboard magic link (prints URL; --apply emails it)
--dry-run: Print what would be sent (default)
--apply: Actually send emails via SMTP
"""

import argparse
import datetime
import os
import smtplib
import sys
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
import whitelist_db
import wl_tokens
import wl_env

SMTP_ENV_KEYS = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS"]


def send_email(to_addr: str, subject: str, body: str) -> None:
    """Send a plain-text email via SMTP."""
    host = wl_env.get_secret("SMTP_HOST")
    port_str = wl_env.get_secret("SMTP_PORT")
    user = wl_env.get_secret("SMTP_USER")
    password = wl_env.get_secret("SMTP_PASS")
    base_url = wl_env.get_secret("BASE_URL") or "https://whitelist.app"

    if not all([host, port_str, user, password]):
        print("[ERROR] SMTP credentials not configured (SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS)")
        print("        Set them in .env or environment variables.")
        sys.exit(1)

    port = int(port_str)
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, password)
        server.sendmail(user, [to_addr], msg.as_string())


def _owner_email(profile) -> Optional[str]:
    """First email field on a profile (dict with 'fields'), or None."""
    for f in profile.get("fields", []):
        if f["field_type"] == "email":
            return f["field_value"]
    return None


def notify_verify(dry_run: bool = True, db_path=None):
    """Send verification reminders to profiles with stale verified_at.

    ``db_path`` defaults to the prod DB (whitelist_db default); tests pass a
    tmp copy so runs never read live data.
    """
    conn = whitelist_db.wl_connect(db_path)
    try:
        profiles = whitelist_db.get_profiles_needing_verification(conn, days=90)
        if not profiles:
            print("[OK] No profiles need verification reminders.")
            return

        email_count = 0
        for profile in profiles:
            token = wl_tokens.make_token(
                wl_env.get_secret("WHITELIST_SECRET").encode(),
                "verify",
                str(profile["id"]),
                expires_days=7,
            )
            link = f"{wl_env.get_secret('BASE_URL') or 'https://whitelist.app'}/verify/{token}"

            if dry_run:
                print(f"[DRY-RUN] Would send verify reminder to {profile['handle']}: {link}")
            else:
                # Look up the owner's email from the profile's own fields.
                prof = whitelist_db.get_profile_by_id(conn, profile["id"])
                owner_email = _owner_email(prof)
                if not owner_email:
                    print(f"[WARN] No email field on profile {profile['handle']} — skipped.")
                    continue
                body = (
                    f"Hi,\n\n"
                    f"Your verification for handle '{prof['handle']}' is getting old.\n\n"
                    f"Re-verify here: {link}\n\n"
                    f"This link expires in 7 days.\n"
                )
                send_email(owner_email, "Whitelist: Verification reminder", body)
                email_count += 1
                print(f"[OK] Sent verify link to {owner_email}")

        print(f"[OK] Verification reminders: {len(profiles)} found, {email_count} sent.")
    finally:
        conn.close()


def notify_requests(dry_run: bool = True, db_path=None):
    """Send alerts for pending access grant requests. ``db_path`` defaults to prod."""
    conn = whitelist_db.wl_connect(db_path)
    try:
        grants = whitelist_db.get_pending_grants(conn)
        if not grants:
            print("[OK] No pending grant requests.")
            return

        email_count = 0
        for grant in grants:
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            if not profile:
                continue

            token = wl_tokens.make_token(
                wl_env.get_secret("WHITELIST_SECRET").encode(),
                "grant_review",
                grant["id"],
                expires_days=7,
            )
            link = f"{wl_env.get_secret('BASE_URL') or 'https://whitelist.app'}/a/{token}"

            owner_email = _owner_email(profile)

            if not owner_email:
                print(f"[WARN] No email found for profile {profile['handle']} ({grant['id']})")
                continue

            body = (
                f"Hi,\n\n"
                f"You have a new access request from {grant['requester_name']} "
                f"({grant['requester_email']}).\n\n"
                f"Review here: {link}\n\n"
                f"This link expires in 7 days.\n"
            )

            if dry_run:
                print(f"[DRY-RUN] Would send request alert to {owner_email}")
                print(f"  Requester: {grant['requester_name']} <{grant['requester_email']}>")
                print(f"  Link: {link}")
            else:
                send_email(owner_email, "Whitelist: New Access Request", body)
                email_count += 1
                print(f"[OK] Sent request alert to {owner_email}")

        print(f"[OK] Request alerts: {len(grants)} found, {email_count} sent.")
    finally:
        conn.close()


def _canonical_owner_handle() -> str:
    """The real handle of the whitelist owner (Jason), from his canonical JSON.

    The old code hardcoded 'jason_heath', which was never seeded (the real
    handle is 'jasonheath'), and silently fell back to whatever profile was
    rowid 1 — which can be a demo persona. Single source of truth: the
    canonical file seed_demo.py seeds from.
    """
    import json
    from pathlib import Path
    path = Path("/home/jason/profile/jason.heath.canonical.json")
    with open(path) as f:
        return json.load(f)["handle"]


def notify_owner_link(dry_run: bool = True, db_path=None):
    """Print (or email) the owner dashboard magic link.

    The link is owner-scoped: the token payload is the owner's profile id —
    never the legacy unscoped ``"owner"`` payload — and it expires in 7
    days (review F2: 365-day unscoped links were a cross-owner God-view).

    ``db_path`` defaults to the prod DB (whitelist_db default); tests must
    pass an explicit copy — never point this at live data with --apply.
    """
    base_url = wl_env.get_secret("BASE_URL") or "https://whitelist.app"

    conn = whitelist_db.wl_connect(db_path)
    try:
        owner_handle = _canonical_owner_handle()
        jason = whitelist_db.get_profile(conn, owner_handle)
        if not jason:
            # Hard fail — sending a dashboard link to a demo persona is
            # worse than no email. No silent rowid-1 fallback.
            print(f"[ERROR] Profile '{owner_handle}' not found in DB — "
                  f"run scripts/seed_demo.py --apply first.")
            sys.exit(1)

        # Owner-scoped, 7-day token (ruling 2A; review F2 recommendation c).
        token = wl_tokens.make_token(
            wl_env.get_secret("WHITELIST_SECRET").encode(),
            "owner_dashboard", str(jason["id"]), expires_days=7,
        )
        link = f"{base_url}/owner/{token}"

        if dry_run:
            print(f"[DRY-RUN] Owner dashboard link:")
            print(f"  {link}")
            return

        owner_email = _owner_email(jason)
        if not owner_email:
            print(f"[WARN] No email field on profile {jason['handle']} — skipped.")
            sys.exit(1)
        body = (
            "Hi,\n\n"
            "Your whitelist dashboard link:\n\n"
            f"{link}\n\n"
            "This link expires in 7 days.\n"
        )
        send_email(owner_email, "Whitelist: Dashboard link", body)
        print(f"[OK] Sent owner dashboard link to {owner_email}")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Whitelist notify script")
    parser.add_argument(
        "--what",
        choices=["verify", "requests", "owner-link"],
        required=True,
        help="What to notify about",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually send emails (default: dry-run)",
    )
    args = parser.parse_args()

    if args.what == "verify":
        notify_verify(dry_run=not args.apply)
    elif args.what == "requests":
        notify_requests(dry_run=not args.apply)
    elif args.what == "owner-link":
        notify_owner_link(dry_run=not args.apply)


if __name__ == "__main__":
    main()
