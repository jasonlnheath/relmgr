#!/usr/bin/env python3
"""Seed demo profiles into the whitelist database.

Usage:
    python3 scripts/seed_demo.py [--dry-run | --apply]

--dry-run: Show what would be seeded (default)
--apply: Actually seed profiles and generate QR codes
"""

import argparse
import datetime
import os
import shutil
import sys
from pathlib import Path

import qrcode

# Add repo root to path
sys.path.insert(0, str(Path(__file__).parent.parent))
import whitelist_db
import wl_env


BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / "contacts.db"
EXPORTS_DIR = BASE_DIR / "exports"
BACKUPS_DIR = BASE_DIR / "backups"
CANONICAL_PATH = Path("/home/jason/profile/jason.heath.canonical.json")

BASE_URL = wl_env.get_secret("BASE_URL") or "https://whitelist.app"


DEMO_PROFILES = [
    {
        "handle": "dana_reyes",
        "name": {"display": "Dana Reyes"},
        "org": {"company": "Northgate Freight", "title": "VP Logistics"},
        "emails": [
            {"address": "dana.reyes@northgatefreight.com", "visibility": "public"},
            {"address": "dana.r@northgatefreight.com", "visibility": "connection"},
        ],
        "phones": [
            {"number": "+13105551234", "visibility": "holder"},
        ],
        "verified_at": (
            datetime.datetime.utcnow() - datetime.timedelta(days=9)
        ).strftime("%Y-%m-%d"),
    },
    {
        "handle": "marcus_chen",
        "name": {"display": "Marcus Chen"},
        "org": {"company": "Pacific Shield Insurance", "title": "Risk Manager"},
        "emails": [
            {"address": "mchen@pacificshield.com", "visibility": "holder"},
        ],
        "phones": [
            {"number": "+14155559876", "visibility": "connection"},
        ],
        "verified_at": (
            datetime.datetime.utcnow() - datetime.timedelta(days=41)
        ).strftime("%Y-%m-%d"),
    },
    {
        "handle": "olivia_banks",
        "name": {"display": "Olivia Banks"},
        "org": {"company": "Summit Heavy Haul", "title": "Fleet Director"},
        "emails": [
            {"address": "olivia@summithaul.com", "visibility": "public"},
            {"address": "olivia.banks@summithaul.com", "visibility": "connection"},
        ],
        "phones": [
            {"number": "+12125554567", "visibility": "holder"},
            {"number": "+12125554568", "visibility": "public"},
        ],
        "verified_at": (
            datetime.datetime.utcnow() - datetime.timedelta(days=180)
        ).strftime("%Y-%m-%d"),
    },
    {
        "handle": "ethan_wolfe",
        "name": {"display": "Ethan Wolfe"},
        "org": {"company": "Ironclad Transport", "title": "Owner"},
        "emails": [
            {"address": "ethan@ironcladtransport.com", "visibility": "public"},
        ],
        "phones": [
            {"number": "+17185553456", "visibility": "public"},
        ],
        "verified_at": (
            datetime.datetime.utcnow() - datetime.timedelta(days=700)
        ).strftime("%Y-%m-%d"),
    },
]


def load_jason(canonical_path: Path = CANONICAL_PATH) -> dict:
    """Load Jason's canonical profile from JSON."""
    import json
    with open(canonical_path) as f:
        return json.load(f)


def make_qr_png(url: str, output_path: Path) -> Path:
    """Generate a QR code PNG for the given URL."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(str(output_path))
    return output_path


def seed_all(
    dry_run: bool = True,
    db_path: Path = DB_PATH,
    canonical_path: Path = CANONICAL_PATH,
    exports_dir: Path = EXPORTS_DIR,
    make_backup: bool = True,
):
    """Seed all demo profiles.

    Paths default to the prod layout; tests must pass explicit db_path /
    exports_dir and never point at the real contacts.db (which is why this
    is parameterized instead of reading module constants).
    """
    if dry_run:
        print("[DRY RUN] Would seed the following profiles:")
        profiles = [load_jason(canonical_path)] + DEMO_PROFILES
        for p in profiles:
            print(f"  - {p['handle']}: {p['name']['display']}")
        print(f"\n[DRY RUN] Would generate QR codes in {exports_dir}")
        if make_backup:
            print("[DRY RUN] Would create backup in", BACKUPS_DIR)
        return

    # Step 1: Backup the prod file before mutating (CLI --apply keeps this on;
    # tests pass make_backup=False against copies)
    if make_backup:
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = BACKUPS_DIR / f"contacts_pre_whitelist_{timestamp}.db"
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(db_path), str(backup_path))
        assert backup_path.exists(), f"Backup not created at {backup_path}"
        print(f"[OK] Backup created: {backup_path}")

    # Step 2: Connect and initialize
    conn = whitelist_db.wl_connect(db_path)
    whitelist_db.wl_init(conn)

    # Step 3: Seed Jason
    jason = load_jason(canonical_path)
    whitelist_db.seed_profile(conn, jason)
    print(f"[OK] Seeded profile: {jason['handle']}")

    # Generate QR for Jason
    exports_dir.mkdir(parents=True, exist_ok=True)
    qr_path = exports_dir / f"qr_{jason['handle']}.png"
    make_qr_png(f"{BASE_URL}/p/{jason['handle']}", qr_path)
    print(f"[OK] QR code: {qr_path}")

    # Step 4: Seed demo personas (with aliases)
    ALIASES = {
        "dana_reyes": ["dana-sales", "dana-reyes-sales"],
        "marcus_chen": ["marcus-chen"],
        "olivia_banks": ["olivia-banks"],
        "ethan_wolfe": ["ethan-wolfe"],
    }

    for profile in DEMO_PROFILES:
        whitelist_db.seed_profile(conn, profile)
        print(f"[OK] Seeded profile: {profile['handle']}")

        # Get the profile id for alias/QR ops (seed_profile doesn't set it on the dict)
        row = conn.execute("SELECT id FROM profiles WHERE handle = ?", (profile["handle"],)).fetchone()
        profile_id = row["id"]

        # Generate QR for primary handle
        qr_path = exports_dir / f"qr_{profile['handle']}.png"
        make_qr_png(f"{BASE_URL}/p/{profile['handle']}", qr_path)
        print(f"[OK] QR code: {qr_path}")

        # Add aliases (idempotent — add_alias returns None on collision)
        for alias in ALIASES.get(profile["handle"], []):
            result = whitelist_db.add_alias(conn, profile_id, alias)
            if result is not None:
                print(f"[OK] Added alias: {alias} → {profile['handle']}")
            else:
                print(f"[OK] Alias already exists: {alias}")

            # Generate QR for alias too
            qr_path = exports_dir / f"qr_{alias}.png"
            make_qr_png(f"{BASE_URL}/p/{alias}", qr_path)
            print(f"[OK] QR code: {qr_path}")

    conn.close()
    print(f"\n[OK] Total: {1 + len(DEMO_PROFILES)} profiles seeded, QR codes generated.")


def main():
    parser = argparse.ArgumentParser(description="Seed demo whitelist profiles")
    parser.add_argument(
        "--apply", action="store_true", help="Actually seed profiles (default: dry-run)"
    )
    args = parser.parse_args()

    seed_all(dry_run=not args.apply)


if __name__ == "__main__":
    main()
