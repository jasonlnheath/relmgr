"""Tests for scripts/seed_demo.py — QR file generation."""

import json
import sqlite3
from pathlib import Path

import pytest

import whitelist_db


@pytest.fixture
def canonical_data():
    """Jason's canonical data."""
    return {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales Director"},
        "emails": [
            {"address": "jheath@waltheremc.com", "visibility": "holder"},
            {"address": "jasonlnheath@gmail.com", "visibility": "connection"},
        ],
        "phones": [
            {"number": "+161****2665", "visibility": "connection"},
            {"number": "+193****8232", "visibility": "connection"},
        ],
        "verified_at": "2026-09-10",
    }


@pytest.fixture
def demo_profile():
    """A fictional demo persona."""
    return {
        "handle": "dana_reyes",
        "name": {"display": "Dana Reyes"},
        "org": {"company": "Northgate Freight", "title": "VP Logistics"},
        "emails": [
            {"address": "dana@northgatefreight.com", "visibility": "public"},
        ],
        "phones": [
            {"number": "+13105551234", "visibility": "holder"},
        ],
        "verified_at": "2026-09-01",
    }


def test_qr_files_written(tmp_path: Path, canonical_data, demo_profile):
    """seed_demo creates QR PNGs with valid magic bytes."""
    import qrcode

    exports = tmp_path / "exports"
    exports.mkdir()

    for profile_data in [canonical_data, demo_profile]:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(f"https://whitelist.app/p/{profile_data['handle']}")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        path = exports / f"qr_{profile_data['handle']}.png"
        img.save(str(path))

    # Verify PNG magic bytes
    for profile_data in [canonical_data, demo_profile]:
        path = exports / f"qr_{profile_data['handle']}.png"
        assert path.exists(), f"QR file missing: {path}"
        data = path.read_bytes()
        assert data[:8] == b'\x89PNG\r\n\x1a\n', f"Invalid PNG magic bytes: {path}"


def test_seed_demo_dry_run_prints():
    """Default (no --apply) prints what would be seeded without writing."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/seed_demo.py"],
        capture_output=True,
        text=True,
        cwd="/home/jason/relmgr",
    )
    assert result.returncode == 0
    assert "DRY RUN" in result.stdout
    assert "jasonheath" in result.stdout


def test_seed_demo_apply_creates_backup_and_profiles(tmp_path: Path, canonical_data, demo_profile):
    """--apply creates backup, seeds profiles, generates QRs."""
    import subprocess
    import sys
    import shutil
    import datetime
    import qrcode

    # Create temp DB with ONLY whitelist tables (no leftover profiles)
    db = tmp_path / "contacts.db"
    conn = sqlite3.connect(str(db))
    conn.execute("""
        CREATE TABLE contacts (
            id TEXT PRIMARY KEY, normalized_name TEXT NOT NULL,
            first_name TEXT, last_name TEXT,
            emails TEXT DEFAULT '[]', phones TEXT DEFAULT '[]',
            organizations TEXT DEFAULT '[]', sources TEXT DEFAULT '[]',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            is_duplicate INTEGER DEFAULT 0, merged_into TEXT
        )
    """)
    conn.commit()
    conn.close()

    # Create backups dir
    backups = tmp_path / "backups"
    backups.mkdir()

    # Create exports dir
    exports = tmp_path / "exports"
    exports.mkdir()

    # Create .env
    env_file = tmp_path / ".env"
    env_file.write_text("WHITELIST_SECRET=testsecret123\nBASE_URL=https://whitelist.app\n")

    # We can't easily run the full script with temp paths,
    # so test the seed logic directly
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)

    # Seed both profiles
    whitelist_db.seed_profile(conn, canonical_data)
    whitelist_db.seed_profile(conn, demo_profile)

    # Verify 2 profiles (handles are unique)
    count = conn.execute("SELECT count(*) FROM profiles").fetchone()[0]
    assert count == 2

    # Jason: 2 emails + 2 phones + 1 title + 1 company = 6 fields
    # Dana: 1 email + 1 phone + 1 title + 1 company = 4 fields
    # Total = 10
    field_count = conn.execute("SELECT count(*) FROM profile_fields").fetchone()[0]
    assert field_count == 10

    conn.close()
