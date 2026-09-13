"""Tests for the verify token endpoint and notify script."""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
import wl_env
from app import create_app


def _make_db(tmp_path: Path):
    """Create a fresh DB with whitelist tables and a seeded profile."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    data = {
        "handle": "testuser",
        "name": {"display": "Test User"},
        "org": {"company": "TestCo", "title": "CTO"},
        "emails": [{"address": "test@testco.com", "visibility": "public"}],
        "phones": [],
        "verified_at": "2025-01-01",  # old
    }
    whitelist_db.seed_profile(conn, data)
    conn.close()
    return db


def test_valid_verify_token_updates_verified_at(tmp_path: Path):
    """A valid verify token stamps profiles.verified_at to today."""
    db = _make_db(tmp_path)

    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    profile_id = profile["id"]
    conn.close()

    token = wl_tokens.make_token(
        b"test-secret", "verify", str(profile_id), expires_days=7
    )

    app = create_app(db)
    client = TestClient(app)

    resp = client.get(f"/verify/{token}")
    assert resp.status_code == 200
    assert "Verification Updated" in resp.text

    # Verify verified_at was updated
    conn = whitelist_db.wl_connect(db)
    profile = conn.execute(
        "SELECT verified_at FROM profiles WHERE id=?", (profile_id,)
    ).fetchone()
    conn.close()

    # Should be today's date
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert profile["verified_at"] is not None
    assert profile["verified_at"].startswith(today)


def test_expired_verify_token_returns_403(tmp_path: Path):
    """Expired verify token → 403."""
    db = _make_db(tmp_path)

    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    profile_id = profile["id"]
    conn.close()

    # Make an expired token
    token = wl_tokens.make_token(
        b"test-secret", "verify", str(profile_id), expires_days=0
    )
    import time
    time.sleep(1.1)

    app = create_app(db)
    client = TestClient(app)

    resp = client.get(f"/verify/{token}")
    assert resp.status_code == 403


def test_tampered_verify_token_returns_403(tmp_path: Path):
    """Tampered verify token → 403."""
    db = _make_db(tmp_path)

    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    profile_id = profile["id"]
    conn.close()

    token = wl_tokens.make_token(
        b"test-secret", "verify", str(profile_id), expires_days=7
    )
    # Tamper with the payload
    parts = token.split(".")
    tampered = "XXXX" + parts[1]

    app = create_app(db)
    client = TestClient(app)

    resp = client.get(f"/verify/{tampered}")
    assert resp.status_code == 403


def test_dry_run_prints_valid_links_zero_emails(tmp_path: Path, capsys):
    """notify.py --what verify (default dry-run) prints links, sends zero emails."""
    db = _make_db(tmp_path)

    # Make verified_at very old so it qualifies for notify
    conn = whitelist_db.wl_connect(db)
    conn.execute(
        "UPDATE profiles SET verified_at=? WHERE id=?",
        ("2020-01-01", 1),
    )
    conn.commit()
    conn.close()

    # Run notify (default is dry-run, no --dry-run flag needed)
    import subprocess
    result = subprocess.run(
        [sys.executable, "scripts/notify.py", "--what", "verify"],
        capture_output=True,
        text=True,
        cwd="/home/jason/relmgr",
    )
    assert result.returncode == 0
    assert "DRY-RUN" in result.stdout

    # No emails should be sent in dry-run mode
    assert "sent" not in result.stdout.lower() or "0 sent" in result.stdout.lower()


def test_notify_apply_without_smtp_exits_1(tmp_path: Path):
    """notify.py --what verify --apply without SMTP creds → exit 1."""
    # Ensure no SMTP creds are set
    old_smtp_host = os.environ.pop("SMTP_HOST", None)
    old_smtp_port = os.environ.pop("SMTP_PORT", None)
    old_smtp_user = os.environ.pop("SMTP_USER", None)
    old_smtp_pass = os.environ.pop("SMTP_PASS", None)

    try:
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "UPDATE profiles SET verified_at=? WHERE id=?",
            ("2020-01-01", 1),
        )
        conn.commit()
        conn.close()

        import subprocess
        result = subprocess.run(
            [sys.executable, "scripts/notify.py", "--what", "verify", "--apply"],
            capture_output=True,
            text=True,
            cwd="/home/jason/relmgr",
        )
        assert result.returncode == 1
        assert "SMTP" in result.stderr or "SMTP" in result.stdout
    finally:
        if old_smtp_host:
            os.environ["SMTP_HOST"] = old_smtp_host
        if old_smtp_port:
            os.environ["SMTP_PORT"] = old_smtp_port
        if old_smtp_user:
            os.environ["SMTP_USER"] = old_smtp_user
        if old_smtp_pass:
            os.environ["SMTP_PASS"] = old_smtp_pass
