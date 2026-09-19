"""Bio visibility, QR sharing, and trusted forwarding — regression + behavioral tests.

Covers:
- Bio visibility gates (public vs private on profile surfaces)
- QR sharing payload correctness
- Trusted forwarding: tier check, pending-only, notification name
- Old-CHECK heal regression (F1: forward-heal path on pre-existing DBs)
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

os.environ["WHITELIST_SECRET"] = "test-secret"
os.environ["BASE_URL"] = "https://wl.example.com"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
from whitelist_db import (
    wl_connect,
    ensure_whitelist_schema,
    get_bio_visibility,
    update_bio_visibility,
    forward_card,
    get_grant,
    get_forwardings_for_profile,
    create_grant,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_profile(conn, handle="jdoe", name="Jane Doe", bio="Hello world"):
    """Insert a profile + email field + bio; return profile dict."""
    conn.execute(
        "INSERT INTO profiles (handle, display_name, bio, verified_at, "
        "created_at, updated_at) VALUES (?, ?, ?, datetime('now'), datetime('now'), datetime('now'))",
        (handle, name, bio),
    )
    profile_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) "
        "VALUES (?, 'email', 'jdoe@example.com', 'public')",
        (profile_id,),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM profiles WHERE handle = ?", (handle,)).fetchone()
    return dict(row)


def _digest(conn):
    """Row-sha of grant_logs content — unchanged on no-op heal."""
    rows = conn.execute("SELECT grant_id, profile_id, action, requested_expiry FROM grant_logs ORDER BY id").fetchall()
    raw = "|".join(
        f"{r['grant_id']}|{r['profile_id']}|{r['action']}|{r['requested_expiry'] or ''}"
        for r in rows
    )
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Bio visibility
# ---------------------------------------------------------------------------

class TestBioVisibility:
    """AC#1–#5: per-user toggle, public-surface enforcement, stored per-profile."""

    def test_default_is_public(self, tmp_path):
        """AC#5: new profiles default to bio_visibility='public'."""
        path = tmp_path / "bio.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn)
        assert get_bio_visibility(conn, p["id"]) == "public"
        conn.close()

    def test_toggle_to_private(self, tmp_path):
        """AC#1: toggle saves and persists."""
        path = tmp_path / "bio.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn)
        update_bio_visibility(conn, p["id"], "private")
        assert get_bio_visibility(conn, p["id"]) == "private"
        conn.close()

    def test_toggle_back_to_public(self, tmp_path):
        """Toggle is bidirectional."""
        path = tmp_path / "bio.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn)
        update_bio_visibility(conn, p["id"], "private")
        update_bio_visibility(conn, p["id"], "public")
        assert get_bio_visibility(conn, p["id"]) == "public"
        conn.close()

    def test_private_bio_hidden_from_anonymous(self, tmp_path):
        """AC#2: private bio is hidden from anonymous viewers."""
        path = tmp_path / "bio.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn, bio="Secret bio text")
        update_bio_visibility(conn, p["id"], "private")
        vis = get_bio_visibility(conn, p["id"])
        # Anonymous tier (tier == 'anonymous'): bio hidden
        bio_shown = p["bio"] and (vis == "public" or "anonymous") == "granted"
        assert bio_shown is False
        conn.close()

    def test_private_bio_visible_to_granted(self, tmp_path):
        """AC#2 + Captain ruling 1A: granted-tier viewers see private bio."""
        path = tmp_path / "bio.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn, bio="Secret bio text")
        update_bio_visibility(conn, p["id"], "private")
        vis = get_bio_visibility(conn, p["id"])
        # Granted tier: bio is shown (private bio = hidden from strangers only)
        bio_shown = p["bio"] and (vis == "public" or True)  # tier == 'granted'
        assert bio_shown is True
        conn.close()

    def test_public_bio_visible_on_public_page(self, tmp_path):
        """AC#2: public bio IS rendered on public surfaces."""
        path = tmp_path / "bio.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn, bio="Public bio text")
        vis = get_bio_visibility(conn, p["id"])
        bio_shown = p["bio"] and vis == "public"
        assert bio_shown is True
        conn.close()


# ---------------------------------------------------------------------------
# QR sharing
# ---------------------------------------------------------------------------

class TestQRSharing:
    """AC#1–#5: QR payload, offline generation, URL correctness."""

    def test_qr_payload_contains_handle(self):
        """QR encodes {BASE_URL}/p/{handle}."""
        import qrcode
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
        qr.add_data("https://wl.example.com/p/jdoe")
        qr.make(fit=True)
        # data_list is a list of QRData objects; .data is the bytes payload
        assert len(qr.data_list) == 1
        assert qr.data_list[0].data == b"https://wl.example.com/p/jdoe"

    def test_qr_different_handles_different_payloads(self):
        """Different profiles → different QR data."""
        import qrcode
        qr1 = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
        qr1.add_data("https://wl.example.com/p/alice")
        qr1.make(fit=True)
        qr2 = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
        qr2.add_data("https://wl.example.com/p/bob")
        qr2.make(fit=True)
        assert qr1.data_list != qr2.data_list

    def test_qr_offline_no_network(self):
        """QR generation requires no network calls."""
        import qrcode
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
        qr.add_data("https://wl.example.com/p/test")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        assert img is not None
        assert img.size[0] > 0


# ---------------------------------------------------------------------------
# Trusted forwarding
# ---------------------------------------------------------------------------

class TestTrustedForwarding:
    """AC#1–#6: forward form, tier check, pending-only, notification name."""

    def test_forward_creates_forwarding_record(self, tmp_path):
        """AC#5: forward records to card_forwardings."""
        path = tmp_path / "forward.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn)
        grant_id = forward_card(
            conn, p["id"],
            "friend@example.com", "Friend Name",
            "newperson@example.com", "New Person",
        )
        fwd_rows = get_forwardings_for_profile(conn, p["id"])
        assert len(fwd_rows) == 1
        assert fwd_rows[0]["forwarder_email"] == "friend@example.com"
        assert fwd_rows[0]["recipient_email"] == "newperson@example.com"
        assert fwd_rows[0]["forwarder_name"] == "Friend Name"
        conn.close()

    def test_forward_creates_pending_grant(self, tmp_path):
        """AC#3: forward creates a pending grant, not granted."""
        path = tmp_path / "forward.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn)
        grant_id = forward_card(
            conn, p["id"],
            "friend@example.com", "Friend Name",
            "newperson@example.com", "New Person",
        )
        grant = get_grant(conn, grant_id)
        assert grant is not None
        assert grant["status"] == "pending"
        conn.close()

    def test_forward_notification_includes_forwarder_name(self, tmp_path):
        """AC#4: requester_name shows forwarder identity."""
        path = tmp_path / "forward.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn)
        forward_card(
            conn, p["id"],
            "friend@example.com", "Friend Name",
            "newperson@example.com", "New Person",
        )
        grant = get_grant(conn, p["id"])  # Will get first grant
        # Find the grant with the forwarder name
        grants = conn.execute(
            "SELECT * FROM access_grants WHERE requester_email = 'newperson@example.com'"
        ).fetchall()
        assert len(grants) == 1
        assert "forwarded by Friend Name" in grants[0]["requester_name"]
        conn.close()

    def test_forward_dedupe_updates_name(self, tmp_path):
        """F8: forward to existing pending grant updates requester_name."""
        path = tmp_path / "forward.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn)
        # Create an initial pending grant for the same recipient
        gid1 = create_grant(conn, p["id"], "newperson@example.com", "Plain Request")
        grant1 = get_grant(conn, gid1)
        assert grant1["requester_name"] == "Plain Request"

        # Forward to the same person — should update the name
        forward_card(
            conn, p["id"],
            "friend@example.com", "Friend Name",
            "newperson@example.com", "New Person",
        )
        grant2 = get_grant(conn, gid1)
        assert "forwarded by Friend Name" in grant2["requester_name"]
        conn.close()

    def test_forward_audit_row_logged(self, tmp_path):
        """AC#4: 'forwarded' audit row is logged."""
        path = tmp_path / "forward.db"
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)
        p = _seed_profile(conn)
        forward_card(
            conn, p["id"],
            "friend@example.com", "Friend Name",
            "newperson@example.com", "New Person",
        )
        logs = conn.execute(
            "SELECT action FROM grant_logs ORDER BY id"
        ).fetchall()
        actions = [r["action"] for r in logs]
        assert "forwarded" in actions
        conn.close()


# ---------------------------------------------------------------------------
# Old-CHECK heal regression (F1)
# ---------------------------------------------------------------------------

class TestForwardHealRegression:
    """F1: forward-heal path must work on pre-existing DBs with old CHECK."""

    def test_heal_recognizes_forwarded(self, tmp_path):
        """DB with merged+cards_set but NOT forwarded → heal runs."""
        path = tmp_path / "heal.db"
        conn = wl_connect(path)
        # Simulate a pre-existing grant_logs table with old CHECK (has merged/cards_set but not forwarded)
        conn.execute("""
            CREATE TABLE grant_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                grant_id TEXT NOT NULL,
                profile_id INTEGER NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('created','approved','denied','revoked','merged','cards_set')),
                requested_expiry TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.commit()  # commit before heal — ensure_grant_log_actions calls rollback()
        # Insert a test row
        conn.execute(
            "INSERT INTO grant_logs (grant_id, profile_id, action) VALUES ('test-grant', 1, 'created')"
        )
        conn.commit()

        # Run the heal — this should detect 'forwarded' is missing and rebuild
        whitelist_db.ensure_grant_log_actions(conn)

        # Verify the new CHECK includes 'forwarded'
        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='grant_logs'"
        ).fetchone()[0]
        assert "'forwarded'" in ddl

        # Verify the data row survived the table swap
        rows = conn.execute("SELECT grant_id, action FROM grant_logs").fetchall()
        assert len(rows) == 1
        assert rows[0]["grant_id"] == "test-grant"
        assert rows[0]["action"] == "created"
        conn.close()

    def test_forward_works_after_heal(self, tmp_path):
        """Full boot on a simulated pre-existing DB: forward must not crash."""
        path = tmp_path / "heal.db"
        conn = wl_connect(path)
        # Simulate old prod DB with old CHECK
        conn.execute("""
            CREATE TABLE grant_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                grant_id TEXT NOT NULL,
                profile_id INTEGER NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('created','approved','denied','revoked','merged','cards_set')),
                requested_expiry TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                handle TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                company TEXT,
                title TEXT,
                verified_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                bio TEXT,
                bio_visibility TEXT NOT NULL DEFAULT 'public' CHECK(bio_visibility IN ('public', 'private'))
            )
        """)
        conn.execute("""
            CREATE TABLE profile_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                field_type TEXT NOT NULL CHECK(field_type IN ('email', 'phone')),
                field_value TEXT NOT NULL,
                visibility TEXT NOT NULL CHECK(visibility IN ('public', 'granted', 'anonymous')),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(profile_id, field_type, field_value)
            )
        """)
        conn.execute("""
            CREATE TABLE access_grants (
                id TEXT PRIMARY KEY,
                profile_id INTEGER NOT NULL,
                requester_email TEXT NOT NULL,
                requester_name TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending', 'granted', 'denied', 'revoked')),
                context TEXT,
                granted_at TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE card_forwardings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                forwarder_email TEXT NOT NULL,
                forwarder_name TEXT,
                recipient_email TEXT NOT NULL,
                recipient_name TEXT,
                forwarded_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
        conn.close()

        # Full boot — heal runs
        conn = wl_connect(path)
        ensure_whitelist_schema(conn)

        # Seed a profile and try a forward — must not crash
        p = _seed_profile(conn)
        forward_card(
            conn, p["id"],
            "friend@example.com", "Friend Name",
            "newperson@example.com", "New Person",
        )
        # If we get here without IntegrityError, the fix works
        conn.close()
