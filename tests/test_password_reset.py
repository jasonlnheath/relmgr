"""Password reset flow (2026-09-20): forgot-password → token → set password.

Covers the first-password / forgot-password lane:

- Token lifecycle: hashed at rest, 30-minute expiry, single-use
  (replay rejected), one active token per account (re-issue invalidates).
- Screens: /signin 'Forgot password?' link, email-entry page,
  reset form reachable ONLY via a live token, signup password rules
  (min 8 chars) enforced, success lands back on sign-in.
- No user enumeration: identical confirmation whether or not the email
  exists — including when email delivery fails.
- Delivery: reset email goes through the existing notify path
  (scripts/notify.send_email); CLI fallback prints the reset URL.
- The captain's scenario: a legacy owner with password_hash NULL gets
  their first password through this flow and can then sign in.
"""
import hashlib
import os

os.environ["WHITELIST_SECRET"] = "test-secret"

import pytest
from fastapi.testclient import TestClient
from pathlib import Path

import whitelist_db
import wl_tokens
from app import create_app
from scripts import notify as notify_script


# ============================================================
# World builder: a signed-up owner + a passwordless legacy owner
# ============================================================


def _make_world(tmp_path: Path) -> Path:
    db = tmp_path / "reset.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    # Signed-up owner (has a password).
    whitelist_db.create_owner_profile(
        conn, "freshowner", "Fresh Owner", "fresh@example.com", "password123")
    # Legacy migrated owner: email on the profile, password_hash NULL —
    # cannot sign in until they set a first password via this flow.
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
    })
    conn.close()
    return db


def _client(db: Path) -> TestClient:
    return TestClient(create_app(db))


def _issue_token(db: Path, email: str) -> str:
    conn = whitelist_db.wl_connect(db)
    try:
        profile = whitelist_db.get_profile_by_email(conn, email)
        return whitelist_db.create_password_reset_token(conn, profile["id"])
    finally:
        conn.close()


def _token_count(db: Path) -> int:
    conn = whitelist_db.wl_connect(db)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM password_reset_tokens").fetchone()[0]
    finally:
        conn.close()


# ============================================================
# Token lifecycle (DB layer)
# ============================================================


class TestTokenLifecycle:
    def test_create_peek_consume_roundtrip(self, tmp_path):
        db = _make_world(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            pid = whitelist_db.get_profile_by_email(conn, "fresh@example.com")["id"]
            raw = whitelist_db.create_password_reset_token(conn, pid)
            assert whitelist_db.peek_password_reset_token(conn, raw) == pid
            assert whitelist_db.consume_password_reset_token(conn, raw) == pid
        finally:
            conn.close()

    def test_single_use_replay_rejected(self, tmp_path):
        db = _make_world(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            pid = whitelist_db.get_profile_by_email(conn, "fresh@example.com")["id"]
            raw = whitelist_db.create_password_reset_token(conn, pid)
            assert whitelist_db.consume_password_reset_token(conn, raw) == pid
            assert whitelist_db.consume_password_reset_token(conn, raw) is None, \
                "a consumed token must not work twice"
            assert whitelist_db.peek_password_reset_token(conn, raw) is None
        finally:
            conn.close()

    def test_expiry(self, tmp_path):
        db = _make_world(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            pid = whitelist_db.get_profile_by_email(conn, "fresh@example.com")["id"]
            raw = whitelist_db.create_password_reset_token(conn, pid, ttl_minutes=-1)
            assert whitelist_db.peek_password_reset_token(conn, raw) is None
            assert whitelist_db.consume_password_reset_token(conn, raw) is None, \
                "an expired token must be rejected"
        finally:
            conn.close()

    def test_hashed_at_rest(self, tmp_path):
        db = _make_world(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            pid = whitelist_db.get_profile_by_email(conn, "fresh@example.com")["id"]
            raw = whitelist_db.create_password_reset_token(conn, pid)
            rows = conn.execute(
                "SELECT token_hash FROM password_reset_tokens").fetchall()
            assert len(rows) == 1
            assert rows[0]["token_hash"] == hashlib.sha256(
                raw.encode("utf-8")).hexdigest(), \
                "storage must hold the SHA-256 hash, not the raw token"
            for row in conn.execute(
                    "SELECT token_hash FROM password_reset_tokens").fetchall():
                assert raw not in row["token_hash"]
        finally:
            conn.close()

    def test_one_active_token_per_account(self, tmp_path):
        db = _make_world(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            pid = whitelist_db.get_profile_by_email(conn, "fresh@example.com")["id"]
            first = whitelist_db.create_password_reset_token(conn, pid)
            second = whitelist_db.create_password_reset_token(conn, pid)
            assert first != second
            assert whitelist_db.peek_password_reset_token(conn, first) is None, \
                "re-issue must invalidate the previous active token"
            assert whitelist_db.peek_password_reset_token(conn, second) == pid
            # One row per re-issue; the superseded row stays (used) for audit.
            assert conn.execute(
                "SELECT COUNT(*) FROM password_reset_tokens").fetchone()[0] == 2
            assert conn.execute(
                "SELECT COUNT(*) FROM password_reset_tokens "
                "WHERE used_at IS NULL").fetchone()[0] == 1
        finally:
            conn.close()

    def test_garbage_token_rejected(self, tmp_path):
        db = _make_world(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            assert whitelist_db.consume_password_reset_token(conn, "junk") is None
            assert whitelist_db.peek_password_reset_token(conn, "") is None
        finally:
            conn.close()


# ============================================================
# Legacy owner first-password (the captain's scenario)
# ============================================================


class TestLegacyFirstPassword:
    def test_passwordless_owner_cannot_sign_in_before(self, tmp_path):
        db = _make_world(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            assert whitelist_db.resolve_owner_by_credentials(
                conn, "jason@waltheremc.com", "firstpassword1") is None
        finally:
            conn.close()

    def test_reset_sets_first_password_and_signin_works(self, tmp_path):
        db = _make_world(tmp_path)
        client = _client(db)
        # Legacy owner signs in → blocked (no password).
        r = client.post("/signin", data={
            "email": "jason@waltheremc.com", "password": "firstpassword1"})
        assert "Invalid email or password." in r.text

        # Reset flow sets the first password.
        raw = _issue_token(db, "jason@waltheremc.com")
        r = client.post(f"/reset-password/{raw}",
                        data={"password": "firstpassword1"},
                        follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].endswith("/signin?reset=1")

        # Sign-in now works with the same credentials.
        r = client.post("/signin", data={
            "email": "jason@waltheremc.com", "password": "firstpassword1"},
            follow_redirects=False)
        assert r.status_code == 303, "legacy owner must sign in after first reset"
        assert "wl_session" in r.headers.get("set-cookie", "")


# ============================================================
# Screens
# ============================================================


class TestScreens:
    def test_signin_has_forgot_password_link(self, tmp_path):
        db = _make_world(tmp_path)
        r = _client(db).get("/signin")
        assert r.status_code == 200
        assert "/forgot-password" in r.text
        assert "Forgot password?" in r.text

    def test_forgot_password_page_renders_email_form(self, tmp_path):
        db = _make_world(tmp_path)
        r = _client(db).get("/forgot-password")
        assert r.status_code == 200
        assert 'action="/forgot-password"' in r.text
        assert 'name="email"' in r.text

    def test_reset_page_reachable_only_via_valid_token(self, tmp_path):
        db = _make_world(tmp_path)
        client = _client(db)
        r = client.get("/reset-password/not-a-real-token")
        assert r.status_code == 403
        assert 'name="password"' not in r.text, \
            "the set-password form must not render for a dead token"
        assert "/forgot-password" in r.text, "offer a path back"

        raw = _issue_token(db, "fresh@example.com")
        r = client.get(f"/reset-password/{raw}")
        assert r.status_code == 200
        assert 'name="password"' in r.text
        assert 'minlength="8"' in r.text

    def test_get_does_not_consume_token(self, tmp_path):
        db = _make_world(tmp_path)
        client = _client(db)
        raw = _issue_token(db, "fresh@example.com")
        client.get(f"/reset-password/{raw}")
        client.get(f"/reset-password/{raw}")
        r = client.get(f"/reset-password/{raw}")
        assert r.status_code == 200, "viewing the form must not burn the token"

    def test_successful_reset_redirects_to_signin_banner(self, tmp_path):
        db = _make_world(tmp_path)
        client = _client(db)
        raw = _issue_token(db, "fresh@example.com")
        r = client.post(f"/reset-password/{raw}",
                        data={"password": "newpassword99"},
                        follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].endswith("/signin?reset=1")
        banner = client.get("/signin?reset=1")
        assert "Password updated" in banner.text

    def test_short_password_rejected_and_token_preserved(self, tmp_path):
        db = _make_world(tmp_path)
        client = _client(db)
        raw = _issue_token(db, "fresh@example.com")
        r = client.post(f"/reset-password/{raw}", data={"password": "short"})
        assert "at least 8 characters" in r.text, "same rule as signup"
        # Token must still work after the rejected attempt.
        r = client.post(f"/reset-password/{raw}",
                        data={"password": "newpassword99"},
                        follow_redirects=False)
        assert r.status_code == 303, "rejected attempt must not burn the link"

    def test_short_password_does_not_change_password(self, tmp_path):
        db = _make_world(tmp_path)
        client = _client(db)
        raw = _issue_token(db, "fresh@example.com")
        client.post(f"/reset-password/{raw}", data={"password": "short"})
        conn = whitelist_db.wl_connect(db)
        try:
            profile = whitelist_db.resolve_owner_by_credentials(
                conn, "fresh@example.com", "password123")
            assert profile is not None, "old password must still work"
            assert whitelist_db.resolve_owner_by_credentials(
                conn, "fresh@example.com", "short") is None
        finally:
            conn.close()


# ============================================================
# Forgot-password POST: confirmation + no user enumeration
# ============================================================


_CONFIRMATION = "If an account exists for that email"


class TestForgotPasswordNoEnumeration:
    def test_known_email_gets_confirmation_and_token(self, tmp_path):
        db = _make_world(tmp_path)
        before = _token_count(db)
        r = _client(db).post("/forgot-password",
                             data={"email": "fresh@example.com"})
        assert r.status_code == 200
        assert _CONFIRMATION in r.text
        assert _token_count(db) == before + 1, "a token must be issued"

    def test_unknown_email_gets_identical_confirmation(self, tmp_path):
        db = _make_world(tmp_path)
        client = _client(db)
        known = client.post("/forgot-password",
                            data={"email": "fresh@example.com"})
        unknown = client.post("/forgot-password",
                              data={"email": "nobody@nowhere.org"})
        assert unknown.status_code == known.status_code == 200
        assert unknown.text == known.text, \
            "responses must be byte-identical — no enumeration oracle"
        assert _token_count(db) == 1, "no token for an unknown email"

    def test_confirmation_even_when_delivery_fails(self, tmp_path):
        db = _make_world(tmp_path)
        client = _client(db)
        ok = client.post("/forgot-password", data={"email": "fresh@example.com"})
        assert ok.status_code == 200 and _CONFIRMATION in ok.text

        def boom(*a, **kw):
            raise RuntimeError("SMTP down")
        orig = notify_script.send_email
        notify_script.send_email = boom
        try:
            failed = client.post("/forgot-password",
                                 data={"email": "fresh@example.com"})
        finally:
            notify_script.send_email = orig
        assert failed.status_code == 200
        assert _CONFIRMATION in failed.text, \
            "delivery failure must not leak account existence"

    def test_email_not_echoed_in_confirmation(self, tmp_path):
        db = _make_world(tmp_path)
        r = _client(db).post("/forgot-password",
                             data={"email": "fresh@example.com"})
        assert "fresh@example.com" not in r.text


# ============================================================
# Delivery through the existing notify path + CLI fallback
# ============================================================


class TestDelivery:
    def test_reset_email_sent_via_notify_path(self, tmp_path, monkeypatch):
        db = _make_world(tmp_path)
        calls = []

        def fake_send(to_addr, subject, body):
            calls.append((to_addr, subject, body))

        monkeypatch.setattr(notify_script, "send_email", fake_send)
        r = _client(db).post("/forgot-password",
                             data={"email": "fresh@example.com"})
        assert r.status_code == 200
        assert len(calls) == 1
        to_addr, subject, body = calls[0]
        assert to_addr == "fresh@example.com"
        assert "reset" in subject.lower()
        # The body's URL must carry a live token for this account.
        url_line = [ln for ln in body.splitlines() if "/reset-password/" in ln][0]
        raw = url_line.strip().rsplit("/", 1)[1]
        conn = whitelist_db.wl_connect(db)
        try:
            pid = whitelist_db.get_profile_by_email(conn, "fresh@example.com")["id"]
            assert whitelist_db.peek_password_reset_token(conn, raw) == pid, \
                "emailed token must be the live single-use token"
        finally:
            conn.close()

    def test_cli_fallback_prints_working_reset_url(self, tmp_path, capsys):
        db = _make_world(tmp_path)
        notify_script.notify_reset(dry_run=True, email="jason@waltheremc.com",
                                   db_path=db)
        out = capsys.readouterr().out
        assert "[DRY-RUN]" in out
        link = [ln.strip() for ln in out.splitlines()
                if "/reset-password/" in ln][0]
        raw = link.rsplit("/", 1)[1]
        # The printed URL is the captain's once-only way in: it must work.
        client = _client(db)
        r = client.post(f"/reset-password/{raw}",
                        data={"password": "firstpassword1"},
                        follow_redirects=False)
        assert r.status_code == 303
        conn = whitelist_db.wl_connect(db)
        try:
            assert whitelist_db.resolve_owner_by_credentials(
                conn, "jason@waltheremc.com", "firstpassword1") is not None
        finally:
            conn.close()

    def test_cli_fallback_reissue_invalidates_previous(self, tmp_path, capsys):
        db = _make_world(tmp_path)
        notify_script.notify_reset(dry_run=True, email="fresh@example.com",
                                   db_path=db)
        first = capsys.readouterr().out
        notify_script.notify_reset(dry_run=True, email="fresh@example.com",
                                   db_path=db)
        second = capsys.readouterr().out
        first_raw = first.rsplit("/", 1)[1].strip()
        second_raw = second.rsplit("/", 1)[1].strip()
        assert first_raw != second_raw
        conn = whitelist_db.wl_connect(db)
        try:
            assert whitelist_db.peek_password_reset_token(conn, first_raw) is None
            assert whitelist_db.peek_password_reset_token(conn, second_raw) is not None
        finally:
            conn.close()

    def test_cli_fallback_unknown_email_fails_loud(self, tmp_path):
        db = _make_world(tmp_path)
        with pytest.raises(SystemExit):
            notify_script.notify_reset(dry_run=True,
                                       email="nobody@nowhere.org", db_path=db)

    def test_cli_reset_requires_email_flag(self):
        with pytest.raises(SystemExit):
            notify_script.notify_reset(dry_run=True, email=None)
