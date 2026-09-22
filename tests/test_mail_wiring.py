"""Mail-layer wiring (2026-09-20): reset / quarterly / connection-request
paths call the transport with the correct envelope; connection requests
raise the in-app row AND the email push; the dashboard carries the unread
badge; the notifications page + read routes close the loop.

No live sends anywhere: the transport is stubbed at the mailer seam
(`mailer._smtp_transport`), which every outbound path funnels through.
"""
import os

import pytest

os.environ["WHITELIST_SECRET"] = "test-secret"

from fastapi.testclient import TestClient
from pathlib import Path

import whitelist_db
import mailer
import wl_tokens
from app import create_app


@pytest.fixture
def mail_env(monkeypatch):
    """Deterministic SMTP config: Gmail defaults + a from-address, no
    APP_BASE_URL/BASE_URL (so the LAN default is observable)."""
    for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS",
                "SMTP_FROM", "SMTP_REPLY_TO", "APP_BASE_URL", "BASE_URL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SMTP_USER", "jasonlnheath@gmail.com")
    monkeypatch.setenv("SMTP_PASS", "app-password")
    return monkeypatch


@pytest.fixture
def recorder(monkeypatch):
    """Recording transport stub at the one seam every path funnels through."""
    calls = []

    def stub(config, msg, to_addr):
        calls.append({
            "to": to_addr,
            "from": msg["From"],
            "subject": msg["Subject"],
            "body": msg.get_payload(),
        })

    monkeypatch.setattr(mailer, "_smtp_transport", stub)
    return calls


@pytest.fixture
def world(tmp_path):
    """One signed-in owner with an email field; returns (db, client, owner_id)."""
    db = tmp_path / "wire.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    pid = whitelist_db.create_owner_profile(
        conn, "owner1", "Owner One", "owner1@example.com", "password123")["id"]
    # create_owner_profile seeds the email profile_field itself.
    conn.close()

    client = TestClient(create_app(db))
    r = client.post("/signin", data={
        "email": "owner1@example.com", "password": "password123"},
        follow_redirects=False)
    assert r.status_code == 303, "world build: sign-in must work"
    tok = wl_tokens.make_token(b"test-secret", "owner_dashboard", str(pid),
                               expires_days=7)
    return db, client, pid, tok


class TestConnectionRequestFlow:
    def test_request_creates_inapp_row_and_email_push(self, world, mail_env, recorder):
        db, client, pid, tok = world
        r = client.post("/p/owner1/request", data={
            "name": "New Person", "email": "newperson@example.com"})
        assert r.status_code == 200

        # Layer 1 — in-app notification row (the source of truth).
        conn = whitelist_db.wl_connect(db)
        try:
            rows = whitelist_db.list_notifications(conn, pid)
        finally:
            conn.close()
        assert len(rows) == 1
        row = rows[0]
        assert row["kind"] == "connection_request"
        assert "New Person" in row["title"]
        assert row["read_at"] is None, "must arrive unread"
        assert row["grant_id"], "decision surface must be reachable"

        # Layer 2 — the email push with a live decision link.
        assert len(recorder) == 1
        mail = recorder[0]
        assert mail["to"] == "owner1@example.com"
        assert mail["from"] == "jasonlnheath@gmail.com", "2026-09-20 ruling"
        assert "connection request" in mail["subject"].lower()
        link = [ln.strip() for ln in mail["body"].splitlines()
                if "/a/" in ln][0]
        assert link.startswith("http://192.168.1.200:8099/"), \
            "default base must be the LAN, not whitelist.app"
        token = link.rsplit("/", 1)[1]
        grant_id = wl_tokens.consume_token(
            b"test-secret", "grant_review", token)
        assert grant_id == row["grant_id"], \
            "emailed link must open the live decision view for this grant"

    def test_unconfigured_smtp_still_creates_inapp_row(self, world, monkeypatch, recorder):
        mail_env = monkeypatch  # clarity
        monkeypatch.delenv("SMTP_PASS", raising=False)  # now unconfigured
        db, client, pid, tok = world
        r = client.post("/p/owner1/request", data={
            "name": "No Mail", "email": "nomail@example.com"})
        assert r.status_code == 200, "delivery failure must not break the page"
        assert recorder == [], "no transport call without credentials"
        conn = whitelist_db.wl_connect(db)
        try:
            rows = whitelist_db.list_notifications(conn, pid)
        finally:
            conn.close()
        assert len(rows) == 1, "in-app row is the source of truth — it must survive SMTP being down"

    def test_duplicate_request_single_notification(self, world, mail_env, recorder):
        db, client, pid, tok = world
        for _ in range(2):
            client.post("/p/owner1/request", data={
                "name": "Dup", "email": "dup@example.com"})
        conn = whitelist_db.wl_connect(db)
        try:
            rows = whitelist_db.list_notifications(conn, pid)
        finally:
            conn.close()
        assert len(rows) == 1, "re-POST of a pending grant must not re-alert"

    def test_forward_creates_notification_and_email(self, world, mail_env, recorder):
        db, client, pid, tok = world
        # A granted forwarder (lifetime, so it stays live).
        conn = whitelist_db.wl_connect(db)
        try:
            gid = whitelist_db.create_grant(
                conn, pid, "friend@example.com", "Friend")
            whitelist_db.update_grant_status(conn, gid, "granted",
                                             granted_at="2026-09-01T00:00:00Z",
                                             expires_at=None)
        finally:
            conn.close()
        r = client.post("/p/owner1/forward", data={
            "forwarder_email": "friend@example.com",
            "forwarder_name": "Friend",
            "recipient_email": "newbie@example.com",
            "recipient_name": "Newbie"})
        assert r.status_code == 200

        conn = whitelist_db.wl_connect(db)
        try:
            rows = [x for x in whitelist_db.list_notifications(conn, pid)
                    if x["kind"] == "forward"]
        finally:
            conn.close()
        assert len(rows) == 1
        assert "forwarded by Friend" in rows[0]["title"]
        assert recorder and "newbie@example.com" in recorder[0]["body"]
        assert "/a/" in recorder[0]["body"], "owner gets the decision view link"


class TestDashboardBadgeAndCenter:
    def test_unread_badge_on_dashboard(self, world, mail_env, recorder):
        db, client, pid, tok = world
        client.post("/p/owner1/request", data={
            "name": "Badge", "email": "badge@example.com"})
        dash = client.get(f"/owner/{tok}", follow_redirects=True)
        assert dash.status_code == 200
        assert "/owner/" in dash.text and "notifications" in dash.text
        # PR 16 re-rendered the bell as a text link: the unread count sits
        # inline before the word ("1 Notifications").
        assert "1 Notifications" in dash.text, "unread count must show on the dashboard link"

    def test_badge_clears_after_mark_read(self, world, mail_env, recorder):
        db, client, pid, tok = world
        client.post("/p/owner1/request", data={
            "name": "Clear", "email": "clear@example.com"})
        page = client.get(f"/owner/{tok}/notifications")
        assert page.status_code == 200
        assert "Connection request from Clear" in page.text

        conn = whitelist_db.wl_connect(db)
        try:
            nid = whitelist_db.list_notifications(conn, pid)[0]["id"]
        finally:
            conn.close()
        r = client.post(f"/owner/{tok}/notifications/{nid}/read",
                        follow_redirects=False)
        assert r.status_code == 303
        dash = client.get(f"/owner/{tok}", follow_redirects=True)
        assert ">1</span>" not in dash.text

    def test_mark_all_read(self, world, mail_env, recorder):
        db, client, pid, tok = world
        for i in range(2):
            client.post("/p/owner1/request", data={
                "name": f"M{i}", "email": f"m{i}@example.com"})
        r = client.post(f"/owner/{tok}/notifications/read-all",
                        follow_redirects=False)
        assert r.status_code == 303
        conn = whitelist_db.wl_connect(db)
        try:
            assert whitelist_db.unread_notification_count(conn, pid) == 0
            assert client.get(f"/owner/{tok}/notifications").text.count("Mark read") == 0
        finally:
            conn.close()

    def test_owner_isolation_on_center(self, tmp_path, mail_env, recorder):
        db = tmp_path / "iso.db"
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        a = whitelist_db.create_owner_profile(
            conn, "ownera", "A", "a@example.com", "password123")["id"]
        b = whitelist_db.create_owner_profile(
            conn, "ownerb", "B", "b@example.com", "password123")["id"]
        conn.close()

        client_a = TestClient(create_app(db))
        client_a.post("/signin", data={"email": "a@example.com",
                                       "password": "password123"})
        client_a.post("/p/ownera/request", data={
            "name": "Stranger", "email": "stranger@example.com"})

        client_b = TestClient(create_app(db))
        client_b.post("/signin", data={"email": "b@example.com",
                                       "password": "password123"})
        tok_b = wl_tokens.make_token(b"test-secret", "owner_dashboard",
                                     str(b), expires_days=7)
        page = client_b.get(f"/owner/{tok_b}/notifications")
        assert page.status_code == 200
        assert "Stranger" not in page.text, "another owner's rows are unreachable"
        assert "No notifications yet" in page.text

        conn = whitelist_db.wl_connect(db)
        try:
            nid = whitelist_db.list_notifications(conn, a)[0]["id"]
        finally:
            conn.close()
        client_b.post(f"/owner/{tok_b}/notifications/{nid}/read")
        conn = whitelist_db.wl_connect(db)
        try:
            assert whitelist_db.unread_notification_count(conn, a) == 1, \
                "foreign mark-read must be a no-op"
        finally:
            conn.close()


class TestResetAndQuarterlyLinks:
    def test_reset_email_uses_configured_base(self, world, mail_env, recorder):
        db, client, pid, tok = world
        mail_env.setenv("APP_BASE_URL", "http://192.168.1.200:8099")
        r = client.post("/forgot-password",
                        data={"email": "owner1@example.com"})
        assert r.status_code == 200
        assert len(recorder) == 1
        link = [ln.strip() for ln in recorder[0]["body"].splitlines()
                if "/reset-password/" in ln][0]
        assert link.startswith("http://192.168.1.200:8099/reset-password/")
        assert "whitelist.app" not in link

    def test_reset_email_default_is_lan_not_whitelist_app(self, world, mail_env, recorder):
        db, client, pid, tok = world
        client.post("/forgot-password", data={"email": "owner1@example.com"})
        link = [ln.strip() for ln in recorder[0]["body"].splitlines()
                if "/reset-password/" in ln][0]
        assert link.startswith("http://192.168.1.200:8099/"), \
            "reset links must work on the LAN today"

    def test_reset_envelope(self, world, mail_env, recorder):
        db, client, pid, tok = world
        client.post("/forgot-password", data={"email": "owner1@example.com"})
        assert recorder[0]["to"] == "owner1@example.com"
        assert "reset" in recorder[0]["subject"].lower()
        assert recorder[0]["from"] == "jasonlnheath@gmail.com"

    def test_quarterly_digest_link_uses_app_base(self, tmp_path, mail_env, recorder):
        from notify import build_quarterly_review
        db = tmp_path / "q.db"
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        pid = whitelist_db.create_owner_profile(
            conn, "qowner", "Q", "q@example.com", "password123")["id"]
        conn.execute(
            """INSERT INTO access_grants (id, profile_id, requester_email,
               requester_name, status, expires_at)
               VALUES ('gq', ?, 'grey@x.com', 'Grey', 'granted',
                       '2020-01-01T00:00:00Z')""", (pid,))
        conn.commit()
        digest = build_quarterly_review(conn)
        conn.close()
        assert digest is not None
        assert f"{mailer.app_base_url()}/dashboard" in digest
        assert "whitelist.example.com" not in digest


class TestDashboardQuarterlyPrompt:
    def test_grey_contacts_raise_quarterly_notification_on_dashboard(
            self, world, mail_env, recorder):
        db, client, pid, tok = world
        conn = whitelist_db.wl_connect(db)
        try:
            conn.execute(
                """INSERT INTO access_grants (id, profile_id, requester_email,
                   requester_name, status, expires_at)
                   VALUES ('g-grey', ?, 'grey@x.com', 'Grey', 'granted',
                           '2020-01-01T00:00:00Z')""", (pid,))
            conn.commit()
        finally:
            conn.close()
        client.get(f"/owner/{tok}", follow_redirects=True)
        conn = whitelist_db.wl_connect(db)
        try:
            kinds = [r["kind"] for r in whitelist_db.list_notifications(conn, pid)]
        finally:
            conn.close()
        assert "quarterly" in kinds
        # Second render must not duplicate (idempotent per quarter).
        client.get(f"/owner/{tok}", follow_redirects=True)
        conn = whitelist_db.wl_connect(db)
        try:
            assert kinds.count("quarterly") == 1
            assert len([r for r in whitelist_db.list_notifications(conn, pid)
                        if r["kind"] == "quarterly"]) == 1
        finally:
            conn.close()
