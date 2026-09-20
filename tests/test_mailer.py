"""Mailer config layer (2026-09-20): SMTP settings block + pluggable transport.

Pins:
- Defaults per the captain ruling: smtp.gmail.com:587 STARTTLS, from
  jasonlnheath@gmail.com; port 465 flips to implicit SSL.
- Config comes from env/.env only (wl_env) — NOTHING is hardcoded, and an
  absent SMTP_USER/SMTP_PASS means "no mail", never a crash.
- send_email builds the envelope (From/To/Subject/body/Reply-To) and hands
  it to the transport; tests inject a recording stub — NO live sends here
  or in any test in this suite.
- app_base_url resolution: APP_BASE_URL > legacy BASE_URL > the LAN default
  http://192.168.1.200:8099 (so reset links work on the home network today).
- scripts/notify.send_email delegates to this layer (one funnel for all
  outbound mail) and keeps its CLI contract (exit 1 when unconfigured).
"""
import os
from email.mime.text import MIMEText

import pytest

os.environ.setdefault("WHITELIST_SECRET", "test-secret")

import mailer
from scripts import notify as notify_script


def _env(mapping):
    """Env getter injection: mapping lookup, everything else absent."""
    return lambda key: mapping.get(key, "")


def _clear_mail_env(monkeypatch):
    for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS",
                "SMTP_FROM", "SMTP_REPLY_TO", "APP_BASE_URL", "BASE_URL"):
        monkeypatch.delenv(key, raising=False)


class TestLoadConfig:
    def test_unconfigured_when_user_or_pass_missing(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        assert mailer.load_config(env=_env({})) is None
        assert mailer.load_config(env=_env({"SMTP_USER": "u@x.com"})) is None
        assert mailer.load_config(env=_env({"SMTP_PASS": "p"})) is None

    def test_gmail_defaults(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        cfg = mailer.load_config(env=_env({
            "SMTP_USER": "jasonlnheath@gmail.com",
            "SMTP_PASS": "app-password",
        }))
        assert cfg is not None
        assert cfg.host == "smtp.gmail.com"
        assert cfg.port == 587
        assert cfg.use_ssl is False, "587 must use STARTTLS, not implicit SSL"
        assert cfg.from_addr == "jasonlnheath@gmail.com", "2026-09-20 ruling"
        assert cfg.reply_to is None

    def test_port_465_selects_implicit_ssl(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        cfg = mailer.load_config(env=_env({
            "SMTP_USER": "u@x.com", "SMTP_PASS": "p", "SMTP_PORT": "465",
        }))
        assert cfg.port == 465
        assert cfg.use_ssl is True

    def test_junk_port_degrades_to_default(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        cfg = mailer.load_config(env=_env({
            "SMTP_USER": "u@x.com", "SMTP_PASS": "p", "SMTP_PORT": "smtp",
        }))
        assert cfg.port == 587

    def test_from_and_reply_to_overridable(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        cfg = mailer.load_config(env=_env({
            "SMTP_USER": "hello@heath.example",
            "SMTP_PASS": "p",
            "SMTP_FROM": "hello@heath.example",
            "SMTP_REPLY_TO": "jasonlnheath@gmail.com",
        }))
        assert cfg.from_addr == "hello@heath.example", \
            "custom domain must be a config flip, zero code"
        assert cfg.reply_to == "jasonlnheath@gmail.com"


class TestSendEmail:
    def test_unconfigured_sends_nothing_and_returns_false(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        calls = []

        def spy(config, msg, to_addr):
            calls.append((config, msg, to_addr))

        assert mailer.send_email("a@b.com", "s", "b",
                                 env=_env({}), transport=spy) is False
        assert calls == [], "unconfigured SMTP must never reach a transport"

    def test_envelope_via_stub_transport(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        calls = []

        def stub(config, msg, to_addr):
            calls.append((config, msg, to_addr))

        ok = mailer.send_email(
            "owner@example.com", "RelMgr: reset your password",
            "Set a new password here:\nhttp://x/reset-password/t",
            env=_env({"SMTP_USER": "jasonlnheath@gmail.com",
                      "SMTP_PASS": "app-password"}),
            transport=stub)
        assert ok is True
        assert len(calls) == 1
        config, msg, to_addr = calls[0]
        assert to_addr == "owner@example.com"
        assert isinstance(msg, MIMEText)
        assert msg["To"] == "owner@example.com"
        assert msg["From"] == "jasonlnheath@gmail.com"
        assert msg["Subject"] == "RelMgr: reset your password"
        assert "/reset-password/t" in msg.get_payload()

    def test_transport_failure_returns_false_not_raises(self, monkeypatch):
        _clear_mail_env(monkeypatch)

        def boom(config, msg, to_addr):
            raise ConnectionRefusedError("smtp down")

        ok = mailer.send_email("a@b.com", "s", "b",
                               env=_env({"SMTP_USER": "u@x.com",
                                         "SMTP_PASS": "p"}),
                               transport=boom)
        assert ok is False


class TestAppBaseUrl:
    def test_lan_default(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        assert mailer.app_base_url(env=_env({})) == "http://192.168.1.200:8099"

    def test_app_base_url_wins(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        assert mailer.app_base_url(env=_env({
            "APP_BASE_URL": "https://cards.heath.example",
            "BASE_URL": "http://10.0.0.1:8099",
        })) == "https://cards.heath.example"

    def test_legacy_base_url_still_honored(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        assert mailer.app_base_url(env=_env({
            "BASE_URL": "http://10.0.0.1:8099",
        })) == "http://10.0.0.1:8099"


class TestNotifyDelegatesToMailer:
    """One funnel: scripts/notify.send_email is a thin wrapper over the
    mailer layer — every outbound path (reset, quarterly, verify,
    owner-link, connection requests) resolves its SMTP config here."""

    def test_delegate_passes_envelope_through(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        calls = []

        def recorder(to, subj, body):
            calls.append((to, subj, body))
            return True  # truthy: notify treats falsy as delivery failure

        monkeypatch.setattr(mailer, "send_email", recorder)
        notify_script.send_email("a@b.com", "subj", "body")
        assert calls == [("a@b.com", "subj", "body")]

    def test_delegate_exits_1_when_unconfigured(self, monkeypatch):
        _clear_mail_env(monkeypatch)
        monkeypatch.setattr(mailer, "send_email", lambda to, subj, body: False)
        with pytest.raises(SystemExit) as exc:
            notify_script.send_email("a@b.com", "subj", "body")
        assert exc.value.code == 1
