"""RelMgr outbound mail layer (2026-09-20).

ONE place for SMTP configuration + the pluggable send transport. Every
outbound path (password reset, quarterly digest, connection-request
alerts, verify/owner-link mail) routes through ``send_email`` here.

Captain ruling 2026-09-20: send from jasonlnheath@gmail.com for now,
BUT prepare the code for a proper domain — switching later is editing
config only (env vars or .env), zero code changes.

Configuration (read lazily via wl_env: env vars first, then .env —
never hardcoded, credentials NEVER committed; see .env.example):

    SMTP_HOST      default smtp.gmail.com
    SMTP_PORT      default 587 (STARTTLS); 465 selects implicit SSL
    SMTP_USER      required — mailbox that authenticates
    SMTP_PASS      required — app password (Gmail: generate one at
                   https://myaccount.google.com/apppasswords)
    SMTP_FROM      default jasonlnheath@gmail.com (the current ruling)
    SMTP_REPLY_TO  optional

    APP_BASE_URL   base for every outbound link; legacy BASE_URL is
                   still honored; default http://192.168.1.200:8099 so
                   reset links WORK on the LAN today.

Tests never touch the network: pass ``transport=`` (a callable taking
(config, message)) or monkeypatch the module-level ``_smtp_transport``.
"""

import smtplib
import sys
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Callable, Optional

import wl_env

# Defaults per the 2026-09-20 ruling. Overridable purely by config.
DEFAULT_SMTP_HOST = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 587
DEFAULT_FROM_ADDR = "jasonlnheath@gmail.com"
DEFAULT_APP_BASE_URL = "http://192.168.1.200:8099"



@dataclass
class SmtpConfig:
    """One resolved SMTP settings block — built only when required keys
    (SMTP_USER/SMTP_PASS) are present."""

    host: str
    port: int
    user: str
    password: str
    from_addr: str
    reply_to: Optional[str] = None
    use_ssl: bool = False


# A transport does the actual hand-off; tests inject recorders.
Transport = Callable[[SmtpConfig, MIMEText, str], None]


def load_config(env: Optional[Callable[[str], str]] = None) -> Optional[SmtpConfig]:
    """Resolve SMTP settings from env/.env. Returns None when unconfigured.

    ``env`` is a key->value getter (defaults to wl_env.get_secret) so tests
    can inject a mapping without touching os.environ. Required: SMTP_USER
    and SMTP_PASS — host/port/from have safe defaults. A missing password
    must mean "no mail", never a crash or a half-send.
    """
    get = env or wl_env.get_secret
    host = get("SMTP_HOST") or DEFAULT_SMTP_HOST
    user = get("SMTP_USER")
    password = get("SMTP_PASS")
    if not user or not password:
        return None
    try:
        port = int(get("SMTP_PORT") or DEFAULT_SMTP_PORT)
    except ValueError:
        port = DEFAULT_SMTP_PORT
    return SmtpConfig(
        host=host,
        port=port,
        user=user,
        password=password,
        from_addr=get("SMTP_FROM") or DEFAULT_FROM_ADDR,
        reply_to=get("SMTP_REPLY_TO") or None,
        # 465 is implicit-SSL per the spec ("587 STARTTLS or 465 SSL —
        # use whatever the mail library handles cleanly": both, by port).
        use_ssl=(port == 465),
    )


def _smtp_transport(config: SmtpConfig, msg: MIMEText, to_addr: str) -> None:
    """The real network send. Module-level so tests can monkeypatch it."""
    if config.use_ssl:
        with smtplib.SMTP_SSL(config.host, config.port) as server:
            server.login(config.user, config.password)
            server.sendmail(config.from_addr, [to_addr], msg.as_string())
    else:
        with smtplib.SMTP(config.host, config.port) as server:
            server.starttls()
            server.login(config.user, config.password)
            server.sendmail(config.from_addr, [to_addr], msg.as_string())


def send_email(
    to_addr: str,
    subject: str,
    body: str,
    *,
    config: Optional[SmtpConfig] = None,
    env: Optional[Callable[[str], str]] = None,
    transport: Optional[Transport] = None,
) -> bool:
    """Send one plain-text email. Returns True on success.

    Unconfigured SMTP or ANY delivery failure returns False — callers
    (reset flow, notification pushes) degrade gracefully; nothing here
    sys.exits, that contract stays in scripts/notify.py for the CLI.
    ``transport`` injection keeps tests off the network entirely.
    """
    cfg = config or load_config(env=env)
    if cfg is None:
        print(
            "[mailer] SMTP not configured (SMTP_USER/SMTP_PASS missing) — "
            "no mail sent. See .env.example.",
            file=sys.stderr,
        )
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = cfg.from_addr
    msg["To"] = to_addr
    if cfg.reply_to:
        msg["Reply-To"] = cfg.reply_to

    sender = transport or _smtp_transport
    try:
        sender(cfg, msg, to_addr)
        return True
    except Exception as exc:  # noqa: BLE001 — a mail failure must never 500 a page
        print(f"[mailer] send to {to_addr} failed: {exc}", file=sys.stderr)
        return False


def app_base_url(env: Optional[Callable[[str], str]] = None) -> str:
    """Base URL used in every outbound link (reset, decision views, QR).

    Resolution: APP_BASE_URL > legacy BASE_URL > the LAN default, so reset
    links work on the home network today and a future domain is a config
    flip only.
    """
    get = env or wl_env.get_secret
    return get("APP_BASE_URL") or get("BASE_URL") or DEFAULT_APP_BASE_URL
