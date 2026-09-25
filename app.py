"""FastAPI application for the whitelist service.

Module-level ``app`` is a real FastAPI instance so that
``uvicorn app:app`` works out of the box (F2). Secrets are read lazily
per-request, never at import time — importing this module must not
require WHITELIST_SECRET to be present.
"""

from pathlib import Path
import hmac
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask
from PIL import Image
from io import BytesIO
from starlette.templating import Jinja2Templates
from jinja2 import pass_context

import whitelist_db
import wl_tokens
import wl_env
import mailer

_NOW_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _parse_dt(value: str):
    """Parse the timestamp formats this DB actually stores.

    Returns a naive UTC datetime, or None if unparseable. Stored values are
    a mix of date-only ('2026-09-10'), space-separated ('2026-09-05 12:34:56')
    and ISO-8601 Z forms — all normalized to naive UTC for arithmetic.
    """
    if value is None:
        return None
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def days_since(value: str) -> int:
    """Whole days between a stored timestamp and now (0 on bad/None input)."""
    dt = _parse_dt(value)
    if dt is None:
        return 0
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - dt
    return max(0, delta.days)


def days_until(value: str) -> int:
    """Whole days from now until a stored timestamp (0 on bad/None input)."""
    dt = _parse_dt(value)
    if dt is None:
        return 0
    delta = dt - datetime.now(timezone.utc).replace(tzinfo=None)
    return max(0, delta.days)


_STALE_AFTER_DAYS = 180


def _rail_letter(name: str) -> str:
    """Pairing-review F2 (2026-09-22): fold a name's initial onto the A–Z
    rail. Accented Latin initials (É, Ü, …) group under their ASCII base
    letter; anything non-alphabetic (digits, CJK, …) lands in the '#'
    bucket so every contact stays reachable from the rail."""
    import unicodedata
    initial = (name or " ")[:1]
    if not initial.isalpha():
        return "#"
    folded = unicodedata.normalize("NFKD", initial) \
        .encode("ascii", "ignore").decode("ascii").upper()
    return folded if folded else "#"


def is_verified_stale(value) -> bool:
    """True when a profile's verified_at is more than 180 days old.

    Boundary (>180 days) lives HERE, not inlined in the /p route. Missing or
    unparseable timestamps are never stale (False) — same as the route's old
    try/except. ``value`` may be date-only, space-separated, or ISO-8601 Z;
    all are normalized via _parse_dt before the comparison.
    """
    dt = _parse_dt(value)
    if dt is None:
        return False
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - dt
    return delta.days > _STALE_AFTER_DAYS


def _get_secret():
    """Read WHITELIST_SECRET at call time (env first, then .env file)."""
    return wl_env.get_secret("WHITELIST_SECRET").encode()


_JINJA_DIR = Path(__file__).parent / "templates"


def _encode_square_jpeg(content: bytes) -> bytes:
    """Validate + normalize an uploaded or client-cropped image for storage.

    Magic-byte sniff (JPEG/PNG only), PIL verify, center-crop to square
    (the client cropper already squares; this is defense in depth), then
    Lanczos-resample to the stored display size: 512×512 JPEG q82.

    Raises ValueError on junk/unsupported content (route maps to 400).
    """
    import io
    if not (content[:3] == b"\xff\xd8\xff" or content[:4] == b"\x89PNG"):
        raise ValueError("unsupported image format")
    try:
        img = Image.open(io.BytesIO(content))
        img.verify()
        img = Image.open(io.BytesIO(content))
        if img.format not in ("JPEG", "PNG"):
            raise ValueError("unsupported image format")
        w, h = img.size
        side = min(w, h)
        left = (w - side) // 2
        top = (h - side) // 2
        img = img.crop((left, top, left + side, top + side))
        img = img.resize((512, 512), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=82)
        return buf.getvalue()
    except ValueError:
        raise
    except Exception:
        raise ValueError("invalid image file")


def _make_jinja():
    jinja = Jinja2Templates(directory=str(_JINJA_DIR))
    # UX pass 2: phone label rendering shared by every field-row template.
    jinja.env.globals["label_display"] = whitelist_db.label_display
    # UX pass 3: +1(XXX)XXX-XXXX display formatting, one formatter for every
    # surface (stored values are never rewritten).
    jinja.env.globals["phone_fmt"] = whitelist_db.format_phone_display
    return jinja


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    import base64
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _make_session_cookie(profile_id: int, secret: bytes) -> str:
    """Create a signed session cookie value (7-day expiry)."""
    expiry = int(time.time()) + 7 * 86400
    payload = f"{profile_id}|{expiry}"
    payload_b64 = _b64url_encode(payload.encode())
    sig = hmac.new(
        secret, f"session|{payload_b64}".encode(), "sha256"
    ).hexdigest()
    return f"{payload_b64}.{sig}"


def _consume_session_cookie(cookie_value: str, secret: bytes):
    """Validate session cookie; returns profile_id int or None."""
    try:
        parts = cookie_value.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        inner = _b64url_decode(payload_b64).decode()
        parts2 = inner.rsplit("|", 1)
        profile_id = int(parts2[0])
        expiry = int(parts2[1])
        if int(time.time()) > expiry:
            return None
        signing_input = f"session|{payload_b64}"
        expected_sig = hmac.new(
            secret, signing_input.encode(), "sha256"
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        return profile_id
    except Exception:
        return None


class LegacyOwnerLinkRetired(Exception):
    """A validly-signed pre-migration owner dashboard link.

    The old unscoped magic links (non-integer payload, e.g. the 365-day
    'owner' links) are RETIRED — captain ruling 2026-09-20, option A. The
    app-wide handler redirects holders to sign-in with no data access.
    """


def _resolve_owner(
    conn, request, token: str, secret: bytes
):
    """Resolve the owner profile from URL token OR session cookie.

    Returns (profile_id, profile_dict, redirect_token_or_None, is_explicit).
    If redirect_token is set, the caller should redirect to /owner/{token}.
    If profile_id is None, the caller should return 403.
    is_explicit is True when the user was authenticated via session cookie
    or a valid URL token.

    Retired links: a validly-signed token with a non-integer payload (the
    pre-migration format) raises LegacyOwnerLinkRetired — handled app-wide
    as a redirect to /signin with no data access. Legacy owners use the
    same sign-in/sign-up as everyone else (captain ruling, option A).
    Tokens that are tampered/expired return 403 via (None, None, None, False).
    """
    # Try URL token first
    if token:
        payload = wl_tokens.consume_token(secret, "owner_dashboard", token)
        if payload is not None:
            # Token is valid — the payload must be an integer profile ID.
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                # Validly signed but pre-migration format: the legacy
                # DB fallback is retired (ruling 2026-09-20, option A).
                raise LegacyOwnerLinkRetired(payload)
            if profile_id:
                profile = whitelist_db.get_profile_by_id(conn, profile_id)
                if profile:
                    return profile_id, profile, None, True
            # Integer payload but no such profile — dead link → 403.
            return None, None, None, False
        else:
            # Token present but INVALID (tampered/expired) — return 403
            return None, None, None, False

    # Try session cookie (only when no URL token)
    session_cookie = request.cookies.get("wl_session")
    if session_cookie:
        profile_id = _consume_session_cookie(session_cookie, secret)
        if profile_id:
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if profile:
                fresh_token = wl_tokens.make_token(
                    secret, "owner_dashboard", str(profile_id)
                )
                return None, None, fresh_token, True  # signal redirect

    # No token and no session → not authenticated.
    return None, None, None, False


def _verify_grant_ownership(conn, grant, profile_id, is_explicit=True):
    """Verify a grant belongs to the current owner (ruling 2A).

    ALWAYS enforced: a dashboard link may only decide grants owned by the
    profile it resolves to. Fail-closed: a grant with no owner_id
    (unmigrated row) is undecidable → deny. The is_explicit parameter is
    kept for call-site compatibility and ignored.
    """
    if grant is None:
        return False
    return grant.get("owner_id") == profile_id


def _decision_outcome(conn, jinja, request, grant_id, decision,
                      expiry_choice) -> HTMLResponse:
    """Apply a decision and render the outcome page (R4(b)) — shared by
    /a/{token}/decision and /owner/{token}/decision.

    Deliberately does NOT consume tokens: each route keeps its own scope
    ('grant_review' vs 'owner_dashboard') and its own 403 error path. The
    apply/404/render flow is the duplicated part, so that's what lives here.
    decision/expiry_choice arrive from request.form() (str at runtime).

    apply_decision raises ValueError on junk decisions or replay against a
    non-pending grant (revoked access must not resurrect) -> 409.
    """
    try:
        result = whitelist_db.apply_decision(conn, grant_id, decision, expiry_choice)
    except ValueError as exc:
        return HTMLResponse(str(exc), status_code=409)
    if result is None:
        return HTMLResponse("Grant not found", status_code=404)
    return HTMLResponse(jinja.get_template("admin_decision.html").render(
        request=request, grant=result["grant"], profile=result["profile"],
        decision=result["decision"]))


def _owner_email_for(conn, owner_profile_id: int) -> str:
    """First email field on a profile ('' when it has none)."""
    row = conn.execute(
        """SELECT field_value FROM profile_fields
           WHERE profile_id = ? AND field_type = 'email'
           ORDER BY id LIMIT 1""",
        (owner_profile_id,),
    ).fetchone()
    return row["field_value"] if row else ""


def _send_connection_request_email(db_path: Path, grant_id: str) -> None:
    """Email push half of the connection-request two-layer model
    (2026-09-20): the in-app notification row is the source of truth and
    is already committed; this adds the owner's email with a 7-day
    decision link (the same /a/{token} grant_review view the digest
    mails use). Runs as a BackgroundTask so a slow/down SMTP server
    never blocks the public request endpoint; failures are logged,
    never raised.
    """
    conn = whitelist_db.wl_connect(db_path)
    try:
        grant = whitelist_db.get_grant(conn, grant_id)
        if not grant:
            return
        owner_id = grant.get("owner_id") or grant["profile_id"]
        owner_email = _owner_email_for(conn, owner_id)
    finally:
        conn.close()
    if not owner_email:
        print(f"[WARN] No email field on owner profile {owner_id}; "
              f"connection-request email skipped for grant {grant_id}",
              file=sys.stderr)
        return

    who = grant.get("requester_name") or grant["requester_email"]
    token = wl_tokens.make_token(
        _get_secret(), "grant_review", grant_id, expires_days=7)
    link = f"{mailer.app_base_url()}/a/{token}"
    body = (
        "Hi,\n\n"
        f"New connection request on RelMgr from {who} "
        f"({grant['requester_email']}).\n\n"
        f"Review and decide here:\n\n{link}\n\n"
        "This link expires in 7 days. You can also decide from the amber "
        "Requests box at the top of your WhiteList.\n"
    )
    mailer.send_email(owner_email, "RelMgr: new connection request", body)


def _qr_png(payload: str) -> bytes:
    """Render *payload* to a PNG QR code (single generator for the profile
    QR and share-bundle QR — one place to keep size/error-correction)."""
    import qrcode
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _vcf_escape(value: str) -> str:
    """Escape one vCard text value (backslash first, then ; , \n)."""
    return (value.replace("\\", "\\\\").replace(";", "\\;")
            .replace(",", "\\,").replace("\r\n", "\\n").replace("\n", "\\n"))


def _build_vcard(profile: dict, cards: list[dict]) -> str:
    """vCard 3.0 built from EXACTLY the fields the viewer can see.

    Ruling 2026-09-20 (VCF download): the 'Save to contacts' file
    carries the same visibility-filtered set the shared view renders —
    cards arrive as cards_for_share_bundle output (visible_fields only).
    Fields are deduped by id (cards are lenses: one field can sit in
    several chosen cards). CRLF line endings per the vCard spec.
    """
    display = profile.get("display_name") or "Unknown"
    parts = display.split(" ", 1)
    first = parts[0]
    last = parts[1] if len(parts) > 1 else ""
    lines = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        f"N:{_vcf_escape(last)};{_vcf_escape(first)};;;",
        f"FN:{_vcf_escape(display)}",
    ]
    if profile.get("title"):
        lines.append(f"TITLE:{_vcf_escape(profile['title'])}")
    if profile.get("company"):
        lines.append(f"ORG:{_vcf_escape(profile['company'])}")
    seen: set[int] = set()
    for card in cards:
        for f in card.get("visible_fields", []):
            fid = f.get("id")
            if fid in seen:
                continue
            seen.add(fid)
            v = _vcf_escape(f["field_value"])
            t = f["field_type"]
            if t == "email":
                lines.append(f"EMAIL;TYPE=INTERNET:{v}")
            elif t == "phone":
                lines.append(f"TEL;TYPE=CELL:{v}")
            elif t == "address":
                lines.append(f"ADR;TYPE=HOME:;;{v};;;")
            elif t == "website":
                lines.append(f"URL:{v}")
            elif t == "birthday":
                lines.append(f"BDAY:{v}")
            elif t == "nickname":
                lines.append(f"NICKNAME:{v}")
            elif t in ("note", "high_school", "maiden_name",
                       "childhood_address1", "childhood_city",
                       "childhood_state", "country"):
                # UX pass 3: personal-history + country fields travel as
                # labeled NOTE lines (vCard has no native slots for them).
                label = ("High school" if t == "high_school"
                         else "Maiden name" if t == "maiden_name"
                         else "Childhood home" if t.startswith("childhood_")
                         else "Country" if t == "country"
                         else "Note")
                lines.append(f"NOTE:{_vcf_escape(label + ': ' + f['field_value'])}")
            elif t == "title":
                lines.append(f"TITLE:{v}")
            elif t == "company":
                lines.append(f"ORG:{v}")
    lines.append("END:VCARD")
    return "\r\n".join(lines) + "\r\n"


def create_app(db_path: Path = None) -> FastAPI:
    """Create and configure the FastAPI application.

    ``db_path`` defaults to contacts.db next to this module. The returned
    app also assigns to the module-level ``app`` attribute so repeated
    create_app() calls don't leave a dead entrypoint behind.
    """
    global app

    # Resolution order: explicit arg > RELMGR_DB_PATH env > local prod file.
    # The env override exists so tests (and their subprocesses) NEVER boot
    # against the real contacts.db — the module-level `app = create_app()` at
    # import time otherwise mutates prod via the boot chain. Deliberately not
    # WHITELIST_-prefixed: test_refactor_fixes strips WHITELIST_* from env and
    # still must not fall back to the prod file. (q38 review)
    path = Path(db_path or os.environ.get("RELMGR_DB_PATH")
                or Path(__file__).parent / "contacts.db")
    jinja = _make_jinja()
    application = FastAPI(title="WhiteList")
    # Tests (and tooling) recover the tmp db path from the bound app.
    application.state.relmgr_db_path = path

    # ============================================================
    # Static files (scroll-mark favicon, badge PNGs)
    # ============================================================
    application.mount("/static", StaticFiles(directory="static"), name="static")

    # Retired pre-migration owner magic links (captain ruling, option A):
    # one app-wide handler so every /owner/… route sends legacy-link holders
    # to sign-in with no data access, instead of a per-route 403.
    @application.exception_handler(LegacyOwnerLinkRetired)
    async def _legacy_link_retired_handler(
        _request: Request, _exc: LegacyOwnerLinkRetired
    ):
        return RedirectResponse(url="/signin", status_code=303)

    # Self-heal legacy schema in ONE ordered call (v1 CHECK lacks 'revoked',
    # additive P3 tables, v2-without-context prod case — see
    # whitelist_db.ensure_whitelist_schema for why the order matters).
    # Idempotent; runs unconditionally so a fresh DB file boots to the full
    # current schema (wl_init is a no-op on existing tables).
    _mconn = whitelist_db.wl_connect(path)
    try:
        whitelist_db.ensure_whitelist_schema(_mconn)
    finally:
        _mconn.close()

    # ============================================================
    # Sign-in / Sign-up / Sign-out (Phase B)
    # ============================================================

    @application.get("/signin", response_class=HTMLResponse)
    async def signin_page(request: Request, reset: str = Query(None)):
        return HTMLResponse(jinja.get_template("signin.html").render(
            request=request, error=None, email="", reset_ok=(reset == "1")))

    @application.post("/signin")
    async def signin_submit(request: Request):
        form = await request.form()
        email = (form.get("email") or "").strip()
        password = form.get("password") or ""

        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_owner_by_credentials(conn, email, password)
            if not profile:
                return HTMLResponse(jinja.get_template("signin.html").render(
                    request=request, error="Invalid email or password.", email=email))

            # Set session cookie
            secret = _get_secret()
            session_cookie = _make_session_cookie(profile["id"], secret)
            # 303 See Other: the browser must follow with GET — a default 307
            # re-POSTs to "/" and lands on 405 Method Not Allowed.
            response = RedirectResponse(url="/", status_code=303)
            response.set_cookie(
                key="wl_session",
                value=session_cookie,
                httponly=True,
                samesite="lax",
                max_age=7 * 86400,
            )
            return response
        finally:
            conn.close()

    @application.get("/signup", response_class=HTMLResponse)
    async def signup_page(request: Request):
        return HTMLResponse(jinja.get_template("signup.html").render(
            request=request, error=None,
            display_name="", handle="", email=""))

    @application.post("/signup")
    async def signup_submit(request: Request):
        form = await request.form()
        display_name = (form.get("display_name") or "").strip()
        handle = (form.get("handle") or "").strip().lower()
        email = (form.get("email") or "").strip().lower()
        password = form.get("password") or ""

        errors = []
        if not display_name:
            errors.append("Display name is required.")
        if (
            not handle
            or len(handle) < 2
            or len(handle) > 40
            or not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", handle)
        ):
            errors.append("Handle must be 2-40 lowercase alphanumeric chars (hyphens ok).")
        if not email or "@" not in email:
            errors.append("Valid email is required.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")

        if errors:
            return HTMLResponse(jinja.get_template("signup.html").render(
                request=request, error=errors[0],
                display_name=display_name, handle=handle, email=email))

        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.create_owner_profile(
                conn, handle, display_name, email, password)

            # Set session cookie
            secret = _get_secret()
            session_cookie = _make_session_cookie(profile["id"], secret)
            # 303 See Other: the browser must follow with GET — a default 307
            # re-POSTs to "/" and lands on 405 Method Not Allowed.
            response = RedirectResponse(url="/", status_code=303)
            response.set_cookie(
                key="wl_session",
                value=session_cookie,
                httponly=True,
                samesite="lax",
                max_age=7 * 86400,
            )
            return response
        except ValueError as exc:
            return HTMLResponse(jinja.get_template("signup.html").render(
                request=request, error=str(exc),
                display_name=display_name, handle=handle, email=email))
        finally:
            conn.close()

    @application.post("/signout")
    async def signout_submit(request: Request):
        # 303 See Other: follow with GET — a default 307 would re-POST to
        # "/signin" and land on 405 Method Not Allowed.
        response = RedirectResponse(url="/signin", status_code=303)
        response.delete_cookie(key="wl_session", path="/")
        return response

    # ============================================================
    # Forgot / reset password (2026-09-20)
    # ============================================================

    def _send_password_reset_email(to_addr: str, reset_url: str) -> bool:
        """Deliver the reset email through the app's mail layer:
        scripts/notify.send_email -> mailer.send_email (SMTP_HOST/PORT
        defaults smtp.gmail.com:587 STARTTLS / 465 SSL; SMTP_USER/SMTP_PASS
        from env or .env; SMTP_FROM/SMTP_REPLY_TO; see .env.example).

        Returns False on ANY delivery failure (unconfigured SMTP, refused
        connection, or notify's sys.exit(1) on missing credentials — hence
        catching SystemExit too). The caller still shows the standard
        confirmation either way, and logs the URL so a deployment without
        working SMTP is never locked out of first sign-in.
        """
        body = (
            "Hi,\n\n"
            "A password reset was requested for your RelMgr account.\n\n"
            f"Set a new password here:\n\n{reset_url}\n\n"
            "This link expires in 30 minutes and can be used once.\n"
            "If you didn't request this, you can ignore this email.\n"
        )
        try:
            from scripts.notify import send_email
            send_email(to_addr, "RelMgr: reset your password", body)
            return True
        except (Exception, SystemExit):
            return False

    @application.get("/forgot-password", response_class=HTMLResponse)
    async def forgot_password_page(request: Request):
        return HTMLResponse(jinja.get_template("forgot_password.html").render(
            request=request, error=None, email="", sent=False))

    @application.post("/forgot-password")
    async def forgot_password_submit(request: Request):
        form = await request.form()
        email = (form.get("email") or "").strip()

        if not email or "@" not in email:
            return HTMLResponse(jinja.get_template("forgot_password.html").render(
                request=request, error="Valid email is required.",
                email=email, sent=False))

        # Timing parity (pairing review F1): ONE dummy pbkdf2 burn on BOTH
        # paths, shared before the existence branch, so the synchronous cost
        # is identical whether or not the email exists. Mint + mail run as a
        # BackgroundTask AFTER the response is sent — with real SMTP the hit
        # path would otherwise pay login/sendmail round-trips the miss path
        # never sees, re-opening the oracle.
        whitelist_db.burn_dummy_password_work()

        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.get_profile_by_email(conn, email)
        finally:
            conn.close()

        background = None
        if profile:
            background = BackgroundTask(
                _issue_and_send_reset, path, email, mailer.app_base_url())

        # Same response whether or not the email exists — no enumeration.
        return HTMLResponse(jinja.get_template("forgot_password.html").render(
            request=request, error=None, email="", sent=True),
            background=background)

    def _issue_and_send_reset(db_path, email: str, base_url: str) -> None:
        """Background half of forgot-password (review F1): mint the reset
        token and attempt delivery AFTER the identical confirmation has been
        sent, so response timing cannot reveal account existence."""
        conn = whitelist_db.wl_connect(db_path)
        try:
            profile = whitelist_db.get_profile_by_email(conn, email)
            if not profile:
                return
            raw = whitelist_db.create_password_reset_token(conn, profile["id"])
            reset_url = f"{base_url}/reset-password/{raw}"
            if not _send_password_reset_email(email, reset_url):
                # Documented local fallback keeps first sign-in unblocked
                # when SMTP can't deliver: scripts/notify.py --what reset
                # --email <addr> prints the reset URL. Logged as well so
                # the captain can lift it straight from service logs.
                print(
                    f"[WARN] Reset email delivery failed; reset URL for "
                    f"{email}: {reset_url}", file=sys.stderr)
        finally:
            conn.close()

    @application.get("/reset-password/{token}", response_class=HTMLResponse)
    async def reset_password_page(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            valid = whitelist_db.peek_password_reset_token(conn, token) is not None
        finally:
            conn.close()
        if not valid:
            return HTMLResponse(jinja.get_template("reset_password.html").render(
                request=request, invalid=True, error=None), status_code=403)
        return HTMLResponse(jinja.get_template("reset_password.html").render(
            request=request, invalid=False, error=None))

    @application.post("/reset-password/{token}")
    async def reset_password_submit(request: Request, token: str):
        form = await request.form()
        password = form.get("password") or ""

        # Validate BEFORE consuming: a too-short submission must not burn
        # the user's one working link.
        if len(password) < 8:
            conn = whitelist_db.wl_connect(path)
            try:
                valid = (whitelist_db.peek_password_reset_token(conn, token)
                         is not None)
            finally:
                conn.close()
            if not valid:
                return HTMLResponse(jinja.get_template("reset_password.html").render(
                    request=request, invalid=True, error=None), status_code=403)
            return HTMLResponse(jinja.get_template("reset_password.html").render(
                request=request, invalid=False,
                error="Password must be at least 8 characters."))

        conn = whitelist_db.wl_connect(path)
        try:
            profile_id = whitelist_db.consume_password_reset_token(conn, token)
            if profile_id is None:
                return HTMLResponse(jinja.get_template("reset_password.html").render(
                    request=request, invalid=True, error=None), status_code=403)
            whitelist_db.set_profile_password(conn, profile_id, password)
        finally:
            conn.close()

        # 303 See Other: the browser must follow with GET.
        return RedirectResponse(url="/signin?reset=1", status_code=303)

    # ============================================================
    # Public routes
    # ============================================================

    @application.get("/", response_class=HTMLResponse)
    async def landing_page(request: Request):
        """Root landing: redirect to sign-in or dashboard based on session."""
        conn = whitelist_db.wl_connect(path)
        try:
            secret = _get_secret()
            result = _resolve_owner(conn, request, "", secret)
            if result[2]:  # redirect needed (session valid, no URL token)
                return RedirectResponse(url=f"/owner/{result[2]}")
            if result[0] is not None and result[3]:  # authenticated via token
                return RedirectResponse(url=f"/owner/{wl_tokens.make_token(secret, 'owner_dashboard', str(result[0]))}")
        finally:
            conn.close()
        return RedirectResponse(url="/signin")

    @application.get("/owner/", response_class=HTMLResponse)
    async def owner_root(request: Request):
        """Owner root (/owner/) — checks session cookie, redirects to dashboard."""
        conn = whitelist_db.wl_connect(path)
        try:
            secret = _get_secret()
            result = _resolve_owner(conn, request, "", secret)
            if result[0] is not None and result[3]:  # explicitly authenticated
                return RedirectResponse(url=f"/owner/{wl_tokens.make_token(secret, 'owner_dashboard', str(result[0]))}")
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
        finally:
            conn.close()
        return RedirectResponse(url="/signin")

    @application.get("/p/{handle}", response_class=HTMLResponse)
    async def profile_page(
        request: Request,
        handle: str,
        e: str = Query(None, alias="e"),
    ):
        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("<h1>Profile not found</h1>", status_code=404)

            # P3-T4: a successful resolution is the tracked event. Anonymous
            # visits keep viewer_email NULL — still a scan (that's the point).
            whitelist_db.record_scan(conn, profile["id"], e if e else None)

            # UX pass (2026-09-22): owner detection for the '← back to
            # My Profile' link. The owner arrives either via session cookie
            # or the ?e= link carrying their OWN email; anyone else
            # (granted contact with their ?e=, or anonymous) never sees it.
            viewer_is_owner = False
            session_cookie = request.cookies.get("wl_session")
            if session_cookie:
                session_profile_id = _consume_session_cookie(
                    session_cookie, _get_secret())
                if session_profile_id and session_profile_id == profile["id"]:
                    viewer_is_owner = True
            if not viewer_is_owner and e:
                owner_email = conn.execute(
                    "SELECT field_value FROM profile_fields "
                    "WHERE profile_id = ? AND field_type = 'email' LIMIT 1",
                    (profile["id"],),
                ).fetchone()
                if owner_email and owner_email[0].lower() == e.lower():
                    viewer_is_owner = True
            owner_token = None
            if viewer_is_owner:
                owner_token = wl_tokens.make_token(
                    _get_secret(), "owner_dashboard", str(profile["id"]),
                    expires_days=365)

            viewer_email = e if e else None
            tier = whitelist_db.effective_tier(conn, profile["id"], viewer_email)

            stale = is_verified_stale(profile.get("verified_at"))

            # B4: the public page renders cards. Profiles with NO cards at
            # all (seed_default_cards only auto-attaches for jasonheath) keep
            # the legacy flat field list — a card-less profile must not
            # render an empty public page.
            cards = whitelist_db.cards_for_public_view(
                conn, profile["id"], tier)

            bio_visibility = whitelist_db.get_bio_visibility(conn, profile["id"])

            return HTMLResponse(jinja.get_template("profile.html").render(
                request=request, profile=profile, tier=tier, stale=stale,
                cards=cards, bio_visibility=bio_visibility, days_since=days_since,
                viewer_is_owner=viewer_is_owner, owner_token=owner_token))
        finally:
            conn.close()

    @application.get("/p/{handle}/request-form", response_class=HTMLResponse)
    async def request_form_page(request: Request, handle: str):
        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("<h1>Profile not found</h1>", status_code=404)
            return HTMLResponse(jinja.get_template("request_form.html").render(
                request=request, profile=profile))
        finally:
            conn.close()

    @application.post("/p/{handle}/request")
    async def submit_request(request: Request, handle: str):
        form = await request.form()
        name = form.get("name", "")
        email = form.get("email", "")
        grant_id = None

        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            if whitelist_db.is_blacklisted(conn, profile["id"], email):
                # Blacklist silence, BOTH directions (ruling 2026-09-20):
                # the sender still sees the normal 'request sent'
                # confirmation below — they can never detect their status —
                # but the request is quarantined silently: no pending
                # grant, no notification, no badge count, no email push.
                whitelist_db.quarantine_request(conn, profile["id"], email, name)
                quarantined = True
                # Cosmetic, display-only id so the success page is
                # INDISTINGUISHABLE from a real one — a blank Grant ID would
                # let the sender detect their blacklisted status (silence
                # rule). This id backs no row anywhere. Fix-pass F3: it is
                # a full uuid4 string, byte-shape-identical to a real
                # grant id (os.urandom(6).hex() had the wrong shape).
                grant_id = str(uuid.uuid4())
            else:
                quarantined = False
                grant_id = whitelist_db.create_grant(conn, profile["id"], email, name, profile.get("owner_id"))
                # Two-layer notification (2026-09-20): the in-app row is the
                # source of truth and commits here; the email is only the push
                # (BackgroundTask below). dedupe_key collapses re-POSTs of a
                # still-pending grant to the same single row.
                grant = whitelist_db.get_grant(conn, grant_id)
                owner_id = grant["owner_id"] or profile["id"]
                whitelist_db.create_notification(
                    conn, owner_id, "connection_request",
                    title=f"Connection request from {name or email}",
                    grant_id=grant_id,
                    dedupe_key=f"grant:{grant_id}")
        finally:
            conn.close()

        background = None if quarantined else BackgroundTask(
            _send_connection_request_email, path, grant_id)
        return HTMLResponse(jinja.get_template("request_success.html").render(
            request=request, profile=profile, grant_id=grant_id),
            background=background)

    @application.post("/p/{handle}/forward")
    async def forward_card(request: Request, handle: str):
        """Forward the profile's shareable card to a new person.

        The forwarder must be a granted contact (verified tier). The
        recipient only sees public-bio-level info. The owner is
        notified via a pending access request.
        """
        form = await request.form()
        forwarder_email = (form.get("forwarder_email") or "").strip()
        forwarder_name = (form.get("forwarder_name") or "").strip()
        recipient_email = (form.get("recipient_email") or "").strip()
        recipient_name = (form.get("recipient_name") or "").strip()

        if not forwarder_email or not recipient_email:
            return HTMLResponse("Both forwarder and recipient info required", status_code=400)

        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            # Verify forwarder is a granted contact
            tier = whitelist_db.effective_tier(
                conn, profile["id"], forwarder_email)
            if tier != "granted":
                return HTMLResponse(
                    "Only approved contacts can forward cards",
                    status_code=403)

            grant_id = whitelist_db.forward_card(
                conn, profile["id"],
                forwarder_email, forwarder_name,
                recipient_email, recipient_name)

            # Two-layer notification for the forward, same as a direct
            # request: in-app row now, email push after the response.
            grant = whitelist_db.get_grant(conn, grant_id)
            owner_id = grant["owner_id"] or profile["id"]
            whitelist_db.create_notification(
                conn, owner_id, "forward",
                title=(f"Card forwarded by {forwarder_name or forwarder_email} "
                       f"to {recipient_name or recipient_email}"),
                grant_id=grant_id,
                dedupe_key=f"grant:{grant_id}")
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("forward_success.html").render(
            request=request, profile=profile, grant_id=grant_id,
            recipient_email=recipient_email),
            background=BackgroundTask(
                _send_connection_request_email, path, grant_id))

    # ------------------------------------------------------------------
    # Sharing (UX pass 3, 2026-09-23): UNIFIED. The chooser → Next →
    # bundle flow is RETIRED — My Profile shows the profile QR between the
    # name and the Share button, and Share fires the native share popup
    # directly with the /p/{handle} link (copy link, email, SMS standard).
    # No card-choosing at share time: the access-grant decision lands after
    # a contact requests access (Connect → amber request box → grant).
    # Legacy /s/{bundle_id} links keep rendering for already-shared URLs.
    # ------------------------------------------------------------------

    def _bundle_share_url(bundle_id: str) -> str:
        return f"{mailer.app_base_url()}/s/{bundle_id}"

    def _profile_share_url(handle: str) -> str:
        return f"{mailer.app_base_url()}/p/{handle}"

    def _bundle_share_message(display_name: str, bundle_id: str) -> str:
        # Exact copy sent by the native share sheet (ruling 2026-09-20).
        return (f"{display_name} wants to share their WhiteList card: "
                f"{_bundle_share_url(bundle_id)}")

    @application.get("/s/{bundle_id}/card.vcf")
    async def share_bundle_vcf(request: Request, bundle_id: str,
                               e: str = Query(None, alias="e")):
        """'Save to contacts' — vCard from EXACTLY the PUBLIC fields.

        F4 ruling (UX pass 2, 2026-09-23): share links ALWAYS deliver the
        PUBLIC-facing page — no granted-tier links. Recipients who want
        more use the request-access flow; the owner grants from there.
        Expired links 404 for everyone."""
        conn = whitelist_db.wl_connect(path)
        try:
            bundle = whitelist_db.get_share_bundle(conn, bundle_id)
            if not bundle:
                return HTMLResponse("Not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, bundle["profile_id"])
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            if whitelist_db.bundle_is_expired(bundle):
                return HTMLResponse("Link expired", status_code=404)
            cards = whitelist_db.cards_for_share_bundle(conn, bundle, "anonymous")
            vcf = _build_vcard(profile, cards)
            filename = profile["handle"] or "card"
        finally:
            conn.close()
        return Response(
            content=vcf,
            media_type="text/vcard",
            headers={"Content-Disposition":
                     f'attachment; filename="{filename}.vcf"'},
        )

    @application.get("/s/{bundle_id}", response_class=HTMLResponse)
    async def share_bundle_view(request: Request, bundle_id: str,
                                e: str = Query(None, alias="e")):
        """The recipient's page: the chosen card set as ONE combined card,
        grouped per card with reach-me actions inside each block.

        F4 ruling (UX pass 2, 2026-09-23): share links ALWAYS deliver the
        PUBLIC-facing page — no granted-tier links. Whoever opens the link
        (stranger or connected contact) sees exactly the public view;
        recipients who want more use the request-access flow (Connect),
        and the owner grants from there.

        Link lifecycle:
        - an expired link shows the expired page and pings the owner ONCE
          (per bundle, deduped) with a fresh dashboard path
        - a BLACKLISTED opener gets the same expired page but triggers NO
          ping — the owner is never bothered by blacklisted people
        """
        conn = whitelist_db.wl_connect(path)
        try:
            bundle = whitelist_db.get_share_bundle(conn, bundle_id)
            if not bundle:
                return HTMLResponse("<h1>Link not found</h1>", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, bundle["profile_id"])
            if not profile:
                return HTMLResponse("<h1>Profile not found</h1>", status_code=404)

            viewer_email = e if e else None

            if whitelist_db.bundle_is_expired(bundle):
                if not whitelist_db.is_blacklisted(
                        conn, profile["id"], viewer_email or ""):
                    # Opener at an expired link → ping the owner ONCE
                    # (dedupe per bundle) with a fresh dashboard path —
                    # the re-share lives on the owner share page.
                    owner_id = profile.get("owner_id") or profile["id"]
                    dashboard_token = wl_tokens.make_token(
                        _get_secret(), "owner_dashboard", str(owner_id),
                        expires_days=7)
                    who = viewer_email or "Someone"
                    whitelist_db.create_notification(
                        conn, owner_id, "expired_link",
                        title="An expired share link was opened",
                        body=(f"{who} opened an expired link to your card. "
                              "Open your share page to re-share it, or let "
                              "them connect from your dashboard."),
                        link=f"/owner/{dashboard_token}",
                        dedupe_key=f"expired_link:{bundle_id}")
                return HTMLResponse(jinja.get_template(
                    "share_expired.html").render(
                    request=request, profile=profile, bundle_id=bundle_id))

            # Tracked event, same P3-T4 contract as /p/{handle}.
            whitelist_db.record_scan(conn, profile["id"],
                                     viewer_email if viewer_email else None)

            stale = is_verified_stale(profile.get("verified_at"))
            # F4 ruling: the link renders the PUBLIC-facing page for every
            # recipient — anonymous tier, no exceptions.
            cards = whitelist_db.cards_for_share_bundle(conn, bundle, "anonymous")
            bio_visibility = whitelist_db.get_bio_visibility(conn, profile["id"])

            return HTMLResponse(jinja.get_template("share_bundle.html").render(
                request=request, profile=profile, bundle_id=bundle_id,
                tier="anonymous", stale=stale, cards=cards,
                bio_visibility=bio_visibility, viewer_email=viewer_email,
                days_since=days_since))
        finally:
            conn.close()

    # ------------------------------------------------------------------ Badge-governed access (2026-09-20)

    @application.post("/owner/{token}/badge")
    async def owner_badge_state(request: Request, token: str):
        """Click-to-change contact-list badges (WhiteList/GreyList/BlackList).

        INSTANT and ALWAYS SILENT: the badge flip is the access governor,
        and the affected contact is NEVER notified — no notification row,
        no email, ever. The notification center only tells the OWNER
        about incoming events, never contacts about rulings.
        """
        form = await request.form()
        grant_id = form.get("grant_id", "")
        state = form.get("state", "")
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)
            try:
                whitelist_db.set_badge_state(conn, grant_id, state)
            except ValueError:
                return HTMLResponse("Invalid badge state", status_code=400)
        finally:
            conn.close()
        return RedirectResponse(url=f"/owner/{token}", status_code=303)

    @application.get("/a/{token}", response_class=HTMLResponse)
    async def admin_link(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "grant_review", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        grant_id = payload
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_review.html").render(
            request=request, grant=grant, profile=profile, token=token))

    @application.post("/a/{token}/decision")
    async def admin_decision(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "grant_review", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        decision = form.get("decision", "")
        expires_at_choice = form.get("expiry", "90")

        grant_id = payload
        conn = whitelist_db.wl_connect(path)
        try:
            return _decision_outcome(conn, jinja, request, grant_id,
                                     decision, expires_at_choice)
        finally:
            conn.close()

    @application.get("/verify/{token}", response_class=HTMLResponse)
    async def verify_page(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "verify", token)
        if payload is None:
            return HTMLResponse("Invalid or expired verification link", status_code=403)

        profile_id = int(payload)
        conn = whitelist_db.wl_connect(path)
        try:
            whitelist_db.update_verified_at(conn, profile_id)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("verify_success.html").render(
            request=request, profile=profile))

    # ------------------------------------------------------------------ Owner dashboard → contact list (Phase A2)
    @application.get("/owner/{token}", response_class=HTMLResponse)
    async def owner_dashboard(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

            # Get query params — junk input must degrade to page 0, not 500.
            q = request.query_params.get("q")
            try:
                page = max(0, int(request.query_params.get("page", 0)))
            except ValueError:
                page = 0
            # UX pass 3 (2026-09-23): reduced rows (~100 per page).
            per_page = 100

            # Owner dashboard: per-owner isolation (ruling 2A). Every auth
            # path — session cookie, integer-payload token, and the legacy
            # fallback link — sees exactly this owner's world, nothing else.
            all_profiles = conn.execute("SELECT * FROM profiles WHERE owner_id = ? ORDER BY id", (profile_id,)).fetchall()
            all_profile_ids = [dict(p)["id"] for p in all_profiles]
            if not all_profile_ids:
                all_profile_ids = [profile_id]

            # UX pass (2026-09-22): fast alphabetical filter rail — ?letter=X
            # keeps only names STARTING with X (prefix filter, unlike the
            # substring search q). Applied to the merged row list below, so
            # it works in both the contacts and pure-whitelist modes.
            letter = (request.query_params.get("letter") or "")[:1].upper()
            available_letters: list[str] = []

            # Use the new contact list data layer (graceful if contacts table missing)
            if whitelist_db._table_exists(conn, "contacts"):
                # Aggregate across all profiles, then paginate at the HTTP level
                # so page 0 = the first `per_page` rows (AC #3). The data layer
                # already applies search (q) and pending-first ordering; we keep
                # one combined pass for cross-profile email dedupe and the true
                # total, then slice it — "page 1 of 51" stays row 51.
                all_rows: list[dict] = []
                seen_emails: set[str] = set()
                for pid in all_profile_ids:
                    profile_rows = whitelist_db.list_contact_list_rows(conn, pid, q=q, page=0, per_page=999999)
                    for r in profile_rows:
                        email = (r.get("email") or "").lower()
                        if email not in seen_emails:
                            seen_emails.add(email)
                            all_rows.append(r)
                total_rows = len(all_rows)
                rows = all_rows
            else:
                # Pure whitelist mode — owner-scoped grants (ruling 2A).
                all_grants = conn.execute(
                    "SELECT * FROM access_grants WHERE owner_id = ? AND profile_id IN ({}) ORDER BY status, created_at".format(",".join("?" for _ in all_profile_ids)),
                    [profile_id] + all_profile_ids,
                ).fetchall()
                rows = []
                profile_map = {p["id"]: dict(p) for p in all_profiles}
                for g in all_grants:
                    gd = dict(g)
                    if gd["status"] == "denied":
                        continue
                    prof = profile_map.get(gd["profile_id"])
                    # UX pass 3: card tabs work in pure-whitelist mode too —
                    # resolve each grant's card refs exactly like the data
                    # layer does in contacts mode.
                    gcard_rows = conn.execute(
                        "SELECT c.id, c.name FROM grant_cards gc JOIN cards c ON gc.card_id = c.id "
                        "WHERE gc.grant_id = ?",
                        (gd["id"],),
                    ).fetchall()
                    gcard_refs = [{"id": r["id"], "name": r["name"]}
                                  for r in gcard_rows]
                    rows.append({
                        "contact_id": None,
                        "name": gd.get("requester_name") or gd.get("requester_email", "Unknown"),
                        "email": gd.get("requester_email", ""),
                        "phone": "",
                        "org": "",
                        "granted": gd["status"] == "granted",
                        "live_grant": gd,
                        "cards": [r["name"] for r in gcard_rows],
                        "card_refs": gcard_refs,
                        "perm": "permanent" if gd.get("expires_at") is None else ("temp" if gd.get("expires_at") else None),
                        "logo_state": ("fresh" if whitelist_db.is_current_quarter(prof.get("verified_at")) else "stale") if prof else None,
                        "refreshed_at": None,
                        "is_pending": gd["status"] == "pending",
                    })
                total_rows = len(rows)

            # Count denied grants for this owner
            denied_count = conn.execute(
                "SELECT COUNT(*) FROM access_grants WHERE owner_id = ? AND status = 'denied'",
                (profile_id,),
            ).fetchone()[0]

            # UX pass 3 (2026-09-23): the in-app notification PAGE is retired
            # (requests live in the amber box below; quarterly = the email +
            # the grey rows in this list). The quarterly prompt ROW is still
            # raised here — the append-only event record survives; only the
            # page, its routes, and the header button are gone.
            whitelist_db.sync_quarterly_notifications(conn, profile_id)

            # Unified row list for single-surface contact list (round-2)
            all_rows = rows
            total_contacts = total_rows

            # UX pass ruling (2026-09-22): ONE ROW PER CARD — a contact with
            # two cards appears twice in the list, once per card, each row
            # deep-linking the detail view with that card selected. Contacts
            # and pending grants without cards render one row as before.
            # UX pass 3 (2026-09-23): PENDING rows leave the main list —
            # they land in the amber request box at the top (below the
            # search bar), per the captain's ruling.
            expanded_rows: list[dict] = []
            pending_rows: list[dict] = []
            for r in all_rows:
                if r.get("is_pending"):
                    pending_rows.append(r)
                    continue
                refs = r.get("card_refs") or []
                if refs:
                    for ref in refs:
                        card_row = dict(r)
                        card_row["row_card"] = ref
                        expanded_rows.append(card_row)
                else:
                    expanded_rows.append(r)
            all_rows = expanded_rows

            # UX pass 3 (2026-09-23): PICTURE-BASED MULTI-SELECT FILTER TABS
            # below the search bar. Card tabs carry the card's own picture
            # (Personal first, then Work, then the rest alphabetical); list
            # badge tabs carry the white/grey/black state. ?f=<id>,<id>,...
            # combines selections: card group OR, state group OR, the two
            # groups AND together (e.g. personal + work1 + grey + white).
            owner_cards_all = whitelist_db.list_cards(conn, profile_id)
            filter_tabs: list[dict] = []
            for c in owner_cards_all:
                filter_tabs.append({
                    "kind": "card",
                    "key": str(c["id"]),
                    "card": c,
                })
            for state_key, label in (("whitelist", "WhiteList"),
                                     ("greylist", "GreyList"),
                                     ("blacklist", "BlackList")):
                filter_tabs.append({
                    "kind": "state",
                    "key": state_key,
                    "label": label,
                })
            raw_f = (request.query_params.get("f") or "")
            selected_f = {tok for tok in raw_f.split(",") if tok}
            valid_keys = {t["key"] for t in filter_tabs}
            selected_f &= valid_keys
            sel_cards = {int(k) for k in selected_f if k.isdigit()}
            sel_states = selected_f - {str(k) for k in sel_cards}

            def _row_state(r: dict) -> str:
                gd = r.get("live_grant")
                if not gd:
                    return "blacklist"  # plain address-book contact: no access
                if gd.get("status") != "granted":
                    return "blacklist"
                return "whitelist" if gd.get("expires_at") is None else "greylist"

            if sel_cards or sel_states:
                def _matches(r: dict) -> bool:
                    card_ok = (not sel_cards
                               or (r.get("row_card") is not None
                                   and r["row_card"]["id"] in sel_cards))
                    state_ok = (not sel_states
                                or _row_state(r) in sel_states)
                    return card_ok and state_ok
                all_rows = [r for r in all_rows if _matches(r)]

            # UX pass 3 sort ruling: card type alphabetical, then the state
            # white/grey/black, then name.
            _STATE_RANK = {"whitelist": 0, "greylist": 1, "blacklist": 2}
            all_rows.sort(key=lambda r: (
                (r.get("row_card") or {}).get("name", "") or "",
                _STATE_RANK[_row_state(r)],
                (r.get("name") or "").lower(),
            ))

            # UX pass (2026-09-22): the A–Z rail + prefix filter run on the
            # MERGED rows, whatever mode produced them; pagination slices
            # AFTER the filter so a letter's rows never fall off the page.
            # Keys are ASCII-folded (F2): É lands under E, others under '#'.
            available_letters = sorted({_rail_letter(r.get("name") or "")
                                        for r in all_rows})
            if letter:
                all_rows = [r for r in all_rows
                            if _rail_letter(r.get("name") or "") == letter]
            total_rows = len(all_rows)
            start = page * per_page
            all_rows = all_rows[start:start + per_page]

            # Owner's own card for the "my card" section
            my_card = None
            owner_profile = conn.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,)).fetchone()
            if owner_profile:
                owner_cards = whitelist_db.list_cards(conn, profile_id)
                if owner_cards:
                    first_card = owner_cards[0]
                    my_card = {
                        "owner_id": profile_id,
                        "id": first_card["id"],
                        "name": owner_profile["display_name"],
                        "email": "",
                        "photo_path": first_card.get("photo_path"),
                    }
                    # Grab email from owner's fields
                    owner_fields = conn.execute(
                        "SELECT * FROM profile_fields WHERE profile_id = ? AND field_type = 'email' LIMIT 1",
                        (profile_id,)
                    ).fetchall()
                    if owner_fields:
                        my_card["email"] = owner_fields[0]["field_value"]

            # Fetch all cards for approve forms (pending rows) — use first profile
            all_cards = whitelist_db.list_cards(conn, all_profile_ids[0] if all_profile_ids else profile_id)

            return HTMLResponse(jinja.get_template("contact_list.html").render(
                request=request,
                all_rows=all_rows,
                pending_rows=pending_rows,
                my_card=my_card,
                all_cards=all_cards,
                filter_tabs=filter_tabs,
                selected_f=selected_f,
                token=token,
                q=q,
                letter=letter,
                available_letters=available_letters,
                page=page,
                per_page=per_page,
                total_rows=total_rows,
                total_contacts=total_contacts,
                denied_count=denied_count,
                days_since=days_since,
                days_until=days_until,
            ))
        finally:
            conn.close()

    # ------------------------------------------------------------------ Approve with cards (P5-T3)
    @application.post("/owner/{token}/approve", response_class=HTMLResponse)
    async def owner_approve(request: Request, token: str):
        form = await request.form()
        grant_id = form.get("grant_id", "")
        decision = form.get("decision", "")
        card_ids_raw = form.getlist("card_ids")
        access = form.get("access", "quarter")

        # Validate: at least one card required
        if not card_ids_raw:
            return HTMLResponse("At least one card must be selected", status_code=400)

        expiry_choice = "lifetime" if access == "lifetime" else "quarter"

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            # Verify grant ownership
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)

            outcome = _decision_outcome(conn, jinja, request, grant_id,
                                       decision, expiry_choice)
            # If approved, set the card assignments (junk ids degrade to 400,
            # never 500 — spec B3/q38; foreign-card ids are rejected inside
            # set_grant_cards, ruling 2A).
            if decision == "approve" and outcome.status_code == 200:
                try:
                    card_ids = [int(c) for c in card_ids_raw]
                    whitelist_db.set_grant_cards(conn, grant_id, card_ids)
                except ValueError:
                    return HTMLResponse("Invalid card selection", status_code=400)
            return outcome
        finally:
            conn.close()

    # ------------------------------------------------------------------ Junk folder (P5-T3)
    @application.get("/owner/{token}/junk", response_class=HTMLResponse)
    async def owner_junk(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            denied = conn.execute(
                "SELECT * FROM access_grants WHERE owner_id = ? AND status = 'denied' ORDER BY created_at DESC",
                (profile_id,),
            ).fetchall()
            denied_list = [dict(d) for d in denied]
            return HTMLResponse(jinja.get_template("junk.html").render(
                request=request,
                denied=denied_list,
                token=token,
                days_since=days_since,
            ))
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Notification PAGE — ELIMINATED (UX pass 3, 2026-09-23 captain ruling
    # investigation): connection requests and forwards now land at the TOP
    # of the whitelist in the amber request box; the quarterly review is
    # the quarterly email + the grey contacts visible in the list itself;
    # expired-link pings were tied to the retired share-chooser flow. The
    # page carried nothing unique. The notifications TABLE and its data
    # layer stay (append-only event record + the email push's source of
    # truth) — only the page, its routes, and the header button are gone.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------ New connection (+ button, UX pass 2)
    # The round + button RIGHT of the search bar: search the database for
    # 'new connections'; on no hits, offer to create a standard vCard.
    @application.get("/owner/{token}/new-connection", response_class=HTMLResponse)
    async def owner_new_connection(request: Request, token: str,
                                   q: str = Query(None)):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            matches = whitelist_db.search_new_connections(conn, profile_id, q or "")
        finally:
            conn.close()
        return HTMLResponse(jinja.get_template("new_connection.html").render(
            request=request, token=token, q=q or "", matches=matches))

    @application.post("/owner/{token}/new-connection")
    async def owner_new_connection_create(request: Request, token: str):
        form = await request.form()
        display_name = (form.get("display_name") or "").strip()
        phone = (form.get("phone") or "").strip()
        email = (form.get("email") or "").strip()

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            if not display_name:
                matches = whitelist_db.search_new_connections(conn, profile_id, "")
                return HTMLResponse(jinja.get_template("new_connection.html").render(
                    request=request, token=token, q="", matches=matches,
                    error="Name is required."), status_code=400)
            new_profile = whitelist_db.create_contact_vcard(
                conn, profile_id, display_name, phone=phone, email=email)
            # UX pass 3 (bug fix + create-flow ruling): land DIRECTLY in the
            # new vCard's editor — ALL field sections ready to populate.
            # BUG FIX (pass 9): seed_default_cards maps email→Work, phone→Personal;
            # always landing on Personal hid the email field. Prefer Work when
            # email was provided (it carries the email fields), else Personal.
            cards = whitelist_db.list_cards(conn, new_profile["id"])
            if email:
                target = next((c for c in cards if c["name"].lower() == "work"),
                              cards[0] if cards else None)
            else:
                target = next((c for c in cards if c["name"].lower() == "personal"),
                              cards[0] if cards else None)
        finally:
            conn.close()
        if target is None:
            # 303 See Other: land back on the contact list with a GET.
            return RedirectResponse(url=f"/owner/{token}", status_code=303)
        return RedirectResponse(
            url=f"/owner/{token}/cards/{target['id']}/edit", status_code=303)

    # ------------------------------------------------------------------ Manage access (P5-T3)
    @application.post("/owner/{token}/access", response_class=HTMLResponse)
    async def owner_manage_access(request: Request, token: str):
        form = await request.form()
        grant_id = form.get("grant_id", "")
        card_ids_raw = form.getlist("card_ids")
        access = form.get("access", "quarter")

        if not grant_id:
            return HTMLResponse("No grant selected", status_code=400)

        expiry_choice = "lifetime" if access == "lifetime" else "quarter"

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            # Verify grant ownership
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)

            # Update expiry if access changed
            if grant["status"] == "granted":
                if expiry_choice == "lifetime":
                    expires_at = None
                elif expiry_choice == "quarter":
                    expires_at = whitelist_db.quarter_end_iso()
                else:
                    expires_at = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")

                whitelist_db.update_grant_status(
                    conn, grant_id, "granted",
                    granted_at=grant.get("granted_at"),
                    expires_at=expires_at,
                    commit=False,
                )
                whitelist_db._log_action(conn, grant_id, grant["profile_id"],
                                         "approved", expiry_choice)
                conn.commit()

            # Update cards (junk ids degrade to 400, never 500 — spec B3/q38;
            # foreign-card ids are rejected inside set_grant_cards, ruling 2A).
            try:
                card_ids = [int(c) for c in card_ids_raw] if card_ids_raw else []
                whitelist_db.set_grant_cards(conn, grant_id, card_ids)
            except ValueError:
                return HTMLResponse("Invalid card selection", status_code=400)

            return HTMLResponse("Access updated")
        finally:
            conn.close()

    # ------------------------------------------------------------------ My Profile tab (Phase A1)

    def _my_profile_html(conn, request, token: str, profile: dict,
                        bio_error=None, new_card_error=None,
                        bio_override=None, share_error=None, status_code=200) -> HTMLResponse:
        """Render my_profile.html from ONE place.

        ALL five My Profile sites (GET /profile, POST /bio, /cards/new,
        /cards/{id}/fields, /fields/new, /cards/{id}/photo) must call this —
        forking the render block is how the B2 scan stats got dropped twice
        (bug #5 in the Qwen pass, and again over HTTP in the q38 review).
        `status_code` lets validation failures answer 400 with the friendly
        rendered page (spec B2: dup card / over-limit bio → 400 page).
        """
        profile_id = profile["id"]

        # Get owner email for View profile link
        owner_email = ""
        for f in profile.get("fields", []):
            if f.get("field_type") == "email":
                owner_email = f["field_value"]
                break

        # Get all cards with fields
        cards = whitelist_db.list_cards(conn, profile_id)
        # Enrich with photo_path and field_ids
        for card in cards:
            card["photo_path"] = card.get("photo_path")
            card["field_ids"] = [f["id"] for f in card.get("fields", [])]

        # B2: header card keeps its scan stats (last 14 days).
        scan_stats = whitelist_db.get_scan_stats(conn, profile_id)
        visit_count = sum(s["scans"] for s in scan_stats)

        bio = profile.get("bio") or ""
        if bio_override is not None:
            # Re-display what the user typed (e.g. an over-limit draft we
            # refused to save) instead of the stale stored value. Copy first —
            # template reads profile.bio for BOTH textarea and header.
            profile = {**profile, "bio": bio_override}
            bio = bio_override
        # Resolve BASE_URL for the share-link template (config-driven:
        # APP_BASE_URL > legacy BASE_URL > LAN default, never fails).
        base_url = mailer.app_base_url()
        # UX pass 3: UNIFIED sharing — the link the QR + Share button carry
        # is the profile URL itself. No bundle, no card-choosing: the
        # access-grant decision lands after a contact requests access.
        share_url = f"{base_url}/p/{profile['handle']}"
        return HTMLResponse(jinja.get_template("my_profile.html").render(
            request=request,
            profile=profile,
            owner_id=profile_id,
            owner_email=owner_email,
            cards=cards,
            token=token,
            bio=bio,
            bio_len=len(bio),
            bio_error=bio_error,
            new_card_error=new_card_error,
            visit_count=visit_count,
            days_since=days_since,
            days_until=days_until,
            share_error=share_error,
            BASE_URL=base_url,
            share_url=share_url,
            share_message=(f"{profile['display_name']} wants to share their "
                           f"WhiteList card: {share_url}"),
            share_subject=f"{profile['display_name']} WhiteList Card",
        ), status_code=status_code)

    @application.get("/owner/{token}/profile", response_class=HTMLResponse)
    async def owner_profile(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            profile = result[1]
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.post("/owner/{token}/bio")
    async def owner_bio(request: Request, token: str):
        form = await request.form()
        bio = (form.get("bio") or "").strip()
        bio_error = None
        if len(bio) > 500:
            # B2: over-limit is REJECTED — never silently truncate-and-save.
            # The draft re-renders so the user can trim it themselves.
            # UX pass 2 (2026-09-22): cap lowered 2000 → 500.
            bio_error = f"Bio must be 500 characters or fewer (currently {len(bio)})."
            conn = whitelist_db.wl_connect(path)
            try:
                result = _resolve_owner(conn, request, token, _get_secret())
                if result[0] is None and result[2] is None:
                    return HTMLResponse("Invalid or expired link", status_code=403)
                if result[2]:
                    return RedirectResponse(url=f"/owner/{result[2]}")
                profile_id = result[0]
                profile = result[1]
                if not profile:
                    return HTMLResponse("Profile not found", status_code=404)
                return _my_profile_html(conn, request, token, profile,
                                        bio_error=bio_error, bio_override=bio,
                                        status_code=400)
            finally:
                conn.close()

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            profile = result[1]
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            whitelist_db.update_bio(conn, profile_id, bio)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            return _my_profile_html(conn, request, token, profile,
                                    bio_error=bio_error)
        finally:
            conn.close()

    @application.post("/owner/{token}/bio-visibility")
    async def owner_bio_visibility(request: Request, token: str):
        """Toggle bio visibility between public and private."""
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        visibility = (form.get("bio_visibility") or "").strip()
        if visibility not in ("public", "private"):
            return HTMLResponse("Invalid visibility value", status_code=400)

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)

            whitelist_db.update_bio_visibility(conn, profile_id, visibility)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/new")
    async def owner_create_card(request: Request, token: str):
        form = await request.form()
        name = (form.get("name") or "").strip()
        name_error = None
        if not name:
            name_error = "Card name is required."
        elif len(name) > 60:
            name_error = "Card name must be 60 characters or fewer."

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

            if not name_error:
                try:
                    whitelist_db.create_card(conn, profile_id, name, [])
                except ValueError:
                    name_error = "A card with this name already exists."

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            # Friendly 400 page on dup (spec B2); friendly 200 on success.
            return _my_profile_html(conn, request, token, profile,
                                    new_card_error=name_error,
                                    status_code=400 if name_error else 200)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/fields")
    async def owner_set_card_fields(request: Request, token: str, card_id: int):
        form = await request.form()
        field_ids_raw = form.getlist("field_ids")
        field_ids = [int(f) for f in field_ids_raw if f]

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

            # Cross-owner guard (AC #6): the token's profile must own this
            # card. Only an EXISTING foreign card 404s; a missing card falls
            # through to set_card_fields, whose ValueError still 400s (B3:
            # junk field ids → 400, never 500).
            card = whitelist_db.get_card_by_id(conn, card_id)
            if card is not None and card["owner_profile_id"] != profile_id:
                return HTMLResponse("Not found", status_code=404)

            try:
                whitelist_db.set_card_fields(conn, card_id, field_ids)
            except ValueError:
                return HTMLResponse("Invalid field or card", status_code=400)

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.post("/owner/{token}/fields/new")
    async def owner_add_field(request: Request, token: str):
        form = await request.form()
        field_type = form.get("field_type", "")
        field_value = (form.get("field_value") or "").strip()
        # UX pass 2 defaults ruling: everything defaults to 'granted'.
        visibility = form.get("visibility", "granted")

        if not field_type or field_type not in ("email", "phone"):
            return HTMLResponse("Invalid field type", status_code=400)
        if not field_value:
            return HTMLResponse("Field value is required", status_code=400)
        if visibility not in ("public", "granted"):
            return HTMLResponse("Invalid visibility", status_code=400)

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

            whitelist_db.add_profile_field(conn, profile_id, field_type, field_value, visibility)

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    # ------------------------------------------------------------------ Card editor (2026-09-20)
    # Conventional vCard creation/edit page for ONE card: photo with
    # client-side crop/zoom/position, every conventional field from the
    # store with its own visibility control. Single render site (same
    # lesson as _my_profile_html: forked render blocks drop state).

    def _resolve_editor_card(conn, request, token: str, card_id: int):
        """Shared auth + ownership guard for the card-editor routes.

        Returns (profile_id, card, error_response) — error_response is set
        when the caller must return it immediately (403 invalid link,
        session-redirect, or 404 unknown/foreign card — ruling 2A).

        UX pass 3 exception: CURATED stub profiles. A profile the owner
        created via the + new-connection flow (owner_id = that owner,
        password_hash NULL — never self-published) is editable by its
        creating owner, so 'Create vCard' can open the new vCard's editor.
        Other accounts still 404 (2A isolation intact), and a profile that
        has signed in / set a password is self-published and closes again.
        """
        result = _resolve_owner(conn, request, token, _get_secret())
        if result[0] is None and result[2] is None:
            return None, None, HTMLResponse("Invalid or expired link", status_code=403)
        if result[2]:
            return None, None, RedirectResponse(url=f"/owner/{result[2]}")
        profile_id = result[0]
        card = whitelist_db.get_card_by_id(conn, card_id)
        if not card:
            return None, None, HTMLResponse("Card not found", status_code=404)
        if card["owner_profile_id"] != profile_id:
            stub = conn.execute(
                "SELECT owner_id, password_hash FROM profiles WHERE id = ?",
                (card["owner_profile_id"],),
            ).fetchone()
            if not (stub is not None and stub["password_hash"] is None
                    and stub["owner_id"] == profile_id):
                return None, None, HTMLResponse("Not found", status_code=404)
        return profile_id, card, None

    def _card_editor_html(conn, request, token: str, profile: dict, card: dict,
                          error: str = None, status_code: int = 200) -> HTMLResponse:
        """Render card_editor.html from ONE place.

        GET /cards/{id}/edit, POST /cards/{id}/edit (validation errors and
        the success re-render) and POST /cards/{id}/photo all answer
        through here so the editor page can never drift between routes.
        """
        field_types = whitelist_db.CARD_EDITOR_FIELD_TYPES
        by_type = {t: [] for t in field_types}
        for f in card.get("fields", []):
            if f["field_type"] in by_type:
                by_type[f["field_type"]].append(dict(f))
        base_url = wl_env.get_secret("BASE_URL") or "https://whitelist.app"
        return HTMLResponse(jinja.get_template("card_editor.html").render(
            request=request,
            profile=profile,
            card=card,
            by_type=by_type,
            sections=whitelist_db.CARD_EDITOR_SECTIONS,
            labels=whitelist_db.CARD_EDITOR_FIELD_LABELS,
            field_types=field_types,
            multi_types=whitelist_db.CARD_EDITOR_MULTI_TYPES,
            token=token,
            owner_id=profile["id"],
            error=error,
            BASE_URL=base_url,
        ), status_code=status_code)

    @application.get("/owner/{token}/cards/{card_id}/edit", response_class=HTMLResponse)
    async def owner_card_edit(request: Request, token: str, card_id: int):
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err
            # UX pass 3: render the CARD-owner profile — for curated stubs
            # (new-connection vCards) the name being edited is the stub's,
            # never the signed-in owner's.
            profile = whitelist_db.get_profile_by_id(conn, card["owner_profile_id"])
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _card_editor_html(conn, request, token, profile, card)
        finally:
            conn.close()

    _FIELD_KEY_RE = re.compile(r"^field_(\d+)_(value|remove)$")

    # UX pass 3 defaults ruling (2026-09-23): identity/friend-finding fields
    # default PUBLIC — title, company, website, birthday, the personal
    # history types (high school / maiden name / nickname), and the
    # city/state-level address parts. Street-level addresses (address1,
    # address2, zip, childhood street) default 'granted'; everything else
    # defaults 'granted'.
    _PUBLIC_DEFAULT_TYPES = ("title", "company", "website", "birthday",
                             "high_school", "maiden_name", "nickname",
                             "city", "state",
                             "childhood_city", "childhood_state")

    def _editor_default_visibility(field_type: str) -> str:
        return ("public" if field_type in _PUBLIC_DEFAULT_TYPES else "granted")

    def _parse_editor_form(form):
        """Parse the card-editor POST body into save_card_editor args.

        Shared by the save route AND the per-field ✕ delete route: the ✕
        posts the WHOLE editor form (formaction override), so the delete
        path must persist everything else keyed in — this is the fix for
        the pass-2 data-loss bug (deleting a field used to drop edits).

        Returns (display_name, card_name, updates, labels, removals,
        new_fields) where updates are (fid, value, visibility), labels map
        fid → raw label submission, and new_fields are
        (type, value, visibility[, label]) 4-tuples.
        """
        display_name = (form.get("display_name") or "").strip()
        card_name = (form.get("card_name") or "").strip()

        # Existing rows: field_{id}_value (+ _visibility, + _label +
        # _label_custom, + _remove). Collect all key kinds first — a row
        # with only non-value keys must still register.
        remove_ids: set[int] = set()
        value_rows: dict[int, tuple[str, str | None]] = {}
        for key in form.keys():
            m = _FIELD_KEY_RE.match(key)
            if not m:
                continue
            fid = int(m.group(1))
            if m.group(2) == "remove":
                remove_ids.add(fid)
            else:
                value_rows[fid] = (form.get(key) or "",
                                   form.get(f"field_{fid}_visibility"))
        updates = [(fid, v, vis) for fid, (v, vis) in value_rows.items()
                   if fid not in remove_ids]
        removals = list(remove_ids)

        labels: dict[int, str] = {}
        for key in form.keys():
            m = re.match(r"^field_(\d+)_label$", key)
            if m:
                fid = int(m.group(1))
                raw = form.get(key) or ""
                if raw == "__custom":
                    raw = form.get(f"field_{fid}_label_custom") or ""
                labels[fid] = raw

        # New rows: new_{type}_value[] + new_{type}_visibility[] (+
        # _label[]/_label_custom[]) as parallel getlists (the + Add rows
        # from the editor UI).
        new_fields: list[tuple] = []
        for t in whitelist_db.CARD_EDITOR_FIELD_TYPES:
            values = form.getlist(f"new_{t}_value")
            vis = form.getlist(f"new_{t}_visibility")
            raw_labels = form.getlist(f"new_{t}_label")
            custom_labels = form.getlist(f"new_{t}_label_custom")
            for i, value in enumerate(values):
                # UX pass 2 defaults ruling: 'granted' everywhere, except
                # title/company/website which default 'public'. (Was
                # blanket-private before the ruling.)
                visibility = (vis[i] if i < len(vis)
                              else _editor_default_visibility(t))
                label = ""
                if i < len(raw_labels):
                    label = raw_labels[i]
                    if label == "__custom" and i < len(custom_labels):
                        label = custom_labels[i]
                new_fields.append((t, value, visibility, label))

        return display_name, card_name, updates, labels, removals, new_fields

    @application.post("/owner/{token}/cards/{card_id}/edit", response_class=HTMLResponse)
    async def owner_card_edit_save(request: Request, token: str, card_id: int):
        form = await request.form()
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            (display_name, card_name, updates, labels, removals,
             new_fields) = _parse_editor_form(form)

            try:
                whitelist_db.save_card_editor(
                    conn, card_id,
                    display_name=display_name, card_name=card_name,
                    field_updates=updates, field_labels=labels,
                    field_removals=removals,
                    new_fields=new_fields,
                )
            except ValueError as exc:
                profile = whitelist_db.get_profile_by_id(conn, card["owner_profile_id"])
                card = whitelist_db.get_card_by_id(conn, card_id)
                return _card_editor_html(conn, request, token, profile, card,
                                         error=str(exc), status_code=400)

            card = whitelist_db.get_card_by_id(conn, card_id)
            profile = whitelist_db.get_profile_by_id(conn, card["owner_profile_id"])
            return _card_editor_html(conn, request, token, profile, card)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/fields/{field_id}/delete")
    async def owner_field_delete(request: Request, token: str, card_id: int,
                                 field_id: int):
        """UX pass (2026-09-22): the editor's per-field ✕ deletes the field
        from the card IMMEDIATELY — no checkbox accumulate-then-save step.

        Pass-2 BUG FIX: the ✕ posts the WHOLE editor form (formaction
        override), and this route used to ignore the body and redirect —
        every other edit keyed into the form was lost on the refresh. The
        full form is now parsed and applied TOGETHER with the removal, so
        deleting a field never drops entered data.

        Unlink semantics match save_card_editor removals: the card_fields
        row goes, the profile_fields row survives (cards are lenses, not
        containers). Ownership/IDOR is enforced by save_card_editor
        (foreign card or field → ValueError → 404).
        """
        form = await request.form()
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            (display_name, card_name, updates, labels, removals,
             new_fields) = _parse_editor_form(form)
            removals.append(field_id)  # the ✕'s own removal
            updates = [(fid, v, vis) for fid, v, vis in updates
                       if fid != field_id]
            labels.pop(field_id, None)
            try:
                whitelist_db.save_card_editor(
                    conn, card_id,
                    display_name=display_name, card_name=card_name,
                    field_updates=updates, field_labels=labels,
                    field_removals=removals,
                    new_fields=new_fields,
                )
            except ValueError as exc:
                # A foreign field id stays a 404 (IDOR, fail closed); any
                # other save error (duplicate value, …) re-renders the
                # editor with the message so keyed data survives.
                row = conn.execute(
                    "SELECT profile_id FROM profile_fields WHERE id = ?",
                    (field_id,),
                ).fetchone()
                if row is None or row["profile_id"] != profile_id:
                    return HTMLResponse("Not found", status_code=404)
                profile = whitelist_db.get_profile_by_id(conn, profile_id)
                card = whitelist_db.get_card_by_id(conn, card_id)
                return _card_editor_html(conn, request, token, profile, card,
                                         error=str(exc), status_code=400)
            # 303 back to the editor GET — the row is gone on landing.
            return RedirectResponse(
                url=f"/owner/{token}/cards/{card_id}/edit", status_code=303)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/delete")
    async def owner_delete_card(request: Request, token: str, card_id: int):
        """Delete ONE card (round-2 captain ask: destructive action with a
        confirm step). The confirm step lives in the editor UI (two-stage
        button); the route itself is the guarded write: ownership is
        enforced by _resolve_editor_card (foreign card → 404, ruling 2A),
        profile_fields survive (cards are lenses, not containers), and
        grant_cards links cascade away with the card."""
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            whitelist_db.delete_card(conn, card_id, profile_id)

            # The card's photo files have no DB row anymore — unlink both
            # slots (default + high-school picture, UX pass 3).
            for photo_path in (f"{profile_id}_{card_id}.jpg",
                               f"{profile_id}_{card_id}_hs.jpg"):
                try:
                    (Path(__file__).parent / "uploads" / photo_path).unlink()
                except OSError:
                    pass

            # 303 (See Other): the browser must land on My Profile with a
            # GET — a 307 would replay the POST onto /profile (405).
            return RedirectResponse(url=f"/owner/{token}/profile", status_code=303)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/photo")
    async def owner_upload_photo(request: Request, token: str, card_id: int,
                                 photo_kind: str = Query(None)):
        from starlette.datastructures import UploadFile
        import os

        form = await request.form()
        remove_photo = form.get("remove_photo")
        # UX pass 3: two picture slots on personal cards — the DEFAULT
        # picture (photo_kind absent/'default') and the HIGH-SCHOOL picture
        # ('hs'). Both default public on personal cards.
        kind = "hs" if photo_kind == "hs" else "default"

        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            upload_dir = Path(__file__).parent / "uploads"
            upload_dir.mkdir(exist_ok=True)
            photo_path = f"{profile_id}_{card_id}.jpg"
            hs_photo_path = f"{profile_id}_{card_id}_hs.jpg"
            slot_path = hs_photo_path if kind == "hs" else photo_path
            full_path = upload_dir / slot_path

            if remove_photo:
                # Remove photo
                stored = (card.get("hs_photo_path") if kind == "hs"
                          else card.get("photo_path"))
                if stored:
                    try:
                        os.unlink(full_path)
                    except OSError:
                        pass
                whitelist_db.update_card_photo(
                    conn, card_id, None, kind=kind)
            else:
                # Two upload paths: the client-side cropper posts its result
                # as a base64 data URL (photo_data); a raw file (photo) is
                # the no-JS fallback. photo_data wins when both arrive.
                photo_file = form.get("photo")
                photo_data = form.get("photo_data")
                content = None
                if isinstance(photo_data, str) and photo_data.startswith("data:image/"):
                    import base64
                    m = re.match(r"^data:image/(jpeg|png);base64,(.*)$", photo_data, re.DOTALL)
                    if not m:
                        return HTMLResponse("Invalid image data", status_code=400)
                    try:
                        content = base64.b64decode(m.group(2))
                    except Exception:
                        return HTMLResponse("Invalid image file", status_code=400)
                    if len(content) > 10 * 1024 * 1024:  # 10 MB
                        return HTMLResponse("File too large (max 10 MB)", status_code=413)
                elif isinstance(photo_file, UploadFile) and photo_file.filename:
                    content = await photo_file.read()
                    if len(content) > 10 * 1024 * 1024:  # 10 MB
                        return HTMLResponse("File too large (max 10 MB)", status_code=413)

                if content is not None:
                    try:
                        data = _encode_square_jpeg(content)
                    except ValueError:
                        return HTMLResponse("Invalid image file", status_code=400)
                    full_path.write_bytes(data)
                    whitelist_db.update_card_photo(
                        conn, card_id,
                        hs_photo_path if kind == "hs" else photo_path,
                        kind=kind)

            card = whitelist_db.get_card_by_id(conn, card_id)
            profile = whitelist_db.get_profile_by_id(conn, card["owner_profile_id"])
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            # Back to the editor (the upload lives there now).
            return _card_editor_html(conn, request, token, profile, card)
        finally:
            conn.close()

    @application.get("/owner/{token}/profile/card/{card_id}")
    async def owner_card_preview(request: Request, token: str, card_id: int):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

            card = whitelist_db.get_card_by_id(conn, card_id)
            if not card:
                return HTMLResponse("Card not found", status_code=404)
            if card["owner_profile_id"] != profile_id:
                return HTMLResponse("Not found", status_code=404)

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("card_preview.html").render(
            request=request,
            card=card,
            profile=profile,
            owner_id=profile_id,
            token=token,
            days_since=days_since,
        ))

    @application.get("/photos/{owner_profile_id}/{card_id}")
    async def serve_photo(owner_profile_id: int, card_id: int):
        upload_dir = Path(__file__).parent / "uploads"
        photo_path = f"{owner_profile_id}_{card_id}.jpg"
        full_path = upload_dir / photo_path
        if not full_path.exists():
            return HTMLResponse("Photo not found", status_code=404)
        from fastapi.responses import FileResponse
        return FileResponse(full_path, media_type="image/jpeg")

    @application.get("/photos/{owner_profile_id}/{card_id}/hs")
    async def serve_hs_photo(owner_profile_id: int, card_id: int):
        """UX pass 3: the HIGH-SCHOOL picture slot on personal cards."""
        upload_dir = Path(__file__).parent / "uploads"
        photo_path = f"{owner_profile_id}_{card_id}_hs.jpg"
        full_path = upload_dir / photo_path
        if not full_path.exists():
            return HTMLResponse("Photo not found", status_code=404)
        from fastapi.responses import FileResponse
        return FileResponse(full_path, media_type="image/jpeg")

    @application.get("/qr/share/{bundle_id}")
    async def serve_bundle_qr(bundle_id: str):
        """QR for a share bundle — encodes the single /s/{bundle_id} link."""
        conn = whitelist_db.wl_connect(path)
        try:
            bundle = whitelist_db.get_share_bundle(conn, bundle_id)
            if not bundle:
                return HTMLResponse("Not found", status_code=404)
        finally:
            conn.close()
        return Response(content=_qr_png(_bundle_share_url(bundle_id)),
                        media_type="image/png")

    @application.get("/qr/{handle}")
    async def serve_qr(handle: str):
        """Serve a QR code PNG for the given profile handle."""
        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
        finally:
            conn.close()

        return Response(content=_qr_png(f"{mailer.app_base_url()}/p/{handle}"),
                        media_type="image/png")

    @application.post("/owner/{token}/decision")
    async def owner_decision(request: Request, token: str):
        form = await request.form()
        grant_id = form.get("grant_id", "")
        decision = form.get("decision", "")
        expiry = form.get("expiry", "90")

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            # Verify grant ownership
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)

            return _decision_outcome(conn, jinja, request, grant_id,
                                     decision, expiry)
        finally:
            conn.close()

    # Context routes (/categorize, /context) REMOVED per Jason ruling
    # 2026-09-12 — feature cut from the product. DB layer untouched; if it's
    # ever revived it's app-layer work only (git history has the code).

    @application.get("/owner/{token}/contact/{grant_id}", response_class=HTMLResponse)
    async def owner_contact_card(request: Request, token: str, grant_id: str):
        """Contact card — single-surface view of one contact from the dashboard.
        Ruling: revoke lives on the contact card, not the list details expander.
        """
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)

            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            cards = whitelist_db.list_cards(conn, grant["profile_id"])
            for card in cards:
                card["photo_path"] = card.get("photo_path")
                card["field_ids"] = [f["id"] for f in card.get("fields", [])]
                # Enrich visible_fields
                if card.get("fields"):
                    card["visible_fields"] = card["fields"]
                else:
                    card["visible_fields"] = []
            # UX pass (2026-09-22): the detail view shows ONE card at a
            # time (captain's pass), with a chip switcher when the contact
            # has several. ?card=<id> selects; default is the first card.
            try:
                selected_card_id = int(request.query_params.get("card", ""))
            except ValueError:
                selected_card_id = None
            selected_card = next(
                (c for c in cards if c["id"] == selected_card_id),
                cards[0] if cards else None)
            stale = is_verified_stale(profile.get("verified_at"))
            # Determine tier for this grant
            if grant["status"] == "granted":
                tier = "granted"
            elif grant["status"] == "pending":
                tier = "pending"
            else:
                tier = "denied"
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("contact_card.html").render(
            request=request, profile=profile, grant=grant, cards=cards,
            selected_card=selected_card,
            tier=tier, stale=stale, days_since=days_since, token=token,
            grant_id=grant_id, is_grey=whitelist_db.is_grey(grant)))

    @application.post("/owner/{token}/bulk", response_class=HTMLResponse)
    async def owner_bulk(request: Request, token: str):
        """P4-T2: one decision over many grants. Per-grant scoping lives in
        bulk_apply (approve/deny -> pending only; revoke -> granted only);
        dead rows skip, they never abort the batch."""
        form = await request.form()
        grant_ids = form.getlist("grant_ids")
        decision = str(form.get("decision", ""))
        expiry = str(form.get("expiry", "90"))

        if not grant_ids:
            return HTMLResponse("No grants selected", status_code=400)

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            # Verify all grants belong to this owner
            for gid in grant_ids:
                grant = whitelist_db.get_grant(conn, gid)
                if grant and not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                    return HTMLResponse("Not found", status_code=404)

            try:
                summary = whitelist_db.bulk_apply(conn, grant_ids, decision, expiry)
            except ValueError as exc:
                return HTMLResponse(str(exc), status_code=400)
        finally:
            conn.close()

        return HTMLResponse(
            f"Bulk {decision}: {summary['approved']} approved, "
            f"{summary['denied']} BlackListed, {summary['revoked']} BlackListed, "
            f"{summary['skipped']} skipped (wrong status or unknown id).")

    @application.post("/owner/{token}/revoke", response_class=HTMLResponse)
    async def owner_revoke(request: Request, token: str):
        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)

            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            # Only active access can be revoked — anything else is an error,
            # surfaced (not swallowed): the helper raises ValueError.
            whitelist_db.revoke_grant(conn, grant_id)
            grant = whitelist_db.get_grant(conn, grant_id)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=409)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_decision.html").render(
            request=request, grant=grant, profile=profile, decision="revoke"))

    # ------------------------------------------------------------------ Quarterly actions
    @application.post("/owner/{token}/quarter/make_permanent", response_class=HTMLResponse)
    async def quarter_make_permanent(request: Request, token: str):
        """Make a grey grant permanent (lifetime access)."""
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            updated = whitelist_db.make_grant_permanent(conn, grant_id)
            if updated is None:
                return HTMLResponse("Grant not found", status_code=404)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=409)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_decision.html").render(
            request=request, grant=updated, profile=profile, decision="make_permanent"))

    @application.post("/owner/{token}/quarter/revoke", response_class=HTMLResponse)
    async def quarter_revoke(request: Request, token: str):
        """Revoke a grey grant (lands in blocked state)."""
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            whitelist_db.revoke_grant(conn, grant_id)
            grant = whitelist_db.get_grant(conn, grant_id)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=409)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_decision.html").render(
            request=request, grant=grant, profile=profile, decision="revoke"))

    @application.post("/owner/{token}/quarter/punt", response_class=HTMLResponse)
    async def quarter_punt(request: Request, token: str):
        """Punt a grey grant for another quarter."""
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            updated = whitelist_db.punt_grant(conn, grant_id)
            if updated is None:
                return HTMLResponse("Grant not found", status_code=404)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=409)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_decision.html").render(
            request=request, grant=updated, profile=profile, decision="punt"))

    app = application
    return application


# Module-level entrypoint: a fully-routed app (not a bare stub) so that
# ``uvicorn app:app`` serves the real service without any pre-call. Secrets are
# only touched per-request, so building here does not require them at import.
app = create_app()
