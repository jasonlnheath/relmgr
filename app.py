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
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse, Response
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
    return Jinja2Templates(directory=str(_JINJA_DIR))


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
        "This link expires in 7 days. You can also decide from your "
        "dashboard notifications.\n"
    )
    mailer.send_email(owner_email, "RelMgr: new connection request", body)


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
    application = FastAPI(title="Whitelist")

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

            viewer_email = e if e else None
            tier = whitelist_db.effective_tier(conn, profile["id"], viewer_email)

            stale = is_verified_stale(profile.get("verified_at"))

            # B4: the public page renders cards. Profiles with NO cards at all
            # (seed_default_cards only auto-attaches for jasonheath) keep the
            # legacy flat field list — a card-less profile must not render an
            # empty public page.
            cards = whitelist_db.cards_for_public_view(
                conn, profile["id"], tier)

            bio_visibility = whitelist_db.get_bio_visibility(conn, profile["id"])

            return HTMLResponse(jinja.get_template("profile.html").render(
                request=request, profile=profile, tier=tier, stale=stale,
                cards=cards, bio_visibility=bio_visibility, days_since=days_since))
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

        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
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

        return HTMLResponse(jinja.get_template("request_success.html").render(
            request=request, profile=profile, grant_id=grant_id),
            background=BackgroundTask(
                _send_connection_request_email, path, grant_id))

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
            per_page = 50

            # Owner dashboard: per-owner isolation (ruling 2A). Every auth
            # path — session cookie, integer-payload token, and the legacy
            # fallback link — sees exactly this owner's world, nothing else.
            all_profiles = conn.execute("SELECT * FROM profiles WHERE owner_id = ? ORDER BY id", (profile_id,)).fetchall()
            all_profile_ids = [dict(p)["id"] for p in all_profiles]
            if not all_profile_ids:
                all_profile_ids = [profile_id]

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
                start = page * per_page
                rows = all_rows[start:start + per_page]
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
                    rows.append({
                        "contact_id": None,
                        "name": gd.get("requester_name") or gd.get("requester_email", "Unknown"),
                        "email": gd.get("requester_email", ""),
                        "phone": "",
                        "org": "",
                        "granted": gd["status"] == "granted",
                        "live_grant": gd,
                        "cards": [],
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

            # Notification center (2026-09-20): raise the quarterly prompt
            # (idempotent per owner+quarter via dedupe key) and read the
            # unread badge count for the dashboard header.
            whitelist_db.sync_quarterly_notifications(conn, profile_id)
            unread_notifications = whitelist_db.unread_notification_count(
                conn, profile_id)

            # Unified row list for single-surface contact list (round-2)
            all_rows = rows
            total_contacts = total_rows

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
                my_card=my_card,
                all_cards=all_cards,
                token=token,
                q=q,
                page=page,
                per_page=per_page,
                total_rows=total_rows,
                total_contacts=total_contacts,
                denied_count=denied_count,
                unread_notifications=unread_notifications,
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

    # ------------------------------------------------------------------ Notification center (2026-09-20)
    # The in-app center is the source of truth; email is only the push.
    @application.get("/owner/{token}/notifications", response_class=HTMLResponse)
    async def owner_notifications(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            notifications = whitelist_db.list_notifications(conn, profile_id)
            unread_notifications = whitelist_db.unread_notification_count(
                conn, profile_id)
        finally:
            conn.close()
        return HTMLResponse(jinja.get_template("notifications.html").render(
            request=request,
            notifications=notifications,
            unread_notifications=unread_notifications,
            token=token,
            days_since=days_since,
        ))

    @application.post("/owner/{token}/notifications/read-all")
    async def owner_notifications_read_all(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            whitelist_db.mark_all_notifications_read(conn, profile_id)
        finally:
            conn.close()
        # 303 See Other: the browser must follow with GET.
        return RedirectResponse(url=f"/owner/{token}/notifications", status_code=303)

    @application.post("/owner/{token}/notifications/{notification_id}/read")
    async def owner_notification_read(request: Request, token: str, notification_id: int):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            # Owner-scoped: a foreign/unknown id is a silent no-op.
            whitelist_db.mark_notification_read(
                conn, profile_id, notification_id)
        finally:
            conn.close()
        return RedirectResponse(url=f"/owner/{token}/notifications", status_code=303)

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
                        bio_override=None, status_code=200) -> HTMLResponse:
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
            BASE_URL=base_url,
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
        if len(bio) > 2000:
            # B2: over-limit is REJECTED — never silently truncate-and-save.
            # The draft re-renders so the user can trim it themselves.
            bio_error = f"Bio must be 2000 characters or fewer (currently {len(bio)})."
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
        visibility = form.get("visibility", "public")

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
    _EDITOR_MULTI_TYPES = ("email", "phone")

    def _resolve_editor_card(conn, request, token: str, card_id: int):
        """Shared auth + ownership guard for the card-editor routes.

        Returns (profile_id, card, error_response) — error_response is set
        when the caller must return it immediately (403 invalid link,
        session-redirect, or 404 unknown/foreign card — ruling 2A).
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
            field_types=field_types,
            multi_types=_EDITOR_MULTI_TYPES,
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
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _card_editor_html(conn, request, token, profile, card)
        finally:
            conn.close()

    _FIELD_KEY_RE = re.compile(r"^field_(\d+)_(value|remove)$")

    @application.post("/owner/{token}/cards/{card_id}/edit", response_class=HTMLResponse)
    async def owner_card_edit_save(request: Request, token: str, card_id: int):
        form = await request.form()
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            display_name = (form.get("display_name") or "").strip()
            card_name = (form.get("card_name") or "").strip()

            # Existing rows: field_{id}_value (+ _visibility, + _remove).
            # Collect both key kinds first — a row with a remove checkbox
            # (and no value input, e.g. a checkbox-only POST) must still
            # register as a removal.
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

            # New rows: new_{type}_value[] + new_{type}_visibility[] as
            # parallel getlists (the + Add rows from the editor UI).
            new_fields: list[tuple[str, str, str]] = []
            for t in whitelist_db.CARD_EDITOR_FIELD_TYPES:
                values = form.getlist(f"new_{t}_value")
                vis = form.getlist(f"new_{t}_visibility")
                for i, value in enumerate(values):
                    # Absent visibility defaults to private — zero-trust
                    # default (user decides, app enforces).
                    visibility = vis[i] if i < len(vis) else "private"
                    new_fields.append((t, value, visibility))

            try:
                whitelist_db.save_card_editor(
                    conn, card_id,
                    display_name=display_name, card_name=card_name,
                    field_updates=updates, field_removals=removals,
                    new_fields=new_fields,
                )
            except ValueError as exc:
                profile = whitelist_db.get_profile_by_id(conn, profile_id)
                card = whitelist_db.get_card_by_id(conn, card_id)
                return _card_editor_html(conn, request, token, profile, card,
                                         error=str(exc), status_code=400)

            card = whitelist_db.get_card_by_id(conn, card_id)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            return _card_editor_html(conn, request, token, profile, card)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/photo")
    async def owner_upload_photo(request: Request, token: str, card_id: int):
        from starlette.datastructures import UploadFile
        import os

        form = await request.form()
        remove_photo = form.get("remove_photo")

        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            upload_dir = Path(__file__).parent / "uploads"
            upload_dir.mkdir(exist_ok=True)
            photo_path = f"{profile_id}_{card_id}.jpg"
            full_path = upload_dir / photo_path

            if remove_photo:
                # Remove photo
                if card.get("photo_path"):
                    try:
                        os.unlink(full_path)
                    except OSError:
                        pass
                whitelist_db.update_card_photo(conn, card_id, None)
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
                    whitelist_db.update_card_photo(conn, card_id, photo_path)

            card = whitelist_db.get_card_by_id(conn, card_id)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
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

        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )
        base_url = mailer.app_base_url()
        qr.add_data(f"{base_url}/p/{handle}")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return Response(content=buf.read(), media_type="image/png")

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
            f"{summary['denied']} denied, {summary['revoked']} revoked, "
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
