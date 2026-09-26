"""Auth routes: sign-in, sign-up, sign-out, forgot/reset password.

Every route opens its own sqlite3 connection against ctx.db_path and
renders through ctx.jinja. Split out of app.py (2026-09-26 refactor);
behavior is unchanged.
"""

import re
import sys

from fastapi import Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.background import BackgroundTask

import mailer
import whitelist_db

from web_support import (
    WebContext,
    _get_secret,
    _make_session_cookie,
)

_SESSION_COOKIE_DAYS = 7


def _set_session_redirect(profile_id: int, request: Request,
                          url: str = "/") -> RedirectResponse:
    """303 redirect with a fresh wl_session cookie (shared by sign-in and
    sign-up). 303 See Other: the browser must follow with GET — a default
    307 re-POSTs to "/" and lands on 405 Method Not Allowed."""
    secret = _get_secret()
    session_cookie = _make_session_cookie(profile_id, secret)
    response = RedirectResponse(url=url, status_code=303)
    response.set_cookie(
        key="wl_session",
        value=session_cookie,
        httponly=True,
        samesite="lax",
        max_age=_SESSION_COOKIE_DAYS * 86400,
        secure=request.url.scheme == "https",
    )
    return response


def register_auth_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path
    jinja = ctx.jinja

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
            return _set_session_redirect(profile["id"], request)
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
            return _set_session_redirect(profile["id"], request)
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
