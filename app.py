"""FastAPI application for the whitelist service.

app.py is the composition root: it builds the FastAPI instance, installs
the security middleware + static mount + retired-link handler, runs the
one-shot schema heal, and registers the route groups (routes_*.py, each
cohesive around one surface). Shared helpers live in web_support.py.

Module-level ``app`` is a real FastAPI instance so that
``uvicorn app:app`` works out of the box (F2). Secrets are read lazily
per-request, never at import time — importing this module must not
require WHITELIST_SECRET to be present.

Test-compat surface (2026-09-26 refactor): tests import helper names from
this module (days_since/_make_session_cookie/_verify_grant_ownership/…)
and monkeypatch ``app._send_connection_request_email`` BEFORE calling
create_app — both keep working via the re-exports below plus the
create_app-time read of that global into WebContext.
"""

from pathlib import Path
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

import whitelist_db
import wl_env

# Shared helpers (web_support) re-exported under their historical app.*
# names — tests and tooling import them from here.
from web_support import (  # noqa: F401
    WebContext,
    LegacyOwnerLinkRetired,
    _STATIC_DIR,
    _build_vcard,
    _consume_session_cookie,
    _decision_outcome,
    _make_jinja,
    _make_session_cookie,
    _qr_png,
    _resolve_owner,
    _send_connection_request_email,
    _static_version,
    _vcf_escape,
    _verify_grant_ownership,
    days_since,
    days_until,
    is_verified_stale,
)

from routes_auth import register_auth_routes
from routes_public import register_public_routes
from routes_share import register_share_routes
from routes_review import register_review_routes
from routes_dashboard import register_dashboard_routes
from routes_profile import register_profile_routes
from routes_editor import register_editor_routes
from routes_media import register_media_routes
from routes_decisions import register_decision_routes


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
    # Security audit 2 (2026-09-26): FastAPI's default /docs, /redoc and
    # /openapi.json are disabled — they served the full route map (44
    # paths) to unauthenticated visitors for zero product value.
    application = FastAPI(title="WhiteList", docs_url=None, redoc_url=None,
                          openapi_url=None)
    # Tests (and tooling) recover the tmp db path from the bound app.
    application.state.relmgr_db_path = path

    # ============================================================
    # Security middleware (audit 2026-09-25): response headers, request
    # body cap, and a small per-IP sliding-window limiter on the
    # anonymous POST surfaces (connection requests, forwards, auth).
    # ============================================================
    _MAX_BODY_BYTES = 16 * 1024 * 1024  # 16 MB across every request
    _RATELIMIT_OFF = bool(
        wl_env.get_secret("WHITELIST_RATELIMIT_DISABLED"))
    _rate_buckets: dict[tuple[str, str], list[float]] = {}
    _RATE_RULES = {
        # path-prefix -> (max requests, window seconds) per client IP
        "auth": (30, 60),        # /signin, /signup, /forgot-password POSTs
        "publicpost": (10, 60),  # /p/{handle}/request + /forward
    }

    def _rate_limited(request: Request) -> bool:
        """True when this client exceeded its window for the bucket the
        request lands in. Single-process (uvicorn) by design; set
        WHITELIST_RATELIMIT_DISABLED=1 to switch it off (tests/load tools).
        """
        p = request.url.path
        if request.method != "POST":
            return False
        if p in ("/signin", "/signup", "/forgot-password"):
            bucket = "auth"
        elif (p.endswith("/request") or p.endswith("/forward")) \
                and p.startswith("/p/"):
            bucket = "publicpost"
        else:
            return False
        max_n, window = _RATE_RULES[bucket]
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        key = (ip, bucket)
        hits = _rate_buckets.setdefault(key, [])
        while hits and now - hits[0] > window:
            hits.pop(0)
        if len(hits) >= max_n:
            return True
        hits.append(now)
        return False

    @application.middleware("http")
    async def _security_middleware(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if (content_length and content_length.isdigit()
                and int(content_length) > _MAX_BODY_BYTES):
            r = HTMLResponse("Request body too large", status_code=413)
            r.headers["Cache-Control"] = "no-cache"
            return r
        if not _RATELIMIT_OFF and _rate_limited(request):
            r = HTMLResponse("Too many requests — try again later.",
                             status_code=429)
            r.headers["Cache-Control"] = "no-cache"
            return r
        response = await call_next(request)
        # Capability tokens live in /owner/{token} URLs — never leak them
        # via Referer on outbound navigation.
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()")
        # Cache discipline (2026-09-26): every HTML page revalidates so a
        # stale phone browser can never mask a deployed fix (Safari had
        # been serving old editor/profile pages after server updates).
        # /static is content-versioned via asset_v() URLs → immutable
        # forever. /photos and /qr mutate in place under the same URL →
        # revalidate (their ETag/Last-Modified make that a cheap 304).
        if "cache-control" not in response.headers:
            ct = response.headers.get("content-type", "")
            p = request.url.path
            if ct.startswith("text/html"):
                response.headers["Cache-Control"] = "no-cache, must-revalidate"
            elif p.startswith("/static/"):
                response.headers["Cache-Control"] = (
                    "public, max-age=31536000, immutable")
            elif p.startswith(("/photos/", "/qr/")):
                response.headers["Cache-Control"] = "no-cache"
        return response

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

    # Route groups (routes_*.py). Registration order mirrors the original
    # single-file order; paths are structurally distinct so ordering is not
    # load-bearing, but keeping it identical makes the split diff-safe.
    ctx = WebContext(
        db_path=path,
        jinja=jinja,
        # Read from THIS module's namespace at create_app time so tests
        # monkeypatching app._send_connection_request_email first stay in
        # control of the BackgroundTask (test_security_audit S5).
        push_connection_email=_send_connection_request_email,
    )
    register_auth_routes(application, ctx)       # /signin /signup /signout /forgot /reset
    register_public_routes(application, ctx)     # / /owner/ /p/{handle} + connect flow
    register_share_routes(application, ctx)      # /s/{bundle_id}[.vcf]
    register_review_routes(application, ctx)     # /a/{token} /verify/{token}
    register_dashboard_routes(application, ctx)  # /owner/{token} contact list + badge/junk/approve/new-connection/access/contact card
    register_profile_routes(application, ctx)    # /owner/{token}/profile + bio/cards/fields
    register_editor_routes(application, ctx)     # card editor + photos upload + preview
    register_media_routes(application, ctx)      # /photos/* /qr/*
    register_decision_routes(application, ctx)   # /decision /bulk /revoke /quarter/*

    app = application
    return application


# Module-level entrypoint: a fully-routed app (not a bare stub) so that
# ``uvicorn app:app`` serves the real service without any pre-call. Secrets are
# only touched per-request, so building here does not require them at import.
app = create_app()
