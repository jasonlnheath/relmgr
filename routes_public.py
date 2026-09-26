"""Public routes: landing, the public profile page (/p/{handle}), and the
connect flow (request form, request POST, forward POST).

Split out of app.py (2026-09-26 refactor); behavior is unchanged.
"""

import uuid

from fastapi import Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.background import BackgroundTask

import whitelist_db
import wl_tokens

from web_support import (
    WebContext,
    _consume_session_cookie,
    _get_secret,
    _resolve_owner,
    days_since,
    is_verified_stale,
)


def register_public_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path
    jinja = ctx.jinja

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

            # Security audit 2026-09-25: owner detection is AUTH-ONLY — a
            # signed owner_dashboard token (?ot=) or the session cookie.
            # The old ?e=-matches-own-email check let ANYONE who knew the
            # owner's signup email mint a 365-day dashboard token and read
            # every private field — email knowledge is not authentication.
            # ?e= remains the granted-CONTACT tracking parameter only.
            viewer_is_owner = False
            ot = request.query_params.get("ot")
            if ot:
                ot_payload = wl_tokens.consume_token(
                    _get_secret(), "owner_dashboard", ot)
                if ot_payload and ot_payload.isdigit() \
                        and int(ot_payload) == profile["id"]:
                    viewer_is_owner = True
            if not viewer_is_owner:
                session_cookie = request.cookies.get("wl_session")
                if session_cookie:
                    session_profile_id = _consume_session_cookie(
                        session_cookie, _get_secret())
                    if session_profile_id and session_profile_id == profile["id"]:
                        viewer_is_owner = True
            owner_token = None
            if viewer_is_owner:
                owner_token = wl_tokens.make_token(
                    _get_secret(), "owner_dashboard", str(profile["id"]))

            viewer_email = e if e else None
            # Owner self-view sees everything; ?e= alone can no longer lift
            # the tier to the owner's own private fields.
            if viewer_is_owner:
                tier = "granted"
            else:
                tier = whitelist_db.effective_tier(
                    conn, profile["id"], viewer_email)

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
                viewer_is_owner=viewer_is_owner, owner_token=owner_token,
                viewer_email=viewer_email))
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
                # Security audit 2026-09-25: deduped re-POSTs must not
                # re-push the owner's email — only a genuinely NEW request
                # notifies (same predicate create_grant dedupes on).
                already_admitted = whitelist_db.find_admitting_grant_id(
                    conn, profile["id"], email or "")
                grant_id = whitelist_db.create_grant(conn, profile["id"], email, name, profile.get("owner_id"))
                is_new_request = already_admitted is None
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

        background = (None if (quarantined or not is_new_request)
                      else BackgroundTask(
                          ctx.push_connection_email, path, grant_id))
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
                ctx.push_connection_email, path, grant_id))
