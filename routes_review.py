"""Emailed grant-review links (/a/{token}) and the verify endpoint.

Split out of app.py (2026-09-26 refactor); behavior is unchanged.
"""

from fastapi import Request
from fastapi.responses import HTMLResponse

import whitelist_db
import wl_tokens

from web_support import (
    WebContext,
    _decision_outcome,
    _get_secret,
)


def register_review_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path
    jinja = ctx.jinja

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
