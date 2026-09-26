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
            # Amber-box redesign (2026-09-26): the review page carries the
            # SAME three-way decision as the dashboard — checkbox card
            # selection over the owner's cards (the same set set_grant_cards
            # validates against), and the requester's bio when they have a
            # profile with one.
            cards = whitelist_db.list_cards(
                conn, grant.get("owner_id") or grant["profile_id"])
            requester = whitelist_db.find_requester_profile(
                conn, grant["requester_email"])
            requester_bio = (requester or {}).get("bio") or ""
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_review.html").render(
            request=request, grant=grant, profile=profile, token=token,
            cards=cards, requester_bio=requester_bio))

    @application.post("/a/{token}/decision")
    async def admin_decision(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "grant_review", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        raw_decision = form.get("decision", "")
        expires_at_choice = form.get("expiry", "90")
        card_ids_raw = form.getlist("card_ids")

        decision = raw_decision
        if decision in ("whitelist", "greylist"):
            # WhiteList = lifetime access, GreyList = the quarter marker —
            # the same approve semantics as the dashboard modal.
            expires_at_choice = "lifetime" if decision == "whitelist" else "quarter"
            decision = "approve"
            if not card_ids_raw:
                return HTMLResponse("At least one card must be selected",
                                    status_code=400)

        grant_id = payload
        conn = whitelist_db.wl_connect(path)
        try:
            if raw_decision == "blacklist":
                # Badge machinery, ALWAYS SILENT: the pending grant lands
                # revoked (== blacklisted, one state) and the requester
                # joins the contact list under the black badge.
                grant = whitelist_db.get_grant(conn, grant_id)
                if not grant:
                    return HTMLResponse("Grant not found", status_code=404)
                updated = whitelist_db.set_badge_state(conn, grant_id, "blocked")
                if updated is None:
                    return HTMLResponse("Grant not found", status_code=404)
                profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
                return HTMLResponse(jinja.get_template("admin_decision.html").render(
                    request=request, grant=updated, profile=profile,
                    decision="revoke"))

            outcome = _decision_outcome(conn, jinja, request, grant_id,
                                        decision, expires_at_choice)
            # Selected cards ride with the approve decisions; legacy
            # approve/deny (old links, tests) keep their no-cards behavior
            # unless cards were posted. Junk/foreign ids degrade to 400,
            # never 500 (spec B3/q38; foreign cards rejected inside
            # set_grant_cards, ruling 2A).
            if (decision == "approve" and outcome.status_code == 200
                    and card_ids_raw):
                try:
                    card_ids = [int(c) for c in card_ids_raw]
                    whitelist_db.set_grant_cards(conn, grant_id, card_ids)
                except ValueError:
                    return HTMLResponse("Invalid card selection", status_code=400)
            return outcome
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
