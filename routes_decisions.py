"""Owner decision routes: the dashboard decision POST, bulk actions,
revoke, and the three quarterly-review actions (make_permanent / revoke /
punt). Every route resolves the owner AND verifies grant ownership
(ruling 2A; the quarter routes once skipped it — security audit 2026-09-25).

Split out of app.py (2026-09-26 refactor); behavior is unchanged.
"""

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

import whitelist_db

from web_support import (
    WebContext,
    _decision_outcome,
    _get_secret,
    _resolve_owner,
    _verify_grant_ownership,
)


# Amber-box three-way vocabulary (2026-09-26): WhiteList = approve at
# lifetime access, GreyList = approve at the quarter marker (the grey
# badge's internal expires_at semantics, unchanged). Legacy approve/deny
# values keep working for older links and tests.
_TRIO_EXPIRY = {"whitelist": "lifetime", "greylist": "quarter"}


def register_decision_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path
    jinja = ctx.jinja

    @application.post("/owner/{token}/decision")
    async def owner_decision(request: Request, token: str):
        form = await request.form()
        grant_id = form.get("grant_id", "")
        decision = form.get("decision", "")
        expiry = form.get("expiry", "90")
        return_to = form.get("return_to", "")

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

            if decision in _TRIO_EXPIRY:
                expiry = _TRIO_EXPIRY[decision]
                decision = "approve"
            elif decision == "blacklist":
                # The badge machinery IS the blacklist entry point (ruling:
                # set_badge_state is the single state-cycle API) — ALWAYS
                # SILENT, like every badge move. A pending grant lands
                # revoked (== blacklisted, one state): the requester joins
                # the contact list under the round black badge and any
                # re-request is quarantined with an indistinguishable
                # success page.
                updated = whitelist_db.set_badge_state(conn, grant_id, "blocked")
                if updated is None:
                    return HTMLResponse("Grant not found", status_code=404)
                if return_to == "list":
                    return RedirectResponse(url=f"/owner/{token}", status_code=303)
                grant = whitelist_db.get_grant(conn, grant_id)
                profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
                return HTMLResponse(jinja.get_template("admin_decision.html").render(
                    request=request, grant=grant, profile=profile, decision="revoke"))

            outcome = _decision_outcome(conn, jinja, request, grant_id,
                                        decision, expiry)
            if return_to == "list" and outcome.status_code == 200:
                return RedirectResponse(url=f"/owner/{token}", status_code=303)
            return outcome
        finally:
            conn.close()

    # Context routes (/categorize, /context) REMOVED per Jason ruling
    # 2026-09-12 — feature cut from the product. DB layer untouched; if it's
    # ever revived it's app-layer work only (git history has the code).

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
        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            # Security audit 2026-09-25: these three quarter routes used to
            # skip _verify_grant_ownership — any authenticated owner could
            # punt / make permanent / revoke ANY grant in the DB (cross-owner
            # IDOR). They now enforce the same ownership rule as /decision.
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id):
                return HTMLResponse("Not found", status_code=404)
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

            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id):
                return HTMLResponse("Not found", status_code=404)
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

            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id):
                return HTMLResponse("Not found", status_code=404)
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
