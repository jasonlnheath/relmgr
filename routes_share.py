"""Share-bundle routes: the /s/{bundle_id} recipient page and its vCard.

Split out of app.py (2026-09-26 refactor); behavior is unchanged.
"""

from fastapi import Request, Query
from fastapi.responses import HTMLResponse, Response

import whitelist_db
import wl_tokens

from web_support import (
    WebContext,
    _build_vcard,
    _get_secret,
    days_since,
    is_verified_stale,
)


def register_share_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path
    jinja = ctx.jinja

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
