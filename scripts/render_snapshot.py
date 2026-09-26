#!/usr/bin/env python3
"""Render-page snapshot harness (refactor tool, 2026-09-26).

Boots the app against a seeded throwaway DB and dumps the rendered HTML
of every key page, with volatile values (capability tokens, timestamps,
asset versions) normalized away. Used to prove a template refactor keeps
every page byte-identical:

    WHITELIST_SECRET=snapshot-secret python scripts/render_snapshot.py OUT_DIR
    diff -r snap_before snap_after

Not part of the app itself; safe to run anywhere (never touches
contacts.db — it always passes an explicit tmp DB path).
"""

import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


def seed(db_path: Path) -> dict:
    """Build a small world covering every template's interesting branches:
    owner with Personal+Work cards (fields across all three visibilities,
    labels, address block), white/grey/black contacts, a pending request,
    and a share bundle."""
    conn = whitelist_db.wl_connect(db_path)
    try:
        whitelist_db.ensure_whitelist_schema(conn)
        whitelist_db.seed_profile(conn, {
            "handle": "snapowner",
            "name": {"display": "Snap Owner"},
            "org": {"company": "WhiteList Co", "title": "Captain"},
            "emails": [{"address": "owner@snap.test",
                        "visibility": "public"}],
            "phones": [{"number": "+15551234567",
                        "visibility": "granted"}],
            "website": "https://snap.test",
            "bio": "Snapshot bio text.",
        })
        owner = whitelist_db.get_profile(conn, "snapowner")
        oid = owner["id"]
        # seed_profile landed after boot's heal pass — re-run the card
        # seeder so Personal/Work exist for the new profile.
        whitelist_db.seed_default_cards(conn)
        cards = whitelist_db.list_cards(conn, oid)
        personal = next(c for c in cards if c["name"] == "Personal")
        work = next(c for c in cards if c["name"] == "Work")

        whitelist_db.update_bio(conn, oid, "Snapshot bio text.")

        # Personal card: address block + personal history + a private note
        # (new_fields create AND link; field_updates only edit existing rows).
        whitelist_db.save_card_editor(
            conn, personal["id"],
            field_updates=[], field_labels={}, field_removals=[],
            new_fields=[
                ("address1", "1 Main St", "granted", ""),
                ("city", "Snapville", "public", ""),
                ("state", "CA", "public", ""),
                ("phone", "+15559876543", "granted", "home"),
                ("note", "A private note", "private", ""),
                ("high_school", "Snap High", "public", ""),
            ])

        # Work card: public title/company.
        whitelist_db.save_card_editor(
            conn, work["id"],
            field_updates=[], field_labels={}, field_removals=[],
            new_fields=[("department", "Deck", "granted", "")])

        # White / grey / black contacts + one pending request (amber box).
        white_id = whitelist_db.create_grant(conn, oid, "white@snap.test",
                                             "Wendy White", oid)
        whitelist_db.update_grant_status(conn, white_id, "granted")
        grey_id = whitelist_db.create_grant(conn, oid, "grey@snap.test",
                                            "Gary Grey", oid)
        whitelist_db.update_grant_status(conn, grey_id, "granted")
        whitelist_db.set_badge_state(conn, grey_id, "greylist")
        blacklist_id = whitelist_db.create_grant(conn, oid, "black@snap.test",
                                                 "Bob Black", oid)
        whitelist_db.update_grant_status(conn, blacklist_id, "granted")
        whitelist_db.set_badge_state(conn, blacklist_id, "blocked")
        pending_id = whitelist_db.create_grant(conn, oid, "pend@snap.test",
                                               "Pat Pending", oid)
        whitelist_db.create_notification(
            conn, oid, "connection_request",
            title="Connection request from Pat Pending",
            grant_id=pending_id, dedupe_key=f"grant:{pending_id}")

        bundle = whitelist_db.create_share_bundle(
            conn, oid, [c["id"] for c in cards])
        return {"oid": oid, "grey_id": grey_id, "bundle_id": bundle["id"],
                "personal_id": personal["id"], "work_id": work["id"]}
    finally:
        conn.close()


def normalize(html: str) -> str:
    """Erase volatile values so two renders of the same page diff clean."""
    html = re.sub(r"v=[0-9a-f]{6,}", "v=X", html)               # asset_v
    html = re.sub(r"/owner/[A-Za-z0-9_.-]{10,}", "/owner/{T}", html)
    html = re.sub(r"[?&](t|ot|e)=[A-Za-z0-9._%+-]+", r"?\1={T}", html)
    html = re.sub(r"/a/[A-Za-z0-9_.-]{10,}", "/a/{T}", html)
    html = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?", "{DATE}", html)
    html = re.sub(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?", "{DATE}", html)
    html = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "{DATE}", html)
    html = re.sub(r"/s/[A-Za-z0-9_-]{8,}", "/s/{B}", html)
    html = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                  "{G}", html)
    return html


def main(out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "snap.db"
        world = seed(db)
        client = TestClient(create_app(db))

        secret = os.environ["WHITELIST_SECRET"].encode()
        token = wl_tokens.make_token(secret, "owner_dashboard",
                                     str(world["oid"]))
        review_token = wl_tokens.make_token(secret, "grant_review",
                                            world["grey_id"])

        pages = {
            "signin": "/signin",
            "signup": "/signup",
            "forgot": "/forgot-password",
            "public_anon": "/p/snapowner",
            "public_granted": "/p/snapowner?e=white@snap.test",
            "request_form": "/p/snapowner/request-form",
            "share_view": f"/s/{world['bundle_id']}",
            "admin_review": f"/a/{review_token}",
            "dashboard": f"/owner/{token}",
            "dashboard_filtered": f"/owner/{token}?f=greylist&letter=G",
            "junk": f"/owner/{token}/junk",
            "new_connection": f"/owner/{token}/new-connection?q=snap",
            "my_profile": f"/owner/{token}/profile",
            "editor_personal": f"/owner/{token}/cards/{world['personal_id']}/edit",
            "editor_work": f"/owner/{token}/cards/{world['work_id']}/edit",
            "card_preview": f"/owner/{token}/profile/card/{world['personal_id']}",
            "contact_grey": f"/owner/{token}/contact/{world['grey_id']}",
        }
        for name, path in pages.items():
            r = client.get(path, follow_redirects=False)
            (out / f"{name}.html").write_text(normalize(r.text))
            print(f"{r.status_code} {name} <- {path.split('?')[0]}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "snap_out")
