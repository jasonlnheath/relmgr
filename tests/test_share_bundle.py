"""Share bundle redesign (captain ruling 2026-09-20 + inbox additions 001/002).

Pins:
- SHARE FLOW: chooser (multi-select own cards) → Next → ONE bundle link +
  one QR encoding the chosen set; live 'what they'll see' preview before Next.
- SHARED VIEW (/s/{bundle_id}): chosen cards only, one combined card grouped
  per card, reach-me actions INSIDE their blocks, no forward section,
  Connect available; visibility tiers exactly like the public profile.
- NATIVE SHARE: owner page carries the exact message text and a
  navigator.share call with a copy-link fallback (API unavailable).
- VCF DOWNLOAD: /s/{id}/card.vcf from exactly the viewer-visible fields.
- SHELF LIFE: links expire exactly one week after creation; expired links
  ping the owner once for strangers, never for blacklisted openers; a
  connected viewer's governed view outlives the link; re-share renews.
- BADGE-GOVERNED ACCESS: contact-list badges click-to-change
  (WhiteList/GreyList/BlackList), instant and ALWAYS SILENT.
- BLACKLIST SILENCE, BOTH DIRECTIONS: blacklisted senders see the normal
  success page but their request is quarantined — no grant row, no
  notification, no badge count.
- NOTIFICATION KIND HEAL: legacy notifications tables gain 'expired_link'
  row-preservingly.
"""
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient

from app import create_app, _build_vcard

_ISO_Z = "%Y-%m-%dT%H:%M:%SZ"


def _make_db(tmp_path: Path) -> Path:
    """Owner profile with cards: Work (public+granted email), Contact
    (public+granted phone); bio; a second owner with one card."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jheath@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "555-1234", "visibility": "granted"}],
    })
    whitelist_db.seed_default_cards(conn)

    # Public email on the Work card, public phone on the Contact card —
    # KEEPING the seeded granted fields (cards are lenses over the same
    # fields; set_card_fields replaces, so extend the existing set).
    def _field_ids(card_id):
        return [r["id"] for r in conn.execute(
            "SELECT pf.id FROM card_fields cf "
            "JOIN profile_fields pf ON cf.field_id = pf.id "
            "WHERE cf.card_id = ?", (card_id,)).fetchall()]

    pub_email = whitelist_db.add_profile_field(
        conn, 1, "email", "public@waltheremc.com", "public")
    pub_phone = whitelist_db.add_profile_field(
        conn, 1, "phone", "555-0000", "public")
    work = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Work'"
    ).fetchone()
    contact = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Contact'"
    ).fetchone()
    whitelist_db.set_card_fields(
        conn, work["id"], _field_ids(work["id"]) + [pub_email["id"]])
    whitelist_db.set_card_fields(
        conn, contact["id"], _field_ids(contact["id"]) + [pub_phone["id"]])

    whitelist_db.update_bio(conn, 1, "I sell wheel bushings.")

    # Second owner (foreign-card tests).
    whitelist_db.seed_profile(conn, {
        "handle": "otherowner",
        "name": {"display": "Other Owner"},
        "emails": [{"address": "other@example.com", "visibility": "public"}],
    })
    whitelist_db.seed_default_cards(conn)
    conn.commit()
    conn.close()
    return db


def _owner_token(profile_id: int = 1) -> str:
    return wl_tokens.make_token(
        b"test-secret", "owner_dashboard", str(profile_id), expires_days=365)


def _card_id(db: Path, name: str, owner: int = 1) -> int:
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = ? AND name = ?",
        (owner, name)).fetchone()
    conn.close()
    return row["id"]


def _bundle_ids_from_redirect(resp) -> str:
    loc = resp.headers["location"]
    return loc.rsplit("/", 1)[-1]


def _create_bundle(client, token, card_ids) -> str:
    """POST the chooser and return the new bundle id (no redirect follow)."""
    resp = client.post(f"/owner/{token}/share",
                       data={"card_ids": [str(c) for c in card_ids]},
                       follow_redirects=False)
    assert resp.status_code == 303, resp.text
    return _bundle_ids_from_redirect(resp)


def _expire_bundle(db: Path, bundle_id: str) -> None:
    conn = whitelist_db.wl_connect(db)
    conn.execute("UPDATE share_bundles SET expires_at = ? WHERE id = ?",
                 ("2020-01-01T00:00:00Z", bundle_id))
    conn.commit()
    conn.close()


def _notification_kinds(db: Path) -> list:
    conn = whitelist_db.wl_connect(db)
    rows = conn.execute("SELECT kind FROM notifications").fetchall()
    conn.close()
    return [r["kind"] for r in rows]


# ============================================================
# Chooser flow
# ============================================================

class TestChooserFlow:
    def test_chooser_renders_on_my_profile(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        token = _owner_token()
        html = client.get(f"/owner/{token}/profile").text
        assert 'id="share-chooser"' in html
        assert f'action="/owner/{token}/share"' in html
        assert f"fetch('/owner/{token}/share/preview'" in html
        assert 'name="card_ids"' in html
        assert "Next" in html
        assert 'id="share-preview"' in html, "live preview panel present"

    def test_share_creates_bundle_and_redirects(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        work, contact = _card_id(db, "Work"), _card_id(db, "Contact")
        bundle_id = _create_bundle(client, _owner_token(), [work, contact])
        conn = whitelist_db.wl_connect(db)
        row = conn.execute(
            "SELECT * FROM share_bundles WHERE id = ?", (bundle_id,)).fetchone()
        conn.close()
        import json
        assert json.loads(row["card_ids"]) == [work, contact]
        # Shelf life: exactly one week out.
        expires = datetime.strptime(row["expires_at"], _ISO_Z).replace(
            tzinfo=timezone.utc)
        delta = expires - datetime.now(timezone.utc)
        assert timedelta(days=7) - timedelta(minutes=5) < delta < timedelta(days=7) + timedelta(minutes=5)

    def test_share_requires_at_least_one_card(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/share", data={})
        assert resp.status_code == 400
        assert "at least one card" in resp.text

    def test_share_rejects_foreign_cards(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        foreign = _card_id(db, "Work", owner=2)
        resp = client.post(f"/owner/{_owner_token()}/share",
                           data={"card_ids": [str(foreign)]})
        assert resp.status_code == 400

    def test_preview_fragment_public_only(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        work = _card_id(db, "Work")
        resp = client.post(f"/owner/{_owner_token()}/share/preview",
                           data={"card_ids": [str(work)]})
        assert resp.status_code == 200
        assert "public@waltheremc.com" in resp.text
        assert "jheath@waltheremc.com" not in resp.text, \
            "preview is what an anonymous recipient sees"
        assert "Work" in resp.text

    def test_preview_ignores_foreign_cards(self, tmp_path):
        """Fix-pass F1 LEAK PIN: the preview filters card_ids to the
        owner's own cards exactly like the create route. The previous
        pin was vacuous — it checked the display name, which never
        renders in the fragment, while the foreign card's public field
        content DID leak into the HTML."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        foreign = _card_id(db, "Work", owner=2)
        resp = client.post(f"/owner/{_owner_token()}/share/preview",
                           data={"card_ids": [str(foreign)]})
        assert resp.status_code == 200
        assert "other@example.com" not in resp.text, \
            "foreign card field content must never render in the preview"
        assert ">Work</h3>" not in resp.text, \
            "a foreign card must not render a group block at all"
        assert "Nothing shared yet." in resp.text, \
            "foreign-only selection drops to an empty fragment"

    def test_preview_mixed_ids_keeps_own_drops_foreign(self, tmp_path):
        """Fix-pass F1: filtering keeps the owner's own cards; only the
        foreign ids are dropped (not the whole fragment)."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        own = _card_id(db, "Contact")
        foreign = _card_id(db, "Work", owner=2)
        resp = client.post(f"/owner/{_owner_token()}/share/preview",
                           data={"card_ids": [str(own), str(foreign)]})
        assert resp.status_code == 200
        assert "555-0000" in resp.text, "own card still previews"
        assert "other@example.com" not in resp.text, \
            "foreign card dropped from a mixed selection"


# ============================================================
# Owner share page: single QR + single link + native share
# ============================================================

class TestOwnerSharePage:
    def test_share_page_qr_link_and_native_share(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        work = _card_id(db, "Work")
        bundle_id = _create_bundle(client, _owner_token(), [work])
        resp = client.get(f"/owner/{_owner_token()}/share/{bundle_id}")
        assert resp.status_code == 200
        assert f"/qr/share/{bundle_id}" in resp.text
        assert f"/s/{bundle_id}" in resp.text
        # Exact native-share message, and the fallback pair.
        assert "Jason Heath wants to share their WhiteList card:" in resp.text
        assert "navigator.share" in resp.text
        assert "copyShareLink" in resp.text

    def test_bundle_qr_serves_png(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        work = _card_id(db, "Work")
        bundle_id = _create_bundle(client, _owner_token(), [work])
        resp = client.get(f"/qr/share/{bundle_id}")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/png"

    def test_share_page_foreign_bundle_404(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        work = _card_id(db, "Work")
        bundle_id = _create_bundle(client, _owner_token(), [work])
        resp = client.get(f"/owner/{_owner_token(2)}/share/{bundle_id}")
        assert resp.status_code == 404


# ============================================================
# Shared view: chosen cards, tiers, grouped actions, no forward
# ============================================================

class TestSharedView:
    def _bundle(self, tmp_path, names=("Work", "Contact")):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        bundle_id = _create_bundle(
            client, _owner_token(), [_card_id(db, n) for n in names])
        return db, client, bundle_id

    def test_renders_chosen_cards_only(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        html = client.get(f"/s/{bundle_id}").text
        assert "Work" in html and "Contact" in html
        assert "Identity" not in html, "unchosen cards must not render"
        assert "Location" not in html
        assert "Details" not in html

    def test_respects_visibility_anonymous(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        html = client.get(f"/s/{bundle_id}").text
        assert "public@waltheremc.com" in html
        assert "555-0000" in html
        assert "jheath@waltheremc.com" not in html, "granted email hidden"
        assert "555-1234" not in html, "granted phone hidden"
        assert "🔒" not in html

    def test_respects_visibility_granted(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        # A connected viewer sees granted fields exactly like /p does.
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "friend@example.com", "Friend")
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime",
                                    merge_contacts=False)
        conn.close()
        html = client.get(f"/s/{bundle_id}?e=friend@example.com").text
        assert "jheath@waltheremc.com" in html
        assert "555-1234" in html

    def test_actions_live_inside_their_blocks(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        html = client.get(f"/s/{bundle_id}").text
        # No single confusing "Reach me" row anymore.
        assert "Reach me" not in html
        # Grouped: Work heading, then its email icon, then Contact, its icons.
        i_work = html.index(">Work</h3>")
        i_mail = html.index('href="mailto:')
        i_contact = html.index(">Contact</h3>")
        i_tel = html.index('href="tel:')
        assert i_work < i_mail < i_contact < i_tel, \
            "each card's action icons must sit inside its own block"

    def test_each_group_header_carries_its_card_photo(self, tmp_path):
        """Fix-pass F2 (captain ruling): EVERY chosen card's picture is
        rendered at its own group header — photo when the card has one,
        initials circle otherwise (page-avatar pattern)."""
        db, client, bundle_id = self._bundle(tmp_path)
        work, contact = _card_id(db, "Work"), _card_id(db, "Contact")
        conn = whitelist_db.wl_connect(db)
        whitelist_db.update_card_photo(conn, work, f"1_{work}.jpg")
        whitelist_db.update_card_photo(conn, contact, f"1_{contact}.jpg")
        conn.close()
        html = client.get(f"/s/{bundle_id}").text
        assert f'/photos/1/{work}' in html, "Work header must carry its photo"
        assert f'/photos/1/{contact}' in html, \
            "Contact header must carry its photo — not just the first card"
        # Each photo sits in its own block: card img above card heading.
        i_work_img = html.index(f'/photos/1/{work}')
        i_contact_img = html.index(f'/photos/1/{contact}')
        assert i_work_img < html.index(">Work</h3>")
        assert i_contact_img < html.index(">Contact</h3>")

    def test_photoless_cards_show_initials_not_foreign_photos(self, tmp_path):
        """The page-avatar pattern stays: no photo_path → initials circle,
        never a broken or borrowed image."""
        db, client, bundle_id = self._bundle(tmp_path)
        html = client.get(f"/s/{bundle_id}").text
        assert "/photos/" not in html
        assert ">WO<" in html and ">CO<" in html, \
            "each header falls back to its own initials circle"

    def test_no_forward_section(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        html = client.get(f"/s/{bundle_id}?e=jheath@waltheremc.com").text
        assert "Forward your card" not in html
        assert "/forward" not in html

    def test_connect_button_available(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        html = client.get(f"/s/{bundle_id}").text
        assert "/p/jasonheath/request-form" in html

    def test_save_to_contacts_link(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        html = client.get(f"/s/{bundle_id}").text
        assert "Save to contacts" in html
        assert f"/s/{bundle_id}/card.vcf" in html

    def test_unknown_bundle_404(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        assert client.get("/s/nope").status_code == 404

    def test_view_records_scan(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        client.get(f"/s/{bundle_id}")
        conn = whitelist_db.wl_connect(db)
        n = conn.execute(
            "SELECT COUNT(*) FROM scan_events WHERE profile_id = 1").fetchone()[0]
        conn.close()
        assert n == 1

    def test_link_stable_while_fields_update(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        before = client.get(f"/s/{bundle_id}").text
        assert "public@waltheremc.com" in before
        # Owner edits the field value; same link, fresh content.
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "UPDATE profile_fields SET field_value = 'newpublic@waltheremc.com' "
            "WHERE field_value = 'public@waltheremc.com'")
        conn.commit()
        conn.close()
        after = client.get(f"/s/{bundle_id}").text
        assert "newpublic@waltheremc.com" in after


# ============================================================
# VCF download — exactly the viewer-visible fields
# ============================================================

class TestVcfDownload:
    def _bundle(self, tmp_path, names=("Work", "Contact")):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        bundle_id = _create_bundle(
            client, _owner_token(), [_card_id(db, n) for n in names])
        return db, client, bundle_id

    def test_vcf_anon_public_only(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        resp = client.get(f"/s/{bundle_id}/card.vcf")
        assert resp.status_code == 200
        assert "text/vcard" in resp.headers["content-type"]
        body = resp.text
        assert "BEGIN:VCARD" in body and "END:VCARD" in body
        assert "FN:Jason Heath" in body
        assert "public@waltheremc.com" in body
        assert "jheath@waltheremc.com" not in body
        assert "555-1234" not in body
        assert 'TEL;TYPE=CELL:555-0000' in body

    def test_vcf_granted_viewer_gets_granted_fields(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "friend@example.com", "Friend")
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime",
                                    merge_contacts=False)
        conn.close()
        body = client.get(f"/s/{bundle_id}/card.vcf?e=friend@example.com").text
        assert "jheath@waltheremc.com" in body
        assert "555-1234" in body

    def test_vcf_dedupes_fields_shared_by_cards(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        # Attach the public email to BOTH chosen cards → one EMAIL line.
        conn = whitelist_db.wl_connect(db)
        pub = conn.execute(
            "SELECT id FROM profile_fields WHERE field_value = 'public@waltheremc.com'"
        ).fetchone()
        contact = conn.execute(
            "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Contact'"
        ).fetchone()
        whitelist_db.set_card_fields(conn, contact["id"], [pub["id"]])
        conn.close()
        body = client.get(f"/s/{bundle_id}/card.vcf").text
        assert body.count("EMAIL;TYPE=INTERNET:") == 1

    def test_vcf_escapes_vcard_specials(self):
        profile = {"display_name": "Heath; Jason, Jr", "handle": "x",
                   "title": None, "company": None}
        cards = [{"visible_fields": [
            {"id": 1, "field_type": "note", "field_value": "a,b;c\nd"}]}]
        body = _build_vcard(profile, cards)
        assert "N:Jason\\, Jr;Heath\\;;;;" in body
        assert "NOTE:a\\,b\\;c\\nd" in body

    def test_vcf_expired_for_stranger_404(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        _expire_bundle(db, bundle_id)
        assert client.get(f"/s/{bundle_id}/card.vcf").status_code == 404


# ============================================================
# Shelf life — one week, expiry behavior, re-share
# ============================================================

class TestShelfLife:
    def _bundle(self, tmp_path, names=("Work", "Contact")):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        bundle_id = _create_bundle(
            client, _owner_token(), [_card_id(db, n) for n in names])
        return db, client, bundle_id

    def test_expired_link_pings_owner_for_stranger(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        _expire_bundle(db, bundle_id)
        resp = client.get(f"/s/{bundle_id}")
        assert resp.status_code == 200
        assert "expired" in resp.text.lower()
        assert "/p/jasonheath/request-form" in resp.text, "Connect path offered"
        kinds = _notification_kinds(db)
        assert kinds.count("expired_link") == 1
        # Second hit: the ping dedupes — one row per bundle.
        client.get(f"/s/{bundle_id}")
        assert _notification_kinds(db).count("expired_link") == 1

    def test_expired_link_connected_viewer_outlives_it(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "friend@example.com", "Friend")
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime",
                                    merge_contacts=False)
        conn.close()
        _expire_bundle(db, bundle_id)
        html = client.get(f"/s/{bundle_id}?e=friend@example.com").text
        assert "jheath@waltheremc.com" in html, "governed view outlives link"
        assert _notification_kinds(db) == [], "no ping for connected viewers"

    def test_expired_link_blacklisted_no_ping(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "enemy@example.com", "Enemy")
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime",
                                    merge_contacts=False)
        whitelist_db.revoke_grant(conn, gid)
        conn.close()
        _expire_bundle(db, bundle_id)
        resp = client.get(f"/s/{bundle_id}?e=enemy@example.com")
        assert resp.status_code == 200
        assert "expired" in resp.text.lower()
        assert _notification_kinds(db) == [], "owner never pinged by blocked"

    def test_reshare_renews_same_link(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        _expire_bundle(db, bundle_id)
        assert client.get(f"/s/{bundle_id}").text.count("expired") >= 1
        resp = client.post(f"/owner/{_owner_token()}/share/{bundle_id}/reshare",
                           follow_redirects=False)
        assert resp.status_code == 303
        conn = whitelist_db.wl_connect(db)
        row = conn.execute(
            "SELECT expires_at FROM share_bundles WHERE id = ?",
            (bundle_id,)).fetchone()
        conn.close()
        expires = datetime.strptime(row["expires_at"], _ISO_Z).replace(
            tzinfo=timezone.utc)
        assert expires > datetime.now(timezone.utc) + timedelta(days=6)
        html = client.get(f"/s/{bundle_id}").text
        assert "public@waltheremc.com" in html, "link works again"

    def test_reshare_foreign_bundle_404(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        resp = client.post(f"/owner/{_owner_token(2)}/share/{bundle_id}/reshare")
        assert resp.status_code == 404

    def test_owner_share_page_flags_expiry_with_reshare(self, tmp_path):
        db, client, bundle_id = self._bundle(tmp_path)
        _expire_bundle(db, bundle_id)
        html = client.get(f"/owner/{_owner_token()}/share/{bundle_id}").text
        assert "expired" in html.lower()
        assert f"/owner/{_owner_token()}/share/{bundle_id}/reshare" in html


# ============================================================
# Badge-governed access — instant, silent
# ============================================================

class TestBadgeGovernedAccess:
    def _granted(self, tmp_path, email="friend@example.com"):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, email, "Friend")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter",
                                    merge_contacts=False)
        conn.close()
        return db, client, gid

    def test_badge_whitelist_makes_permanent(self, tmp_path):
        db, client, gid = self._granted(tmp_path)
        resp = client.post(f"/owner/{_owner_token()}/badge",
                           data={"grant_id": gid, "state": "whitelist"},
                           follow_redirects=False)
        assert resp.status_code == 303
        conn = whitelist_db.wl_connect(db)
        g = whitelist_db.get_grant(conn, gid)
        conn.close()
        assert g["status"] == "granted"
        assert g["expires_at"] is None

    def test_badge_greylist_sets_quarter_expiry(self, tmp_path):
        db, client, gid = self._granted(tmp_path)
        client.post(f"/owner/{_owner_token()}/badge",
                    data={"grant_id": gid, "state": "greylist"})
        conn = whitelist_db.wl_connect(db)
        g = whitelist_db.get_grant(conn, gid)
        conn.close()
        assert g["status"] == "granted"
        assert g["expires_at"] == whitelist_db.quarter_end_iso()

    def test_badge_blocked_severs_access_and_governs_bundle(self, tmp_path):
        db, client, gid = self._granted(tmp_path)
        client.post(f"/owner/{_owner_token()}/badge",
                    data={"grant_id": gid, "state": "blocked"})
        conn = whitelist_db.wl_connect(db)
        g = whitelist_db.get_grant(conn, gid)
        conn.close()
        assert g["status"] == "revoked"
        # Blocked badge = the access governor: viewer drops to anon tier.
        work, contact = _card_id(db, "Work"), _card_id(db, "Contact")
        bundle_id = _create_bundle(client, _owner_token(), [work, contact])
        html = client.get(f"/s/{bundle_id}?e=friend@example.com").text
        assert "jheath@waltheremc.com" not in html
        assert "public@waltheremc.com" in html

    def test_badge_blocked_then_whitelist_revives(self, tmp_path):
        db, client, gid = self._granted(tmp_path)
        client.post(f"/owner/{_owner_token()}/badge",
                    data={"grant_id": gid, "state": "blocked"})
        client.post(f"/owner/{_owner_token()}/badge",
                    data={"grant_id": gid, "state": "whitelist"})
        conn = whitelist_db.wl_connect(db)
        g = whitelist_db.get_grant(conn, gid)
        conn.close()
        assert g["status"] == "granted" and g["expires_at"] is None

    def test_badge_changes_are_always_silent(self, tmp_path):
        db, client, gid = self._granted(tmp_path)
        conn = whitelist_db.wl_connect(db)
        before = conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0]
        conn.close()
        for state in ("blocked", "whitelist", "greylist"):
            client.post(f"/owner/{_owner_token()}/badge",
                        data={"grant_id": gid, "state": state})
        assert _notification_kinds(db) == [], "no notification ever, any move"
        conn = whitelist_db.wl_connect(db)
        after = conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0]
        conn.close()
        assert after == before == 0

    def test_badge_route_guards(self, tmp_path):
        db, client, gid = self._granted(tmp_path)
        resp = client.post(f"/owner/{_owner_token()}/badge",
                           data={"grant_id": gid, "state": "golden"})
        assert resp.status_code == 400
        resp = client.post(f"/owner/{_owner_token()}/badge",
                           data={"grant_id": "nope", "state": "whitelist"})
        assert resp.status_code == 404

    def test_contact_list_badges_are_click_to_change(self, tmp_path):
        db, client, gid = self._granted(tmp_path)
        token = _owner_token()
        html = client.get(f"/owner/{token}").text
        assert f'action="/owner/{token}/badge"' in html
        assert 'name="state"' in html
        # _granted creates a quarterly grant → greylist badge, next=BlackList
        assert 'data-state="greylist"' in html and "Click to change to BlackList" in html


# ============================================================
# Blacklist silence — both directions
# ============================================================

class TestBlacklistSilence:
    def _blacklisted(self, tmp_path, email="enemy@example.com"):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, email, "Enemy")
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime",
                                    merge_contacts=False)
        whitelist_db.revoke_grant(conn, gid)
        conn.close()
        return db, client, email

    def test_blacklisted_request_quarantined_silently(self, tmp_path):
        db, client, email = self._blacklisted(tmp_path)
        resp = client.post("/p/jasonheath/request",
                           data={"name": "Enemy", "email": email})
        # Sender sees the NORMAL confirmation — indistinguishable.
        assert resp.status_code == 200
        assert "Request Sent" in resp.text
        assert "Grant ID:" in resp.text
        conn = whitelist_db.wl_connect(db)
        q = conn.execute("SELECT * FROM quarantined_requests").fetchall()
        grants = conn.execute(
            "SELECT * FROM access_grants WHERE requester_email = ?",
            (email,)).fetchall()
        conn.close()
        assert len(q) == 1 and q[0]["email"] == email
        assert all(g["status"] != "pending" for g in grants), \
            "no fresh pending grant row"
        assert _notification_kinds(db) == [], "no notification, no badge count"

    def test_blacklisted_request_no_email_push(self, tmp_path):
        db, client, email = self._blacklisted(tmp_path)
        client.post("/p/jasonheath/request",
                    data={"name": "Enemy", "email": email})
        # The success page's background task is None — nothing queued.
        # (No notification row exists to drive any digest/mail either.)
        assert _notification_kinds(db) == []

    def test_quarantined_grant_id_is_full_uuid4(self, tmp_path):
        """Fix-pass F3: the display-only Grant ID must be a full uuid4
        string so the success page is byte-shape indistinguishable from
        a real grant (os.urandom(6).hex() had the wrong shape)."""
        db, client, email = self._blacklisted(tmp_path)
        resp = client.post("/p/jasonheath/request",
                           data={"name": "Enemy", "email": email})
        m = re.search(r"Grant ID:\s*([0-9a-fA-F-]+)", resp.text)
        assert m, "success page shows a Grant ID"
        display_id = m.group(1).strip()
        assert len(display_id) == 36, display_id
        parsed = uuid.UUID(display_id)
        assert parsed.version == 4
        assert str(parsed) == display_id, "canonical uuid4 rendering"

    def test_quarantine_dedupes_per_email_per_day(self, tmp_path):
        """Fix-pass F4: repeat quarantined requests from the same
        blacklisted email on the same day collapse to one row."""
        db, client, email = self._blacklisted(tmp_path)
        for _ in range(3):
            resp = client.post("/p/jasonheath/request",
                               data={"name": "Enemy", "email": email})
            assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        rows = conn.execute(
            "SELECT * FROM quarantined_requests WHERE LOWER(email) = LOWER(?)",
            (email,)).fetchall()
        conn.close()
        assert len(rows) == 1, "one quarantined row per email per day"

    def test_quarantine_dedupe_is_scoped_per_profile(self, tmp_path):
        """Same email blacklisted by two owners: each owner's quarantine
        keeps its own (single) row."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        for pid in (1, 2):
            gid = whitelist_db.create_grant(conn, pid, "dup@example.com", "D")
            whitelist_db.apply_decision(conn, gid, "approve", "lifetime",
                                        merge_contacts=False)
            whitelist_db.revoke_grant(conn, gid)
        conn.close()
        client.post("/p/jasonheath/request",
                    data={"name": "D", "email": "dup@example.com"})
        client.post("/p/otherowner/request",
                    data={"name": "D", "email": "dup@example.com"})
        conn = whitelist_db.wl_connect(db)
        rows = conn.execute(
            "SELECT profile_id FROM quarantined_requests "
            "WHERE LOWER(email) = LOWER('dup@example.com')").fetchall()
        conn.close()
        assert sorted(r["profile_id"] for r in rows) == [1, 2]

    def test_normal_request_still_notifies(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post("/p/jasonheath/request",
                           data={"name": "New Person", "email": "new@example.com"})
        assert resp.status_code == 200
        assert _notification_kinds(db) == ["connection_request"]
        conn = whitelist_db.wl_connect(db)
        pending = conn.execute(
            "SELECT COUNT(*) FROM access_grants WHERE status = 'pending'"
        ).fetchone()[0]
        conn.close()
        assert pending == 1


# ============================================================
# Notification kind heal + profile page redesign pins
# ============================================================

class TestNotificationKindHeal:
    def test_legacy_notifications_table_heals_row_preserving(self, tmp_path):
        db = tmp_path / "heal.db"
        conn = whitelist_db.wl_connect(db)
        whitelist_db.wl_init(conn)
        whitelist_db.seed_profile(conn, {
            "handle": "healowner",
            "name": {"display": "Heal Owner"},
        })
        conn.commit()
        # Force a legacy pre-'expired_link' table with one existing row.
        conn.executescript("""
            DROP TABLE notifications;
            CREATE TABLE notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK(kind IN ('connection_request', 'forward', 'quarterly')),
                title TEXT NOT NULL,
                body TEXT,
                link TEXT,
                grant_id TEXT,
                dedupe_key TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                read_at TEXT
            );
            INSERT INTO notifications (owner_profile_id, kind, title)
                VALUES (1, 'quarterly', 'old row');
        """)
        conn.commit()
        whitelist_db.ensure_notification_kinds(conn)
        # Old row survives; new vocabulary inserts cleanly; dedupe survives.
        rows = conn.execute("SELECT kind FROM notifications").fetchall()
        assert [r["kind"] for r in rows] == ["quarterly"]
        nid = whitelist_db.create_notification(
            conn, 1, "expired_link", "ping", dedupe_key="expired_link:b1")
        assert nid is not None
        assert whitelist_db.create_notification(
            conn, 1, "expired_link", "ping", dedupe_key="expired_link:b1") is None
        conn.close()


class TestProfilePageRedesign:
    def test_card_bar_opens_preview_edit_kept(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        # No separate Preview link anymore...
        assert ">Preview</a>" not in html
        # ...the card bar itself opens the preview...
        assert "/profile/card/" in html
        assert "onclick=\"window.location='/owner/" in html
        # ...and Edit stays, without triggering the bar's onclick.
        assert "/cards/" in html and "event.stopPropagation()" in html

    def test_no_standalone_qr_panel_on_my_profile(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        assert 'id="qr-panel"' not in html, "share flow moved to chooser → bundle"
