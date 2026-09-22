"""Card editor round 2 (2026-09-20 captain walkthrough) + dashboard cleanup.

Pins:
- Dashboard shows ONLY the owner's own cards, each with a clear Edit action
- Editor renders the FULL round-2 field set: preferred-channel phone slots
  (Text number / FaceTime number), video/messaging/social app sections with
  "+ Add …" affordances, and the structured address block
- Save round-trips ALL fields + visibility (public/granted/private)
- Photo upload via the client-side cropper (photo_data) stores the cropped
  result at the display size (512×512 square JPEG)
- Zoom slider starts at 1.0× (fit) and tracks proportionally — no jump
- All dropdowns keep the dark glass background (wl-select) — no white-on-white
- Delete-card action with a confirm step; per-user isolation; fields survive
- Legacy single-line 'address' rows migrate to 'address1'
- Cross-owner editor access → 404 (ruling 2A)
- Friendly 400s: duplicate field value, duplicate card name, junk visibility
"""
import base64
import io
import os
import re
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from PIL import Image
from app import create_app


# Round-2 field vocabulary — pinned explicitly (re-pinned, not loosened).
FIELD_TYPES = (
    "email", "phone", "text_number", "facetime_number",
    "facetime", "skype", "video_app",
    "messenger", "messaging_app",
    "facebook", "instagram", "social_other",
    "title", "company", "address1", "address2", "city", "state", "zip",
    "website", "birthday", "note",
)

# Legacy 'address' must no longer be creatable — the address block replaced it.
RETIRED_TYPES = ("address",)


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "555-1234", "visibility": "granted"}],
    })
    whitelist_db.seed_default_cards(conn)
    conn.close()
    return db


def _owner_token(payload="1"):
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", payload,
                                expires_days=365)


def _first_card_id(db, owner_id=1):
    conn = whitelist_db.wl_connect(db)
    cid = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = ? ORDER BY id LIMIT 1",
        (owner_id,),
    ).fetchone()[0]
    conn.close()
    return cid


# ============================================================
# Dashboard: only the owner's own cards, each with Edit
# ============================================================

class TestDashboardOwnsOnlyItsCards:
    def _two_owner_db(self, tmp_path: Path) -> Path:
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('otherco','Other Co')"
        )
        whitelist_db.create_card(conn, 2, "Intruder Card", [])
        conn.commit()
        conn.close()
        return db

    def test_dashboard_lists_only_owned_cards(self, tmp_path):
        db = self._two_owner_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        # Own cards render…
        for own in ("Work", "Contact", "Identity"):
            assert own in html, f"own card '{own}' missing from dashboard"
        # …and nobody else's card ever does (ruling 2A made visible).
        assert "Intruder Card" not in html, "another owner's card leaked onto the dashboard"

    def test_every_own_card_has_an_edit_action(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        edit_links = re.findall(r'href="/owner/[^"]+/cards/(\d+)/edit"', html)
        assert edit_links, "no Edit action on any card"
        conn = whitelist_db.wl_connect(db)
        owned = {r[0] for r in conn.execute(
            "SELECT id FROM cards WHERE owner_profile_id = 1").fetchall()}
        conn.close()
        assert set(int(x) for x in edit_links) == owned, \
            "Edit actions must cover exactly the owner's own cards"


# ============================================================
# Editor renders every round-2 field type, grouped in sections
# ============================================================

class TestEditorRendersAllFieldTypes:
    def test_all_types_present_for_seeded_card(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        card_id = _first_card_id(db)
        resp = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit")
        assert resp.status_code == 200
        for t in FIELD_TYPES:
            assert f'data-type="{t}"' in resp.text, \
                f"editor section for '{t}' missing"
        for t in RETIRED_TYPES:
            assert f'data-type="{t}"' not in resp.text, \
                f"retired type '{t}' still has its own editor section"
        # Both name inputs (card + profile display name) render too.
        assert 'name="card_name"' in resp.text
        assert 'name="display_name"' in resp.text

    def test_preferred_channel_slots_are_labeled_not_checkboxes(self, tmp_path):
        """The captain's ask: dedicated, clearly-labeled Text number and
        FaceTime number slots — never mystery checkboxes next to phones."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        card_id = _first_card_id(db)
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        # Section heading + per-row channel labels…
        assert "Phone numbers" in html
        assert "Text number" in html
        assert "FaceTime number" in html
        # …dedicated always-visible slots for both…
        assert 'name="new_text_number_value"' in html
        assert 'name="new_facetime_number_value"' in html
        # …and each field row carries an immediate ✕ delete button
        # (UX pass 2026-09-22: the old remove-checkbox pile-up is gone —
        # the ✕ POSTs the field's delete right away).
        assert ">✕</button>" in html, \
            "each field row must carry an immediate ✕ delete button"
        assert "\u2705" not in html and "> \u2715" not in html, \
            "bare mystery ✕ checkbox must be gone"

    def test_app_sections_with_add_affordances(self, tmp_path):
        """Video apps / Messaging apps / Socials sections show their named
        slots first, then a '+ Add …' affordance covering all others."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        card_id = _first_card_id(db)
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        # Named slots + section headings.
        for heading in ("Video apps", "Messaging apps", "Social", "Address"):
            assert heading in html, f"section '{heading}' missing"
        for slot in ("facetime", "skype", "messenger", "facebook", "instagram"):
            assert f'name="new_{slot}_value"' in html, f"named slot '{slot}' missing"
        # + Add affordances (generic types cover all other apps/platforms).
        for add in ("+ Add video app", "+ Add messaging app", "+ Add social",
                    "+ Add phone", "+ Add email"):
            assert add in html, f"'{add}' affordance missing"
        # The structured address block replaces the single line.
        for label in ("Address 1", "Address 2", "City", "State/Province",
                      "Zip/Postal Code"):
            assert label in html, f"address row '{label}' missing"

    def test_existing_values_render_with_visibility(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        card_id = conn.execute(
            "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Work'"
        ).fetchone()[0]
        conn.close()
        resp = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        assert 'value="jason@waltheremc.com"' in resp
        m = re.search(r'name="field_(\d+)_visibility"', resp)
        assert m, "visibility control missing on an existing field row"

    def test_private_tier_offered(self, tmp_path):
        """The editor exposes the full tier model: public/granted/private."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        card_id = _first_card_id(db)
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        for tier in ("public", "granted", "private"):
            assert f'value="{tier}"' in html, f"tier '{tier}' not offered"

    def test_editor_unknown_card_404(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}/cards/999999/edit")
        assert resp.status_code == 404


# ============================================================
# Save round-trips all fields + visibility
# ============================================================

class TestEditorSaveRoundTrip:
    def test_one_field_per_type_round_trips(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)

        data = {"card_name": "Work", "display_name": "Jason Heath"}
        expectations = {
            "email": ("work@acme.com", "public"),
            "phone": ("+1-555-999-0000", "granted"),
            "text_number": ("+1-555-999-0001", "public"),
            "facetime_number": ("+1-555-999-0002", "granted"),
            "facetime": ("jason@acme.com", "granted"),
            "skype": ("live:.cid.jason", "private"),
            "video_app": ("Zoom 555-123-4567", "granted"),
            "messenger": ("m.me/jasonh", "public"),
            "messaging_app": ("WhatsApp +1-555-999-0003", "granted"),
            "facebook": ("facebook.com/jason.heath", "public"),
            "instagram": ("@jasonheath", "public"),
            "social_other": ("YouTube @heathtech", "public"),
            "title": ("VP Engineering", "granted"),
            "company": ("Acme Inc.", "private"),
            "address1": ("123 Main St", "public"),
            "address2": ("Suite 400", "public"),
            "city": ("Denver", "public"),
            "state": ("CO", "public"),
            "zip": ("80014", "public"),
            "website": ("https://acme.com", "granted"),
            "birthday": ("1985-06-15", "private"),
            "note": ("Met at the conference.", "private"),
        }
        for t, (value, vis) in expectations.items():
            data[f"new_{t}_value"] = value
            data[f"new_{t}_visibility"] = vis

        resp = client.post(f"/owner/{tok}/cards/{card_id}/edit", data=data)
        assert resp.status_code == 200

        # DB: every field exists with the right value AND visibility,
        # linked to the card.
        conn = whitelist_db.wl_connect(db)
        rows = {
            r["field_type"]: (r["field_value"], r["visibility"])
            for r in conn.execute(
                "SELECT pf.* FROM card_fields cf JOIN profile_fields pf"
                " ON cf.field_id = pf.id WHERE cf.card_id = ?",
                (card_id,),
            ).fetchall()
        }
        conn.close()
        for t, (value, vis) in expectations.items():
            assert rows[t] == (value, vis), \
                f"{t}: expected {(value, vis)}, got {rows.get(t)}"

        # Re-render: the editor shows the saved values back.
        html = client.get(f"/owner/{tok}/cards/{card_id}/edit").text
        for t, (value, _) in expectations.items():
            assert value in html, f"{t} value not shown after save"

    def test_visibility_change_on_existing_field(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        conn = whitelist_db.wl_connect(db)
        fid = conn.execute(
            "SELECT pf.id FROM card_fields cf JOIN profile_fields pf"
            " ON cf.field_id = pf.id WHERE cf.card_id = ? AND pf.field_type='email'",
            (card_id,),
        ).fetchone()[0]
        conn.close()
        client.post(f"/owner/{tok}/cards/{card_id}/edit",
                    data={f"field_{fid}_value": "jason@waltheremc.com",
                          f"field_{fid}_visibility": "private"})
        conn = whitelist_db.wl_connect(db)
        vis = conn.execute(
            "SELECT visibility FROM profile_fields WHERE id = ?", (fid,)
        ).fetchone()[0]
        conn.close()
        assert vis == "private", "visibility change did not stick"

    def test_second_phone_added(self, tmp_path):
        """Repeatable types accept multiple rows in one save."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        resp = client.post(f"/owner/{tok}/cards/{card_id}/edit", data={
            "new_phone_value": ["+1-555-111-1111", "+1-555-222-2222"],
            "new_phone_visibility": ["public", "private"],
        })
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        phones = {r["field_value"]: r["visibility"] for r in conn.execute(
            "SELECT pf.field_value, pf.visibility FROM card_fields cf"
            " JOIN profile_fields pf ON cf.field_id = pf.id"
            " WHERE cf.card_id = ? AND pf.field_type = 'phone'",
            (card_id,),
        ).fetchall()}
        conn.close()
        assert phones == {"+1-555-111-1111": "public",
                          "+1-555-222-2222": "private"}

    def test_remove_field_unlinks_from_card(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        conn = whitelist_db.wl_connect(db)
        fid = conn.execute(
            "SELECT pf.id FROM card_fields cf JOIN profile_fields pf"
            " ON cf.field_id = pf.id WHERE cf.card_id = ?",
            (card_id,),
        ).fetchone()[0]
        conn.close()
        resp = client.post(f"/owner/{tok}/cards/{card_id}/edit",
                           data={f"field_{fid}_remove": "1"})
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        on_card = conn.execute(
            "SELECT 1 FROM card_fields WHERE card_id = ? AND field_id = ?",
            (card_id, fid),
        ).fetchone()
        still_exists = conn.execute(
            "SELECT 1 FROM profile_fields WHERE id = ?", (fid,)
        ).fetchone()
        conn.close()
        assert on_card is None, "remove did not unlink from the card"
        assert still_exists is not None, "unlink must not destroy the field row"

    def test_display_name_round_trips(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        client.post(f"/owner/{tok}/cards/{card_id}/edit",
                    data={"display_name": "Jason K. Heath"})
        conn = whitelist_db.wl_connect(db)
        name = conn.execute(
            "SELECT display_name FROM profiles WHERE id = 1").fetchone()[0]
        conn.close()
        assert name == "Jason K. Heath"

    def test_card_rename_round_trips(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        resp = client.post(f"/owner/{tok}/cards/{card_id}/edit",
                           data={"card_name": "Renamed"})
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        name = conn.execute(
            "SELECT name FROM cards WHERE id = ?", (card_id,)).fetchone()[0]
        conn.close()
        assert name == "Renamed"


# ============================================================
# Save validation → friendly 400s
# ============================================================

class TestEditorSaveValidation:
    def test_duplicate_value_400(self, tmp_path):
        """Renaming a field's value onto another existing value of the same
        type collides with UNIQUE(profile_id, field_type, field_value)."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        # Card 1 (Work) already carries jason@waltheremc.com; give it a
        # second email, then rename it onto the first.
        client.post(f"/owner/{tok}/cards/{card_id}/edit",
                    data={"new_email_value": "second@acme.com",
                          "new_email_visibility": "public"})
        conn = whitelist_db.wl_connect(db)
        second = conn.execute(
            "SELECT id FROM profile_fields WHERE field_value = 'second@acme.com'"
        ).fetchone()[0]
        conn.close()
        resp = client.post(f"/owner/{tok}/cards/{card_id}/edit",
                           data={f"field_{second}_value": "jason@waltheremc.com",
                                 f"field_{second}_visibility": "public"})
        assert resp.status_code == 400
        assert "already" in resp.text

    def test_duplicate_card_name_400(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        # Card 1 is 'Work'; renaming it onto the existing 'Contact' clashes.
        resp = client.post(f"/owner/{tok}/cards/1/edit",
                           data={"card_name": "Contact"})
        assert resp.status_code == 400
        assert "already exists" in resp.text

    def test_junk_visibility_400(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        resp = client.post(f"/owner/{tok}/cards/{card_id}/edit",
                           data={"new_email_value": "x@x.com",
                                 "new_email_visibility": "world"})
        assert resp.status_code == 400

    def test_junk_type_ignored_or_400_never_500(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        resp = client.post(f"/owner/{tok}/cards/{card_id}/edit",
                           data={"new_hacker_value": "x"})
        assert resp.status_code == 200  # unknown new_ types are ignored


# ============================================================
# Cross-owner: the editor is IDOR-hard (ruling 2A)
# ============================================================

class TestEditorCrossOwner:
    def _two_owner_db(self, tmp_path: Path) -> tuple[Path, int]:
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('otherco','Other Co')"
        )
        intruder = whitelist_db.create_card(conn, 2, "Intruder", [])
        conn.commit()
        conn.close()
        return db, intruder["id"]

    def test_get_foreign_card_404(self, tmp_path):
        db, intruder_card = self._two_owner_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token('1')}/cards/{intruder_card}/edit")
        assert resp.status_code == 404

    def test_post_foreign_card_404_no_write(self, tmp_path):
        db, intruder_card = self._two_owner_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token('1')}/cards/{intruder_card}/edit",
                           data={"display_name": "Hax", "new_note_value": "x"})
        assert resp.status_code == 404
        conn = whitelist_db.wl_connect(db)
        name = conn.execute(
            "SELECT display_name FROM profiles WHERE id = 2").fetchone()[0]
        conn.close()
        assert name == "Other Co", "cross-owner write went through"

    def test_foreign_field_id_in_update_400(self, tmp_path):
        """A crafted field_{id} update naming ANOTHER profile's field fails
        closed (400) instead of editing it."""
        db, _ = self._two_owner_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        foreign_fid = conn.execute(
            "SELECT id FROM profile_fields WHERE profile_id = 2 LIMIT 1"
        ).fetchone()
        if foreign_fid is None:
            conn.execute(
                "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)"
                " VALUES (2, 'note', 'foreign', 'public')"
            )
            conn.commit()
            foreign_fid = conn.execute(
                "SELECT id FROM profile_fields WHERE profile_id = 2 LIMIT 1"
            ).fetchone()
        fid = foreign_fid[0]
        conn.close()
        card_id = _first_card_id(db)
        resp = client.post(f"/owner/{_owner_token('1')}/cards/{card_id}/edit",
                           data={f"field_{fid}_value": "owned now",
                                 f"field_{fid}_visibility": "public"})
        assert resp.status_code == 400
        conn = whitelist_db.wl_connect(db)
        val = conn.execute(
            "SELECT field_value FROM profile_fields WHERE id = ?", (fid,)
        ).fetchone()[0]
        conn.close()
        assert val == "foreign", "cross-owner field edit went through"


# ============================================================
# Photo: the cropped result is what gets stored
# ============================================================

class TestEditorPhotoUpload:
    @staticmethod
    def _jpeg_data_url(width=640, height=400, color="red") -> str:
        img = Image.new("RGB", (width, height), color=color)
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        return "data:image/jpeg;base64," + b64

    def test_cropped_result_stored_at_display_size(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)

        resp = client.post(f"/owner/{tok}/cards/{card_id}/photo",
                           data={"photo_data": self._jpeg_data_url()})
        assert resp.status_code == 200

        upload = Path(__file__).resolve().parent.parent / "uploads" / f"1_{card_id}.jpg"
        assert upload.exists(), "cropped photo never hit disk"
        try:
            stored = Image.open(upload)
            assert stored.format == "JPEG"
            assert stored.size == (512, 512), \
                f"display size must be 512×512, got {stored.size}"
        finally:
            upload.unlink()

        conn = whitelist_db.wl_connect(db)
        photo_path = conn.execute(
            "SELECT photo_path FROM cards WHERE id = ?", (card_id,)
        ).fetchone()[0]
        conn.close()
        assert photo_path == f"1_{card_id}.jpg"

    def test_cropped_png_accepted(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)

        img = Image.new("RGB", (300, 300), color="blue")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode()
        resp = client.post(f"/owner/{tok}/cards/{card_id}/photo",
                           data={"photo_data": "data:image/png;base64," + b64})
        assert resp.status_code == 200
        upload = Path(__file__).resolve().parent.parent / "uploads" / f"1_{card_id}.jpg"
        assert upload.exists()
        upload.unlink()

    def test_junk_photo_data_400(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        resp = client.post(f"/owner/{tok}/cards/{card_id}/photo",
                           data={"photo_data": "data:image/jpeg;base64,not-base64!!"})
        assert resp.status_code == 400

    def test_raw_file_fallback_still_works(self, tmp_path):
        """No-JS path: a raw file upload still lands (existing contract)."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)

        img = Image.new("RGB", (100, 100), color="green")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        buf.seek(0)
        resp = client.post(f"/owner/{tok}/cards/{card_id}/photo",
                           files={"photo": ("x.jpg", buf, "image/jpeg")})
        assert resp.status_code == 200
        upload = Path(__file__).resolve().parent.parent / "uploads" / f"1_{card_id}.jpg"
        assert upload.exists()
        upload.unlink()

    def test_non_image_photo_data_400(self, tmp_path):
        """Valid base64, but not a real JPEG/PNG — the magic-byte check
        rejects it before anything touches disk."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        b64 = base64.b64encode(b"\xff\xd8\xff\xe0 definitely not an image").decode()
        resp = client.post(f"/owner/{tok}/cards/{card_id}/photo",
                           data={"photo_data": "data:image/jpeg;base64," + b64})
        assert resp.status_code == 400
        upload = Path(__file__).resolve().parent.parent / "uploads" / f"1_{card_id}.jpg"
        assert not upload.exists(), "junk image data must never reach disk"

    def test_editor_renders_photo_after_upload(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        client.post(f"/owner/{tok}/cards/{card_id}/photo",
                    data={"photo_data": self._jpeg_data_url()})
        html = client.get(f"/owner/{tok}/cards/{card_id}/edit").text
        assert f"/photos/1/{card_id}" in html, "editor does not show the stored photo"
        upload = Path(__file__).resolve().parent.parent / "uploads" / f"1_{card_id}.jpg"
        if upload.exists():
            upload.unlink()


# ============================================================
# Zoom slider: starts at 1.0× (fit), tracks proportionally
# ============================================================

class TestZoomSlider:
    def test_slider_starts_at_fit_and_tracks_proportionally(self, tmp_path):
        """Round-2 bug: the instant the slider was touched, zoom jumped to
        ~4× because pixel scale was slider/100 (natural size). The slider is
        now a fit-relative multiplier (100 = 1.0× fit, 400 = 4× fit) and
        pixel scale derives from minZoom × multiplier."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        card_id = _first_card_id(db)
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        assert 'id="crop-zoom" min="100" max="400" value="100"' in html, \
            "slider must be a 100–400 multiplier starting at 1.0×"
        assert 'id="crop-zoom-val"' in html and "1.0\u00d7" in html, \
            "a live multiplier readout must start at 1.0×"
        assert "zoom = minZoom * mult" in html, \
            "pixel scale must be fit × multiplier (proportional tracking)"
        assert "zoomInput.value = '100'" in html, \
            "loading an image must reset the slider to the fit multiplier"
        assert "zoom = parseInt(zoomInput.value, 10) / 100;" not in html, \
            "the old natural-size jump must be gone"


# ============================================================
# Dropdowns: dark glass everywhere (bio dropdown was white-on-white)
# ============================================================

class TestDarkGlassDropdowns:
    def test_every_editor_select_keeps_dark_glass(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        card_id = _first_card_id(db)
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        selects = re.findall(r"<select\s[^>]*>", html)
        assert selects, "editor should render visibility dropdowns"
        for tag in selects:
            assert "wl-select" in tag, f"dropdown missing dark glass class: {tag}"
            assert "bg-transparent" not in tag, \
                f"transparent select renders white-on-white: {tag}"
        # The shared dark-glass CSS ships on the page (base.html).
        assert ".wl-select {" in html
        assert "color-scheme: dark" in html

    def test_bio_visibility_dropdown_dark_glass(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        m = re.search(r'<select name="bio_visibility"[^>]*>', html)
        assert m, "bio visibility dropdown missing"
        assert "wl-select" in m.group(0), \
            "bio visibility dropdown must keep the dark glass background"
        assert "bg-transparent" not in m.group(0)


# ============================================================
# Delete card: confirm step, isolation, fields survive
# ============================================================

class TestDeleteCard:
    def test_editor_offers_delete_with_confirm_step(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        card_id = _first_card_id(db)
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        assert f"/cards/{card_id}/delete" in html, "no delete action in the editor"
        assert "Yes, delete card" in html, "confirm step missing"
        assert "Keep card" in html, "confirm cancel missing"
        # UX pass (2026-09-22, captain ruling): the confirm copy states the
        # deletion semantics — holders keep the vCard (badge gone, becomes
        # a normal vCard) — and that the fields stay on the profile.
        assert "fields" in html and "stay on your profile" in html, \
            "confirm copy must say what happens to the data"
        assert "normal vCard" in html, \
            "confirm copy must say holders keep the vCard"

    def test_delete_removes_card_but_keeps_profile_fields(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        conn = whitelist_db.wl_connect(db)
        fields_before = conn.execute(
            "SELECT COUNT(*) FROM profile_fields WHERE profile_id = 1"
        ).fetchone()[0]
        on_card_before = conn.execute(
            "SELECT COUNT(*) FROM card_fields WHERE card_id = ?", (card_id,)
        ).fetchone()[0]
        conn.close()
        assert on_card_before > 0, "seeded card should carry fields"

        resp = client.post(f"/owner/{tok}/cards/{card_id}/delete",
                           follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == f"/owner/{tok}/profile"

        conn = whitelist_db.wl_connect(db)
        card_left = conn.execute(
            "SELECT 1 FROM cards WHERE id = ?", (card_id,)).fetchone()
        links_left = conn.execute(
            "SELECT COUNT(*) FROM card_fields WHERE card_id = ?", (card_id,)
        ).fetchone()[0]
        fields_after = conn.execute(
            "SELECT COUNT(*) FROM profile_fields WHERE profile_id = 1"
        ).fetchone()[0]
        conn.close()
        assert card_left is None, "card row survived the delete"
        assert links_left == 0, "card_fields links survived the delete"
        assert fields_after == fields_before, \
            "deleting a card must never destroy profile field data"

    def test_delete_cascades_grant_card_links(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        conn = whitelist_db.wl_connect(db)
        grant_id = whitelist_db.create_grant(
            conn, 1, "friend@example.com", "Friend")
        whitelist_db.set_grant_cards(conn, grant_id, [card_id])
        conn.close()
        client.post(f"/owner/{tok}/cards/{card_id}/delete")
        conn = whitelist_db.wl_connect(db)
        links = conn.execute(
            "SELECT COUNT(*) FROM grant_cards WHERE card_id = ?", (card_id,)
        ).fetchone()[0]
        conn.close()
        assert links == 0, "dangling grant_cards link after card delete"

    def test_foreign_card_delete_404_and_survives(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('otherco','Other Co')"
        )
        intruder = whitelist_db.create_card(conn, 2, "Intruder", [])
        conn.commit()
        conn.close()
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token('1')}/cards/{intruder['id']}/delete")
        assert resp.status_code == 404, "cross-owner delete must fail closed"
        conn = whitelist_db.wl_connect(db)
        still = conn.execute(
            "SELECT 1 FROM cards WHERE id = ?", (intruder["id"],)).fetchone()
        conn.close()
        assert still is not None, "foreign card was deleted"

    def test_delete_removes_photo_file(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = _first_card_id(db)
        client.post(f"/owner/{tok}/cards/{card_id}/photo",
                    data={"photo_data": TestEditorPhotoUpload._jpeg_data_url()})
        upload = Path(__file__).resolve().parent.parent / "uploads" / f"1_{card_id}.jpg"
        assert upload.exists(), "photo never landed before delete test"
        client.post(f"/owner/{tok}/cards/{card_id}/delete")
        assert not upload.exists(), "orphaned photo file after card delete"


# ============================================================
# Legacy single-line 'address' → structured address block
# ============================================================

class TestLegacyAddressMigration:
    @staticmethod
    def _v2_db(tmp_path: Path) -> Path:
        """A v2-era DB: profile_fields with the OLD 8-type CHECK (created
        before wl_init so wl_init's CREATE IF NOT EXISTS skips it)."""
        db = tmp_path / "v2.db"
        conn = whitelist_db.wl_connect(db)
        conn.execute("""
            CREATE TABLE profile_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                field_type TEXT NOT NULL CHECK(field_type IN
                    ('email','phone','title','company','address','website','birthday','note')),
                field_value TEXT NOT NULL,
                visibility TEXT NOT NULL CHECK(visibility IN ('public','granted','private')),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(profile_id, field_type, field_value),
                FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
            )
        """)
        whitelist_db.wl_init(conn)
        whitelist_db.ensure_cards_schema(conn)
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('legacy','Legacy Co')"
        )
        conn.execute(
            "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)"
            " VALUES (1, 'address', '123 Old Rd, Denver, CO 80014', 'granted')"
        )
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name) VALUES (1, 'Location')"
        )
        conn.execute("INSERT INTO card_fields (card_id, field_id) VALUES (1, 1)")
        conn.commit()
        conn.close()
        return db

    def test_address_row_migrates_to_address1(self, tmp_path):
        db = self._v2_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        row = conn.execute(
            "SELECT field_type, field_value, visibility FROM profile_fields WHERE id = 1"
        ).fetchone()
        link = conn.execute(
            "SELECT COUNT(*) FROM card_fields WHERE card_id = 1 AND field_id = 1"
        ).fetchone()[0]
        conn.close()
        assert row["field_type"] == "address1", "legacy address row not migrated"
        assert row["field_value"] == "123 Old Rd, Denver, CO 80014"
        assert row["visibility"] == "granted"
        assert link == 1, "card link lost in migration"

    def test_migrated_address_edits_in_address_section(self, tmp_path):
        db = self._v2_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/cards/1/edit").text
        assert 'value="123 Old Rd, Denver, CO 80014"' in html, \
            "migrated value missing from the editor"
        assert 'data-type="address1"' in html, \
            "migrated field must live in the address1 slot"
