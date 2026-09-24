"""UX pass 5c (2026-09-24): address blocks + preview fixes + picker rebuild.

Package C of parallel pass 5:
1. Address BLOCKS on vCard + Personal editors: one '+ Add address'
   control appends a complete grouped block (address1, address2, city,
   state, zip, country); fields group by block, never by line. Work
   keeps its flat per-component Address section.
2. Card PREVIEW fixes: right-justified field names that never overlap
   values, and consistency with the profile view (bio + reach badges).
3. Add-field picker: PURGE the pass-4 scoped variants (email_personal,
   phone_work, …) from every picker; add the six-field Google-parity set
   from data/whitelist-field-gap-analysis/report.md §6, context-filtered:
   vCard all six, Personal personal-appropriate, Work professional.
"""
import os
import re
import sys
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["WHITELIST_SECRET"] = "test-secret"  # same convention as the other suites

import whitelist_db as w  # noqa: E402
import wl_tokens  # noqa: E402
from app import _build_vcard, create_app  # noqa: E402

SECRET = b"test-secret"

BLOCK_TYPES = ("address1", "address2", "city", "state", "zip", "country")
PASS5_TYPES = ("department", "po_box", "related_person", "event",
               "custom_field", "name_prefix", "name_suffix")


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = w.wl_connect(db)
    w.ensure_whitelist_schema(conn)
    w.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "5551234567", "visibility": "granted"}],
    })
    w.ensure_whitelist_schema(conn)
    conn.commit()
    conn.close()
    return db


def _owner_token():
    return wl_tokens.make_token(SECRET, "owner_dashboard", "1", expires_days=365)


def _card_id(db, name):
    conn = w.wl_connect(db)
    cid = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = 1 AND lower(name) = ?",
        (name.lower(),)).fetchone()[0]
    conn.close()
    return cid


def _editor_gets(db, client, name):
    resp = client.get(f"/owner/{_owner_token()}/cards/{_card_id(db, name)}/edit")
    assert resp.status_code == 200
    return resp.text


def _set_bio(db, bio):
    conn = w.wl_connect(db)
    conn.execute("UPDATE profiles SET bio = ? WHERE id = 1", (bio,))
    conn.commit()
    conn.close()


# ============================================================
# 1. Picker purge + context filtering (six-field addition)
# ============================================================

class TestPickerRebuild:
    def test_purged_scoped_types_absent_from_all_editors(self, tmp_path):
        """The pass-4 Google-Contacts scoped additions are GONE from every
        picker — email/phone/etc. already exist as base fields."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        for name in ("Personal", "Work"):
            html = _editor_gets(db, client, name)
            for t in ("email_personal", "email_work", "phone_personal",
                      "phone_work", "address1_personal", "country_work",
                      "facebook_personal", "instagram_work"):
                assert f'value="{t}"' not in html, \
                    f"purged scoped type '{t}' still offered on {name}"

    def test_vcard_picker_gets_all_six(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = w.wl_connect(db)
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name, scope) VALUES (1, 'Backup', 'vcard')")
        conn.commit()
        vid = conn.execute(
            "SELECT id FROM cards WHERE name = 'Backup'").fetchone()[0]
        conn.close()
        html = client.get(f"/owner/{_owner_token()}/cards/{vid}/edit").text
        for t in PASS5_TYPES:
            assert f'value="{t}"' in html, f"vcard picker missing '{t}'"

    def test_personal_picker_personal_appropriate(self, tmp_path):
        """Personal: po_box, related_person, event — NOT department,
        custom_field, name prefix/suffix (those are vCard/Work per the
        gap-analysis report's template tags)."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = _editor_gets(db, client, "Personal")
        for t in ("po_box", "related_person", "event"):
            assert f'value="{t}"' in html, f"personal picker missing '{t}'"
        for t in ("department", "custom_field", "name_prefix", "name_suffix"):
            assert f'value="{t}"' not in html, \
                f"'{t}' should not be offered on Personal"

    def test_work_picker_professional_appropriate(self, tmp_path):
        """Work: department + po_box — NOT relation/event/prefix/suffix."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = _editor_gets(db, client, "Work")
        for t in ("department", "po_box"):
            assert f'value="{t}"' in html, f"work picker missing '{t}'"
        for t in ("related_person", "event", "name_prefix", "name_suffix",
                  "custom_field"):
            assert f'value="{t}"' not in html, \
                f"'{t}' should not be offered on Work"

    def test_picker_sections_helper_filters_blocks(self, tmp_path):
        """On block scopes the six components leave the picker (they are
        added via '+ Add address'); po_box stays. Work keeps them all."""
        assert [t for t, _ in w.picker_sections("vcard")[5][1]] == ["po_box"]
        assert [t for t, _ in w.picker_sections("personal")[5][1]] == ["po_box"]
        work_addr = [t for t, _ in w.picker_sections("work")[5][1]]
        assert "address1" in work_addr and "po_box" in work_addr


# ============================================================
# 2. Address blocks (vCard + Personal; Work unchanged)
# ============================================================

class TestAddressBlocks:
    def test_personal_editor_renders_blocks(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = _editor_gets(db, client, "Personal")
        assert 'data-address-blocks' in html
        assert 'onclick="addAddressBlock()"' in html
        assert '+ Add address' in html
        assert 'template data-newblock' in html or '<template data-newblock' in html
        # One component input per block position, six per block
        assert 'name="new_address1_value"' in html
        assert 'name="new_country_value"' in html
        # po_box standalone (NOT inside the block template count of six)
        assert 'data-type="po_box"' in html

    def test_vcard_editor_renders_blocks(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = w.wl_connect(db)
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name, scope) VALUES (1, 'Backup', 'vcard')")
        conn.commit()
        vid = conn.execute(
            "SELECT id FROM cards WHERE name = 'Backup'").fetchone()[0]
        conn.close()
        html = client.get(f"/owner/{_owner_token()}/cards/{vid}/edit").text
        assert 'data-address-blocks' in html
        assert 'onclick="addAddressBlock()"' in html

    def test_work_keeps_flat_address_section(self, tmp_path):
        """Work template unchanged: per-component rows, NO block control."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = _editor_gets(db, client, "Work")
        # The JS helper appears in every editor's script block; the block
        # CONTAINER and its button must not render on work.
        assert '<div data-address-blocks' not in html
        assert 'data-type="address1"' in html

    def test_save_complete_block(self, tmp_path):
        """Posting one block's six inputs creates all six fields, and the
        re-render groups them as one block."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        form = {
            "card_name": "Personal", "display_name": "",
            "first_name": "Jason", "last_name": "Heath", "suffix": "",
            "new_address1_value": "123 Main St",
            "new_address2_value": "Apt 4",
            "new_city_value": "Springfield",
            "new_state_value": "IL",
            "new_zip_value": "62704",
            "new_country_value": "USA",
        }
        resp = client.post(f"/owner/{_owner_token()}/cards/{_card_id(db, 'Personal')}/edit",
                           data=form)
        assert resp.status_code == 200
        conn = w.wl_connect(db)
        saved = dict(conn.execute(
            "SELECT field_type, field_value FROM profile_fields "
            "WHERE profile_id = 1 AND field_type = 'address1'").fetchone())
        conn.close()
        assert saved["field_value"] == "123 Main St"
        html = resp.text
        assert 'value="123 Main St"' in html
        assert 'value="Springfield"' in html
        assert 'data-address-blocks' in html

    def test_existing_fields_render_inside_blocks(self, tmp_path):
        """Legacy flat address rows (pre-pass-5) render grouped in the
        block section — one block per positional set."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = w.wl_connect(db)
        pid = _card_id(db, "Personal")
        for t, v in (("address1", "10 Oak Ave"), ("city", "Portland"),
                     ("state", "OR")):
            cur = conn.execute(
                "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)"
                " VALUES (1, ?, ?, 'granted')", (t, v))
            conn.execute(
                "INSERT INTO card_fields (card_id, field_id) VALUES (?, ?)",
                (pid, cur.lastrowid))
        conn.commit()
        conn.close()
        html = _editor_gets(db, client, "Personal")
        assert 'value="10 Oak Ave"' in html
        assert 'value="Portland"' in html
        # All inside the block container: the block markup precedes the
        # po_box standalone row
        assert html.index('data-address-blocks') < html.index('value="10 Oak Ave"')

    def test_empty_values_are_not_saved(self, tmp_path):
        """Empty add-row slots stay non-content (unchanged save contract)."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        form = {
            "card_name": "Personal", "display_name": "",
            "first_name": "Jason", "last_name": "Heath", "suffix": "",
            "new_address1_value": "123 Main St",
            "new_city_value": "",
        }
        client.post(f"/owner/{_owner_token()}/cards/{_card_id(db, 'Personal')}/edit",
                    data=form)
        conn = w.wl_connect(db)
        n = conn.execute(
            "SELECT COUNT(*) c FROM profile_fields WHERE profile_id = 1 "
            "AND field_type IN ('address1','city') AND field_value = ''").fetchone()["c"]
        conn.close()
        assert n == 0


# ============================================================
# 3. Schema heal: pass-4 DB gains the pass-5 CHECK
# ============================================================

class TestPass5SchemaHeal:
    def _old_db(self, tmp_path):
        db = tmp_path / "old.db"
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        old_types = tuple(t for t in w.CARD_EDITOR_FIELD_TYPES
                          if t not in PASS5_TYPES)
        conn.executescript(f"""
            CREATE TABLE profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                handle TEXT UNIQUE, display_name TEXT);
            CREATE TABLE profile_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                field_type TEXT NOT NULL CHECK(field_type IN {old_types!r}),
                field_value TEXT NOT NULL,
                visibility TEXT NOT NULL CHECK(visibility IN ('public','granted','private')),
                label TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(profile_id, field_type, field_value)
            );
            INSERT INTO profiles (handle, display_name) VALUES ('j', 'Jason');
            INSERT INTO profile_fields (profile_id, field_type, field_value, visibility, label)
                VALUES (1, 'phone', '5551234567', 'private', 'mobile');
        """)
        conn.commit()
        conn.close()
        return db

    def test_heal_preserves_rows_and_admits_new_types(self, tmp_path):
        db = self._old_db(tmp_path)
        conn = w.wl_connect(db)
        w.ensure_whitelist_schema(conn)
        rows = [tuple(r) for r in conn.execute(
            "SELECT id, field_type, field_value, visibility, label "
            "FROM profile_fields ORDER BY id").fetchall()]
        assert rows == [(1, 'phone', '5551234567', 'private', 'mobile')]
        for t in PASS5_TYPES:
            conn.execute(
                "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)"
                " VALUES (1, ?, 'x', 'granted')", (t,))
        conn.commit()
        conn.close()

    def test_heal_is_idempotent(self, tmp_path):
        db = self._old_db(tmp_path)
        conn = w.wl_connect(db)
        w.ensure_whitelist_schema(conn)
        w.ensure_whitelist_schema(conn)  # second run: no error, no dup swap
        n = conn.execute("SELECT COUNT(*) c FROM profile_fields").fetchone()["c"]
        assert n == 1
        conn.close()


# ============================================================
# 4. Visibility defaults for the six additions
# ============================================================

class TestPass5VisibilityDefaults:
    def test_custom_field_defaults_private_others_granted(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = w.wl_connect(db)
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name, scope) VALUES (1, 'Backup', 'vcard')")
        conn.commit()
        vid = conn.execute(
            "SELECT id FROM cards WHERE name = 'Backup'").fetchone()[0]
        conn.close()
        form = {
            "card_name": "Backup", "display_name": "",
            "first_name": "Jason", "last_name": "Heath", "suffix": "",
            "new_custom_field_value": "secret-handle",
            "new_custom_field_label": "chat",
            "new_department_value": "Operations",
            "new_event_value": "2020-06-13",
            "new_related_person_value": "Tessa Test",
            "new_po_box_value": "PO Box 7",
            "new_name_prefix_value": "Mr",
        }
        resp = client.post(f"/owner/{_owner_token()}/cards/{vid}/edit", data=form)
        assert resp.status_code == 200
        conn = w.wl_connect(db)
        vis = {r["field_type"]: r["visibility"] for r in conn.execute(
            "SELECT field_type, visibility FROM profile_fields WHERE profile_id = 1 "
            f"AND field_type IN {PASS5_TYPES!r}").fetchall()}
        conn.close()
        assert vis["custom_field"] == "private"
        for t in ("department", "event", "related_person", "po_box", "name_prefix"):
            assert vis[t] == "granted", f"{t} should default granted"

    def test_labels_persist(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = w.wl_connect(db)
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name, scope) VALUES (1, 'Backup', 'vcard')")
        conn.commit()
        vid = conn.execute(
            "SELECT id FROM cards WHERE name = 'Backup'").fetchone()[0]
        conn.close()
        form = {
            "card_name": "Backup", "display_name": "",
            "first_name": "Jason", "last_name": "Heath", "suffix": "",
            "new_event_value": "2020-06-13",
            "new_event_label": "anniversary",
            "new_related_person_value": "Tessa Test",
            "new_related_person_label": "Assistant",
        }
        client.post(f"/owner/{_owner_token()}/cards/{vid}/edit", data=form)
        conn = w.wl_connect(db)
        labels = {r["field_type"]: r["label"] for r in conn.execute(
            "SELECT field_type, label FROM profile_fields WHERE profile_id = 1 "
            "AND field_type IN ('event','related_person')").fetchall()}
        conn.close()
        assert labels["event"] == "anniversary"
        assert labels["related_person"] == "Assistant"


# ============================================================
# 5. Card preview: right-justified labels, bio, badges
# ============================================================

class TestCardPreview:
    def _preview(self, client, tok, card_id=1):
        resp = client.get(f"/owner/{tok}/profile/card/{card_id}")
        assert resp.status_code == 200
        return resp.text

    def test_right_justified_labels_never_overlap(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        html = self._preview(client, tok)
        # The pass-5 row layout: fixed right-justified label column.
        assert 'w-28 flex-shrink-0 text-right pr-4' in html
        # The overlapping w-20 label from the old preview is gone.
        assert 'w-20 text-xs' not in html

    def test_bio_shown(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        _set_bio(db, "Sales guy. Love motorcycles.")
        tok = _owner_token()
        html = self._preview(client, tok)
        assert "Love motorcycles." in html

    def test_badges_call_text_email(self, tmp_path):
        """Phone badge rows on the personal card, email badge on the work
        card — round call/text/video/email buttons like the profile view."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        html = self._preview(client, tok, card_id=_card_id(db, "Personal"))
        assert 'href="tel:5551234567"' in html
        assert 'href="sms:5551234567"' in html
        html_work = self._preview(client, tok, card_id=_card_id(db, "Work"))
        assert 'href="mailto:jason@waltheremc.com"' in html_work

    def test_phone_display_formatting(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        html = self._preview(client, tok)
        assert "+1(555)123-4567" in html

    def test_scoped_legacy_field_renders_with_base_label(self, tmp_path):
        """A stored pass-4 scoped row (email_personal) renders its family
        label after the purge — never the raw type string."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = w.wl_connect(db)
        conn.execute(
            "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)"
            " VALUES (1, 'email_personal', 'scoped@x.com', 'granted')")
        conn.execute(
            "INSERT INTO card_fields (card_id, field_id) VALUES (1, "
            "(SELECT id FROM profile_fields WHERE profile_id = 1 AND field_type = 'email_personal'))")
        conn.commit()
        conn.close()
        tok = _owner_token()
        html = self._preview(client, tok)
        assert "scoped@x.com" in html
        assert ">email<" in html.lower() or "EMAIL" in html

    def test_field_label_display_helper(self, tmp_path=None):
        assert w.field_label_display("email_personal") == "Email"
        assert w.field_label_display("email") == "Email"
        assert w.field_label_display("state") == "State/Province"
        assert w.field_label_display("department") == "Department"
        assert w.field_label_display("po_box") == "PO Box"
        assert w.field_label_display("event") == "Significant date"


# ============================================================
# 6. vCard export carries the six additions
# ============================================================

class TestVcardExport:
    def _card(self, fields):
        return {"id": 1, "name": "Personal", "visible_fields": fields}

    def test_name_prefix_suffix_in_n_components(self):
        vcf = _build_vcard(
            {"display_name": "Jason Heath"},
            [self._card([
                {"id": 1, "field_type": "name_prefix", "field_value": "Mr",
                 "label": None, "visibility": "public"},
                {"id": 2, "field_type": "name_suffix", "field_value": "Jr.",
                 "label": None, "visibility": "public"},
            ])])
        assert "N:Heath;Jason;;;Mr;Jr." in vcf

    def test_new_types_travel_as_note_lines(self):
        vcf = _build_vcard(
            {"display_name": "Jason Heath"},
            [self._card([
                {"id": 1, "field_type": "department", "field_value": "Ops",
                 "label": None, "visibility": "public"},
                {"id": 2, "field_type": "po_box", "field_value": "PO Box 7",
                 "label": None, "visibility": "public"},
                {"id": 3, "field_type": "related_person", "field_value": "Tessa",
                 "label": "Assistant", "visibility": "granted"},
                {"id": 4, "field_type": "event", "field_value": "2020-06-13",
                 "label": "anniversary", "visibility": "granted"},
                {"id": 5, "field_type": "custom_field", "field_value": "handle",
                 "label": "chat", "visibility": "private"},
            ])])
        assert "NOTE:Department: Ops" in vcf
        assert "NOTE:PO Box 7" in vcf.replace("PO Box: PO Box 7", "PO Box 7") or \
            "NOTE:PO Box: PO Box 7" in vcf
        assert "NOTE:Assistant: Tessa" in vcf
        assert "NOTE:Anniversary: 2020-06-13" in vcf
        assert "NOTE:chat: handle" in vcf
