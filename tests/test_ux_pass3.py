"""UX pass 3 (2026-09-23, third captain walk-through) — regression pins.

Covers:
1. BUG FIX: 'Create vCard' opens the NEW vCard's editor (all fields ready)
2. BUG FIX: contact-card Status shows GreyList for badge-grey contacts
   (a future quarter marker is still the grey STATE)
3. Country field on every card editor
4. Phone formatting +1 (XXX) XXX-XXXX on display surfaces
5. Default cards: EVERY profile gets Personal + Work (always, even empty);
   Personal is the TOP card (default public picture) on every surface
6. Personal-only identity fields (high school / maiden name / nickname /
   childhood home) — multiples allowed, public by default (city/state-level);
   birthday defaults public; HIGH-SCHOOL picture slot on personal cards
   (both pictures default public)
7. Unified sharing: chooser page eliminated; QR between name and Share;
   Share fires the native share popup; sharing always includes the bio
8. Pending requests land in an AMBER box at the top of the whitelist
9. Search broadens to titles/phones/addresses (never bios)
10. Picture-based MULTI-SELECT filter tabs below the search bar; rows have
    no email sub-line, ONE click target, ~100 rows per page; badges are
    round and as large as the profile picture
11. My-card row: whole row opens the edit-profile page; bio 'Visibility'
    button removed (dropdown applies on change)
12. Notifications PAGE eliminated (requests live in the list)
13. Pass-3 field-type CHECK heal on legacy DBs (row-preserving swap)
"""
import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import json
import re

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "5551234567", "visibility": "granted"}],
    })
    # Boot after the profile exists: seeds the Personal+Work default pair.
    whitelist_db.ensure_whitelist_schema(conn)
    conn.commit()
    conn.close()
    return db


def _owner_token(payload="1"):
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", payload,
                                expires_days=365)


def _card_id(db: Path, name: str, owner: int = 1) -> int:
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = ? AND name = ?",
        (owner, name)).fetchone()
    conn.close()
    assert row is not None, f"card {name} missing"
    return row["id"]


# ============================================================
# 1. BUG FIX: create-vCard opens the new vCard's editor
# ============================================================

class TestCreateVCardFlow:
    def test_create_opens_new_vcard_editor(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        resp = client.post(f"/owner/{tok}/new-connection", data={
            "display_name": "Jane Rivers",
            "phone": "555-123-4567",
            "email": "jane@x.com",
        }, follow_redirects=False)
        assert resp.status_code == 303
        loc = resp.headers["location"]
        assert "/cards/" in loc and loc.endswith("/edit"), \
            "create must land in the new vCard's editor"
        editor = client.get(loc)
        assert editor.status_code == 200
        # Scoped templates: the email lands on the WORK card, whose
        # professional-appropriate sections are ready to populate. Identity
        # fields (Personal history / Childhood home / Birthday) stay on
        # Personal and never render on Work.
        for heading in ("Emails", "Phone numbers", "Addresses", "Title",
                        "Company", "Department", "Website", "Note"):
            assert heading in editor.text, f"editor missing '{heading}'"
        for absent in ("Personal history", "Childhood home", "Birthday",
                       "Significant dates", "Related people",
                       "Custom fields"):
            assert absent not in editor.text, \
                f"non-professional section '{absent}' leaked onto Work"
        assert "Jane Rivers" in editor.text

    def test_curated_stub_editable_by_creating_owner_only(self, tmp_path):
        """The stub profile is editable by its creating owner (ruling 2A
        stays: another ACCOUNT still 404s)."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        rival = whitelist_db.create_owner_profile(
            conn, "rival", "Rival Co", "rival@x.com", "password123")["id"]
        stub = whitelist_db.create_contact_vcard(conn, 1, "Jane Rivers")
        conn.commit()
        cid = conn.execute(
            "SELECT id FROM cards WHERE owner_profile_id = ? LIMIT 1",
            (stub["id"],)).fetchone()[0]
        conn.close()
        client = TestClient(create_app(db))
        ok = client.get(f"/owner/{_owner_token(1)}/cards/{cid}/edit")
        assert ok.status_code == 200
        foreign = client.get(f"/owner/{_owner_token(rival)}/cards/{cid}/edit")
        assert foreign.status_code == 404, "another owner must not edit a stub"

    def test_stub_always_gets_personal_and_work(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        stub = whitelist_db.create_contact_vcard(conn, 1, "No Contact Info")
        conn.commit()
        cards = whitelist_db.list_cards(conn, stub["id"])
        conn.close()
        assert [c["name"] for c in cards] == ["Personal", "Work"], \
            "even an empty stub defaults with Personal + Work"


# ============================================================
# 2. BUG FIX: grey state display on the contact card
# ============================================================

class TestGreyStateDisplay:
    def test_badge_grey_contact_shows_greelist_on_card(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey Guy")
        whitelist_db.set_badge_state(conn, gid, "greylist")
        grant = whitelist_db.get_grant(conn, gid)
        # set_badge_state stamps a FUTURE quarter marker…
        assert grant["expires_at"] > whitelist_db._now_iso()
        # …and is_grey STILL reports grey (the bug fix).
        assert whitelist_db.is_grey(grant) is True
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/contact/{gid}").text
        assert "GreyList" in html, "card must agree with the list badge"
        # review actions surface for grey contacts
        assert "Add to WhiteList" in html

    def test_whitelist_badge_contact_shows_whitelist(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "white@x.com", "White Gal")
        whitelist_db.set_badge_state(conn, gid, "whitelist")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/contact/{gid}").text
        assert "WhiteList" in html


# ============================================================
# 3+4. Country on every card + phone formatting
# ============================================================

class TestCountryAndPhoneFormat:
    def test_country_slot_on_every_card_editor(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        for name in ("Personal", "Work"):
            html = client.get(
                f"/owner/{_owner_token()}/cards/{_card_id(db, name)}/edit").text
            assert 'name="new_country_value"' in html, f"{name}: country slot"
            assert "Country" in html

    def test_phone_format_helper(self, tmp_path):
        f = whitelist_db.format_phone_display
        assert f("5551234567") == "+1 (555) 123-4567"
        assert f("+15551234567") == "+1 (555) 123-4567"
        assert f("(555) 123-4567") == "+1 (555) 123-4567"
        assert f("+442079460958") == "+442079460958", "non-US unchanged"
        assert f("555") == "555"

    def test_public_profile_formats_phones(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        pub = whitelist_db.add_profile_field(
            conn, 1, "phone", "3125550123", "public")
        personal = conn.execute(
            "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Personal'"
        ).fetchone()
        whitelist_db.set_card_fields(conn, personal["id"], [pub["id"]])
        conn.close()
        client = TestClient(create_app(db))
        html = client.get("/p/jasonheath").text
        assert "+1 (312) 555-0123" in html


# ============================================================
# 5. Default cards: Personal + Work, Personal first everywhere
# ============================================================

class TestDefaultCards:
    def test_every_profile_defaults_personal_and_work(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        cards = whitelist_db.list_cards(conn, 1)
        conn.close()
        assert [c["name"] for c in cards] == ["Personal", "Work"]

    def test_personal_is_the_public_default_card(self, tmp_path):
        """Anonymous viewers get the TOP (Personal) card only; its picture
        is THE default public picture."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.add_profile_field(conn, 1, "birthday", "1985-06-15", "public")
        personal = _card_id(db, "Personal")
        whitelist_db.set_card_fields(conn, personal, [
            r["id"] for r in conn.execute(
                "SELECT id FROM profile_fields WHERE profile_id=1").fetchall()])
        conn.close()
        client = TestClient(create_app(db))
        html = client.get("/p/jasonheath").text
        assert "Personal" in html
        assert "Work" not in html, "anon sees the top card only"

    def test_grant_ordering_personal_first_on_share(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        bundle = whitelist_db.create_share_bundle(
            conn, 1, [_card_id(db, "Work"), _card_id(db, "Personal")])
        cards = whitelist_db.cards_for_share_bundle(conn, bundle, "granted")
        conn.close()
        assert [c["name"] for c in cards][0] == "Personal", \
            "multiple cards shared: personal takes precedence (top)"


# ============================================================
# 6. Personal identity fields + high-school picture
# ============================================================

class TestPersonalIdentityFields:
    def test_new_types_render_with_multiples(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(
            f"/owner/{_owner_token()}/cards/{_card_id(db, 'Personal')}/edit").text
        for t in ("high_school", "maiden_name", "nickname",
                  "childhood_address1", "childhood_city", "childhood_state"):
            assert f'name="new_{t}_value"' in html
            assert f"addFieldRow('{t}')" in html, f"{t} is repeatable"

    def test_identity_fields_default_public_addresses_city_level(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        # defaults via the dedicated add-row selects (saved with NO visibility
        # key, the route falls back to the same table)
        html = client.get(
            f"/owner/{_owner_token()}/cards/{_card_id(db, 'Personal')}/edit").text
        for t in ("high_school", "maiden_name", "nickname",
                  "childhood_city", "childhood_state", "birthday", "city", "state"):
            m = re.search(
                r'name="new_' + t + r'_visibility".*?<option value="(\w+)" selected>',
                html, re.DOTALL)
            assert m and m.group(1) == "public", f"{t} defaults public"
        for t in ("childhood_address1", "address1", "zip"):
            m = re.search(
                r'name="new_' + t + r'_visibility".*?<option value="(\w+)" selected>',
                html, re.DOTALL)
            assert m and m.group(1) == "granted", \
                f"{t} street-level defaults granted"

    def test_public_profile_shows_identity_fields(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        personal = _card_id(db, "Personal")
        fids = []
        for t, v in (("high_school", "Lincoln High"),
                     ("nickname", "Jay"),
                     ("childhood_city", "Ada"),
                     ("birthday", "1985-06-15")):
            fids.append(whitelist_db.add_profile_field(
                conn, 1, t, v, "public")["id"])
        whitelist_db.set_card_fields(conn, personal, fids)
        conn.close()
        client = TestClient(create_app(db))
        html = client.get("/p/jasonheath").text
        for label in ("high school", "nickname", "childhood city", "birthday"):
            assert label in html
        for value in ("Lincoln High", "Jay", "Ada", "1985-06-15"):
            assert value in html

    def test_hs_picture_slot_upload_and_public_display(self, tmp_path):
        import base64
        import io
        from PIL import Image
        buf = io.BytesIO()
        Image.new("RGB", (600, 400), (10, 10, 10)).save(buf, format="PNG")
        data_url = "data:image/png;base64," + base64.b64encode(
            buf.getvalue()).decode()

        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        cid = _card_id(db, "Personal")
        # editor offers the HS slot on personal cards only
        personal_html = client.get(f"/owner/{tok}/cards/{cid}/edit").text
        assert "High school picture" in personal_html
        assert 'photo_kind=hs' in personal_html
        work_html = client.get(
            f"/owner/{tok}/cards/{_card_id(db, 'Work')}/edit").text
        assert "High school picture" not in work_html

        resp = client.post(f"/owner/{tok}/cards/{cid}/photo?photo_kind=hs",
                           data={"photo_data": data_url})
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        stored = conn.execute(
            "SELECT hs_photo_path FROM cards WHERE id = ?", (cid,)).fetchone()[0]
        conn.close()
        assert stored == f"1_{cid}_hs.jpg"
        assert client.get(f"/photos/1/{cid}/hs").status_code == 200

        # both pictures default public — anon sees the HS picture
        html = client.get("/p/jasonheath").text
        assert f'/photos/1/{cid}/hs' in html


# ============================================================
# 7. Unified sharing
# ============================================================

class TestUnifiedSharing:
    def test_share_always_includes_bio(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.update_bio(conn, 1, "Wheel bushings, best prices.")
        whitelist_db.update_bio_visibility(conn, 1, "private")
        bundle = whitelist_db.create_share_bundle(conn, 1, [_card_id(db, "Work")])
        conn.commit()
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/s/{bundle['id']}").text
        assert "Wheel bushings, best prices." in html, \
            "sharing ALWAYS includes the bio"


# ============================================================
# 8. Pending requests: amber box at the top
# ============================================================

class TestPendingAmberBox:
    def test_pending_requests_render_in_amber_box(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "newbie@x.com", "New Bee")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert "var(--wl-amber-field)" in html, "the box wears amber"
        assert "New Bee" in html
        assert "Approve" in html and "Deny" in html
        # pending rows live ABOVE the filter tabs (top of the list)
        assert html.index("Requests") < html.index("Filter contacts")


# ============================================================
# 9. Search broadening
# ============================================================

class TestSearchBroadening:
    def test_search_matches_registry_profile_fields_not_bio(self, tmp_path):
        db = _make_db(tmp_path)
        import store
        store.init_db(db)
        conn = whitelist_db.wl_connect(db)
        # The contact 'Grace' exists as a registry profile with public fields.
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('graceh','Grace Hopper')")
        gid_profile = conn.execute(
            "SELECT id FROM profiles WHERE handle='graceh'").fetchone()[0]
        for t, v in (("email", "grace@x.com"),
                     ("title", "Rear Admiral"),
                     ("phone", "555-0100"),
                     ("city", "Arlington")):
            conn.execute(
                "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)"
                " VALUES (?, ?, ?, 'public')", (gid_profile, t, v))
        conn.execute("UPDATE profiles SET bio = 'COMPILER QUEEN' WHERE id = ?",
                     (gid_profile,))
        gid = whitelist_db.create_grant(conn, 1, "grace@x.com", "Grace Hopper")
        conn.commit()
        rows = whitelist_db.list_contact_list_rows(conn, 1, q="Admiral")
        assert [r["name"] for r in rows] == ["Grace Hopper"], "titles searchable"
        rows = whitelist_db.list_contact_list_rows(conn, 1, q="555-0100")
        assert rows, "phones searchable"
        rows = whitelist_db.list_contact_list_rows(conn, 1, q="Arlington")
        assert rows, "addresses searchable"
        rows = whitelist_db.list_contact_list_rows(conn, 1, q="COMPILER QUEEN")
        assert rows == [], "bios NEVER match (ruling)"
        conn.close()


# ============================================================
# 10. Filter tabs + row design + pagination
# ============================================================

class TestFilterTabsAndRows:
    def _world(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        personal, work = _card_id(db, "Personal"), _card_id(db, "Work")
        g1 = whitelist_db.create_grant(conn, 1, "a@x.com", "Alice A")
        whitelist_db.set_badge_state(conn, g1, "whitelist")
        whitelist_db.set_grant_cards(conn, g1, [personal])
        g2 = whitelist_db.create_grant(conn, 1, "b@x.com", "Bob B")
        whitelist_db.set_badge_state(conn, g2, "greylist")
        whitelist_db.set_grant_cards(conn, g2, [personal, work])
        g3 = whitelist_db.create_grant(conn, 1, "c@x.com", "Cara C")
        whitelist_db.set_badge_state(conn, g3, "blocked")
        conn.commit()
        conn.close()
        return db, personal, work, g1, g2, g3

    def test_tabs_render_picture_and_state_icons(self, tmp_path):
        db, *_ = self._world(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert 'role="group" aria-label="Filter contacts"' in html
        personal, work = _card_id(db, "Personal"), _card_id(db, "Work")
        conn = whitelist_db.wl_connect(db)
        whitelist_db.update_card_photo(conn, personal, f"1_{personal}.jpg")
        conn.commit()
        conn.close()
        html = client.get(f"/owner/{_owner_token()}").text
        assert f"/photos/1/{personal}" in html, "personal tab carries its picture"
        for key in ("whitelist", "greylist", "blacklist"):
            assert f"/static/badge-{key}.png" in html

    def test_multiselect_card_and_state_filters_combine(self, tmp_path):
        db, personal, work, g1, g2, g3 = self._world(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        # personal + grey → only Bob (grey, has personal)
        html = client.get(f"/owner/{tok}?f={personal},greylist").text
        assert "Bob B" in html
        assert "Alice A" not in html
        assert "Cara C" not in html
        # personal OR work (card group) + white OR grey (state group)
        html = client.get(f"/owner/{tok}?f={personal},{work},greylist,whitelist").text
        assert "Alice A" in html and "Bob B" in html
        assert "Cara C" not in html
        # blacklist alone → Cara (revoked) + plain contacts
        html = client.get(f"/owner/{tok}?f=blacklist").text
        assert "Cara C" in html
        assert "Alice A" not in html

    def test_rows_have_no_email_and_one_click_target(self, tmp_path):
        db, *_ = self._world(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert "a@x.com" not in html, "no email sub-line on contact rows"
        assert 'class="absolute inset-0 z-0 rounded-xl"' in html, \
            "whole-row overlay link (ONE click target)"

    def test_badges_round_and_picture_sized(self, tmp_path):
        db, *_ = self._world(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert "w-10 h-10 rounded-full overflow-hidden" in html, \
            "list badges are round and as large as the 40px profile picture"

    def test_rows_sort_card_then_state(self, tmp_path):
        db, personal, work, g1, g2, g3 = self._world(tmp_path)
        rows = None
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        # Within the Personal card, white (Alice) precedes grey (Bob);
        # Bob's Work row then follows all Personal rows.
        i_alice = html.index("Alice A")
        i_bob = html.index("Bob B")
        assert i_alice < i_bob, "within a card: white/grey/black, then name"

    def test_per_page_is_100(self, tmp_path):
        db, *_ = self._world(tmp_path)
        client = TestClient(create_app(db))
        # 150 plain contacts → page 0 shows exactly 100 rows
        import json as _json
        import store
        store.init_db(db)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_contacts_owner(conn)
        for i in range(150):
            conn.execute(
                "INSERT INTO contacts (id, normalized_name, emails, phones,"
                " organizations, sources, created_at, updated_at, is_duplicate,"
                " owner_profile_id) VALUES (?, ?, ?, '[]', '[]', '[]',"
                " datetime('now'), datetime('now'), 0, 1)",
                (f"c{i}", f"Filler Person {i:03d}",
                 _json.dumps([{"address": f"filler{i}@x.com"}])))
        conn.commit()
        conn.close()
        html = client.get(f"/owner/{_owner_token()}").text
        assert html.count("wl-card p-3") == 100


# ============================================================
# 11. My-card row + bio visibility dropdown
# ============================================================

class TestMyCardAndBioDropdown:
    def test_my_card_row_opens_edit_profile(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        html = client.get(f"/owner/{tok}").text
        my_card_pos = html.find('href="/owner/' + tok + '/profile"')
        assert my_card_pos != -1, "the whole my-card row links to the editor"
        assert "Edit profile" not in html, "edit link removed"
        assert my_card_pos < html.find('name="q"'), "my card sits above search"

    def test_bio_visibility_dropdown_auto_submits(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        assert 'onchange="this.form.submit()"' in html
        assert ">Visibility</button>" not in html, "visibility button removed"


# ============================================================
# 12. Notifications page eliminated
# ============================================================

class TestNotificationsEliminated:
    def test_page_and_routes_gone(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        assert client.get(f"/owner/{tok}/notifications").status_code == 404
        html = client.get(f"/owner/{tok}").text
        assert "Notifications</a>" not in html, "header button gone"

    def test_request_still_notifies_data_layer_and_email(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        client.post("/p/jasonheath/request", data={
            "name": "Still Here", "email": "still@x.com"})
        conn = whitelist_db.wl_connect(db)
        rows = whitelist_db.list_notifications(conn, 1)
        conn.close()
        assert rows and rows[0]["kind"] == "connection_request", \
            "the data layer + email push survive (only the page is gone)"


# ============================================================
# 13. Pass-3 enum heal on legacy DBs
# ============================================================

class TestPass3EnumHeal:
    def test_legacy_db_gains_new_field_types(self, tmp_path):
        db = tmp_path / "legacy.db"
        conn = whitelist_db.wl_connect(db)
        whitelist_db.wl_init(conn)
        # Simulate a pre-pass-3 DB: strip the new vocabulary from the CHECK
        # by swapping to a hand-made v3-shaped table.
        conn.executescript("""
            PRAGMA foreign_keys=OFF;
            CREATE TABLE profile_fields_v3legacy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                field_type TEXT NOT NULL CHECK(field_type IN
                    ('email', 'phone', 'text_number', 'facetime_number',
                     'facetime', 'skype', 'video_app', 'messenger',
                     'messaging_app', 'facebook', 'instagram', 'social_other',
                     'title', 'company', 'address1', 'address2', 'city',
                     'state', 'zip', 'website', 'birthday', 'note')),
                field_value TEXT NOT NULL,
                visibility TEXT NOT NULL CHECK(visibility IN
                    ('public', 'granted', 'private')),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(profile_id, field_type, field_value),
                FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
            );
            INSERT INTO profile_fields_v3legacy
                (id, profile_id, field_type, field_value, visibility)
            SELECT id, profile_id, field_type, field_value, visibility
            FROM profile_fields;
            DROP TABLE profile_fields;
            ALTER TABLE profile_fields_v3legacy RENAME TO profile_fields;
            PRAGMA foreign_keys=ON;
        """)
        conn.commit()
        # Heal through the ONE ordered entry point.
        whitelist_db.ensure_whitelist_schema(conn)
        # New types are accepted now…
        whitelist_db.add_profile_field(conn, 1, "nickname", "Jay", "public")
        whitelist_db.add_profile_field(conn, 1, "country", "USA", "granted")
        rows = conn.execute(
            "SELECT field_type FROM profile_fields WHERE profile_id = 1"
        ).fetchall()
        conn.commit()
        conn.close()
        assert {"nickname", "country"} <= {r["field_type"] for r in rows}, \
            "post-heal DB accepts the pass-3 vocabulary"
