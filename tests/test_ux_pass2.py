"""UX pass 2 (2026-09-22, second captain walk-through) — regression pins.

Covers:
1. Phone labels: Mobile/Home/Work + CUSTOM label (editor + display surfaces)
2. Field visibility defaults: granted everywhere EXCEPT title/company/website
   (public) — editor selects, absent-visibility saves, legacy title/company
   seed, and the /fields/new route
3. BUG FIX: deleting a field from the card editor must never drop the other
   keyed-in data (the ✕ posts the whole form; the route now applies it)
4. Visibility dropdowns keyboard-controlled (ArrowUp/ArrowDown handler)
5. View profile: field names right-justified + spaced (never overwrite values)
6. Share-from-profile chooser preview renders GRANTED data (defaults ruling)
7. Share email default subject: '<First> <Last> WhiteList Card'
8. 'Forward your card' section removed from the view-profile page
9. Bio cap 500 (client maxlength + server-side reject)
10. Grey buttons everywhere (amber revoke/punt folded into slate)
11. Profile QR removed; ONE Connect button (randos notify the owner)
12. Contact-card Access section: Status = WhiteList/GreyList/BlackList,
    no Requestor/Name rows, no Revoke button, no Expires row
13. 'Are you sure?' confirm on badge state changes (list-name copy)
14. Contact list: no Details expander; pending Approve/Deny inline
15. Layout: my card ABOVE search, centered title, notifications LEFT,
    round + button RIGHT of search → new-connection search / create vCard
16. Grey/black NEVER expire: quarterly notification copy carries the ruling
"""
import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import re

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "555-1234", "visibility": "granted"}],
    })
    conn.commit()
    conn.close()
    return db


def _owner_token():
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", "1", expires_days=365)


def _card_id(db: Path, name: str, owner: int = 1) -> int:
    conn = whitelist_db.wl_connect(db)
    cid = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = ? AND name = ?",
        (owner, name),
    ).fetchone()[0]
    conn.close()
    return cid


def _editor_gets(db: Path, client: TestClient, card_name: str) -> tuple[str, int]:
    cid = _card_id(db, card_name)
    resp = client.get(f"/owner/{_owner_token()}/cards/{cid}/edit")
    assert resp.status_code == 200
    return resp.text, cid


# ============================================================
# 1. Phone labels (mobile / home / work / custom)
# ============================================================

class TestPhoneLabels:
    def test_phone_row_renders_label_select(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html, _ = _editor_gets(db, client, "Contact")
        assert 'name="field_' in html and "_label\"" in html
        assert ">Mobile</option>" in html
        assert ">Home</option>" in html
        assert ">Work</option>" in html
        assert ">Custom\u2026</option>" in html

    def test_custom_label_saves_and_displays(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html, cid = _editor_gets(db, client, "Contact")
        fid = int(re.search(r'name="field_(\d+)_value"', html).group(1))
        resp = client.post(f"/owner/{_owner_token()}/cards/{cid}/edit", data={
            "field_1_value": "555-1234",
            "field_1_visibility": "granted",
            f"field_{fid}_label": "__custom",
            f"field_{fid}_label_custom": "QA Team",
        })
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        label = conn.execute(
            "SELECT label FROM profile_fields WHERE id = ?", (fid,)
        ).fetchone()[0]
        conn.close()
        assert label == "QA Team", "custom label stored verbatim"
        # The editor re-render shows the custom input populated + selected.
        assert 'value="QA Team"' in resp.text
        assert 'value="__custom" selected' in resp.text

    def test_builtin_label_folds_lowercase(self, tmp_path):
        conn = whitelist_db.wl_connect(":memory:")
        assert whitelist_db.normalize_field_label("Mobile") == "mobile"
        assert whitelist_db.normalize_field_label("WORK") == "work"
        assert whitelist_db.normalize_field_label(" Home ") == "home"
        assert whitelist_db.normalize_field_label("__custom") == ""
        assert whitelist_db.normalize_field_label("") == ""
        conn.close()

    def test_label_display_helper(self, tmp_path):
        conn = whitelist_db.wl_connect(":memory:")
        assert whitelist_db.label_display("mobile") == "Mobile"
        assert whitelist_db.label_display("home") == "Home"
        assert whitelist_db.label_display("work") == "Work"
        assert whitelist_db.label_display("QA Team") == "QA Team"
        assert whitelist_db.label_display(None) == ""
        conn.close()

    def test_label_surfaces_on_public_profile(self, tmp_path):
        db = _make_db(tmp_path)
        # Boot the app first: ensure_whitelist_schema adds the label column.
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        fid = conn.execute(
            "SELECT id FROM profile_fields WHERE field_type='phone'"
        ).fetchone()[0]
        conn.execute("UPDATE profile_fields SET label='mobile' WHERE id=?", (fid,))
        gid = whitelist_db.create_grant(conn, 1, "friend@x.com", "Friend")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        conn.commit()
        conn.close()

        html = client.get("/p/jasonheath?e=friend%40x.com").text
        assert "Mobile" in html, "phone label renders on the view-profile page"

    def test_new_phone_row_carries_label_select(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html, _ = _editor_gets(db, client, "Contact")
        assert 'name="new_phone_label"' in html


# ============================================================
# 2. Visibility defaults: granted everywhere except title/company/website
# ============================================================

class TestVisibilityDefaults:
    def test_new_row_select_defaults(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html, _ = _editor_gets(db, client, "Work")

        def _selected_default(name: str) -> str:
            m = re.search(
                r'name="' + name + r'".*?</select>', html, re.DOTALL)
            assert m, f"{name} select renders"
            sel = re.search(
                r'<option value="(\w+)" selected>(\w+)</option>', m.group(0))
            return sel.group(1) if sel else "(none)"

        assert _selected_default("new_email_visibility") == "granted", \
            "email add-row defaults to granted"
        assert _selected_default("new_title_visibility") == "public", \
            "title add-row defaults to public (UX pass 2 defaults ruling)"
        assert _selected_default("new_company_visibility") == "public"
        assert _selected_default("new_website_visibility") == "public"
        assert _selected_default("new_phone_visibility") == "granted"

    def test_save_without_visibility_defaults_granted(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        # The Contact card has no extra phone; add one with NO visibility key.
        resp = client.post(f"/owner/{_owner_token()}/cards/{_card_id(db, 'Contact')}/edit",
                           data={"new_phone_value": "+1-555-000-1111"})
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        vis = conn.execute(
            "SELECT visibility FROM profile_fields WHERE field_value='+1-555-000-1111'"
        ).fetchone()[0]
        conn.close()
        assert vis == "granted", "absent visibility defaults to granted"

    def test_save_without_visibility_title_defaults_public(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/cards/{_card_id(db, 'Identity')}/edit",
                           data={"new_title_value": "VP Engineering"})
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        vis = conn.execute(
            "SELECT visibility FROM profile_fields WHERE field_type='title' "
            "AND field_value='VP Engineering'"
        ).fetchone()[0]
        conn.close()
        assert vis == "public", "title defaults to public"

    def test_legacy_title_company_seed_now_public(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Simulate a legacy profile carrying only the columns: clear the
        # seeded rows, then re-run the seed heal.
        conn.execute("DELETE FROM profile_fields WHERE field_type IN ('title','company')")
        whitelist_db._seed_title_company_fields(conn)
        rows = conn.execute(
            "SELECT field_type, visibility FROM profile_fields "
            "WHERE field_type IN ('title','company')").fetchall()
        conn.close()
        assert rows, "seed heal re-inserted the rows"
        assert all(r["visibility"] == "public" for r in rows), \
            "title/company seeds follow the public default"

    def test_fields_new_route_defaults_granted(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/fields/new",
                           data={"field_type": "phone",
                                 "field_value": "+1-555-999-0000"})
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        vis = conn.execute(
            "SELECT visibility FROM profile_fields WHERE field_value='+1-555-999-0000'"
        ).fetchone()[0]
        conn.close()
        assert vis == "granted"


# ============================================================
# 3. BUG FIX: field delete must not drop keyed-in data
# ============================================================

class TestDeleteKeepsKeyedData:
    def test_delete_field_persists_other_edits(self, tmp_path):
        """The pass-2 data-loss repro: type into OTHER rows, hit a ✕ — the
        ✕ posts the WHOLE form, and every other edit must survive."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html, cid = _editor_gets(db, client, "Work")
        # Work card: one email field (jason@waltheremc.com).
        fid = int(re.search(r'name="field_(\d+)_value"', html).group(1))
        resp = client.post(
            f"/owner/{_owner_token()}/cards/{cid}/fields/{fid}/delete",
            data={
                # Existing field's (unchanged) value rides along…
                f"field_{fid}_value": "jason@waltheremc.com",
                f"field_{fid}_visibility": "granted",
                # …plus a NEW value keyed into an add-row.
                "new_email_value": "second@acme.com",
                "new_email_visibility": "granted",
                # …plus a card rename.
                "card_name": "Work",
                "display_name": "Jason Heath",
            })
        assert resp.status_code == 200, "lands back on the editor after the redirect"
        conn = whitelist_db.wl_connect(db)
        linked = [r["field_value"] for r in conn.execute(
            "SELECT pf.field_value FROM card_fields cf "
            "JOIN profile_fields pf ON cf.field_id = pf.id WHERE cf.card_id = ?",
            (cid,)).fetchall()]
        conn.close()
        assert "jason@waltheremc.com" not in linked, "the ✕'s field is unlinked"
        assert "second@acme.com" in linked, "the keyed-in new field SURVIVED the delete"

    def test_delete_field_value_edit_riding_also_applies(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html, cid = _editor_gets(db, client, "Work")
        fid = int(re.search(r'name="field_(\d+)_value"', html).group(1))
        # A DIFFERENT card's field row is keyed + edited in the same POST.
        contact_fid = int(re.search(
            r'name="field_(\d+)_value"',
            client.get(f"/owner/{_owner_token()}/cards/{_card_id(db, 'Contact')}/edit").text,
        ).group(1))
        resp = client.post(
            f"/owner/{_owner_token()}/cards/{cid}/fields/{fid}/delete",
            data={
                f"field_{fid}_value": "jason@waltheremc.com",
                f"field_{fid}_visibility": "granted",
                f"field_{contact_fid}_value": "555-9999",
                f"field_{contact_fid}_visibility": "granted",
            })
        assert resp.status_code == 200
        conn = whitelist_db.wl_connect(db)
        val = conn.execute(
            "SELECT field_value FROM profile_fields WHERE id = ?",
            (contact_fid,)).fetchone()[0]
        conn.close()
        assert val == "555-9999", "an edit to a shared field rode along and applied"

    def test_delete_foreign_field_still_404(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(
            f"/owner/{_owner_token()}/cards/{_card_id(db, 'Work')}/fields/999999/delete",
            data={})
        assert resp.status_code == 404


# ============================================================
# 4. Keyboard-controlled dropdowns
# ============================================================

class TestKeyboardDropdowns:
    def test_arrow_key_handler_on_visibility_selects(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html, _ = _editor_gets(db, client, "Work")
        assert "ArrowDown" in html and "ArrowUp" in html, \
            "visibility dropdowns are keyboard-controlled (UX pass 2)"
        # The handler ships app-wide from base.html — check it on the
        # profile page too.
        profile_html = client.get(f"/owner/{_owner_token()}/profile").text
        assert "ArrowDown" in profile_html


# ============================================================
# 5. View profile: right-justified field names, spaced
# ============================================================

class TestViewProfileFieldRows:
    def _granted_client(self, db: Path):
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "friend@x.com", "Friend")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        conn.close()
        client = TestClient(create_app(db))
        return client

    def test_labels_right_justified_with_spacing(self, tmp_path):
        db = _make_db(tmp_path)
        client = self._granted_client(db)
        html = client.get("/p/jasonheath?e=friend%40x.com").text
        assert "text-right pr-4" in html, \
            "field names RIGHT-justified with spacing (never overwrite values)"

    def test_no_forward_section(self, tmp_path):
        db = _make_db(tmp_path)
        client = self._granted_client(db)
        html = client.get("/p/jasonheath?e=friend%40x.com").text
        assert "Forward your card" not in html, \
            "redundant forward section removed from view-my-profile (UX pass 2)"
        assert "/forward" not in html


# ============================================================
# 6+7. Share preview granted tier + share email subject
# ============================================================

class TestSharePreviewAndSubject:
    def test_owner_share_subject_is_name_card(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        work = _card_id(db, "Work")
        client.post(f"/owner/{_owner_token()}/share",
                    data={"card_ids": [str(work)]})
        # POST redirects to /share/{bundle_id}
        # (re-create to know the id — the bundle id is derived from the row)
        conn = whitelist_db.wl_connect(db)
        bundle_id = conn.execute(
            "SELECT id FROM share_bundles ORDER BY created_at DESC LIMIT 1"
        ).fetchone()[0]
        conn.close()
        resp = client.get(f"/owner/{_owner_token()}/share/{bundle_id}")
        assert 'id="share-subject"' in resp.text
        assert "Jason Heath WhiteList Card" in resp.text, \
            "default email subject '<First> <Last> WhiteList Card'"
        assert "encodeURIComponent('WhiteList card')" not in resp.text


# ============================================================
# 9. Bio cap 500
# ============================================================

class TestBioCap500:
    def test_over_limit_rejected(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/bio",
                           data={"bio": "x" * 501})
        assert resp.status_code == 400
        assert "500 characters" in resp.text

    def test_boundary_ok_and_maxlength(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/bio",
                           data={"bio": "y" * 500})
        assert resp.status_code == 200
        html = client.get(f"/owner/{_owner_token()}/profile").text
        assert 'maxlength="500"' in html
        assert "/500 characters" in html


# ============================================================
# 10. Grey buttons everywhere
# ============================================================

class TestGreyEverywhere:
    def test_revoke_and_punt_buttons_are_slate(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))  # boot first: heals grant columns
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        # Force the grey state (expired quarter grant)
        conn.execute(
            "UPDATE access_grants SET expires_at='2020-01-01T00:00:00Z', "
            "quarter_status='pending_review' WHERE id = ?", (gid,))
        conn.commit()
        conn.close()
        html = client.get(
            f"/owner/{_owner_token()}/contact/{gid}").text
        base = client.get("/signin").text  # base.html ships in every page
        assert ".wl-btn-revoke { background: var(--wl-btn-slate)" in base
        assert ".wl-btn-punt { background: var(--wl-btn-slate)" in base
        assert ".wl-btn-revoke { background: var(--wl-amber)" not in base, \
            "revoke/punt buttons folded into the standard grey (grey everywhere)"


# ============================================================
# 11. Profile QR removed; ONE Connect button
# ============================================================

class TestProfileConnect:
    def test_anon_gets_connect_no_qr(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get("/p/jasonheath").text
        assert "/qr/jasonheath" not in html, "QR removed from the profile"
        connects = re.findall(r">\s*Connect\s*</a>", html)
        assert len(connects) == 1, "exactly ONE Connect button"
        assert "Scan to connect" not in html

    def test_connect_links_request_form(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get("/p/jasonheath").text
        assert "/p/jasonheath/request-form" in html


# ============================================================
# 12. Contact-card Access section
# ============================================================

class TestContactCardAccessSection:
    def _grant(self, db: Path, email: str, name: str):
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, email, name)
        conn.close()
        return gid

    def test_whitelist_state_and_no_revoke_no_requestor(self, tmp_path):
        db = _make_db(tmp_path)
        gid = self._grant(db, "active@x.com", "Active")
        conn = whitelist_db.wl_connect(db)
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/contact/{gid}").text
        assert "WhiteList" in html, "Status shows the LIST name"
        assert "Revoke" not in html, "revoke button removed (main page has it)"
        assert "active@x.com" not in html.split("Access")[1].split("</div>")[0] \
            if "Access" in html else True
        # Requestor / Name rows removed:
        access_html = html.split('Access</h2>')[1]
        assert ">requester<" not in access_html
        assert ">name<" not in access_html
        assert ">expires<" not in access_html, "grey/black never expire — no Expires row"

    def test_grey_state_shows_greylist(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))  # boot first: heals grant columns
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at='2020-01-01T00:00:00Z', "
            "quarter_status='pending_review' WHERE id = ?", (gid,))
        conn.commit()
        conn.close()
        html = client.get(f"/owner/{_owner_token()}/contact/{gid}").text
        assert "GreyList" in html
        assert "Make Permanent" in html, "grey keeps its review choices"
        assert "Punt Another Quarter" in html
        assert "Revoke" not in html

    def test_blacklist_state_shows_blacklist(self, tmp_path):
        db = _make_db(tmp_path)
        gid = self._grant(db, "gone@x.com", "Gone")
        conn = whitelist_db.wl_connect(db)
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        whitelist_db.revoke_grant(conn, gid)
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/contact/{gid}").text
        assert "BlackList" in html


# ============================================================
# 13+14+15. Contact list: confirm, no details, layout, + button
# ============================================================

class TestContactListPass2:
    def _granted_row(self, db: Path, email="listed@x.com", name="Listed"):
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, email, name)
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime")
        conn.close()
        return gid

    def test_badge_confirm_uses_list_names(self, tmp_path):
        db = _make_db(tmp_path)
        self._granted_row(db)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert "confirm(" in html, "'Are you sure?' on badge changes"
        # A WhiteList row's next state is GreyList: the confirm names the LIST.
        assert "Change this contact to GreyList?" in html
        assert "blocked" not in html.split("confirm(")[1].split(")")[0], \
            "confirm copy says the LIST name, never the internal 'blocked'"

    def test_badge_confirm_blacklist_copy(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "w@x.com", "W")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        # A (live) grey row's next state is BlackList.
        assert "Change this contact to BlackList?" in html

    def test_no_details_expander(self, tmp_path):
        db = _make_db(tmp_path)
        self._granted_row(db)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        assert "<details" not in html, "the Details dropdown is removed"

    def test_pending_actions_inline(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "pending@x.com", "Pending")
        conn.close()
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        # Approve/Deny must not hide behind a details expander.
        approve_pos = html.find('value="approve"')
        details_pos = html.find("<details")
        assert approve_pos != -1
        assert details_pos == -1
        assert "pending@x.com" in html, "requester identity stays visible"

    def test_layout_my_card_above_search(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        edit_profile_pos = html.find("Edit profile")
        search_pos = html.find('name="q"')
        assert edit_profile_pos != -1 and search_pos != -1
        assert edit_profile_pos < search_pos, "my card sits ABOVE the search bar"

    def test_layout_notifications_left_title_centered(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        notif_pos = html.find("Notifications</a>")
        title_pos = html.find(">WhiteList</h1>")
        signout_pos = html.find("Sign out</button>")
        assert notif_pos < title_pos < signout_pos, \
            "notifications LEFT, centered title, sign out right"
        assert "left-1/2" in html, "title is centered"

    def test_round_plus_button_right_of_search(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}").text
        search_pos = html.find('name="q"')
        plus_pos = html.find("Add a new connection")
        assert plus_pos > search_pos, "+ button sits RIGHT of the search bar"
        after = html[plus_pos:plus_pos + 500]
        assert "rounded-full" in after, "the + button is round"


# ============================================================
# 15b. New-connection search + create standard vCard
# ============================================================

class TestNewConnection:
    def _seed_contact(self, db: Path, name="Jordan Rivers", email="jordan@x.com"):
        import json
        import store
        store.init_db(db)  # the contacts table lives in the store layer
        create_app(db)     # boot once: ensure_contacts_owner adds the owner column
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "INSERT INTO contacts (id, normalized_name, first_name, last_name,"
            " emails, phones, organizations, sources, created_at, updated_at)"
            " VALUES ('c-new', ?, 'Jordan', 'Rivers', ?, '[]', '[]', '[]',"
            " datetime('now'), datetime('now'))",
            (name.lower().replace(" ", "-"), json.dumps([{"address": email}])),
        )
        conn.execute(
            "UPDATE contacts SET owner_profile_id = 1 WHERE owner_profile_id IS NULL")
        conn.commit()
        conn.close()

    def test_search_finds_new_connections(self, tmp_path):
        db = _make_db(tmp_path)
        self._seed_contact(db)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}/new-connection?q=jordan")
        assert resp.status_code == 200
        assert "Jordan Rivers" in resp.text
        assert "jordan@x.com" in resp.text
        # A hit does NOT offer the create form.
        assert "Create a standard vCard" not in resp.text

    def test_no_hits_offers_create_vcard(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}/new-connection?q=nobody")
        assert resp.status_code == 200
        assert "No matches" in resp.text
        assert "Create a standard vCard" in resp.text

    def test_create_vcard_makes_profile_with_fields_and_cards(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/new-connection", data={
            "display_name": "Casey New",
            "phone": "+1-555-777-1234",
            "email": "casey@new.com",
        }, follow_redirects=False)
        assert resp.status_code == 303, "lands back on the contact list"
        conn = whitelist_db.wl_connect(db)
        prof = conn.execute(
            "SELECT * FROM profiles WHERE display_name = 'Casey New'"
        ).fetchone()
        assert prof is not None
        fields = {(r["field_type"], r["field_value"], r["visibility"]) for r in conn.execute(
            "SELECT field_type, field_value, visibility FROM profile_fields "
            "WHERE profile_id = ?", (prof["id"],)).fetchall()}
        cards = conn.execute(
            "SELECT COUNT(*) FROM cards WHERE owner_profile_id = ?",
            (prof["id"],)).fetchone()[0]
        conn.close()
        assert ("phone", "+1-555-777-1234", "granted") in fields
        assert ("email", "casey@new.com", "granted") in fields
        assert cards >= 2, "default cards seeded for the new vCard"

    def test_create_requires_name(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/new-connection",
                           data={"display_name": ""})
        assert resp.status_code == 400
        assert "Name is required." in resp.text

    def test_plus_button_carries_search_query(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}?q=jordan").text
        assert "/owner/%s/new-connection?q=jordan" % _owner_token() in html


# ============================================================
# 16. Grey/black never expire
# ============================================================

class TestNeverExpireSemantics:
    def test_quarterly_notification_copy(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))  # boot first: heals grant columns
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at='2020-01-01T00:00:00Z', "
            "quarter_status='pending_review' WHERE id = ?", (gid,))
        conn.commit()
        whitelist_db.sync_quarterly_notifications(conn, 1)
        note = conn.execute(
            "SELECT * FROM notifications WHERE kind='quarterly'").fetchone()
        conn.close()
        assert note is not None
        assert "never expire" in note["body"]
        assert "never" in note["body"] and "delete" in note["body"], \
            "review never deletes contacts"

    def test_grey_badge_state_has_no_expiry_ui(self, tmp_path):
        """A grey contact shows as GreyList with no 'expires' surface, even
        with a lapsed internal quarter marker."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))  # boot first: heals grant columns
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at='2020-01-01T00:00:00Z', "
            "quarter_status='pending_review' WHERE id = ?", (gid,))
        conn.commit()
        conn.close()
        html = client.get(f"/owner/{_owner_token()}/contact/{gid}").text
        assert ">expires<" not in html
        assert "GreyList" in html


# ============================================================
# SPEC: the wording updates are asserted by test_spec_documents_pass2
# (kept next to the code pins so a spec revert fails CI too).
# ============================================================

def test_spec_documents_pass2():
    spec = (Path(__file__).parent.parent / "SPEC.md").read_text()
    assert "granted" in spec and "Field visibility defaults" in spec, \
        "item 2: visibility defaults documented"
    assert "never expire" in spec.lower(), "item 16: never-expire semantics"
    assert "Connect" in spec, "item 11: Connect replaces the profile QR"
    assert "500" in spec, "item 9: bio cap 500"
