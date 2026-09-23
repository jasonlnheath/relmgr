"""UX pass 1 (2026-09-22 captain walk-through) — regression pins.

Covers:
- Style ruling: NO green or red buttons — approve/deny wear slate gray
- Card editor: ✕ deletes a field from the card IMMEDIATELY (route + link)
- Card deletion copy: holders keep the vCard (normal vCard, badge gone)
- Contact list: clicking a contact opens their card; both cards visible
  as chips on the row; fast A–Z filter rail (?letter=, prefix filter)
- Contact detail: ONE card at a time with a chip switcher (?card=)
- Public profile: owner sees '← Back to My Profile', strangers never do
- Public profile: reach-me renders ONE ROW PER CARD with that card's photo
- My Profile: no title/company line; chooser copy per spec; bio maxlength
- Owner share sheet: shows the ACTUAL card below the QR/link; forward
  fallback (email/SMS) where the Web Share API is missing
"""
import os
from html.parser import HTMLParser
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import _make_session_cookie, create_app


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


def _owner_session_client(client: TestClient):
    client.cookies.set("wl_session", _make_session_cookie(1, b"test-secret"))
    return client


# ---------------------------------------------------------------
# DOM-lite parser (pairing-review F4): structural assertions instead
# of strings-anywhere. stdlib only — no bs4 in .venv.
# ---------------------------------------------------------------

class _DomLite(HTMLParser):
    """Collects: nested-form violations, wl-card row blocks (anchors +
    chip spans per row). Div-stack based; void tags ignored."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.form_depth = 0
        self.nested_form_actions = []
        self.div_stack = []          # class attr of each open div
        self.row_idx = []            # indices into self.rows (open wl-cards)
        self.rows = []               # {anchors: [{cls,href,text}], chips: [text]}
        self._anchor = None
        self._chip = None

    def _in_row(self):
        return self.row_idx[-1] if self.row_idx else None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class") or ""
        if tag == "form":
            if self.form_depth:
                self.nested_form_actions.append(a.get("action", ""))
            self.form_depth += 1
        elif tag == "div":
            self.div_stack.append(cls)
            if "wl-card" in cls and "p-3" in cls:
                self.rows.append({"anchors": [], "chips": []})
                self.row_idx.append(len(self.rows) - 1)
        elif tag == "a":
            self._anchor = {"cls": cls, "href": a.get("href", ""), "text": ""}
        elif tag == "span" and "text-[10px]" in cls and self._in_row() is not None:
            self._chip = ""

    def handle_data(self, data):
        if self._anchor is not None:
            self._anchor["text"] += data
        if self._chip is not None:
            self._chip += data

    def handle_endtag(self, tag):
        if tag == "form":
            self.form_depth = max(0, self.form_depth - 1)
        elif tag == "a":
            if self._anchor is not None and self._in_row() is not None:
                self.rows[self._in_row()]["anchors"].append(self._anchor)
            self._anchor = None
        elif tag == "span":
            if self._chip is not None and self._in_row() is not None:
                self.rows[self._in_row()]["chips"].append(self._chip.strip())
            self._chip = None
        elif tag == "div" and self.div_stack:
            cls = self.div_stack.pop()
            if "wl-card" in cls and "p-3" in cls and self.row_idx:
                self.row_idx.pop()


def _parse_rows(html: str):
    p = _DomLite()
    p.feed(html)
    return p


def _assert_no_nested_forms(html: str, label: str):
    p = _DomLite()
    p.feed(html)
    assert not p.nested_form_actions, (
        f"{label}: nested <form> elements are invalid HTML and the browser "
        f"re-targets the inner submit to the outer form: "
        f"{p.nested_form_actions}")


# ============================================================
# Style ruling: no green/red buttons
# ============================================================

class TestGrayButtonRuling:
    def test_approve_and_deny_classes_use_slate(self):
        css = (Path(__file__).parent.parent / "templates" / "base.html").read_text()
        approve = css.split(".wl-btn-approve {", 1)[1].split("}", 1)[0]
        deny = css.split(".wl-btn-deny {", 1)[1].split("}", 1)[0]
        for block in (approve, deny):
            assert "--wl-btn-slate" in block, "buttons must wear the default gray"
            assert "--wl-success" not in block and "--wl-danger" not in block, \
                "no green/red buttons anywhere (captain ruling 2026-09-22)"

    def test_share_icon_is_not_emoji_red(self):
        html = (Path(__file__).parent.parent / "templates" / "my_profile.html").read_text()
        assert "📤" not in html, "the outbox emoji renders red — use an ink SVG icon"
        assert 'stroke="currentColor"' in html

    def test_editor_action_buttons_use_default_gray(self):
        html = (Path(__file__).parent.parent / "templates" / "card_editor.html").read_text()
        assert 'wl-btn-approve px-3 py-1.5' not in html.replace("\n", ""), \
            "photo save button must be the default gray (wl-btn-ink)"
        # UX pass 3: the cropper is slot-aware — class-based save buttons.
        assert 'class="photo-save wl-btn-ink px-3 py-1.5 rounded text-xs"' in html


# ============================================================
# Card editor: immediate ✕ field deletion
# ============================================================

class TestImmediateFieldDelete:
    def test_delete_route_unlinks_field_from_card(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        card_id = conn.execute("SELECT id FROM cards LIMIT 1").fetchone()[0]
        whitelist_db.save_card_editor(
            conn, card_id, new_fields=[("phone", "+1-555-9999", "private")])
        row = conn.execute(
            "SELECT field_id FROM card_fields WHERE card_id = ? LIMIT 1",
            (card_id,)).fetchone()
        fid = row["field_id"] if isinstance(row, dict) or hasattr(row, "keys") else row[0]
        conn.close()

        r = client.post(f"/owner/{_owner_token()}/cards/{card_id}/fields/{fid}/delete",
                        follow_redirects=False)
        assert r.status_code == 303, "delete should redirect back to the editor"

        conn = whitelist_db.wl_connect(db)
        link = conn.execute(
            "SELECT * FROM card_fields WHERE card_id = ? AND field_id = ?",
            (card_id, fid)).fetchone()
        field = conn.execute(
            "SELECT * FROM profile_fields WHERE id = ?", (fid,)).fetchone()
        conn.close()
        assert link is None, "✕ must unlink the field from the card immediately"
        assert field is not None, "profile_fields row survives (cards are lenses)"

    def test_delete_route_rejects_foreign_field(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        card_id = conn.execute("SELECT id FROM cards LIMIT 1").fetchone()[0]
        conn.close()
        r = client.post(f"/owner/{_owner_token()}/cards/{card_id}/fields/999999/delete")
        assert r.status_code == 404

    def test_editor_rows_carry_x_button_no_checkbox(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        card_id = conn.execute("SELECT id FROM cards LIMIT 1").fetchone()[0]
        whitelist_db.save_card_editor(
            conn, card_id, new_fields=[("phone", "+1-555-9999", "private")])
        conn.close()
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        assert ">✕</button>" in html, "field rows must carry the immediate ✕"
        assert "field_1_remove" not in html, "the remove-checkbox pile-up is gone"


# ============================================================
# Card deletion semantics (captain ruling)
# ============================================================

class TestDeleteCardSemanticsCopy:
    def test_confirm_copy_explains_vcard_semantics(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        card_id = conn.execute("SELECT id FROM cards LIMIT 1").fetchone()[0]
        conn.close()
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        assert "normal vCard" in html, "must say holders keep the vCard"
        assert "badge" in html, "must say the badge disappears"


# ============================================================
# Contact list: click-to-open, card chips, A–Z rail
# ============================================================

def _granted_client(tmp_path, n_contacts=3):
    """Owner + granted contacts, contacts-mode (store.py table present);
    returns (client, token, grant_ids)."""
    db = _make_db(tmp_path)
    import store
    store.init_db(db)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    grant_ids = []
    names = ["Alice Anderson", "Bob Brown", "Carol Clark"]
    for i in range(n_contacts):
        gid = whitelist_db.create_grant(conn, 1, f"p{i}@example.com", names[i])
        grant_ids.append(gid)
        whitelist_db.set_badge_state(conn, gid, "whitelist")
    conn.commit()
    conn.close()
    client = TestClient(create_app(db))
    token = _owner_token()
    return client, token, grant_ids


class TestContactListClickAndChips:
    def test_contact_name_links_to_detail(self, tmp_path):
        client, token, grant_ids = _granted_client(tmp_path)
        html = client.get(f"/owner/{token}").text
        assert f"/owner/{token}/contact/{grant_ids[0]}" in html, \
            "clicking a contact must open their information"
        assert "View Contact →" not in html, "redundant link removed"

    def test_row_per_card_ruling(self, tmp_path):
        """Captain ruling 2026-09-22: ONE ROW PER CARD — a contact with two
        cards appears twice in the list, once per card."""
        client, token, grant_ids = _granted_client(tmp_path)
        conn = whitelist_db.wl_connect(tmp_path / "test.db")
        gid = grant_ids[0]
        card_ids = [r["id"] for r in conn.execute(
            "SELECT id FROM cards ORDER BY id LIMIT 2")]
        for cid in card_ids:
            conn.execute("INSERT INTO grant_cards (grant_id, card_id) VALUES (?, ?)",
                         (gid, cid))
        conn.commit()
        conn.close()
        html = client.get(f"/owner/{token}").text
        dom = _parse_rows(html)
        # structural: exactly two ROW blocks carry a whole-row overlay link
        # (UX pass 3: ONE clickable row — the overlay anchor has no text,
        # its class is 'absolute inset-0 …'), each deep-linking its own
        # card, each chipped with that card's name
        name_rows = [r for r in dom.rows
                     if any("absolute inset-0" in a["cls"] and
                            f"/owner/{token}/contact/{grant_ids[0]}" in a["href"]
                            for a in r["anchors"])]
        assert len(name_rows) == 2, \
            f"one row per card: expected 2 whole-row links for the contact, got {len(name_rows)}"
        linked_cards = set()
        for row in name_rows:
            card_qs = [a["href"] for a in row["anchors"] if "?card=" in a["href"]]
            assert len(card_qs) == 1, "each per-card row deep-links one card"
            linked_cards.add(card_qs[0].rsplit("card=", 1)[-1])
            assert row["chips"], "each per-card row carries its card-name chip"
        assert linked_cards == {str(c) for c in card_ids}, \
            "the two rows deep-link the two different cards"

    def test_row_shows_its_card_chip(self, tmp_path):
        client, token, grant_ids = _granted_client(tmp_path)
        conn = whitelist_db.wl_connect(tmp_path / "test.db")
        gid = grant_ids[0]
        card = conn.execute(
            "SELECT id, name FROM cards ORDER BY id LIMIT 1").fetchone()
        conn.execute("INSERT INTO grant_cards (grant_id, card_id) VALUES (?, ?)",
                     (gid, card["id"]))
        conn.commit()
        conn.close()
        html = client.get(f"/owner/{token}").text
        dom = _parse_rows(html)
        # the chip sits IN the row whose link deep-links this card — not
        # merely 'somewhere on the page'
        target = [r for r in dom.rows
                  if any(a["href"].endswith(f"?card={card['id']}")
                         for a in r["anchors"])]
        assert len(target) == 1, "exactly one row deep-links this card"
        assert card["name"] in target[0]["chips"], \
            "that row's chip is the card's name"


class TestBadgeToggleCopyRuling:
    def test_toggle_says_blacklist_never_blocked(self, tmp_path):
        """Captain ruling 2026-09-22: the toggle confirmation must say
        'BlackList' (the list name), never the internal 'blocked'."""
        client, token, grant_ids = _granted_client(tmp_path)
        # make one contact grey (granted with quarter expiry) — its next
        # toggle target is blocked/BlackList
        conn = whitelist_db.wl_connect(tmp_path / "test.db")
        whitelist_db.set_badge_state(conn, grant_ids[0], "greylist")
        conn.commit()
        conn.close()
        html = client.get(f"/owner/{token}").text
        assert "Click to change to BlackList" in html, \
            "grey rows toggle to BlackList"
        assert "Click to change to Blocked" not in html
        assert "Click to change to GreyList" in html
        # a blacklisted row toggles back with the list name, not 'whitelist'
        conn = whitelist_db.wl_connect(tmp_path / "test.db")
        whitelist_db.set_badge_state(conn, grant_ids[1], "blocked")
        conn.commit()
        conn.close()
        html = client.get(f"/owner/{token}").text
        assert "Click to change to WhiteList" in html


class TestAlphabeticalRail:
    def test_letter_filter_keeps_only_matching_initial(self, tmp_path):
        client, token, _ = _granted_client(tmp_path)
        html = client.get(f"/owner/{token}?letter=A").text
        assert "Alice Anderson" in html
        assert "Bob Brown" not in html, "?letter=A must drop non-A initials"
        assert "Carol Clark" not in html

    def test_rail_offers_present_letters_only(self, tmp_path):
        client, token, _ = _granted_client(tmp_path)
        html = client.get(f"/owner/{token}").text
        assert 'aria-label="Filter by A"' in html
        assert 'aria-label="Filter by B"' in html
        assert 'aria-label="Filter by Q"' not in html, \
            "letters with no entries must not be clickable"
        assert ">Q</span>" in html, "empty letters render dimmed"

    def test_active_letter_clears_on_click(self, tmp_path):
        client, token, _ = _granted_client(tmp_path)
        html = client.get(f"/owner/{token}?letter=A").text
        assert 'Clear letter filter' in html


# ============================================================
# Contact detail: ONE card + switcher
# ============================================================

class TestContactDetailOneCard:
    def test_detail_renders_switcher_and_selected_card(self, tmp_path):
        client, token, grant_ids = _granted_client(tmp_path)
        conn = whitelist_db.wl_connect(tmp_path / "test.db")
        card_ids = [r["id"] for r in conn.execute("SELECT id FROM cards ORDER BY id")]
        conn.close()
        html = client.get(f"/owner/{token}/contact/{grant_ids[0]}").text
        # every profile card has a switch link targeting THIS grant
        for cid in card_ids:
            assert f"/owner/{token}/contact/{grant_ids[0]}?card={cid}" in html, \
                "multi-card contacts need a chip per card"

    def test_detail_card_query_param_selects_card(self, tmp_path):
        client, token, grant_ids = _granted_client(tmp_path)
        conn = whitelist_db.wl_connect(tmp_path / "test.db")
        # UX pass 3: default pair is Personal (id 1) + Work (id 2); Work
        # carries the seeded title/company fields.
        card_ids = [r["id"] for r in conn.execute("SELECT id FROM cards ORDER BY id")]
        conn.close()
        identity_id, other_id = card_ids[-1], card_ids[0]
        html = client.get(f"/owner/{token}/contact/{grant_ids[0]}?card={identity_id}").text
        # the ACTIVE chip (slate fill) is the selected card — others are not
        import re as _re
        chips = _re.findall(
            r'<a href="([^"]*card=(\d+))"[^>]*style="([^"]*)"', html)
        style_by_card = {cid: style for href, cid, style in chips}
        assert str(identity_id) in style_by_card
        assert "--wl-btn-slate" in style_by_card[str(identity_id)], \
            "selected chip must wear the active fill"
        assert "--wl-btn-slate" not in style_by_card[str(other_id)], \
            "non-selected chips must not"
        # the selected card's own fields render (Work carries title/company)
        assert "Sales" in html and "Walther EMC" in html

    def test_detail_photo_block_belongs_to_selected_card(self, tmp_path):
        client, token, grant_ids = _granted_client(tmp_path)
        conn = whitelist_db.wl_connect(tmp_path / "test.db")
        card_ids = [r["id"] for r in conn.execute("SELECT id FROM cards ORDER BY id")]
        conn.close()
        personal_id = card_ids[0]
        html = client.get(f"/owner/{token}/contact/{grant_ids[0]}?card={personal_id}").text
        # the selected card's picture block (initials circle for Personal —
        # no photo in fixture) sits with the card heading and its fields
        pos_initials = html.find(">PE</span>")
        pos_heading = html.find("Personal</h2>")
        pos_phone = html.find("555-1234")
        assert -1 not in (pos_initials, pos_heading, pos_phone)
        assert pos_initials < pos_heading < pos_phone, \
            "picture block, card heading and that card's fields render together"


# ============================================================
# Public profile: owner back-link + per-card reach-me rows
# ============================================================

class TestProfileViewBackLink:
    def test_owner_session_sees_back_link(self, tmp_path):
        db = _make_db(tmp_path)
        client = _owner_session_client(TestClient(create_app(db)))
        html = client.get("/p/jasonheath").text
        assert "← Back to My Profile" in html
        assert "/owner/" in html, "back link carries a fresh owner token"

    def test_owner_email_link_sees_back_link(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get("/p/jasonheath?e=jason@waltheremc.com").text
        assert "← Back to My Profile" in html

    def test_stranger_never_sees_back_link(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get("/p/jasonheath").text
        assert "Back to My Profile" not in html


class TestReachMeRowsPerCard:
    def test_reach_me_row_per_card_with_own_photo(self, tmp_path):
        """One row per card, each led by THAT card's picture, that card's
        icons following it — pinned by ordering, not substrings-anywhere."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get("/p/jasonheath?e=jason@waltheremc.com").text
        assert "Reach me" in html
        pos_reach = html.find("Reach me")
        # UX pass 3 card order: Personal first (phone icons, initials circle),
        # then Work (email icon) — each row led by THAT card's picture.
        pos_personal_initials = html.find(">PE</span>", pos_reach)
        pos_tel = html.find("tel:555-1234", pos_reach)
        pos_work_initials = html.find(">WO</span>", pos_reach)
        pos_mailto = html.find("mailto:", pos_reach)
        assert -1 not in (pos_personal_initials, pos_tel, pos_work_initials, pos_mailto), \
            "both reachable cards render a row"
        assert pos_reach < pos_personal_initials < pos_tel < pos_work_initials < pos_mailto, \
            "each card's picture leads its own row; icons follow their picture"
        # no third initials circle after the Work row (no other reachable card)
        assert html.find(">PE</span>", pos_work_initials) == -1


# ============================================================
# My Profile: header, chooser copy, bio limit
# ============================================================

class TestMyProfilePass:
    def test_header_has_no_title_line(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        assert "Sales at Walther EMC" not in html, \
            "title line removed — the bio carries what people need"

    def test_unified_share_per_spec(self, tmp_path):
        """UX pass 3: the chooser is GONE — the QR sits between the name
        and the Share button, and Share fires the native share popup."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        assert 'src="/qr/jasonheath"' in html, "QR renders on My Profile"
        assert 'id="share-button"' in html
        assert "navigator.share" in html, "native share popup is the primary path"
        assert "Choose the cards you want to share." not in html

    def test_bio_has_live_maxlength(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        assert 'maxlength="500"' in html, "live prune while typing (UX pass 2 cap)"
        assert 'id="bio-count"' in html

    def test_back_to_contact_list_link(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        html = client.get(f"/owner/{_owner_token()}/profile").text
        assert f'href="/owner/{_owner_token()}"' in html

    def test_bio_over_limit_still_rejected_server_side(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        r = client.post(f"/owner/{_owner_token()}/bio", data={"bio": "x" * 501})
        assert r.status_code == 400, "server-side limit stays (client maxlength is UX only)"


# ============================================================
# Pairing-review F1 guard: no nested <form> anywhere it renders
# ============================================================

class TestNoNestedForms:
    def test_card_editor_renders_without_nested_forms(self, tmp_path):
        """F1 regression guard: nested <form>s are invalid HTML — the
        browser re-targets the inner submit to the outer form, which is
        exactly how the ✕ silently became a card-save. Route-level POST
        tests cannot catch this; this parse can."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        conn = whitelist_db.wl_connect(db)
        card_id = conn.execute("SELECT id FROM cards LIMIT 1").fetchone()[0]
        whitelist_db.save_card_editor(
            conn, card_id, new_fields=[("phone", "+1-555-9999", "private")])
        conn.close()
        html = client.get(f"/owner/{_owner_token()}/cards/{card_id}/edit").text
        _assert_no_nested_forms(html, "card editor")
        # and the ✕ is a submit override ON the outer form, not a nested one
        assert 'formaction="/owner/' in html and "fields/" in html

    def test_other_pass_surfaces_render_without_nested_forms(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        _assert_no_nested_forms(client.get(f"/owner/{tok}").text, "contact list")
        _assert_no_nested_forms(client.get(f"/owner/{tok}/profile").text, "my profile")
        _assert_no_nested_forms(client.get("/p/jasonheath").text, "public profile")


# ============================================================
# Owner share sheet: actual card + forward fallback
# ============================================================

def _share_client(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    card_ids = [r["id"] for r in conn.execute("SELECT id FROM cards ORDER BY id LIMIT 1")]
    bundle = whitelist_db.create_share_bundle(conn, 1, card_ids)
    conn.commit()
    conn.close()
    client = TestClient(create_app(db))
    return client, _owner_token(), bundle["id"]


# ============================================================
# Unified sharing (UX pass 3): the chooser page is RETIRED. The share
# surface is My Profile itself (QR + native Share button + standard
# fallbacks). Legacy /s/{bundle_id} links keep rendering for recipients.
# ============================================================

class TestOwnerShareSheet:
    def test_share_chooser_routes_retired(self, tmp_path):
        client, token, bundle_id = _share_client(tmp_path)
        assert client.post(f"/owner/{token}/share").status_code in (404, 405)
        assert client.get(f"/owner/{token}/share/{bundle_id}").status_code == 404

    def test_my_profile_carries_qr_native_share_and_fallbacks(self, tmp_path):
        client, token, bundle_id = _share_client(tmp_path)
        html = client.get(f"/owner/{token}/profile").text
        assert 'src="/qr/jasonheath"' in html, "QR above the Share button"
        assert 'id="share-button"' in html
        assert 'id="share-fallback"' in html, "copy link / email / SMS fallback"
        assert 'id="share-copy"' in html, "copy link"
        assert "mailto:" in html, "forward via email"
        assert "sms:" in html, "forward via messaging"
        assert "navigator.share" in html, "Web Share API stays the primary path"

    def test_legacy_bundle_link_still_renders(self, tmp_path):
        client, token, bundle_id = _share_client(tmp_path)
        resp = client.get(f"/s/{bundle_id}")
        assert resp.status_code == 200, "already-shared links keep working"
        assert "Save to contacts" in resp.text
