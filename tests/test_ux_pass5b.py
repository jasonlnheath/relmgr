"""UX pass 5, package B (2026-09-25 captain feedback).

Pins:
- Card preview: EVERY field row (populated or not) carries an ✕ on the
  right that removes the field from the card immediately — the narrow
  unlink (card_fields link row goes, profile_fields row survives), never
  the editor's apply-full-body route (an empty editor body would blank
  the profile name columns — the pass-2 data-loss bug class)
- IDOR: foreign card / foreign field → 404, fail closed
- Contact list search: ✕ clear button at the right of the bar (aria
  labelled, hidden when empty), ONE #list-region swapped live per
  keystroke (no Enter required), Tab order input → ✕ → +
- Search still filters server-side via ?q= (the live fetch targets the
  same GET)
- My Profile Share button: navigator.share wiring with name+link payload
  and the copy-link / mailto: / sms: fallback row
"""
import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


def _make_db(tmp_path: Path) -> Path:
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
    conn.commit()
    conn.close()
    return db


def _owner_token(payload="1"):
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", payload,
                                expires_days=365)


def _add_field(db: Path, profile_id: int, field_type: str, value: str,
               visibility: str = "granted") -> int:
    conn = whitelist_db.wl_connect(db)
    cur = conn.execute(
        "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
        (profile_id, field_type, value, visibility),
    )
    fid = cur.lastrowid
    conn.commit()
    conn.close()
    return fid


def _link_field(db: Path, card_id: int, field_id: int) -> None:
    conn = whitelist_db.wl_connect(db)
    conn.execute("INSERT INTO card_fields (card_id, field_id) VALUES (?, ?)",
                 (card_id, field_id))
    conn.commit()
    conn.close()


def _first_card_id(db: Path, owner_id: int = 1) -> int:
    conn = whitelist_db.wl_connect(db)
    cid = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = ? ORDER BY id LIMIT 1",
        (owner_id,),
    ).fetchone()[0]
    conn.close()
    return cid


def _field_ids_on_card(db: Path, card_id: int) -> list[int]:
    conn = whitelist_db.wl_connect(db)
    ids = [r[0] for r in conn.execute(
        "SELECT field_id FROM card_fields WHERE card_id = ?", (card_id,))]
    conn.close()
    return ids


# ============================================================
# Card preview: per-field kill-x (populated or not)
# ============================================================

class TestPreviewFieldKillX:
    def test_every_row_has_x_populated_or_not(self, tmp_path):
        db = _make_db(tmp_path)
        card_id = _first_card_id(db)
        f_populated = _add_field(db, 1, "phone", "555-9876")
        f_empty = _add_field(db, 1, "note", "")  # empty value — still a row
        _link_field(db, card_id, f_populated)
        _link_field(db, card_id, f_empty)
        client = TestClient(create_app(db))
        token = _owner_token()

        resp = client.get(f"/owner/{token}/profile/card/{card_id}")
        assert resp.status_code == 200
        # One delete action per field row — exactly as many as the card
        # carries, INCLUDING the empty-value note row (populated or not;
        # the count is relative because the seed may link its own fields).
        assert resp.text.count("/preview/fields/") == len(_field_ids_on_card(db, card_id))
        assert f"/preview/fields/{f_populated}/delete" in resp.text
        assert f"/preview/fields/{f_empty}/delete" in resp.text

    def test_x_removes_field_from_card_and_survives_profile_field(self, tmp_path):
        db = _make_db(tmp_path)
        card_id = _first_card_id(db)
        fid = _add_field(db, 1, "email", "preview@x.com")
        _link_field(db, card_id, fid)
        client = TestClient(create_app(db))
        token = _owner_token()

        resp = client.post(f"/owner/{token}/cards/{card_id}/preview/fields/{fid}/delete",
                           follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == f"/owner/{token}/profile/card/{card_id}"

        # The link row is gone, the profile_fields row SURVIVES
        assert fid not in _field_ids_on_card(db, card_id)
        conn = whitelist_db.wl_connect(db)
        row = conn.execute(
            "SELECT field_value FROM profile_fields WHERE id = ?", (fid,)).fetchone()
        conn.close()
        assert row is not None and row[0] == "preview@x.com"

        # And the preview no longer renders THAT row's delete action
        resp = client.get(f"/owner/{token}/profile/card/{card_id}")
        assert f"/preview/fields/{fid}/delete" not in resp.text

    def test_x_never_blanks_profile_name_columns(self, tmp_path):
        """The preview ✕ must NOT ride through save_card_editor: an absent
        editor form would blank first_name/last_name (step 0 of
        save_card_editor writes submitted name components)."""
        db = _make_db(tmp_path)
        card_id = _first_card_id(db)
        fid = _add_field(db, 1, "phone", "555-0000")
        _link_field(db, card_id, fid)
        client = TestClient(create_app(db))
        token = _owner_token()

        # Seed explicit name components — the preview ✕ must leave them
        # exactly as they are.
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "UPDATE profiles SET first_name = 'Jason', last_name = 'Heath' WHERE id = 1")
        conn.commit()
        conn.close()

        client.post(f"/owner/{token}/cards/{card_id}/preview/fields/{fid}/delete")

        conn = whitelist_db.wl_connect(db)
        row = conn.execute(
            "SELECT first_name, last_name, display_name FROM profiles WHERE id = 1"
        ).fetchone()
        conn.close()
        assert row["first_name"] == "Jason"
        assert row["last_name"] == "Heath"
        assert row["display_name"] == "Jason Heath"

    def test_foreign_card_404(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('otherco','Other Co')")
        conn.execute(
            "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility, created_at, updated_at)"
            " VALUES (2, 'email', 'other@x.com', 'granted', datetime('now'), datetime('now'))")
        conn.commit()
        conn.close()
        intruder_card = whitelist_db.create_card(whitelist_db.wl_connect(db), 2,
                                                 "Intruder", [])
        fid = _add_field(db, 2, "phone", "555-1111")
        _link_field(db, intruder_card["id"], fid)

        client = TestClient(create_app(db))
        token = _owner_token()  # owner 1
        resp = client.post(
            f"/owner/{token}/cards/{intruder_card['id']}/preview/fields/{fid}/delete")
        assert resp.status_code == 404
        # Untouched
        assert fid in _field_ids_on_card(db, intruder_card["id"])

    def test_foreign_field_404(self, tmp_path):
        db = _make_db(tmp_path)
        card_id = _first_card_id(db)
        # A field owned by ANOTHER profile, never linked to this card
        conn = whitelist_db.wl_connect(db)
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('otherco','Other Co')")
        conn.commit()
        conn.close()
        foreign_fid = _add_field(db, 2, "phone", "555-2222")

        client = TestClient(create_app(db))
        token = _owner_token()
        resp = client.post(
            f"/owner/{token}/cards/{card_id}/preview/fields/{foreign_fid}/delete")
        assert resp.status_code == 404

    def test_unknown_field_404(self, tmp_path):
        db = _make_db(tmp_path)
        card_id = _first_card_id(db)
        client = TestClient(create_app(db))
        token = _owner_token()
        resp = client.post(
            f"/owner/{token}/cards/{card_id}/preview/fields/999999/delete")
        assert resp.status_code == 404

    def test_data_layer_remove_card_field(self, tmp_path):
        db = _make_db(tmp_path)
        card_id = _first_card_id(db)
        fid = _add_field(db, 1, "city", "Greenfield")
        _link_field(db, card_id, fid)
        conn = whitelist_db.wl_connect(db)

        out = whitelist_db.remove_card_field(conn, card_id, fid)
        assert all(f["id"] != fid for f in out["fields"])
        # profile_fields row survives
        row = conn.execute(
            "SELECT field_value FROM profile_fields WHERE id = ?", (fid,)).fetchone()
        assert row is not None and row[0] == "Greenfield"

        # Unknown card → ValueError
        try:
            whitelist_db.remove_card_field(conn, 999999, fid)
            raised = False
        except ValueError:
            raised = True
        assert raised

        # Field owned by another profile → ValueError (IDOR, fail closed)
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES ('otherco','Other Co')")
        conn.commit()
        foreign_fid = _add_field(db, 2, "phone", "555-3333")
        try:
            whitelist_db.remove_card_field(conn, card_id, foreign_fid)
            raised = False
        except ValueError:
            raised = True
        assert raised
        conn.close()


# ============================================================
# Contact list search: clear ✕, live-filter region
# ============================================================

class TestSearchLiveFilter:
    def _client_with_contacts(self, tmp_path):
        import store
        db = _make_db(tmp_path)
        store.init_db(db)
        store.upsert_contact({
            "id": "c1", "normalized_name": "Alice Smith",
            "first_name": "Alice", "last_name": "Smith",
            "emails": ["alice@test.com"], "phones": ["555-0001"],
            "organizations": [], "sources": [],
        }, db_path=db)
        store.upsert_contact({
            "id": "c2", "normalized_name": "Bob Jones",
            "first_name": "Bob", "last_name": "Jones",
            "emails": ["bob@test.com"], "phones": ["555-0002"],
            "organizations": [], "sources": [],
        }, db_path=db)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        conn.commit()
        conn.close()
        client = TestClient(create_app(db))
        return client, _owner_token()

    def test_clear_button_present_and_aria_labelled(self, tmp_path):
        client, token = self._client_with_contacts(tmp_path)
        token = _owner_token()
        resp = client.get(f"/owner/{token}")
        assert resp.status_code == 200
        assert "id=\"search-clear\"" in resp.text
        assert "Clear search" in resp.text
        # Hidden (not rendered visible) when the query is empty…
        tag = resp.text.split("id=\"search-clear\"")[1][:400]
        assert "hidden" in tag
        # …and revealed once a query rides in.
        resp = client.get(f"/owner/{token}?q=Alice")
        tag = resp.text.split("id=\"search-clear\"")[1][:400]
        assert "hidden" not in tag

    def test_list_region_wraps_query_dependent_output(self, tmp_path):
        client, token = self._client_with_contacts(tmp_path)
        resp = client.get(f"/owner/{token}")
        assert "id=\"list-region\"" in resp.text
        # The region opens before the rows and closes after pagination
        region_start = resp.text.index("list-region")
        assert "Alice Smith" in resp.text[region_start:]

    def test_q_still_filters_server_side(self, tmp_path):
        client, token = self._client_with_contacts(tmp_path)
        resp = client.get(f"/owner/{token}?q=Alice")
        assert resp.status_code == 200
        assert "Alice Smith" in resp.text
        assert "Bob Jones" not in resp.text

    def test_live_filter_script_wiring(self, tmp_path):
        client, token = self._client_with_contacts(tmp_path)
        resp = client.get(f"/owner/{token}")
        assert "input.addEventListener" in resp.text
        assert "history.replaceState" in resp.text
        # The no-JS GET form remains the fallback
        assert "action=\"/owner/" in resp.text

    def test_q_filters_pure_whitelist_mode(self, tmp_path):
        """UX pass 5: no contacts table (pure-whitelist mode) — the search
        box must still filter; it used to silently do nothing there."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        for n, em in [("Alice Smith", "alice@x.com"), ("Bob Jones", "bob@x.com")]:
            gid = whitelist_db.create_grant(conn, 1, em, n)
            whitelist_db.apply_decision(conn, gid, "approve", "permanent")
        conn.commit()
        conn.close()
        # NO store.init_db — the contacts table stays absent.
        client = TestClient(create_app(db))
        token = _owner_token()
        resp = client.get(f"/owner/{token}?q=Ali")
        assert resp.status_code == 200
        assert "Alice Smith" in resp.text
        assert "Bob Jones" not in resp.text


# ============================================================
# My Profile share button: Web Share API + fallback row
# ============================================================

class TestShareButton:
    def test_share_button_wiring_and_fallback(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        token = _owner_token()
        resp = client.get(f"/owner/{token}/profile")
        assert resp.status_code == 200
        assert "id=\"share-button\"" in resp.text
        assert "data-share-url" in resp.text
        # Native hand-off (Web Share API) with the card's name + link
        assert "navigator.share" in resp.text
        assert "/p/jasonheath" in resp.text
        # Fallback where unavailable: copy link + explicit sms:/mailto:
        assert "id=\"share-fallback\"" in resp.text
        assert "id=\"share-copy\"" in resp.text
        assert "mailto:" in resp.text
        assert "sms:" in resp.text
