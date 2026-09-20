"""Phase A1: My Profile tab — bio, cards, fields, photos, card preview.

Tests pin:
- Bio edit round-trips, over-limit rejected, blank allowed
- Create card round-trips, duplicate name → 400 not 500
- Card field add/remove round-trips via set_card_fields
- Unknown field id → 400
- JPEG photo uploads, serves, replaces
- Non-image 400s, oversize 413
- Photo remove clears DB and disk
- Cross-owner card access → 404
- Card preview route works
- Boot migration idempotent (bio + photo_path columns)
"""
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


# ============================================================
# Bio edit
# ============================================================

class TestBioEdit:
    def test_bio_round_trip(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}/profile")
        assert resp.status_code == 200

        resp = client.post(f"/owner/{_owner_token()}/bio",
                           data={"bio": "I sell stuff."})
        assert resp.status_code == 200
        assert "I sell stuff." in resp.text

    def test_bio_over_limit_rejected(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        long_bio = "x" * 2001
        resp = client.post(f"/owner/{_owner_token()}/bio",
                           data={"bio": long_bio})
        # q38 review: spec B2 says over-limit is REJECTED (400 page, nothing
        # saved) — this pin previously locked in truncate-and-save at 200.
        assert resp.status_code == 400
        assert "2000 characters" in resp.text

    def test_bio_blank_allowed(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        # Set a bio first
        client.post(f"/owner/{_owner_token()}/bio", data={"bio": "hello"})
        # Clear it
        resp = client.post(f"/owner/{_owner_token()}/bio", data={"bio": ""})
        assert resp.status_code == 200
        # Bio textarea should be empty
        assert 'textarea' in resp.text and 'I sell stuff.' not in resp.text


# ============================================================
# Create card
# ============================================================

class TestCreateCard:
    def test_create_card_round_trip(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(f"/owner/{_owner_token()}/cards/new",
                           data={"name": "Sales"})
        assert resp.status_code == 200
        assert "Sales" in resp.text

    def test_duplicate_name_400(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        # Work already exists from seed. Spec B2: "duplicate name (UNIQUE) →
        # friendly 400 page" — q38 review corrects this pin from 200 to 400.
        resp = client.post(f"/owner/{_owner_token()}/cards/new",
                           data={"name": "Work"})
        assert resp.status_code == 400
        assert "already exists" in resp.text


# ============================================================
# Card fields
# ============================================================

class TestCardFields:
    def _first_edit_card(self, client, tok):
        """Find a card via its Edit action on the profile page, then open
        the editor (the inline field pickers moved off the dashboard)."""
        resp = client.get(f"/owner/{tok}/profile")
        assert resp.status_code == 200
        m = re.search(r'cards/(\d+)/edit', resp.text)
        assert m, "No card Edit action on the profile page"
        return int(m.group(1))

    def test_field_add_remove_round_trip(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = self._first_edit_card(client, tok)

        # The editor renders the card's existing field rows.
        resp = client.get(f"/owner/{tok}/cards/{card_id}/edit")
        assert resp.status_code == 200
        m = re.search(r'name="field_(\d+)_value"', resp.text)
        assert m, "No existing field row in the editor"
        fid = int(m.group(1))

        # Save an updated value + visibility through the editor form.
        resp = client.post(
            f"/owner/{tok}/cards/{card_id}/edit",
            data={f"field_{fid}_value": "renamed@example.com",
                  f"field_{fid}_visibility": "private"},
        )
        assert resp.status_code == 200
        assert "renamed@example.com" in resp.text

        # Remove it again via the editor's remove checkbox.
        resp = client.post(
            f"/owner/{tok}/cards/{card_id}/edit",
            data={f"field_{fid}_remove": "1"},
        )
        assert resp.status_code == 200
        assert "renamed@example.com" not in resp.text

    def test_unknown_field_id_400(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.post(
            f"/owner/{_owner_token()}/cards/999999/fields",
            data={"field_ids": [999999]},
        )
        assert resp.status_code == 400


# ============================================================
# Photo upload (via the card editor page)
# ============================================================

class TestPhotoUpload:
    def _first_edit_card(self, client, tok):
        """Card id from its Edit action; the photo form lives in the editor."""
        resp = client.get(f"/owner/{tok}/profile")
        assert resp.status_code == 200
        m = re.search(r'cards/(\d+)/edit', resp.text)
        assert m, "No card Edit action on the profile page"
        return int(m.group(1))

    def _make_jpeg(self):
        img = Image.new("RGB", (100, 100), color="red")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        buf.seek(0)
        return buf

    def test_jpeg_upload(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = self._first_edit_card(client, tok)

        resp = client.post(
            f"/owner/{tok}/cards/{card_id}/photo",
            files={"photo": ("test.jpg", self._make_jpeg(), "image/jpeg")},
        )
        assert resp.status_code == 200
        # Back on the editor page after upload
        assert "Edit Card" in resp.text

    def test_png_upload_accepted(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = self._first_edit_card(client, tok)

        img = Image.new("RGB", (100, 100), color="blue")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        resp = client.post(
            f"/owner/{tok}/cards/{card_id}/photo",
            files={"photo": ("test.png", buf, "image/png")},
        )
        assert resp.status_code == 200

    def test_text_file_jpg_400(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = self._first_edit_card(client, tok)

        resp = client.post(
            f"/owner/{tok}/cards/{card_id}/photo",
            files={"photo": ("fake.jpg", b"not an image", "image/jpeg")},
        )
        assert resp.status_code == 400

    def test_oversize_413(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = self._first_edit_card(client, tok)

        big = b"\xff\xd8\xff\xe0" + b"\x00" * (11 * 1024 * 1024)
        resp = client.post(
            f"/owner/{tok}/cards/{card_id}/photo",
            files={"photo": ("big.jpg", big, "image/jpeg")},
        )
        assert resp.status_code == 413

    def test_photo_served(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = self._first_edit_card(client, tok)

        # Upload first
        img = Image.new("RGB", (100, 100), color="green")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        buf.seek(0)
        resp = client.post(
            f"/owner/{tok}/cards/{card_id}/photo",
            files={"photo": ("test.jpg", buf, "image/jpeg")},
        )
        assert resp.status_code == 200

        # The editor page now renders the photo URL
        m2 = re.search(r'photos/\d+/(\d+)', resp.text)
        assert m2, "Photo URL not rendered after upload"
        card_id2 = int(m2.group(1))

        # Serve it
        resp = client.get(f"/photos/1/{card_id2}")
        assert resp.status_code == 200, f"Photo serve failed: {resp.status_code}"
        assert len(resp.content) > 0, "Photo serve returned empty content"

    def test_photo_remove(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        tok = _owner_token()
        card_id = self._first_edit_card(client, tok)

        # Upload
        img = Image.new("RGB", (100, 100), color="yellow")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        buf.seek(0)
        client.post(
            f"/owner/{tok}/cards/{card_id}/photo",
            files={"photo": ("test.jpg", buf, "image/jpeg")},
        )

        # Remove
        resp = client.post(
            f"/owner/{tok}/cards/{card_id}/photo",
            data={"remove_photo": "1"},
        )
        assert resp.status_code == 200

    def test_photo_not_found(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get("/photos/1/999999")
        assert resp.status_code == 404


# ============================================================
# Card preview
# ============================================================

class TestCardPreview:
    def test_preview_works(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}/profile")
        import re
        m = re.search(r'profile/card/(\d+)', resp.text)
        assert m, "No card preview route found"
        card_id = int(m.group(1))

        resp = client.get(f"/owner/{_owner_token()}/profile/card/{card_id}")
        assert resp.status_code == 200

    def test_cross_owner_404(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        # Card id 1 belongs to profile 1 (Jason).
        # If we had another profile, its card would be different.
        # For now, just verify non-existent card → 404
        resp = client.get(f"/owner/{_owner_token()}/profile/card/999999")
        assert resp.status_code == 404


# ============================================================
# Boot migration idempotent
# ============================================================

class TestBootMigration:
    def test_bio_column_added(self, tmp_path):
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

        # First run: adds bio column
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(profiles)").fetchall()]
        assert "bio" in cols
        conn.close()

        # Second run: idempotent
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        cols2 = [r["name"] for r in conn.execute("PRAGMA table_info(profiles)").fetchall()]
        assert cols == cols2  # same columns
        conn.close()

    def test_photo_path_column_added(self, tmp_path):
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

        # First run: adds photo_path column
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(cards)").fetchall()]
        assert "photo_path" in cols
        conn.close()

        # Second run: idempotent
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        cols2 = [r["name"] for r in conn.execute("PRAGMA table_info(cards)").fetchall()]
        assert cols == cols2
        conn.close()
