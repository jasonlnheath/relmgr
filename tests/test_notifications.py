"""In-app notification center (2026-09-20): creation/read/unread lifecycle.

The center is the source of truth; email is the push. Pins the DB layer:
- create/list/count scoped to ONE owner (no cross-owner reads)
- dedupe_key idempotency: one row per grant, one per owner+quarter
- mark read (single + all), already-read and foreign-id no-ops
- quarterly sync raises exactly one prompt per quarter, only when grey
  contacts exist
"""
import os

import pytest

os.environ.setdefault("WHITELIST_SECRET", "test-secret")

from pathlib import Path

import whitelist_db


@pytest.fixture
def conn(tmp_path):
    db = tmp_path / "notif.db"
    c = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(c)
    whitelist_db.create_owner_profile(
        c, "owner1", "Owner One", "owner1@example.com", "password123")
    whitelist_db.create_owner_profile(
        c, "owner2", "Owner Two", "owner2@example.com", "password123")
    yield c
    c.close()


def _pid(conn, handle):
    return conn.execute(
        "SELECT id FROM profiles WHERE handle = ?", (handle,)).fetchone()["id"]


class TestCreateAndList:
    def test_create_returns_id_and_lists_newest_first(self, conn):
        owner = _pid(conn, "owner1")
        a = whitelist_db.create_notification(
            conn, owner, "connection_request", "first", grant_id="g-a",
            dedupe_key="grant:g-a")
        b = whitelist_db.create_notification(
            conn, owner, "quarterly", "second")
        assert a and b
        rows = whitelist_db.list_notifications(conn, owner)
        assert [r["id"] for r in rows] == [b, a]

    def test_unknown_kind_rejected(self, conn):
        owner = _pid(conn, "owner1")
        with pytest.raises(ValueError):
            whitelist_db.create_notification(conn, owner, "sms", "nope")

    def test_owner_isolation(self, conn):
        owner1, owner2 = _pid(conn, "owner1"), _pid(conn, "owner2")
        whitelist_db.create_notification(
            conn, owner1, "connection_request", "for one", dedupe_key="k1")
        assert whitelist_db.list_notifications(conn, owner2) == []
        assert whitelist_db.unread_notification_count(conn, owner2) == 0


class TestDedupe:
    def test_same_dedupe_key_never_duplicates(self, conn):
        owner = _pid(conn, "owner1")
        first = whitelist_db.create_notification(
            conn, owner, "connection_request", "request", grant_id="g1",
            dedupe_key="grant:g1")
        again = whitelist_db.create_notification(
            conn, owner, "connection_request", "re-POST of same grant",
            grant_id="g1", dedupe_key="grant:g1")
        assert first is not None and again is None, \
            "a still-pending grant re-POST must not re-alert"
        assert len(whitelist_db.list_notifications(conn, owner)) == 1

    def test_null_dedupe_key_always_inserts(self, conn):
        owner = _pid(conn, "owner1")
        assert whitelist_db.create_notification(conn, owner, "quarterly", "a")
        assert whitelist_db.create_notification(conn, owner, "quarterly", "b")


class TestUnreadLifecycle:
    def test_mark_read_flips_count_exactly_once(self, conn):
        owner = _pid(conn, "owner1")
        nid = whitelist_db.create_notification(
            conn, owner, "connection_request", "hi", dedupe_key="k")
        assert whitelist_db.unread_notification_count(conn, owner) == 1
        assert whitelist_db.mark_notification_read(conn, owner, nid) is True
        assert whitelist_db.unread_notification_count(conn, owner) == 0
        assert whitelist_db.mark_notification_read(conn, owner, nid) is False, \
            "re-mark must be a no-op"
        assert whitelist_db.unread_notification_count(conn, owner) == 0

    def test_foreign_or_unknown_id_is_noop(self, conn):
        owner1, owner2 = _pid(conn, "owner1"), _pid(conn, "owner2")
        nid = whitelist_db.create_notification(
            conn, owner1, "connection_request", "private", dedupe_key="k")
        assert whitelist_db.mark_notification_read(conn, owner2, nid) is False
        assert whitelist_db.mark_notification_read(conn, owner2, 424242) is False
        assert whitelist_db.unread_notification_count(conn, owner1) == 1

    def test_mark_all_read(self, conn):
        owner = _pid(conn, "owner1")
        for i in range(3):
            whitelist_db.create_notification(conn, owner, "quarterly", f"n{i}")
        assert whitelist_db.mark_all_notifications_read(conn, owner) == 3
        assert whitelist_db.unread_notification_count(conn, owner) == 0
        assert whitelist_db.mark_all_notifications_read(conn, owner) == 0

    def test_read_rows_stay_listed(self, conn):
        owner = _pid(conn, "owner1")
        nid = whitelist_db.create_notification(conn, owner, "forward", "fwd")
        whitelist_db.mark_notification_read(conn, owner, nid)
        rows = whitelist_db.list_notifications(conn, owner)
        assert len(rows) == 1 and rows[0]["read_at"] is not None


class TestQuarterlySync:
    def test_no_grey_contacts_no_notification(self, conn):
        owner = _pid(conn, "owner1")
        assert whitelist_db.sync_quarterly_notifications(conn, owner) is None
        assert whitelist_db.list_notifications(conn, owner) == []

    def test_grey_contacts_raise_one_prompt_per_quarter(self, conn):
        owner = _pid(conn, "owner1")
        conn.execute(
            """INSERT INTO access_grants (id, profile_id, requester_email,
               requester_name, status, expires_at)
               VALUES ('g-grey', ?, 'grey@example.com', 'Grey', 'granted',
                       '2020-01-01T00:00:00Z')""", (owner,))
        conn.commit()
        first = whitelist_db.sync_quarterly_notifications(conn, owner)
        assert first is not None
        assert "Quarterly review" in \
            whitelist_db.get_notification(conn, owner, first)["title"]
        again = whitelist_db.sync_quarterly_notifications(conn, owner)
        assert again is None, "idempotent per owner+quarter (dashboard calls this on every render)"
        assert len(whitelist_db.list_notifications(conn, owner)) == 1


class TestFreshDbBootsToSchema:
    def test_empty_file_gets_notifications_table(self, tmp_path):
        db = tmp_path / "fresh.db"
        c = whitelist_db.wl_connect(db)
        whitelist_db.wl_init(c)
        tables = {r["name"] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        assert "notifications" in tables
        c.close()
