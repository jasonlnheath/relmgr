"""Whitelist database layer — profiles, fields, access grants."""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

_ISO_Z = "%Y-%m-%dT%H:%M:%SZ"

# Password hashing — pbkdf2-hmac-sha256 (no external deps).
# Format: pbkdf2_sha256$<rounds>$<salt_hex>$<hash_hex>
_PWHASH_ROUNDS = 260_000  # OWASP 2023 recommendation for SHA-256


def hash_password(plain: str) -> str:
    """Hash a plaintext password. Returns a pbkdf2-hmac-sha256 string."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, _PWHASH_ROUNDS)
    salt_hex = salt.hex()
    hash_hex = dk.hex()
    return f"pbkdf2_sha256${_PWHASH_ROUNDS}${salt_hex}${hash_hex}"


def verify_password(plain: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored hash. Timing-safe."""
    try:
        prefix, rounds_s, salt_hex, hash_hex = stored_hash.split("$")
        if prefix != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, rounds)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime(_ISO_Z)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def quarter_end_iso(now: Optional[datetime] = None) -> str:
    """Return the last instant of the UTC calendar quarter containing *now*.

    Quarters: Q1 = Jan-Mar, Q2 = Apr-Jun, Q3 = Jul-Sep, Q4 = Oct-Dec.
    Format: %Y-%m-%dT%H:%M:%SZ (same as _now_iso).

    If *now* is None, uses current UTC time.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    # Quarters close on the last day of March / June / September / December.
    q = (now.month - 1) // 3 + 1
    end_month, last_day = ((3, 31), (6, 30), (9, 30), (12, 31))[q - 1]
    end = now.replace(month=end_month, day=last_day, hour=23, minute=59, second=59, microsecond=0)
    return end.strftime(_ISO_Z)


def is_current_quarter(value: Optional[str]) -> bool:
    """Return True if the timestamp falls in the same UTC calendar quarter as today.

    Contract:
    - None → False
    - Empty string → False
    - Same quarter → True
    - Different quarter → False

    This is NOT the same as is_verified_stale (>180d). Different rule.
    """
    if not value:
        return False
    ts = None
    # Try Z-suffixed first, then +00:00, then naive
    for fmt in (_ISO_Z, "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%dT%H:%M:%S"):
        try:
            ts = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            break
        except (ValueError, TypeError):
            continue
    if ts is None:
        return False
    now = datetime.now(timezone.utc)
    # Same quarter = same year AND same quarter index
    return (ts.year == now.year and
            (ts.month - 1) // 3 == (now.month - 1) // 3)


# Shared "is this grant's expiry still live?" SQL predicate (R1) — the single
# source of truth used by both effective_tier() and create_grant()'s dedupe,
# so the two sides can never drift apart again. expires_at is one of:
#   NULL                 -> lifetime grant, always active
#   ISO-8601 Z timestamp -> compared chronologically (ISO sorts as TEXT)
#   legacy '14d'/'90d'   -> pre-fix bug rows; must NOT leak, treated as expired
# The bracketed-digit GLOB guard admits only real timestamps, so a
# lexicographic '90d' > '2026...' can never mark a dead row live and LEAK.
_LIVE_GRANT_EXPIRY_SQL = (
    "(expires_at IS NULL OR (expires_at GLOB '[0-9]*Z' AND expires_at > ?))"
)


def wl_connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Open a connection with WAL, foreign keys, and row factory."""
    path = str(db_path or Path("contacts.db"))
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def wl_init(conn: sqlite3.Connection) -> None:
    """Create whitelist tables if they don't exist (additive only)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            handle TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            company TEXT,
            title TEXT,
            verified_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS profile_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL,
            field_type TEXT NOT NULL CHECK(field_type IN ('email', 'phone', 'title', 'company', 'address', 'website', 'birthday', 'note')),
            field_value TEXT NOT NULL,
            visibility TEXT NOT NULL CHECK(visibility IN ('public', 'granted', 'private')),
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(profile_id, field_type, field_value),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS access_grants (
            id TEXT PRIMARY KEY,
            profile_id INTEGER NOT NULL,
            requester_email TEXT NOT NULL,
            requester_name TEXT,
            status TEXT NOT NULL CHECK(status IN ('pending', 'granted', 'denied', 'revoked')),
            context TEXT,
            granted_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS profile_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            alias TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- P3-T3: context category registry (built-ins seeded after the script).
        CREATE TABLE IF NOT EXISTS grant_contexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL UNIQUE
        );

        -- P3-T4: profile-page view events (additive analytics).
        CREATE TABLE IF NOT EXISTS scan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            viewer_email TEXT,
            scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_scan_events_profile ON scan_events(profile_id);

        -- Whitelist: trusted card forwarding (2026-09-18).
        CREATE TABLE IF NOT EXISTS card_forwardings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            forwarder_email TEXT NOT NULL,
            forwarder_name TEXT,
            recipient_email TEXT NOT NULL,
            recipient_name TEXT,
            forwarded_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        );
    """)
    # P3-T2: append-only audit trail — DDL comes from the shared _grant_logs_ddl()
    # so the action vocabulary can never drift between wl_init / ensure / heal.
    conn.executescript(_grant_logs_ddl())
    _seed_builtin_contexts(conn)
    # Phase B: per-owner isolation (profiles + access_grants)
    ensure_owner_auth_schema(conn)
    ensure_access_grants_owner(conn)


# ============================================================
# VCard field expansion migration (2026-09-18)
# ============================================================

# The vCard field expansion adds new field_type values and renames 'anonymous'
# visibility to 'private'.  SQLite cannot ALTER a CHECK constraint, so we use
# the table-swap pattern (same as the access_grants v2 migration).

_VCARD_FIELD_TYPES = ('email', 'phone', 'title', 'company', 'address', 'website', 'birthday', 'note')
_VCARD_VISIBILITY = ('public', 'granted', 'private')

_PROFILE_FIELDS_V2_DDL = f"""
CREATE TABLE profile_fields_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    field_type TEXT NOT NULL CHECK(field_type IN {_VCARD_FIELD_TYPES!r}),
    field_value TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK(visibility IN {_VCARD_VISIBILITY!r}),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(profile_id, field_type, field_value),
    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
)
"""


def ensure_vcard_fields_schema(conn: sqlite3.Connection) -> None:
    """Migrate profile_fields to support the full vCard field set.

    Additive migration — safe to run on any existing DB:
    1. If the table already has the new CHECK, do nothing.
    2. Otherwise, swap to a v2 table with expanded field_type and visibility
       CHECK constraints, mapping 'anonymous' → 'private'.
    3. Seed title/company rows from profiles.* columns if they exist.
    """
    # Fast path: check if the table already has the expanded CHECK.
    # We look at the CREATE TABLE DDL in sqlite_master.
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='profile_fields'"
    ).fetchone()
    if row and row[0] and _VCARD_FIELD_TYPES[0] in row[0] and _VCARD_FIELD_TYPES[-1] in row[0]:
        # Already migrated — but still run the title/company seed below.
        _seed_title_company_fields(conn)
        conn.commit()
        return

    # Swap: create v2 table, copy data (mapping anonymous→private), drop old,
    # rename v2 to old.
    # F3 guard: a crashed prior migration may leave profile_fields_v2 behind.
    conn.execute("DROP TABLE IF EXISTS profile_fields_v2")
    conn.execute(_PROFILE_FIELDS_V2_DDL)

    # F1: disable FK enforcement around the swap so the DROP TABLE does NOT
    # cascade-delete card_fields rows (which hold custom card mappings).  Ids
    # are preserved, so surviving card_fields rows stay valid.
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("""
        INSERT INTO profile_fields_v2
            (id, profile_id, field_type, field_value,
             visibility, created_at, updated_at)
        SELECT id, profile_id, field_type, field_value,
               CASE WHEN visibility = 'anonymous' THEN 'private'
                    ELSE visibility
               END,
               created_at, updated_at
        FROM profile_fields
    """)
    conn.execute("DROP TABLE profile_fields")
    conn.execute("ALTER TABLE profile_fields_v2 RENAME TO profile_fields")
    conn.execute("PRAGMA foreign_keys=ON")

    # Now seed title/company as profile_fields rows from profiles.* columns.
    _seed_title_company_fields(conn)
    conn.commit()


def _seed_title_company_fields(conn: sqlite3.Connection) -> None:
    """Migrate profiles.title and profiles.company into profile_fields rows.

    Only inserts rows that don't already exist (idempotent). Existing
    profile_fields rows for the same type+value are preserved.

    Handles legacy profiles tables that lack title/company columns (no-op).
    """
    # Check if title/company columns exist (legacy DBs may not have them)
    has_title = conn.execute(
        "PRAGMA table_info(profiles)"
    ).fetchall()
    col_names = {r[1] for r in has_title}
    if "title" not in col_names and "company" not in col_names:
        return  # legacy schema — nothing to migrate

    profiles = conn.execute(
        "SELECT id, title, company FROM profiles WHERE title IS NOT NULL OR company IS NOT NULL"
    ).fetchall()
    for p in profiles:
        pid = p[0]
        if "title" in col_names and p[1]:  # title
            conn.execute(
                "INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (?, 'title', ?, 'granted')",
                (pid, p[1]),
            )
        if "company" in col_names and p[2]:  # company
            conn.execute(
                "INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (?, 'company', ?, 'granted')",
                (pid, p[2]),
            )


# ============================================================
# Owner auth (sign-in / per-user isolation)
# ============================================================


def create_owner_profile(
    conn: sqlite3.Connection,
    handle: str,
    display_name: str,
    email: str,
    password: str,
    company: str = None,
    title: str = None,
) -> dict:
    """Create a new owner profile with authentication credentials.

    Returns the profile dict (with fields attached).
    Raises ValueError on duplicate handle or email.
    """
    # Check for duplicate handle
    existing = conn.execute(
        "SELECT id FROM profiles WHERE handle = ?", (handle,)
    ).fetchone()
    if existing:
        raise ValueError("Handle already taken.")

    # Check for duplicate email
    existing_email = conn.execute(
        "SELECT profile_id FROM profile_fields WHERE field_type = 'email' AND LOWER(field_value) = LOWER(?)",
        (email,),
    ).fetchone()
    if existing_email:
        raise ValueError("Email already registered.")

    now = _now_iso()
    pw_hash = hash_password(password)

    conn.execute(
        """INSERT INTO profiles (handle, display_name, company, title, verified_at,
                                created_at, updated_at, password_hash, owner_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (handle, display_name, company, title, None, now, now, pw_hash, None),
    )
    profile_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Add email field (visibility: anonymous — only for auth)
    conn.execute(
        """INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)
           VALUES (?, 'email', ?, 'anonymous')""",
        (profile_id, email),
    )

    # Set owner_id = self (per-owner isolation)
    conn.execute(
        "UPDATE profiles SET owner_id = ? WHERE id = ?", (profile_id, profile_id)
    )

    conn.commit()
    return get_profile_by_id(conn, profile_id)


def resolve_owner_by_credentials(
    conn: sqlite3.Connection,
    email: str,
    password: str,
) -> Optional[dict]:
    """Look up a profile by email + password.

    Returns the profile dict (with fields) on success, None on failure.
    Uses a constant-time comparison to prevent timing attacks.
    """
    row = conn.execute(
        """SELECT p.* FROM profiles p
           JOIN profile_fields f ON f.profile_id = p.id
           WHERE f.field_type = 'email'
             AND LOWER(f.field_value) = LOWER(?)
             AND p.password_hash IS NOT NULL
           LIMIT 1""",
        (email,),
    ).fetchone()
    if row is None:
        return None
    profile = _fetch_profile(conn, row)
    if not verify_password(password, profile["password_hash"]):
        return None
    return profile


# ============================================================
# Profile seeding
# ============================================================


def seed_profile(conn: sqlite3.Connection, data: dict) -> None:
    """Upsert a whitelist profile and its fields from a canonical-JSON-like dict.

    Args:
        conn: sqlite3 connection (must have wl_init() run first).
        data: dict with keys matching canonical JSON shape:
            - handle (str, required)
            - name.display (str)
            - org.company (str)
            - org.title (str)
            - emails (list of {address, visibility, type?})
            - phones (list of {number, visibility, type?})
            - website (str, optional)
            - address (str, optional)
            - birthday (str, optional, ISO date)
            - note (str, optional)
            - verified_at (str, optional)
    """
    handle = data["handle"]
    display_name = data.get("name", {}).get("display", handle)
    company = data.get("org", {}).get("company")
    title = data.get("org", {}).get("title")
    verified_at = data.get("verified_at")

    now = _now_iso()

    conn.execute(
        """INSERT INTO profiles (handle, display_name, company, title, verified_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(handle) DO UPDATE SET
               display_name=excluded.display_name,
               company=excluded.company,
               title=excluded.title,
               verified_at=excluded.verified_at,
               updated_at=excluded.updated_at""",
        (handle, display_name, company, title, verified_at, now),
    )

    profile_id = conn.execute(
        "SELECT id FROM profiles WHERE handle = ?", (handle,)
    ).fetchone()[0]

    # Delete old fields for this profile (clean up before re-insert)
    conn.execute("DELETE FROM profile_fields WHERE profile_id = ?", (profile_id,))

    # Email fields
    for item in data.get("emails", []):
        vis = item.get("visibility", "public")
        field_vis = "public" if vis == "public" else "granted"
        conn.execute(
            """INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, ?, ?, ?)""",
            (profile_id, "email", item["address"], field_vis),
        )

    # Phone fields
    for item in data.get("phones", []):
        vis = item.get("visibility", "public")
        field_vis = "public" if vis == "public" else "granted"
        conn.execute(
            """INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, ?, ?, ?)""",
            (profile_id, "phone", item["number"], field_vis),
        )

    # Title field (from org.title)
    if title:
        conn.execute(
            """INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, 'title', ?, 'granted')""",
            (profile_id, title),
        )

    # Company field (from org.company)
    if company:
        conn.execute(
            """INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, 'company', ?, 'granted')""",
            (profile_id, company),
        )

    # Website field
    website = data.get("website")
    if website:
        conn.execute(
            """INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, 'website', ?, 'granted')""",
            (profile_id, website),
        )

    # Address field
    address = data.get("address")
    if address:
        conn.execute(
            """INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, 'address', ?, 'granted')""",
            (profile_id, address),
        )

    # Birthday field
    birthday = data.get("birthday")
    if birthday:
        conn.execute(
            """INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, 'birthday', ?, 'granted')""",
            (profile_id, birthday),
        )

    # Note field
    note = data.get("note")
    if note:
        conn.execute(
            """INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, 'note', ?, 'granted')""",
            (profile_id, note),
        )

    conn.commit()


def effective_tier(
    conn: sqlite3.Connection,
    profile_id: int,
    viewer_email: Optional[str],
    now: Optional[str] = None,
) -> str:
    """Determine a viewer's access tier for a given profile.

    Returns 'granted' if the viewer has an active grant, 'anonymous' otherwise.
    Expired grants are treated as anonymous.
    """
    if now is None:
        now = _now_iso()

    if viewer_email is None:
        return "anonymous"

    # Owner self-view: your own email always resolves to granted — you see
    # your own profile in full (dashboard 'View profile' passes ?e=). Checked
    # against this profile's own email fields, case-insensitive.
    own = conn.execute(
        """SELECT 1 FROM profile_fields
           WHERE profile_id = ? AND field_type = 'email'
             AND LOWER(field_value) = LOWER(?)
           LIMIT 1""",
        (profile_id, viewer_email),
    ).fetchone()
    if own:
        return "granted"

    # Robust tier check via the shared live-grant predicate
    # (_LIVE_GRANT_EXPIRY_SQL — see its comment for why legacy expiry strings
    # can't leak). Do not re-inline this SQL; both sides of R1 must stay one.
    row = conn.execute(
        f"""SELECT status FROM access_grants
            WHERE profile_id = ? AND LOWER(requester_email) = LOWER(?)
              AND status = 'granted' AND {_LIVE_GRANT_EXPIRY_SQL}""",
        (profile_id, viewer_email, now),
    ).fetchone()

    return "granted" if row else "anonymous"


def _fetch_profile(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    """Attach a profile's fields to its row dict (R2 — single shape builder).

    Field ORDER BY is part of the contract (tests render off it); the three
    fetchers below differ only in how they find the row.
    """
    profile = dict(row)
    fields = conn.execute(
        "SELECT * FROM profile_fields WHERE profile_id = ? ORDER BY field_type, field_value",
        (profile["id"],),
    ).fetchall()
    profile["fields"] = [dict(f) for f in fields]
    return profile


def get_profile(conn: sqlite3.Connection, handle: str) -> Optional[dict]:
    """Fetch a profile and its fields by handle."""
    row = conn.execute(
        "SELECT * FROM profiles WHERE handle = ?", (handle,)
    ).fetchone()
    return _fetch_profile(conn, row) if row else None


def get_profile_by_id(conn: sqlite3.Connection, profile_id: int) -> Optional[dict]:
    """Fetch a profile and its fields by integer ID."""
    row = conn.execute(
        "SELECT * FROM profiles WHERE id = ?", (profile_id,)
    ).fetchone()
    return _fetch_profile(conn, row) if row else None


def get_grant(conn: sqlite3.Connection, grant_id: str) -> Optional[dict]:
    """Fetch a single access grant."""
    row = conn.execute(
        "SELECT * FROM access_grants WHERE id = ?", (grant_id,)
    ).fetchone()
    return dict(row) if row else None


def create_grant(
    conn: sqlite3.Connection,
    profile_id: int,
    requester_email: str,
    requester_name: str,
    owner_id: Optional[int] = None,
) -> str:
    """Create a pending access grant. Returns grant UUID.

    Spec: dedupe on profile+email — but only against *live* grants (pending,
    or granted-and-not-yet-expired). A denied or expired grant is history, not
    a life ban: re-requesting after one inserts a fresh pending row instead of
    silently returning the dead grant id.

    owner_id: the profile that owns this grant (for per-owner isolation).
    If None, defaults to profile_id.
    """
    row = conn.execute(
        f"""SELECT id FROM access_grants
            WHERE profile_id = ? AND LOWER(requester_email) = LOWER(?)
              AND (
                    status = 'pending'
                    OR (status = 'granted' AND {_LIVE_GRANT_EXPIRY_SQL})
                  )
            ORDER BY created_at DESC LIMIT 1""",
        (profile_id, requester_email, _now_iso()),
    ).fetchone()
    if row:
        return row[0]

    grant_id = str(uuid.uuid4())
    if owner_id is None:
        owner_id = profile_id
    conn.execute(
        """INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status, owner_id)
           VALUES (?, ?, ?, ?, 'pending', ?)""",
        (grant_id, profile_id, requester_email, requester_name, owner_id),
    )
    # Audit row in the SAME transaction as the insert — commit both together.
    _log_action(conn, grant_id, profile_id, "created")
    conn.commit()
    return grant_id


def update_grant_status(
    conn: sqlite3.Connection,
    grant_id: str,
    status: str,
    granted_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    commit: bool = True,
) -> None:
    """Update a grant's status and optional fields.

    commit=False stages the UPDATE without committing — used by
    apply_decision's approve+merge path so decision + contact merge land on
    ONE commit (merge_requester_into_contacts issues it). Default True keeps
    every existing caller's behavior byte-identical.
    """
    if status == "granted":
        conn.execute(
            """UPDATE access_grants SET status = ?, granted_at = ?, expires_at = ?,
               updated_at = datetime('now') WHERE id = ?""",
            (status, granted_at, expires_at, grant_id),
        )
    else:
        conn.execute(
            """UPDATE access_grants SET status = ?, updated_at = datetime('now')
               WHERE id = ?""",
            (status, grant_id),
        )
    if commit:
        conn.commit()


def get_pending_grants_for_profile(
    conn: sqlite3.Connection, profile_id: int
) -> list[dict]:
    """Return all pending grants for a profile."""
    rows = conn.execute(
        "SELECT * FROM access_grants WHERE profile_id = ? AND status = 'pending'",
        (profile_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all_grants_for_profile(
    conn: sqlite3.Connection, profile_id: int
) -> list[dict]:
    """Return all grants (any status) for a profile."""
    rows = conn.execute(
        "SELECT * FROM access_grants WHERE profile_id = ? ORDER BY created_at DESC",
        (profile_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def update_verified_at(conn: sqlite3.Connection, profile_id: int) -> None:
    """Stamp a profile's verified_at to now."""
    now = _now_iso()
    conn.execute(
        "UPDATE profiles SET verified_at = ?, updated_at = ? WHERE id = ?",
        (now, now, profile_id),
    )
    conn.commit()


def get_profiles_needing_verification(
    conn: sqlite3.Connection, days: int = 90
) -> list[dict]:
    """Find profiles whose verified_at is older than *days* days."""
    rows = conn.execute(
        f"""SELECT * FROM profiles
           WHERE verified_at IS NOT NULL AND verified_at < datetime('now', '-{days} days')
           ORDER BY verified_at"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_pending_grants(conn: sqlite3.Connection) -> list[dict]:
    """Return all pending access grants."""
    rows = conn.execute(
        "SELECT * FROM access_grants WHERE status = 'pending' ORDER BY created_at"
    ).fetchall()
    return [dict(r) for r in rows]


# ============================================================
# Alias resolution
# ============================================================

def resolve_handle(conn: sqlite3.Connection, handle: str) -> Optional[dict]:
    """Resolve a handle to a profile dict.

    Looks up by ``profiles.handle`` first, then by ``profile_aliases.alias``.
    Returns ``None`` if not found.
    """
    row = conn.execute(
        "SELECT * FROM profiles WHERE handle = ?", (handle,)
    ).fetchone()
    if row:
        return _fetch_profile(conn, row)

    # Try alias resolution
    alias_row = conn.execute(
        "SELECT profile_id FROM profile_aliases WHERE LOWER(alias) = LOWER(?)", (handle,)
    ).fetchone()
    if alias_row:
        return get_profile_by_id(conn, alias_row["profile_id"])

    return None


def add_alias(conn: sqlite3.Connection, profile_id: int, alias: str) -> Optional[int]:
    """Add an alias for a profile. Returns alias id on success, None on collision.

    Collision rules (case-insensitive):
    - Alias must not match any existing profile.handle
    - Alias must not match any existing alias
    """
    normalized = alias.strip().lower()

    # Check collision with existing handles
    existing_handle = conn.execute(
        "SELECT id FROM profiles WHERE LOWER(handle) = LOWER(?)", (normalized,)
    ).fetchone()
    if existing_handle:
        return None

    # Check collision with existing aliases
    existing_alias = conn.execute(
        "SELECT id FROM profile_aliases WHERE LOWER(alias) = LOWER(?)", (normalized,)
    ).fetchone()
    if existing_alias:
        return None

    row = conn.execute(
        "INSERT INTO profile_aliases (profile_id, alias) VALUES (?, ?)",
        (profile_id, normalized),
    )
    conn.commit()
    return row.lastrowid


def get_all_grants_for_profile_ordered(conn: sqlite3.Connection, profile_id: int) -> list[dict]:
    """Return all grants for a profile, pending first then active, ordered by created_at desc."""
    rows = conn.execute(
        """SELECT * FROM access_grants WHERE profile_id = ?
           ORDER BY
             CASE WHEN status = 'pending' THEN 0 ELSE 1 END,
             created_at DESC""",
        (profile_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def apply_decision(conn: sqlite3.Connection, grant_id: str, decision: str, expiry_choice: str,
                   merge_contacts: bool = True):
    """Apply an approve/deny decision to a grant. Shared helper used by both /a/... and /owner/... routes.

    Args:
        conn: database connection.
        grant_id: UUID string of the grant.
        decision: 'approve' or 'deny' (anything else -> ValueError).
        expiry_choice: '14', '90', 'quarter', 'lifetime', or anything else -> 90d.

    Guards (review pass, 2026-09-11): HMAC links are stateless and replayable
    until expiry, so a decision must only land on a *pending* grant. Without
    this, Approve → revoke → replay-the-old-link resurrects access, and any
    junk decision string silently denied the requester. bulk_apply learned
    this lesson (pending-only filter); the single-decision path never did.

    merge_contacts (P5 wiring): an approve also merges the requester into the
    contacts table — Whitelist = source of truth. The status write + audit row
    are staged BEFORE calling merge; merge's own commit makes decision and
    contact merge a single atomic transaction (if the merge raises on bad
    data, nothing commits and the request stays pending-retryable — no
    granted-but-unmerged limbo). Deny never merges. Set merge_contacts=False
    for explicit-button style flows.

    Returns:
        dict with keys: grant, profile, decision. None if grant not found.
    Raises:
        ValueError on unknown decision or a non-pending grant (route maps
        it to 409).
    """
    if decision not in ("approve", "deny"):
        raise ValueError(f"unknown decision: {decision!r} — expected 'approve' or 'deny'")

    grant = get_grant(conn, grant_id)
    if not grant:
        return None
    if grant["status"] != "pending":
        raise ValueError(
            f"cannot {decision} a {grant['status']!r} grant — only pending requests can be decided"
        )

    profile = get_profile_by_id(conn, grant["profile_id"])
    now = _now_iso()

    # Compute expires_at
    if decision == "approve":
        if expiry_choice == "lifetime":
            expires_at = None
        elif expiry_choice == "14":
            expires_at = (datetime.now(timezone.utc) + timedelta(days=14)).strftime(_ISO_Z)
        elif expiry_choice == "quarter":
            expires_at = quarter_end_iso()
        else:
            # '90' and anything unrecognized -> 90d default
            expires_at = (datetime.now(timezone.utc) + timedelta(days=90)).strftime(_ISO_Z)
    else:
        expires_at = None  # denied grants carry no expiry

    status = "granted" if decision == "approve" else "denied"
    merge_enabled = merge_contacts and decision == "approve"

    # Quarterly rhythm: set quarter_status on approve.
    quarter_status = None
    if decision == "approve":
        if expiry_choice == "quarter":
            quarter_status = "active"  # live quarter grant
        # lifetime grants keep quarter_status NULL

    update_grant_status(
        conn, grant_id,
        status,
        granted_at=now if decision == "approve" else None,
        expires_at=expires_at,
        commit=not merge_enabled,   # merge issues the single commit below
    )
    if quarter_status is not None:
        try:
            conn.execute(
                "UPDATE access_grants SET quarter_status = ?, updated_at = datetime('now') WHERE id = ?",
                (quarter_status, grant_id),
            )
        except Exception:
            pass  # old DB without quarter_status column — skip silently
    # P3-T2 audit row: approved/denied, with the requested expiry as logged.
    _log_action(conn, grant_id, grant["profile_id"],
                "approved" if decision == "approve" else "denied",
                expiry_choice)

    if merge_enabled:
        # Atomicity point: the staged status write + approved log row commit
        # together with the contacts merge. merge issues its own commit; the
        # one below covers the empty-email edge (merge returns None without
        # writing) and is harmless otherwise. If the merge raises, nothing
        # commits — the grant stays pending and the approve is retryable.
        # Absent contacts table (pure-whitelist deployment / minimal store):
        # skip the merge rather than fail an otherwise-valid approval.
        if _table_exists(conn, "contacts"):
            merge_requester_into_contacts(conn, dict(grant))
    conn.commit()

    # Refresh after update
    grant = get_grant(conn, grant_id)
    profile = get_profile_by_id(conn, grant["profile_id"])
    return {"grant": grant, "profile": profile, "decision": decision}


# ============================================================
# Revocation — P3-T1 ("the un-approve")
# ============================================================

# The v2 DDL is the single source of truth for the access_grants schema.
# 'revoked' was never legal in the v1 CHECK, so any table lacking it must be
# rebuilt via table swap (SQLite cannot ALTER a CHECK in place).
_ACCESS_GRANTS_V2_DDL = """
CREATE TABLE access_grants (
    id TEXT PRIMARY KEY,
    profile_id INTEGER NOT NULL,
    requester_email TEXT NOT NULL,
    requester_name TEXT,
    status TEXT NOT NULL CHECK(status IN ('pending', 'granted', 'denied', 'revoked')),
    context TEXT,
    granted_at TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
)"""

# V3: quarterly rhythm — tracks grey-list review state.
# Uses ALTER TABLE (additive) instead of table swap since we only need
# two optional nullable columns. V2 was a table swap because the v1
# CHECK constraint lacked 'revoked'.

# Single source of truth for the grant_logs audit vocabulary. Every writer
# routes through _log_action; every table-creation site (wl_init,
# ensure_grant_logs) and the legacy heal below read this one constant — a
# new action word appears here first and can never drift between DDLs.
_GRANT_LOGS_CHECK = (
    "CHECK(action IN ('created', 'approved', 'denied', 'revoked', "
    "'merged', 'cards_set', 'permanent', 'punted', 'forwarded'))"
)


def _grant_logs_ddl() -> str:
    return f"""
        CREATE TABLE IF NOT EXISTS grant_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            grant_id TEXT NOT NULL,
            profile_id INTEGER NOT NULL,
            action TEXT NOT NULL {_GRANT_LOGS_CHECK},
            requested_expiry TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_grant_logs_grant ON grant_logs(grant_id);
    """


def ensure_grant_logs(conn: sqlite3.Connection) -> None:
    """Additive-only: guarantee the grant_logs audit table exists (idempotent)."""
    conn.executescript(_grant_logs_ddl())


# Copy column list — mirrors the legacy table exactly (byte-preserving copy;
# also self-documents what an old DB actually carries).
_GRANT_LOGS_COLS = ("id", "grant_id", "profile_id", "action",
                   "requested_expiry", "created_at")


def ensure_grant_log_actions(conn: sqlite3.Connection) -> None:
    """One-time, idempotent heal for grant_logs stuck on the legacy CHECK.

    Prod reached v2 before P5 added 'merged'/'cards_set' to the vocabulary,
    so its table still rejects both and P5 writes crash mid-transaction
    (IntegrityError) — exactly what tests can't catch when their fixtures
    hand-write a no-CHECK DDL. SQLite cannot ALTER a CHECK in place: old-DDL
    tables are rebuilt by row-preserving swap (CREATE new → copy rows →
    DROP old → RENAME), same pattern as ensure_access_grants_v2. Detection
    reads the stored DDL, not PRAGMA — column sets match, only the CHECK
    text differs. Safe on every boot: one sqlite_master read, no-op when
    current (and therefore hermetic).
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='grant_logs'"
    ).fetchone()
    if not row or not row[0]:
        return  # fresh DB pre-wl_init — nothing to heal
    ddl_sql = row[0]
    if "'merged'" in ddl_sql and "'cards_set'" in ddl_sql and "'permanent'" in ddl_sql and "'punted'" in ddl_sql and "'forwarded'" in ddl_sql:
        return  # current DDL

    new_ddl = (
        "CREATE TABLE grant_logs_new (\n"
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "    grant_id TEXT NOT NULL,\n"
        "    profile_id INTEGER NOT NULL,\n"
        "    action TEXT NOT NULL " + _GRANT_LOGS_CHECK + ",\n"
        "    requested_expiry TEXT,\n"
        "    created_at TEXT NOT NULL DEFAULT (datetime('now'))\n"
        ")"
    )
    cols = ", ".join(_GRANT_LOGS_COLS)
    conn.rollback()  # defensive: never nest a manual BEGIN
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(new_ddl)
        conn.execute(
            f"INSERT INTO grant_logs_new ({cols}) SELECT {cols} FROM grant_logs"
        )
        conn.execute("DROP TABLE grant_logs")
        conn.execute("ALTER TABLE grant_logs_new RENAME TO grant_logs")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_grant_logs_grant ON grant_logs(grant_id)"
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def _log_action(conn: sqlite3.Connection, grant_id: str, profile_id: int,
                action: str, requested_expiry: Optional[str] = None) -> None:
    """Append one audit row. The caller commits (it already does, alongside its
    own state change), so the transition and its audit row ship on the same
    commit — a log without its write, or vice versa, is an audit gap."""
    conn.execute(
        """INSERT INTO grant_logs (grant_id, profile_id, action, requested_expiry)
           VALUES (?, ?, ?, ?)""",
        (grant_id, profile_id, action, requested_expiry),
    )


# ============================================================
# Context categories — P3-T3 (organize requests by type)
# ============================================================

# Built-in registry. Custom categories are an open question for Jason; the
# table is intentionally open to INSERTs (additive), but no custom-category
# UI ships yet — seeding below is the only sanctioned writer today.
BUILTIN_CONTEXT_CATEGORIES = [
    "sales-prospect", "partner", "vendor", "media", "personal", "other",
]


def ensure_grant_contexts(conn: sqlite3.Connection) -> None:
    """Additive-only: guarantee the category registry exists + built-ins seeded.

    Idempotent (ON CONFLICT DO NOTHING) — safe to run on every boot, like
    ensure_grant_logs/ensure_access_grants_v2.
    """
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS grant_contexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL UNIQUE
        );
    """)
    _seed_builtin_contexts(conn)
    conn.commit()


def list_contexts(conn: sqlite3.Connection) -> list[dict]:
    """All registered categories, seed order (stable for UIs)."""
    rows = conn.execute(
        "SELECT * FROM grant_contexts ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


def add_context_category(conn: sqlite3.Connection, category: str) -> Optional[dict]:
    """P4-T1: sanctioned writer for CUSTOM registry categories.

    Contract:
    - None/blank after strip          -> None (nothing stored)
    - duplicate of any existing row, case-insensitively -> None
    - otherwise                       -> normalized (strip+lower) row appended
      after the built-ins and returned; set_grant_context's registry check
      makes it instantly usable.
    """
    if category is None:
        return None
    normalized = str(category).strip().lower()
    if not normalized:
        return None
    existing = conn.execute(
        "SELECT 1 FROM grant_contexts WHERE LOWER(category) = LOWER(?)", (normalized,)
    ).fetchone()
    if existing:
        return None
    conn.execute("INSERT INTO grant_contexts (category) VALUES (?)", (normalized,))
    conn.commit()
    row = conn.execute(
        "SELECT * FROM grant_contexts WHERE category = ?", (normalized,)
    ).fetchone()
    return dict(row)


def _seed_builtin_contexts(conn: sqlite3.Connection) -> None:
    """Insert built-in registry rows only if they don't already exist.

    Uses a per-row existence check to avoid sqlite_sequence bumps that
    INSERT OR IGNORE causes on no-op (the rowid counter advances even
    when the insert is suppressed, corrupting hermeticity checks).
    """
    for cat in BUILTIN_CONTEXT_CATEGORIES:
        exists = conn.execute(
            "SELECT 1 FROM grant_contexts WHERE category = ?", (cat,)
        ).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO grant_contexts (category) VALUES (?)", (cat,)
            )


def set_grant_context(conn: sqlite3.Connection, grant_id: str, category: str) -> Optional[dict]:
    """Tag a grant with a context category.

    Contract (tests pin this):
    - category not in the registry  -> None, row untouched (no free-text)
    - grant id unknown              -> None
    - otherwise                     -> stored; the refreshed grant dict returned
    """
    if conn.execute(
        "SELECT 1 FROM grant_contexts WHERE category = ?", (category,)
    ).fetchone() is None:
        return None
    cur = conn.execute(
        "UPDATE access_grants SET context = ?, updated_at = datetime('now') WHERE id = ?",
        (category, grant_id),
    )
    if cur.rowcount == 0:
        return None
    conn.commit()
    return get_grant(conn, grant_id)


def ensure_access_grants_context(conn: sqlite3.Connection) -> None:
    """Additive repair for access_grants tables that reached v2 WITHOUT the
    context column (exactly what production did — the table-swap predates
    P3-T3). A DDL-based check would miss them ('revoked' present), so this
    inspects columns directly. Idempotent: one PRAGMA read on healed DBs.

    ADD COLUMN is row-preserving by construction (existing rows get NULL);
    no table swap needed for an optional, nullable column.
    """
    cols = [r[1] for r in conn.execute("PRAGMA table_info(access_grants)")]
    if not cols:
        return  # table not created yet (fresh DB pre-wl_init) — nothing to repair
    if "context" in cols:
        return
    conn.execute("ALTER TABLE access_grants ADD COLUMN context TEXT")
    conn.commit()


# ============================================================
# Scan analytics — P3-T4 (profile page access tracking)
# ============================================================

def ensure_scan_events(conn: sqlite3.Connection) -> None:
    """Additive-only: guarantee the scan_events table exists (idempotent)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            viewer_email TEXT,
            scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_scan_events_profile ON scan_events(profile_id);
    """)
    conn.commit()


def record_scan(conn: sqlite3.Connection, profile_id: int,
                viewer_email: Optional[str]) -> None:
    """Log one profile-page view. Anonymous visits keep viewer_email NULL —
    an unauthenticated look is still a scan (that's the point of this table).
    """
    conn.execute(
        "INSERT INTO scan_events (profile_id, viewer_email) VALUES (?, ?)",
        (profile_id, viewer_email),
    )
    conn.commit()


def get_scan_stats(conn: sqlite3.Connection, profile_id: int) -> list[dict]:
    """Exactly 14 daily entries for one profile, oldest→newest (last= today).

    Zero-filled: days with no visits appear as {'scans': 0}, so the bar chart
    never has a hole. Scans outside the window are excluded from the counts.
    """
    rows = conn.execute(
        """SELECT date(scanned_at) AS d, COUNT(*) AS n
           FROM scan_events
           WHERE profile_id = ? AND scanned_at >= datetime('now', '-13 days')
           GROUP BY d""",
        (profile_id,),
    ).fetchall()
    by_date = {r["d"]: r["n"] for r in rows}

    today = datetime.now(timezone.utc)
    stats = []
    for back in range(13, -1, -1):
        day = (today - timedelta(days=back)).strftime("%Y-%m-%d")
        stats.append({"date": day, "scans": by_date.get(day, 0)})
    return stats


def get_grant_logs(conn: sqlite3.Connection, grant_id: Optional[str] = None) -> list[dict]:
    """Audit rows for one grant (or all), oldest first (rowid order)."""
    if grant_id is None:
        rows = conn.execute("SELECT * FROM grant_logs ORDER BY id").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM grant_logs WHERE grant_id = ? ORDER BY id", (grant_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def ensure_access_grants_v2(conn: sqlite3.Connection) -> None:
    """One-time, idempotent v2 migration of access_grants.

    Detects a pre-v2 table (no 'revoked' in its DDL), rebuilds it via table
    swap inside one transaction — CREATE v2 -> copy rows -> DROP old ->
    RENAME. Row-preserving: every grant row survives byte-for-byte. Safe to
    call on every boot; on an already-v2 table it is a no-op (one DDL read).

    Pre-v2 tables have exactly 9 columns; the column list in the copy SELECT
    mirrors that, which also makes this function self-documenting about what
    an old DB actually contains (no context column).
    """
    ddl = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='access_grants'"
    ).fetchone()
    if not ddl or ddl[0]:
        if not ddl:
            return  # fresh DB: wl_init will (or has) created it
        if "revoked" in ddl[0]:
            return  # already v2

    # The copy columns are the EXACT legacy column set. A v1-era row can
    # never contain 'context' — the column did not exist then — so copying
    # only these 9 fields is byte-preserving by construction.
    cols = ("id", "profile_id", "requester_email", "requester_name",
            "status", "granted_at", "expires_at", "created_at", "updated_at")
    col_list = ", ".join(cols)
    conn.rollback()  # defensive: never nest a manual BEGIN
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(_ACCESS_GRANTS_V2_DDL.replace("access_grants", "access_grants_v2", 1))
        conn.execute(
            f"""INSERT INTO access_grants_v2 ({col_list})
               SELECT {col_list} FROM access_grants"""
        )
        conn.execute("DROP TABLE access_grants")
        conn.execute("ALTER TABLE access_grants_v2 RENAME TO access_grants")
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def ensure_access_grants_v3(conn: sqlite3.Connection) -> None:
    """One-time, idempotent v3 migration of access_grants (quarterly rhythm).

    Adds two columns:
    - quarter_status: tracks grey-list review state
      ('active' = live quarter grant, 'pending_review' = awaiting decision,
       'punted' = owner extended for another quarter)
    - last_reviewed_at: when the owner last made a decision on this grant

    Uses column-level ADD COLUMN (row-preserving) instead of table swap,
    since we only need two optional nullable columns.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(access_grants)")]
    if "quarter_status" in cols:
        return  # already has quarterly rhythm columns

    conn.execute("ALTER TABLE access_grants ADD COLUMN quarter_status TEXT")
    conn.execute("ALTER TABLE access_grants ADD COLUMN last_reviewed_at TEXT")

    # Seed existing quarter grants: any granted grant with an expires_at
    # that looks like a quarter-end timestamp gets quarter_status='active'.
    conn.execute(
        "UPDATE access_grants SET quarter_status = 'active' "
        "WHERE status = 'granted' AND expires_at IS NOT NULL "
        "AND expires_at GLOB '[0-9]*Z'"
    )
    conn.commit()


def revoke_grant(conn: sqlite3.Connection, grant_id: str) -> Optional[dict]:
    """Revoke an ACTIVE (status='granted') grant — the "un-approve".

    Semantics:
    - Grant not found            -> None
    - Status is NOT 'granted'    -> ValueError (a pending request isn't access;
      a denial/expiry/revoke of history is a no-op by design)
    - Otherwise                  -> status becomes 'revoked'; granted_at and
      expires_at are preserved (history, not erasure) and the refreshed grant
      dict is returned.

    effective_tier() treats 'revoked' as anonymous — revocation severs access
    immediately. A revoked requester may re-request; create_grant's dedupe
    skips the dead row and a fresh pending request is inserted (F6 parity).
    """
    grant = get_grant(conn, grant_id)
    if grant is None:
        return None
    if grant["status"] != "granted":
        raise ValueError(
            f"cannot revoke a {grant['status']!r} grant — only active access can be revoked"
        )
    conn.execute(
        """UPDATE access_grants SET status = 'revoked', updated_at = datetime('now')
           WHERE id = ?""",
        (grant_id,),
    )
    # P3-T2 audit row — same transaction as the status flip.
    _log_action(conn, grant_id, grant["profile_id"], "revoked")
    conn.commit()
    return get_grant(conn, grant_id)


# ============================================================
# Quarterly rhythm — grey state helpers
# ============================================================

def is_grey(grant: dict) -> bool:
    """Return True if a grant is in the grey state.

    Grey state is derived: a grant is grey when:
    - status == 'granted'
    - expires_at is set (not lifetime)
    - expires_at has passed (the grant has expired)

    Grey contacts are pending a quarterly decision: make permanent,
    revoke, or punt for another quarter. Punted contacts that have
    lapsed their punt extension also re-enter the grey cycle.
    """
    if grant.get("status") != "granted":
        return False
    if grant.get("expires_at") is None:
        return False  # lifetime grants are never grey
    now = _now_iso()
    if not re.fullmatch(r"[0-9].*Z", grant["expires_at"]):
        return False  # legacy expiry strings are not grey
    if grant["expires_at"] > now:
        return False  # not yet expired
    return True  # expired granted = grey (derived, no exceptions)


def mark_grey_pending_review(conn: sqlite3.Connection, profile_id: int) -> int:
    """Mark all expired quarter grants for a profile as pending_review.

    Called at boot to transition expired quarter grants into the grey
    review state. Returns the count of rows updated.

    Only affects grants where:
    - status = 'granted'
    - quarter_status is 'active' (not yet in review)
    - expires_at has passed

    Note: with derived-grey, this helper is optional — grey is computed
    from (expired + not_punted) at query time. This function is kept for
    explicit state-tracking use cases.
    """
    now = _now_iso()
    cur = conn.execute(
        """UPDATE access_grants
           SET quarter_status = 'pending_review'
           WHERE profile_id = ?
             AND status = 'granted'
             AND (quarter_status = 'active' OR quarter_status IS NULL)
             AND expires_at IS NOT NULL
             AND expires_at GLOB '[0-9]*Z'
             AND expires_at <= ?""",
        (profile_id, now),
    )
    conn.commit()
    return cur.rowcount


def get_grey_contacts(conn: sqlite3.Connection) -> list[dict]:
    """Return all grey contacts across all profiles.

    Grey state is derived: status='granted', expires_at passed.
    No quarter_status filter — punted contacts that have lapsed
    their extension re-enter the grey cycle.

    Returns a list of dicts with grant info plus profile info attached.
    """
    rows = conn.execute(
        """SELECT ag.*, p.display_name, p.handle as profile_handle
           FROM access_grants ag
           JOIN profiles p ON ag.profile_id = p.id
           WHERE ag.status = 'granted'
             AND ag.expires_at IS NOT NULL
             AND ag.expires_at <= ?
           ORDER BY p.display_name, ag.created_at""",
        (_now_iso(),),
    ).fetchall()
    return [dict(r) for r in rows]


def get_grey_contacts_by_owner(conn: sqlite3.Connection) -> dict:
    """Return grey contacts grouped by owner profile.

    Returns a dict mapping profile_id -> list of grey contact dicts.
    Each contact dict carries grant info plus profile_handle and display_name.
    """
    grey = get_grey_contacts(conn)
    by_owner: dict[int, list[dict]] = {}
    for g in grey:
        pid = g["profile_id"]
        if pid not in by_owner:
            by_owner[pid] = []
        by_owner[pid].append(g)
    return by_owner


def get_grey_contact_count(conn: sqlite3.Connection, profile_id: int) -> int:
    """Count grey contacts for a specific profile.

    Grey state is derived: status='granted', expires_at passed.
    No quarter_status filter — lapsed punted contacts re-enter.
    """
    row = conn.execute(
        """SELECT COUNT(*) FROM access_grants
           WHERE profile_id = ?
             AND status = 'granted'
             AND expires_at IS NOT NULL
             AND expires_at <= ?""",
        (profile_id, _now_iso()),
    ).fetchone()
    return row[0]


def make_grant_permanent(conn: sqlite3.Connection, grant_id: str) -> Optional[dict]:
    """Make a grey grant permanent (lifetime access).

    - Sets expires_at = NULL
    - Sets quarter_status = NULL (no more quarterly reviews)
    - Stamps last_reviewed_at
    - Appends audit row
    - Returns the updated grant dict, or None if not found.
    """
    grant = get_grant(conn, grant_id)
    if grant is None:
        return None
    if grant["status"] != "granted":
        raise ValueError(f"cannot make permanent a {grant['status']!r} grant")
    if grant.get("expires_at") is None:
        return grant  # already permanent

    conn.execute(
        """UPDATE access_grants
           SET expires_at = NULL,
               quarter_status = NULL,
               last_reviewed_at = datetime('now'),
               updated_at = datetime('now')
           WHERE id = ?""",
        (grant_id,),
    )
    _log_action(conn, grant_id, grant["profile_id"], "permanent")
    conn.commit()
    return get_grant(conn, grant_id)


def punt_grant(conn: sqlite3.Connection, grant_id: str) -> Optional[dict]:
    """Punt a grey grant for another quarter.

    - Extends expires_at to the next quarter end
    - Sets quarter_status = 'punted'
    - Stamps last_reviewed_at
    - Appends audit row
    - Returns the updated grant dict, or None if not found.
    """
    grant = get_grant(conn, grant_id)
    if grant is None:
        return None
    if grant["status"] != "granted":
        raise ValueError(f"cannot punt a {grant['status']!r} grant")
    if grant.get("expires_at") is None:
        return grant  # lifetime grants can't be punted

    next_quarter_end = quarter_end_iso()
    conn.execute(
        """UPDATE access_grants
           SET expires_at = ?,
               quarter_status = 'punted',
               last_reviewed_at = datetime('now'),
               updated_at = datetime('now')
           WHERE id = ?""",
        (next_quarter_end, grant_id),
    )
    _log_action(conn, grant_id, grant["profile_id"], "punted")
    conn.commit()
    return get_grant(conn, grant_id)


# ============================================================
# Bulk actions — P4-T2 (dashboard multi-select)
# ============================================================

def bulk_apply(conn: sqlite3.Connection, grant_ids, decision: str,
               expiry_choice: str = "90") -> dict:
    """Apply one decision to many grants; per-grant scoping, no all-or-nothing.

    Scoping (a dead row never aborts the batch — each transition is its own
    apply_decision call with its own commit + audit row):
    - 'approve' / 'deny': only status='pending' rows are touched.
    - 'revoke':           only status='granted' rows are touched.
    Anything else (unknown id, wrong current status) counts as skipped.
    Repeated ids act once (first occurrence wins), so a double-submitted form
    can't produce duplicate audit rows.

    Returns {'approved': n, 'denied': n, 'revoked': n, 'skipped': n}.
    Raises ValueError on an unknown decision (route maps it to 400).
    """
    if decision not in ("approve", "deny", "revoke"):
        raise ValueError(f"unknown bulk decision: {decision!r}")

    summary = {"approved": 0, "denied": 0, "revoked": 0, "skipped": 0}
    seen = set()
    for gid in grant_ids:
        if not gid or gid in seen:
            continue
        seen.add(gid)
        grant = get_grant(conn, gid)
        if grant is None:
            summary["skipped"] += 1
            continue
        if decision == "revoke":
            if grant["status"] != "granted":
                summary["skipped"] += 1
                continue
            # revoke_grant raises ValueError only on non-'granted' — already
            # filtered above, so it either succeeds or the DB is genuinely sick.
            revoke_grant(conn, gid)
            summary["revoked"] += 1
        else:
            if grant["status"] != "pending":
                summary["skipped"] += 1
                continue
            result = apply_decision(conn, gid, decision, expiry_choice)
            if result is None:  # vanished between read and write
                summary["skipped"] += 1
            else:
                summary["approved" if decision == "approve" else "denied"] += 1
    return summary


# ============================================================
# Identity join + merge — T0 (Whitelist = source of truth)
# ============================================================



def find_contact_by_email(conn: sqlite3.Connection, email: str) -> Optional[dict]:
    """Find a contacts row by exact email match (case-insensitive).

    contacts.emails stores JSON arrays like:
        [{"address": "alice@example.com", "type": "primary"}]

    Contract:
    - Exact match on email.address (case-insensitive)
    - LIVE rows only: contacts with is_duplicate = 1 are dedup tombstones —
      they must never be matched (and therefore written), or a merge would
      update the loser while the winner diverges and split the person.
    - Returns None for empty/None email, '[]' rows, or no match
    - No false positives: alice@example.com does NOT match
      alice@example.com.evil (exact substring only, no LIKE)
    - Read-only: never writes to the database
    """
    if not email or not email.strip():
        return None
    email = email.strip().lower()

    # Scan live contacts rows, parse JSON, do exact case-insensitive match
    rows = conn.execute(
        "SELECT * FROM contacts WHERE is_duplicate = 0 OR is_duplicate IS NULL"
    ).fetchall()
    for row in rows:
        d = dict(row)  # sqlite3.Row doesn't have .get()
        emails_raw = d.get("emails", "[]")
        if not emails_raw or emails_raw == "[]":
            continue
        try:
            emails = json.loads(emails_raw)
        except (json.JSONDecodeError, TypeError):
            continue
        for e in emails:
            if isinstance(e, dict):
                addr = e.get("address", "").strip().lower()
            else:
                addr = str(e).strip().lower()
            if addr == email:
                return d
    return None


def _json_list(raw) -> list:
    """Parse a contacts JSON-array column into a list ([] on junk/None)."""
    try:
        parsed = json.loads(raw or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
    return parsed if isinstance(parsed, list) else []


def merge_requester_into_contacts(conn: sqlite3.Connection, grant: dict) -> Optional[dict]:
    """Merge a grant's requester info into the contacts table (Whitelist = truth).

    Contract:
    - No duplicates: if contact exists by email, overwrite; else create new
    - Whitelist fields (requester_email, requester_name) overwrite existing
      NAME ONLY — provenance is sacred: existing emails and sources are
      append-merged, never replaced (a gmail-sourced contact must not lose
      its gmail entry to a merge write).
    - New contacts get source 'whitelist-merge'
    - Empty requester_email -> None (no write, digest unchanged)
    - Commits state + audit row on same commit (contract #2)

    Args:
        conn: database connection (must have WAL + FK enabled).
        grant: dict with keys 'requester_email', 'requester_name'.

    Returns:
        The merged/created contacts row as dict, or None if no merge happened.
    """
    email = (grant.get("requester_email") or "").strip()
    if not email:
        return None

    name = grant.get("requester_name", "").strip()
    now = _now_iso()
    wl_source = {"source": "whitelist-merge", "source_id": "grant"}

    # Try to find existing contact by email
    existing = find_contact_by_email(conn, email)

    if existing:
        # Overwrite the name (Whitelist wins); merge everything else.
        new_name = name if name else existing.get("normalized_name", "")
        emails_list = _json_list(existing.get("emails"))
        if not any((e.get("address") or "").strip().lower() == email.lower()
                   for e in emails_list if isinstance(e, dict)):
            emails_list.append({"address": email, "type": "primary"})
        phones_json = existing.get("phones", "[]")  # keep existing phones

        sources_list = _json_list(existing.get("sources"))
        if not any(str(s.get("source", "")) == "whitelist-merge"
                   for s in sources_list if isinstance(s, dict)):
            sources_list.append(wl_source)

        conn.execute(
            """UPDATE contacts SET
                normalized_name = ?,
                emails = ?,
                phones = ?,
                sources = ?,
                updated_at = ?
               WHERE id = ?""",
            (
                new_name,
                json.dumps(emails_list),
                phones_json,
                json.dumps(sources_list),
                now,
                existing["id"],
            ),
        )
        # Audit row: same commit as state change. profile_id = granting profile
        # (the contact's own id is a TEXT uuid — not representable in the
        # INTEGER column — so grant_id is the join back to the merge).
        _log_action(conn, grant.get("id", ""), grant.get("profile_id", 0), "merged")
        conn.commit()
        return dict(conn.execute(
            "SELECT * FROM contacts WHERE id = ?", (existing["id"],)
        ).fetchone())
    else:
        # Create new contact
        cid = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO contacts
               (id, normalized_name, emails, phones, organizations, sources,
                created_at, updated_at, is_duplicate, merged_into)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)""",
            (
                cid,
                name or email.split("@")[0],
                json.dumps([{"address": email, "type": "primary"}]),
                "[]",
                "[]",
                json.dumps([{"source": "whitelist-merge", "source_id": "grant"}]),
                now,
                now,
            ),
        )
        # Audit row: same commit as state change (profile_id = granting profile)
        _log_action(conn, grant.get("id", ""), grant.get("profile_id", 0), "merged")
        conn.commit()
        return dict(conn.execute(
            "SELECT * FROM contacts WHERE id = ?", (cid,)
        ).fetchone())


# ============================================================
# Cards schema + CRUD — T1 (Jason's field groupings)
# ============================================================


def ensure_cards_schema(conn: sqlite3.Connection) -> None:
    """Additive-only: guarantee the 3 cards tables exist (idempotent).

    Tables created:
    - cards: owner → named field-groups ("Work", "Personal")
    - card_fields: which profile_fields belong to each card
    - grant_cards: which cards a grant has access to

    Must be called LAST in ensure_whitelist_schema (after existing ensures).
    """
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(owner_profile_id, name)
        );

        CREATE TABLE IF NOT EXISTS card_fields (
            card_id INTEGER NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
            field_id INTEGER NOT NULL REFERENCES profile_fields(id) ON DELETE CASCADE,
            PRIMARY KEY (card_id, field_id)
        );

        CREATE TABLE IF NOT EXISTS grant_cards (
            grant_id TEXT NOT NULL REFERENCES access_grants(id) ON DELETE CASCADE,
            card_id INTEGER NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (grant_id, card_id)
        );
    """)


def create_card(conn: sqlite3.Connection, owner_profile_id: int,
                name: str, field_ids: list[int]) -> dict:
    """Create a card (named field-group) for an owner profile.

    Contract:
    - empty card allowed (field_ids can be [])
    - unknown field_id → ValueError (field must exist in profile_fields)
    - duplicate name for same owner → ValueError

    Args:
        conn: database connection.
        owner_profile_id: the profile that owns this card.
        name: card name (e.g., "Work", "Personal").
        field_ids: list of profile_fields.id to include.

    Returns:
        The created card as dict.
    """
    # Validate all field_ids exist and belong to this owner
    for fid in field_ids:
        row = conn.execute(
            "SELECT 1 FROM profile_fields WHERE id = ? AND profile_id = ?",
            (fid, owner_profile_id),
        ).fetchone()
        if row is None:
            raise ValueError(f"field_id {fid} not found or not owned by profile {owner_profile_id}")

    now = _now_iso()
    try:
        cur = conn.execute(
            "INSERT INTO cards (owner_profile_id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (owner_profile_id, name, now, now),
        )
    except sqlite3.IntegrityError:
        raise ValueError(f"duplicate card name '{name}' for profile {owner_profile_id}")
    card_id = cur.lastrowid

    # Insert card_fields
    for fid in field_ids:
        conn.execute(
            "INSERT INTO card_fields (card_id, field_id) VALUES (?, ?)",
            (card_id, fid),
        )

    conn.commit()
    return get_card_by_id(conn, card_id)


def get_card_by_id(conn: sqlite3.Connection, card_id: int) -> Optional[dict]:
    """Fetch a card by ID with its fields attached."""
    row = conn.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["fields"] = [dict(r) for r in conn.execute(
        "SELECT pf.* FROM card_fields cf JOIN profile_fields pf ON cf.field_id = pf.id WHERE cf.card_id = ?",
        (card_id,),
    ).fetchall()]
    return d


def list_cards(conn: sqlite3.Connection, owner_profile_id: int) -> list[dict]:
    """All cards for an owner, with fields attached."""
    rows = conn.execute(
        "SELECT * FROM cards WHERE owner_profile_id = ? ORDER BY name",
        (owner_profile_id,),
    ).fetchall()
    result = []
    for r in rows:
        card = get_card_by_id(conn, r["id"])
        if card is not None:
            result.append(card)
    return result


def cards_for_public_view(
    conn: sqlite3.Connection,
    profile_id: int,
    tier: str,
) -> list[dict]:
    """Cards to show on the public /p/{handle} page (spec B4).

    Contract:
    - tier 'granted' (includes owner self-view): all of the owner's cards in
      id order. A card is hidden only when it has zero fields with visibility
      in ('public', 'granted', 'private') — cards are lenses on the same field
      data, not access boundaries. Private fields are visible to granted
      viewers but hidden from anonymous viewers.
    - otherwise (anonymous): the default card only — lowest `cards.id` for the
      owner — public fields only.

    Each returned card dict carries a `visible_fields` key: the subset of its
    fields the viewer may see (same row shape as ``fields`` from
    ``get_card_by_id``).
    """
    visible_vis = (("public", "granted", "private") if tier == "granted" else ("public",))
    rows = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = ? ORDER BY id",
        (profile_id,),
    ).fetchall()
    card_ids = [r["id"] for r in rows]
    if not card_ids:
        return []
    default_only = tier != "granted"
    out: list[dict] = []
    for card_id in ([card_ids[0]] if default_only else card_ids):
        card = get_card_by_id(conn, card_id)
        if card is None:
            continue
        visible_fields = [f for f in card["fields"] if f["visibility"] in visible_vis]
        if not default_only and not visible_fields:
            continue  # no field the viewer may see inside — hide the card
        card["visible_fields"] = visible_fields
        out.append(card)
    return out


def set_grant_cards(conn: sqlite3.Connection, grant_id: str,
                    card_ids: list[int]) -> Optional[dict]:
    """Set the cards a grant has access to (replace semantics).

    Contract:
    - unknown grant → None, row untouched
    - unknown card_id → ValueError (card must exist)
    - empty list → clear all cards
    - commits state + audit row on same commit (contract #2)

    Args:
        conn: database connection.
        grant_id: the grant to modify.
        card_ids: list of card IDs to assign (replace existing).

    Returns:
        The updated grant dict, or None if grant not found.
    """
    grant = get_grant(conn, grant_id)
    if grant is None:
        return None

    # Validate all card_ids exist
    for cid in card_ids:
        row = conn.execute("SELECT 1 FROM cards WHERE id = ?", (cid,)).fetchone()
        if row is None:
            raise ValueError(f"card_id {cid} not found")

    # Clear existing
    conn.execute("DELETE FROM grant_cards WHERE grant_id = ?", (grant_id,))

    # Insert new
    for cid in card_ids:
        conn.execute(
            "INSERT INTO grant_cards (grant_id, card_id) VALUES (?, ?)",
            (grant_id, cid),
        )

    # Audit row: same commit as state change
    _log_action(conn, grant_id, grant["profile_id"], "cards_set")
    conn.commit()
    return get_grant(conn, grant_id)


def get_active_cards_for_grant(conn: sqlite3.Connection, grant_id: str) -> list[dict]:
    """All cards a grant has access to."""
    rows = conn.execute(
        "SELECT c.* FROM grant_cards gc JOIN cards c ON gc.card_id = c.id WHERE gc.grant_id = ?",
        (grant_id,),
    ).fetchall()
    result = []
    for r in rows:
        card = get_card_by_id(conn, r["id"])
        if card is not None:
            result.append(card)
    return result


# ============================================================
# Phase A1 boot migrations: bio + photo_path columns
# ============================================================

def ensure_profile_bio_column(conn: sqlite3.Connection) -> None:
    """Add bio column to profiles if missing (idempotent)."""
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(profiles)").fetchall()]
    if "bio" not in cols:
        conn.execute("ALTER TABLE profiles ADD COLUMN bio TEXT")


def ensure_profile_bio_visibility_column(conn: sqlite3.Connection) -> None:
    """Add bio_visibility column to profiles if missing (idempotent).

    Controls whether the bio is visible on public surfaces.
    'public' = shown to everyone; 'private' = hidden until grant flow.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(profiles)").fetchall()]
    if "bio_visibility" not in cols:
        conn.execute(
            "ALTER TABLE profiles ADD COLUMN bio_visibility "
            "TEXT NOT NULL DEFAULT 'public' "
            "CHECK(bio_visibility IN ('public', 'private'))"
        )


def ensure_card_photo_column(conn: sqlite3.Connection) -> None:
    """Add photo_path column to cards if missing (idempotent)."""
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(cards)").fetchall()]
    if "photo_path" not in cols:
        conn.execute("ALTER TABLE cards ADD COLUMN photo_path TEXT")


# ============================================================
# Trusted forwarding (Whitelist captain ruling 2026-09-18)
# ============================================================

def ensure_card_forwardings(conn: sqlite3.Connection) -> None:
    """Create the card_forwardings table if it doesn't exist.

    Tracks when a granted contact forwards the owner's shareable card
    to a new person. The forwarding contact's identity is always
    visible to the owner; the forwarded-to person never gets private
    data access.
    """
    if _table_exists(conn, "card_forwardings"):
        return
    conn.execute("""
        CREATE TABLE card_forwardings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            forwarder_email TEXT NOT NULL,
            forwarder_name TEXT,
            recipient_email TEXT NOT NULL,
            recipient_name TEXT,
            forwarded_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
        )
    """)
    conn.commit()


def forward_card(
    conn: sqlite3.Connection,
    profile_id: int,
    forwarder_email: str,
    forwarder_name: str,
    recipient_email: str,
    recipient_name: str,
) -> int:
    """Record a card forwarding.

    Returns the grant id. The owner is notified via a pending
    access request so they can decide whether to grant access to the
    new contact.
    """
    conn.execute(
        "INSERT INTO card_forwardings "
        "(profile_id, forwarder_email, forwarder_name, recipient_email, recipient_name) "
        "VALUES (?, ?, ?, ?, ?)",
        (profile_id, forwarder_email, forwarder_name, recipient_email, recipient_name),
    )
    conn.commit()

    # Create a pending access request for the forwarded-to person
    # so the owner can review and decide.
    # Build a display name that surfaces the forwarder to the owner:
    # "Recipient Name (forwarded by Forwarder Name)".
    display_name = recipient_name or recipient_email
    if forwarder_name:
        display_name = f"{display_name} (forwarded by {forwarder_name})"
    grant_id = create_grant(
        conn, profile_id, recipient_email, display_name
    )
    # F8: create_grant dedupes on profile+email — if a pending grant
    # already exists, its requester_name won't carry the forwarder info.
    # Update it so the owner's notification is always correct.
    existing = get_grant(conn, grant_id)
    if existing and existing["requester_name"] != display_name:
        conn.execute(
            "UPDATE access_grants SET requester_name = ?, updated_at = datetime('now') WHERE id = ?",
            (display_name, grant_id),
        )
    # Audit: note the forward source
    _log_action(conn, grant_id, profile_id, "forwarded")
    conn.commit()
    return grant_id


def get_forwardings_for_profile(
    conn: sqlite3.Connection, profile_id: int
) -> list[dict]:
    """Get all card forwardings for a profile, ordered newest first."""
    rows = conn.execute(
        "SELECT * FROM card_forwardings "
        "WHERE profile_id = ? ORDER BY forwarded_at DESC",
        (profile_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ============================================================
# Boot orchestrator — R4(a)
# ============================================================

def ensure_owner_auth_schema(conn: sqlite3.Connection) -> None:
    """Add per-owner auth columns to profiles (idempotent).

    Adds:
      - password_hash TEXT   — pbkdf2-hmac-sha256 hash (nullable; legacy owners are None)
      - owner_id INTEGER     — self-referencing FK for per-owner isolation
                               (nullable; defaults to own id for legacy)

    Legacy migration: every existing profile with no owner_id gets
    owner_id = its own id, so the isolation layer is transparent.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(profiles)").fetchall()]
    if "password_hash" not in cols:
        conn.execute("ALTER TABLE profiles ADD COLUMN password_hash TEXT")
    if "owner_id" not in cols:
        conn.execute("ALTER TABLE profiles ADD COLUMN owner_id INTEGER REFERENCES profiles(id)")
        # Legacy migration: every existing profile owns itself
        conn.execute("UPDATE profiles SET owner_id = id WHERE owner_id IS NULL")
    conn.commit()


def ensure_access_grants_owner(conn: sqlite3.Connection) -> None:
    """Add owner_id column to access_grants for per-owner isolation.

    Legacy migration: every existing grant gets owner_id from its profile.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(access_grants)").fetchall()]
    if "owner_id" not in cols:
        conn.execute("ALTER TABLE access_grants ADD COLUMN owner_id INTEGER REFERENCES profiles(id)")
        # Legacy migration: every existing grant gets owner_id from its profile
        conn.execute("""
            UPDATE access_grants SET owner_id = (
                SELECT owner_id FROM profiles WHERE profiles.id = access_grants.profile_id
            )
            WHERE owner_id IS NULL
        """)
    conn.commit()


def ensure_whitelist_schema(conn: sqlite3.Connection) -> None:
    """Run every legacy-schema self-heal in THE REQUIRED ORDER. One place to
    touch for future migrations; app boot is a single call. Idempotent.

    Order is load-bearing: the v2 table swap must run BEFORE the context-column
    heal — prod reached v2 (the 'revoked' swap) before P3-T3 existed, so that
    heal inspects columns via PRAGMA instead of the DDL string (a DDL check is
    a no-op on exactly those DBs). The additive tables (logs, contexts, scans)
    sit in between; every request writes grant_logs, so their absence is a
    boot crash. Each ensure stays public + idempotent for direct callers.

    Self-contained: wl_init runs FIRST so a fresh empty file boots to the
    full current schema in this one call (it used to assume the base tables
    already existed and crashed in seed_default_cards on an empty DB).
    On existing DBs every step is idempotent — one read, no writes.
    """
    wl_init(conn)                         # base tables fresh, no-op otherwise
    ensure_access_grants_v2(conn)         # v1 CHECK -> v2 table swap first
    ensure_grant_logs(conn)               # P3-T2 audit trail (CREATE IF NOT)
    ensure_grant_log_actions(conn)        # legacy-CHECK heal: 'merged'/'cards_set'
    ensure_grant_contexts(conn)           # P3-T3 category registry + built-ins
    ensure_scan_events(conn)              # P3-T4 profile-view events
    ensure_access_grants_context(conn)    # v2-without-context prod case, LAST
    ensure_cards_schema(conn)             # P5 cards tables (depends on profiles/fields)
    ensure_vcard_fields_schema(conn)      # VCard field expansion (field_type + visibility)
    ensure_profile_bio_column(conn)       # Phase A1: profiles.bio
    ensure_card_photo_column(conn)              # Phase A1: cards.photo_path
    ensure_profile_bio_visibility_column(conn)  # Whitelist: bio visibility toggle
    ensure_card_forwardings(conn)               # Whitelist: trusted forwarding
    ensure_access_grants_v3(conn)               # quarterly rhythm: quarter_status columns
    ensure_owner_auth_schema(conn)              # Phase B: per-owner sign-in auth
    ensure_access_grants_owner(conn)            # Phase B: access_grants owner_id
    seed_default_cards(conn)                    # P5: seed Work/Personal cards


def seed_default_cards(conn: sqlite3.Connection) -> None:
    """Seed / self-heal the default cards (idempotent).

    Default cards and their field types:
    - Identity: title, company
    - Work: email
    - Contact: phone
    - Location: address, website
    - Details: birthday, note

    Two roles:
    1. First boot after a profile appears: create cards for field types that
       have data.
    2. Reseed heal: seed_profile() DELETEs all profile_fields and reinserts
       with fresh ids — card_fields' ON DELETE CASCADE silently empties every
       card, and the old "cards exist -> skip" logic never repaired it. So a
       default-named card with zero fields gets its field mapping rebuilt by
       type on every boot. Cost of the heal: an intentionally emptied card
       refills; deliberate per-card curation should use other names. Custom
       (non-default) cards are never touched.
    """
    # Fresh empty DB pre-wl_init has no profiles table yet — seeding is a
    # no-op there; boot re-runs this on every real request path.
    if not _table_exists(conn, "profiles"):
        return
    # EVERY owner profile gets its default cards (product ruling 2026-09-12:
    # hard-coding handle='jasonheath' left all other owners with nothing to
    # curate on their My Profile page).
    owners = conn.execute("SELECT id FROM profiles ORDER BY id").fetchall()

    # Card name → set of field types that belong to it
    # Order matters: the first card (lowest id) is the default card for
    # anonymous viewers. Work must come first so its public fields are
    # visible to anon viewers.
    CARD_FIELD_TYPES = {
        "Work": {"email"},
        "Contact": {"phone"},
        "Identity": {"title", "company"},
        "Location": {"address", "website"},
        "Details": {"birthday", "note"},
    }

    now = _now_iso()
    for owner in owners:
        owner_id = owner["id"]
        for card_name, field_types in CARD_FIELD_TYPES.items():
            # Collect field ids for all field types in this card
            field_ids = []
            for ft in field_types:
                field_ids.extend(r["id"] for r in conn.execute(
                    "SELECT id FROM profile_fields WHERE profile_id = ? AND field_type = ?",
                    (owner_id, ft),
                ).fetchall())

            card = conn.execute(
                "SELECT id FROM cards WHERE owner_profile_id = ? AND name = ?",
                (owner_id, card_name),
            ).fetchone()

            if card is None:
                if not field_ids:
                    continue  # nothing to group yet
                conn.execute(
                    "INSERT INTO cards (owner_profile_id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (owner_id, card_name, now, now),
                )
                card_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            else:
                card_id = card["id"]
                n_fields = conn.execute(
                    "SELECT COUNT(*) FROM card_fields WHERE card_id = ?", (card_id,)
                ).fetchone()[0]
                if n_fields > 0 or not field_ids:
                    continue  # populated (curated) or nothing to backfill
                # Cascade-orphaned by a reseed — rebuild the mapping, skip dupes.
            existing_mapped = {r["id"] for r in conn.execute(
                "SELECT pf.id FROM card_fields cf JOIN profile_fields pf ON cf.field_id = pf.id WHERE cf.card_id = ?",
                (card_id,),
            ).fetchall()}
            for fid in field_ids:
                if fid not in existing_mapped:
                    conn.execute(
                        "INSERT INTO card_fields (card_id, field_id) VALUES (?, ?)",
                        (card_id, fid),
                    )

    conn.commit()


# ============================================================
# Phase A1 helpers: bio, card_fields, add_field, photo
# ============================================================

def update_bio(conn: sqlite3.Connection, profile_id: int, bio: str) -> None:
    """Set or clear the profile bio."""
    conn.execute(
        "UPDATE profiles SET bio = ?, updated_at = datetime('now') WHERE id = ?",
        (bio, profile_id),
    )
    conn.commit()


def update_bio_visibility(conn: sqlite3.Connection, profile_id: int, bio_visibility: str) -> None:
    """Set the bio visibility (public or private) for a profile."""
    conn.execute(
        "UPDATE profiles SET bio_visibility = ?, updated_at = datetime('now') WHERE id = ?",
        (bio_visibility, profile_id),
    )
    conn.commit()


def get_bio_visibility(conn: sqlite3.Connection, profile_id: int) -> str:
    """Return the bio_visibility for a profile ('public' or 'private')."""
    row = conn.execute(
        "SELECT bio_visibility FROM profiles WHERE id = ?",
        (profile_id,),
    ).fetchone()
    return row["bio_visibility"] if row else "public"


def set_card_fields(conn: sqlite3.Connection, card_id: int, field_ids: list[int]) -> None:
    """Set the fields for a card (replace semantics).

    Validates all field_ids exist and belong to the card's owner.
    """
    card = get_card_by_id(conn, card_id)
    if card is None:
        raise ValueError(f"card_id {card_id} not found")

    owner_id = card["owner_profile_id"]
    for fid in field_ids:
        row = conn.execute(
            "SELECT 1 FROM profile_fields WHERE id = ? AND profile_id = ?",
            (fid, owner_id),
        ).fetchone()
        if row is None:
            raise ValueError(f"field_id {fid} not found or not owned by profile {owner_id}")

    conn.execute("DELETE FROM card_fields WHERE card_id = ?", (card_id,))
    for fid in field_ids:
        conn.execute(
            "INSERT INTO card_fields (card_id, field_id) VALUES (?, ?)",
            (card_id, fid),
        )
    conn.execute(
        "UPDATE cards SET updated_at = datetime('now') WHERE id = ?",
        (card_id,),
    )
    conn.commit()


def add_profile_field(conn: sqlite3.Connection, profile_id: int,
                      field_type: str, field_value: str,
                      visibility: str) -> dict:
    """Add a new field to a profile.

    Valid field_type values: email, phone, title, company, address, website,
    birthday, note.

    Valid visibility values: public (everyone), granted (granted contacts only),
    private (granted contacts only, but marked as private).

    Raises ValueError on UNIQUE violation (duplicate value for same type).
    """
    conn.execute(
        "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
        (profile_id, field_type, field_value, visibility),
    )
    conn.commit()
    return conn.execute(
        "SELECT * FROM profile_fields WHERE profile_id = ? AND field_value = ? ORDER BY id DESC LIMIT 1",
        (profile_id, field_value),
    ).fetchone()


def update_card_photo(conn: sqlite3.Connection, card_id: int,
                      photo_path: str | None) -> None:
    """Set or clear a card's photo path."""
    conn.execute(
        "UPDATE cards SET photo_path = ?, updated_at = datetime('now') WHERE id = ?",
        (photo_path, card_id),
    )
    conn.commit()


# ============================================================
# Phase A2: Contact List data layer
# ============================================================


def _grant_is_live(grant_expires_at, now_iso: str) -> bool:
    """Python twin of the SQL live-expiry predicate (one rule, two dialects).

    ``_LIVE_GRANT_EXPIRY_SQL`` is the SQL form; this is what Python code in
    this module should compare against — do NOT re-inline the logic. The
    bracketed-digit guard on the ISO side means a legacy '90d' expiry is
    never live (it sorts lexically above any real timestamp, so a blind
    string comparison would mark dead rows LIVE and leak logos).
    """
    if grant_expires_at is None:
        return True
    # Must exactly mirror the SQL GLOB '[0-9]*Z' — starts with a digit, ends
    # with Z (e.g. '2026-12-31T23:59:59Z'). Legacy '90d'/'14d' values fail
    # the guard and are therefore NOT live.
    if isinstance(grant_expires_at, str) and re.fullmatch(r"[0-9].*Z", grant_expires_at):
        return grant_expires_at > now_iso
    return False


def list_contact_list_rows(
    conn: sqlite3.Connection,
    profile_id: int,
    q: str | None = None,
    page: int = 0,
    per_page: int = 50,
) -> list[dict]:
    """Return contact list rows for the owner dashboard.

    Returns dicts with keys:
      contact_id, name, email, phone, org, granted, live_grant,
      cards, perm, logo_state, refreshed_at, is_pending

    Ordering: pending grants first, then A-Z by display name.
    Search filters by name or email substring (case-insensitive).
    Pagination: page 0 = first page of per_page rows.
    """
    # ── 1. Get all pending grants (not denied) ──
    pending_grants = conn.execute(
        "SELECT * FROM access_grants "
        "WHERE profile_id = ? AND status = 'pending' "
        "ORDER BY created_at",
        (profile_id,),
    ).fetchall()

    # ── 2. Get all active (granted/revoked) grants for this profile ──
    active_grants = conn.execute(
        "SELECT * FROM access_grants "
        "WHERE profile_id = ? AND status IN ('granted', 'revoked') "
        "ORDER BY created_at",
        (profile_id,),
    ).fetchall()

    # ── 3. Build grant lookup by email ──
    grant_by_email: dict[str, dict] = {}
    for g in pending_grants + active_grants:
        gd = dict(g)
        email = gd.get("requester_email", "").lower()
        if email:
            grant_by_email[email] = gd

    # ── 4. Get all contacts (non-duplicate) ──
    contacts = conn.execute(
        "SELECT * FROM contacts WHERE is_duplicate = 0 ORDER BY normalized_name"
    ).fetchall()

    # ── 5. Build contact lookup by email ──
    contact_by_email: dict[str, dict] = {}
    for c in contacts:
        cd = dict(c)
        emails_raw = cd.get("emails", "[]")
        if isinstance(emails_raw, str):
            import json
            emails = json.loads(emails_raw)
        else:
            emails = emails_raw or []
        for e in emails:
            if isinstance(e, dict):
                addr = e.get("address", "")
            else:
                addr = str(e)
            if addr:
                contact_by_email[addr.lower()] = cd

    # ── 6. Get card names for active grants ──
    grant_card_names: dict[str, list[str]] = {}
    for g in active_grants:
        gd = dict(g)
        cards = conn.execute(
            "SELECT c.name FROM grant_cards gc JOIN cards c ON gc.card_id = c.id WHERE gc.grant_id = ?",
            (gd["id"],),
        ).fetchall()
        grant_card_names[gd["id"]] = [r["name"] for r in cards]

    # ── 7. Build rows ──
    rows: list[dict] = []
    seen_emails: set[str] = set()

    # Pending grants first
    for g in pending_grants:
        gd = dict(g)
        email = gd.get("requester_email", "").lower()
        name = gd.get("requester_name", email.split("@")[0] if "@" in email else email)
        row = {
            "contact_id": None,
            "name": name,
            "email": gd.get("requester_email", ""),
            "phone": "",
            "org": "",
            "granted": False,
            "live_grant": gd,
            "cards": [],
            "perm": None,
            "logo_state": None,
            "refreshed_at": None,
            "is_pending": True,
        }
        rows.append(row)
        if email:
            seen_emails.add(email)

    # Active grants (not denied)
    for g in active_grants:
        gd = dict(g)
        email = gd.get("requester_email", "").lower()
        name = gd.get("requester_name", email.split("@")[0] if "@" in email else email)
        card_names = grant_card_names.get(gd["id"], [])
        expires_at = gd.get("expires_at")
        perm = "permanent" if expires_at is None else ("temp" if expires_at else None)
        granted = gd.get("status") == "granted"

        # Logo logic: ONLY live grants get a shield (AC #4: expired/revoked
        # = no logo). Freshness source, in order: matched contact's
        # updated_at -> else grant's granted_at. Dead grants fall through
        # with logo_state None — the perm badge still shows their state.
        contact = contact_by_email.get(email)
        logo_state = None
        refreshed_at = None
        if _grant_is_live(gd.get("expires_at"), _now_iso()):
            if contact:
                updated_at = contact.get("updated_at")
                if updated_at and is_current_quarter(updated_at):
                    logo_state = "fresh"
                    refreshed_at = updated_at
                elif updated_at:
                    logo_state = "stale"
                    refreshed_at = updated_at
            else:
                granted_at = gd.get("granted_at")
                if granted_at and is_current_quarter(granted_at):
                    logo_state = "fresh"
                    refreshed_at = granted_at
                elif granted_at:
                    logo_state = "stale"
                    refreshed_at = granted_at

        row = {
            "contact_id": contact.get("id") if contact else None,
            "name": name,
            "email": gd.get("requester_email", ""),
            "phone": contact.get("phones", "[]") if contact else "",
            "org": contact.get("organizations", "[]") if contact else "",
            "granted": granted,
            "live_grant": gd,
            "cards": card_names,
            "perm": perm,
            "logo_state": logo_state,
            "refreshed_at": refreshed_at,
            "is_pending": False,
        }
        rows.append(row)
        if email:
            seen_emails.add(email)

    # Contacts without matching grants (plain contacts)
    for c in contacts:
        cd = dict(c)
        emails_raw = cd.get("emails", "[]")
        if isinstance(emails_raw, str):
            import json
            emails = json.loads(emails_raw)
        else:
            emails = emails_raw or []
        _e = emails[0] if emails else None
        if isinstance(_e, dict):
            primary_email = _e.get("address", "")
        else:
            primary_email = str(_e) if _e else ""
        if primary_email.lower() in seen_emails:
            continue  # already shown as a grant row
        # Check if this contact has ANY grant (pending or active)
        has_grant = False
        for e in emails:
            if isinstance(e, dict):
                addr = e.get("address", "").lower()
            else:
                addr = str(e).lower()
            if addr and addr in grant_by_email:
                has_grant = True
                break
        if has_grant:
            continue  # already in rows as grant

        first_name = cd.get("first_name") or ""
        last_name = cd.get("last_name") or ""
        name = f"{first_name} {last_name}".strip() or cd.get("normalized_name", "Unknown")

        # Plain contacts (no grant) get NO logo per spec: "shown ONLY when the person has a live grant"
        row = {
            "contact_id": cd.get("id"),
            "name": name,
            "email": primary_email,
            "phone": cd.get("phones", "[]"),
            "org": cd.get("organizations", "[]"),
            "granted": False,
            "live_grant": None,
            "cards": [],
            "perm": None,
            "logo_state": None,
            "refreshed_at": None,
            "is_pending": False,
        }
        rows.append(row)
        if primary_email:
            seen_emails.add(primary_email.lower())

    # ── 8. Apply search filter ──
    if q:
        q_lower = q.lower()
        rows = [
            r for r in rows
            if q_lower in r["name"].lower() or q_lower in r["email"].lower()
        ]

    # ── 9. Apply pagination ──
    total = len(rows)
    start = page * per_page
    end = start + per_page
    rows = rows[start:end]

    return rows
