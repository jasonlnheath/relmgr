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


_DUMMY_HASH_CACHE: Optional[str] = None


def _dummy_password_hash() -> str:
    """A valid-format hash of random bytes, cached (F8 timing hardening).

    Burned on unknown-email sign-in so the miss path costs the same pbkdf2
    work as a real verify — remote email enumeration via response timing
    must not be possible.
    """
    global _DUMMY_HASH_CACHE
    if _DUMMY_HASH_CACHE is None:
        _DUMMY_HASH_CACHE = hash_password(secrets.token_hex(16))
    return _DUMMY_HASH_CACHE


def burn_dummy_password_work() -> None:
    """One dummy pbkdf2 verify, unconditionally, for response-timing
    symmetry on paths that must not reveal whether an email exists
    (sign-in F8; forgot-password review F1). Call BEFORE the existence
    branch so both branches pay the same synchronous cost."""
    verify_password(secrets.token_hex(16), _dummy_password_hash())


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

# Never-expire ruling (UX pass 2, 2026-09-22): a status='granted' grant
# NEVER loses access — the lapsed quarter marker only feeds the quarterly
# review prompt, never tier admission. Admission = the live-expiry predicate
# (lifetime / unexpired real timestamp) OR the grant carries any
# real-timestamp expiry at all (the grey cycle: marker lapsed, access
# persists until the owner's own badge move). Legacy '14d'/'90d' bug rows
# still fail the GLOB guard on BOTH sides and can never leak. Single source
# of truth shared by effective_tier() and create_grant()'s dedupe — the two
# sides must not drift (R1). Exactly one ? parameter (now).
_ADMITTED_EXPIRY_SQL = (
    f"({_LIVE_GRANT_EXPIRY_SQL} OR expires_at GLOB '[0-9]*Z')"
)

# ============================================================
# Card-editor field registry (round 2, 2026-09-20 captain walkthrough)
# ============================================================
# The full field-type vocabulary a card may carry. Round 2 adds:
# - preferred-channel phone slots: text_number / facetime_number
#   (explicit fields, replacing unlabeled per-row checkboxes)
# - video apps: facetime / skype named slots + video_app generic
# - messaging apps: messenger named slot + messaging_app generic
# - socials: facebook / instagram named slots + social_other generic
# - structured address block: address1/address2/city/state/zip
#   replacing the single-line 'address' type (migrated 1:1 → address1)
CARD_EDITOR_FIELD_TYPES = (
    'email', 'phone', 'text_number', 'facetime_number',
    'facetime', 'skype', 'video_app',
    'messenger', 'messaging_app',
    'facebook', 'instagram', 'social_other',
    'title', 'company', 'address1', 'address2', 'city', 'state', 'zip',
    'country',
    'website', 'birthday', 'note',
    # UX pass 3 (2026-09-23) personal-identity fields for friend-finding:
    # personal cards only, MULTIPLES allowed, city/state-level addresses only
    # public by default (street-level childhood address defaults granted).
    'high_school', 'maiden_name', 'nickname',
    'childhood_address1', 'childhood_city', 'childhood_state',
    # UX pass 5 (2026-09-24) Google-parity six-field addition
    # (data/whitelist-field-gap-analysis/report.md §6):
    'department',        # Work/vCard — Organization Department
    'po_box',            # shared address component — NOT folded into address2
    'related_person',    # Personal — related person (label = role, free text)
    'event',             # Personal — significant date (label = anniversary/other)
    'custom_field',      # vCard — label+value; defaults PRIVATE (arbitrary content)
    'name_prefix',       # vCard — Mr / Dr / …
    'name_suffix',       # vCard — Jr. / III / …
)

CARD_EDITOR_FIELD_LABELS = {
    'email': 'Email',
    'phone': 'Phone',
    'text_number': 'Text number',
    'facetime_number': 'FaceTime number',
    'facetime': 'FaceTime',
    'skype': 'Skype',
    'video_app': 'Video app',
    'messenger': 'Messenger',
    'messaging_app': 'Messaging app',
    'facebook': 'Facebook',
    'instagram': 'Instagram',
    'social_other': 'Social',
    'title': 'Title',
    'company': 'Company',
    'address1': 'Address 1',
    'address2': 'Address 2',
    'city': 'City',
    'state': 'State/Province',
    'zip': 'Zip/Postal Code',
    'country': 'Country',
    'website': 'Website',
    'birthday': 'Birthday',
    'note': 'Note',
    'high_school': 'High school',
    'maiden_name': 'Maiden name',
    'nickname': 'Nickname',
    'childhood_address1': 'Childhood address',
    'childhood_city': 'Childhood city',
    'childhood_state': 'Childhood state',
    # UX pass 5: Google-parity additions
    'department': 'Department',
    'po_box': 'PO Box',
    'related_person': 'Related person',
    'event': 'Significant date',
    'custom_field': 'Custom field',
    'name_prefix': 'Name prefix',
    'name_suffix': 'Name suffix',
}

# UX pass 5: address block component types (vcard + personal scopes).
ADDRESS_BLOCK_TYPES: tuple[str, ...] = (
    'address1', 'address2', 'city', 'state', 'zip', 'country',
)

# UX pass 5: card scopes whose Address section renders as grouped blocks.
# Regression-verify 2026-09-26: 'work' added — an address is a six-line
# block on every card kind; the new-connection flow lands in the stub's
# Work editor when an email was provided, and the captain saw no address
# block / + Add address control there. Every _SCOPE_TEMPLATES Addresses
# section carries the same six block components, so grouping is uniform.
ADDRESS_BLOCK_SCOPES = ('vcard', 'personal', 'work')


def address_blocks(scope: str) -> bool:
    """True when this card scope's Address section renders as blocks."""
    return scope in ADDRESS_BLOCK_SCOPES


# UX pass 5: scoped event labels (Google's Significant-date enum).
EVENT_LABEL_CHOICES = ('anniversary', 'other')


# UX pass 5: scope templates — section layout per card scope.
# Shape: same as CARD_EDITOR_SECTIONS: [(heading, ((type, sublabel), …)), …]
# Context-filtered six-field addition (gap-analysis report §6):
#   vcard    — all six (department, po_box, related_person, event,
#              custom_field, name prefix/suffix)
#   personal — po_box, related_person, event
#   work     — department, po_box
_SCOPE_TEMPLATES: tuple[tuple[str, tuple[tuple[str, str | None], ...], ...], ...] = (
    # ── vcard (generic contact vCard — NO identity fields) ──
    ('vcard', (
        ('Emails', (('email', None),)),
        ('Phone numbers', (
            ('phone', None),
            ('text_number', 'Text number'),
            ('facetime_number', 'FaceTime number'),
        )),
        ('Video apps', (
            ('facetime', 'FaceTime'),
            ('skype', 'Skype'),
            ('video_app', 'Video app'),
        )),
        ('Messaging apps', (
            ('messenger', 'Messenger'),
            ('messaging_app', 'Messaging app'),
        )),
        ('Social', (
            ('facebook', 'Facebook'),
            ('instagram', 'Instagram'),
            ('social_other', 'Social'),
        )),
        ('Addresses', (
            ('address1', 'Address 1'),
            ('address2', 'Address 2'),
            ('city', 'City'),
            ('state', 'State/Province'),
            ('zip', 'Zip/Postal Code'),
            ('country', 'Country'),
            ('po_box', 'PO Box'),
        )),
        ('Name', (
            ('name_prefix', 'Prefix'),
            ('name_suffix', 'Suffix'),
        )),
        ('Title', (('title', None),)),
        ('Company', (('company', None),)),
        ('Department', (('department', None),)),
        ('Website', (('website', None),)),
        ('Birthday', (('birthday', None),)),
        ('Significant dates', (('event', None),)),
        ('Related people', (('related_person', None),)),
        ('Custom fields', (('custom_field', None),)),
        ('Note', (('note', None),)),
    )),
    # ── personal (NO professional — no title/company/department/website;
    #    identity fields stay here) ──
    ('personal', (
        ('Emails', (('email', None),)),
        ('Phone numbers', (
            ('phone', None),
            ('text_number', 'Text number'),
            ('facetime_number', 'FaceTime number'),
        )),
        ('Video apps', (
            ('facetime', 'FaceTime'),
            ('skype', 'Skype'),
            ('video_app', 'Video app'),
        )),
        ('Messaging apps', (
            ('messenger', 'Messenger'),
            ('messaging_app', 'Messaging app'),
        )),
        ('Social', (
            ('facebook', 'Facebook'),
            ('instagram', 'Instagram'),
            ('social_other', 'Social'),
        )),
        ('Addresses', (
            ('address1', 'Address 1'),
            ('address2', 'Address 2'),
            ('city', 'City'),
            ('state', 'State/Province'),
            ('zip', 'Zip/Postal Code'),
            ('country', 'Country'),
            ('po_box', 'PO Box'),
        )),
        ('Birthday', (('birthday', None),)),
        ('Significant dates', (('event', None),)),
        ('Related people', (('related_person', None),)),
        ('Note', (('note', None),)),
        ('Personal history', (
            ('high_school', 'High school'),
            ('maiden_name', 'Maiden/Surname'),
            ('nickname', 'Nickname'),
        )),
        ('Childhood home', (
            ('childhood_address1', 'Childhood address'),
            ('childhood_city', 'Childhood city'),
            ('childhood_state', 'Childhood state'),
        )),
    )),
    # ── work (professional — no identity fields; title/company/department) ──
    ('work', (
        ('Emails', (('email', None),)),
        ('Phone numbers', (
            ('phone', None),
            ('text_number', 'Text number'),
            ('facetime_number', 'FaceTime number'),
        )),
        ('Video apps', (
            ('facetime', 'FaceTime'),
            ('skype', 'Skype'),
            ('video_app', 'Video app'),
        )),
        ('Messaging apps', (
            ('messenger', 'Messenger'),
            ('messaging_app', 'Messaging app'),
        )),
        ('Social', (
            ('facebook', 'Facebook'),
            ('instagram', 'Instagram'),
            ('social_other', 'Social'),
        )),
        ('Addresses', (
            ('address1', 'Address 1'),
            ('address2', 'Address 2'),
            ('city', 'City'),
            ('state', 'State/Province'),
            ('zip', 'Zip/Postal Code'),
            ('country', 'Country'),
            ('po_box', 'PO Box'),
        )),
        ('Title', (('title', None),)),
        ('Company', (('company', None),)),
        ('Department', (('department', None),)),
        ('Website', (('website', None),)),
        ('Note', (('note', None),)),
    )),
)


def picker_sections(scope: str) -> list[tuple[str, tuple[tuple[str, str | None], ...]]]:
    """Return the scope-filtered section list for card-editor rendering."""
    for key, sections in _SCOPE_TEMPLATES:
        if key == scope:
            return list(sections)  # shallow copy
    # Fallback: flat CARD_EDITOR_SECTIONS (legacy/unknown scopes)
    return list(CARD_EDITOR_SECTIONS)


# Editor sections in render order: (heading, ((field_type, sublabel), …)).
# sublabel is the per-row channel label shown when one section hosts several
# field types (e.g. 'Text number' inside Phone numbers); None for a section
# whose heading already names the single type.
CARD_EDITOR_SECTIONS = (
    ('Emails', (('email', None),)),
    ('Phone numbers', (
        ('phone', None),
        ('text_number', 'Text number'),
        ('facetime_number', 'FaceTime number'),
    )),
    ('Video apps', (
        ('facetime', 'FaceTime'),
        ('skype', 'Skype'),
        ('video_app', 'Video app'),
    )),
    ('Messaging apps', (
        ('messenger', 'Messenger'),
        ('messaging_app', 'Messaging app'),
    )),
    ('Social', (
        ('facebook', 'Facebook'),
        ('instagram', 'Instagram'),
        ('social_other', 'Social'),
    )),
    ('Address Block 1', (
        ('address1', 'Address 1'),
        ('address2', 'Address 2'),
        ('city', 'City'),
        ('state', 'State/Province'),
        ('zip', 'Zip/Postal Code'),
        ('country', 'Country'),
    )),
    ('Title', (('title', None),)),
    ('Company', (('company', None),)),
    ('Website', (('website', None),)),
    ('Birthday', (('birthday', None),)),
    ('Note', (('note', None),)),
    # UX pass 3 (2026-09-23): personal-identity fields for friend-finding.
    # MULTIPLES allowed (someone attends several schools, carries several
    # nicknames); addresses surface city/state publicly, street-level data
    # stays granted by default.
    ('Personal history', (
        ('high_school', 'High school'),
        ('maiden_name', 'Maiden name'),
        ('nickname', 'Nickname'),
    )),
    ('Childhood home', (
        ('childhood_address1', 'Childhood address'),
        ('childhood_city', 'Childhood city'),
        ('childhood_state', 'Childhood state'),
    )),
    # UX pass 5: Google-parity six-field additions
    ('Department', (('department', None),)),
    ('PO Box', (('po_box', None),)),
    ('Related people', (('related_person', None),)),
    ('Significant dates', (('event', None),)),
    ('Custom fields', (('custom_field', None),)),
    ('Name prefix', (('name_prefix', None),)),
    ('Name suffix', (('name_suffix', None),)),
)

# UX pass 5: private-default field types (custom_field defaults PRIVATE).
_PRIVATE_DEFAULT_TYPES = ('custom_field',)


def editor_default_visibility(field_type: str) -> str:
    """Default visibility for a NEW field row in the editor."""
    if field_type in _PRIVATE_DEFAULT_TYPES:
        return 'private'
    # Public defaults: identity/friend-finding fields
    _PUBLIC_DEFAULT_TYPES = ('title', 'company', 'website', 'birthday',
                             'high_school', 'maiden_name', 'nickname',
                             'city', 'state',
                             'childhood_city', 'childhood_state')
    return 'public' if field_type in _PUBLIC_DEFAULT_TYPES else 'granted'


# Repeatable types that get a "+ Add …" row button in the editor.
# UX pass 5: related_person, event, custom_field are multi.
CARD_EDITOR_MULTI_TYPES = ('email', 'phone', 'video_app', 'messaging_app', 'social_other',
                           'high_school', 'maiden_name', 'nickname',
                           'childhood_address1', 'childhood_city', 'childhood_state',
                           'related_person', 'event', 'custom_field')

# ============================================================
# Card ordering + kind (UX pass 3, 2026-09-23): Personal is THE default
# card (top of every surface, its picture is the default public picture),
# Work second, everything else alphabetical after. One SQL fragment so the
# public view, share bundles, and the owner's card list can never drift.
# ============================================================

_CARD_ORDER_SQL = (
    "CASE WHEN lower(name) = 'personal' THEN 0 "
    "WHEN lower(name) = 'work' THEN 1 ELSE 2 END, name"
)


def card_kind(card: dict) -> str | None:
    """'personal' | 'work' | None for a card dict (name-based, lowercased)."""
    name = (card.get("name") or "").strip().lower()
    if name == "personal":
        return "personal"
    if name == "work":
        return "work"
    return None


def format_phone_display(value) -> str:
    """UX pass 7: display phones as +1 (XXX) XXX-XXXX.

    10-digit numbers (and 11-digit +1-prefixed) format as US; anything
    else (international, extensions, junk) renders unchanged. Display-time
    only — stored values are never rewritten.
    """
    if value is None:
        return ""
    raw = str(value)
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) == 10:
        return f"+1 ({digits[0:3]}) {digits[3:6]}-{digits[6:10]}"
    return raw


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
    conn.executescript(f"""
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
            field_type TEXT NOT NULL CHECK(field_type IN {CARD_EDITOR_FIELD_TYPES!r}),
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

        -- Password reset (2026-09-20): single-use, 30-minute tokens.
        -- Only the SHA-256 hash of the raw token is stored (hashed at rest);
        -- raw tokens exist only inside the emailed reset URL.
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            used_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_profile
            ON password_reset_tokens(profile_id);

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

        -- In-app notification center (2026-09-20): the source of truth;
        -- email is only the push. One row per owner event (connection
        -- request, forward, quarterly prompt). dedupe_key carries the
        -- idempotency contract: NULL means always insert, otherwise the
        -- unique index collapses repeats (one row per grant, one per
        -- owner+quarter for the quarterly prompt).
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('connection_request', 'forward', 'quarterly', 'expired_link')),
            title TEXT NOT NULL,
            body TEXT,
            link TEXT,
            grant_id TEXT,
            dedupe_key TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            read_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_owner
            ON notifications(owner_profile_id, created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_dedupe
            ON notifications(dedupe_key) WHERE dedupe_key IS NOT NULL;
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


# Round-2 vCard expansion (2026-09-20): preferred-channel phone slots
# (text_number / facetime_number), video/messaging/social app types, and the
# structured address block. SQLite cannot ALTER a CHECK constraint → the
# same table-swap pattern as v2. The single-line 'address' type maps 1:1
# onto 'address1' so every existing value survives.
_PROFILE_FIELDS_V3_DDL = f"""
CREATE TABLE profile_fields_v3 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    field_type TEXT NOT NULL CHECK(field_type IN {CARD_EDITOR_FIELD_TYPES!r}),
    field_value TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK(visibility IN {_VCARD_VISIBILITY!r}),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(profile_id, field_type, field_value),
    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
)
"""


def ensure_vcard_fields_v3_schema(conn: sqlite3.Connection) -> None:
    """Migrate profile_fields to the round-2 field-type set.

    Idempotent: detects the v3 CHECK by the distinctive ``'address1'``
    literal in the table DDL (no earlier vocabulary contains it, and no
    v2-era value can contain it either — the CHECK forbade it). Must run
    AFTER ensure_vcard_fields_schema: a pre-v2 table is first swapped to
    v2 (visibility heal), then v2 → v3 here.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='profile_fields'"
    ).fetchone()
    if row is None or not row[0]:
        return  # table absent — wl_init creates it fresh this boot
    if "'address1'" in row[0]:
        return  # already v3

    # F3 guard (same as v2): a crashed prior migration may leave the v3
    # table behind — drop it before swapping.
    conn.execute("DROP TABLE IF EXISTS profile_fields_v3")
    conn.execute(_PROFILE_FIELDS_V3_DDL)

    # FK enforcement off around the swap so the DROP TABLE does not
    # cascade-delete card_fields rows (ids are preserved — same as v2).
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("""
        INSERT INTO profile_fields_v3
            (id, profile_id, field_type, field_value,
             visibility, created_at, updated_at)
        SELECT id, profile_id,
               CASE WHEN field_type = 'address' THEN 'address1'
                    ELSE field_type
               END,
               field_value, visibility, created_at, updated_at
        FROM profile_fields
    """)
    conn.execute("DROP TABLE profile_fields")
    conn.execute("ALTER TABLE profile_fields_v3 RENAME TO profile_fields")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.commit()


# UX pass 3 (2026-09-23): personal-identity field types (high_school,
# maiden_name, nickname, childhood address parts) plus 'country'. SQLite
# cannot ALTER a CHECK constraint → the same row-preserving table-swap
# heal as v2/v3, detected by the distinctive 'childhood_city' literal.
_PROFILE_FIELDS_PASS3_DDL = f"""
CREATE TABLE profile_fields_pass3 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    field_type TEXT NOT NULL CHECK(field_type IN {CARD_EDITOR_FIELD_TYPES!r}),
    field_value TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK(visibility IN {_VCARD_VISIBILITY!r}),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(profile_id, field_type, field_value),
    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
)
"""


def ensure_vcard_fields_pass3_schema(conn: sqlite3.Connection) -> None:
    """Migrate profile_fields to the pass-3 field-type set (idempotent).

    Must run AFTER ensure_vcard_fields_v3_schema (pre-v3 tables are swapped
    forward by that heal first). No value mapping — purely additive
    vocabulary. Ids and card_fields links survive the swap (same F1
    foreign_keys=OFF convention as v2/v3).
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='profile_fields'"
    ).fetchone()
    if row is None or not row[0]:
        return  # table absent — wl_init creates it fresh this boot
    if "'childhood_city'" in row[0]:
        return  # already pass-3

    conn.execute("DROP TABLE IF EXISTS profile_fields_pass3")
    conn.execute(_PROFILE_FIELDS_PASS3_DDL)
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("""
        INSERT INTO profile_fields_pass3
            (id, profile_id, field_type, field_value,
             visibility, created_at, updated_at)
        SELECT id, profile_id, field_type, field_value,
               visibility, created_at, updated_at
        FROM profile_fields
    """)
    conn.execute("DROP TABLE profile_fields")
    conn.execute("ALTER TABLE profile_fields_pass3 RENAME TO profile_fields")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.commit()


# UX pass 5: DDL with the six-field addition (department, po_box, etc.).
_PROFILE_FIELDS_PASS5_DDL = f"""
CREATE TABLE profile_fields_pass5 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    field_type TEXT NOT NULL CHECK(field_type IN {CARD_EDITOR_FIELD_TYPES!r}),
    field_value TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK(visibility IN {_VCARD_VISIBILITY!r}),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(profile_id, field_type, field_value),
    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
)
"""


def ensure_vcard_fields_pass5_schema(conn: sqlite3.Connection) -> None:
    """Migrate profile_fields to the pass-5 field-type set (idempotent).

    Adds the Google-parity six-field set: department, po_box,
    related_person, event, custom_field, name_prefix, name_suffix.
    Must run AFTER ensure_vcard_fields_pass3_schema (pre-v3 tables are
    swapped forward by that heal first).

    No value mapping — purely additive vocabulary. Ids and card_fields
    links survive the swap (same F1 foreign_keys=OFF convention).
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='profile_fields'"
    ).fetchone()
    if row is None or not row[0]:
        return  # table absent — wl_init creates it fresh this boot
    if "'department'" in row[0]:
        return  # already pass-5

    conn.execute("DROP TABLE IF EXISTS profile_fields_pass5")
    conn.execute(_PROFILE_FIELDS_PASS5_DDL)
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("""
        INSERT INTO profile_fields_pass5
            (id, profile_id, field_type, field_value,
             visibility, created_at, updated_at)
        SELECT id, profile_id, field_type, field_value,
               visibility, created_at, updated_at
        FROM profile_fields
    """)
    conn.execute("DROP TABLE profile_fields")
    conn.execute("ALTER TABLE profile_fields_pass5 RENAME TO profile_fields")
    conn.execute("PRAGMA foreign_keys=ON")
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
            # UX pass 2 (2026-09-22): title defaults to PUBLIC.
            conn.execute(
                "INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (?, 'title', ?, 'public')",
                (pid, p[1]),
            )
        if "company" in col_names and p[2]:  # company
            conn.execute(
                "INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility) VALUES (?, 'company', ?, 'public')",
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

    # Add email field (visibility: private — only used for auth lookup,
    # never rendered publicly; CHECK allows public/granted/private).
    conn.execute(
        """INSERT INTO profile_fields (profile_id, field_type, field_value, visibility)
           VALUES (?, 'email', ?, 'private')""",
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
        # Unknown email: burn the same pbkdf2 work as a real verify so the
        # miss path is not a ~30x-faster email-enumeration oracle (review F8).
        verify_password(password, _dummy_password_hash())
        return None
    profile = _fetch_profile(conn, row)
    if not verify_password(password, profile["password_hash"]):
        return None
    return profile


# ============================================================
# Password reset tokens (2026-09-20)
# ============================================================

_RESET_TOKEN_TTL_MINUTES = 30  # sane default: enough to finish a reset,
                               # short enough to be nearly worthless replayed


def _hash_reset_token(raw_token: str) -> str:
    """SHA-256 hex of a raw reset token — what we store, never the raw value."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_password_reset_token(
    conn: sqlite3.Connection, profile_id: int,
    ttl_minutes: int = _RESET_TOKEN_TTL_MINUTES,
) -> str:
    """Issue a password-reset token for *profile_id*. Returns the RAW token.

    Only the SHA-256 hash goes to storage. Exactly one active token per
    account: any previous unused token for the profile is invalidated here.
    Default TTL is 30 minutes (_RESET_TOKEN_TTL_MINUTES); pass
    ttl_minutes<=0 to mint an already-expired token (tests).
    """
    now = datetime.now(timezone.utc)
    conn.execute(
        "UPDATE password_reset_tokens SET used_at = ? "
        "WHERE profile_id = ? AND used_at IS NULL",
        (now.strftime(_ISO_Z), profile_id),
    )
    raw = secrets.token_urlsafe(32)
    expires_at = (now + timedelta(minutes=ttl_minutes)).strftime(_ISO_Z)
    conn.execute(
        "INSERT INTO password_reset_tokens (profile_id, token_hash, expires_at) "
        "VALUES (?, ?, ?)",
        (profile_id, _hash_reset_token(raw), expires_at),
    )
    conn.commit()
    return raw


def peek_password_reset_token(
    conn: sqlite3.Connection, raw_token: str,
) -> Optional[int]:
    """Validate a reset token WITHOUT consuming it. Returns profile_id or None.

    Used by the GET screen so the form only renders for a live token;
    consumption itself happens only on a successful POST.
    """
    row = conn.execute(
        "SELECT profile_id FROM password_reset_tokens "
        "WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        (_hash_reset_token(raw_token), _now_iso()),
    ).fetchone()
    return row["profile_id"] if row else None


def consume_password_reset_token(
    conn: sqlite3.Connection, raw_token: str,
) -> Optional[int]:
    """Atomically claim a reset token. Returns profile_id or None.

    The conditional UPDATE is the single-use guarantee: used_at flips inside
    the same statement that checks used_at IS NULL / not-expired, so two
    concurrent submissions cannot both win (sqlite serializes writers).
    Expired, unknown, and replayed tokens all return None.
    """
    now = _now_iso()
    cur = conn.execute(
        "UPDATE password_reset_tokens SET used_at = ? "
        "WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        (now, _hash_reset_token(raw_token), now),
    )
    conn.commit()
    if cur.rowcount != 1:
        return None
    row = conn.execute(
        "SELECT profile_id FROM password_reset_tokens WHERE token_hash = ?",
        (_hash_reset_token(raw_token),),
    ).fetchone()
    return row["profile_id"] if row else None


def set_profile_password(
    conn: sqlite3.Connection, profile_id: int, password: str,
) -> None:
    """Set (or replace) a profile's password hash. Works for passwordless
    legacy owners too — after this they sign in like any signup owner."""
    conn.execute(
        "UPDATE profiles SET password_hash = ?, updated_at = ? WHERE id = ?",
        (hash_password(password), _now_iso(), profile_id),
    )
    conn.commit()


def get_profile_by_email(
    conn: sqlite3.Connection, email: str,
) -> Optional[dict]:
    """Fetch a profile by its (private) email field, case-insensitive."""
    row = conn.execute(
        """SELECT p.* FROM profiles p
           JOIN profile_fields f ON f.profile_id = p.id
           WHERE f.field_type = 'email' AND LOWER(f.field_value) = LOWER(?)
           LIMIT 1""",
        (email,),
    ).fetchone()
    return _fetch_profile(conn, row) if row else None


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

    # Address field (round 2: the single-line address lands in Address 1;
    # the editor owns the rest of the structured block)
    address = data.get("address")
    if address:
        conn.execute(
            """INSERT OR IGNORE INTO profile_fields (profile_id, field_type, field_value, visibility)
               VALUES (?, 'address1', ?, 'granted')""",
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
    Revoked/denied grants are anonymous; GRANTED grants — including grey ones
    whose quarter marker has lapsed — are 'granted' (never-expire ruling,
    UX pass 2: the marker only prompts the quarterly review, it never ends
    access).
    """
    if now is None:
        now = _now_iso()

    if viewer_email is None:
        return "anonymous"

    # Security audit 2026-09-25: the old 'own email → granted' self-view
    # branch is REMOVED — knowing the owner's signup email must never
    # equal authentication (it leaked every private field on ?e=).
    # Owner self-view is handled at the route layer via session cookie or
    # a signed ?ot= token; ?e= here is the granted-CONTACT tracking param.

    # Tier admission via the shared admitted-grant predicate
    # (_ADMITTED_EXPIRY_SQL — grey-aware per the never-expire ruling; see its
    # comment for why legacy expiry strings can't leak). Do not re-inline
    # this SQL; both sides of R1 must stay one.
    row = conn.execute(
        f"""SELECT status FROM access_grants
            WHERE profile_id = ? AND LOWER(requester_email) = LOWER(?)
              AND status = 'granted' AND {_ADMITTED_EXPIRY_SQL}""",
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


def find_admitting_grant_id(
    conn: sqlite3.Connection,
    profile_id: int,
    requester_email: str,
) -> Optional[str]:
    """The id of the grant create_grant's dedupe would collapse onto
    (pending, or granted-and-admitted — the same predicate), else None.

    Security audit 2026-09-25: lets the request route tell a NEW request
    apart from a deduped re-POST, so only genuinely new requests push the
    owner's email (repeat POSTs used to re-send the email every time —
    a free spam vector against the owner's inbox).
    """
    row = conn.execute(
        f"""SELECT id FROM access_grants
            WHERE profile_id = ? AND LOWER(requester_email) = LOWER(?)
              AND (
                    status = 'pending'
                    OR (status = 'granted' AND {_ADMITTED_EXPIRY_SQL})
                  )
            ORDER BY created_at DESC LIMIT 1""",
        (profile_id, requester_email, _now_iso()),
    ).fetchone()
    return row[0] if row else None


def create_grant(
    conn: sqlite3.Connection,
    profile_id: int,
    requester_email: str,
    requester_name: str,
    owner_id: Optional[int] = None,
) -> str:
    """Create a pending access grant. Returns grant UUID.

    Spec: dedupe on profile+email — but only against *admitting* grants
    (pending, or granted — grey included, never-expire ruling UX pass 2: a
    grey contact re-requesting must NOT mint a duplicate pending row). A
    denied or revoked grant is history, not a life ban: re-requesting after
    one inserts a fresh pending row instead of silently returning the dead
    grant id.

    owner_id: the profile that owns this grant (for per-owner isolation).
    If None, defaults to profile_id.
    """
    row = conn.execute(
        f"""SELECT id FROM access_grants
            WHERE profile_id = ? AND LOWER(requester_email) = LOWER(?)
              AND (
                    status = 'pending'
                    OR (status = 'granted' AND {_ADMITTED_EXPIRY_SQL})
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

def set_badge_state(conn: sqlite3.Connection, grant_id: str,
                    state: str) -> Optional[dict]:
    """Badge-governed access (ruling 2026-09-20): one-click badge moves
    from the contact list, INSTANT and ALWAYS SILENT.

    state vocabulary (the contact-list badge labels):
    - 'whitelist': status='granted', lifetime access (expires_at NULL,
      quarter_status cleared) — revived from blacklist too
    - 'greylist':  status='granted', expires at the next quarter end
      (temp access; enters the quarterly cycle when it lapses)
    - 'blocked':   status='revoked' (revoked == blacklisted, one state);
      granted_at/expires_at preserved as history

    SILENCE CONTRACT: the affected contact is NEVER notified — no
    notification row (those are owner-only anyway), no email, nothing.
    Only the grant state flips and an audit row lands (reusing the
    existing grant_logs vocabulary: permanent / approved / revoked).

    Returns the refreshed grant dict, None when the grant is unknown,
    ValueError on an unknown state.
    """
    if state not in ("whitelist", "greylist", "blocked"):
        raise ValueError(f"unknown badge state: {state!r}")
    grant = get_grant(conn, grant_id)
    if grant is None:
        return None
    if state == "whitelist":
        conn.execute(
            """UPDATE access_grants
               SET status = 'granted', expires_at = NULL,
                   quarter_status = NULL,
                   last_reviewed_at = datetime('now'),
                   updated_at = datetime('now')
               WHERE id = ?""",
            (grant_id,),
        )
        _log_action(conn, grant_id, grant["profile_id"], "permanent")
    elif state == "greylist":
        conn.execute(
            """UPDATE access_grants
               SET status = 'granted', expires_at = ?,
                   quarter_status = NULL,
                   last_reviewed_at = datetime('now'),
                   updated_at = datetime('now')
               WHERE id = ?""",
            (quarter_end_iso(), grant_id),
        )
        _log_action(conn, grant_id, grant["profile_id"], "approved",
                    requested_expiry="quarter")
    else:  # blocked
        conn.execute(
            """UPDATE access_grants SET status = 'revoked',
               updated_at = datetime('now') WHERE id = ?""",
            (grant_id,),
        )
        _log_action(conn, grant_id, grant["profile_id"], "revoked")
    conn.commit()
    return get_grant(conn, grant_id)


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
    # UX pass 3 bug fix (2026-09-23): a badge-move to grey stamps a FUTURE
    # quarter marker (set_badge_state), and the contact card used to render
    # that contact as WhiteList until the marker lapsed — contradicting the
    # contact list. Grey is now the STATE 'granted + real-timestamp marker',
    # whether the marker has lapsed yet or not (the marker feeds the
    # quarterly review, it never expires access — semantics ruling). Legacy
    # '14d'/'90d' strings still fail the GLOB-shaped guard and never grey.
    if not re.fullmatch(r"[0-9].*Z", grant["expires_at"]):
        return False  # legacy expiry strings are not grey
    return True


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


def _contacts_has_owner_col(conn: sqlite3.Connection) -> bool:
    """True when the contacts table has the owner_profile_id column.

    Production DBs get it from ensure_contacts_owner at boot; minimal test
    fixtures that build only the base schema keep working unscoped.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(contacts)").fetchall()]
    return "owner_profile_id" in cols


def find_contact_by_email(
    conn: sqlite3.Connection,
    email: str,
    owner_profile_id: int | None = None,
) -> Optional[dict]:
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
    - owner_profile_id: when set, only contacts owned by this profile are
      candidates (per-owner isolation, ruling 2A — merge writes must never
      touch another owner's address book). None = unscoped (pre-migration
      fixtures / read-only test digests only; production callers pass it).
    """
    if not email or not email.strip():
        return None
    email = email.strip().lower()

    # Scan live contacts rows, parse JSON, do exact case-insensitive match.
    # Owner-scoped when an owner is given and the schema carries the owner
    # column (boot migration adds it to every real DB that has contacts;
    # minimal fixtures that predate it keep legacy unscoped behaviour).
    if owner_profile_id is not None and _contacts_has_owner_col(conn):
        rows = conn.execute(
            "SELECT * FROM contacts "
            "WHERE (is_duplicate = 0 OR is_duplicate IS NULL) AND owner_profile_id = ?",
            (owner_profile_id,),
        ).fetchall()
    else:
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

    # Try to find existing contact by email — owner-scoped: the merge must
    # only ever touch the granting owner's own address book (ruling 2A).
    existing = find_contact_by_email(conn, email, owner_profile_id=grant.get("owner_id"))

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
        # Create new contact — owned by the granting owner (ruling 2A).
        cid = str(uuid.uuid4())
        owner_id = grant.get("owner_id")
        if _contacts_has_owner_col(conn) and owner_id is not None:
            conn.execute(
                """INSERT INTO contacts
                   (id, normalized_name, emails, phones, organizations, sources,
                    created_at, updated_at, is_duplicate, merged_into, owner_profile_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)""",
                (
                    cid,
                    name or email.split("@")[0],
                    json.dumps([{"address": email, "type": "primary"}]),
                    "[]",
                    "[]",
                    json.dumps([{"source": "whitelist-merge", "source_id": "grant"}]),
                    now,
                    now,
                    owner_id,
                ),
            )
        else:
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


def delete_card(conn: sqlite3.Connection, card_id: int,
                owner_profile_id: int) -> None:
    """Delete ONE card owned by ``owner_profile_id`` (fail closed).

    Cards are lenses on the profile's field data: deleting a card drops the
    cards row plus its card_fields and grant_cards links (FK ON DELETE
    CASCADE) but NEVER touches profile_fields — the data survives and can
    be re-grouped onto another card. The owner's photo file is unlinked by
    the route layer (uploads are an app concern, not a data-layer one).

    Raises ValueError when the card doesn't exist or belongs to another
    profile (IDOR — fail closed, ruling 2A).
    """
    row = conn.execute(
        "SELECT owner_profile_id FROM cards WHERE id = ?", (card_id,)
    ).fetchone()
    if row is None or row["owner_profile_id"] != owner_profile_id:
        raise ValueError(
            f"card_id {card_id} not found or not owned by profile {owner_profile_id}"
        )
    conn.execute("DELETE FROM cards WHERE id = ?", (card_id,))
    conn.commit()


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
    """All cards for an owner, with fields attached.

    UX pass 3 ordering: Personal first, Work second, then the rest
    alphabetically — the top card carries the default public picture.
    """
    rows = conn.execute(
        "SELECT * FROM cards WHERE owner_profile_id = ? "
        f"ORDER BY {_CARD_ORDER_SQL}",
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
        "SELECT id FROM cards WHERE owner_profile_id = ? "
        f"ORDER BY {_CARD_ORDER_SQL}",
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

    # Validate all card_ids exist AND belong to the grant's owner (ruling 2A:
    # cross-owner card attach by ID manipulation must fail, not silently
    # attach another owner's cards). Validated BEFORE the delete so a
    # rejection leaves the grant's card set untouched. .get() tolerates
    # pre-migration fixture schemas whose grants lack the owner_id column.
    effective_owner = grant.get("owner_id")
    if effective_owner is None:
        effective_owner = grant.get("profile_id")
    for cid in card_ids:
        row = conn.execute(
            "SELECT 1 FROM cards WHERE id = ? AND owner_profile_id = ?",
            (cid, effective_owner),
        ).fetchone()
        if row is None:
            raise ValueError(f"card_id {cid} not found or not owned by this owner")

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
# Share bundles (captain ruling 2026-09-20): one link encodes the
# CHOSEN SET of cards; the recipient page renders that set as one
# combined card. The link is stable while fields update because the
# bundle stores card IDs — field VALUES are read live at render time.
# Shelf life (ruling 2026-09-20, link lifecycle): every bundle link
# expires exactly one week after creation.
# ============================================================

_BUNDLE_TTL_DAYS = 7


def bundle_expiry_iso(created: Optional[datetime] = None) -> str:
    """Expiry instant for a bundle created at *created* (UTC now default):
    exactly one week later, _ISO_Z format."""
    if created is None:
        created = datetime.now(timezone.utc)
    expires = created + timedelta(days=_BUNDLE_TTL_DAYS)
    return expires.strftime(_ISO_Z)


def ensure_share_bundles_schema(conn: sqlite3.Connection) -> None:
    """Create the share_bundles table if it doesn't exist (idempotent).

    Also heals the pre-TTL shape (no expires_at column) additively —
    SQLite cannot add a column with a non-constant default, so the
    heal is a plain ADD COLUMN; create_share_bundle always writes it.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS share_bundles (
            id TEXT PRIMARY KEY,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            card_ids TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL DEFAULT '9999-12-31T23:59:59Z'
        )
    """)
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(share_bundles)").fetchall()]
    if "expires_at" not in cols:
        conn.execute(
            "ALTER TABLE share_bundles ADD COLUMN expires_at TEXT "
            "NOT NULL DEFAULT '9999-12-31T23:59:59Z'")
    conn.commit()


def bundle_is_expired(bundle: dict, now: Optional[datetime] = None) -> bool:
    """True when the bundle's one-week shelf life has passed."""
    if now is None:
        now = datetime.now(timezone.utc)
    raw = (bundle.get("expires_at") or "").strip()
    if not raw:
        return False
    try:
        expires = datetime.strptime(raw, _ISO_Z).replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return now >= expires


def filter_owned_cards(conn: sqlite3.Connection, profile_id: int,
                       card_ids: list[int]) -> list[int]:
    """card_ids filtered to cards that exist AND belong to profile_id
    (the exact ownership predicate create_share_bundle enforces), deduped
    while preserving first-seen order.

    Fix-pass F1: any route that renders cards from caller-supplied ids
    (create AND the live preview) must pass the ids through this filter
    so a foreign card id can never leak another owner's content.
    """
    ordered: list[int] = []
    for cid in card_ids:
        row = conn.execute(
            "SELECT 1 FROM cards WHERE id = ? AND owner_profile_id = ?",
            (cid, profile_id),
        ).fetchone()
        if row is not None and cid not in ordered:
            ordered.append(cid)
    return ordered


def create_share_bundle(conn: sqlite3.Connection, profile_id: int,
                        card_ids: list[int]) -> dict:
    """Create a share bundle: a stable ID for a chosen set of cards.

    Contract:
    - card_ids must be non-empty (ValueError otherwise)
    - every card_id must exist AND belong to profile_id (ValueError
      otherwise — cross-owner attach by ID manipulation must fail)
    - duplicates collapse, bundle order preserves the caller's order
    - the link carries a one-week shelf life (expires_at = now + 7d)
    - commits before returning

    Returns the bundle dict {id, profile_id, card_ids, created_at,
    expires_at}.
    """
    if not card_ids:
        raise ValueError("share bundle needs at least one card")
    # Validate existence + ownership BEFORE insert (same ruling-2A posture
    # as set_grant_cards): every requested id must be an owned card —
    # cross-owner attach by ID manipulation must fail (ValueError).
    requested = list(dict.fromkeys(card_ids))  # dedupe, first-seen order
    ordered = filter_owned_cards(conn, profile_id, requested)
    if len(ordered) != len(requested):
        raise ValueError(
            "card_id(s) not found or not owned by profile "
            f"{profile_id}: "
            + ", ".join(str(c) for c in requested if c not in ordered))

    bundle_id = secrets.token_urlsafe(9)
    conn.execute(
        "INSERT INTO share_bundles (id, profile_id, card_ids, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (bundle_id, profile_id, json.dumps(ordered), bundle_expiry_iso()),
    )
    conn.commit()
    return get_share_bundle(conn, bundle_id)


def renew_share_bundle(conn: sqlite3.Connection, bundle_id: str) -> Optional[dict]:
    """Re-share path for an expired link: stamp a fresh one-week shelf
    life on the SAME bundle (same chosen set, same stable link id — the
    id is un-guessable, and renewal is owner-only via the token route).
    Returns the refreshed bundle, or None when unknown."""
    bundle = get_share_bundle(conn, bundle_id)
    if bundle is None:
        return None
    conn.execute(
        "UPDATE share_bundles SET expires_at = ? WHERE id = ?",
        (bundle_expiry_iso(), bundle_id),
    )
    conn.commit()
    return get_share_bundle(conn, bundle_id)


def get_share_bundle(conn: sqlite3.Connection, bundle_id: str) -> Optional[dict]:
    """Fetch one share bundle; card_ids comes back as a list[int]."""
    row = conn.execute(
        "SELECT * FROM share_bundles WHERE id = ?", (bundle_id,)
    ).fetchone()
    if row is None:
        return None
    bundle = dict(row)
    try:
        bundle["card_ids"] = [int(c) for c in json.loads(row["card_ids"])]
    except (ValueError, TypeError):
        bundle["card_ids"] = []
    return bundle


def is_blacklisted(conn: sqlite3.Connection, profile_id: int,
                   email: str) -> bool:
    """True when *email* has a revoked (blacklisted) grant for this
    profile. Revoked and blocked are one state (spec ruling) — any
    'revoked' row marks the sender blacklisted forever, regardless of
    newer grants."""
    row = conn.execute(
        """SELECT 1 FROM access_grants
           WHERE profile_id = ? AND LOWER(requester_email) = LOWER(?)
             AND status = 'revoked' LIMIT 1""",
        (profile_id, (email or "").strip()),
    ).fetchone()
    return row is not None


def ensure_quarantine_schema(conn: sqlite3.Connection) -> None:
    """Create the quarantined_requests table if missing (idempotent).

    Blacklist silence, both directions (ruling 2026-09-20): a blacklisted
    person's connection request is stored HERE — never in access_grants,
    never in the notification center, never emailed. The sender still
    sees the normal success page (they can never detect their status).
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS quarantined_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            email TEXT NOT NULL,
            name TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.commit()


def quarantine_request(conn: sqlite3.Connection, profile_id: int,
                       email: str, name: str = "") -> None:
    """Silently file a blacklisted sender's request. ALWAYS SILENT: no
    notification row, no email push, no badge count — the owner is never
    bothered by people they have blacklisted, and the sender gets the
    standard success page.

    Fix-pass F4: simple per-email dedupe — at most one quarantined row
    per blacklisted email per day, so repeat re-POSTs collapse instead
    of piling up identical rows.
    """
    addr = (email or "").strip()
    existing = conn.execute(
        """SELECT 1 FROM quarantined_requests
           WHERE profile_id = ? AND LOWER(email) = LOWER(?)
             AND date(created_at) = date('now') LIMIT 1""",
        (profile_id, addr),
    ).fetchone()
    if existing:
        return
    conn.execute(
        "INSERT INTO quarantined_requests (profile_id, email, name) VALUES (?, ?, ?)",
        (profile_id, addr, (name or "").strip() or None),
    )
    conn.commit()


def cards_for_share_bundle(
    conn: sqlite3.Connection,
    bundle: dict,
    tier: str,
) -> list[dict]:
    """The bundle's chosen cards, tier-filtered like the public profile.

    Visibility tiers behave EXACTLY as cards_for_public_view today:
    - anonymous: public fields only
    - granted (incl. owner self-view): public + granted + private
    - a card with zero visible fields for this tier is hidden
    Only the CHOSEN SET differs: the bundle's cards render (in bundle
    order) instead of the default-card-only anonymous rule.
    """
    visible_vis = (("public", "granted", "private")
                   if tier == "granted" else ("public",))
    out: list[dict] = []
    resolved = [c for c in (get_card_by_id(conn, cid)
                            for cid in bundle["card_ids"])
                if c is not None]
    # UX pass 3: Personal first (its picture leads the shared set), Work
    # second, the rest alphabetical — same ordering contract as the profile.
    resolved.sort(key=lambda c: (0 if card_kind(c) == "personal"
                                 else 1 if card_kind(c) == "work" else 2,
                                 c["name"]))
    for card in resolved:
        visible_fields = [f for f in card["fields"]
                          if f["visibility"] in visible_vis]
        if not visible_fields:
            continue
        card["visible_fields"] = visible_fields
        out.append(card)
    return out


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


def ensure_profile_field_labels(conn: sqlite3.Connection) -> None:
    """Add profile_fields.label for phone label support (UX pass 2, 2026-09-22).

    Values: 'mobile' / 'home' / 'work', or a free CUSTOM label string.
    NULL = unlabeled (renders with the field-type's default label). Purely
    additive column — safe on every existing DB, no table swap needed.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(profile_fields)").fetchall()]
    if "label" not in cols:
        conn.execute("ALTER TABLE profile_fields ADD COLUMN label TEXT")
    conn.commit()


def ensure_pass2_visibility_heal(conn: sqlite3.Connection) -> None:
    """F3 (captain ruling, UX pass 2, 2026-09-23): backfill the new
    visibility defaults onto ALL EXISTING field data — ONE TIME.

    The pass-2 defaults ruling ('granted' everywhere; title/company/website
    public) originally applied to new data only, so pre-pass-2 rows kept
    stale defaults. This heal converges existing rows:

    - title, company, website  -> 'public'   (unless 'private': explicit)
    - every other field_type   -> 'granted'  (from 'public'/'granted')
    - any row at 'private'     -> UNTOUCHED  (explicitly user-set: hidden on
      purpose; a heal must never auto-expose hidden data)

    The bio is a profiles column, not a field row: 'public' already IS its
    default and 'private' was an explicit toggle — no write, same exemption.

    Marker-gated via the whitelist_meta table: runs exactly once, so later
    EXPLICIT visibility edits are never reverted by a reboot. Rows already
    matching the new defaults are never written.
    """
    conn.execute(
        """CREATE TABLE IF NOT EXISTS whitelist_meta (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
           )"""
    )
    done = conn.execute(
        "SELECT value FROM whitelist_meta WHERE key = 'pass2_visibility_heal'"
    ).fetchone()
    if done:
        return  # heal already applied — explicit edits are safe from here on

    conn.execute(
        """UPDATE profile_fields SET visibility = 'public', updated_at = datetime('now')
           WHERE field_type IN ('title', 'company', 'website')
             AND visibility IN ('granted', 'public')""")
    conn.execute(
        """UPDATE profile_fields SET visibility = 'granted', updated_at = datetime('now')
           WHERE field_type NOT IN ('title', 'company', 'website')
             AND visibility = 'public'""")
    conn.execute(
        "INSERT OR REPLACE INTO whitelist_meta (key, value) VALUES ('pass2_visibility_heal', 'done')"
    )
    conn.commit()


# Built-in phone label vocabulary (everything else in the label column is a
# CUSTOM label typed by the owner, stored verbatim).
PHONE_LABEL_CHOICES = ("mobile", "home", "work")
PHONE_LABEL_CUSTOM = "__custom"


def normalize_field_label(raw: str | None) -> str:
    """Normalize an editor label submission to a storable label value.

    Built-in choices fold to lowercase ('Mobile' → 'mobile'); a CUSTOM
    submission keeps the typed text verbatim; empty/absent → '' (no label).
    """
    text = (raw or "").strip()
    if not text or text == PHONE_LABEL_CUSTOM:
        return ""
    folded = text.lower()
    return folded if folded in PHONE_LABEL_CHOICES else text


def label_display(label: str | None) -> str:
    """Render a stored label for display ('mobile' → 'Mobile', custom
    text shown as typed, '' → '')."""
    text = (label or "").strip()
    if not text:
        return ""
    if text in PHONE_LABEL_CHOICES:
        return text.capitalize()
    return text


def ensure_card_photo_column(conn: sqlite3.Connection) -> None:
    """Add photo_path column to cards if missing (idempotent)."""
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(cards)").fetchall()]
    if "photo_path" not in cols:
        conn.execute("ALTER TABLE cards ADD COLUMN photo_path TEXT")


def ensure_card_hs_photo_column(conn: sqlite3.Connection) -> None:
    """UX pass 3 (2026-09-23): high-school picture on personal cards.

    Second picture slot (cards.hs_photo_path) — additive column, idempotent.
    Both the default and the HS picture default PUBLIC (ruling): anonymous
    viewers see them on the public profile.
    """
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(cards)").fetchall()]
    if "hs_photo_path" not in cols:
        conn.execute("ALTER TABLE cards ADD COLUMN hs_photo_path TEXT")


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
# In-app notification center (2026-09-20) — the source of truth.
# Email is the push, these rows are the record: unread badge on the
# dashboard, full list at /owner/{token}/notifications.
# ============================================================

_NOTIFICATION_KINDS = (
    "connection_request", "forward", "quarterly", "expired_link")


def ensure_notification_kinds(conn: sqlite3.Connection) -> None:
    """Heal the notifications kind CHECK to the current vocabulary
    (idempotent, row-preserving table swap — SQLite cannot ALTER a
    CHECK in place; same pattern as ensure_grant_log_actions).

    Adds 'expired_link' (ruling 2026-09-20): the ping an owner receives
    when a stranger opens their expired share link. Detection reads the
    stored DDL, not PRAGMA — column sets match, only CHECK text differs.
    """
    if not _table_exists(conn, "notifications"):
        return
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='notifications'"
    ).fetchone()
    if row and row[0] and "'expired_link'" in row[0]:
        return  # current DDL
    conn.executescript("""
        CREATE TABLE notifications_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('connection_request', 'forward', 'quarterly', 'expired_link')),
            title TEXT NOT NULL,
            body TEXT,
            link TEXT,
            grant_id TEXT,
            dedupe_key TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            read_at TEXT
        );
        INSERT INTO notifications_new
            (id, owner_profile_id, kind, title, body, link, grant_id,
             dedupe_key, created_at, read_at)
        SELECT id, owner_profile_id, kind, title, body, link, grant_id,
               dedupe_key, created_at, read_at FROM notifications;
        DROP TABLE notifications;
        ALTER TABLE notifications_new RENAME TO notifications;
        CREATE INDEX idx_notifications_owner
            ON notifications(owner_profile_id, created_at);
        CREATE UNIQUE INDEX idx_notifications_dedupe
            ON notifications(dedupe_key) WHERE dedupe_key IS NOT NULL;
    """)
    conn.commit()


def create_notification(
    conn: sqlite3.Connection,
    owner_profile_id: int,
    kind: str,
    title: str,
    body: Optional[str] = None,
    link: Optional[str] = None,
    grant_id: Optional[str] = None,
    dedupe_key: Optional[str] = None,
) -> Optional[int]:
    """Insert one notification row. Returns its id, or None when a
    dedupe_key collision suppressed the insert (one row per grant, one
    per owner+quarter — repeats never re-alert)."""
    if kind not in _NOTIFICATION_KINDS:
        raise ValueError(f"unknown notification kind: {kind}")
    cur = conn.execute(
        """INSERT OR IGNORE INTO notifications
           (owner_profile_id, kind, title, body, link, grant_id, dedupe_key)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (owner_profile_id, kind, title, body, link, grant_id, dedupe_key),
    )
    conn.commit()
    return cur.lastrowid if cur.rowcount else None


def list_notifications(
    conn: sqlite3.Connection, owner_profile_id: int, limit: int = 200
) -> list[dict]:
    """All notifications for ONE owner, newest first (per-owner isolation:
    a foreign owner's rows are unreachable by construction)."""
    rows = conn.execute(
        """SELECT * FROM notifications
           WHERE owner_profile_id = ?
           ORDER BY created_at DESC, id DESC LIMIT ?""",
        (owner_profile_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def unread_notification_count(conn: sqlite3.Connection, owner_profile_id: int) -> int:
    """Unread badge count for one owner."""
    row = conn.execute(
        "SELECT COUNT(*) FROM notifications "
        "WHERE owner_profile_id = ? AND read_at IS NULL",
        (owner_profile_id,),
    ).fetchone()
    return row[0]


def get_notification(
    conn: sqlite3.Connection, owner_profile_id: int, notification_id: int
) -> Optional[dict]:
    """Fetch one notification, owner-scoped; None when missing or foreign."""
    row = conn.execute(
        "SELECT * FROM notifications WHERE id = ? AND owner_profile_id = ?",
        (notification_id, owner_profile_id),
    ).fetchone()
    return dict(row) if row else None


def mark_notification_read(
    conn: sqlite3.Connection, owner_profile_id: int, notification_id: int
) -> bool:
    """Stamp read_at on ONE owner's notification. Returns True when a row
    was flipped; False for unknown id, foreign id, or already-read."""
    cur = conn.execute(
        """UPDATE notifications SET read_at = ?
           WHERE id = ? AND owner_profile_id = ? AND read_at IS NULL""",
        (_now_iso(), notification_id, owner_profile_id),
    )
    conn.commit()
    return bool(cur.rowcount)


def mark_all_notifications_read(conn: sqlite3.Connection, owner_profile_id: int) -> int:
    """Mark every unread notification for one owner read; returns count."""
    cur = conn.execute(
        """UPDATE notifications SET read_at = ?
           WHERE owner_profile_id = ? AND read_at IS NULL""",
        (_now_iso(), owner_profile_id),
    )
    conn.commit()
    return cur.rowcount


def sync_quarterly_notifications(
    conn: sqlite3.Connection, owner_profile_id: int
) -> Optional[int]:
    """Raise ONE quarterly-review notification when this owner has grey
    contacts (contacts in the review cycle). Idempotent per owner per
    quarter via the dedupe key — the dashboard calls this on every
    render, so repeats must be free.

    Semantics ruling (UX pass 2, 2026-09-22): grey and black contacts
    NEVER expire — the quarterly review exists to update/confirm contact
    information and review grey/black contacts, never to delete them.
    """
    grey_count = get_grey_contact_count(conn, owner_profile_id)
    if not grey_count:
        return None
    label = "contact" if grey_count == 1 else "contacts"
    return create_notification(
        conn,
        owner_profile_id,
        "quarterly",
        f"Quarterly review: {grey_count} grey {label} to review",
        body=("Quarterly review time — confirm and update contact "
              "information, fill in missing fields, and review your grey "
              "and black contacts. Grey and black contacts never expire "
              "and the review never deletes a contact — every state "
              "change is your choice."),
        dedupe_key=f"quarterly:{owner_profile_id}:{quarter_end_iso()}",
    )


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


def ensure_contacts_owner(conn: sqlite3.Connection) -> None:
    """Add owner_profile_id to contacts for per-owner isolation (ruling 2A).

    The contacts table was one global address book; review F1 proved every
    signed-in owner saw all of it. Legacy migration: existing rows are
    claimed by the first (legacy owner) profile, so the pre-migration owner
    keeps their world and no other owner ever sees it. Rows inserted later
    without an owner (legacy store path) are claimed by the same backfill on
    the next boot.
    """
    if not _table_exists(conn, "contacts"):
        return  # fresh DB: wl_init does not build contacts (store.init_db does)
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(contacts)").fetchall()]
    if "owner_profile_id" not in cols:
        conn.execute(
            "ALTER TABLE contacts ADD COLUMN owner_profile_id INTEGER REFERENCES profiles(id)"
        )
    conn.execute(
        """
        UPDATE contacts SET owner_profile_id = (
            SELECT MIN(id) FROM profiles
        )
        WHERE owner_profile_id IS NULL
    """
    )
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
    ensure_share_bundles_schema(conn)           # share bundles: one link = chosen card set
    ensure_notification_kinds(conn)             # 'expired_link' kind heal (table swap)
    ensure_quarantine_schema(conn)              # blacklist silence: quarantine store
    ensure_vcard_fields_schema(conn)      # VCard field expansion (field_type + visibility)
    ensure_vcard_fields_v3_schema(conn)   # Round-2 types: 'address'→'address1' + apps (AFTER v2)
    ensure_vcard_fields_pass3_schema(conn)      # UX pass 3: personal-identity types + country
    ensure_vcard_fields_pass5_schema(conn)      # UX pass 5: six-field set (dept, po_box, etc.)
    ensure_pass2_visibility_heal(conn)    # UX pass 2 F3: one-time visibility defaults backfill
    ensure_profile_field_labels(conn)     # UX pass 2: phone label support (additive column)
    ensure_profile_bio_column(conn)       # Phase A1: profiles.bio
    ensure_card_photo_column(conn)              # Phase A1: cards.photo_path
    ensure_card_hs_photo_column(conn)           # UX pass 3: cards.hs_photo_path (high-school picture)
    ensure_profile_bio_visibility_column(conn)  # Whitelist: bio visibility toggle
    ensure_card_forwardings(conn)               # Whitelist: trusted forwarding
    ensure_access_grants_v3(conn)               # quarterly rhythm: quarter_status columns
    ensure_owner_auth_schema(conn)              # Phase B: per-owner sign-in auth
    ensure_access_grants_owner(conn)            # Phase B: access_grants owner_id
    ensure_contacts_owner(conn)                 # Phase B: contacts owner_profile_id
    seed_default_cards(conn)                    # P5: seed Work/Personal cards


def seed_default_cards(conn: sqlite3.Connection) -> None:
    """Seed / self-heal the default cards (idempotent).

    UX pass 3 ruling (2026-09-23): EVERY profile defaults with exactly two
    default cards — 'Personal' and 'Work', ALWAYS created (even empty, even
    with no fields yet). Personal is created FIRST so it holds the lower id:
    the top card, whose picture is THE default public picture. Field types:
    - Personal: phone/text channels, birthday, personal history
      (high_school, maiden_name, nickname), childhood home parts
    - Work: email, title, company, website, country

    Legacy default-named cards (Identity, Contact, Location, Details,
    Social) are no longer created fresh, but their field mappings are still
    REPAIRED when cascade-orphaned by a seed_profile reseed (the same heal
    as before — an intentionally emptied legacy card refills; deliberate
    curation should use other names). Custom cards are never touched.
    """
    # Fresh empty DB pre-wl_init has no profiles table yet — seeding is a
    # no-op there; boot re-runs this on every real request path.
    if not _table_exists(conn, "profiles"):
        return
    # EVERY owner profile gets its default cards (product ruling 2026-09-12:
    # hard-coding handle='jasonheath' left all other owners with nothing to
    # curate on their My Profile page).
    owners = conn.execute("SELECT id FROM profiles ORDER BY id").fetchall()

    # UX pass 3 default pair — ALWAYS created, in this order (Personal
    # must land the lower id: it is the top card / default picture).
    DEFAULT_CARD_ORDER = ("Personal", "Work")
    DEFAULT_CARD_TYPES = {
        "Personal": {"phone", "text_number", "facetime_number", "birthday",
                     "high_school", "maiden_name", "nickname",
                     "childhood_address1", "childhood_city", "childhood_state"},
        "Work": {"email", "title", "company", "website", "country"},
    }
    # Legacy default names: never created fresh any more, but a card that
    # already exists with one of these names still gets its mapping rebuilt
    # when a reseed cascade empties it.
    CARD_FIELD_TYPES = {
        "Contact": {"phone", "text_number", "facetime_number",
                    "facetime", "skype", "video_app",
                    "messenger", "messaging_app"},
        "Identity": {"title", "company"},
        "Location": {"address1", "address2", "city", "state", "zip",
                     "country", "website"},
        "Details": {"birthday", "note"},
        "Social": {"facebook", "instagram", "social_other"},
    }

    now = _now_iso()
    for owner in owners:
        owner_id = owner["id"]
        # --- Pass 3 default pair: create-always, heal-always ---
        for card_name in DEFAULT_CARD_ORDER:
            field_types = DEFAULT_CARD_TYPES[card_name]
            field_ids = []
            for ft in sorted(field_types):
                field_ids.extend(r["id"] for r in conn.execute(
                    "SELECT id FROM profile_fields WHERE profile_id = ? AND field_type = ?",
                    (owner_id, ft),
                ).fetchall())
            card = conn.execute(
                "SELECT id FROM cards WHERE owner_profile_id = ? AND name = ?",
                (owner_id, card_name),
            ).fetchone()
            if card is None:
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
                if n_fields > 0:
                    continue  # populated (curated)
                # Empty Personal/Work: backfill any matching fields (a reseed
                # cascade or later-added data), but the card itself stays.
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

        # --- Legacy names: heal-only (never created fresh) ---
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
                continue  # legacy names are no longer seeded
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
                      visibility: str, label: str | None = None) -> dict:
    """Add a new field to a profile.

    Valid field_type values: email, phone, title, company, address, website,
    birthday, note.

    Valid visibility values: public (everyone), granted (granted contacts only),
    private (granted contacts only, but marked as private).

    ``label`` is the optional phone label ('mobile'/'home'/'work' or custom
    text; UX pass 2).

    Raises ValueError on UNIQUE violation (duplicate value for same type).
    """
    conn.execute(
        "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility, label, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
        (profile_id, field_type, field_value, visibility,
         normalize_field_label(label) or None),
    )
    conn.commit()
    return conn.execute(
        "SELECT * FROM profile_fields WHERE profile_id = ? AND field_value = ? ORDER BY id DESC LIMIT 1",
        (profile_id, field_value),
    ).fetchone()


def update_card_photo(conn: sqlite3.Connection, card_id: int,
                      photo_path: str | None,
                      kind: str = "default") -> None:
    """Set or clear a card's photo path.

    UX pass 3: kind='hs' targets the HIGH-SCHOOL picture slot
    (cards.hs_photo_path); 'default' is the classic picture
    (cards.photo_path).
    """
    col = "hs_photo_path" if kind == "hs" else "photo_path"
    conn.execute(
        f"UPDATE cards SET {col} = ?, updated_at = datetime('now') WHERE id = ?",
        (photo_path, card_id),
    )
    conn.commit()


# The full vCard field set the card editor covers (SPEC.md §Standard contact
# field set). Shared with the route so the editor form and the save path can
# never drift apart on which types are conventional.
def save_card_editor(
    conn: sqlite3.Connection,
    card_id: int,
    *,
    display_name: str | None = None,
    card_name: str | None = None,
    field_updates: list[tuple[int, str, str]] | None = None,
    field_labels: dict[int, str] | None = None,
    field_removals: list[int] | None = None,
    new_fields: list[tuple] | None = None,
) -> dict:
    """Apply the card-editor form: ONE commit for the whole save.

    Mirrors the _log_action convention (state + dependents on a single
    commit) so a failed save never leaves a half-edited card.

    Args:
        card_id: the card being edited.
        display_name: new profiles.display_name (None/empty → unchanged).
        card_name: new cards.name (None/empty → unchanged).
        field_updates: (field_id, value, visibility) — value/visibility are
            applied only when they differ from the stored row.
        field_labels: {field_id: label} — phone label support (UX pass 2);
            '' clears the label. Applied with the same differ logic.
        field_removals: field_ids to UNLINK from this card (card_fields row
            deleted; the profile_fields row survives — cards are lenses on
            the same field data, unlinking never destroys it).
        new_fields: (field_type, value, visibility) or, with phone label,
            (field_type, value, visibility, label) — created (or reused when
            the profile already has an identical type+value row) and linked
            to the card.

    Returns the refreshed card dict.

    Raises ValueError (→ friendly 400 at the route layer):
        - unknown card
        - a field_update/removal names a field that doesn't exist or belongs
          to another profile (IDOR — fail closed)
        - a value collides with UNIQUE(profile_id, field_type, field_value)
        - a card_name collides with the owner's other cards
        - unknown field_type or visibility on a new field
    """
    card = get_card_by_id(conn, card_id)
    if card is None:
        raise ValueError(f"card_id {card_id} not found")
    owner_id = card["owner_profile_id"]
    field_updates = field_updates or []
    field_labels = field_labels or {}
    field_removals = field_removals or []
    new_fields = new_fields or []

    try:
        # 1. Identity: display_name lives on profiles (name components are
        #    profile-level, not per-card).
        if display_name:
            conn.execute(
                "UPDATE profiles SET display_name = ?, updated_at = datetime('now') WHERE id = ?",
                (display_name.strip(), owner_id),
            )

        # 2. Card rename.
        if card_name and card_name.strip() and card_name.strip() != card["name"]:
            name = card_name.strip()
            clash = conn.execute(
                "SELECT id FROM cards WHERE owner_profile_id = ? AND name = ? AND id != ?",
                (owner_id, name, card_id),
            ).fetchone()
            if clash is not None:
                raise ValueError(f"a card named '{name}' already exists")
            conn.execute(
                "UPDATE cards SET name = ?, updated_at = datetime('now') WHERE id = ?",
                (name, card_id),
            )

        # 3. Removals first so a removal + re-add of the same value in one
        #    save never trips the UNIQUE constraint mid-flight.
        for fid in field_removals:
            row = conn.execute(
                "SELECT profile_id FROM profile_fields WHERE id = ?", (fid,)
            ).fetchone()
            if row is None or row["profile_id"] != owner_id:
                raise ValueError(f"field_id {fid} not found or not owned by this profile")
            conn.execute(
                "DELETE FROM card_fields WHERE card_id = ? AND field_id = ?",
                (card_id, fid),
            )

        # 4. Updates to fields already on the card.
        for fid, value, visibility in field_updates:
            row = conn.execute(
                "SELECT profile_id, field_type, field_value, visibility FROM profile_fields WHERE id = ?",
                (fid,),
            ).fetchone()
            if row is None or row["profile_id"] != owner_id:
                raise ValueError(f"field_id {fid} not found or not owned by this profile")
            if visibility not in _VCARD_VISIBILITY:
                raise ValueError(f"invalid visibility '{visibility}'")
            value = (value or "").strip()
            if not value:
                # An emptied value means "no content" — unlink it from the
                # card rather than storing an empty string.
                conn.execute(
                    "DELETE FROM card_fields WHERE card_id = ? AND field_id = ?",
                    (card_id, fid),
                )
                continue
            if value != row["field_value"]:
                try:
                    conn.execute(
                        "UPDATE profile_fields SET field_value = ?, updated_at = datetime('now') WHERE id = ?",
                        (value, fid),
                    )
                except sqlite3.IntegrityError:
                    raise ValueError(
                        f"{row['field_type']} '{value}' is already on this profile"
                    )
            if visibility != row["visibility"]:
                conn.execute(
                    "UPDATE profile_fields SET visibility = ?, updated_at = datetime('now') WHERE id = ?",
                    (visibility, fid),
                )

        # Phone label support (UX pass 2): labels apply STANDALONE at the
        # transaction level — a row keyed only a label (no value/visibility
        # change, or a value emptied to unlink) must still save it. ''
        # clears, value sets; ownership checked (IDOR — fail closed).
        for fid, raw_label in field_labels.items():
            row = conn.execute(
                "SELECT profile_id FROM profile_fields WHERE id = ?", (fid,)
            ).fetchone()
            if row is None or row["profile_id"] != owner_id:
                raise ValueError(f"field_id {fid} not found or not owned by this profile")
            new_label = normalize_field_label(raw_label) or None
            conn.execute(
                "UPDATE profile_fields SET label = ?, updated_at = datetime('now') WHERE id = ?",
                (new_label, fid),
            )

        # 5. New fields: create (or reuse an identical type+value row) and
        #    link to the card.
        for entry in new_fields:
            field_type, value, visibility = entry[0], entry[1], entry[2]
            label = normalize_field_label(entry[3]) if len(entry) > 3 else None
            if field_type not in CARD_EDITOR_FIELD_TYPES:
                raise ValueError(f"invalid field type '{field_type}'")
            if visibility not in _VCARD_VISIBILITY:
                raise ValueError(f"invalid visibility '{visibility}'")
            value = (value or "").strip()
            if not value:
                continue  # empty add-row slot — not content
            existing = conn.execute(
                "SELECT id FROM profile_fields WHERE profile_id = ? AND field_type = ? AND field_value = ?",
                (owner_id, field_type, value),
            ).fetchone()
            if existing is not None:
                fid = existing["id"]
                conn.execute(
                    "UPDATE profile_fields SET visibility = ?, updated_at = datetime('now') WHERE id = ?",
                    (visibility, fid),
                )
            else:
                cur = conn.execute(
                    "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility, label, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
                    (owner_id, field_type, value, visibility,
                     label or None),
                )
                fid = cur.lastrowid
            conn.execute(
                "INSERT OR IGNORE INTO card_fields (card_id, field_id) VALUES (?, ?)",
                (card_id, fid),
            )

        conn.execute("UPDATE cards SET updated_at = datetime('now') WHERE id = ?", (card_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return get_card_by_id(conn, card_id)


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
      cards, card_refs, perm, logo_state, refreshed_at, is_pending
    (card_refs: [{id, name}] for the list's ONE-ROW-PER-CARD rendering.)

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

    # ── 4. Get all contacts (non-duplicate) for THIS owner (ruling 2A) ──
    # Per-owner isolation: each owner sees exactly their own address book.
    # The owner_profile_id column arrives with ensure_contacts_owner at boot;
    # minimal pre-migration fixtures without it keep legacy behaviour.
    if _contacts_has_owner_col(conn):
        contacts = conn.execute(
            "SELECT * FROM contacts WHERE is_duplicate = 0 AND owner_profile_id = ? "
            "ORDER BY normalized_name",
            (profile_id,),
        ).fetchall()
    else:
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
    grant_card_refs: dict[str, list[dict]] = {}
    for g in active_grants:
        gd = dict(g)
        cards = conn.execute(
            "SELECT c.id, c.name FROM grant_cards gc JOIN cards c ON gc.card_id = c.id WHERE gc.grant_id = ?",
            (gd["id"],),
        ).fetchall()
        grant_card_names[gd["id"]] = [r["name"] for r in cards]
        # UX pass ruling (2026-09-22): the list renders ONE ROW PER CARD,
        # so each row needs the card id (to deep-link the detail view) —
        # not just the name.
        grant_card_refs[gd["id"]] = [{"id": r["id"], "name": r["name"]} for r in cards]

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
            "card_refs": grant_card_refs.get(gd["id"], []),
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
    # UX pass 3 (2026-09-23): search matches ALL public-facing and granted
    # fields EXCEPT bios — not just name/email. Per row the haystack is:
    # name + email + the row's phones/org text (contacts-table mode) + the
    # registry profile's public/granted field VALUES (matched by email),
    # titles, phones and addresses included. The bio lives on profiles.bio
    # and is never part of the blob (ruling: bios never match).
    if q:
        q_lower = q.lower()
        emails = {r["email"].lower() for r in rows if r.get("email")}
        fields_by_email: dict[str, str] = {}
        if emails:
            email_to_pid = {
                r["field_value"].strip().lower(): r["profile_id"]
                for r in conn.execute(
                    "SELECT profile_id, field_value FROM profile_fields "
                    "WHERE field_type = 'email'")
                if r["field_value"] and r["field_value"].strip().lower() in emails
            }
            if email_to_pid:
                pids = sorted(set(email_to_pid.values()))
                marks = ",".join("?" for _ in pids)
                blob_by_pid: dict[int, list[str]] = {}
                for r in conn.execute(
                    f"SELECT profile_id, field_value FROM profile_fields "
                    f"WHERE profile_id IN ({marks}) AND visibility != 'private'",
                    pids,
                ):
                    blob_by_pid.setdefault(r["profile_id"], []).append(
                        r["field_value"] or "")
                for addr, pid in email_to_pid.items():
                    fields_by_email[addr] = " \n".join(
                        blob_by_pid.get(pid, []))

        def _haystack(r: dict) -> str:
            parts = [r["name"] or "", r["email"] or "",
                     str(r.get("phone") or ""), str(r.get("org") or "")]
            if r.get("email"):
                parts.append(fields_by_email.get(r["email"].lower(), ""))
            return " \n".join(parts).lower()

        rows = [r for r in rows if q_lower in _haystack(r)]

    # ── 9. Apply pagination ──
    total = len(rows)
    start = page * per_page
    end = start + per_page
    rows = rows[start:end]

    return rows


# ============================================================
# New-connection search + standard vCard creation (UX pass 2)
# ============================================================

def search_new_connections(conn: sqlite3.Connection,
                           owner_profile_id: int, q: str,
                           limit: int = 10) -> list[dict]:
    """Search the owner's contacts database for 'new connections'.

    The + button on the contact list searches the imported address book
    (contacts table, owner-scoped per ruling 2A) by name or email
    substring. Returns light rows: name, email, phone, org (JSON columns
    already unpacked). Empty query → [].
    """
    text = (q or "").strip()
    if not text:
        return []
    if not _table_exists(conn, "contacts"):
        return []  # store layer never ran — nothing to search, never a crash
    like = f"%{text}%"
    if _contacts_has_owner_col(conn):
        rows = conn.execute(
            "SELECT * FROM contacts "
            "WHERE is_duplicate = 0 AND owner_profile_id = ? "
            "AND (normalized_name LIKE ? OR emails LIKE ? OR phones LIKE ?) "
            "ORDER BY normalized_name LIMIT ?",
            (owner_profile_id, like, like, like, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM contacts "
            "WHERE is_duplicate = 0 "
            "AND (normalized_name LIKE ? OR emails LIKE ? OR phones LIKE ?) "
            "ORDER BY normalized_name LIMIT ?",
            (like, like, like, limit),
        ).fetchall()

    import json as _json
    out: list[dict] = []
    for r in rows:
        cd = dict(r)

        def _first_json_list(raw) -> list:
            try:
                data = _json.loads(raw) if isinstance(raw, str) else (raw or [])
            except (ValueError, TypeError):
                data = []
            return data if isinstance(data, list) else []

        emails = _first_json_list(cd.get("emails"))
        phones = _first_json_list(cd.get("phones"))
        orgs = _first_json_list(cd.get("organizations"))

        def _text_of(entry) -> str:
            if isinstance(entry, dict):
                return str(entry.get("address") or entry.get("number")
                           or entry.get("name") or "")
            return str(entry) if entry else ""

        email = _text_of(emails[0]) if emails else ""
        phone = _text_of(phones[0]) if phones else ""
        org = _text_of(orgs[0]) if orgs else ""
        name = (f"{cd.get('first_name') or ''} {cd.get('last_name') or ''}"
                ).strip() or cd.get("normalized_name", "Unknown")
        out.append({
            "contact_id": cd.get("id"),
            "name": name,
            "email": email,
            "phone": phone,
            "org": org,
        })
    return out


def _slugify_handle(name: str) -> str:
    """Fold a display name onto the handle vocabulary ([a-z0-9-])."""
    import re as _re
    slug = _re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return slug or "contact"


def create_contact_vcard(conn: sqlite3.Connection, owner_profile_id: int,
                         display_name: str, phone: str = "",
                         email: str = "") -> dict:
    """Create a standard vCard profile (UX pass 2 + button, no-hit path).

    A 'standard vCard' is a registry profile carrying the entered name and
    the conventional phone/email fields at their DEFAULT visibility
    ('granted' per the UX pass 2 defaults ruling). Default cards are
    seeded for the new profile and the created fields are attached to
    their default cards, exactly like a self-published profile would look
    after seeding.

    UX pass 3 (2026-09-23): the stub profile is stamped owner_id = the
    creating owner and has no password — a CURATED profile. The card
    editor's ownership guard lets the creating owner open its editor
    ("create opens the NEW vCard with ALL fields ready to populate")
    while other accounts still 404 (ruling 2A isolation intact).

    Returns the created profile dict (with fields attached).
    Raises ValueError when display_name is empty.
    """
    name = (display_name or "").strip()
    if not name:
        raise ValueError("Display name is required.")
    phone = (phone or "").strip()
    email = (email or "").strip()

    base = _slugify_handle(name)
    handle = base
    n = 2
    while conn.execute("SELECT 1 FROM profiles WHERE handle = ?",
                       (handle,)).fetchone():
        handle = f"{base}-{n}"
        n += 1

    now = _now_iso()
    conn.execute(
        "INSERT INTO profiles (handle, display_name, owner_id, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (handle, name, owner_profile_id, now, now),
    )
    profile_id = conn.execute(
        "SELECT id FROM profiles WHERE handle = ?", (handle,)
    ).fetchone()[0]

    if phone:
        add_profile_field(conn, profile_id, "phone", phone, "granted")
    if email:
        add_profile_field(conn, profile_id, "email", email, "granted")
    seed_default_cards(conn)
    conn.commit()
    return get_profile_by_id(conn, profile_id)
