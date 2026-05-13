"""RelMgr configuration — data sources and auth settings."""

import os
from pathlib import Path

# Database
DB_PATH = Path(__file__).parent / "contacts.db"

# Source configuration
SOURCES = {
    "google": {
        "enabled": False,
        "scope": "https://www.googleapis.com/auth/contacts.readonly",
        "credentials_file": None,  # ~/.hermes/google_token.json used by default
    },
    "apple": {
        "enabled": False,
        "csv_path": None,  # Export from iCloud.com → Contacts → Export vCard
    },
    "outlook": {
        "enabled": False,
        "client_id": os.getenv("OUTLOOK_CLIENT_ID"),
        "tenant_id": os.getenv("OUTLOOK_TENANT_ID"),
        "client_secret": os.getenv("OUTLOOK_CLIENT_SECRET"),
    },
    "android": {
        "enabled": False,
        "vcf_path": None,  # Exported VCF file from Android contacts app
        "csv_path": None,  # Alternative: exported CSV
    },
}

# Deduplication thresholds
DEDUP_EXACT = 0.80      # Auto-merge
DEDUP_REVIEW = 0.50     # Flag for manual review
DEDUP_FUZZY_NAME_THRESHOLD = 0.85  # Levenshtein similarity threshold

# Output
EXPORT_DIR = Path(__file__).parent / "exports"
