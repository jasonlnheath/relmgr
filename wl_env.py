"""Environment variable loader for whitelist — reads env then .env file."""

import os
from pathlib import Path

_ENV_FILE = Path(__file__).parent / ".env"


def get_secret(key: str) -> str:
    """Return env var *key*, falling back to .env file.

    Reads os.environ first, then parses KEY=VALUE lines from .env.
    """
    value = os.environ.get(key)
    if value:
        return value
    if _ENV_FILE.exists():
        with open(_ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() == key:
                        return v.strip()
    return ""
