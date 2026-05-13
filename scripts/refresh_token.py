#!/usr/bin/env python3
"""Refresh Google OAuth token using stored refresh token."""

import json
import sys
from pathlib import Path

TOKEN_PATH = Path("/home/jason/.hermes/google_token.json")


def refresh():
    if not TOKEN_PATH.exists():
        print("ERROR: No token file found")
        return False

    with open(TOKEN_PATH) as f:
        data = json.load(f)

    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request

    creds = Credentials(
        token=data.get("access_token"),
        refresh_token=data.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=data["client_id"],
        client_secret=data["client_secret"],
        scopes=data.get("scopes", []),
    )

    try:
        creds.refresh(Request())
    except Exception as e:
        print(f"ERROR: {e}")
        return False

    # Update token file
    data["access_token"] = creds.token
    data["expiry"] = creds.expiry.isoformat() if creds.expiry else ""
    data["valid"] = True
    data["expired"] = False

    with open(TOKEN_PATH, "w") as f:
        json.dump(data, f, indent=2)

    print("Token refreshed successfully")
    return True


if __name__ == "__main__":
    success = refresh()
    sys.exit(0 if success else 1)
