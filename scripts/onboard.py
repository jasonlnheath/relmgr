#!/usr/bin/env python3
"""RelMgr Onboarding — interactive setup for all contact sources."""

import json
import os
import sys
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def prompt(msg: str, default: str = "") -> str:
    """Interactive prompt with optional default."""
    if default:
        answer = input(f"{msg} [{default}]: ").strip()
        return answer if answer else default
    return input(f"{msg}: ").strip()


def confirm(msg: str) -> bool:
    """Yes/No confirmation."""
    answer = input(f"{msg} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def refresh_google_token(token_path: str) -> bool:
    """Refresh Google OAuth token using stored refresh token."""
    print("\n--- Google Contacts ---")
    print("Checking existing OAuth token...")

    if not os.path.exists(token_path):
        print("No existing token found. You'll need to authenticate via Gmail onboarding.")
        print("For now, we'll skip Google and you can add it later.")
        return False

    try:
        with open(token_path) as f:
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

        if creds.valid:
            print("✓ Token is already valid")
            return True

        creds.refresh(Request())
        data["access_token"] = creds.token
        data["expiry"] = creds.expiry.isoformat() if creds.expiry else ""
        data["valid"] = True
        data["expired"] = False

        with open(token_path, "w") as f:
            json.dump(data, f, indent=2)

        print("✓ Token refreshed successfully")
        return True

    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("  Install with: pip install google-api-python-client google-auth")
        return False
    except Exception as e:
        print(f"✗ Error refreshing token: {e}")
        print("  You can fix this later by re-running onboarding or manually refreshing.")
        return False


def setup_source_path(name: str, extensions: tuple = (".csv", ".vcf"), default_dir: str = None) -> str | None:
    """Prompt user for a file path, validating extension."""
    print(f"\n--- {name} ---")
    print(f"Where is your {name.lower()} export file?")
    print(f"  Supported formats: {', '.join(extensions)}")

    if default_dir and os.path.isdir(default_dir):
        print(f"  Default directory: {default_dir}")

    while True:
        path = prompt("File path", default_dir or "")
        if not path:
            print("  Skipping this source (you can add it later)")
            return None

        p = Path(path)
        if not p.exists():
            print(f"  ✗ File not found: {path}")
            continue

        ext = p.suffix.lower()
        if ext not in extensions:
            print(f"  ✗ Unsupported format: {ext}. Expected: {', '.join(extensions)}")
            continue

        print(f"  ✓ Found: {p.name} ({p.stat().st_size:,} bytes)")
        return str(p.resolve())


def setup_google_contacts(token_path: str, config: dict) -> bool:
    """Set up Google Contacts source."""
    print("\n--- Google Contacts ---")
    print("This uses your existing Gmail OAuth token.")

    if os.path.exists(token_path):
        if confirm("Refresh existing token?"):
            success = refresh_google_token(token_path)
            if success:
                config["google"] = {"enabled": True, "credentials_file": token_path}
                print("✓ Google Contacts enabled")
                return True
    else:
        print("No existing token found. You'll need to authenticate separately.")

    if confirm("Skip Google for now? (you can add it later)"):
        config["google"] = {"enabled": False}
        return True

    return False


def setup_apple_contacts(config: dict) -> bool:
    """Set up Apple/iCloud contacts via VCF export."""
    print("\n--- Apple/iCloud Contacts ---")
    print("To export from iCloud:")
    print("  1. Go to icloud.com/contacts in a browser")
    print("  2. Select all contacts (⌘A or Ctrl+A)")
    print("  3. Click gear icon → Export vCard")
    print("  4. Save the .vcf file and provide its path below")

    path = setup_source_path("Apple/iCloud", (".vcf",), default_dir=os.path.expanduser("~/Downloads"))
    if path:
        config["apple"] = {"enabled": True, "csv_path": path}
        print("✓ Apple/iCloud Contacts configured")
        return True

    config["apple"] = {"enabled": False}
    return False


def setup_outlook_contacts(config: dict) -> bool:
    """Set up Outlook contacts via CSV export."""
    print("\n--- Outlook/Exchange Contacts ---")
    print("To export from Outlook:")
    print("  Web: outlook.com/contacts → Settings → Export contacts")
    print("  Desktop: File → Open & Export → Import/Export → Export to CSV")
    print("  Corporate: Ask IT to export your contacts as CSV")

    path = setup_source_path("Outlook", (".csv",), default_dir=os.path.expanduser("~/Documents"))
    if path:
        config["outlook"] = {"enabled": True, "csv_path": path}
        print("✓ Outlook Contacts configured")
        return True

    config["outlook"] = {"enabled": False}
    return False


def setup_android_contacts(config: dict) -> bool:
    """Set up Android contacts via VCF/CSV export."""
    print("\n--- Android Contacts ---")
    print("To export from Android:")
    print("  1. Open Contacts app → Settings")
    print("  2. Import/Export → Export to storage")
    print("  3. This creates a .vcf file on your phone")
    print("  4. Transfer the file to this computer (USB, cloud, etc.)")

    path = setup_source_path("Android", (".vcf", ".csv"), default_dir=os.path.expanduser("~/Downloads"))
    if path:
        config["android"] = {"enabled": True, "vcf_path": path}
        print("✓ Android Contacts configured")
        return True

    config["android"] = {"enabled": False}
    return False


def save_config(config: dict, config_path: Path) -> None:
    """Save configuration to config.yaml."""
    # Write as Python config for easy import
    with open(config_path, "w") as f:
        f.write("# RelMgr configuration — auto-generated by onboarding\n\n")
        f.write("import os\n")
        f.write("from pathlib import Path\n\n")
        f.write("DB_PATH = Path(__file__).parent / 'contacts.db'\n\n")
        f.write("SOURCES = {\n")
        for source, settings in config.items():
            f.write(f"    \"{source}\": {{\n")
            for key, value in settings.items():
                if isinstance(value, str):
                    f.write(f'        "{key}": {json.dumps(value)},\n')
                elif isinstance(value, bool):
                    f.write(f'        "{key}": {str(value).lower()},\n')
                else:
                    f.write(f'        "{key}": {json.dumps(value)},\n')
            f.write("    },\n")
        f.write("}\n\n")
        f.write("# Deduplication thresholds\n")
        f.write("DEDUP_EXACT = 0.80      # Auto-merge at this score\n")
        f.write("DEDUP_REVIEW = 0.50     # Flag for manual review below this\n")
        f.write("DEDUP_FUZZY_NAME_THRESHOLD = 0.75  # Fuzzy name match threshold\n")

    print(f"\n✓ Configuration saved to {config_path}")


def main():
    print("=" * 60)
    print("  RelMgr — Contact Onboarding")
    print("=" * 60)
    print()
    print("This will walk you through setting up each contact source.")
    print("You can always re-run onboarding later to add or change sources.\n")

    config = {}
    config_path = Path(__file__).parent.parent / "config.py"
    token_path = "/home/jason/.hermes/google_token.json"

    # Google (optional but recommended)
    if confirm("Set up Google Contacts?"):
        setup_google_contacts(token_path, config)

    # Apple/iCloud
    if confirm("\nSet up Apple/iCloud Contacts?"):
        setup_apple_contacts(config)

    # Outlook
    if confirm("\nSet up Outlook/Exchange Contacts?"):
        setup_outlook_contacts(config)

    # Android
    if confirm("\nSet up Android Contacts?"):
        setup_android_contacts(config)

    # Save config
    save_config(config, config_path)

    # Summary
    enabled = [k for k, v in config.items() if v.get("enabled")]
    print(f"\n{'=' * 60}")
    print(f"  Setup complete!")
    print(f"  Enabled sources: {', '.join(enabled) if enabled else 'None'}")
    print(f"  Run 'python cli.py sync' to fetch contacts")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
