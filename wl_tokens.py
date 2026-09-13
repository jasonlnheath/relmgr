"""HMAC-based token generation and consumption for whitelist."""

import base64
import hashlib
import hmac
import time
from typing import Optional


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def make_token(
    secret: bytes,
    purpose: str,
    payload: str,
    expires_days: int = 7,
) -> str:
    """Create an HMAC-SHA256 token.

    Token format: base64url(payload|expiry_unix).HMAC-SHA256(purpose|payload|expiry_unix, secret)
    """
    expiry_unix = str(int(time.time()) + expires_days * 86400)
    inner = f"{payload}|{expiry_unix}"
    payload_b64 = _b64url_encode(inner.encode("utf-8"))

    signing_input = f"{purpose}|{payload_b64}|{expiry_unix}"
    sig = hmac.new(
        secret,
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"{payload_b64}.{sig}"


def consume_token(
    secret: bytes,
    purpose: str,
    token: str,
) -> Optional[str]:
    """Validate and consume an HMAC token.

    Returns the decoded payload string on success, None on any failure
    (tampered payload, expired, wrong purpose, bad signature).
    """
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None

        payload_b64, provided_sig = parts
        inner = _b64url_decode(payload_b64).decode("utf-8")
        parts2 = inner.rsplit("|", 1)
        if len(parts2) != 2:
            return None
        payload, expiry_str = parts2
        expiry_unix = int(expiry_str)

        # Check expiry
        if int(time.time()) > expiry_unix:
            return None

        # Verify HMAC with timing-safe comparison
        signing_input = f"{purpose}|{payload_b64}|{expiry_str}"
        expected_sig = hmac.new(
            secret,
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(provided_sig, expected_sig):
            return None

        return payload
    except Exception:
        return None
