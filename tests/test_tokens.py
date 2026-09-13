"""Tests for wl_tokens.py — HMAC token round-trip and invalidation."""

import time

import wl_tokens


SECRET = b"test-secret-for-hmac-validation-only"


def test_round_trip_valid():
    """Valid token is accepted and payload is returned."""
    token = wl_tokens.make_token(SECRET, "test_purpose", "my-payload", expires_days=7)
    result = wl_tokens.consume_token(SECRET, "test_purpose", token)
    assert result == "my-payload"


def test_round_trip_different_purpose():
    """Token with wrong purpose returns None."""
    token = wl_tokens.make_token(SECRET, "test_purpose", "my-payload", expires_days=7)
    result = wl_tokens.consume_token(SECRET, "wrong_purpose", token)
    assert result is None


def test_tampered_payload_returns_none():
    """Tampered payload (corrupted base64) returns None."""
    token = wl_tokens.make_token(SECRET, "test_purpose", "my-payload", expires_days=7)
    # Corrupt the payload part (before the dot)
    parts = token.split(".")
    corrupted = "XXXX" + parts[1][4:]  # replace first 4 chars of payload
    result = wl_tokens.consume_token(SECRET, "test_purpose", corrupted)
    assert result is None


def test_expired_token_returns_none():
    """Token with 0-day expiry is expired and returns None."""
    token = wl_tokens.make_token(SECRET, "test_purpose", "my-payload", expires_days=0)
    # Wait a moment to ensure time passes
    time.sleep(1.1)
    result = wl_tokens.consume_token(SECRET, "test_purpose", token)
    assert result is None


def test_right_sig_wrong_purpose():
    """Correct signature but wrong purpose → None."""
    token = wl_tokens.make_token(SECRET, "purpose_a", "payload", expires_days=7)
    result = wl_tokens.consume_token(SECRET, "purpose_b", token)
    assert result is None


def test_wrong_secret_returns_none():
    """Token signed with different secret → None."""
    token = wl_tokens.make_token(SECRET, "test_purpose", "my-payload", expires_days=7)
    result = wl_tokens.consume_token(b"different-secret", "test_purpose", token)
    assert result is None
