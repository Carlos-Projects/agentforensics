"""Cryptographic utilities for evidence integrity."""

from __future__ import annotations

import hashlib
import hmac


def sha256(data: bytes) -> str:
    """Compute SHA-256 hash.

    Args:
        data: Input bytes.

    Returns:
        Hex-encoded hash string.
    """
    return hashlib.sha256(data).hexdigest()


def hmac_sign(data: bytes, key: bytes) -> str:
    """Compute HMAC-SHA256 signature.

    Args:
        data: Data to sign.
        key: Signing key.

    Returns:
        Hex-encoded HMAC signature.
    """
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes, key: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature.

    Args:
        data: Original data.
        key: Signing key.
        signature: Hex-encoded signature to verify.

    Returns:
        True if signature is valid.
    """
    expected = hmac_sign(data, key)
    return hmac.compare_digest(expected, signature)
