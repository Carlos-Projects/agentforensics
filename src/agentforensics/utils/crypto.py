"""Cryptographic utilities for evidence integrity."""

from __future__ import annotations

import hashlib


def sha256(data: bytes) -> str:
    """Compute SHA-256 hash.

    Args:
        data: Input bytes.

    Returns:
        Hex-encoded hash string.
    """
    return hashlib.sha256(data).hexdigest()
