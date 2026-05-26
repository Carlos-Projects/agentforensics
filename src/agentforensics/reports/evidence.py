"""Evidence chain of custody management with cryptographic integrity."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from agentforensics.utils.crypto import sha256

_CHAIN: list[dict[str, Any]] = []


def compute_evidence_hash(data: bytes) -> str:
    """Compute SHA-256 hash for evidence integrity.

    Args:
        data: Raw evidence bytes.

    Returns:
        Hex-encoded SHA-256 hash.
    """
    return sha256(data)


def create_chain_entry(
    evidence_id: str,
    hash_value: str,
    collector: str = "agentforensics",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a chain of custody entry with parent linkage.

    Each entry includes a ``parent_hash`` field linking to the previous
    entry, forming a tamper-evident hash chain.

    Args:
        evidence_id: Unique evidence identifier.
        hash_value: SHA-256 hash of evidence.
        collector: Identity of the collector.
        metadata: Optional metadata dict.

    Returns:
        Chain of custody entry dictionary.
    """
    parent_hash = _CHAIN[-1]["entry_hash"] if _CHAIN else "0" * 64
    timestamp = datetime.now(UTC).isoformat()

    entry_data = json.dumps(
        {
            "evidence_id": evidence_id,
            "hash": hash_value,
            "parent_hash": parent_hash,
            "collector": collector,
            "timestamp": timestamp,
            "action": "collected",
            "metadata": metadata or {},
        },
        sort_keys=True,
    ).encode()

    entry_hash = sha256(entry_data)

    entry: dict[str, Any] = {
        "entry_hash": entry_hash,
        "evidence_id": evidence_id,
        "hash": hash_value,
        "parent_hash": parent_hash,
        "collector": collector,
        "timestamp": timestamp,
        "action": "collected",
        "metadata": metadata or {},
    }

    _CHAIN.append(entry)
    return entry


def get_chain() -> list[dict[str, Any]]:
    """Return the full chain of custody."""
    return list(_CHAIN)


def verify_chain() -> tuple[bool, list[str]]:
    """Verify integrity of the entire chain of custody.

    Checks:
    1. Every entry's ``entry_hash`` matches a recomputation.
    2. Every entry's ``parent_hash`` matches the previous entry's hash.
    3. The first entry's ``parent_hash`` is the zero-hash.

    Returns:
        Tuple of ``(is_valid: bool, errors: list[str])``.
    """
    errors: list[str] = []

    for i, entry in enumerate(_CHAIN):
        recomputed = sha256(
            json.dumps(
                {
                    "evidence_id": entry["evidence_id"],
                    "hash": entry["hash"],
                    "parent_hash": entry["parent_hash"],
                    "collector": entry["collector"],
                    "timestamp": entry["timestamp"],
                    "action": entry["action"],
                    "metadata": entry.get("metadata", {}),
                },
                sort_keys=True,
            ).encode()
        )
        if recomputed != entry["entry_hash"]:
            errors.append(f"Entry {i}: hash mismatch (tamper detected)")

    for i in range(1, len(_CHAIN)):
        if _CHAIN[i]["parent_hash"] != _CHAIN[i - 1]["entry_hash"]:
            errors.append(f"Entry {i}: parent_hash chain broken")

    if _CHAIN and _CHAIN[0]["parent_hash"] != "0" * 64:
        errors.append("Entry 0: first entry parent_hash must be zero-hash")

    return len(errors) == 0, errors


def clear_chain() -> None:
    """Clear the chain of custody (for testing)."""
    _CHAIN.clear()
