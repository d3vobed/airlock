"""SHA-256 hashing utilities for artifact identity.

The SHA-256 digest is the authoritative identity for an artifact.
Changing any single byte of an artifact produces a different digest.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    """Return the hex SHA-256 digest of the file at ``path``."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def artifact_id(digest: str) -> str:
    """Build an immutable artifact identifier from a hex digest."""
    return f"airlock:sha256:{digest}"


def normalize_digest(value: str) -> str:
    """Return the hex part of a digest, tolerating a ``sha256:`` prefix."""
    if value.startswith("sha256:"):
        return value.split(":", 1)[1].lower()
    return value.lower()
