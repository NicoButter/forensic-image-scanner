"""Cryptographic hashing helpers for original evidence files."""

import hashlib
from pathlib import Path

DEFAULT_CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Calculate a file's SHA-256 using bounded-memory block reads."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
