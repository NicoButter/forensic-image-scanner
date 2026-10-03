"""Hashing tests."""

import hashlib

import pytest

from forensic_image_scanner.hashing import sha256_file


def test_sha256_file_reads_in_blocks(tmp_path) -> None:
    content = (b"forensic evidence\x00" * 1000) + b"tail"
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(content)

    assert sha256_file(evidence, chunk_size=17) == hashlib.sha256(content).hexdigest()


def test_sha256_rejects_invalid_chunk_size(tmp_path) -> None:
    evidence = tmp_path / "empty.bin"
    evidence.touch()

    with pytest.raises(ValueError, match="greater than zero"):
        sha256_file(evidence, chunk_size=0)
