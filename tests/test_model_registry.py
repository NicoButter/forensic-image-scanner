"""Deterministic model manifest and registry tests."""

import hashlib
import json
from pathlib import Path

import pytest

from forensic_image_scanner.models.exceptions import (
    InvalidManifestError,
    ModelBlockedError,
    ModelIntegrityError,
    ModelNotFoundError,
)
from forensic_image_scanner.models.manifest import ModelManifest, ProvenanceStatus
from forensic_image_scanner.models.registry import ModelRegistry


def manifest_data(content: bytes = b"dummy model") -> dict[str, object]:
    """Build valid schema-v1 test data."""
    return {
        "schema_version": 1,
        "model_id": "dummy",
        "model_version": "1.0",
        "filename": "model.bin",
        "sha256": hashlib.sha256(content).hexdigest(),
        "source": "https://example.invalid/model/revision/abc123",
        "source_revision": "abc123",
        "code_license": "Apache-2.0",
        "weights_license": "Apache-2.0",
        "framework": "dummy-runtime",
        "input_size": [2, 2],
        "labels": ["negative", "positive"],
        "provenance_status": "verified",
        "size_bytes": len(content),
    }


def write_registered_model(tmp_path, data: dict[str, object], content: bytes | None) -> None:
    """Create a controlled dummy model directory."""
    model_directory = tmp_path / "dummy"
    model_directory.mkdir()
    (model_directory / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    if content is not None:
        (model_directory / "model.bin").write_bytes(content)


def test_valid_manifest() -> None:
    manifest = ModelManifest.from_dict(manifest_data())

    assert manifest.schema_version == 1
    assert manifest.input_size == (2, 2)
    assert manifest.provenance_status is ProvenanceStatus.VERIFIED


def test_invalid_manifest() -> None:
    data = manifest_data()
    data["schema_version"] = 999

    with pytest.raises(InvalidManifestError, match="unsupported schema_version"):
        ModelManifest.from_dict(data)


@pytest.mark.parametrize(
    "filename",
    ["nudenet-320n.json", "falconsai-nsfw-image-detection.json"],
)
def test_audited_reference_manifests_are_valid(filename: str) -> None:
    manifest = ModelManifest.from_file(
        Path("docs") / "model_manifests" / filename
    )

    assert manifest.schema_version == 1


def test_manifest_rejects_duplicate_auxiliary_artifact() -> None:
    data = manifest_data()
    data["artifacts"] = [
        {
            "filename": "model.bin",
            "sha256": "0" * 64,
            "size_bytes": 1,
        }
    ]

    with pytest.raises(InvalidManifestError, match="duplicate artifact filename"):
        ModelManifest.from_dict(data)


def test_correct_sha256(tmp_path) -> None:
    content = b"dummy model"
    write_registered_model(tmp_path, manifest_data(content), content)

    model = ModelRegistry(tmp_path).load("dummy")

    assert model.path.read_bytes() == content


def test_incorrect_sha256(tmp_path) -> None:
    write_registered_model(tmp_path, manifest_data(b"expected"), b"altered!")

    with pytest.raises(ModelIntegrityError, match="SHA-256 mismatch"):
        ModelRegistry(tmp_path).load("dummy")


def test_missing_model(tmp_path) -> None:
    write_registered_model(tmp_path, manifest_data(), None)

    with pytest.raises(ModelNotFoundError, match="artifact does not exist"):
        ModelRegistry(tmp_path).load("dummy")


@pytest.mark.parametrize(
    "status",
    [ProvenanceStatus.BLOCKED_LICENSE, ProvenanceStatus.BLOCKED_PROVENANCE],
)
def test_blocked_model(tmp_path, status: ProvenanceStatus) -> None:
    data = manifest_data()
    data["provenance_status"] = status.value
    write_registered_model(tmp_path, data, None)

    with pytest.raises(ModelBlockedError, match=status.value):
        ModelRegistry(tmp_path).load("dummy")
