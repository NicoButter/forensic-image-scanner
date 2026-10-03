"""Controlled model import tests using only small dummy artifacts."""

import hashlib

import pytest

from forensic_image_scanner.models.exceptions import (
    ModelAlreadyInstalledError,
    ModelHashMismatchError,
)
from forensic_image_scanner.models.importer import import_model
from forensic_image_scanner.models.manifest import ModelManifest


def make_manifest(model: bytes, config: bytes) -> ModelManifest:
    """Create a valid manifest for tiny local test artifacts."""
    return ModelManifest.from_dict(
        {
            "schema_version": 1,
            "model_id": "dummy-import",
            "model_version": "1",
            "filename": "model.safetensors",
            "sha256": hashlib.sha256(model).hexdigest(),
            "source": "https://example.invalid/revision/1",
            "source_revision": "1",
            "code_license": "Apache-2.0",
            "weights_license": "Apache-2.0",
            "framework": "test",
            "input_size": [2, 2],
            "labels": ["normal", "nsfw"],
            "provenance_status": "partial",
            "size_bytes": len(model),
            "artifacts": [
                {
                    "filename": "config.json",
                    "sha256": hashlib.sha256(config).hexdigest(),
                    "size_bytes": len(config),
                }
            ],
        }
    )


def test_import_is_verified_and_atomic(tmp_path) -> None:
    model = b"safe tensors payload"
    config = b'{"model_type":"test"}'
    source_model = tmp_path / "source.safetensors"
    source_config = tmp_path / "source-config.json"
    source_model.write_bytes(model)
    source_config.write_bytes(config)

    imported = import_model(
        make_manifest(model, config),
        source_model,
        {"config.json": source_config},
        tmp_path / "controlled",
    )

    assert imported.path.read_bytes() == model
    assert imported.auxiliary_paths["config.json"].read_bytes() == config
    assert (imported.path.parent / "manifest.json").is_file()


def test_import_rejects_modified_source(tmp_path) -> None:
    source_model = tmp_path / "source.safetensors"
    source_config = tmp_path / "source-config.json"
    source_model.write_bytes(b"modified")
    source_config.write_bytes(b"config")

    with pytest.raises(ModelHashMismatchError):
        import_model(
            make_manifest(b"expected", b"config"),
            source_model,
            {"config.json": source_config},
            tmp_path / "controlled",
        )


def test_import_never_overwrites_existing_model(tmp_path) -> None:
    model = b"model"
    config = b"config"
    source_model = tmp_path / "source.safetensors"
    source_config = tmp_path / "source-config.json"
    source_model.write_bytes(model)
    source_config.write_bytes(config)
    manifest = make_manifest(model, config)
    root = tmp_path / "controlled"
    import_model(manifest, source_model, {"config.json": source_config}, root)

    with pytest.raises(ModelAlreadyInstalledError):
        import_model(manifest, source_model, {"config.json": source_config}, root)
