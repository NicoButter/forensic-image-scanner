"""Controlled, atomic, network-free model artifact import."""

import os
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path

from forensic_image_scanner.models.exceptions import (
    ModelAlreadyInstalledError,
    ModelArtifactMissingError,
)
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.models.registry import ModelRegistry, VerifiedModel
from forensic_image_scanner.models.verifier import verify_auxiliary_artifact, verify_model_file


def import_model(
    manifest: ModelManifest,
    source_model: Path,
    source_artifacts: Mapping[str, Path],
    destination_root: Path,
) -> VerifiedModel:
    """Verify and atomically register explicitly supplied local model artifacts."""
    verify_model_file(source_model, manifest)
    expected_artifacts = {artifact.filename: artifact for artifact in manifest.artifacts}
    if set(source_artifacts) != set(expected_artifacts):
        missing = sorted(set(expected_artifacts) - set(source_artifacts))
        unexpected = sorted(set(source_artifacts) - set(expected_artifacts))
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected: {', '.join(unexpected)}")
        raise ModelArtifactMissingError(
            f"auxiliary artifact set does not match manifest ({'; '.join(details)})"
        )
    for filename, artifact in expected_artifacts.items():
        verify_auxiliary_artifact(source_artifacts[filename], artifact)

    root = destination_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = root / manifest.model_id
    if destination.exists():
        raise ModelAlreadyInstalledError(f"model already installed: {destination}")

    stage_path = Path(tempfile.mkdtemp(prefix=f".{manifest.model_id}.", dir=root))
    try:
        shutil.copyfile(source_model, stage_path / manifest.filename)
        for filename, source in source_artifacts.items():
            shutil.copyfile(source, stage_path / filename)
        manifest_source = stage_path / "manifest.json"
        manifest_source.write_text(_manifest_json(manifest), encoding="utf-8")

        verify_model_file(stage_path / manifest.filename, manifest)
        for artifact in manifest.artifacts:
            verify_auxiliary_artifact(stage_path / artifact.filename, artifact)
        if destination.exists():
            raise ModelAlreadyInstalledError(f"model already installed: {destination}")
        os.rename(stage_path, destination)
    except Exception:
        if stage_path.exists():
            shutil.rmtree(stage_path)
        raise
    return ModelRegistry(root).load(manifest.model_id)


def _manifest_json(manifest: ModelManifest) -> str:
    """Serialize the validated manifest with only deterministic schema-v1 fields."""
    import json

    data = {
        "schema_version": manifest.schema_version,
        "model_id": manifest.model_id,
        "model_version": manifest.model_version,
        "filename": manifest.filename,
        "sha256": manifest.sha256,
        "source": manifest.source,
        "source_revision": manifest.source_revision,
        "code_license": manifest.code_license,
        "weights_license": manifest.weights_license,
        "framework": manifest.framework,
        "input_size": list(manifest.input_size),
        "labels": list(manifest.labels),
        "provenance_status": manifest.provenance_status.value,
        "size_bytes": manifest.size_bytes,
        **({"source_url": manifest.source_url} if manifest.source_url else {}),
        "artifacts": [
            {
                "filename": artifact.filename,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                **({"source_url": artifact.source_url} if artifact.source_url else {}),
            }
            for artifact in manifest.artifacts
        ],
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"
