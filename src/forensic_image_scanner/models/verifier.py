"""Bounded-memory model artifact integrity verification."""

from pathlib import Path

from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.models.exceptions import (
    ModelArtifactMissingError,
    ModelHashMismatchError,
    ModelIntegrityError,
)
from forensic_image_scanner.models.manifest import ArtifactManifest, ModelManifest


def verify_model_file(path: Path, manifest: ModelManifest) -> None:
    """Verify existence, optional byte size, and SHA-256 of an artifact."""
    if not path.is_file():
        raise ModelArtifactMissingError(f"model artifact does not exist: {path}")
    if manifest.size_bytes is not None and path.stat().st_size != manifest.size_bytes:
        raise ModelIntegrityError(
            f"model size mismatch for {manifest.model_id}: expected {manifest.size_bytes}, "
            f"found {path.stat().st_size}"
        )
    actual_sha256 = sha256_file(path)
    if actual_sha256 != manifest.sha256:
        raise ModelHashMismatchError(
            f"model SHA-256 mismatch for {manifest.model_id}: "
            f"expected {manifest.sha256}, found {actual_sha256}"
        )


def verify_auxiliary_artifact(path: Path, artifact: ArtifactManifest) -> None:
    """Verify one required auxiliary artifact."""
    if not path.is_file():
        raise ModelArtifactMissingError(f"model artifact does not exist: {path}")
    if path.stat().st_size != artifact.size_bytes:
        raise ModelIntegrityError(
            f"model size mismatch for {artifact.filename}: expected {artifact.size_bytes}, "
            f"found {path.stat().st_size}"
        )
    actual_sha256 = sha256_file(path)
    if actual_sha256 != artifact.sha256:
        raise ModelHashMismatchError(
            f"model SHA-256 mismatch for {artifact.filename}: "
            f"expected {artifact.sha256}, found {actual_sha256}"
        )
