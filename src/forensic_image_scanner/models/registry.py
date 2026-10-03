"""Filesystem-backed, network-free model registry."""

from dataclasses import dataclass
from pathlib import Path

from forensic_image_scanner.models.exceptions import (
    InvalidManifestError,
    ModelBlockedError,
    ModelNotInstalledError,
)
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.models.verifier import verify_auxiliary_artifact, verify_model_file


@dataclass(frozen=True, slots=True)
class VerifiedModel:
    """A manifest and artifact that passed policy and integrity checks."""

    manifest: ModelManifest
    path: Path
    auxiliary_paths: dict[str, Path]


class ModelRegistry:
    """Resolve only explicitly imported models beneath a controlled root."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def load(self, model_id: str) -> VerifiedModel:
        """Load and verify a registered model without any network access."""
        if not model_id or Path(model_id).name != model_id or model_id in {".", ".."}:
            raise InvalidManifestError("model_id must be a plain directory name")

        model_directory = self.root / model_id
        manifest_path = model_directory / "manifest.json"
        try:
            manifest = ModelManifest.from_file(manifest_path)
        except FileNotFoundError as exc:
            raise ModelNotInstalledError(f"model manifest does not exist: {manifest_path}") from exc

        if manifest.model_id != model_id:
            raise InvalidManifestError(
                f"manifest model_id {manifest.model_id!r} does not match directory {model_id!r}"
            )
        if manifest.provenance_status.is_blocked:
            raise ModelBlockedError(
                f"model {model_id!r} is blocked: {manifest.provenance_status.value}"
            )

        model_path = model_directory / manifest.filename
        verify_model_file(model_path, manifest)
        auxiliary_paths: dict[str, Path] = {}
        for artifact in manifest.artifacts:
            artifact_path = model_directory / artifact.filename
            verify_auxiliary_artifact(artifact_path, artifact)
            auxiliary_paths[artifact.filename] = artifact_path
        return VerifiedModel(manifest=manifest, path=model_path, auxiliary_paths=auxiliary_paths)

    def registered_model_ids(self) -> tuple[str, ...]:
        """List directories containing a manifest, without loading artifacts."""
        if not self.root.is_dir():
            return ()
        return tuple(
            child.name
            for child in sorted(self.root.iterdir())
            if child.is_dir() and (child / "manifest.json").is_file()
        )
