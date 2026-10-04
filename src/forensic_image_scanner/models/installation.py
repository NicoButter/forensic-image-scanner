"""High-level, atomic model installation and administration service."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from forensic_image_scanner.models.downloader import download_verified
from forensic_image_scanner.models.exceptions import (
    ModelAlreadyInstalledError,
    ModelArtifactMissingError,
    ModelBlockedError,
    ModelDownloadCancelled,
    ModelDownloadError,
    ModelNotInstalledError,
)
from forensic_image_scanner.models.importer import _manifest_json
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.models.references import load_reference_manifest
from forensic_image_scanner.models.registry import ModelRegistry, VerifiedModel
from forensic_image_scanner.models.verifier import verify_auxiliary_artifact, verify_model_file

LOGGER = logging.getLogger(__name__)
ProgressCallback = Callable[[int, int], None]
PhaseCallback = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class InstallArtifact:
    filename: str
    size_bytes: int
    sha256: str
    source_url: str | None
    primary: bool = False


class ModelInstallationService:
    """Install only bundled, audited model definitions into a controlled root."""

    def __init__(self, model_root: str | Path) -> None:
        self.model_root = Path(model_root).expanduser().resolve()

    def install_from_url(
        self,
        model_id: str,
        *,
        progress: ProgressCallback | None = None,
        phase: PhaseCallback | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> VerifiedModel:
        manifest = self._installable_manifest(model_id)
        self._protect_existing(model_id)
        artifacts = self._artifacts(manifest)
        if any(not artifact.source_url for artifact in artifacts):
            raise ModelDownloadError("audited manifest does not declare every artifact URL")

        LOGGER.info("model download requested: %s", model_id)
        self.model_root.mkdir(parents=True, exist_ok=True)
        download_root = self.model_root / ".downloads"
        download_root.mkdir(exist_ok=True)
        task_directory = Path(tempfile.mkdtemp(prefix=f"{model_id}.", dir=download_root))
        total = sum(artifact.size_bytes for artifact in artifacts)
        completed = 0
        try:
            LOGGER.info("model download started: %s", model_id)
            if phase is not None:
                phase("downloading")
            for artifact in artifacts:
                if cancelled is not None and cancelled():
                    raise ModelDownloadCancelled("model download cancelled")
                destination = task_directory / f"{artifact.filename}.part"
                base = completed
                download_verified(
                    artifact.source_url or "",
                    destination,
                    artifact.size_bytes,
                    artifact.sha256,
                    progress=(
                        (lambda received, _size, offset=base: progress(offset + received, total))
                        if progress is not None
                        else None
                    ),
                    cancelled=cancelled,
                )
                completed += artifact.size_bytes
            return self._install_verified_parts(manifest, artifacts, task_directory, phase)
        except Exception:
            LOGGER.exception("model installation failed: %s", model_id)
            raise
        finally:
            shutil.rmtree(task_directory, ignore_errors=True)

    def install_from_file(
        self,
        model_id: str,
        source: str | Path,
        *,
        phase: PhaseCallback | None = None,
    ) -> VerifiedModel:
        manifest = self._installable_manifest(model_id)
        self._protect_existing(model_id)
        source_path = Path(source).expanduser()
        if not source_path.is_dir() or source_path.is_symlink():
            raise ModelArtifactMissingError(
                "local import requires a real directory containing every declared artifact"
            )
        source_root = source_path.resolve(strict=True)
        artifacts = self._artifacts(manifest)
        self.model_root.mkdir(parents=True, exist_ok=True)
        download_root = self.model_root / ".downloads"
        download_root.mkdir(exist_ok=True)
        task_directory = Path(tempfile.mkdtemp(prefix=f"{model_id}.import.", dir=download_root))
        try:
            for artifact in artifacts:
                candidate = source_root / artifact.filename
                if candidate.is_symlink() or not candidate.is_file():
                    raise ModelArtifactMissingError(
                        f"required regular artifact is missing: {artifact.filename}"
                    )
                resolved = candidate.resolve(strict=True)
                if not resolved.is_relative_to(source_root):
                    raise ModelArtifactMissingError(
                        f"artifact escapes import directory: {artifact.filename}"
                    )
                destination = task_directory / f"{artifact.filename}.part"
                shutil.copyfile(resolved, destination)
            return self._install_verified_parts(manifest, artifacts, task_directory, phase)
        finally:
            shutil.rmtree(task_directory, ignore_errors=True)

    def verify_installed(self, model_id: str) -> VerifiedModel:
        LOGGER.info("verification started: %s", model_id)
        verified = ModelRegistry(self.model_root).load(model_id)
        LOGGER.info("verification success: %s", model_id)
        return verified

    def remove(self, model_id: str) -> None:
        self._known_manifest(model_id)
        destination = self.model_root / model_id
        if not destination.exists():
            raise ModelNotInstalledError(f"model is not installed: {model_id}")
        if destination.is_symlink() or not destination.is_dir():
            raise ModelNotInstalledError("refusing to remove a non-directory model path")
        shutil.rmtree(destination)
        LOGGER.info("installation removed: %s", model_id)

    def is_installed(self, model_id: str) -> bool:
        self._known_manifest(model_id)
        return (self.model_root / model_id / "manifest.json").is_file()

    def _install_verified_parts(
        self,
        manifest: ModelManifest,
        artifacts: tuple[InstallArtifact, ...],
        part_directory: Path,
        phase: PhaseCallback | None,
    ) -> VerifiedModel:
        if phase is not None:
            phase("verifying")
        LOGGER.info("verification started: %s", manifest.model_id)
        primary = part_directory / f"{manifest.filename}.part"
        verify_model_file(primary, manifest)
        by_name = {artifact.filename: artifact for artifact in manifest.artifacts}
        for artifact in artifacts:
            if not artifact.primary:
                verify_auxiliary_artifact(
                    part_directory / f"{artifact.filename}.part", by_name[artifact.filename]
                )
        LOGGER.info("verification success: %s", manifest.model_id)

        if phase is not None:
            phase("installing")
        installing_root = self.model_root / ".installing"
        installing_root.mkdir(exist_ok=True)
        container = Path(tempfile.mkdtemp(prefix="transaction.", dir=installing_root))
        staged = container / manifest.model_id
        staged.mkdir()
        try:
            for artifact in artifacts:
                os.replace(
                    part_directory / f"{artifact.filename}.part", staged / artifact.filename
                )
            (staged / "manifest.json").write_text(_manifest_json(manifest), encoding="utf-8")
            verified = ModelRegistry(container).load(manifest.model_id)
            destination = self.model_root / manifest.model_id
            if destination.exists():
                raise ModelAlreadyInstalledError(
                    f"model already installed; refusing to overwrite: {destination}"
                )
            os.rename(staged, destination)
            LOGGER.info("installation completed: %s", manifest.model_id)
            return VerifiedModel(
                verified.manifest,
                destination / verified.path.name,
                {
                    name: destination / path.name
                    for name, path in verified.auxiliary_paths.items()
                },
            )
        finally:
            shutil.rmtree(container, ignore_errors=True)

    def _protect_existing(self, model_id: str) -> None:
        destination = self.model_root / model_id
        if destination.exists():
            try:
                self.verify_installed(model_id)
            except Exception as exc:
                raise ModelAlreadyInstalledError(
                    f"existing model directory is protected: {destination}"
                ) from exc
            raise ModelAlreadyInstalledError("Model already installed and verified.")

    @staticmethod
    def _known_manifest(model_id: str) -> ModelManifest:
        return load_reference_manifest(model_id)

    def _installable_manifest(self, model_id: str) -> ModelManifest:
        manifest = self._known_manifest(model_id)
        if manifest.provenance_status.is_blocked:
            raise ModelBlockedError(f"model installation is blocked: {model_id}")
        return manifest

    @staticmethod
    def _artifacts(manifest: ModelManifest) -> tuple[InstallArtifact, ...]:
        if manifest.size_bytes is None:
            raise ModelArtifactMissingError("primary artifact has no declared size")
        primary = InstallArtifact(
            manifest.filename,
            manifest.size_bytes,
            manifest.sha256,
            manifest.source_url,
            True,
        )
        auxiliary = tuple(
            InstallArtifact(
                artifact.filename,
                artifact.size_bytes,
                artifact.sha256,
                artifact.source_url,
            )
            for artifact in manifest.artifacts
        )
        return (primary, *auxiliary)
