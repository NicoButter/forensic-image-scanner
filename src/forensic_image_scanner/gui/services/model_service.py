"""Service for reading model registry and audit metadata."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from forensic_image_scanner.model_paths import resolve_model_directory
from forensic_image_scanner.models.exceptions import ModelRegistryError
from forensic_image_scanner.models.references import load_reference_manifest, reference_model_ids
from forensic_image_scanner.models.registry import ModelRegistry


@dataclass(frozen=True, slots=True)
class ModelStatus:
    """Simple DTO describing a model entry for the GUI."""

    model_id: str
    status: str
    provenance: str
    installed: bool
    verified: bool
    label: str


class ModelService:
    """QML-free adapter around the model registry and manifest metadata."""

    def __init__(self, model_root: str | Path | None = None) -> None:
        self.model_root = Path(model_root) if model_root is not None else resolve_model_directory()

    def available_models(self) -> list[ModelStatus]:
        """Return a GUI-friendly summary of known models."""
        registry = ModelRegistry(self.model_root)
        models: list[ModelStatus] = []
        for model_id in reference_model_ids():
            manifest = load_reference_manifest(model_id)
            installed = (self.model_root / model_id / "manifest.json").is_file()
            verified = False
            status = "Not installed"
            provenance = manifest.provenance_status.value
            if installed:
                status = manifest.provenance_status.value
                if manifest.provenance_status.is_blocked:
                    verified = False
                else:
                    try:
                        registry.load(model_id)
                    except ModelRegistryError:
                        verified = False
                    else:
                        verified = True
                        status = "Verified"
            if status == "Not installed":
                provenance = "Not installed"
            models.append(
                ModelStatus(
                    model_id=model_id,
                    status=status,
                    provenance=provenance,
                    installed=installed,
                    verified=verified,
                    label=manifest.labels[0] if manifest.labels else "unknown",
                )
            )
        return models

    def verify_model(self, model_id: str) -> bool:
        """Verify a model through the registry and return the result."""
        registry = ModelRegistry(self.model_root)
        try:
            registry.load(model_id)
        except ModelRegistryError:
            return False
        return True

    def usable_model_ids(self) -> list[str]:
        """Return all models that can be used by the GUI for analysis."""
        return [
            entry.model_id
            for entry in self.available_models()
            if entry.installed and entry.verified and entry.status == "Verified"
        ]
