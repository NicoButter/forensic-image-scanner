"""Versioned, bundled reference manifests for explicitly audited models."""

import json
from importlib.resources import files

from forensic_image_scanner.models.exceptions import ModelNotInstalledError
from forensic_image_scanner.models.manifest import ModelManifest


def load_reference_manifest(model_id: str) -> ModelManifest:
    """Load a bundled audit manifest without consulting any network service."""
    if not model_id or "/" in model_id or "\\" in model_id:
        raise ModelNotInstalledError("model_id must be a plain directory name")
    manifest_path = files("forensic_image_scanner.model_manifests").joinpath(
        f"{model_id}.json"
    )
    if not manifest_path.is_file():
        raise ModelNotInstalledError(f"no audited reference manifest for {model_id!r}")
    return ModelManifest.from_dict(json.loads(manifest_path.read_text(encoding="utf-8")))


def reference_model_ids() -> tuple[str, ...]:
    """Return the audited model IDs bundled with this package."""
    directory = files("forensic_image_scanner.model_manifests")
    return tuple(
        sorted(
            path.name.removesuffix(".json")
            for path in directory.iterdir()
            if path.name.endswith(".json")
        )
    )
