"""Deterministic controlled-model directory resolution."""

import os
from pathlib import Path

ENVIRONMENT_VARIABLE = "FORENSIC_IMAGE_SCANNER_MODEL_DIR"


def resolve_model_directory(explicit: Path | None) -> Path:
    """Resolve model root: CLI option, environment variable, then platform default."""
    if explicit is not None:
        return explicit.expanduser()
    configured = os.environ.get(ENVIRONMENT_VARIABLE)
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "forensic-image-scanner" / "models"
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return data_home / "forensic-image-scanner" / "models"
