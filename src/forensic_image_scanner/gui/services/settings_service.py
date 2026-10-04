"""Settings and application configuration service."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class SettingsService:
    """Presents the minimal GUI configuration used by the desktop app."""

    model_directory: str = str(Path.home() / ".forensic-image-scanner" / "models")
    report_directory: str = str(Path.home() / "forensic-image-scanner-reports")
    theme: str = "Dark"
    safe_review_mode: bool = True
    log_level: str = "INFO"
    status_messages: list[str] = field(default_factory=lambda: ["OFFLINE", "READ ONLY"])
