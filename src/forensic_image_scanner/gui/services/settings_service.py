"""Settings and application configuration service."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings


class SettingsService:
    """Wraps Qt settings and keeps application configuration off widgets."""

    def __init__(self, organization: str = "Forensic Image Scanner") -> None:
        self.settings = QSettings(organization, "Forensic Image Scanner")

    @property
    def model_directory(self) -> str:
        default = str(Path.home() / ".forensic-image-scanner" / "models")
        return self.settings.value("model_directory", default, type=str)

    @model_directory.setter
    def model_directory(self, value: str) -> None:
        self.settings.setValue("model_directory", value)

    @property
    def report_directory(self) -> str:
        default = str(Path.home() / "forensic-image-scanner-reports")
        return self.settings.value("report_directory", default, type=str)

    @report_directory.setter
    def report_directory(self, value: str) -> None:
        self.settings.setValue("report_directory", value)

    @property
    def theme(self) -> str:
        return self.settings.value("theme", "Dark", type=str)

    @theme.setter
    def theme(self, value: str) -> None:
        self.settings.setValue("theme", value)

    @property
    def safe_review_mode(self) -> bool:
        return self.settings.value("safe_review_mode", True, type=bool)

    @safe_review_mode.setter
    def safe_review_mode(self, value: bool) -> None:
        self.settings.setValue("safe_review_mode", value)
