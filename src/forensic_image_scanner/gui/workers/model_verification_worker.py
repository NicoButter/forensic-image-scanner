"""Background worker used to verify a model path through the registry."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Signal

from forensic_image_scanner.models.registry import ModelRegistry


class ModelVerificationWorker(QObject):
    """Verify a model registry entry without blocking the UI."""

    started = Signal(str)
    completed = Signal(bool, str)
    failed = Signal(str)

    def __init__(self, model_root: str, model_id: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.model_root = Path(model_root)
        self.model_id = model_id

    def run(self) -> None:
        self.started.emit(self.model_id)
        try:
            verified = ModelRegistry(self.model_root).load(self.model_id)
            self.completed.emit(True, verified.manifest.model_id)
        except Exception as exc:  # pragma: no cover - surfaced as user-visible error
            self.completed.emit(False, str(exc))
