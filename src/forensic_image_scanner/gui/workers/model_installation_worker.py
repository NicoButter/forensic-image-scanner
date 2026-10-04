"""Background worker for model installation and integrity verification."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from forensic_image_scanner.models.exceptions import ModelDownloadCancelled
from forensic_image_scanner.models.installation import ModelInstallationService


class ModelInstallationWorker(QObject):
    """Run blocking model administration without touching GUI widgets."""

    progress = Signal(int, int)
    phase_changed = Signal(str)
    completed = Signal(str)
    cancelled = Signal()
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        service: ModelInstallationService,
        action: str,
        model_id: str,
        source: Path | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.action = action
        self.model_id = model_id
        self.source = source
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def run(self) -> None:
        try:
            if self.action == "download":
                self.service.install_from_url(
                    self.model_id,
                    progress=self.progress.emit,
                    phase=self.phase_changed.emit,
                    cancelled=self._cancelled.is_set,
                )
            elif self.action == "import":
                if self.source is None:
                    raise ValueError("import source is required")
                self.service.install_from_file(
                    self.model_id, self.source, phase=self.phase_changed.emit
                )
            elif self.action == "verify":
                self.phase_changed.emit("verifying")
                self.service.verify_installed(self.model_id)
            else:
                raise ValueError(f"unknown model worker action: {self.action}")
        except ModelDownloadCancelled:
            self.cancelled.emit()
        except Exception as exc:  # pragma: no cover - converted to a visible error
            self.failed.emit(str(exc))
        else:
            self.completed.emit(self.model_id)
        finally:
            self.finished.emit()
