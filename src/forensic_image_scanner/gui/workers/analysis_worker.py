"""Qt worker for sequential evidence analysis."""

from __future__ import annotations

import threading

from PySide6.QtCore import QObject, Signal

from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService


class AnalysisWorker(QObject):
    """Run AnalysisService off the GUI thread with cooperative cancellation."""

    started = Signal(int)
    file_started = Signal(int, int, str)
    file_completed = Signal(object)
    progress = Signal(int, int)
    error = Signal(str, str)
    cancelled = Signal(object)
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        service: AnalysisService,
        request: AnalysisRequest,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.request = request
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def run(self) -> None:
        try:
            summary = self.service.run(
                self.request,
                cancelled=self._cancelled.is_set,
                started=self.started.emit,
                file_started=self.file_started.emit,
                file_completed=self.file_completed.emit,
                progress=self.progress.emit,
                file_error=self.error.emit,
            )
        except Exception as exc:  # pragma: no cover - surfaced to GUI
            self.failed.emit(str(exc))
        else:
            if summary.cancelled:
                self.cancelled.emit(summary)
            else:
                self.completed.emit(summary)
        finally:
            self.finished.emit()
