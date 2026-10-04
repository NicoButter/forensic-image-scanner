"""Qt worker for verified explicit export and working-copy move operations."""

from __future__ import annotations

import threading

from PySide6.QtCore import QObject, Signal

from forensic_image_scanner.export_service import ExportService
from forensic_image_scanner.results import ImageAnalysisResult, SourceMode


class ExportWorker(QObject):
    """Run one sequential batch away from the UI with file-boundary cancellation."""

    started = Signal(int)
    file_started = Signal(int, int, str)
    file_completed = Signal(object)
    progress = Signal(int, int)
    completed = Signal(object)
    cancelled = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        service: ExportService,
        results: list[ImageAnalysisResult],
        *,
        move: bool,
        source_mode: SourceMode,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.service = service
        self.results = results
        self.move = move
        self.source_mode = source_mode
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def run(self) -> None:
        self.started.emit(len(self.results))
        current = 0

        def report(index: int, total: int, result: ImageAnalysisResult) -> None:
            nonlocal current
            current = index
            self.file_completed.emit(result)
            self.progress.emit(index, total)

        def announce(index: int, total: int, result: ImageAnalysisResult) -> None:
            self.file_started.emit(index, total, result.relative_path)

        try:
            # The service does filesystem work; this QObject only relays state.
            if self.move:
                updated = self.service.move_results(
                    self.results,
                    source_mode=self.source_mode,
                    cancelled=self._cancelled.is_set,
                    file_started=announce,
                    progress=report,
                )
            else:
                updated = self.service.export_results(
                    self.results,
                    cancelled=self._cancelled.is_set,
                    file_started=announce,
                    progress=report,
                )
        except Exception as exc:  # pragma: no cover - presentation boundary
            self.failed.emit(str(exc))
        else:
            if current < len(self.results) and self._cancelled.is_set():
                self.cancelled.emit(updated)
            else:
                self.completed.emit(updated)
        finally:
            self.finished.emit()
