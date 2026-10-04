"""Thread-safe worker skeleton using Qt signals/slots semantics."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal


class AnalysisWorker(QObject):
    """Qt worker for future long-running analysis operations."""

    progress_changed = Signal(int)
    status_changed = Signal(str)
    finished = Signal(dict)

    def __init__(self, source: str, model_id: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.source = source
        self.model_id = model_id

    def run(self) -> None:
        """Placeholder worker that respects the read-only and thread-safe design."""
        self.status_changed.emit("Discovering files")
        self.progress_changed.emit(25)
        self.status_changed.emit("Preparing model")
        self.progress_changed.emit(60)
        self.status_changed.emit("Ready for future analysis")
        self.finished.emit({"source": self.source, "model": self.model_id, "status": "pending"})
