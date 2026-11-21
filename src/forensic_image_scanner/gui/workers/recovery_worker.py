"""Qt worker for cancellable TSK inspection and filesystem recovery."""

import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

from forensic_image_scanner.recovery import FilesystemRecoveryService, RecoveryRequest


class RecoveryWorker(QObject):
    progress = Signal(str, int, int, str)
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        service: FilesystemRecoveryService,
        source: Path,
        request: RecoveryRequest | None = None,
    ) -> None:
        super().__init__()
        self.service = service
        self.source = source
        self.request = request
        self.cancel_event = threading.Event()

    @Slot()
    def run(self) -> None:
        try:
            if self.request is None:
                result = self.service.inspect_source(self.source)
            else:
                result = self.service.recover(
                    self.request,
                    cancel=self.cancel_event,
                    progress=lambda phase, current, total, name: self.progress.emit(
                        phase, current, total, name
                    ),
                )
            self.completed.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()

    @Slot()
    def cancel(self) -> None:
        self.cancel_event.set()
