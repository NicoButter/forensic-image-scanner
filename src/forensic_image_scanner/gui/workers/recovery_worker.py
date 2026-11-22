"""Qt worker for cancellable TSK inspection and filesystem recovery."""

import threading
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

from forensic_image_scanner.acquisition.workflow import PhysicalAcquisitionWorkflow
from forensic_image_scanner.media import MediaCatalogService
from forensic_image_scanner.pipeline import RecoveryAnalysisPipeline
from forensic_image_scanner.recovery import FilesystemRecoveryService, RecoveryRequest
from forensic_image_scanner.recovery.carving import CarvingRequest, PhotoRecCarvingService


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


class RecoveryExecutionWorker(QObject):
    progress = Signal(str, int, int, str)
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        filesystem_request: RecoveryRequest | None,
        carving_request: CarvingRequest | None,
        inspection: object | None,
    ) -> None:
        super().__init__()
        self.filesystem_request = filesystem_request
        self.carving_request = carving_request
        self.inspection = inspection
        self.cancel_event = threading.Event()

    @Slot()
    def run(self) -> None:
        try:
            summary = None
            if self.filesystem_request is not None:
                summary = FilesystemRecoveryService().recover(
                    self.filesystem_request,
                    inspection=self.inspection,
                    cancel=self.cancel_event,
                    progress=self._progress,
                    write_reports=self.carving_request is None,
                )
            if self.carving_request is not None:
                summary = PhotoRecCarvingService().carve(
                    self.carving_request,
                    inspection=self.inspection,
                    base_summary=summary,
                    cancel=self.cancel_event,
                    progress=self._progress,
                )
            if summary is not None and not summary.cancelled:
                MediaCatalogService().build(
                    summary, progress=self._progress, cancel=self.cancel_event
                )
            self.completed.emit(summary)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()

    def _progress(self, phase: str, current: int, total: int, name: str) -> None:
        self.progress.emit(phase, current, total, name)

    @Slot()
    def cancel(self) -> None:
        self.cancel_event.set()


class PipelineWorker(QObject):
    progress = Signal(str, int, int, str)
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, request, inspection):
        super().__init__()
        self.request = request
        self.inspection = inspection
        self.cancel_event = threading.Event()

    @Slot()
    def run(self):
        try:
            self.completed.emit(
                RecoveryAnalysisPipeline().run(
                    self.request,
                    inspection=self.inspection,
                    cancel=self.cancel_event,
                    progress=self.progress.emit,
                )
            )
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()

    @Slot()
    def cancel(self):
        self.cancel_event.set()


class PhysicalWorker(QObject):
    progress = Signal(str, int, int, str)
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, request, operation, filesystem, carving, pipeline):
        super().__init__()
        self.request, self.operation = request, operation
        self.filesystem, self.carving, self.pipeline = filesystem, carving, pipeline
        self.cancel_event = threading.Event()

    @Slot()
    def run(self):
        try:
            self.completed.emit(
                PhysicalAcquisitionWorkflow().run(
                    self.request,
                    self.operation,
                    filesystem=self.filesystem,
                    carving=self.carving,
                    pipeline=self.pipeline,
                    cancel=self.cancel_event,
                    progress=self.progress.emit,
                )
            )
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()

    @Slot()
    def cancel(self):
        self.cancel_event.set()
