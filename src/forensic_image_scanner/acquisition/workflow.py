"""Acquire a physical source before invoking existing image workflows."""

import threading
from dataclasses import dataclass, replace
from pathlib import Path

from forensic_image_scanner.acquisition import (
    AcquisitionMethod,
    AcquisitionRequest,
    AcquisitionResult,
    AcquisitionService,
    VerificationStatus,
)
from forensic_image_scanner.media import MediaCatalogService
from forensic_image_scanner.pipeline import PipelineRequest, RecoveryAnalysisPipeline
from forensic_image_scanner.recovery import FilesystemRecoveryService, RecoveryRequest
from forensic_image_scanner.recovery.carving import CarvingRequest, PhotoRecCarvingService
from forensic_image_scanner.recovery.reports import write_recovery_reports
from forensic_image_scanner.workflow.models import OperationMode


@dataclass(frozen=True)
class PhysicalWorkflowResult:
    acquisition: AcquisitionResult
    downstream: object | None


class PhysicalAcquisitionWorkflow:
    def run(
        self,
        acquisition: AcquisitionRequest,
        operation: OperationMode,
        *,
        filesystem: bool,
        carving: bool,
        pipeline: PipelineRequest | None = None,
        cancel: threading.Event | None = None,
        progress=None,
    ) -> PhysicalWorkflowResult:
        if operation not in {OperationMode.RECOVER, OperationMode.RECOVER_ANALYZE}:
            raise ValueError("physical workflow requires a recovery operation")
        if not filesystem and not carving:
            raise ValueError("a recovery engine is required")
        if operation is OperationMode.RECOVER_ANALYZE and pipeline is None:
            raise ValueError("analysis pipeline configuration is required")
        cancel = cancel or threading.Event()
        progress = progress or (lambda *args: None)
        acquired = AcquisitionService().acquire(acquisition, cancel=cancel, progress=progress)
        if not acquired.completed or acquired.cancelled or cancel.is_set():
            return PhysicalWorkflowResult(acquired, None)
        if (
            acquired.method is AcquisitionMethod.E01
            and acquired.verification is not VerificationStatus.VERIFIED
        ):
            return PhysicalWorkflowResult(acquired, None)
        image = Path(acquired.output).resolve()
        target = acquisition.target.resolve()
        if not image.is_relative_to(target / "acquisition") or not image.is_file():
            raise ValueError("acquired image is not a regular file in the acquisition directory")
        progress("ACQUISITION COMPLETE", 1, 1, str(image))
        if operation is OperationMode.RECOVER_ANALYZE:
            assert pipeline is not None
            result = RecoveryAnalysisPipeline().run(
                replace(
                    pipeline, source=image, target=target, filesystem=filesystem, carving=carving
                ),
                cancel=cancel,
                progress=progress,
            )
            return PhysicalWorkflowResult(acquired, result)
        fs = FilesystemRecoveryService()
        inspection = fs.inspect_source(image) if filesystem else None
        summary = None
        if filesystem and not cancel.is_set():
            summary = fs.recover(
                RecoveryRequest(image, target),
                inspection=inspection,
                cancel=cancel,
                progress=progress,
                write_reports=not carving,
            )
            if carving and cancel.is_set():
                write_recovery_reports(summary)
        if carving and not cancel.is_set():
            summary = PhotoRecCarvingService().carve(
                CarvingRequest(image, target),
                inspection=inspection,
                base_summary=summary,
                cancel=cancel,
                progress=progress,
            )
        if summary is not None and not cancel.is_set():
            MediaCatalogService().build(summary, cancel=cancel, progress=progress)
        return PhysicalWorkflowResult(acquired, summary)
