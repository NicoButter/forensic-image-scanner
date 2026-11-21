"""Compatibility routing from the high-level workflow to existing analysis."""

from pathlib import Path

from forensic_image_scanner.analysis_service import AnalysisRequest
from forensic_image_scanner.scoring.ensemble import AnalysisProfile
from forensic_image_scanner.workflow.models import OperationMode, SourceKind, WorkflowRequest
from forensic_image_scanner.workflow.validation import validate_workflow


def analysis_request_from_workflow(
    request: WorkflowRequest,
    *,
    model: str,
    profile: AnalysisProfile,
    nudenet_variant: str,
    recursive: bool = True,
    sha256: bool = True,
    safe_review: bool = True,
) -> AnalysisRequest:
    """Route the sole executable FIS-011 combination to AnalysisRequest."""
    validation = validate_workflow(request)
    if (
        request.source.kind is not SourceKind.DIRECTORY
        or request.operation is not OperationMode.ANALYZE
        or not validation.executable
    ):
        raise ValueError("workflow is configured but cannot be executed")
    return AnalysisRequest(
        source=Path(request.source.location),
        output=request.target.path,
        model=model,
        recursive=recursive,
        sha256=sha256,
        safe_review=safe_review,
        profile=profile,
        nudenet_variant=nudenet_variant,
    )
