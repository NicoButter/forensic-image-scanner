"""Stable, serializable result types shared across the pipeline."""

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class Classification(StrEnum):
    """Human-review priority produced by the scoring layer."""

    LOW = "LOW"
    REVIEW = "REVIEW"
    HIGH = "HIGH"


class SourceMode(StrEnum):
    """Authority assigned to the selected source for post-analysis actions."""

    EVIDENCE = "EVIDENCE"
    WORKING_COPY = "WORKING_COPY"


class ExportStatus(StrEnum):
    """State of the non-destructive export transaction."""

    NOT_EXPORTED = "NOT_EXPORTED"
    EXPORTING = "EXPORTING"
    EXPORTED = "EXPORTED"
    EXPORT_FAILED = "EXPORT_FAILED"


class MoveStatus(StrEnum):
    """State of the explicit working-copy removal transaction."""

    MOVING = "MOVING"
    MOVED = "MOVED"
    MOVE_PARTIAL = "MOVE_PARTIAL"
    MOVE_FAILED = "MOVE_FAILED"


@dataclass(frozen=True, slots=True)
class Detection:
    """A detector-specific observation, not a legal conclusion."""

    label: str
    confidence: float
    bounding_box: tuple[int, int, int, int] | None = None


@dataclass(slots=True)
class AnalysisResult:
    """Auditable result for one original evidence file."""

    file: Path
    sha256: str
    mime_type: str | None
    size_bytes: int
    detector_name: str
    detector_version: str
    model_name: str
    model_version: str
    model_sha256: str
    detections: list[Detection] = field(default_factory=list)
    confidence: float | None = None
    classification: Classification = Classification.LOW
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        data = asdict(self)
        data["file"] = str(self.file)
        data["analyzed_at"] = self.analyzed_at.isoformat()
        data["classification"] = self.classification.value
        return data


@dataclass(frozen=True, slots=True)
class ImageAnalysisResult:
    """Complete per-file record produced by sequential directory analysis."""

    path: Path
    relative_path: str
    filename: str
    size_bytes: int
    mime_type: str | None
    sha256: str
    model_id: str
    model_revision: str
    model_sha256: str
    provenance_status: str
    normal_score: float | None
    nsfw_score: float | None
    top_label: str | None
    confidence: float | None
    triage: Classification | None
    device: str
    analysis_timestamp: datetime
    status: str
    error_type: str | None = None
    error_message: str | None = None
    export_status: ExportStatus = ExportStatus.NOT_EXPORTED
    exported_path: Path | None = None
    export_timestamp: datetime | None = None
    exported_sha256: str | None = None
    source_verified_before_export: bool = False
    move_status: MoveStatus | None = None
    source_removed: bool | None = None

    @property
    def error(self) -> str:
        return self.error_message or ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        data["original_path"] = str(self.path)
        data["analysis_timestamp"] = self.analysis_timestamp.isoformat()
        data["exported_path"] = (
            str(self.exported_path) if self.exported_path is not None else None
        )
        data["export_timestamp"] = (
            self.export_timestamp.isoformat() if self.export_timestamp is not None else None
        )
        data["triage"] = self.triage.value if self.triage is not None else None
        data["export_status"] = self.export_status.value
        data["move_status"] = self.move_status.value if self.move_status is not None else None
        data["error"] = self.error
        # The flat fields above retain report compatibility.  The structured
        # sections make source and transfer provenance unambiguous to consumers.
        data["source"] = {
            "path": str(self.path),
            "relative_path": self.relative_path,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "mime_type": self.mime_type,
            "sha256": self.sha256,
        }
        data["analysis"] = {
            "status": self.status,
            "triage": data["triage"],
            "normal_score": self.normal_score,
            "nsfw_score": self.nsfw_score,
            "top_label": self.top_label,
            "confidence": self.confidence,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "model_sha256": self.model_sha256,
            "provenance_status": self.provenance_status,
            "device": self.device,
            "timestamp": data["analysis_timestamp"],
            "error_type": self.error_type,
            "error": self.error,
        }
        data["export"] = {
            "status": data["export_status"],
            "destination": data["exported_path"],
            "sha256": self.exported_sha256,
            "timestamp": data["export_timestamp"],
            "source_verified_before_export": self.source_verified_before_export,
            "move_status": data["move_status"],
            "source_removed": self.source_removed,
        }
        return data


@dataclass(frozen=True, slots=True)
class AnalysisSummary:
    """Final state and counters for one directory analysis session."""

    source: Path
    output: Path
    model_id: str
    discovered: int
    processed: int
    low: int
    review: int
    high: int
    errors: int
    elapsed_seconds: float
    cancelled: bool
    results: tuple[ImageAnalysisResult, ...]
    json_path: Path
    csv_path: Path

    @property
    def images_per_second(self) -> float:
        return self.processed / self.elapsed_seconds if self.elapsed_seconds else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "output": str(self.output),
            "model_id": self.model_id,
            "discovered": self.discovered,
            "processed": self.processed,
            "low": self.low,
            "review": self.review,
            "high": self.high,
            "errors": self.errors,
            "elapsed_seconds": self.elapsed_seconds,
            "images_per_second": self.images_per_second,
            "cancelled": self.cancelled,
            "json_path": str(self.json_path),
            "csv_path": str(self.csv_path),
        }
