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

    @property
    def error(self) -> str:
        return self.error_message or ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        data["analysis_timestamp"] = self.analysis_timestamp.isoformat()
        data["triage"] = self.triage.value if self.triage is not None else None
        data["error"] = self.error
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
