"""Common detector contract."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from PIL import Image

from forensic_image_scanner.results import Detection


@dataclass(frozen=True, slots=True)
class DetectorOutput:
    """Normalized output returned by every detector adapter."""

    detector_name: str
    detector_version: str
    model_name: str
    model_version: str
    model_sha256: str
    detections: list[Detection] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    top_label: str | None = None
    confidence: float | None = None
    provenance_status: str | None = None
    runtime: dict[str, Any] = field(default_factory=dict)


class Detector(ABC):
    """Interface implemented by all local inference engines."""

    @abstractmethod
    def analyze(self, image: Image.Image) -> DetectorOutput:
        """Analyze an in-memory image without writing to the evidence path."""
