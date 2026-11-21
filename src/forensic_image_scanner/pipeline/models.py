"""Inputs and outputs for the recovery analysis pipeline."""

from dataclasses import dataclass
from pathlib import Path

from forensic_image_scanner.scoring.ensemble import AnalysisProfile


@dataclass(frozen=True)
class PipelineRequest:
    source: Path
    target: Path
    model_root: Path
    profile: AnalysisProfile = AnalysisProfile.COMBINED
    model: str = "falconsai-nsfw-image-detection"
    variant: str = "320n"
    filesystem: bool = True
    carving: bool = True
    volume_ids: tuple[str, ...] = ()
    images: bool = True
    videos: bool = True
    sample_seconds: float = 5.0
    max_frames: int = 1000


@dataclass
class PipelineResult:
    summary: dict
    analysis: object | None
