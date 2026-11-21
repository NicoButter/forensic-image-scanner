"""Explicit experimental triage rules for the three offline analysis profiles."""

from dataclasses import dataclass
from enum import StrEnum

from forensic_image_scanner.results import Classification, NudeNetResult
from forensic_image_scanner.scoring import DEFAULT_TRIAGE_POLICY, TriagePolicy

FALCONSAI_MODEL = "falconsai-nsfw-image-detection"
EXPOSED_CLASSES = frozenset(
    {
        "ANUS_EXPOSED",
        "BUTTOCKS_EXPOSED",
        "FEMALE_BREAST_EXPOSED",
        "FEMALE_GENITALIA_EXPOSED",
        "MALE_GENITALIA_EXPOSED",
    }
)


class AnalysisProfile(StrEnum):
    FALCONSAI = "falconsai"
    NUDENET = "nudenet"
    COMBINED = "combined"


@dataclass(frozen=True, slots=True)
class EnsemblePolicy:
    exposed_threshold: float = 0.60
    strong_threshold: float = 0.85

    def __post_init__(self) -> None:
        if not 0 <= self.exposed_threshold <= self.strong_threshold <= 1:
            raise ValueError("invalid anatomical thresholds")

    def anatomical_score(self, result: NudeNetResult) -> float:
        return max(
            (d.confidence for d in result.detections if d.label in EXPOSED_CLASSES),
            default=0.0,
        )

    def classify(
        self,
        nsfw: float | None,
        nude: NudeNetResult | None,
        triage: TriagePolicy = DEFAULT_TRIAGE_POLICY,
    ) -> tuple[Classification | None, tuple[str, ...]]:
        priority = triage.classify(nsfw) if nsfw is not None else None
        reasons = [f"Falconsai NSFW score {nsfw:.6g}"] if nsfw is not None else []
        if nude is None:
            return priority, tuple(reasons)
        if nude.status != "OK":
            reasons.append(f"NudeNet unavailable: {nude.error}")
            return priority, tuple(reasons)

        exposed = [
            detection
            for detection in nude.detections
            if detection.label in EXPOSED_CLASSES and detection.confidence >= self.exposed_threshold
        ]
        reasons.extend(f"NudeNet {item.label} {item.confidence:.6g}" for item in exposed)
        if not exposed:
            reasons.append("No qualifying exposed anatomy detected")
            return priority or Classification.LOW, tuple(reasons)
        if priority is Classification.HIGH or (
            priority is not Classification.LOW
            and self.anatomical_score(nude) >= self.strong_threshold
        ):
            return Classification.HIGH, tuple(reasons)
        return Classification.REVIEW, tuple(reasons)


DEFAULT_ENSEMBLE_POLICY = EnsemblePolicy()
