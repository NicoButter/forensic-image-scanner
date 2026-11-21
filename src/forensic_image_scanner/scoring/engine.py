"""Experimental project triage policy for raw NSFW probabilities."""

from dataclasses import dataclass

from forensic_image_scanner.results import Classification


@dataclass(frozen=True, slots=True)
class TriagePolicy:
    """Classify a raw NSFW score without modifying it."""

    review_threshold: float = 0.60
    high_threshold: float = 0.85

    def __post_init__(self) -> None:
        if not 0.0 <= self.review_threshold <= self.high_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= review <= high <= 1")

    def classify(self, nsfw_score: float) -> Classification:
        if not 0.0 <= nsfw_score <= 1.0:
            raise ValueError("score must be between 0 and 1")
        if nsfw_score >= self.high_threshold:
            return Classification.HIGH
        if nsfw_score >= self.review_threshold:
            return Classification.REVIEW
        return Classification.LOW


DEFAULT_TRIAGE_POLICY = TriagePolicy()


def classify_confidence(
    confidence: float,
    *,
    review_threshold: float = DEFAULT_TRIAGE_POLICY.review_threshold,
    high_threshold: float = DEFAULT_TRIAGE_POLICY.high_threshold,
) -> Classification:
    """Preserve the legacy scoring API for callers with explicit thresholds."""
    return classify_nsfw_score(
        confidence, review_threshold=review_threshold, high_threshold=high_threshold
    )


def classify_nsfw_score(
    nsfw_score: float,
    *,
    review_threshold: float = DEFAULT_TRIAGE_POLICY.review_threshold,
    high_threshold: float = DEFAULT_TRIAGE_POLICY.high_threshold,
) -> Classification:
    """Apply triage to a raw score, including scores from earlier reports."""
    return TriagePolicy(review_threshold, high_threshold).classify(nsfw_score)
