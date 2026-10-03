"""Simple, explicit triage scoring policy."""

from forensic_image_scanner.results import Classification


def classify_confidence(
    confidence: float, *, review_threshold: float = 0.5, high_threshold: float = 0.8
) -> Classification:
    """Map a normalized confidence to a review priority."""
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
    if not 0.0 <= review_threshold <= high_threshold <= 1.0:
        raise ValueError("thresholds must satisfy 0 <= review <= high <= 1")
    if confidence >= high_threshold:
        return Classification.HIGH
    if confidence >= review_threshold:
        return Classification.REVIEW
    return Classification.LOW
