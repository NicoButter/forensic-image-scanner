"""Simple, explicit triage scoring policy."""

from forensic_image_scanner.results import Classification


def classify_confidence(
    confidence: float, *, review_threshold: float = 0.30, high_threshold: float = 0.70
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


def classify_nsfw_score(
    nsfw_score: float, *, review_threshold: float = 0.30, high_threshold: float = 0.70
) -> Classification:
    """Apply the project's experimental triage policy to the raw NSFW score."""
    return classify_confidence(
        nsfw_score,
        review_threshold=review_threshold,
        high_threshold=high_threshold,
    )
