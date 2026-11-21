"""Thresholds apply to raw NSFW scores independently of detector labels."""

import pytest

from forensic_image_scanner.results import Classification
from forensic_image_scanner.scoring import DEFAULT_TRIAGE_POLICY, TriagePolicy, classify_nsfw_score


def test_default_policy_thresholds() -> None:
    assert DEFAULT_TRIAGE_POLICY.review_threshold == 0.60
    assert DEFAULT_TRIAGE_POLICY.high_threshold == 0.85


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Classification.LOW),
        (0.59, Classification.LOW),
        (0.60, Classification.REVIEW),
        (0.8499, Classification.REVIEW),
        (0.85, Classification.HIGH),
        (1.0, Classification.HIGH),
    ],
)
def test_triage_thresholds(score, expected) -> None:
    assert DEFAULT_TRIAGE_POLICY.classify(score) is expected
    assert classify_nsfw_score(score) is expected


@pytest.mark.parametrize(
    ("review", "high"),
    [(-0.1, 0.85), (0.60, 1.1), (0.9, 0.85), (float("nan"), 0.85), (0.60, float("inf"))],
)
def test_invalid_policy_is_rejected(review, high) -> None:
    with pytest.raises(ValueError, match="thresholds"):
        TriagePolicy(review, high)


@pytest.mark.parametrize("score", [-0.1, 1.1, float("nan"), float("inf")])
def test_invalid_score_is_rejected(score) -> None:
    with pytest.raises(ValueError, match="score"):
        DEFAULT_TRIAGE_POLICY.classify(score)


def test_prior_policy_can_be_applied_to_a_stored_score() -> None:
    assert TriagePolicy(0.30, 0.70).classify(0.59) is Classification.REVIEW
