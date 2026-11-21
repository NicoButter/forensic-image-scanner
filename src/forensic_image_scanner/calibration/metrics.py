"""Binary classification metrics for an explicit NSFW threshold sweep."""

from collections.abc import Sequence
from dataclasses import dataclass

THRESHOLDS = (0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95)
PREDICTION_THRESHOLD = THRESHOLDS[0]


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


@dataclass(frozen=True, slots=True)
class ThresholdMetrics:
    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None
    recall: float | None
    specificity: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    f1: float | None
    accuracy: float | None

    @property
    def confusion_matrix(self) -> dict[str, dict[str, int]]:
        """Rows represent predictions and columns represent expected labels."""
        return {
            "normal": {"normal": self.tn, "nsfw": self.fn},
            "nsfw": {"normal": self.fp, "nsfw": self.tp},
        }


def sweep_thresholds(
    normal_scores: Sequence[float], nsfw_scores: Sequence[float]
) -> list[ThresholdMetrics]:
    """Use score >= threshold for NSFW and leave undefined ratios unset."""
    sweep = []
    for threshold in THRESHOLDS:
        fp = sum(score >= threshold for score in normal_scores)
        tp = sum(score >= threshold for score in nsfw_scores)
        tn = len(normal_scores) - fp
        fn = len(nsfw_scores) - tp
        sweep.append(
            ThresholdMetrics(
                threshold=threshold,
                tp=tp,
                fp=fp,
                tn=tn,
                fn=fn,
                precision=_ratio(tp, tp + fp),
                recall=_ratio(tp, tp + fn),
                specificity=_ratio(tn, tn + fp),
                false_positive_rate=_ratio(fp, fp + tn),
                false_negative_rate=_ratio(fn, fn + tp),
                f1=_ratio(2 * tp, 2 * tp + fp + fn),
                accuracy=_ratio(tp + tn, tp + fp + tn + fn),
            )
        )
    return sweep
