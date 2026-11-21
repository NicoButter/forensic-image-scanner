"""Machine-readable records and the terminal summary for calibration runs."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from forensic_image_scanner.calibration.dataset import ClassLabel
from forensic_image_scanner.calibration.metrics import PREDICTION_THRESHOLD, ThresholdMetrics


@dataclass(frozen=True, slots=True)
class CalibrationResult:
    filename: str
    relative_path: str
    expected_class: ClassLabel
    normal_score: float | None = None
    nsfw_score: float | None = None
    predicted_class: ClassLabel | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    mode: str
    model_id: str
    model_revision: str
    model_sha256: str
    results: list[CalibrationResult]
    sweep: list[ThresholdMetrics]

    @property
    def error_count(self) -> int:
        return sum(result.error is not None for result in self.results)

    def write_json(self, destination: Path) -> None:
        """Create a report while preserving all existing files."""
        data = asdict(self)
        data["prediction_threshold"] = PREDICTION_THRESHOLD
        data["counts"] = self._counts()
        data["error_count"] = self.error_count
        for row, metrics in zip(data["sweep"], self.sweep, strict=True):
            row["confusion_matrix"] = metrics.confusion_matrix
        payload = json.dumps(data, ensure_ascii=False, allow_nan=False, indent=2)
        output = destination.open("x", encoding="utf-8")
        try:
            with output:
                output.write(payload + "\n")
        except OSError:
            destination.unlink(missing_ok=True)
            raise

    def format_summary(self) -> str:
        counts = self._counts()
        lines = [self.mode, f"NORMAL {counts['normal']} · NSFW {counts['nsfw']}"]
        lines.append(f"Scored {len(self.results) - self.error_count} · Errors {self.error_count}")
        lines.append(f"Per-file NSFW prediction threshold: {PREDICTION_THRESHOLD:.2f}")
        if self.mode == "Synthetic negative controls":
            lines.extend(("", f"{'CONTROL':<22} {'NORMAL':>12} {'NSFW':>12}"))
            for result in self.results:
                if result.error is None:
                    lines.append(
                        f"{Path(result.filename).stem:<22} "
                        f"{result.normal_score:>12.8f} {result.nsfw_score:>12.8f}"
                    )

        lines.extend(
            (
                "",
                "Confusion matrix per threshold (rows = predicted, columns = expected)",
                "                    EXPECTED",
                "                 NORMAL     NSFW",
                "PRED NORMAL          TN       FN",
                "PRED NSFW            FP       TP",
                "",
                "Threshold     TN     FN     FP     TP   Precision  Recall  Specificity"
                "     FPR     FNR      F1  Accuracy",
            )
        )
        for row in self.sweep:
            lines.append(
                f"{row.threshold:>9.2f} {row.tn:>6} {row.fn:>6} {row.fp:>6} {row.tp:>6} "
                f"{_format_ratio(row.precision):>11} {_format_ratio(row.recall):>7} "
                f"{_format_ratio(row.specificity):>12} {_format_ratio(row.false_positive_rate):>7} "
                f"{_format_ratio(row.false_negative_rate):>7} {_format_ratio(row.f1):>7} "
                f"{_format_ratio(row.accuracy):>9}"
            )
        for result in self.results:
            if result.error is not None:
                lines.append(f"Error for {result.relative_path!r}: {result.error!r}")
        return "\n".join(lines)

    def _counts(self) -> dict[str, int]:
        return {
            "normal": sum(result.expected_class == "normal" for result in self.results),
            "nsfw": sum(result.expected_class == "nsfw" for result in self.results),
        }


def _format_ratio(value: float | None) -> str:
    return "—" if value is None else f"{value:.3f}"
