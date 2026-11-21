"""Sequential calibration using the same verified detector and image path as analysis."""

from collections.abc import Iterable
from pathlib import Path
from tempfile import TemporaryDirectory

from forensic_image_scanner.analysis import analyze_image_file
from forensic_image_scanner.calibration.controls import generate_negative_controls
from forensic_image_scanner.calibration.dataset import ClassLabel, discover_corpus
from forensic_image_scanner.calibration.metrics import PREDICTION_THRESHOLD, sweep_thresholds
from forensic_image_scanner.calibration.report import CalibrationReport, CalibrationResult
from forensic_image_scanner.detectors.exceptions import DetectorError
from forensic_image_scanner.detectors.falconsai import FalconsaiDetector
from forensic_image_scanner.models.registry import ModelRegistry


def calibrate_corpus(root: Path, model_root: Path, model_id: str) -> CalibrationReport:
    """Score a pre-labelled local corpus once and evaluate all thresholds."""
    return _run(root, discover_corpus(root), model_root, model_id, "Calibration corpus")


def calibrate_controls(model_root: Path, model_id: str) -> CalibrationReport:
    """Run reproducible negative controls without keeping generated images."""
    with TemporaryDirectory(prefix="fis-negative-controls-") as directory:
        root = Path(directory)
        files = [(path, "normal") for path in generate_negative_controls(root)]
        return _run(root, files, model_root, model_id, "Synthetic negative controls")


def _run(
    root: Path,
    files: Iterable[tuple[Path, ClassLabel]],
    model_root: Path,
    model_id: str,
    mode: str,
) -> CalibrationReport:
    model = ModelRegistry(model_root).load(model_id)
    detector = FalconsaiDetector(model)
    detector.prepare()

    results = []
    scores: dict[ClassLabel, list[float]] = {"normal": [], "nsfw": []}
    for path, expected in files:
        relative_path = path.relative_to(root).as_posix()
        try:
            output = analyze_image_file(path, detector).detector
        except (DetectorError, OSError) as exc:
            results.append(
                CalibrationResult(
                    path.name, relative_path, expected, error=f"{type(exc).__name__}: {exc}"
                )
            )
            continue

        nsfw = output.scores["nsfw"]
        predicted: ClassLabel = "nsfw" if nsfw >= PREDICTION_THRESHOLD else "normal"
        scores[expected].append(nsfw)
        results.append(
            CalibrationResult(
                path.name, relative_path, expected, output.scores["normal"], nsfw, predicted
            )
        )

    return CalibrationReport(
        mode,
        model.manifest.model_id,
        model.manifest.model_version,
        model.manifest.sha256,
        results,
        sweep_thresholds(scores["normal"], scores["nsfw"]),
    )
