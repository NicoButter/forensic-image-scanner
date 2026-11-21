"""Evaluate profiles using the production detectors and triage policy."""

from collections.abc import Iterable
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory

from forensic_image_scanner.analysis import inspect_image_file
from forensic_image_scanner.calibration.controls import generate_negative_controls
from forensic_image_scanner.calibration.dataset import ClassLabel, discover_corpus
from forensic_image_scanner.calibration.metrics import (
    PREDICTION_THRESHOLD,
    measure_threshold,
    sweep_thresholds,
)
from forensic_image_scanner.calibration.report import CalibrationReport, CalibrationResult
from forensic_image_scanner.detectors.exceptions import DetectorError
from forensic_image_scanner.detectors.falconsai import FalconsaiDetector
from forensic_image_scanner.detectors.nudenet import DEFAULT_VARIANT, NudeNetClient
from forensic_image_scanner.models.references import load_reference_manifest
from forensic_image_scanner.models.registry import ModelRegistry
from forensic_image_scanner.results import Classification
from forensic_image_scanner.scoring.ensemble import DEFAULT_ENSEMBLE_POLICY, AnalysisProfile


def calibrate_corpus(
    root: Path,
    model_root: Path,
    model_id: str,
    *,
    profile: AnalysisProfile = AnalysisProfile.FALCONSAI,
    variant: str = DEFAULT_VARIANT,
) -> CalibrationReport:
    """Score a pre-labelled local corpus with the selected profile."""
    return _run(
        root, discover_corpus(root), model_root, model_id, "Calibration corpus", profile, variant
    )


def calibrate_controls(
    model_root: Path,
    model_id: str,
    *,
    profile: AnalysisProfile = AnalysisProfile.FALCONSAI,
    variant: str = DEFAULT_VARIANT,
) -> CalibrationReport:
    """Run reproducible negative controls without keeping generated images."""
    with TemporaryDirectory(prefix="fis-negative-controls-") as directory:
        root = Path(directory)
        files = [(path, "normal") for path in generate_negative_controls(root)]
        return _run(
            root, files, model_root, model_id, "Synthetic negative controls", profile, variant
        )


def _run(
    root: Path,
    files: Iterable[tuple[Path, ClassLabel]],
    model_root: Path,
    model_id: str,
    mode: str,
    profile: AnalysisProfile,
    variant: str,
) -> CalibrationReport:
    with ExitStack() as stack:
        backend = None
        detector = None
        if profile is not AnalysisProfile.FALCONSAI:
            backend = stack.enter_context(NudeNetClient.from_registry(model_root, variant, root))
        if profile is AnalysisProfile.NUDENET:
            manifest = load_reference_manifest(f"nudenet-{variant}")
        else:
            model = ModelRegistry(model_root).load(model_id)
            manifest = model.manifest
            detector = FalconsaiDetector(model)
            detector.prepare()
        results = [
            _score(path, path.relative_to(root), label, detector, backend, profile)
            for path, label in files
        ]

    scores: dict[ClassLabel, list[float]] = {"normal": [], "nsfw": []}
    decisions: dict[ClassLabel, list[float]] = {"normal": [], "nsfw": []}
    for row in results:
        if row.error is None:
            decisions[row.expected_class].append(float(row.triage in {"HIGH", "REVIEW"}))
            score = row.nsfw_score if profile is AnalysisProfile.FALCONSAI else row.anatomical_score
            if score is not None:
                scores[row.expected_class].append(score)
    return CalibrationReport(
        mode,
        manifest.model_id,
        manifest.model_version,
        manifest.sha256,
        results,
        sweep_thresholds(scores["normal"], scores["nsfw"])
        if profile is not AnalysisProfile.COMBINED
        else [],
        profile=profile.value,
        nudenet_variant=variant if backend is not None else None,
        policy_metrics=measure_threshold(decisions["normal"], decisions["nsfw"], 1.0),
        nudenet_sha256=backend.digest if backend is not None else None,
    )


def _score(path, relative, expected, detector, backend, profile) -> CalibrationResult:
    try:
        _, _, image = inspect_image_file(path)
        output = detector.analyze(image.image) if detector is not None else None
    except (DetectorError, OSError) as exc:
        return CalibrationResult(
            path.name, relative.as_posix(), expected, error=f"{type(exc).__name__}: {exc}"
        )
    nude = backend.analyze(path) if backend is not None else None
    policy = DEFAULT_ENSEMBLE_POLICY
    nsfw = output.scores["nsfw"] if output is not None else None
    anatomy = policy.anatomical_score(nude) if nude is not None and nude.status == "OK" else None
    error = nude.error if nude is not None else None
    priority, reasons = policy.classify(nsfw, nude)
    predicted = None
    if error is None:
        if profile is AnalysisProfile.COMBINED:
            positive = priority in {Classification.HIGH, Classification.REVIEW}
        else:
            score = nsfw if nsfw is not None else anatomy
            assert score is not None
            positive = score >= PREDICTION_THRESHOLD
        predicted = "nsfw" if positive else "normal"
    return CalibrationResult(
        path.name,
        relative.as_posix(),
        expected,
        output.scores["normal"] if output is not None else None,
        nsfw,
        predicted,
        error=f"BackendError: {error}" if error else None,
        triage=priority.value if priority is not None else None,
        triage_reasons=reasons,
        nudenet=nude,
        anatomical_score=anatomy,
    )
