"""Sequential, read-only directory analysis shared by GUI and CLI."""

from __future__ import annotations

import mimetypes
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from forensic_image_scanner.analysis import inspect_image_file
from forensic_image_scanner.detectors.base import Detector
from forensic_image_scanner.detectors.falconsai import FalconsaiDetector
from forensic_image_scanner.detectors.nudenet import DEFAULT_VARIANT, BackendError, NudeNetClient
from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.models.exceptions import ModelRegistryError
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.models.references import load_reference_manifest
from forensic_image_scanner.models.registry import ModelRegistry, VerifiedModel
from forensic_image_scanner.reports.csv_report import write_csv_report
from forensic_image_scanner.reports.json_report import write_json_report
from forensic_image_scanner.results import (
    AnalysisSummary,
    Classification,
    ImageAnalysisResult,
    NudeNetResult,
)
from forensic_image_scanner.scoring import DEFAULT_TRIAGE_POLICY, TriagePolicy
from forensic_image_scanner.scoring.ensemble import (
    DEFAULT_ENSEMBLE_POLICY,
    AnalysisProfile,
    EnsemblePolicy,
)

SUPPORTED_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff"})
DetectorFactory = Callable[[VerifiedModel], Detector]


def discover_image_files(source: Path, *, recursive: bool = True) -> list[Path]:
    """Discover supported regular images without traversing directory symlinks."""
    iterator = source.rglob("*") if recursive else source.iterdir()
    return sorted(
        candidate
        for candidate in iterator
        if not candidate.is_symlink()
        and candidate.is_file()
        and candidate.suffix.casefold() in SUPPORTED_EXTENSIONS
    )


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    source: Path
    output: Path
    model: str
    recursive: bool = True
    sha256: bool = True
    safe_review: bool = True
    profile: AnalysisProfile = AnalysisProfile.FALCONSAI
    nudenet_variant: str = DEFAULT_VARIANT

    def validate(self) -> AnalysisRequest:
        source = self.source.expanduser().resolve()
        output = self.output.expanduser().resolve()
        if not source.is_dir():
            raise ValueError(f"evidence source is not a directory: {source}")
        if output == source or output.is_relative_to(source):
            raise ValueError("report output cannot be inside the evidence source")
        if not self.model or Path(self.model).name != self.model:
            raise ValueError("model must be a plain audited model ID")
        if not self.sha256:
            raise ValueError("SHA-256 is mandatory for forensic analysis")
        if output.exists() and not output.is_dir():
            raise ValueError(f"report output is not a directory: {output}")
        return replace(self, source=source, output=output, profile=AnalysisProfile(self.profile))


class AnalysisService:
    """Prepare the selected local detectors and process images sequentially."""

    def __init__(
        self,
        model_root: str | Path,
        *,
        detector_factory: DetectorFactory = FalconsaiDetector,
        triage_policy: TriagePolicy = DEFAULT_TRIAGE_POLICY,
        ensemble_policy: EnsemblePolicy = DEFAULT_ENSEMBLE_POLICY,
    ) -> None:
        self.model_root = Path(model_root).expanduser().resolve()
        self.detector_factory = detector_factory
        self.triage_policy = triage_policy
        self.ensemble_policy = ensemble_policy

    def discover_files(self, request: AnalysisRequest) -> list[Path]:
        validated = request.validate()
        return discover_image_files(validated.source, recursive=validated.recursive)

    def run(
        self,
        request: AnalysisRequest,
        *,
        cancelled: Callable[[], bool] | None = None,
        started: Callable[[int], None] | None = None,
        file_started: Callable[[int, int, str], None] | None = None,
        file_completed: Callable[[ImageAnalysisResult], None] | None = None,
        progress: Callable[[int, int], None] | None = None,
        file_error: Callable[[str, str], None] | None = None,
        files: list[Path] | None = None,
    ) -> AnalysisSummary:
        validated = request.validate()
        detector = None
        if validated.profile is AnalysisProfile.NUDENET:
            manifest = load_reference_manifest(f"nudenet-{validated.nudenet_variant}")
        else:
            model = ModelRegistry(self.model_root).load(validated.model)
            manifest = model.manifest
            if manifest.operational_status == "experimental":
                raise ValueError("use --profile nudenet and --variant for NudeNet weights")
            detector = self.detector_factory(model)
            prepare = getattr(detector, "prepare", None)
            if callable(prepare):
                prepare()

        with ExitStack() as stack:
            backend = None
            backend_failure = None
            if validated.profile is not AnalysisProfile.FALCONSAI:
                try:
                    backend = stack.enter_context(
                        NudeNetClient.from_registry(
                            self.model_root, validated.nudenet_variant, validated.source
                        )
                    )
                except (BackendError, ModelRegistryError) as exc:
                    if validated.profile is AnalysisProfile.NUDENET:
                        raise
                    reason = (
                        str(exc) if isinstance(exc, BackendError) else "NudeNet model unavailable"
                    )
                    backend_failure = NudeNetResult(
                        validated.nudenet_variant, "ERROR", error=reason
                    )

            return self._run_files(
                validated,
                manifest,
                detector,
                backend,
                backend_failure,
                cancelled,
                started,
                file_started,
                file_completed,
                progress,
                file_error,
                files,
            )

    def _run_files(
        self,
        validated,
        manifest,
        detector,
        backend,
        backend_failure,
        cancelled,
        started,
        file_started,
        file_completed,
        progress,
        file_error,
        files,
    ) -> AnalysisSummary:
        if files is None:
            files = self.discover_files(validated)
        else:
            files = [path.resolve() for path in files]
            if any(
                not path.is_relative_to(validated.source) or not path.is_file() for path in files
            ):
                raise ValueError("explicit files must be regular files inside the source")
        if started is not None:
            started(len(files))
        start_time = time.monotonic()
        results: list[ImageAnalysisResult] = []

        for index, path in enumerate(files, start=1):
            if cancelled is not None and cancelled():
                break
            if file_started is not None:
                file_started(index, len(files), str(path))
            try:
                result = self._analyze_one(
                    validated, path, detector, manifest, backend, backend_failure
                )
            except Exception as exc:
                result = self._error_result(validated, path, manifest, exc)
                if file_error is not None:
                    file_error(str(path), str(exc))
            if result.status == "error" and result.nudenet is not None and file_error is not None:
                file_error(str(path), result.error)
            results.append(result)
            if file_completed is not None:
                file_completed(result)
            if progress is not None:
                progress(len(results), len(files))

        elapsed = time.monotonic() - start_time
        validated.output.mkdir(parents=True, exist_ok=True)
        json_path = validated.output / "analysis.json"
        csv_path = validated.output / "analysis.csv"
        write_json_report(results, json_path)
        write_csv_report(results, csv_path)
        counts = {classification: 0 for classification in Classification}
        for result in results:
            if result.triage is not None:
                counts[result.triage] += 1
        return AnalysisSummary(
            source=validated.source,
            output=validated.output,
            model_id=manifest.model_id,
            discovered=len(files),
            processed=len(results),
            low=counts[Classification.LOW],
            review=counts[Classification.REVIEW],
            high=counts[Classification.HIGH],
            errors=sum(result.status == "error" for result in results),
            elapsed_seconds=elapsed,
            cancelled=len(results) < len(files),
            results=tuple(results),
            json_path=json_path,
            csv_path=csv_path,
        )

    def _analyze_one(
        self,
        request: AnalysisRequest,
        path: Path,
        detector: Detector | None,
        manifest: ModelManifest,
        backend: NudeNetClient | None,
        backend_failure: NudeNetResult | None,
    ) -> ImageAnalysisResult:
        digest, size, loaded = inspect_image_file(path)
        output = detector.analyze(loaded.image) if detector is not None else None
        normal_score = float(output.scores["normal"]) if output is not None else None
        nsfw_score = float(output.scores["nsfw"]) if output is not None else None
        nude = backend.analyze(path) if backend is not None else backend_failure
        triage, reasons = self.ensemble_policy.classify(nsfw_score, nude, self.triage_policy)
        error = nude.error if nude and triage is None else None
        return ImageAnalysisResult(
            path=path,
            relative_path=path.relative_to(request.source).as_posix(),
            filename=path.name,
            size_bytes=size,
            mime_type=loaded.mime_type,
            sha256=digest,
            model_id=manifest.model_id,
            model_revision=manifest.model_version,
            model_sha256=manifest.sha256,
            provenance_status=manifest.provenance_status.value,
            normal_score=normal_score,
            nsfw_score=nsfw_score,
            top_label=output.top_label if output else None,
            confidence=output.confidence if output else None,
            triage=triage,
            device=str(output.runtime.get("device", "cpu")) if output else "cpu",
            analysis_timestamp=datetime.now(UTC),
            status="error" if error else "completed",
            error_type="BackendError" if error else None,
            error_message=error,
            profile=request.profile.value,
            nudenet=nude,
            triage_reasons=reasons,
        )

    @staticmethod
    def _error_result(
        request: AnalysisRequest,
        path: Path,
        manifest: ModelManifest,
        error: Exception,
    ) -> ImageAnalysisResult:
        try:
            size = path.stat().st_size
            digest = sha256_file(path)
        except OSError:
            size = 0
            digest = ""
        return ImageAnalysisResult(
            path=path,
            relative_path=path.relative_to(request.source).as_posix(),
            filename=path.name,
            size_bytes=size,
            mime_type=mimetypes.guess_type(path.name)[0],
            sha256=digest,
            model_id=manifest.model_id,
            model_revision=manifest.model_version,
            model_sha256=manifest.sha256,
            provenance_status=manifest.provenance_status.value,
            normal_score=None,
            nsfw_score=None,
            top_label=None,
            confidence=None,
            triage=None,
            device="cpu",
            analysis_timestamp=datetime.now(UTC),
            status="error",
            error_type=type(error).__name__,
            error_message=str(error),
            profile=request.profile.value,
        )
