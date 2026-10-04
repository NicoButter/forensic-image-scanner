"""Sequential, read-only directory analysis shared by GUI and CLI."""

from __future__ import annotations

import mimetypes
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from forensic_image_scanner.analysis import analyze_image_file
from forensic_image_scanner.detectors.base import Detector
from forensic_image_scanner.detectors.falconsai import FalconsaiDetector
from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.models.registry import ModelRegistry, VerifiedModel
from forensic_image_scanner.reports.csv_report import write_csv_report
from forensic_image_scanner.reports.json_report import write_json_report
from forensic_image_scanner.results import (
    AnalysisSummary,
    Classification,
    ImageAnalysisResult,
)
from forensic_image_scanner.scoring.engine import classify_nsfw_score

SUPPORTED_EXTENSIONS = frozenset(
    {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff"}
)
DetectorFactory = Callable[[VerifiedModel], Detector]


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    source: Path
    output: Path
    model: str
    recursive: bool = True
    sha256: bool = True
    safe_review: bool = True

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
        return AnalysisRequest(
            source=source,
            output=output,
            model=self.model,
            recursive=self.recursive,
            sha256=True,
            safe_review=self.safe_review,
        )


class AnalysisService:
    """Verify one model and process supported evidence images sequentially."""

    def __init__(
        self,
        model_root: str | Path,
        *,
        detector_factory: DetectorFactory = FalconsaiDetector,
    ) -> None:
        self.model_root = Path(model_root).expanduser().resolve()
        self.detector_factory = detector_factory

    def discover_files(self, request: AnalysisRequest) -> list[Path]:
        validated = request.validate()
        iterator = (
            validated.source.rglob("*")
            if validated.recursive
            else validated.source.iterdir()
        )
        return sorted(
            candidate
            for candidate in iterator
            if candidate.is_file()
            and not candidate.is_symlink()
            and candidate.suffix.casefold() in SUPPORTED_EXTENSIONS
        )

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
    ) -> AnalysisSummary:
        validated = request.validate()
        model = ModelRegistry(self.model_root).load(validated.model)
        detector = self.detector_factory(model)
        prepare = getattr(detector, "prepare", None)
        if callable(prepare):
            prepare()
        files = self.discover_files(validated)
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
                result = self._analyze_one(validated, path, detector, model)
            except Exception as exc:
                result = self._error_result(validated, path, model, exc)
                if file_error is not None:
                    file_error(str(path), str(exc))
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
            model_id=validated.model,
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

    @staticmethod
    def _analyze_one(
        request: AnalysisRequest,
        path: Path,
        detector: Detector,
        model: VerifiedModel,
    ) -> ImageAnalysisResult:
        analyzed = analyze_image_file(path, detector)
        output = analyzed.detector
        normal_score = float(output.scores["normal"])
        nsfw_score = float(output.scores["nsfw"])
        return ImageAnalysisResult(
            path=path,
            relative_path=path.relative_to(request.source).as_posix(),
            filename=path.name,
            size_bytes=analyzed.size_bytes,
            mime_type=analyzed.mime_type,
            sha256=analyzed.sha256,
            model_id=model.manifest.model_id,
            model_revision=model.manifest.model_version,
            model_sha256=model.manifest.sha256,
            provenance_status=model.manifest.provenance_status.value,
            normal_score=normal_score,
            nsfw_score=nsfw_score,
            top_label=output.top_label,
            confidence=output.confidence,
            triage=classify_nsfw_score(nsfw_score),
            device=str(output.runtime.get("device", "cpu")),
            analysis_timestamp=datetime.now(UTC),
            status="completed",
        )

    @staticmethod
    def _error_result(
        request: AnalysisRequest,
        path: Path,
        model: VerifiedModel,
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
            model_id=model.manifest.model_id,
            model_revision=model.manifest.model_version,
            model_sha256=model.manifest.sha256,
            provenance_status=model.manifest.provenance_status.value,
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
        )
