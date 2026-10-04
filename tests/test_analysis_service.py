"""Sequential analysis service tests using a tiny deterministic detector."""

from __future__ import annotations

import csv
import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from PIL import Image

from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService
from forensic_image_scanner.detectors.base import DetectorOutput
from forensic_image_scanner.gui.models.result_list_model import ResultListModel
from forensic_image_scanner.gui.workers.analysis_worker import AnalysisWorker
from forensic_image_scanner.models.importer import import_model
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.results import (
    AnalysisSummary,
    Classification,
    Detection,
    ImageAnalysisResult,
)
from forensic_image_scanner.scoring.engine import classify_nsfw_score


class FakeDetector:
    def __init__(self, _model) -> None:
        pass

    def analyze(self, image: Image.Image) -> DetectorOutput:
        nsfw = image.getpixel((0, 0))[0] / 255
        normal = 1.0 - nsfw
        scores = {"normal": normal, "nsfw": nsfw}
        top = max(scores, key=scores.__getitem__)
        return DetectorOutput(
            detector_name="fake-falconsai",
            detector_version="test",
            model_name="dummy-model",
            model_version="1",
            model_sha256="0" * 64,
            detections=[Detection(top, scores[top])],
            scores=scores,
            top_label=top,
            confidence=scores[top],
            provenance_status="partial",
            runtime={"device": "cpu", "offline": True},
        )


def install_dummy_model(root: Path) -> None:
    model = b"model"
    config = b"config"
    manifest = ModelManifest.from_dict(
        {
            "schema_version": 1,
            "model_id": "dummy-model",
            "model_version": "1",
            "filename": "model.safetensors",
            "sha256": hashlib.sha256(model).hexdigest(),
            "source": "https://example.invalid/dummy/1",
            "source_revision": "1",
            "code_license": "Apache-2.0",
            "weights_license": "Apache-2.0",
            "framework": "test",
            "input_size": [2, 2],
            "labels": ["normal", "nsfw"],
            "provenance_status": "partial",
            "size_bytes": len(model),
            "artifacts": [
                {
                    "filename": "config.json",
                    "sha256": hashlib.sha256(config).hexdigest(),
                    "size_bytes": len(config),
                }
            ],
        }
    )
    source = root.parent / "model-source"
    source.mkdir()
    model_path = source / "model.safetensors"
    config_path = source / "config.json"
    model_path.write_bytes(model)
    config_path.write_bytes(config)
    import_model(manifest, model_path, {"config.json": config_path}, root)


def make_service(tmp_path: Path) -> AnalysisService:
    model_root = tmp_path / "models"
    install_dummy_model(model_root)
    return AnalysisService(model_root, detector_factory=FakeDetector)


def make_request(tmp_path: Path, source: Path) -> AnalysisRequest:
    return AnalysisRequest(source, tmp_path / "output", "dummy-model")


def test_analysis_request_validation(tmp_path) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    assert make_request(tmp_path, source).validate().source == source.resolve()
    with pytest.raises(ValueError, match="inside"):
        AnalysisRequest(source, source / "reports", "dummy-model").validate()
    with pytest.raises(ValueError, match="SHA-256"):
        AnalysisRequest(source, tmp_path / "out", "dummy-model", sha256=False).validate()


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Classification.LOW),
        (0.2999, Classification.LOW),
        (0.30, Classification.REVIEW),
        (0.6999, Classification.REVIEW),
        (0.70, Classification.HIGH),
        (1.0, Classification.HIGH),
    ],
)
def test_triage_thresholds(score, expected) -> None:
    assert classify_nsfw_score(score) is expected


def test_sequential_progress_exports_and_evidence_unchanged(tmp_path) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    for name, value in (("low.png", 20), ("review.png", 128), ("high.png", 240)):
        Image.new("RGB", (4, 4), (value, value, value)).save(source / name)
    before = {path: (path.stat().st_size, path.stat().st_mtime_ns) for path in source.iterdir()}
    service = make_service(tmp_path)
    progress: list[tuple[int, int]] = []
    completed: list[str] = []

    summary = service.run(
        make_request(tmp_path, source),
        progress=lambda current, total: progress.append((current, total)),
        file_completed=lambda result: completed.append(result.filename),
    )

    assert summary.processed == 3
    assert (summary.low, summary.review, summary.high, summary.errors) == (1, 1, 1, 0)
    assert progress == [(1, 3), (2, 3), (3, 3)]
    assert len(completed) == 3
    assert json.loads(summary.json_path.read_text(encoding="utf-8"))[0]["status"] == "completed"
    with summary.csv_path.open(encoding="utf-8", newline="") as report:
        assert len(list(csv.DictReader(report))) == 3
    after = {path: (path.stat().st_size, path.stat().st_mtime_ns) for path in source.iterdir()}
    assert after == before


def test_single_file_error_does_not_abort(tmp_path) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "broken.png").write_bytes(b"not an image")
    Image.new("RGB", (2, 2), (0, 0, 0)).save(source / "valid.png")

    summary = make_service(tmp_path).run(make_request(tmp_path, source))

    assert summary.processed == 2
    assert summary.errors == 1
    broken = next(result for result in summary.results if result.filename == "broken.png")
    assert broken.status == "error"
    assert broken.sha256 == hashlib.sha256(b"not an image").hexdigest()
    valid = next(result for result in summary.results if result.filename == "valid.png")
    assert valid.status == "completed"


def test_cooperative_cancel_keeps_completed_results(tmp_path) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    for index in range(3):
        Image.new("RGB", (2, 2), (index, index, index)).save(source / f"{index}.png")
    stop = threading.Event()

    summary = make_service(tmp_path).run(
        make_request(tmp_path, source),
        cancelled=stop.is_set,
        file_completed=lambda _result: stop.set(),
    )

    assert summary.cancelled
    assert summary.processed == 1
    assert len(json.loads(summary.json_path.read_text(encoding="utf-8"))) == 1


def test_csv_injection_is_neutralized(tmp_path) -> None:
    source = tmp_path / "evidence"
    source.mkdir()
    Image.new("RGB", (2, 2)).save(source / "=formula.png")

    summary = make_service(tmp_path).run(make_request(tmp_path, source))
    with summary.csv_path.open(encoding="utf-8", newline="") as report:
        row = next(csv.DictReader(report))
    assert row["filename"] == "'=formula.png"


def make_result(name: str, score: float | None, status: str = "completed") -> ImageAnalysisResult:
    triage = classify_nsfw_score(score) if score is not None else None
    return ImageAnalysisResult(
        path=Path(name),
        relative_path=name,
        filename=name,
        size_bytes=1,
        mime_type="image/png",
        sha256="0" * 64,
        model_id="dummy-model",
        model_revision="1",
        model_sha256="1" * 64,
        provenance_status="partial",
        normal_score=None if score is None else 1 - score,
        nsfw_score=score,
        top_label=None,
        confidence=score,
        triage=triage,
        device="cpu",
        analysis_timestamp=datetime.now(UTC),
        status=status,
    )


def test_result_list_orders_by_nsfw_descending_and_filters() -> None:
    model = ResultListModel(
        [
            make_result("low.png", 0.1),
            make_result("high.png", 0.9),
            make_result("bad.png", None, "error"),
        ]
    )
    assert model.result_at(0).filename == "high.png"
    assert model.result_at(1).filename == "low.png"
    model.set_category_enabled("HIGH", False)
    assert all(model.result_at(index).filename != "high.png" for index in range(model.rowCount()))


def test_analysis_worker_forwards_service_signals(tmp_path) -> None:
    result = make_result("one.png", 0.1)
    summary = AnalysisSummary(
        source=tmp_path,
        output=tmp_path / "out",
        model_id="dummy-model",
        discovered=1,
        processed=1,
        low=1,
        review=0,
        high=0,
        errors=0,
        elapsed_seconds=0.1,
        cancelled=False,
        results=(result,),
        json_path=tmp_path / "out" / "analysis.json",
        csv_path=tmp_path / "out" / "analysis.csv",
    )

    class FakeService:
        def run(self, _request, **callbacks):
            callbacks["started"](1)
            callbacks["file_started"](1, 1, str(result.path))
            callbacks["file_completed"](result)
            callbacks["progress"](1, 1)
            return summary

    request = AnalysisRequest(tmp_path, tmp_path.parent / "out", "dummy-model")
    worker = AnalysisWorker(FakeService(), request)
    events: list[object] = []
    worker.started.connect(lambda total: events.append(("started", total)))
    worker.file_completed.connect(lambda item: events.append(item))
    worker.completed.connect(lambda item: events.append(item))
    worker.run()
    assert events == [("started", 1), result, summary]
