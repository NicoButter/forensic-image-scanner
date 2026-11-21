"""Pipeline ordering, provenance, aggregation, and cancellation."""

import json
import threading
from types import SimpleNamespace

from forensic_image_scanner.media import MediaIntegrity, MediaRecord
from forensic_image_scanner.pipeline import PipelineRequest, RecoveryAnalysisPipeline
from forensic_image_scanner.pipeline.service import aggregate_video
from forensic_image_scanner.results import Classification


def test_pipeline_orders_services_and_preserves_provenance(tmp_path, monkeypatch):
    import forensic_image_scanner.pipeline.service as module

    source = tmp_path / "case.dd"
    source.write_bytes(b"evidence")
    target = tmp_path / "case"
    image = target / "recovered" / "image.png"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"fixture")
    events = []
    recovery = SimpleNamespace(cancelled=False, count=lambda _: 1)
    media = MediaRecord(
        "media",
        "a" * 64,
        "recovered/image.png",
        7,
        "image",
        ".png",
        integrity=MediaIntegrity.VALID,
        recovery_ids=["tsk", "carve"],
        recovery_methods=["filesystem_metadata", "file_carving"],
        original_paths=["DCIM/a.png"],
    )

    class Filesystem:
        def recover(self, *args, **kwargs):
            events.append("recovery")
            return recovery

    class Catalog:
        def build(self, *args, **kwargs):
            events.append("catalog")
            return [media]

    class Analysis:
        def __init__(self, *args):
            pass

        def run(self, request, **kwargs):
            events.append("analysis")
            result = SimpleNamespace(
                path=image,
                triage=Classification.HIGH,
                status="completed",
                to_dict=lambda: {"triage": "HIGH"},
            )
            return SimpleNamespace(results=[result])

    monkeypatch.setattr(module, "FilesystemRecoveryService", Filesystem)
    monkeypatch.setattr(module, "MediaCatalogService", Catalog)
    monkeypatch.setattr(module, "AnalysisService", Analysis)
    monkeypatch.setattr(module, "probe_tsk", lambda: SimpleNamespace(available=False))
    result = RecoveryAnalysisPipeline().run(
        PipelineRequest(source, target, tmp_path / "models", filesystem=True, carving=False)
    )
    assert events == ["recovery", "catalog", "analysis"]
    assert result.summary["media"][0]["recovery_ids"] == ["tsk", "carve"]
    report = json.loads((target / "reports/pipeline_summary.json").read_text())
    assert report["high"] == 1 and report["analyzed_images"] == 1


def test_video_aggregation_and_cancellation(tmp_path):
    media = SimpleNamespace(media_id="video")
    results = [
        SimpleNamespace(triage=triage, status="completed", to_dict=lambda: {})
        for triage in (Classification.LOW, Classification.HIGH, Classification.REVIEW)
    ]
    video = aggregate_video(media, results, 5)
    assert video["triage"] == "HIGH" and video["highest_risk_timestamp"] == 5
    assert len(video["relevant_frames"]) == 2
    source = tmp_path / "case.dd"
    source.write_bytes(b"image")
    cancel = threading.Event()
    cancel.set()
    target = tmp_path / "case"
    result = RecoveryAnalysisPipeline().run(
        PipelineRequest(source, target, tmp_path / "models", filesystem=False, carving=False),
        cancel=cancel,
    )
    assert result.summary["cancelled"]
    assert json.loads((target / "reports/pipeline_summary.json").read_text())["cancelled"]


def test_run_cli_routes_profile_and_engines(tmp_path, monkeypatch, capsys):
    import forensic_image_scanner.cli as cli

    observed = []

    class Pipeline:
        def run(self, request, **kwargs):
            observed.append(request)
            return SimpleNamespace(summary={"errors": 0, "cancelled": False})

    monkeypatch.setattr(cli, "probe_tsk", lambda: SimpleNamespace(available=False))
    monkeypatch.setattr(cli, "probe_photorec", lambda: SimpleNamespace(available=True))
    monkeypatch.setattr(cli, "RecoveryAnalysisPipeline", Pipeline)
    assert (
        cli.main(
            [
                "run",
                str(tmp_path / "image.dd"),
                "--target",
                str(tmp_path / "case"),
                "--operation",
                "recover-analyze",
                "--profile",
                "combined",
            ]
        )
        == 0
    )
    assert observed[0].carving and not observed[0].filesystem
    assert observed[0].profile.value == "combined"
    assert '"cancelled": false' in capsys.readouterr().out


def test_unavailable_ffmpeg_and_invalid_media_are_skipped(tmp_path, monkeypatch):
    import forensic_image_scanner.pipeline.service as module

    source = tmp_path / "case.dd"
    source.write_bytes(b"image")
    target = tmp_path / "case"
    target.mkdir()
    recovery = SimpleNamespace(cancelled=False, count=lambda _: 2)
    bad = MediaRecord(
        "bad", "a" * 64, "recovered/bad.png", 1, "image", ".png", integrity=MediaIntegrity.CORRUPT
    )
    video = MediaRecord(
        "vid", "b" * 64, "recovered/vid.mp4", 1, "video", ".mp4", integrity=MediaIntegrity.VALID
    )

    class Filesystem:
        def recover(self, *args, **kwargs):
            return recovery

    class Catalog:
        def build(self, *args, **kwargs):
            return [bad, video]

    monkeypatch.setattr(module, "FilesystemRecoveryService", Filesystem)
    monkeypatch.setattr(module, "MediaCatalogService", Catalog)
    monkeypatch.setattr(module, "probe_tsk", lambda: SimpleNamespace(available=False))
    monkeypatch.setattr(
        module,
        "sample_video",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("FFMPEG_NOT_AVAILABLE")),
    )
    result = RecoveryAnalysisPipeline().run(
        PipelineRequest(source, target, tmp_path / "models", filesystem=True, carving=False)
    )
    assert result.summary["skipped"] == 2 and result.summary["low"] == 0
    assert result.summary["errors"] == 0
    assert result.summary["skips"][1]["reason"] == "FFMPEG_NOT_AVAILABLE"
