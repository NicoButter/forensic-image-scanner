"""Focused case persistence, provenance, report, and command integration tests."""

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from forensic_image_scanner.acquisition import (
    AcquisitionMethod,
    AcquisitionResult,
    VerificationStatus,
)
from forensic_image_scanner.case import CaseService, CaseStatus
from forensic_image_scanner.case.audit import read_events
from forensic_image_scanner.cli import main


def test_case_creation_stable_identity_metadata_and_atomic_manifest(tmp_path, monkeypatch):
    import forensic_image_scanner.case.service as service_module

    case_dir = tmp_path / "case"
    case = CaseService.create(case_dir, case_number="CASE-7", examiner="Examiner")
    case_id = case.case_id
    assert re.fullmatch(r"FIS-\d{8}-[0-9A-F]{8}", case_id)
    assert case.metadata.title is None
    assert case.metadata.status is CaseStatus.OPEN
    assert (case_dir / "logs" / "audit.jsonl").is_file()
    assert CaseService.open(case_dir).case_id == case_id

    replaces = []
    real_replace = service_module.os.replace

    def replace(source, destination):
        replaces.append(Path(destination))
        real_replace(source, destination)

    monkeypatch.setattr(service_module.os, "replace", replace)
    case.update_metadata(title="Evidence review", notes="Initial notes")

    assert replaces == [case_dir / "case.json"]
    assert CaseService.open(case_dir).metadata.title == "Evidence review"
    assert not list(case_dir.glob(".case-*"))


def test_audit_is_append_only_ordered_and_validated(tmp_path):
    case = CaseService.create(tmp_path / "case")
    case.add_audit_event("source selected", "source", {"source_id": "source-1"})
    with case.operation("recovery"):
        case.add_audit_event("media validation completed", "media")

    events = read_events(case.audit_path, case.case_id)
    assert [event.event for event in events] == [
        "case created",
        "source selected",
        "recovery started",
        "media validation completed",
        "recovery completed",
    ]
    assert len((case.audit_path).read_text(encoding="utf-8").splitlines()) == len(events)

    with case.audit_path.open("a", encoding="utf-8") as audit_file:
        audit_file.write('{"case_id":"wrong"}\n')
    with pytest.raises(ValueError, match="malformed case audit record"):
        CaseService.open(case.root)


def test_source_provenance_keeps_device_and_acquired_image_distinct(tmp_path):
    case = CaseService.create(tmp_path / "case")
    device = tmp_path / "device"
    device.touch()
    source = case.record_source(
        "physical_device",
        device,
        model="Fixture disk",
        serial="SERIAL-1",
        capacity=100,
        transport="USB",
    )
    image = case.root / "acquisition" / "source.E01"
    image.write_bytes(b"fixture image")
    record_path = case.root / "acquisition" / "acquisition.json"
    record_path.write_text("{}", encoding="utf-8")
    acquisition = AcquisitionResult(
        source=str(device),
        source_identity="SERIAL-1",
        output=str(image),
        method=AcquisitionMethod.E01,
        verification=VerificationStatus.VERIFIED,
        completed=True,
        cancelled=False,
        model="Fixture disk",
        serial="SERIAL-1",
        capacity_bytes=100,
        transport="USB",
        tool="ewfacquire",
        tool_version="fixture",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        sha256="a" * 64,
        bytes_acquired=100,
        errors=(),
    )

    case.record_acquisition(acquisition, source_id=source.source_id)
    reopened = CaseService.open(case.root)
    stored_source = reopened.data["sources"][0]
    assert stored_source["source_kind"] == "physical_device"
    assert stored_source["original_location"] == str(device)
    assert stored_source["acquired_image"] == "acquisition/source.E01"
    assert reopened.data["acquisitions"][0]["image"] == "acquisition/source.E01"

    forensic_image = case.record_source("forensic_image", image)
    assert forensic_image.source_id != source.source_id
    assert len(case.data["sources"]) == 2


def test_recovery_and_pipeline_references_are_relative_and_persisted(tmp_path):
    case = CaseService.create(tmp_path / "case")
    recovery = case.root / "reports" / "recovery.json"
    pipeline = case.root / "reports" / "pipeline_summary.json"
    recovery.write_text('{"recovered":2}\n', encoding="utf-8")
    pipeline.write_text('{"analyzed_images":1}\n', encoding="utf-8")

    case.record_recovery(recovery)
    case.record_pipeline_summary(pipeline)
    reopened = CaseService.open(case.root)

    assert reopened.data["recoveries"][0]["path"] == "reports/recovery.json"
    assert reopened.data["pipeline_summary"]["path"] == "reports/pipeline_summary.json"


def test_forensic_json_and_offline_html_report(tmp_path):
    case = CaseService.create(tmp_path / "case", title="Evidence case")
    analysis = case.root / "reports" / "analysis.json"
    analysis.write_text(
        json.dumps(
            [
                {
                    "triage": "HIGH",
                    "relative_path": "high.jpg",
                    "sha256": "a" * 64,
                    "nsfw_score": 0.9,
                },
                {
                    "triage": "REVIEW",
                    "relative_path": "review.jpg",
                    "sha256": "b" * 64,
                    "nsfw_score": 0.7,
                },
                {
                    "triage": "LOW",
                    "relative_path": "low.jpg",
                    "sha256": "c" * 64,
                    "nsfw_score": 0.1,
                },
            ]
        ),
        encoding="utf-8",
    )
    catalog = case.root / "reports" / "media_catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "records": [
                    {"media_id": "a" * 64, "sha256": "a" * 64, "integrity": "valid"},
                    {"media_id": "b" * 64, "sha256": "b" * 64, "integrity": "partial"},
                ]
            }
        ),
        encoding="utf-8",
    )
    pipeline = case.root / "reports" / "pipeline_summary.json"
    pipeline.write_text(
        json.dumps(
            {
                "low": 1,
                "review": 1,
                "high": 1,
                "errors": 0,
                "analyzed_images": 3,
                "analyzed_videos": 1,
                "videos": [{"relative_path": "clip.mp4", "triage": "REVIEW", "sampled_frames": 4}],
            }
        ),
        encoding="utf-8",
    )
    case.record_analysis(analysis)
    case.record_media_catalog(catalog)
    case.record_pipeline_summary(pipeline)

    json_path, html_path = case.generate_report()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["case"]["case_id"] == case.case_id
    assert payload["findings"]["high"][0]["reference"] == "high.jpg"
    assert payload["findings"]["review"][0]["reference"] == "review.jpg"
    assert payload["media_integrity_summary"]["valid"] == 1
    assert payload["video_sampled_analysis"]["sampled_frames"] == 4
    assert "Human review required." in payload["limitations"]
    assert (
        "Triage labels are FIS prioritization labels, not legal conclusions."
        in payload["limitations"]
    )
    html_report = html_path.read_text(encoding="utf-8")
    assert "REVIEW findings" in html_report and "HIGH findings" in html_report
    assert "Video sampled analysis" in html_report
    assert "cdn" not in html_report.casefold()
    reopened = CaseService.open(case.root)
    assert {item["kind"] for item in reopened.data["reports"]} >= {
        "forensic_report_json",
        "forensic_report_html",
    }
    assert payload["analysis_summary"]["high"] == len(payload["findings"]["high"])
    assert payload["analysis_summary"]["review"] == len(payload["findings"]["review"])
    assert payload["video_sampled_analysis"]["videos_analyzed"] == 1


def test_case_report_rejects_inconsistent_video_summary_without_overwriting_report(tmp_path):
    case = CaseService.create(tmp_path / "case")
    json_report, _html_report = case.generate_report()
    previous_report = json_report.read_bytes()
    pipeline = case.root / "reports" / "pipeline_summary.json"
    pipeline.write_text(
        json.dumps(
            {
                "sampled_frames": 3,
                "analyzed_videos": 1,
                "videos": [
                    {
                        "triage": "HIGH",
                        "sampled_frames": 3,
                        "sampling_cap": 2,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    case.record_pipeline_summary(pipeline)

    with pytest.raises(ValueError, match="REPORT_INCONSISTENT: sampled-frame cap mismatch"):
        case.generate_report()

    assert json_report.read_bytes() == previous_report


@pytest.mark.parametrize("artifact_kind", ["recovery", "catalog", "pipeline", "acquisition"])
def test_case_report_rejects_malformed_operational_artifacts(
    tmp_path, artifact_kind
):
    case = CaseService.create(tmp_path / artifact_kind)
    if artifact_kind == "recovery":
        artifact = case.root / "reports" / "recovery.json"
        artifact.write_text("{", encoding="utf-8")
        case.record_recovery(artifact)
        preserved_artifact = artifact
    elif artifact_kind == "catalog":
        artifact = case.root / "reports" / "media_catalog.json"
        artifact.write_text("{", encoding="utf-8")
        case.record_media_catalog(artifact)
        preserved_artifact = artifact
    elif artifact_kind == "pipeline":
        artifact = case.root / "reports" / "pipeline_summary.json"
        artifact.write_text("{", encoding="utf-8")
        case.record_pipeline_summary(artifact)
        preserved_artifact = artifact
    else:
        source = tmp_path / "device"
        source.touch()
        image = case.root / "acquisition" / "source.raw"
        image.write_bytes(b"fixture")
        (case.root / "acquisition" / "acquisition.json").write_text(
            "{", encoding="utf-8"
        )
        now = datetime.now(UTC)
        case.record_acquisition(
            AcquisitionResult(
                source=str(source),
                source_identity="SERIAL",
                model=None,
                serial="SERIAL",
                capacity_bytes=1,
                transport=None,
                method=AcquisitionMethod.RAW,
                tool="ddrescue",
                tool_version="fixture",
                started_at=now,
                completed_at=now,
                output=str(image),
                bytes_acquired=1,
                sha256=None,
                verification=VerificationStatus.NOT_PERFORMED,
                completed=True,
                errors=(),
                cancelled=False,
            )
        )
        preserved_artifact = image

    with pytest.raises(ValueError, match="malformed"):
        case.generate_report()

    assert preserved_artifact.is_file()


def test_case_rejects_escaping_references_and_invalid_status(tmp_path):
    case = CaseService.create(tmp_path / "case")
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="escapes"):
        case.add_report_reference(outside, kind="external")

    data = json.loads((case.root / "case.json").read_text(encoding="utf-8"))
    data["reports"].append({"kind": "escape", "path": "../outside.json"})
    (case.root / "case.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="relative"):
        CaseService.open(case.root)

    data["reports"] = []
    data["status"] = "UNKNOWN"
    (case.root / "case.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid case metadata"):
        CaseService.open(case.root)


def test_case_rejects_symlinked_artifact_directories_and_recovered_escape(tmp_path):
    case = CaseService.create(tmp_path / "case")
    outside = tmp_path / "outside"
    outside.mkdir()
    artifact = outside / "recovered.jpg"
    artifact.write_bytes(b"fixture")

    try:
        (case.root / "recovered").rmdir()
        (case.root / "recovered").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    with pytest.raises(ValueError, match="recovered directory is unsafe"):
        CaseService.open(case.root)

    (case.root / "recovered").unlink()
    with pytest.raises(ValueError, match="escapes the case directory"):
        case.record_recovery(artifact)


def test_case_malformed_manifest_and_audit_fail_closed(tmp_path):
    case = CaseService.create(tmp_path / "case")
    case_file = case.root / "case.json"
    case_file.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match=re.escape("case.json is malformed")):
        CaseService.open(case.root)

    case_file.write_text(json.dumps(case.data), encoding="utf-8")
    case.audit_path.write_text("{bad json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed case audit record"):
        CaseService.open(case.root)


def test_case_detects_missing_manifest_and_case_id_mismatch(tmp_path):
    case = CaseService.create(tmp_path / "case")
    manifest = case.root / "case.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["case_id"] = "FIS-20260101-00000000"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="case_id mismatch"):
        CaseService.open(case.root)

    manifest.unlink()
    with pytest.raises(ValueError, match=re.escape("case.json is missing")):
        CaseService.open(case.root)


def test_completed_case_requires_explicit_reopen_and_no_active_operations(tmp_path):
    case = CaseService.create(tmp_path / "case")
    with case.operation("analysis"), pytest.raises(
        ValueError, match="active operations"
    ):
        case.complete()

    assert case.complete().status is CaseStatus.COMPLETED
    with pytest.raises(ValueError, match="finalized"):
        case.update_metadata(title="Late update")
    with pytest.raises(ValueError, match="finalized"):
        case.begin_operation("recovery")
    assert case.reopen().status is CaseStatus.IN_PROGRESS
    with case.operation("recovery"):
        pass


def test_case_operation_cancellation_is_audited_and_not_completed(tmp_path):
    case = CaseService.create(tmp_path / "case")
    with pytest.raises(InterruptedError), case.operation("recovery"):
        raise InterruptedError("CANCELLED")

    reopened = CaseService.open(case.root)
    assert reopened.active_operations == ()
    assert reopened.metadata.status is CaseStatus.IN_PROGRESS
    assert read_events(reopened.audit_path, reopened.case_id)[-1].event == "recovery failed"


@pytest.mark.parametrize("command", ["info", "report", "complete"])
def test_cli_case_commands(command, tmp_path, capsys):
    case_path = tmp_path / "case"
    created = CaseService.create(case_path, case_number="CASE-CLI")
    if command == "complete":
        args = ["case", "complete", str(case_path)]
    else:
        args = ["case", command, str(case_path)]

    assert main(args) == 0
    output = capsys.readouterr().out
    if command == "info":
        assert created.case_id in output
    elif command == "report":
        assert (case_path / "reports" / "forensic_report.json").is_file()
        assert (case_path / "reports" / "forensic_report.html").is_file()
    else:
        assert "COMPLETED" in output


def test_cli_case_create_options_and_case_target_acquisition(
    monkeypatch, tmp_path, capsys
):
    import forensic_image_scanner.cli as cli

    case_path = tmp_path / "case"
    assert main(
        [
            "case",
            "create",
            str(case_path),
            "--case-number",
            "CASE-CLI",
            "--title",
            "CLI case",
            "--examiner",
            "Examiner",
        ]
    ) == 0
    created_id = json.loads(capsys.readouterr().out)["case_id"]
    source = tmp_path / "device"
    source.touch()

    class Service:
        def acquire(self, request, **_kwargs):
            output = request.target / "acquisition" / "source.E01"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"evidence")
            (output.parent / "acquisition.json").write_text("{}", encoding="utf-8")
            return SimpleNamespace(
                source=str(source),
                output=str(output),
                method=AcquisitionMethod.E01,
                verification=VerificationStatus.VERIFIED,
                completed=True,
                cancelled=False,
                model=None,
                serial="SERIAL",
                capacity_bytes=7,
                transport="USB",
                sha256=None,
                bytes_acquired=7,
                errors=(),
            )

    monkeypatch.setattr(cli, "AcquisitionService", Service)
    assert main(
        [
            "acquire",
            str(source),
            "--case",
            str(case_path),
            "--format",
            "e01",
        ]
    ) == 0
    reopened = CaseService.open(case_path)
    assert reopened.case_id == created_id
    assert reopened.data["sources"][0]["source_kind"] == "physical_device"
    assert reopened.data["acquisitions"][0]["image"] == "acquisition/source.E01"


@pytest.mark.parametrize("then", ["recover", "recover-analyze"])
def test_case_physical_acquisition_hands_off_to_supported_workflow(
    monkeypatch, tmp_path, then
):
    import forensic_image_scanner.cli as cli
    from forensic_image_scanner.workflow import OperationMode

    case = CaseService.create(tmp_path / "case")
    device = tmp_path / "device"
    device.touch()
    expected_mode = (
        OperationMode.RECOVER if then == "recover" else OperationMode.RECOVER_ANALYZE
    )
    calls = []

    class PhysicalWorkflow:
        def run(self, request, operation, **_kwargs):
            calls.append((request, operation))
            output = request.target / "acquisition" / "source.E01"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"fixture image")
            reports = request.target / "reports"
            reports.mkdir(parents=True, exist_ok=True)
            (reports / "recovery.json").write_text(
                json.dumps(
                    {
                        "case_id": case.case_id,
                        "records": [],
                        "recovered": 0,
                        "source_sha256": "a" * 64,
                    }
                ),
                encoding="utf-8",
            )
            if operation is OperationMode.RECOVER_ANALYZE:
                (reports / "pipeline_summary.json").write_text(
                    json.dumps(
                        {
                            "case_id": case.case_id,
                            "errors": 0,
                            "cancelled": False,
                            "videos": [],
                            "sampled_frames": 0,
                        }
                    ),
                    encoding="utf-8",
                )
            now = datetime.now(UTC)
            acquired = AcquisitionResult(
                source=str(device),
                source_identity="SERIAL",
                model="Fixture disk",
                serial="SERIAL",
                capacity_bytes=12,
                transport="USB",
                method=AcquisitionMethod.E01,
                tool="ewfacquire",
                tool_version="fixture",
                started_at=now,
                completed_at=now,
                output=str(output),
                bytes_acquired=12,
                sha256="a" * 64,
                verification=VerificationStatus.VERIFIED,
                completed=True,
                errors=(),
                cancelled=False,
            )
            return SimpleNamespace(
                acquisition=acquired,
                downstream=SimpleNamespace(summary={"errors": 0, "cancelled": False}),
            )

    monkeypatch.setattr(cli, "PhysicalAcquisitionWorkflow", PhysicalWorkflow)
    monkeypatch.setattr(cli, "probe_tsk", lambda: SimpleNamespace(available=True))
    monkeypatch.setattr(cli, "probe_photorec", lambda: SimpleNamespace(available=False))
    assert main(
        [
            "acquire",
            str(device),
            "--case",
            str(case.root),
            "--format",
            "e01",
            "--then",
            then,
        ]
    ) == 0

    assert calls[0][1] is expected_mode
    reopened = CaseService.open(case.root)
    assert reopened.data["sources"][0]["source_kind"] == "physical_device"
    assert reopened.data["sources"][0]["acquired_image"] == "acquisition/source.E01"
    assert reopened.data["acquisitions"][0]["verification"] == "verified"
    assert reopened.data["recoveries"][0]["path"] == "reports/recovery.json"
    if then == "recover-analyze":
        assert reopened.data["pipeline_summary"]["path"] == "reports/pipeline_summary.json"


def test_cli_run_attaches_recovery_pipeline_to_case(monkeypatch, tmp_path):
    import forensic_image_scanner.cli as cli

    case = CaseService.create(tmp_path / "case")
    source = tmp_path / "disk.dd"
    source.write_bytes(b"fixture")

    class Pipeline:
        def run(self, request, **_kwargs):
            reports = request.target / "reports"
            reports.mkdir(parents=True, exist_ok=True)
            (reports / "recovery.json").write_text(
                json.dumps({"source": str(source), "source_sha256": "a" * 64}),
                encoding="utf-8",
            )
            (reports / "pipeline_summary.json").write_text(
                json.dumps({"errors": 0, "cancelled": False, "videos": []}),
                encoding="utf-8",
            )
            return SimpleNamespace(summary={"errors": 0, "cancelled": False})

    monkeypatch.setattr(cli, "RecoveryAnalysisPipeline", Pipeline)
    monkeypatch.setattr(cli, "probe_tsk", lambda: SimpleNamespace(available=True))
    monkeypatch.setattr(cli, "probe_photorec", lambda: SimpleNamespace(available=False))

    assert main(
        [
            "run",
            str(source),
            "--case",
            str(case.root),
            "--operation",
            "recover-analyze",
        ]
    ) == 0

    reopened = CaseService.open(case.root)
    assert reopened.data["sources"][0]["source_kind"] == "forensic_image"
    assert reopened.data["sources"][0]["sha256"] == "a" * 64
    assert reopened.data["pipeline_summary"]["path"] == "reports/pipeline_summary.json"
    assert reopened.data["recoveries"][0]["path"] == "reports/recovery.json"


def test_cli_recover_attaches_recovery_and_catalog_to_case(monkeypatch, tmp_path):
    import forensic_image_scanner.cli as cli

    case = CaseService.create(tmp_path / "case")
    source = tmp_path / "disk.dd"
    source.write_bytes(b"fixture")

    class Summary:
        target = case.root
        cancelled = False
        deleted_entries = 0
        media_candidates = 0
        records = ()
        json_path = case.root / "reports" / "recovery.json"
        csv_path = case.root / "reports" / "recovery.csv"

        def count(self, _status):
            return 0

    class Filesystem:
        def inspect_source(self, _source):
            return object()

        def recover(self, request, **_kwargs):
            reports = request.target / "reports"
            reports.mkdir(parents=True, exist_ok=True)
            Summary.json_path.write_text(
                json.dumps(
                    {
                        "source": str(source),
                        "source_sha256": "b" * 64,
                        "records": [],
                        "recovered": 0,
                    }
                ),
                encoding="utf-8",
            )
            Summary.csv_path.write_text("recovery_id\n", encoding="utf-8")
            return Summary()

    class Catalog:
        def build(self, _summary, **_kwargs):
            reports = case.root / "reports"
            (reports / "media_catalog.json").write_text('{"records":[]}', encoding="utf-8")
            (reports / "media_catalog.csv").write_text("media_id\n", encoding="utf-8")

    monkeypatch.setattr(cli, "probe_tsk", lambda: SimpleNamespace(available=True))
    monkeypatch.setattr(cli, "probe_photorec", lambda: SimpleNamespace(available=False))
    monkeypatch.setattr(cli, "FilesystemRecoveryService", Filesystem)
    monkeypatch.setattr(cli, "MediaCatalogService", Catalog)

    assert main(["recover", str(source), "--case", str(case.root)]) == 0

    reopened = CaseService.open(case.root)
    assert reopened.data["recoveries"][0]["path"] == "reports/recovery.json"
    assert reopened.data["media_catalog"]["path"] == "reports/media_catalog.json"
    assert reopened.data["sources"][0]["sha256"] == "b" * 64


def test_cli_scan_attaches_analysis_report_to_case(monkeypatch, tmp_path):
    import forensic_image_scanner.cli as cli

    case = CaseService.create(tmp_path / "case")
    source = tmp_path / "images"
    source.mkdir()

    class Analysis:
        def __init__(self, _model_root):
            pass

        def run(self, request, **_kwargs):
            path = request.output / "analysis.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("[]\n", encoding="utf-8")
            return SimpleNamespace(
                processed=0,
                discovered=0,
                low=0,
                review=0,
                high=0,
                errors=0,
                elapsed_seconds=0.0,
                images_per_second=0.0,
                nudenet_errors=0,
                json_path=path,
                csv_path=request.output / "analysis.csv",
            )

    monkeypatch.setattr(cli, "AnalysisService", Analysis)

    assert main(
        [
            "scan",
            str(source),
            "--case",
            str(case.root),
            "--model",
            "mock-model",
        ]
    ) == 0

    reopened = CaseService.open(case.root)
    assert reopened.data["sources"][0]["source_kind"] == "directory"
    assert any(item["kind"] == "analysis" for item in reopened.data["reports"])


def test_gui_basic_case_controls_and_header(monkeypatch, tmp_path):
    import forensic_image_scanner.gui.pages.analyze_page as analyze_page

    monkeypatch.setenv("FORENSIC_IMAGE_SCANNER_MODEL_DIR", str(tmp_path / "models"))
    monkeypatch.setattr(
        analyze_page, "probe_tsk", lambda: SimpleNamespace(available=False, version="mock")
    )
    monkeypatch.setattr(
        analyze_page, "probe_photorec", lambda: SimpleNamespace(available=False, version="mock")
    )
    monkeypatch.setattr(
        analyze_page,
        "probe_acquisition_tools",
        lambda: SimpleNamespace(e01_available=False, raw_available=False),
    )
    from PySide6.QtWidgets import QApplication

    from forensic_image_scanner.gui.pages.analyze_page import AnalyzePage
    from forensic_image_scanner.gui.state.application_state import ApplicationState

    app = QApplication.instance() or QApplication([])
    page = AnalyzePage(ApplicationState())
    case = CaseService.create(
        tmp_path / "case",
        case_number="CASE-GUI",
        title="GUI case",
        examiner="Examiner",
    )

    page._set_case(case)

    assert page.new_case_button.text() == "NEW CASE"
    assert page.open_case_button.text() == "OPEN CASE"
    assert case.case_id in page.case_header.text()
    assert "CASE-GUI" in page.case_header.text()
    assert "GUI case" in page.case_header.text()
    assert "Examiner" in page.case_header.text()
    assert "OPEN" in page.case_header.text()
    assert not page.open_case_folder_button.isHidden()
    page._complete_case()
    assert "COMPLETED" in page.case_header.text()
    assert not page.reopen_case_button.isHidden()
    page._reopen_case()
    assert "IN_PROGRESS" in page.case_header.text()
    assert app is not None
