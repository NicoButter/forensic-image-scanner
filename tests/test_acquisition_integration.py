"""CLI and capability integration without physical devices."""

import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_image_scanner.acquisition import (
    AcquisitionMethod,
    AcquisitionRequest,
    SafetyResult,
)
from forensic_image_scanner.cli import main
from forensic_image_scanner.workflow import (
    OperationMode,
    SourceDescriptor,
    SourceKind,
    TargetDescriptor,
    capability_for,
)


@pytest.mark.parametrize(
    ("operation", "extras"),
    [
        (OperationMode.RECOVER, {}),
        (OperationMode.RECOVER_ANALYZE, {"analysis_available": True}),
    ],
)
def test_physical_capability_and_safety_gate(operation, extras):
    options = dict(tsk_available=True, acquisition_available=True, **extras)
    assert capability_for(
        SourceKind.PHYSICAL_DEVICE,
        operation,
        acquisition_safe=True,
        **options,
    ).supported
    assert not capability_for(
        SourceKind.PHYSICAL_DEVICE,
        operation,
        acquisition_safe=False,
        **options,
    ).supported


@pytest.mark.parametrize(("fmt", "resume"), [("e01", False), ("raw", False), ("raw", True)])
def test_cli_acquire(fmt, resume, monkeypatch, tmp_path):
    import forensic_image_scanner.cli as cli

    requests = []
    source = tmp_path / "device"
    source.touch()

    class Service:
        def acquire(self, request):
            requests.append(request)
            return SimpleNamespace(
                output="case/image",
                verification=SimpleNamespace(value="ok"),
                completed=True,
                cancelled=False,
            )

    monkeypatch.setattr(cli, "AcquisitionService", Service)
    argv = ["acquire", str(source), "--target", str(tmp_path / "case"), "--format", fmt]
    if resume:
        argv.append("--resume")
    assert main(argv) == 0 and requests[0].resume is resume


@pytest.mark.parametrize(
    ("then", "operation"),
    [
        ("recover", OperationMode.RECOVER),
        ("recover-analyze", OperationMode.RECOVER_ANALYZE),
    ],
)
def test_cli_acquire_then_hands_off_to_physical_workflow(
    then, operation, monkeypatch, tmp_path
):
    import forensic_image_scanner.cli as cli

    calls = []

    class Workflow:
        def run(self, request, mode, **kwargs):
            calls.append((request, mode, kwargs))
            acquired = SimpleNamespace(output="case/source.E01", completed=True)
            return SimpleNamespace(acquisition=acquired, downstream=SimpleNamespace(summary={}))

    monkeypatch.setattr(cli, "PhysicalAcquisitionWorkflow", Workflow)
    monkeypatch.setattr(
        cli,
        "probe_tsk",
        lambda: SimpleNamespace(available=True),
    )
    monkeypatch.setattr(
        cli,
        "probe_photorec",
        lambda: SimpleNamespace(available=False),
    )
    source = tmp_path / "device"
    source.touch()

    assert main(
        [
            "acquire",
            str(source),
            "--target",
            str(tmp_path / "case"),
            "--format",
            "e01",
            "--then",
            then,
        ]
    ) == 0
    request, actual_operation, kwargs = calls[0]
    assert request.method is AcquisitionMethod.E01
    assert actual_operation is operation
    assert kwargs["filesystem"] is True
    if operation is OperationMode.RECOVER_ANALYZE:
        assert kwargs["pipeline"].source == source


def test_acquisition_safety_rejection_prevents_execution(monkeypatch, tmp_path):
    import forensic_image_scanner.acquisition.service as service

    source = tmp_path / "device"
    source.touch()
    request = AcquisitionRequest(source, tmp_path / "case", AcquisitionMethod.E01)
    executed = []
    monkeypatch.setattr(
        service,
        "check_acquisition_safety",
        lambda *_args: SafetyResult(False, errors=("SOURCE_TARGET_COLLISION",)),
    )
    monkeypatch.setattr(service, "acquire_ewf", lambda *_args: executed.append("acquire"))

    with pytest.raises(ValueError, match="SOURCE_TARGET_COLLISION"):
        service.AcquisitionService().acquire(request)
    assert executed == []
    assert not request.target.exists()


def test_ewf_verifying_progress_begins_when_verifier_process_starts(monkeypatch, tmp_path):
    import forensic_image_scanner.acquisition.ewf as ewf

    phases = []
    commands = []
    monkeypatch.setattr(ewf, "tool_help", lambda _binary: "-u unattended\n-t target\n")

    def run_owned(arguments, _log_path, _cancel, *, on_started=None):
        commands.append(arguments[0])
        if arguments[0] == "/mock/ewfacquire":
            (tmp_path / "source.E01").write_bytes(b"mock evidence")
        elif on_started is not None:
            on_started()
        return 0

    monkeypatch.setattr(ewf, "run_owned", run_owned)
    outcome = ewf.acquire_ewf(
        tmp_path / "device",
        tmp_path,
        Path("/mock/ewfacquire"),
        Path("/mock/ewfverify"),
        threading.Event(),
        progress=lambda phase, *_args: phases.append(phase),
    )

    assert commands == ["/mock/ewfacquire", "/mock/ewfverify"]
    assert phases == ["VERIFYING"]
    assert outcome.verification_succeeded


def test_safety_result_default_blocks():
    assert not SafetyResult(False).allowed


def _gui_page(monkeypatch, tmp_path, *, safe=True):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtWidgets import QApplication

    import forensic_image_scanner.gui.pages.analyze_page as analyze_page

    app = QApplication.instance() or QApplication([])
    source = tmp_path / "device"
    source.touch()
    target = tmp_path / "case"
    safety = SafetyResult(
        safe,
        errors=() if safe else ("SOURCE_TARGET_COLLISION",),
        source_identity="8:16" if safe else None,
        target_disks=("8:0",) if safe else (),
        capacity_bytes=128,
        serial="fixture-serial",
    )
    monkeypatch.setattr(analyze_page, "check_acquisition_safety", lambda *_args: safety)
    monkeypatch.setattr(
        analyze_page,
        "probe_acquisition_tools",
        lambda: SimpleNamespace(e01_available=True, raw_available=True),
    )
    monkeypatch.setattr(
        analyze_page,
        "probe_tsk",
        lambda: SimpleNamespace(available=True, version="mock TSK"),
    )
    monkeypatch.setattr(
        analyze_page,
        "probe_photorec",
        lambda: SimpleNamespace(available=False, version="unavailable"),
    )
    from forensic_image_scanner.gui.pages.analyze_page import AnalyzePage
    from forensic_image_scanner.gui.state.application_state import ApplicationState

    state = ApplicationState()
    page = AnalyzePage(state)
    state.source_descriptor = SourceDescriptor(
        SourceKind.PHYSICAL_DEVICE, str(source), "Mock device", True, True
    )
    state.target_descriptor = TargetDescriptor(target)
    state.operation_mode = OperationMode.RECOVER
    page._update_start_state()
    return app, page, source, target, safety


def _mock_acquisition(monkeypatch, *, method, verified=True):
    import forensic_image_scanner.acquisition.service as service

    safety = SafetyResult(
        True,
        source_identity="8:16",
        target_disks=("8:0",),
        capacity_bytes=128,
        serial="fixture-serial",
    )
    monkeypatch.setattr(service, "check_acquisition_safety", lambda *_args: safety)
    monkeypatch.setattr(
        service,
        "probe_acquisition_tools",
        lambda: SimpleNamespace(
            e01_available=True,
            ewfacquire=Path("/mock/ewfacquire"),
            ewfverify=Path("/mock/ewfverify"),
            raw_available=True,
            ddrescue=Path("/mock/ddrescue"),
        ),
    )
    monkeypatch.setattr(service, "tool_version", lambda _binary: "mock tool")

    if method is AcquisitionMethod.E01:

        def acquire_ewf(_source, directory, _acquire, _verify, _cancel, _metadata, progress=None):
            image = directory / "source.E01"
            image.write_bytes(b"mock evidence")
            if progress is not None:
                progress("VERIFYING", 0, 1, str(image))
            return SimpleNamespace(
                verification_succeeded=verified,
                errors=() if verified else ("EWF_VERIFICATION_FAILED",),
            )

        monkeypatch.setattr(service, "acquire_ewf", acquire_ewf)
    else:

        def acquire_raw(_source, directory, _binary, _cancel, **_kwargs):
            image, mapfile = directory / "source.raw", directory / "source.map"
            image.write_bytes(b"mock evidence")
            mapfile.write_text("mock map")
            return image, mapfile, ()

        monkeypatch.setattr(service, "acquire_raw", acquire_raw)


def _run_gui_worker(monkeypatch, page, source, target, method):
    import forensic_image_scanner.acquisition.workflow as workflow
    from forensic_image_scanner.gui.workers.recovery_worker import PhysicalWorker
    from forensic_image_scanner.pipeline import PipelineRequest

    class Pipeline:
        def run(self, request, **_kwargs):
            assert request.source == (target / "acquisition" / (
                "source.E01" if method is AcquisitionMethod.E01 else "source.raw"
            )).resolve()
            return SimpleNamespace(summary={}, analysis=None)

    monkeypatch.setattr(workflow, "RecoveryAnalysisPipeline", Pipeline)
    request = AcquisitionRequest(source, target, method)
    pipeline = PipelineRequest(source, target, target / "models")
    worker = PhysicalWorker(
        request,
        OperationMode.RECOVER_ANALYZE,
        filesystem=False,
        carving=True,
        pipeline=pipeline,
    )
    phases = []
    worker.progress.connect(lambda phase, *_args: phases.append(phase))
    worker.progress.connect(page._recovery_progress)
    worker.completed.connect(page._physical_completed)
    worker.failed.connect(page._recovery_failed)
    worker.run()
    return phases, worker


def test_gui_e01_stage_progression_and_verification_success(monkeypatch, tmp_path):
    _mock_acquisition(monkeypatch, method=AcquisitionMethod.E01)
    app, page, source, target, _safety = _gui_page(monkeypatch, tmp_path)

    phases, _worker = _run_gui_worker(monkeypatch, page, source, target, AcquisitionMethod.E01)

    assert phases == ["CHECKING SAFETY", "ACQUIRING", "VERIFYING", "ACQUISITION COMPLETE"]
    assert page.status_label.text().startswith("ACQUISITION COMPLETE")
    assert "Verification · verified" in page.preview.text()
    assert "Downstream · completed" in page.preview.text()
    assert not page.open_recovered_button.isHidden()
    assert app is not None


def test_gui_e01_verification_failure_is_explicit_and_stops_handoff(monkeypatch, tmp_path):
    _mock_acquisition(monkeypatch, method=AcquisitionMethod.E01, verified=False)
    app, page, source, target, _safety = _gui_page(monkeypatch, tmp_path)

    phases, _worker = _run_gui_worker(monkeypatch, page, source, target, AcquisitionMethod.E01)

    assert phases == ["CHECKING SAFETY", "ACQUIRING", "VERIFYING"]
    assert "ACQUISITION COMPLETED\nVERIFICATION FAILED" in page.preview.text()
    assert "VERIFICATION FAILED" in page.status_label.text()
    assert "Verification · failed" in page.preview.text()
    assert "Downstream · not run" in page.preview.text()
    assert app is not None


def test_gui_raw_never_reports_verification(monkeypatch, tmp_path):
    _mock_acquisition(monkeypatch, method=AcquisitionMethod.RAW)
    app, page, source, target, _safety = _gui_page(monkeypatch, tmp_path)

    phases, _worker = _run_gui_worker(monkeypatch, page, source, target, AcquisitionMethod.RAW)

    assert "VERIFYING" not in phases
    assert phases == ["CHECKING SAFETY", "ACQUIRING", "ACQUISITION COMPLETE"]
    assert page.status_label.text().startswith("ACQUISITION COMPLETE")
    assert app is not None


def test_gui_safety_blocked_start_is_disabled(monkeypatch, tmp_path):
    app, page, _source, _target, _safety = _gui_page(monkeypatch, tmp_path, safe=False)

    assert not page.start_button.isEnabled()
    page._handle_start()
    assert page.recovery_thread is None
    assert "SOURCE_TARGET_COLLISION" in page.acquisition_status.text()
    assert app is not None


def test_gui_resume_control_is_offered_for_valid_raw_record(monkeypatch, tmp_path):
    import forensic_image_scanner.gui.pages.analyze_page as analyze_page

    app, page, source, target, safety = _gui_page(monkeypatch, tmp_path)
    directory = target / "acquisition"
    directory.mkdir(parents=True)
    (directory / "source.raw").write_bytes(b"x" * 128)
    (directory / "source.map").write_text("mock map")
    (directory / "acquisition.json").write_text(
        json.dumps(
            {
                "method": "raw",
                "source": str(source.resolve()),
                "source_identity": safety.source_identity,
                "capacity_bytes": safety.capacity_bytes,
                "serial": safety.serial,
            }
        )
    )
    monkeypatch.setattr(analyze_page, "_map_stats", lambda *_args: (0, 0, 128))
    page.acquisition_method.setCurrentIndex(
        page.acquisition_method.findData(AcquisitionMethod.RAW)
    )

    assert not page.acquisition_resume.isHidden()
    page.acquisition_resume.setChecked(True)
    assert page.acquisition_resume.isChecked()
    assert app is not None


def test_gui_cancellation_requests_worker_cancel(monkeypatch, tmp_path):
    app, page, _source, _target, _safety = _gui_page(monkeypatch, tmp_path)
    calls = []
    page.recovery_worker = SimpleNamespace(cancel=lambda: calls.append("cancelled"))

    page._cancel_analysis()

    assert calls == ["cancelled"]
    assert page.status_label.text() == "Cancelling current operation…"
    assert app is not None
