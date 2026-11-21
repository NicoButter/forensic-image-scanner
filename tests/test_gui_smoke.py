"""Smoke tests for the optional Qt desktop GUI."""

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QItemSelectionModel
from PySide6.QtWidgets import QApplication

from forensic_image_scanner.gui import create_application, main
from forensic_image_scanner.gui.main_window import MainWindow
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.models.importer import import_model
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.recovery import RecoveryVolume, SourceInspection
from forensic_image_scanner.recovery.tsk.probe import TskCapability
from forensic_image_scanner.results import (
    AnalysisSummary,
    Classification,
    ImageAnalysisResult,
    SourceMode,
)
from forensic_image_scanner.scoring.ensemble import AnalysisProfile
from forensic_image_scanner.workflow import (
    OperationMode,
    SourceDescriptor,
    SourceKind,
    TargetDescriptor,
)
from forensic_image_scanner.workflow.source_inspection import (
    inspect_directory,
    inspect_forensic_image,
)
from tests.test_analysis_service import make_result


@pytest.fixture(autouse=True)
def isolated_model_directory(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("FORENSIC_IMAGE_SCANNER_MODEL_DIR", str(tmp_path / "models"))


def test_gui_entry_points_are_importable() -> None:
    assert callable(create_application)
    assert callable(main)


def test_pipeline_completion_updates_existing_results_page(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    page = window.pages["analyze"]
    summary = SimpleNamespace(
        results=[], processed=0, high=0, review=0, low=0, errors=0, nudenet_errors=0
    )
    counts = {
        key: 0
        for key in (
            "recovered",
            "analyzed_images",
            "analyzed_videos",
            "low",
            "review",
            "high",
            "skipped",
            "errors",
        )
    }
    counts["cancelled"] = False
    page._pipeline_completed(SimpleNamespace(summary=counts, analysis=summary))
    assert "RECOVERY + ANALYSIS COMPLETE" in page.preview.text()
    assert page.state.analysis_summary is summary
    assert not page.view_pipeline_results_button.isHidden()
    page.view_pipeline_results_button.click()
    assert page.state.selected_page == "results"
    assert app is not None


def test_main_window_initializes() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert window.windowTitle() == "Forensic Image Scanner"
    assert window.state.selected_page == "home"
    assert window.stack.count() == 6
    assert window.network_badge.text() == "ANALYSIS OFFLINE"
    assert window.model_badge.text() == "NO MODEL"
    assert app is not None


def test_home_actions_use_central_navigation() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()

    window.pages["home"].action_buttons["models"].click()

    assert window.state.selected_page == "models"
    assert window.stack.currentWidget() is window.pages["models"]
    assert window.sidebar.buttons["models"].isChecked()
    assert app is not None


def test_network_badge_reflects_explicit_model_install_activity() -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)

    state.model_download_active = True
    assert window.network_badge.text() == "MODEL DOWNLOAD"
    state.model_download_active = False
    assert window.network_badge.text() == "ANALYSIS OFFLINE"
    assert app is not None


def test_open_window_updates_all_model_views_after_install(monkeypatch, tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    model = b"dummy model"
    config = b"dummy config"
    manifest = ModelManifest.from_dict(
        {
            "schema_version": 1,
            "model_id": "dummy-model",
            "model_version": "1",
            "filename": "model.safetensors",
            "sha256": hashlib.sha256(model).hexdigest(),
            "source": "https://example.invalid/model/1",
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
    monkeypatch.setenv("FORENSIC_IMAGE_SCANNER_MODEL_DIR", str(tmp_path / "models"))
    import forensic_image_scanner.gui.pages.models_page as models_page_module
    import forensic_image_scanner.gui.services.model_service as model_service_module

    monkeypatch.setattr(model_service_module, "reference_model_ids", lambda: ("dummy-model",))
    monkeypatch.setattr(model_service_module, "load_reference_manifest", lambda _model_id: manifest)
    monkeypatch.setattr(models_page_module, "load_reference_manifest", lambda _model_id: manifest)
    state = ApplicationState()
    window = MainWindow(state)
    assert window.pages["analyze"].manage_models_button.isVisibleTo(window.pages["analyze"])

    source = tmp_path / "source"
    source.mkdir()
    model_path = source / "model.safetensors"
    config_path = source / "config.json"
    model_path.write_bytes(model)
    config_path.write_bytes(config)
    import_model(manifest, model_path, {"config.json": config_path}, tmp_path / "models")
    window.pages["models"]._operation_completed("dummy-model")
    window.pages["models"].refresh()

    assert window.model_badge.text() == "MODEL VERIFIED"
    assert window.pages["home"].summary_values["Active model"].text() == "dummy-model"
    assert window.pages["analyze"].model_combo.findData("dummy-model") >= 0
    assert (
        window.pages["models"]
        .cards["dummy-model"]
        .verify_button.isVisibleTo(window.pages["models"])
    )
    assert app is not None


def test_results_page_populates_from_application_state(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    result = ImageAnalysisResult(
        path=tmp_path / "evidence" / "image.png",
        relative_path="image.png",
        filename="image.png",
        size_bytes=10,
        mime_type="image/png",
        sha256="0" * 64,
        model_id="dummy-model",
        model_revision="1",
        model_sha256="1" * 64,
        provenance_status="partial",
        normal_score=0.1,
        nsfw_score=0.9,
        top_label="nsfw",
        confidence=0.9,
        triage=Classification.HIGH,
        device="cpu",
        analysis_timestamp=datetime.now(UTC),
        status="completed",
    )
    summary = AnalysisSummary(
        source=tmp_path / "evidence",
        output=tmp_path / "reports",
        model_id="dummy-model",
        discovered=1,
        processed=1,
        low=0,
        review=0,
        high=1,
        errors=0,
        elapsed_seconds=1.0,
        cancelled=False,
        results=(result,),
        json_path=tmp_path / "reports" / "analysis.json",
        csv_path=tmp_path / "reports" / "analysis.csv",
    )

    state.set_analysis_results([result], summary)

    page = window.pages["results"]
    assert page.list_model.rowCount() == 1
    assert page.list_model.result_at(0) is result
    assert "HIGH 1" in page.summary_label.text()
    assert not page.move_button.isEnabled()
    assert "Moving files is disabled" in page.move_button.toolTip()
    page.list_view.selectionModel().select(
        page.list_model.index(0, 0), QItemSelectionModel.SelectionFlag.Select
    )
    state.source_mode = SourceMode.WORKING_COPY
    assert page.export_button.isEnabled()
    assert page.move_button.isEnabled()
    assert app is not None


def test_results_page_filter_modes_and_review_counts() -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    page = window.pages["results"]
    assert {name for name, box in page.filter_boxes.items() if box.isChecked()} == {
        "HIGH",
        "REVIEW",
    }

    results = (
        make_result("low.png", 0.59),
        make_result("error.png", None, "error"),
        make_result("review.png", 0.60),
        make_result("high.png", 0.85),
    )
    summary = AnalysisSummary(
        source=results[0].path.parent,
        output=results[0].path.parent,
        model_id="dummy-model",
        discovered=4,
        processed=4,
        low=1,
        review=1,
        high=1,
        errors=1,
        elapsed_seconds=1.0,
        cancelled=False,
        results=results,
        json_path=results[0].path.with_suffix(".json"),
        csv_path=results[0].path.with_suffix(".csv"),
    )
    state.set_analysis_results(list(results), summary)
    summary_text = page.summary_label.text()
    assert "4 analyzed" in summary_text
    assert "2 require review" in summary_text
    assert "LOW 1" in summary_text and "ERROR 1" in summary_text
    assert page.list_model.rowCount() == 2
    assert page.list_model.result_at(0) is results[3]

    assert page.filter_mode_button.text() == "SHOW ALL RESULTS"
    page.filter_mode_button.click()
    assert all(box.isChecked() for box in page.filter_boxes.values())
    assert [page.list_model.result_at(index) for index in range(4)] == [
        results[3],
        results[2],
        results[0],
        results[1],
    ]
    assert page.summary_label.text() == summary_text

    assert page.filter_mode_button.text() == "SHOW RELEVANT ONLY"
    page.filter_mode_button.click()
    assert {name for name, box in page.filter_boxes.items() if box.isChecked()} == {
        "HIGH",
        "REVIEW",
    }
    assert page.list_model.rowCount() == 2
    page.filter_boxes["ERROR"].setChecked(True)
    assert page.list_model.rowCount() == 3
    assert app is not None


def test_optional_detector_cards_and_combined_profile(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    cards = window.pages["models"].cards
    assert cards["nudenet-320n"].download_button.text() == "INSTALL BACKEND"
    assert cards["nudenet-640m"].status_label.text() == "NOT INSTALLED"

    model_root = tmp_path / "models"
    falconsai = "falconsai-nsfw-image-detection"
    nudenet = "nudenet-640m"
    for model_id in (falconsai, nudenet):
        directory = model_root / model_id
        directory.mkdir(parents=True)
        (directory / "manifest.json").write_text("{}")
    state.record_model_verification(falconsai, True)
    page = window.pages["analyze"]
    assert page.model_combo.currentText() == "Falconsai Only"
    state.backend_ready.add(nudenet)
    state.record_model_verification(nudenet, True)
    assert page.model_combo.currentText() == "Combined Detection · 640m"
    assert "READY · EXPERIMENTAL" in page.detector_summary.text()
    assert page.model_combo.findText("NudeNet Only · 640m") >= 0
    state.backend_ready.discard(nudenet)
    state.model_status_changed.emit(nudenet)
    assert page.model_combo.currentText() == "Falconsai Only"
    assert app is not None


def test_new_operation_exposes_sources_target_and_operation_choices(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    page = window.pages["analyze"]

    assert set(page.source_kind_buttons) == set(SourceKind)
    assert set(page.operation_buttons) == set(OperationMode)
    assert page.output_button.text() == "BROWSE TARGET"
    assert "recovered/" in page.target_preview.text()
    assert "ANALYZE EXISTING MEDIA" in page.operation_buttons[OperationMode.ANALYZE].text()
    assert app is not None


def test_directory_analyze_is_only_executable_gui_workflow(monkeypatch, tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    page = window.pages["analyze"]
    source_path = tmp_path / "evidence"
    target_path = tmp_path / "case"
    source_path.mkdir()
    monkeypatch.setattr(
        page,
        "_selected_profile",
        lambda: (AnalysisProfile.FALCONSAI, "test-model", "320n"),
    )

    page._set_source(inspect_directory(source_path))
    page.output_directory = str(target_path)
    page.output_edit.setText(str(target_path))
    state.target_descriptor = TargetDescriptor(target_path)
    state.discovery_completed = True
    page._update_start_state()
    assert page.discover_button.isEnabled()
    assert page.start_button.isEnabled()

    page._select_operation(OperationMode.RECOVER)
    assert not page.discover_button.isEnabled()
    assert not page.start_button.isEnabled()
    assert "not enabled for this source type" in page.status_label.text()
    assert app is not None


def test_changing_source_clears_discovery_but_preserves_results(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    page = window.pages["analyze"]
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    sentinel = object()

    page._set_source(inspect_directory(first))
    state.discovery_completed = True
    state.discovery_summary = {"total_images": 7}
    state.analysis_results = [sentinel]
    page._set_source(inspect_directory(second))

    assert not state.discovery_completed
    assert state.discovery_summary == {}
    assert state.analysis_results == [sentinel]
    assert page.source_edit.text() == str(second)
    assert app is not None


def test_forensic_image_candidate_is_configurable_but_not_executable(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    page = window.pages["analyze"]
    image = tmp_path / "disk.E01"
    image.write_bytes(b"candidate")

    page._select_source_kind(SourceKind.FORENSIC_IMAGE)
    page._set_source(inspect_forensic_image(image))
    page.output_directory = str(tmp_path / "target")
    state.target_directory = page.output_directory
    page._select_operation(OperationMode.RECOVER)

    assert "EWF (not verified)" in page.source_card.text()
    assert not page.start_button.isEnabled()
    assert state.source_mode is SourceMode.EVIDENCE
    assert app is not None


def test_application_state_emits_typed_workflow_values(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    sources = []
    targets = []
    operations = []
    capabilities = []
    state.source_changed.connect(sources.append)
    state.target_changed.connect(targets.append)
    state.operation_changed.connect(operations.append)
    state.workflow_capability_changed.connect(capabilities.append)
    source_path = tmp_path / "evidence"
    source_path.mkdir()
    source = inspect_directory(source_path)
    target = TargetDescriptor(tmp_path / "case")

    state.source_descriptor = source
    state.target_descriptor = target
    state.operation_mode = OperationMode.RECOVER

    assert sources[-1] is source
    assert targets[-1] is target
    assert operations[-1] is OperationMode.RECOVER
    assert not capabilities[-1].supported
    assert app is not None


def test_header_access_badge_follows_source_semantics(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    source_path = tmp_path / "working"
    source_path.mkdir()
    state.source_mode = SourceMode.WORKING_COPY
    state.source_descriptor = inspect_directory(source_path, read_only=False)
    assert window.read_only_badge.text() == "WORKING COPY"

    state.source_descriptor = SourceDescriptor(
        SourceKind.PHYSICAL_DEVICE,
        "/dev/fake",
        "Fake drive",
        False,
        True,
    )
    assert window.read_only_badge.text() == "EVIDENCE READ-ONLY"
    assert app is not None


def test_forensic_recovery_becomes_executable_with_tsk_and_inspection(
    monkeypatch, tmp_path
) -> None:
    import forensic_image_scanner.gui.pages.analyze_page as analyze_page_module

    tools = {name: Path(f"/usr/bin/{name}") for name in ("mmls", "fsstat", "fls", "icat")}
    monkeypatch.setattr(
        analyze_page_module,
        "probe_tsk",
        lambda: TskCapability(True, "TSK test", tools, ()),
    )
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)
    page = window.pages["analyze"]
    image = tmp_path / "case.dd"
    image.write_bytes(b"fixture")
    volume = RecoveryVolume("volume-01", 2048, 1000, "NTFS", "NTFS", True, 512, "case.dd")

    page._select_source_kind(SourceKind.FORENSIC_IMAGE)
    page._set_source(inspect_forensic_image(image))
    page.output_directory = str(tmp_path / "target")
    state.target_directory = page.output_directory
    page._select_operation(OperationMode.RECOVER)
    page._recovery_inspection_completed(SourceInspection(image, "GPT", 512, (volume,), "TSK test"))

    assert page.start_button.isEnabled()
    assert "Raw multimedia carving" in page.workflow_summary.text()
    assert "PhotoRec · READY" in page.workflow_summary.text()
    assert state.workflow_capability_changed is not None
    assert app is not None
