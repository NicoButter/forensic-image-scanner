"""Smoke tests for the optional Qt desktop GUI."""

import hashlib
import os
from datetime import UTC, datetime

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QItemSelectionModel
from PySide6.QtWidgets import QApplication

from forensic_image_scanner.gui import create_application, main
from forensic_image_scanner.gui.main_window import MainWindow
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.models.importer import import_model
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.results import (
    AnalysisSummary,
    Classification,
    ImageAnalysisResult,
    SourceMode,
)


@pytest.fixture(autouse=True)
def isolated_model_directory(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("FORENSIC_IMAGE_SCANNER_MODEL_DIR", str(tmp_path / "models"))


def test_gui_entry_points_are_importable() -> None:
    assert callable(create_application)
    assert callable(main)


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
    assert window.pages["models"].cards["dummy-model"].verify_button.isVisibleTo(
        window.pages["models"]
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
