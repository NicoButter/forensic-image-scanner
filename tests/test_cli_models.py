"""CLI tests for offline model management and result serialization."""

import json
from types import SimpleNamespace

from PIL import Image

from forensic_image_scanner.analysis import analyze_image_file
from forensic_image_scanner.cli import main
from forensic_image_scanner.detectors.falconsai import FalconsaiDetector
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.models.registry import VerifiedModel


class FakeRuntime:
    def predict(self, image: Image.Image) -> list[float]:
        return [0.6, 0.4]

    def metadata(self) -> dict[str, object]:
        return {"device": "cpu", "offline": True}


def test_model_list_and_info_are_available_offline(tmp_path, capsys) -> None:
    assert main(["model", "list", "--model-dir", str(tmp_path)]) == 0
    listed = capsys.readouterr().out
    assert "falconsai-nsfw-image-detection" in listed
    assert "nudenet-320n" in listed

    assert (
        main(
            [
                "model",
                "info",
                "falconsai-nsfw-image-detection",
                "--model-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    info = capsys.readouterr().out
    assert "Provenance status:    partial" in info
    assert "SHA-256 expected:" in info


def test_model_verify_reports_not_installed(tmp_path, caplog) -> None:
    assert (
        main(
            [
                "model",
                "verify",
                "falconsai-nsfw-image-detection",
                "--model-dir",
                str(tmp_path),
            ]
        )
        == 3
    )
    assert "Model is unavailable" in caplog.text


def test_analysis_serialization_with_synthetic_image(tmp_path) -> None:
    source = tmp_path / "gradient.png"
    Image.linear_gradient("L").resize((16, 16)).save(source)
    manifest = ModelManifest.from_dict(
        {
            "schema_version": 1,
            "model_id": "falconsai-nsfw-image-detection",
            "model_version": "test",
            "filename": "model.safetensors",
            "sha256": "0" * 64,
            "source": "https://example.invalid",
            "source_revision": "test",
            "code_license": "Apache-2.0",
            "weights_license": "Apache-2.0",
            "framework": "pytorch",
            "input_size": [224, 224],
            "labels": ["normal", "nsfw"],
            "provenance_status": "partial",
            "size_bytes": 1,
        }
    )
    model = VerifiedModel(manifest, tmp_path / "model.safetensors", {})
    detector = FalconsaiDetector(model, runtime_factory=lambda _: FakeRuntime())

    serialized = json.dumps(analyze_image_file(source, detector).to_dict())

    assert '"scores"' in serialized
    assert '"normal"' in serialized
    assert '"nsfw"' in serialized


def test_model_admin_commands_delegate_to_installation_service(monkeypatch, tmp_path) -> None:
    calls: list[tuple[str, object]] = []

    class FakeInstallationService:
        def __init__(self, root) -> None:
            calls.append(("init", root))

        def install_from_url(self, model_id, progress=None):
            calls.append(("download", model_id))
            if progress is not None:
                progress(1, 1)
            return SimpleNamespace(
                manifest=SimpleNamespace(model_id=model_id), path=tmp_path / model_id / "model"
            )

        def install_from_file(self, model_id, source):
            calls.append(("import", (model_id, source)))
            return SimpleNamespace(
                manifest=SimpleNamespace(model_id=model_id), path=tmp_path / model_id / "model"
            )

        def remove(self, model_id) -> None:
            calls.append(("remove", model_id))

    monkeypatch.setattr(
        "forensic_image_scanner.cli.ModelInstallationService", FakeInstallationService
    )
    model_id = "falconsai-nsfw-image-detection"
    assert main(["model", "download", model_id, "--model-dir", str(tmp_path)]) == 0
    assert main(["model", "import", model_id, str(tmp_path), "--model-dir", str(tmp_path)]) == 0
    assert main(["model", "remove", model_id, "--model-dir", str(tmp_path)]) == 0
    assert ("download", model_id) in calls
    assert ("import", (model_id, tmp_path)) in calls
    assert ("remove", model_id) in calls
