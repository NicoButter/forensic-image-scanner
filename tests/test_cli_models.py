"""CLI tests for offline model management and result serialization."""

import json

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
