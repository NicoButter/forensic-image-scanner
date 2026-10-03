"""Falconsai adapter unit tests without Torch or a real model artifact."""

import os
from pathlib import Path

from PIL import Image

from forensic_image_scanner.detectors.falconsai import FalconsaiDetector, _set_offline_environment
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.models.registry import VerifiedModel


class FakeRuntime:
    """Small deterministic runtime substitute."""

    def predict(self, image: Image.Image) -> list[float]:
        assert image.mode == "RGB"
        return [0.2, 0.8]

    def metadata(self) -> dict[str, object]:
        return {"device": "cpu", "offline": True}


def test_detector_returns_structured_normal_nsfw_scores() -> None:
    manifest = ModelManifest.from_dict(
        {
            "schema_version": 1,
            "model_id": "falconsai-nsfw-image-detection",
            "model_version": "test-revision",
            "filename": "model.safetensors",
            "sha256": "0" * 64,
            "source": "https://example.invalid",
            "source_revision": "test-revision",
            "code_license": "Apache-2.0",
            "weights_license": "Apache-2.0",
            "framework": "pytorch",
            "input_size": [224, 224],
            "labels": ["normal", "nsfw"],
            "provenance_status": "partial",
            "size_bytes": 1,
            "artifacts": [],
        }
    )
    model = VerifiedModel(manifest=manifest, path=Path("model.safetensors"), auxiliary_paths={})
    detector = FalconsaiDetector(model, runtime_factory=lambda _: FakeRuntime())

    output = detector.analyze(Image.new("L", (4, 4), 127))

    assert output.scores == {"normal": 0.2, "nsfw": 0.8}
    assert output.top_label == "nsfw"
    assert output.confidence == 0.8
    assert output.provenance_status == "partial"
    assert output.runtime["device"] == "cpu"


def test_runtime_enables_strict_offline_environment(monkeypatch) -> None:
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY"):
        monkeypatch.delenv(name, raising=False)

    _set_offline_environment()

    assert os.environ["HF_HUB_OFFLINE"] == "1"
    assert os.environ["TRANSFORMERS_OFFLINE"] == "1"
    assert os.environ["HF_HUB_DISABLE_TELEMETRY"] == "1"
