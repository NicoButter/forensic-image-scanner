"""Optional offline integration test for an administrator-imported Falconsai model."""

import os
from pathlib import Path

import pytest
from PIL import Image

from forensic_image_scanner.detectors.falconsai import FalconsaiDetector
from forensic_image_scanner.models.registry import ModelRegistry

pytestmark = pytest.mark.model


def test_real_model_scores_are_normalized(tmp_path, monkeypatch) -> None:
    """Run only with `pytest -m model` after explicit local model import."""
    root = os.environ.get("FORENSIC_IMAGE_SCANNER_MODEL_DIR")
    if not root:
        pytest.skip("FORENSIC_IMAGE_SCANNER_MODEL_DIR is not configured")
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")
    model = ModelRegistry(Path(root)).load("falconsai-nsfw-image-detection")
    image = Image.new("RGB", (32, 32), "white")
    scores = FalconsaiDetector(model).analyze(image).scores

    assert set(scores) == {"normal", "nsfw"}
    assert sum(scores.values()) == pytest.approx(1.0)
