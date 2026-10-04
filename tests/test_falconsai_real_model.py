"""Optional offline integration test for an administrator-imported Falconsai model."""

import os
from pathlib import Path

import pytest
from PIL import Image

from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService

pytestmark = pytest.mark.model


def test_real_model_batch_scores_are_normalized_and_evidence_is_unchanged(
    tmp_path, monkeypatch
) -> None:
    """Run a small offline directory analysis after explicit local model import."""
    root = os.environ.get("FORENSIC_IMAGE_SCANNER_MODEL_DIR")
    if not root:
        pytest.skip("FORENSIC_IMAGE_SCANNER_MODEL_DIR is not configured")
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")
    source = tmp_path / "evidence"
    source.mkdir()
    for name, color in (("black.png", "black"), ("white.png", "white"), ("gray.png", "gray")):
        Image.new("RGB", (32, 32), color).save(source / name)
    before = {path: (path.stat().st_size, path.stat().st_mtime_ns) for path in source.iterdir()}

    summary = AnalysisService(Path(root)).run(
        AnalysisRequest(
            source=source,
            output=tmp_path / "reports",
            model="falconsai-nsfw-image-detection",
        )
    )

    assert summary.processed == 3
    assert summary.errors == 0
    for result in summary.results:
        assert result.normal_score is not None
        assert result.nsfw_score is not None
        assert result.normal_score + result.nsfw_score == pytest.approx(1.0)
        assert 0.0 <= result.normal_score <= 1.0
        assert 0.0 <= result.nsfw_score <= 1.0
        assert result.device == "cpu"
    after = {path: (path.stat().st_size, path.stat().st_mtime_ns) for path in source.iterdir()}
    assert after == before
