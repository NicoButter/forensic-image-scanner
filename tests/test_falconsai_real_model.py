"""Optional offline integration test for an administrator-imported Falconsai model."""

import math
import socket

import pytest

from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService
from forensic_image_scanner.calibration.controls import generate_negative_controls
from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.model_paths import resolve_model_directory
from forensic_image_scanner.models.registry import ModelRegistry

pytestmark = pytest.mark.model


def test_real_model_batch_scores_are_normalized_and_evidence_is_unchanged(
    tmp_path, monkeypatch
) -> None:
    """Run a small offline directory analysis after explicit local model import."""
    model_id = "falconsai-nsfw-image-detection"
    root = resolve_model_directory(None)
    if model_id not in ModelRegistry(root).registered_model_ids():
        pytest.skip(f"{model_id} is not installed under {root}")
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")

    network_attempts = []

    def reject_network(*args, **kwargs):
        network_attempts.append((args, kwargs))
        raise AssertionError("model inference attempted network access")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
    monkeypatch.setattr(socket.socket, "connect_ex", reject_network)
    monkeypatch.setattr(socket, "getaddrinfo", reject_network)
    source = tmp_path / "evidence"
    source.mkdir()
    paths = generate_negative_controls(source)
    before = {path: (sha256_file(path), path.stat().st_mtime_ns) for path in paths}

    summary = AnalysisService(root).run(
        AnalysisRequest(
            source=source,
            output=tmp_path / "reports",
            model=model_id,
        )
    )

    assert summary.processed == len(paths) == 13
    assert summary.errors == 0
    assert not network_attempts
    print(f"\n{'CONTROL':<22} {'NORMAL':>12} {'NSFW':>12}")
    for result in summary.results:
        assert result.normal_score is not None
        assert result.nsfw_score is not None
        assert math.isfinite(result.normal_score) and math.isfinite(result.nsfw_score)
        assert result.normal_score + result.nsfw_score == pytest.approx(1.0)
        assert 0.0 <= result.normal_score <= 1.0
        assert 0.0 <= result.nsfw_score <= 1.0
        assert result.device == "cpu"
        print(f"{result.path.stem:<22} {result.normal_score:>12.8f} {result.nsfw_score:>12.8f}")
    after = {path: (sha256_file(path), path.stat().st_mtime_ns) for path in source.iterdir()}
    assert after == before
