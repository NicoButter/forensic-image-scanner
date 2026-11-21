"""Offline CLI and binary metrics tests without external model weights."""

import json

import pytest
from PIL import Image

from forensic_image_scanner.calibration import runner
from forensic_image_scanner.calibration.metrics import sweep_thresholds
from forensic_image_scanner.cli import EXIT_ANALYSIS, main
from forensic_image_scanner.hashing import sha256_file
from tests.test_analysis_service import FakeDetector, install_dummy_model


def test_metrics_and_inclusive_thresholds() -> None:
    sweep = sweep_thresholds([0.10, 0.20, 0.70], [0.80, 0.90, 0.95])
    assert [row.threshold for row in sweep] == [n / 100 for n in range(50, 100, 5)]
    at_70 = sweep[4]
    assert (at_70.tp, at_70.fp, at_70.tn, at_70.fn) == (3, 1, 2, 0)
    assert at_70.confusion_matrix == {
        "normal": {"normal": 2, "nsfw": 0},
        "nsfw": {"normal": 1, "nsfw": 3},
    }
    assert at_70.precision == pytest.approx(0.75)
    assert at_70.recall == pytest.approx(1)
    assert at_70.specificity == pytest.approx(2 / 3)
    assert at_70.false_positive_rate == pytest.approx(1 / 3)
    assert at_70.false_negative_rate == pytest.approx(0)
    assert at_70.f1 == pytest.approx(6 / 7)
    assert at_70.accuracy == pytest.approx(5 / 6)
    at_85 = sweep[7]
    assert (at_85.tp, at_85.fp, at_85.tn, at_85.fn) == (2, 0, 3, 1)
    assert at_85.false_negative_rate == pytest.approx(1 / 3)
    assert at_85.f1 == pytest.approx(0.8)


def test_undefined_ratios_are_unset() -> None:
    row = sweep_thresholds([0.1, 0.2], [])[0]
    assert row.precision is row.recall is row.false_negative_rate is row.f1 is None
    assert row.specificity == row.accuracy == 1
    assert row.false_positive_rate == 0
    assert sweep_thresholds([], [])[0].accuracy is None


def test_calibrate_cli_reports_scores_and_errors_without_changing_corpus(
    tmp_path, monkeypatch, capsys
) -> None:
    models = tmp_path / "models"
    model_id = "falconsai-nsfw-image-detection"
    install_dummy_model(models, model_id)

    class TestDetector(FakeDetector):
        def prepare(self):
            pass

    monkeypatch.setattr(runner, "FalconsaiDetector", TestDetector)
    corpus = tmp_path / "corpus"
    normal = corpus / "normal" / "nested"
    normal.mkdir(parents=True)
    (corpus / "nsfw").mkdir()
    low = normal / "low.PNG"
    high = corpus / "nsfw" / "high.png"
    broken = normal / "broken.png"
    Image.new("RGB", (4, 4), (12, 0, 0)).save(low)
    Image.new("RGB", (4, 4), (235, 0, 0)).save(high)
    broken.write_bytes(b"broken")
    (normal / "ignored.png").symlink_to(high)
    (corpus / "normal" / "redirect").symlink_to(corpus / "nsfw", target_is_directory=True)
    before = {p: (sha256_file(p), p.stat().st_mtime_ns) for p in (low, high, broken)}

    destination = tmp_path / "report.json"
    argv = ["calibrate", str(corpus), "--model-dir", str(models), "--output", str(destination)]
    assert main(argv) == EXIT_ANALYSIS
    assert "Scored 2 · Errors 1" in capsys.readouterr().out
    report = json.loads(destination.read_text())
    assert report["model_id"] == model_id
    assert report["prediction_threshold"] == 0.50
    assert report["counts"] == {"normal": 2, "nsfw": 1}
    assert report["error_count"] == 1
    assert report["sweep"][0]["confusion_matrix"] == {
        "normal": {"normal": 1, "nsfw": 0},
        "nsfw": {"normal": 0, "nsfw": 1},
    }
    assert report["results"][0]["error"].startswith("ImageDecodeError")
    assert report["results"][1] == {
        "filename": "low.PNG",
        "relative_path": "normal/nested/low.PNG",
        "expected_class": "normal",
        "normal_score": 1 - 12 / 255,
        "nsfw_score": 12 / 255,
        "predicted_class": "normal",
        "error": None,
    }
    assert {p: (sha256_file(p), p.stat().st_mtime_ns) for p in before} == before
    assert main(argv) == 2

    inside = corpus / "report.json"
    assert main([*argv[:-1], str(inside)]) == 2
    assert not inside.exists()


def test_calibrate_rejects_ambiguous_mode_or_missing_class(tmp_path) -> None:
    assert main(["calibrate"]) == 2
    assert main(["calibrate", str(tmp_path), "--synthetic-controls"]) == 2
    assert main(["calibrate", str(tmp_path)]) == 2
