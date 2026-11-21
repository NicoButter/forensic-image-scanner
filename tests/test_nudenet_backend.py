"""Protocol and ensemble tests using local synthetic data."""

import json
import sys
from dataclasses import replace

import pytest
from PIL import Image

from forensic_image_scanner.analysis_service import AnalysisService
from forensic_image_scanner.detectors.nudenet import NUDENET_VERSION, BackendError, NudeNetClient
from forensic_image_scanner.results import AnatomicalDetection, Classification, NudeNetResult
from forensic_image_scanner.scoring.ensemble import DEFAULT_ENSEMBLE_POLICY, AnalysisProfile
from tests.test_analysis_service import make_request, make_service

LABEL = "FEMALE_BREAST_EXPOSED"
DIGEST = "a" * 64
HEALTH = {
    "schema_version": 1,
    "status": "ready",
    "backend": "nudenet",
    "backend_version": NUDENET_VERSION,
    "model": "320n",
    "model_sha256": DIGEST,
    "license": "AGPL-3.0",
}


def client(body, *, startup=2, inference=2):
    script = f"""
import json, sys, time
for line in sys.stdin:
    request = json.loads(line)
    if request['operation'] == 'health':
        print({json.dumps(json.dumps(HEALTH))}, flush=True)
    else:
        {body}
"""
    return NudeNetClient(
        [sys.executable, "-u", "-c", script],
        "320n",
        DIGEST,
        (LABEL,),
        startup_timeout=startup,
        inference_timeout=inference,
    )


def test_health_and_detection_preserve_class_score_box(tmp_path):
    response = json.dumps(
        {
            "schema_version": 1,
            "status": "ok",
            "detections": [{"class": LABEL, "confidence": 0.94, "box": [120, 80, 230, 190]}],
        }
    )
    with client(f"print({response!r}, flush=True)") as backend:
        assert backend.health == HEALTH
        result = backend.analyze(tmp_path / "image.png")
        assert result.detections == (AnatomicalDetection(LABEL, 0.94, (120, 80, 230, 190)),)
        process = backend.process
    assert process.poll() is not None


@pytest.mark.parametrize("body", ["print('not JSON')", "sys.exit(0)", "time.sleep(30)"])
def test_backend_failure_is_a_recoverable_result(tmp_path, body):
    with client(body, inference=0.2) as backend:
        process = backend.process
        assert backend.analyze(tmp_path / "image.png").status == "ERROR"
        assert process.poll() is not None


def test_bad_health_identity_is_rejected():
    backend = client("pass")
    backend.digest = "b" * 64
    with pytest.raises(BackendError, match="health check"), backend:
        pytest.fail("incorrect identity accepted")


def test_unavailable_and_startup_timeout(tmp_path):
    with pytest.raises(BackendError, match="not installed"):
        NudeNetClient.from_registry(tmp_path, "320n", tmp_path)
    process = NudeNetClient(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        "320n",
        DIGEST,
        (LABEL,),
        startup_timeout=0.1,
    )
    with pytest.raises(BackendError, match="health timed out"), process:
        pytest.fail("timeout backend accepted")


@pytest.mark.parametrize(
    "patch",
    [
        {"box": [1, 2, -3, 4]},
        {"box": [1, 2, True, 4]},
        {"confidence": True},
        {"confidence": float("nan")},
        {"class": "UNKNOWN"},
    ],
)
def test_invalid_detection_fields_are_rejected(tmp_path, patch):
    detection = {"class": LABEL, "confidence": 0.9, "box": [1, 2, 3, 4], **patch}
    response = json.dumps({"schema_version": 1, "status": "ok", "detections": [detection]})
    with client(f"print({response!r})") as backend:
        assert backend.analyze(tmp_path / "image.png").status == "ERROR"


def test_ensemble_priorities_and_explanations():
    policy = DEFAULT_ENSEMBLE_POLICY
    empty = NudeNetResult("320n", "OK")
    failed = NudeNetResult("320n", "ERROR", error="timeout")
    strong = NudeNetResult("320n", "OK", (AnatomicalDetection(LABEL, 0.94, (1, 2, 3, 4)),))
    weak = NudeNetResult("320n", "OK", (AnatomicalDetection(LABEL, 0.60, (1, 2, 3, 4)),))
    covered = NudeNetResult(
        "320n", "OK", (AnatomicalDetection("FEMALE_BREAST_COVERED", 0.99, (1, 2, 3, 4)),)
    )
    priority, reasons = policy.classify(0.92, empty)
    assert priority is Classification.HIGH
    assert any("No qualifying" in reason for reason in reasons)
    assert policy.classify(0.92, strong)[0] is Classification.HIGH
    assert policy.classify(0.20, strong)[0] is Classification.REVIEW
    assert policy.classify(0.70, strong)[0] is Classification.HIGH
    assert policy.classify(0.20, covered)[0] is Classification.LOW
    assert policy.classify(None, strong)[0] is Classification.HIGH
    assert policy.classify(None, weak)[0] is Classification.REVIEW
    assert policy.classify(None, failed)[0] is None
    assert policy.classify(0.92, failed) == (
        Classification.HIGH,
        ("Falconsai NSFW score 0.92", "NudeNet unavailable: timeout"),
    )


def test_combined_preserves_falconsai_when_backend_is_unavailable(tmp_path):
    source = tmp_path / "evidence"
    source.mkdir()
    Image.new("RGB", (4, 4), (240, 0, 0)).save(source / "object.png")
    service: AnalysisService = make_service(tmp_path)
    request = replace(make_request(tmp_path, source), profile=AnalysisProfile.COMBINED)
    result = service.run(request).results[0]
    assert result.status == "completed"
    assert result.nsfw_score == 240 / 255
    assert result.triage is Classification.HIGH
    assert result.nudenet is not None and result.nudenet.status == "ERROR"
    assert result.to_dict()["detectors"]["nudenet"]["detections"] == ()


def test_object_without_corroboration_stays_high_in_combined_report(tmp_path, monkeypatch):
    source = tmp_path / "evidence"
    source.mkdir()
    Image.new("RGB", (4, 4), (240, 0, 0)).save(source / "object.png")
    response = '{"schema_version":1,"status":"ok","detections":[]}'
    monkeypatch.setattr(
        NudeNetClient, "from_registry", lambda *_args: client(f"print({response!r})")
    )
    service = make_service(tmp_path)
    request = replace(make_request(tmp_path, source), profile=AnalysisProfile.COMBINED)
    summary = service.run(request)
    result = summary.results[0]
    assert result.triage is Classification.HIGH
    assert summary.nudenet_errors == 0
    row = json.loads(summary.json_path.read_text())[0]
    assert row["nsfw_score"] == 240 / 255
    assert row["detectors"]["nudenet"]["status"] == "OK"
    assert row["detectors"]["nudenet"]["detections"] == []
    assert any("No qualifying" in reason for reason in row["triage_reasons"])
