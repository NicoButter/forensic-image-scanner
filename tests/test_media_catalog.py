"""Small, local media validation and provenance fixtures."""

import json
import subprocess
import threading

import pytest
from PIL import Image

from forensic_image_scanner.media import MediaCatalogService, MediaIntegrity, MediaRecord
from forensic_image_scanner.media.image_validator import validate_image
from forensic_image_scanner.media.video_validator import validate_video


def record(path, kind="image"):
    return MediaRecord("id", "a" * 64, str(path), path.stat().st_size, kind, path.suffix)


@pytest.mark.parametrize("fmt,suffix", [("JPEG", ".jpg"), ("PNG", ".png")])
def test_valid_images_and_mismatch(tmp_path, fmt, suffix):
    path = tmp_path / ("image" + suffix)
    Image.new("RGB", (8, 8)).save(path, fmt)
    item = record(path)
    validate_image(path, item)
    assert item.integrity == MediaIntegrity.VALID and item.actual_format == fmt
    item.candidate_extension = ".gif"
    validate_image(path, item)
    assert item.warnings


def test_corrupt_image_and_missing_raw(tmp_path, monkeypatch):
    path = tmp_path / "bad.jpg"
    path.write_bytes(b"broken")
    item = record(path)
    validate_image(path, item)
    assert item.integrity == MediaIntegrity.CORRUPT
    import forensic_image_scanner.formats.raw as raw

    monkeypatch.setattr(raw, "load_raw_image", lambda _: (_ for _ in ()).throw(RuntimeError()))
    path = tmp_path / "bad.nef"
    path.write_bytes(b"broken")
    item = record(path)
    validate_image(path, item)
    assert item.integrity == MediaIntegrity.UNSUPPORTED


def test_truncated_image_is_not_valid(tmp_path):
    path = tmp_path / "truncated.jpg"
    Image.new("RGB", (32, 32)).save(path, "JPEG")
    data = path.read_bytes()
    path.write_bytes(data[:-10])
    item = record(path)
    validate_image(path, item)
    assert item.integrity in {MediaIntegrity.PARTIAL, MediaIntegrity.CORRUPT}


def test_video_probe_outcomes(tmp_path, monkeypatch):
    import forensic_image_scanner.media.video_validator as video

    path = tmp_path / "clip.mp4"
    path.write_bytes(b"video")
    monkeypatch.setattr(video.shutil, "which", lambda _: None)
    item = record(path, "video")
    validate_video(path, item)
    assert item.integrity == MediaIntegrity.UNSUPPORTED
    monkeypatch.setattr(video.shutil, "which", lambda _: "/usr/bin/ffprobe")
    data = {"format": {"format_name": "mov", "duration": "2"}, "streams": [
        {"codec_type": "video", "codec_name": "h264", "width": 8, "height": 8}
    ]}

    def run_probe(arguments, **kwargs):
        assert isinstance(arguments, list)
        assert kwargs["shell"] is False
        assert kwargs["cwd"] == path.parent
        kwargs["stdout"].write(json.dumps(data).encode())
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(video.subprocess, "run", run_probe)
    item = record(path, "video")
    validate_video(path, item)
    assert item.integrity == MediaIntegrity.VALID
    data["streams"] = []
    item = record(path, "video")
    validate_video(path, item)
    assert item.integrity == MediaIntegrity.CORRUPT
    monkeypatch.setattr(
        video.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("ffprobe", 1)),
    )
    item = record(path, "video")
    validate_video(path, item)
    assert item.errors
    monkeypatch.setattr(
        video.subprocess,
        "run",
        lambda arguments, **kwargs: (
            kwargs["stdout"].write(b"not json"),
            subprocess.CompletedProcess(arguments, 0),
        )[1],
    )
    item = record(path, "video")
    validate_video(path, item)
    assert item.integrity == MediaIntegrity.CORRUPT and item.errors


@pytest.mark.parametrize("payload", [b"[]", b"{bad json}"])
def test_video_probe_rejects_malformed_json_shape(tmp_path, monkeypatch, payload):
    import forensic_image_scanner.media.video_validator as video

    path = tmp_path / "clip.mp4"
    path.write_bytes(b"fixture")
    monkeypatch.setattr(video.shutil, "which", lambda _: "/usr/bin/ffprobe")

    def run_probe(arguments, **kwargs):
        kwargs["stdout"].write(payload)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(video.subprocess, "run", run_probe)
    item = record(path, "video")
    validate_video(path, item)

    assert item.integrity is MediaIntegrity.CORRUPT
    assert item.errors == ["MALFORMED_FFPROBE_JSON"]


def test_video_probe_caps_metadata_output(tmp_path, monkeypatch):
    import forensic_image_scanner.media.video_validator as video

    path = tmp_path / "clip.mp4"
    path.write_bytes(b"fixture")
    monkeypatch.setattr(video.shutil, "which", lambda _: "/usr/bin/ffprobe")

    def run_probe(arguments, **kwargs):
        kwargs["stdout"].write(b" " * (video.MAX_PROBE_OUTPUT_BYTES + 1))
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(video.subprocess, "run", run_probe)
    item = record(path, "video")
    validate_video(path, item)

    assert item.errors == ["FFPROBE_OUTPUT_LIMIT"]


def test_catalog_merges_provenance_and_reports(tmp_path):
    path = tmp_path / "recovered" / "one.png"
    path.parent.mkdir()
    Image.new("RGB", (8, 8)).save(path)
    source = {"recovered_sha256": "a" * 64, "recovered_relative_path": "recovered/one.png",
              "candidate_media_kind": "image", "candidate_extension": ".png",
              "method": "filesystem_metadata", "recovery_id": "one",
              "original_path": "DCIM/a.png", "recovery_status": "recovered"}
    duplicate = dict(source, method="file_carving", recovery_id="two", original_path="UNKNOWN")
    result = MediaCatalogService().build_records(tmp_path, [source, duplicate])
    assert len(result) == 1 and result[0].recovery_ids == ["one", "two"]
    assert len(result[0].provenance) == 2 and result[0].integrity == MediaIntegrity.VALID
    assert (tmp_path / "reports/media_catalog.json").exists()
    assert (tmp_path / "reports/media_catalog.csv").exists()


def test_catalog_order_is_stable_across_input_order(tmp_path):
    recovered = tmp_path / "recovered"
    recovered.mkdir()
    records = []
    for name, digest in (("z.png", "f" * 64), ("a.png", "a" * 64)):
        path = recovered / name
        Image.new("RGB", (4, 4)).save(path)
        records.append(
            {
                "recovered_sha256": digest,
                "recovered_relative_path": f"recovered/{name}",
                "candidate_media_kind": "image",
                "candidate_extension": ".png",
                "method": "filesystem_metadata",
                "recovery_id": name,
                "original_path": name,
                "recovery_status": "recovered",
            }
        )

    forward = MediaCatalogService().build_records(tmp_path, records)
    reverse = MediaCatalogService().build_records(tmp_path, list(reversed(records)))

    assert [item.media_id for item in forward] == [item.media_id for item in reverse]


def test_catalog_cancellation_reports_partial_state_and_preserves_artifact(tmp_path):
    path = tmp_path / "recovered" / "image.png"
    path.parent.mkdir()
    Image.new("RGB", (4, 4)).save(path)
    record_data = {
        "recovered_sha256": "a" * 64,
        "recovered_relative_path": "recovered/image.png",
        "candidate_media_kind": "image",
        "candidate_extension": ".png",
        "method": "filesystem_metadata",
        "recovery_id": "one",
        "original_path": "image.png",
        "recovery_status": "recovered",
    }
    original = path.read_bytes()
    cancel = threading.Event()
    cancel.set()

    result = MediaCatalogService().build_records(
        tmp_path, [record_data], cancel=cancel
    )

    payload = json.loads(
        (tmp_path / "reports" / "media_catalog.json").read_text(encoding="utf-8")
    )
    assert result == [] and payload["cancelled"] is True
    assert payload["records"] == []
    assert path.read_bytes() == original
