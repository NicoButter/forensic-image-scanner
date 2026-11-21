"""Small, local media validation and provenance fixtures."""

import json
import subprocess

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
    monkeypatch.setattr(video.subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess(a, 0, json.dumps(data), ""))
    item = record(path, "video")
    validate_video(path, item)
    assert item.integrity == MediaIntegrity.VALID
    data["streams"] = []
    item = record(path, "video")
    validate_video(path, item)
    assert item.integrity == MediaIntegrity.CORRUPT
    monkeypatch.setattr(video.subprocess, "run", lambda *a, **k:
                        (_ for _ in ()).throw(subprocess.TimeoutExpired("ffprobe", 1)))
    item = record(path, "video")
    validate_video(path, item)
    assert item.errors
    monkeypatch.setattr(video.subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess(a, 0, "not json", ""))
    item = record(path, "video")
    validate_video(path, item)
    assert item.integrity == MediaIntegrity.CORRUPT and item.errors


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
