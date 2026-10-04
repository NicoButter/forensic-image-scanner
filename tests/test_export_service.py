"""Tests for explicit verified export and controlled working-copy moves."""

from __future__ import annotations

import csv
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from forensic_image_scanner.export_service import ExportService
from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.reports.csv_report import write_csv_report
from forensic_image_scanner.reports.json_report import write_json_report
from forensic_image_scanner.results import (
    Classification,
    ExportStatus,
    ImageAnalysisResult,
    MoveStatus,
    SourceMode,
)


def make_result(
    source_root: Path, relative_path: str, *, score: float = 0.9
) -> ImageAnalysisResult:
    path = source_root / relative_path
    digest = sha256_file(path)
    return ImageAnalysisResult(
        path=path,
        relative_path=relative_path,
        filename=path.name,
        size_bytes=path.stat().st_size,
        mime_type="image/jpeg",
        sha256=digest,
        model_id="test-model",
        model_revision="1",
        model_sha256="a" * 64,
        provenance_status="partial",
        normal_score=1 - score,
        nsfw_score=score,
        top_label="nsfw",
        confidence=score,
        triage=Classification.HIGH,
        device="cpu",
        analysis_timestamp=datetime.now(UTC),
        status="completed",
    )


def write_source(root: Path, relative_path: str, data: bytes) -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_export_preserves_source_hash_mtime_and_relative_path(tmp_path) -> None:
    source = tmp_path / "evidence"
    output = tmp_path / "reports"
    original = write_source(source, "recup_dir.1/f00001.jpg", b"synthetic image bytes")
    result = make_result(source, "recup_dir.1/f00001.jpg")
    before = (original.stat().st_size, original.stat().st_mtime_ns, sha256_file(original))

    updated = ExportService(source, output).export_result(result)

    destination = output / "exported" / "HIGH" / "recup_dir.1" / "f00001.jpg"
    assert updated.export_status is ExportStatus.EXPORTED
    assert updated.exported_path == destination
    assert updated.exported_sha256 == before[2]
    assert updated.source_verified_before_export
    assert sha256_file(destination) == before[2]
    assert (original.stat().st_size, original.stat().st_mtime_ns, sha256_file(original)) == before
    audit = (output / "audit.log").read_text(encoding="utf-8")
    assert "export requested" in audit
    assert "export destination integrity verified" in audit
    assert "export completed" in audit


def test_export_multiple_same_names_do_not_collide(tmp_path) -> None:
    source = tmp_path / "evidence"
    output = tmp_path / "reports"
    write_source(source, "recup_dir.1/f00001.jpg", b"one")
    write_source(source, "recup_dir.99/f00001.jpg", b"two")
    results = [
        make_result(source, "recup_dir.1/f00001.jpg"),
        make_result(source, "recup_dir.99/f00001.jpg"),
    ]

    updated = ExportService(source, output).export_results(results)

    assert len(updated) == 2
    assert (output / "exported" / "HIGH" / "recup_dir.1" / "f00001.jpg").read_bytes() == b"one"
    assert (output / "exported" / "HIGH" / "recup_dir.99" / "f00001.jpg").read_bytes() == b"two"


def test_export_rejects_source_modified_since_analysis(tmp_path) -> None:
    source = tmp_path / "evidence"
    output = tmp_path / "reports"
    original = write_source(source, "image.jpg", b"before")
    result = make_result(source, "image.jpg")
    original.write_bytes(b"after")

    updated = ExportService(source, output).export_result(result)

    assert updated.export_status is ExportStatus.EXPORT_FAILED
    assert "SOURCE MODIFIED SINCE ANALYSIS" in updated.error
    assert not (output / "exported" / "HIGH" / "image.jpg").exists()
    assert original.read_bytes() == b"after"


def test_export_rejects_path_traversal(tmp_path) -> None:
    source = tmp_path / "evidence"
    output = tmp_path / "reports"
    write_source(source, "image.jpg", b"bytes")
    result = make_result(source, "image.jpg")
    unsafe = replace(result, relative_path="../outside.jpg")

    updated = ExportService(source, output).export_result(unsafe)

    assert updated.export_status is ExportStatus.EXPORT_FAILED
    assert "unsafe relative path" in updated.error
    assert not (tmp_path / "outside.jpg").exists()


def test_export_hash_mismatch_removes_part_and_preserves_source(tmp_path, monkeypatch) -> None:
    source = tmp_path / "evidence"
    output = tmp_path / "reports"
    original = write_source(source, "image.jpg", b"bytes")
    result = make_result(source, "image.jpg")
    expected = result.sha256

    import forensic_image_scanner.export_service as export_module

    def wrong_destination_hash(path: Path) -> str:
        return expected if path == original else "0" * 64

    monkeypatch.setattr(export_module, "sha256_file", wrong_destination_hash)
    updated = ExportService(source, output).export_result(result)

    assert updated.export_status is ExportStatus.EXPORT_FAILED
    assert original.exists()
    assert not list(output.rglob("*.part"))
    assert not (output / "exported" / "HIGH" / "image.jpg").exists()


def test_export_cancellation_keeps_completed_files(tmp_path) -> None:
    source = tmp_path / "evidence"
    output = tmp_path / "reports"
    write_source(source, "one.jpg", b"one")
    write_source(source, "two.jpg", b"two")
    results = [make_result(source, "one.jpg"), make_result(source, "two.jpg")]
    stopped = False

    def progress(_current: int, _total: int, _result: ImageAnalysisResult) -> None:
        nonlocal stopped
        stopped = True

    updated = ExportService(source, output).export_results(
        results, cancelled=lambda: stopped, progress=progress
    )

    assert len(updated) == 1
    assert (output / "exported" / "HIGH" / "one.jpg").exists()
    assert not (output / "exported" / "HIGH" / "two.jpg").exists()


def test_move_requires_working_copy_and_deletes_only_after_verified_copy(tmp_path) -> None:
    source = tmp_path / "working"
    output = tmp_path / "reports"
    original = write_source(source, "nested/image.jpg", b"working bytes")
    result = make_result(source, "nested/image.jpg")
    service = ExportService(source, output)

    with pytest.raises(PermissionError):
        service.move_result(result, source_mode=SourceMode.EVIDENCE)
    assert original.exists()

    updated = service.move_result(result, source_mode=SourceMode.WORKING_COPY)

    destination = output / "exported" / "HIGH" / "nested" / "image.jpg"
    assert updated.move_status is MoveStatus.MOVED
    assert updated.source_removed is True
    assert not original.exists()
    assert sha256_file(destination) == result.sha256


def test_failed_move_hash_does_not_delete_source(tmp_path, monkeypatch) -> None:
    source = tmp_path / "working"
    output = tmp_path / "reports"
    original = write_source(source, "image.jpg", b"bytes")
    result = make_result(source, "image.jpg")

    import forensic_image_scanner.export_service as export_module

    monkeypatch.setattr(export_module, "sha256_file", lambda _path: "0" * 64)
    updated = ExportService(source, output).move_result(result, source_mode=SourceMode.WORKING_COPY)

    assert updated.move_status is MoveStatus.MOVE_FAILED
    assert updated.source_removed is False
    assert original.exists()


def test_move_reports_partial_when_verified_destination_cannot_delete_source(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "working"
    output = tmp_path / "reports"
    original = write_source(source, "image.jpg", b"bytes")
    result = make_result(source, "image.jpg")
    original_unlink = Path.unlink

    def refuse_only_source(path: Path, *args, **kwargs) -> None:
        if path == original:
            raise PermissionError("source removal denied")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_only_source)
    updated = ExportService(source, output).move_result(result, source_mode=SourceMode.WORKING_COPY)

    assert updated.move_status is MoveStatus.MOVE_PARTIAL
    assert updated.source_removed is False
    assert original.exists()
    assert updated.exported_path is not None
    assert updated.exported_path.read_bytes() == b"bytes"


def test_reports_record_export_metadata_without_losing_source_fields(tmp_path) -> None:
    source = tmp_path / "evidence"
    output = tmp_path / "reports"
    write_source(source, "image.jpg", b"bytes")
    updated = ExportService(source, output).export_result(make_result(source, "image.jpg"))
    csv_path = output / "analysis.csv"
    json_path = output / "analysis.json"
    write_csv_report([updated], csv_path)
    write_json_report([updated], json_path)

    with csv_path.open(encoding="utf-8", newline="") as report:
        row = next(csv.DictReader(report))
    assert row["original_path"] == str(source / "image.jpg")
    assert row["export_status"] == "EXPORTED"
    assert row["exported_sha256"] == updated.sha256
    payload = json.loads(json_path.read_text(encoding="utf-8"))[0]
    assert payload["source"]["sha256"] == updated.sha256
    assert payload["analysis"]["triage"] == "HIGH"
    assert payload["export"]["destination"] == str(updated.exported_path)


def test_source_symlink_is_never_exported(tmp_path) -> None:
    source = tmp_path / "evidence"
    output = tmp_path / "reports"
    target = write_source(tmp_path, "target.jpg", b"bytes")
    source.mkdir()
    link = source / "image.jpg"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    result = make_result(source, "image.jpg")

    updated = ExportService(source, output).export_result(result)

    assert updated.export_status is ExportStatus.EXPORT_FAILED
    assert not (output / "exported" / "HIGH" / "image.jpg").exists()
