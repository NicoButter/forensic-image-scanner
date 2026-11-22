"""Filesystem recovery orchestration with a deterministic fake TSK backend."""

import json
import shutil
import threading
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.recovery import (
    DeletedMediaEntry,
    FilesystemRecoveryService,
    MediaKind,
    RecoveryRequest,
    RecoveryStatus,
    RecoveryVolume,
    SourceInspection,
)
from forensic_image_scanner.recovery.service import _safe_name
from forensic_image_scanner.recovery.tsk.runner import TskCommandError


def entry(name="IMG 001.JPG", size=7, *, metadata="1304-128-1", reallocated=False):
    return DeletedMediaEntry(
        "volume-01",
        "NTFS",
        metadata,
        name,
        f"/Users/A/{name}",
        size,
        datetime(2024, 1, 1, tzinfo=UTC),
        None,
        None,
        None,
        Path(name).suffix.casefold(),
        MediaKind.IMAGE,
        reallocated,
        False,
    )


class FakeBackend:
    def __init__(self, payload=b"content", error=None, entries=None):
        self.payload = payload
        self.error = error
        self.entries = tuple(entries or (entry(),))
        self.volume = RecoveryVolume(
            "volume-01", 2048, 10000, "NTFS partition", "NTFS", True, 512, "case.dd"
        )

    def inspect(self, source):
        return SourceInspection(source, "GPT", 512, (self.volume,), "TSK test 4.14")

    def enumerate_deleted(self, source, volume):
        return self.entries, len(self.entries) + 2

    def extract(self, source, volume, item, destination, cancel):
        if self.error:
            raise TskCommandError(self.error, self.error.lower())
        destination.write_bytes(self.payload)


def run_recovery(tmp_path, backend, *, cancel=None, target_name="target"):
    source = tmp_path / "case.dd"
    source.write_bytes(b"evidence")
    target = tmp_path / target_name
    summary = FilesystemRecoveryService(backend).recover(
        RecoveryRequest(source, target), cancel=cancel
    )
    return source, target, summary


def test_successful_recovery_is_hashed_atomic_and_reported(tmp_path) -> None:
    _source, target, summary = run_recovery(tmp_path, FakeBackend())
    record = summary.records[0]
    recovered = target / record.recovered_relative_path
    assert record.status is RecoveryStatus.RECOVERED
    assert record.recovered_sha256 == sha256_file(recovered)
    assert recovered.read_bytes() == b"content"
    assert summary.deleted_entries == 3 and summary.media_candidates == 1
    assert summary.source_stat_unchanged
    assert not (target / ".fis-tmp").exists()
    payload = json.loads((target / "reports" / "recovery.json").read_text())
    assert payload["recovery_method"] == "filesystem_metadata"
    assert payload["source_sha256"] == "UNKNOWN"
    assert (target / "reports" / "recovery.csv").is_file()
    assert (target / "logs" / "recovery.log").is_file()


def test_size_mismatch_is_partial(tmp_path) -> None:
    _, _, summary = run_recovery(tmp_path, FakeBackend(payload=b"short"))
    record = summary.records[0]
    assert record.status is RecoveryStatus.PARTIAL
    assert record.error_type == "SIZE_MISMATCH"
    assert record.size_match is False


def test_zero_byte_extraction_is_failed_and_removed(tmp_path) -> None:
    _, target, summary = run_recovery(tmp_path, FakeBackend(payload=b""))
    assert summary.records[0].status is RecoveryStatus.FAILED
    assert summary.records[0].error_type == "EMPTY_OUTPUT"
    assert not list(target.rglob("*.part"))


@pytest.mark.parametrize("error", ["EMPTY_OUTPUT", "RECOVERY_FAILED", "TIMEOUT"])
def test_extraction_failures_continue_and_clean_temporary(tmp_path, error) -> None:
    _, target, summary = run_recovery(tmp_path, FakeBackend(error=error))
    assert summary.records[0].status is RecoveryStatus.FAILED
    assert summary.records[0].error_type == error
    assert not list(target.rglob("*.part"))


def test_reallocated_is_skipped_by_default(tmp_path) -> None:
    backend = FakeBackend(entries=(entry(reallocated=True),))
    _, _, summary = run_recovery(tmp_path, backend)
    assert summary.records[0].status is RecoveryStatus.SKIPPED
    assert summary.records[0].error_type == "REALLOCATED"


def test_precancel_preserves_partial_report(tmp_path) -> None:
    cancel = threading.Event()
    cancel.set()
    _, target, summary = run_recovery(tmp_path, FakeBackend(), cancel=cancel)
    assert summary.cancelled and summary.records == ()
    assert (target / "reports" / "recovery.json").is_file()


@pytest.mark.parametrize("directory", [".fis-tmp", "recovered", "reports", "logs"])
def test_recovery_rejects_symlinked_output_directories(tmp_path, directory):
    source = tmp_path / "case.dd"
    source.write_bytes(b"evidence")
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = target / directory
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(ValueError, match="unsafe recovery target directory"):
        FilesystemRecoveryService(FakeBackend()).recover(
            RecoveryRequest(source, target)
        )
    assert not list(outside.iterdir())


def test_target_free_space_floor_stops_safely(monkeypatch, tmp_path) -> None:
    import forensic_image_scanner.recovery.service as service_module

    usage = shutil.disk_usage(tmp_path)
    monkeypatch.setattr(
        service_module.shutil,
        "disk_usage",
        lambda _path: usage._replace(free=1),
    )
    _, target, summary = run_recovery(tmp_path, FakeBackend())
    assert summary.records[0].error_type == "FAILED_TARGET_FULL"
    assert summary.metadata["target_full"] is True
    assert not list((target / "recovered").rglob("*"))


@pytest.mark.parametrize(
    ("hostile", "expected_suffix"),
    [
        ("../../image.jpg", "image.jpg"),
        (r"C:\\Users\\N\\image.jpg", "image.jpg"),
        ("/foo/bar image.jpg", "bar image.jpg"),
        ("unicodé 名.jpg", "unicodé 名.jpg"),
        ("bad\x00:name?.jpg", "bad_name_.jpg"),
        ("CON.jpg", "_CON.jpg"),
    ],
)
def test_safe_output_names(hostile, expected_suffix) -> None:
    assert _safe_name(hostile).endswith(expected_suffix)
    assert len(_safe_name("x" * 300 + ".jpg")) <= 120


def test_existing_reports_are_not_overwritten(tmp_path) -> None:
    run_recovery(tmp_path, FakeBackend())
    source = tmp_path / "case.dd"
    with pytest.raises(FileExistsError):
        FilesystemRecoveryService(FakeBackend()).recover(
            RecoveryRequest(source, tmp_path / "target")
        )


def test_csv_escapes_formula_but_json_preserves_original(tmp_path) -> None:
    backend = FakeBackend(entries=(entry(name="=SUM.jpg"),))
    _, target, _summary = run_recovery(tmp_path, backend)
    csv_text = (target / "reports" / "recovery.csv").read_text()
    payload = json.loads((target / "reports" / "recovery.json").read_text())
    assert "'=SUM.jpg" in csv_text
    assert payload["records"][0]["original_name"] == "=SUM.jpg"


def test_one_volume_enumeration_failure_does_not_abort_others(tmp_path) -> None:
    class TwoVolumeBackend(FakeBackend):
        def __init__(self):
            super().__init__()
            self.other = RecoveryVolume(
                "volume-02", 4096, 10000, "Ext4", "Ext4", True, 512, "case.dd"
            )

        def inspect(self, source):
            return SourceInspection(source, "GPT", 512, (self.volume, self.other), "TSK test 4.14")

        def enumerate_deleted(self, source, volume):
            if volume.volume_id == "volume-01":
                raise TskCommandError("ENUMERATION_FAILED", "fixture failure")
            return (replace(entry(), volume_id="volume-02", filesystem="Ext4"),), 1

    backend = TwoVolumeBackend()
    _, _, summary = run_recovery(tmp_path, backend)
    assert summary.count(RecoveryStatus.RECOVERED) == 1
    assert summary.metadata["enumeration_errors"][0]["volume_id"] == "volume-01"
