"""PhotoRec carving configuration and normalization without large images."""

import json
import subprocess
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.recovery import (
    DeletedMediaEntry,
    MediaKind,
    RecoveredMedia,
    RecoveryMethod,
    RecoverySessionSummary,
    RecoveryStatus,
    RecoveryVolume,
    SourceInspection,
)
from forensic_image_scanner.recovery.carving.photorec_backend import (
    PhotoRecBackend,
    PhotoRecOutput,
)
from forensic_image_scanner.recovery.carving.photorec_config import (
    IMAGE_GROUPS,
    VIDEO_GROUPS,
    build_plan,
)
from forensic_image_scanner.recovery.carving.photorec_runner import PhotoRecError, PhotoRecRunner
from forensic_image_scanner.recovery.carving.probe import PhotoRecCapability, probe_photorec
from forensic_image_scanner.recovery.carving.service import (
    CarvingRequest,
    PhotoRecCarvingService,
)


def volume(filesystem="NTFS", slot="000:000") -> RecoveryVolume:
    return RecoveryVolume(
        "volume-01",
        2048,
        1000,
        "Data",
        filesystem,
        bool(filesystem),
        512,
        "case.dd",
        partition_slot=slot,
    )


def inspection(filesystem="NTFS") -> SourceInspection:
    return SourceInspection(Path("case.dd"), "GPT", 512, (volume(filesystem),), "TSK fixture")


def test_photorec_probe_available_missing_and_errors() -> None:
    def runner(arguments, **kwargs):
        assert arguments == ["/usr/bin/photorec", "/version"]
        assert kwargs["timeout"] == 5 and not kwargs["check"]
        return subprocess.CompletedProcess(arguments, 0, "PhotoRec 7.2, Utility\n", "")

    capability = probe_photorec(lambda _name: "/usr/bin/photorec", runner)
    assert capability.available and capability.version == "7.2"
    assert not probe_photorec(lambda _name: None, runner).available

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("photorec", 5)

    assert not probe_photorec(lambda _name: "/usr/bin/photorec", timeout).available


def test_format_plan_uses_actual_groups_partition_and_scope() -> None:
    plan = build_plan(inspection(), volume(), frozenset({MediaKind.IMAGE, MediaKind.VIDEO}))
    assert set(plan.format_groups) == {*IMAGE_GROUPS, *VIDEO_GROUPS}
    assert plan.scan_scope == "freespace"
    assert plan.partition_number == 1
    assert plan.command.startswith("partition_gpt,fileopt,everything,disable,")
    assert plan.command.endswith("freespace,1,search")
    whole = build_plan(inspection("exFAT"), volume("exFAT"), frozenset({MediaKind.IMAGE}))
    assert whole.scan_scope == "wholespace"


class FakeCarvingBackend:
    def __init__(self, files, error=None):
        self.files = files
        self.error = error
        self.capability = PhotoRecCapability(True, Path("/usr/bin/photorec"), "7.2")

    def carve(self, source, source_inspection, selected_volume, media, session, cancel):
        if self.error:
            raise PhotoRecError(self.error, self.error.lower())
        root = session / f"raw-{selected_volume.volume_id}.1"
        root.mkdir()
        for name, data in self.files:
            (root / name).write_bytes(data)
        log = session / f"photorec-{selected_volume.volume_id}.log"
        log.write_text(f"source={source}\n")
        return PhotoRecOutput(
            root,
            build_plan(source_inspection, selected_volume, media),
            log,
        )


def run_carving(tmp_path, backend, *, base=None, cancel=None):
    source = tmp_path / "case.dd"
    source.write_bytes(b"forensic image")
    target = tmp_path / "target"
    service = PhotoRecCarvingService(backend)
    result = service.carve(
        CarvingRequest(source, target),
        inspection=SourceInspection(source, "GPT", 512, (volume(),), "TSK fixture"),
        base_summary=base,
        cancel=cancel,
    )
    return source, target, result


def test_carving_normalizes_media_rejects_zero_and_ignores_documents(tmp_path) -> None:
    backend = FakeCarvingBackend(
        [
            ("f001.jpg", b"image"),
            ("f002.MP4", b"video"),
            ("zero.png", b""),
            ("document.pdf", b"not media"),
        ]
    )
    source, target, summary = run_carving(tmp_path, backend)
    assert summary.source_stat_unchanged
    assert len(summary.records) == 3
    assert summary.count(RecoveryStatus.RECOVERED) == 2
    assert summary.count(RecoveryStatus.FAILED) == 1
    for record in summary.records[:2]:
        recovered = target / record.recovered_relative_path
        assert recovered.is_file()
        assert record.recovered_sha256 == sha256_file(recovered)
        assert recovered.resolve().is_relative_to(target.resolve())
    payload = json.loads((target / "reports" / "recovery.json").read_text())
    assert payload["carved"] == 2 and payload["duplicates"] == 0
    assert payload["recovery_method"] == "file_carving"
    assert payload["records"][0]["original_name"] == "UNKNOWN"
    assert payload["records"][0]["metadata_address"] == "UNKNOWN"
    assert not (target / ".fis-tmp").exists()
    assert "<SOURCE>" in (target / "logs" / "photorec-volume-01.log").read_text()
    assert str(source) not in (target / "logs" / "photorec-volume-01.log").read_text()


def filesystem_summary(source, target, data) -> RecoverySessionSummary:
    canonical = target / "recovered" / "filesystem" / "volume-01" / "images" / "photo.jpg"
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(data)
    digest = sha256_file(canonical)
    item = DeletedMediaEntry(
        "volume-01",
        "NTFS",
        "42",
        "photo.jpg",
        "/photo.jpg",
        len(data),
        None,
        None,
        None,
        None,
        ".jpg",
        MediaKind.IMAGE,
        False,
        False,
    )
    record = RecoveredMedia(
        "volume-01_42",
        item,
        2048,
        RecoveryMethod.FILESYSTEM_METADATA,
        RecoveryStatus.RECOVERED,
        len(data),
        True,
        str(canonical.relative_to(target)),
        digest,
    )
    return RecoverySessionSummary(
        source,
        target,
        "TSK fixture",
        datetime.now(UTC),
        datetime.now(UTC),
        1,
        1,
        1,
        1,
        (record,),
        False,
    )


def test_dedup_preserves_filesystem_and_carving_provenance(tmp_path) -> None:
    source = tmp_path / "case.dd"
    source.write_bytes(b"forensic image")
    target = tmp_path / "target"
    base = filesystem_summary(source, target, b"same bytes")
    summary = PhotoRecCarvingService(FakeCarvingBackend([("f001.jpg", b"same bytes")])).carve(
        CarvingRequest(source, target),
        inspection=SourceInspection(source, "GPT", 512, (volume(),), "TSK fixture"),
        base_summary=base,
    )
    assert len(summary.records) == 2
    carved = summary.records[1]
    assert carved.method is RecoveryMethod.FILE_CARVING
    assert carved.status is RecoveryStatus.SKIPPED
    assert carved.duplicate_of == "volume-01_42"
    assert carved.recovered_relative_path == base.records[0].recovered_relative_path
    assert len(list((target / "recovered").rglob("*.jpg"))) == 1
    payload = json.loads((target / "reports" / "recovery.json").read_text())
    assert payload["filesystem_recovered"] == 1
    assert payload["duplicates"] == 1
    assert payload["recovery_method"] == "mixed"
    assert {record["method"] for record in payload["records"]} == {
        "filesystem_metadata",
        "file_carving",
    }


@pytest.mark.parametrize("error", ["TIMEOUT", "CANCELLED", "CARVING_FAILED"])
def test_carving_errors_are_bounded_and_reported(tmp_path, error) -> None:
    cancel = threading.Event()
    _, _target, summary = run_carving(tmp_path, FakeCarvingBackend([], error), cancel=cancel)
    if error == "CANCELLED":
        assert summary.cancelled
    else:
        assert summary.metadata["carving_errors"][0]["error_type"] == error


def test_backend_builds_argument_array_without_shell(tmp_path) -> None:
    calls = []

    class Runner:
        def run(self, arguments, **kwargs):
            calls.append((arguments, kwargs))
            Path(arguments[2] + ".1").mkdir()
            kwargs["log_path"].write_text("ok")
            return 0

    source = tmp_path / "case.dd"
    source.write_bytes(b"image")
    session = tmp_path / "session"
    session.mkdir()
    capability = PhotoRecCapability(True, Path("/usr/bin/photorec"), "7.2")
    PhotoRecBackend(capability, Runner()).carve(
        source,
        SourceInspection(source, "GPT", 512, (volume(),), "TSK fixture"),
        volume(),
        frozenset({MediaKind.IMAGE}),
        session,
        threading.Event(),
    )
    arguments, kwargs = calls[0]
    assert arguments[:5] == [
        "/usr/bin/photorec",
        "/d",
        str(session / "raw-volume-01"),
        "/cmd",
        str(source),
    ]
    assert isinstance(arguments, list) and "shell" not in kwargs
    assert kwargs["cwd"] == session


def test_disk_full_stops_without_finalizing(monkeypatch, tmp_path) -> None:
    import forensic_image_scanner.recovery.carving.service as service_module

    usage = service_module.shutil.disk_usage(tmp_path)
    monkeypatch.setattr(service_module.shutil, "disk_usage", lambda _path: usage._replace(free=1))
    _, target, summary = run_carving(tmp_path, FakeCarvingBackend([("f001.jpg", b"image")]))
    assert summary.metadata["carving_errors"][0]["error_type"] == "FAILED_TARGET_FULL"
    assert not list((target / "recovered").rglob("*"))


def test_photorec_runner_stops_when_target_fills(monkeypatch, tmp_path) -> None:
    import forensic_image_scanner.recovery.carving.photorec_runner as runner_module

    processes = []

    class Process:
        returncode = None

        def __init__(self, arguments, **kwargs):
            self.terminated = False
            processes.append(self)

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    usage = runner_module.shutil.disk_usage(tmp_path)
    checks = iter((usage, usage._replace(free=1)))
    monkeypatch.setattr(runner_module.shutil, "disk_usage", lambda _path: next(checks))
    monkeypatch.setattr(runner_module.subprocess, "Popen", Process)
    with pytest.raises(PhotoRecError) as caught:
        PhotoRecRunner().run(
            ["/usr/bin/photorec", "/cmd", "case.dd", "search"],
            cwd=tmp_path,
            log_path=tmp_path / "photorec.log",
            timeout=1,
            cancel=threading.Event(),
        )
    assert caught.value.code == "FAILED_TARGET_FULL"
    assert len(processes) == 1 and processes[0].terminated


@pytest.mark.parametrize(("cancelled", "code"), [(True, "CANCELLED"), (False, "TIMEOUT")])
def test_photorec_runner_stops_only_owned_child(monkeypatch, tmp_path, cancelled, code) -> None:
    processes = []

    class Process:
        returncode = None

        def __init__(self, arguments, **kwargs):
            self.arguments = arguments
            self.terminated = False
            processes.append(self)

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def kill(self):
            self.returncode = -9

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr(
        "forensic_image_scanner.recovery.carving.photorec_runner.subprocess.Popen", Process
    )
    cancel = threading.Event()
    if cancelled:
        cancel.set()
    with pytest.raises(PhotoRecError) as caught:
        PhotoRecRunner().run(
            ["/usr/bin/photorec", "/cmd", "case.dd", "search"],
            cwd=tmp_path,
            log_path=tmp_path / "photorec.log",
            timeout=0.1,
            cancel=cancel,
        )
    assert caught.value.code == code
    assert len(processes) == 1 and processes[0].terminated


@pytest.mark.photorec
def test_installed_photorec_probe() -> None:
    capability = probe_photorec()
    if not capability.available:
        pytest.skip("system PhotoRec is not installed")
    assert capability.version
