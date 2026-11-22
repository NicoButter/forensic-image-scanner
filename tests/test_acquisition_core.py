"""Acquisition safety and owned-process tests require no real devices."""

import json
import os
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_image_scanner.acquisition import (
    AcquisitionMethod,
    AcquisitionRequest,
    AcquisitionService,
    SafetyResult,
    VerificationStatus,
)
from forensic_image_scanner.acquisition.ddrescue import acquire_raw
from forensic_image_scanner.acquisition.ewf import acquire_ewf
from forensic_image_scanner.acquisition.runner import AcquisitionCancelled, run_owned
from forensic_image_scanner.acquisition.safety import check_acquisition_safety


@pytest.fixture
def safety_env(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.safety as safety

    source = tmp_path / "disk"
    source.touch()
    original_stat = Path.stat

    def fake_stat(path, *args, **kwargs):
        if path == source:
            return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 16))
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(safety.os, "access", lambda *args: True)
    monkeypatch.setattr(safety.shutil, "disk_usage", lambda path: SimpleNamespace(free=10_000))
    monkeypatch.setattr(safety, "_active_swap_ids", lambda: set())
    monkeypatch.setattr(safety, "_physical_disk", lambda identity: True)
    disks = {
        "blockdevices": [
            {
                "path": str(source),
                "type": "disk",
                "maj:min": "8:16",
                "size": 100,
                "model": "source",
                "serial": "serial",
                "children": [{"type": "part", "maj:min": "8:17"}],
            },
            {
                "type": "disk",
                "maj:min": "8:0",
                "size": 100,
                "children": [{"type": "part", "maj:min": "8:1"}],
            },
        ]
    }
    mounts = {"filesystems": [{"target": "/", "maj:min": "8:1", "options": "rw"}]}
    target = {"filesystems": [{"target": "/", "maj:min": "8:1"}]}

    def fake_command(command):
        if command[0] == "lsblk":
            return disks
        if "--target" in command:
            return target
        return mounts

    monkeypatch.setattr(safety, "_run_json", fake_command)
    return SimpleNamespace(
        source=source,
        target=tmp_path / "case",
        disks=disks,
        mounts=mounts,
        target_mount=target,
        module=safety,
        monkeypatch=monkeypatch,
    )


def test_safety_separate_disk_and_ro_mount(safety_env):
    safety_env.mounts["filesystems"].append(
        {"target": "/evidence", "maj:min": "8:17", "options": "ro"}
    )
    result = check_acquisition_safety(safety_env.source, safety_env.target)
    assert result.allowed and any("SOURCE_RO_MOUNTED" in item for item in result.warnings)


def test_btrfs_synthetic_device_resolves_all_members(safety_env):
    safety_env.mounts["filesystems"].append(
        {
            "target": "/evidence",
            "maj:min": "0:42",
            "options": "rw",
            "fstype": "btrfs",
            "uuid": "a5564cc7-62bb-43dc-abf1-fef3f6e524cb",
        }
    )
    safety_env.monkeypatch.setattr(safety_env.module, "_btrfs_devices", lambda _: {"8:17", "8:1"})
    result = check_acquisition_safety(safety_env.source, safety_env.target)
    assert not result.allowed and "SOURCE_RW_MOUNTED" in result.errors


def test_btrfs_unknown_members_block(safety_env):
    safety_env.mounts["filesystems"].append(
        {
            "target": "/evidence",
            "maj:min": "0:42",
            "options": "ro",
            "fstype": "btrfs",
            "uuid": "a5564cc7-62bb-43dc-abf1-fef3f6e524cb",
        }
    )
    safety_env.monkeypatch.setattr(safety_env.module, "_btrfs_devices", lambda _: {"99:99"})
    result = check_acquisition_safety(safety_env.source, safety_env.target)
    assert not result.allowed and "BTRFS_BACKING_UNKNOWN" in result.errors


def test_btrfs_target_sharing_any_source_disk_is_blocked(safety_env):
    safety_env.target_mount["filesystems"][0].update(
        {
            "maj:min": "0:42",
            "fstype": "btrfs",
            "uuid": "a5564cc7-62bb-43dc-abf1-fef3f6e524cb",
        }
    )
    safety_env.monkeypatch.setattr(safety_env.module, "_btrfs_devices", lambda _: {"8:17", "8:1"})
    result = check_acquisition_safety(safety_env.source, safety_env.target)
    assert not result.allowed and "SOURCE_TARGET_SAME_DISK" in result.errors


def test_unresolved_non_pseudo_mount_blocks(safety_env):
    safety_env.mounts["filesystems"].append(
        {
            "target": "/pool",
            "maj:min": "0:99",
            "options": "rw",
            "fstype": "zfs",
            "source": "pool/data",
        }
    )
    result = check_acquisition_safety(safety_env.source, safety_env.target)
    assert not result.allowed and "MOUNT_BACKING_UNKNOWN" in result.errors


@pytest.mark.parametrize(
    "case,code",
    [
        ("root", "SOURCE_IS_SYSTEM_DISK"),
        ("same", "SOURCE_TARGET_SAME_DISK"),
        ("rw", "SOURCE_RW_MOUNTED"),
        ("unknown", "TARGET_BACKING_UNKNOWN"),
        ("partition", "SOURCE_NOT_WHOLE_PHYSICAL_DISK"),
        ("unreadable", "SOURCE_NOT_READABLE"),
        ("space", "INSUFFICIENT_TARGET_SPACE"),
        ("swap", "SOURCE_CONTAINS_ACTIVE_SWAP"),
        ("unknown_root", "ROOT_BACKING_UNKNOWN"),
        ("virtual", "SOURCE_NOT_WHOLE_PHYSICAL_DISK"),
        ("system_ro", "SOURCE_CONTAINS_SYSTEM_FILESYSTEM"),
    ],
)
def test_safety_blocks_dangerous_or_unknown(safety_env, case, code):
    if case == "root":
        safety_env.mounts["filesystems"][0]["maj:min"] = "8:17"
    elif case == "same":
        safety_env.target_mount["filesystems"][0]["maj:min"] = "8:17"
    elif case == "rw":
        safety_env.mounts["filesystems"].append(
            {"target": "/evidence", "maj:min": "8:17", "options": "rw"}
        )
    elif case == "unknown":
        safety_env.target_mount["filesystems"][0]["maj:min"] = "99:99"
    elif case == "partition":
        safety_env.disks["blockdevices"][0]["type"] = "part"
    elif case == "unreadable":
        safety_env.monkeypatch.setattr(safety_env.module.os, "access", lambda *args: False)
    elif case == "space":
        safety_env.monkeypatch.setattr(
            safety_env.module.shutil, "disk_usage", lambda _: SimpleNamespace(free=1)
        )
    elif case == "swap":
        safety_env.monkeypatch.setattr(safety_env.module, "_active_swap_ids", lambda: {"8:17"})
    elif case == "unknown_root":
        safety_env.mounts["filesystems"][0]["maj:min"] = "99:99"
    elif case == "virtual":
        safety_env.monkeypatch.setattr(
            safety_env.module, "_physical_disk", lambda identity: identity != "8:16"
        )
    elif case == "system_ro":
        safety_env.mounts["filesystems"].append(
            {"target": "/boot/efi", "maj:min": "8:17", "options": "ro"}
        )
    result = check_acquisition_safety(safety_env.source, safety_env.target)
    assert not result.allowed and code in result.errors


def test_regular_file_is_not_a_physical_device(tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"not a block device")
    result = check_acquisition_safety(source, tmp_path / "target")
    assert not result.allowed and "SOURCE_NOT_BLOCK_DEVICE" in result.errors


def test_ewf_command_and_verification_failure(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.ewf as ewf

    calls = []
    monkeypatch.setattr(ewf, "tool_help", lambda _: "-u: unattended\n-t: target\n-d: sha256\n")

    def run(args, log, cancel):
        calls.append(args)
        if len(calls) == 1:
            (tmp_path / "source.E01").write_bytes(b"EWF")
            return 0
        return 1

    monkeypatch.setattr(ewf, "run_owned", run)
    result = acquire_ewf(
        Path("/dev/sdb"),
        tmp_path,
        Path("/bin/ewfacquire"),
        Path("/bin/ewfverify"),
        threading.Event(),
    )
    assert calls[0] == [
        "/bin/ewfacquire",
        "-u",
        "-t",
        str(tmp_path / "source"),
        "-d",
        "sha256",
        "/dev/sdb",
    ]
    assert calls[1] == ["/bin/ewfverify", str(tmp_path / "source.E01")]
    assert not result.verification_succeeded and result.errors == ("EWF_VERIFICATION_FAILED",)


def test_ewf_verification_success(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.ewf as ewf

    calls = []
    monkeypatch.setattr(ewf, "tool_help", lambda _: "-u unattended\n-t target\n")

    def run(args, log, cancel):
        calls.append(args)
        if len(calls) == 1:
            (tmp_path / "source.E01").write_bytes(b"EWF")
        return 0

    monkeypatch.setattr(ewf, "run_owned", run)
    result = acquire_ewf(
        Path("/dev/sdb"),
        tmp_path,
        Path("/bin/ewfacquire"),
        Path("/bin/ewfverify"),
        threading.Event(),
    )
    assert result.verification_succeeded and len(calls) == 2


def test_ewf_cancel_never_runs_verification(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.ewf as ewf

    calls = []
    monkeypatch.setattr(ewf, "tool_help", lambda _: "-u: unattended\n-t: target\n")

    def run(args, log, cancel):
        calls.append(args)
        raise AcquisitionCancelled("cancelled")

    monkeypatch.setattr(ewf, "run_owned", run)
    with pytest.raises(AcquisitionCancelled):
        acquire_ewf(
            Path("/dev/sdb"),
            tmp_path,
            Path("/bin/ewfacquire"),
            Path("/bin/ewfverify"),
            threading.Event(),
        )
    assert len(calls) == 1


def test_ewf_rejects_existing_output(tmp_path):
    (tmp_path / "source.E01").write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        acquire_ewf(
            Path("/dev/sdb"),
            tmp_path,
            Path("/bin/ewfacquire"),
            Path("/bin/ewfverify"),
            threading.Event(),
        )
    assert (tmp_path / "source.E01").read_bytes() == b"existing"


def test_raw_mapfile_resume_and_cancellation(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.ddrescue as rescue

    calls = []
    monkeypatch.setattr(rescue, "tool_help", lambda _: "-n, --no-scrape skip scraping")

    def run(args, log, cancel):
        calls.append(args)
        (tmp_path / "source.raw").write_bytes(b"raw")
        (tmp_path / "source.map").write_text("map")
        if len(calls) == 1:
            raise AcquisitionCancelled("cancelled")
        return 0

    monkeypatch.setattr(rescue, "run_owned", run)
    with pytest.raises(AcquisitionCancelled):
        acquire_raw(Path("/dev/sdb"), tmp_path, Path("/bin/ddrescue"), threading.Event())
    image, mapfile, errors = acquire_raw(
        Path("/dev/sdb"), tmp_path, Path("/bin/ddrescue"), threading.Event(), resume=True
    )
    assert not errors and image.exists() and mapfile.exists()
    assert calls[0] == calls[1] == ["/bin/ddrescue", "-n", "/dev/sdb", str(image), str(mapfile)]
    with pytest.raises(FileExistsError):
        acquire_raw(Path("/dev/sdb"), tmp_path, Path("/bin/ddrescue"), threading.Event())


def test_service_writes_record_and_rejects_mismatched_resume(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.service as service

    source = tmp_path / "source"
    source.touch()
    safety = SafetyResult(
        True,
        source_device=str(source),
        source_identity="8:16",
        target_disks=("8:0",),
        serial="SERIAL",
        capacity_bytes=10,
    )
    monkeypatch.setattr(service, "check_acquisition_safety", lambda *args: safety)
    monkeypatch.setattr(
        service,
        "probe_acquisition_tools",
        lambda: SimpleNamespace(raw_available=True, ddrescue=Path("/bin/ddrescue")),
    )
    monkeypatch.setattr(service, "tool_version", lambda _: "test")

    def acquire(source, directory, binary, cancel, *, resume, expected_size):
        image, mapfile = directory / "source.raw", directory / "source.map"
        image.write_bytes(b"x" * 10)
        mapfile.write_text("0x0 0xa +\n")
        return image, mapfile, ()

    monkeypatch.setattr(service, "acquire_raw", acquire)
    request = AcquisitionRequest(source, tmp_path / "case", AcquisitionMethod.RAW)
    result = AcquisitionService().acquire(request)
    assert result.completed and result.verification is VerificationStatus.NOT_PERFORMED
    report = json.loads((request.target / "acquisition/acquisition.json").read_text())
    assert report["source_identity"] == "8:16" and report["mapfile"].endswith("source.map")
    resumed = AcquisitionService().acquire(
        AcquisitionRequest(source, request.target, AcquisitionMethod.RAW, resume=True)
    )
    assert resumed.completed and resumed.mapfile == result.mapfile
    changed = SafetyResult(
        True, source_identity="8:32", target_disks=("8:0",), serial="SERIAL", capacity_bytes=10
    )
    monkeypatch.setattr(service, "check_acquisition_safety", lambda *args: changed)
    with pytest.raises(ValueError, match="RESUME_SOURCE_IDENTITY_MISMATCH"):
        AcquisitionService().acquire(
            AcquisitionRequest(source, request.target, AcquisitionMethod.RAW, resume=True)
        )


def test_service_cancel_preserves_state_and_report(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.service as service

    source = tmp_path / "source"
    source.touch()
    safety = SafetyResult(
        True, source_identity="8:16", target_disks=("8:0",), serial="SERIAL", capacity_bytes=10
    )
    monkeypatch.setattr(service, "check_acquisition_safety", lambda *args: safety)
    monkeypatch.setattr(
        service,
        "probe_acquisition_tools",
        lambda: SimpleNamespace(raw_available=True, ddrescue=Path("/bin/ddrescue")),
    )
    monkeypatch.setattr(service, "tool_version", lambda _: "test")

    def cancel_backend(source, directory, binary, cancel, *, resume, expected_size):
        (directory / "source.raw").write_bytes(b"partial")
        (directory / "source.map").write_text("0x0 0x7 +\n0x7 0x3 ?\n")
        raise AcquisitionCancelled("cancelled")

    monkeypatch.setattr(service, "acquire_raw", cancel_backend)
    request = AcquisitionRequest(source, tmp_path / "case", AcquisitionMethod.RAW)
    result = AcquisitionService().acquire(request)
    assert result.cancelled and not result.completed
    assert result.bytes_acquired == 7
    assert "DDRESCUE_UNRECOVERED_BYTES: 3" in result.errors
    assert (request.target / "acquisition/source.raw").read_bytes() == b"partial"
    report = json.loads((request.target / "acquisition/acquisition.json").read_text())
    assert report["cancelled"] and report["verification"] == "not_performed"


@pytest.mark.parametrize("success", [True, False])
def test_service_ewf_records_verification(tmp_path, monkeypatch, success):
    import forensic_image_scanner.acquisition.service as service

    source = tmp_path / "source"
    source.touch()
    safety = SafetyResult(True, source_identity="8:16", target_disks=("8:0",), capacity_bytes=10)
    monkeypatch.setattr(service, "check_acquisition_safety", lambda *args: safety)
    monkeypatch.setattr(
        service,
        "probe_acquisition_tools",
        lambda: SimpleNamespace(
            e01_available=True, ewfacquire=Path("/bin/acquire"), ewfverify=Path("/bin/verify")
        ),
    )
    monkeypatch.setattr(service, "tool_version", lambda _: "test")
    monkeypatch.setattr(
        service,
        "acquire_ewf",
        lambda *args: SimpleNamespace(
            verification_succeeded=success, errors=() if success else ("EWF_VERIFICATION_FAILED",)
        ),
    )
    request = AcquisitionRequest(source, tmp_path / "case", AcquisitionMethod.E01)
    result = AcquisitionService().acquire(request)
    assert result.completed is success
    assert result.verification is (
        VerificationStatus.VERIFIED if success else VerificationStatus.FAILED
    )
    assert (
        json.loads((request.target / "acquisition/acquisition.json").read_text())["completed"]
        is success
    )


def test_missing_tool_and_blocked_safety_do_not_create_output(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.service as service

    source = tmp_path / "source"
    source.touch()
    request = AcquisitionRequest(source, tmp_path / "case", AcquisitionMethod.RAW)
    monkeypatch.setattr(
        service,
        "check_acquisition_safety",
        lambda *args: SafetyResult(False, errors=("SOURCE_TARGET_SAME_DISK",)),
    )
    with pytest.raises(ValueError, match="SOURCE_TARGET_SAME_DISK"):
        AcquisitionService().acquire(request)
    assert not request.target.exists()
    monkeypatch.setattr(
        service,
        "check_acquisition_safety",
        lambda *args: SafetyResult(
            True, source_identity="8:16", target_disks=("8:0",), capacity_bytes=10
        ),
    )
    monkeypatch.setattr(
        service, "probe_acquisition_tools", lambda: SimpleNamespace(raw_available=False)
    )
    with pytest.raises(RuntimeError, match="DDRESCUE_NOT_AVAILABLE"):
        AcquisitionService().acquire(request)
    assert not request.target.exists()


def test_rescue_rejects_hardlinked_output(tmp_path):
    image, mapfile = tmp_path / "source.raw", tmp_path / "source.map"
    image.write_bytes(b"raw")
    mapfile.write_text("map")
    os.link(image, tmp_path / "other")
    with pytest.raises(ValueError, match="RESUME_REQUIRES"):
        acquire_raw(
            Path("/dev/sdb"), tmp_path, Path("/bin/ddrescue"), threading.Event(), resume=True
        )


def test_rescue_rejects_dangling_output_symlink(tmp_path):
    (tmp_path / "source.raw").symlink_to(tmp_path / "missing")
    with pytest.raises(FileExistsError):
        acquire_raw(Path("/dev/sdb"), tmp_path, Path("/bin/ddrescue"), threading.Event())


def test_map_records_unrecovered_bytes(tmp_path):
    from forensic_image_scanner.acquisition.ddrescue import _map_errors

    mapfile = tmp_path / "source.map"
    mapfile.write_text("# map\n0x00000000  +  1\n0x0 0x8 +\n0x8 0x2 -\n")
    assert _map_errors(mapfile, 10) == [
        "DDRESCUE_UNRECOVERED_BYTES: 2",
        "DDRESCUE_BAD_SECTOR_BYTES: 2",
    ]


def test_runner_terminates_only_owned_child(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.runner as runner

    processes = []

    class Process:
        returncode = None

        def __init__(self, args, **kwargs):
            assert isinstance(args, list) and kwargs["shell"] is False
            self.terminated = False
            processes.append(self)

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr(runner.subprocess, "Popen", Process)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(AcquisitionCancelled):
        run_owned(["tool", "path with spaces"], tmp_path / "log", cancel)
    assert len(processes) == 1 and processes[0].terminated
