"""TSK probing and parser behavior without requiring TSK or disk images."""

import subprocess
import threading
from pathlib import Path

import pytest

from forensic_image_scanner.recovery import MediaKind
from forensic_image_scanner.recovery.media_types import candidate_media_kind
from forensic_image_scanner.recovery.tsk.backend import TskBackend
from forensic_image_scanner.recovery.tsk.parsers import parse_fls, parse_fsstat, parse_mmls
from forensic_image_scanner.recovery.tsk.probe import REQUIRED_TOOLS, TskCapability, probe_tsk
from forensic_image_scanner.recovery.tsk.runner import CommandResult, TskCommandError, TskRunner


def test_probe_all_tools_and_version() -> None:
    paths = {name: f"/usr/bin/{name}" for name in (*REQUIRED_TOOLS, "img_stat")}

    def runner(arguments, **kwargs):
        assert arguments == ["/usr/bin/fls", "-V"]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 5, "check": False}
        return subprocess.CompletedProcess(arguments, 0, "The Sleuth Kit ver 4.14.0\n", "")

    result = probe_tsk(paths.get, runner)
    assert result.available
    assert result.version == "The Sleuth Kit ver 4.14.0"
    assert result.missing_tools == ()


@pytest.mark.parametrize("missing", [("icat",), ("mmls", "fls")])
def test_probe_reports_missing_tools_without_running_version(missing) -> None:
    def which(name):
        return None if name in missing else f"/usr/bin/{name}"

    result = probe_tsk(which, lambda *_args, **_kwargs: pytest.fail("must not run"))
    assert not result.available
    assert result.missing_tools == missing


def test_probe_error_and_timeout_are_unavailable() -> None:
    def which(name):
        return f"/usr/bin/{name}"

    for error in (OSError("no exec"), subprocess.TimeoutExpired("fls", 5)):

        def runner(*_args, error=error, **_kwargs):
            raise error

        assert not probe_tsk(which, runner).available


def test_parse_mmls_gpt_filters_meta_and_unallocated() -> None:
    output = """GUID Partition Table (EFI)
Units are in 4096-byte sectors
000: Meta 0000000000 0000000000 0000000001 Safety Table
001: 000:000 0000000001 0000002047 0000002047 EFI System Partition
002: 000:001 0000002048 0001002047 0001000000 Datos ñ
003: ----- 0001002048 0001004095 0000002048 Unallocated
malformed row
"""
    system, sector_size, rows = parse_mmls(output)
    assert system == "GPT"
    assert sector_size == 4096
    assert [row["description"] for row in rows] == ["EFI System Partition", "Datos ñ"]
    assert rows[1]["start_sector"] == 2048


def test_parse_mmls_mbr_and_fsstat() -> None:
    output = "DOS Partition Table\n000: 000:000 0000000063 0000000999 0000000937 NTFS\n"
    system, sector_size, rows = parse_mmls(output)
    assert (system, sector_size, len(rows)) == ("MBR", 512, 1)
    assert parse_fsstat("File System Type: NTFS\nVolume Name: CASE Ñ\n") == (
        "NTFS",
        "CASE Ñ",
    )
    assert parse_fsstat("unrecognized") == (None, None)


def test_parse_fls_preserves_paths_metadata_and_flags() -> None:
    output = (
        "r/r *\t1304-128-1\t/Users/A Name/IMG 001.JPG\t1700000000\t0\t-\t0\t42\t501\t20\n"
        "r/r * 99 (realloc): $OrphanFiles/vidéo.MP4 (realloc)\t0\t0\t0\t0\t0\t0\t0\n"
        "d/d * 11: deleted directory\n"
        "r/r * 12: report.pdf\t0\t0\t0\t0\t12\t0\t0\n"
    )
    entries = parse_fls(output, "volume-01", "NTFS")
    assert len(entries) == 2
    assert entries[0].metadata_address == "1304-128-1"
    assert entries[0].original_path == "/Users/A Name/IMG 001.JPG"
    assert entries[0].media_kind is MediaKind.IMAGE
    assert entries[0].size_bytes == 42
    assert entries[1].media_kind is MediaKind.VIDEO
    assert entries[1].reallocated and entries[1].orphan
    assert entries[1].original_path is None
    assert entries[1].size_bytes == 0


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("IMG001.JPG", MediaKind.IMAGE),
        ("photo.HEIC", MediaKind.IMAGE),
        ("DSC0001.NEF", MediaKind.IMAGE),
        ("clip.MP4", MediaKind.VIDEO),
        ("movie.mkv", MediaKind.VIDEO),
        ("report.pdf", None),
        ("archive.zip", None),
    ],
)
def test_media_extension_policy(name, kind) -> None:
    assert candidate_media_kind(name) is kind


class FixtureRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.commands = []

    def run_text(self, arguments, *, timeout):
        self.commands.append((tuple(arguments), timeout))
        return self.responses.pop(0)

    def extract(self, arguments, destination, *, timeout, cancel):
        self.commands.append((tuple(arguments), timeout))
        destination.write_bytes(b"recovered")
        return CommandResult(tuple(arguments), "", "", 0)


def capability() -> TskCapability:
    tools = {
        name: Path(f"/usr/bin/{name}") for name in (*REQUIRED_TOOLS, "img_stat", "tsk_recover")
    }
    return TskCapability(True, "TSK fixture", tools, ())


def test_backend_uses_offsets_and_argument_arrays(tmp_path) -> None:
    source = tmp_path / "case.dd"
    source.write_bytes(b"image")
    runner = FixtureRunner(
        [
            CommandResult(
                (),
                "GUID Partition Table (EFI)\n"
                "001: 000:000 0000002048 0000004095 0000002048 Basic data\n",
                "",
                0,
            ),
            CommandResult((), "File System Type: NTFS\n", "", 0),
            CommandResult((), "r/r *\t42\t/deleted.JPG\t0\t0\t0\t0\t9\t0\t0\n", "", 0),
        ]
    )
    backend = TskBackend(capability(), runner)
    inspection = backend.inspect(source)
    volume = inspection.supported_volumes[0]
    entries, deleted_count = backend.enumerate_deleted(source, volume)
    destination = tmp_path / "out.part"
    backend.extract(source, volume, entries[0], destination, threading.Event())

    assert volume.start_sector == 2048 and volume.filesystem == "NTFS"
    assert deleted_count == 1
    assert runner.commands[1][0] == ("/usr/bin/fsstat", "-o", "2048", str(source))
    assert runner.commands[2][0][:6] == (
        "/usr/bin/fls",
        "-r",
        "-d",
        "-p",
        "-l",
        "-o",
    )
    assert runner.commands[3][0] == (
        "/usr/bin/icat",
        "-r",
        "-o",
        "2048",
        str(source),
        "42",
    )


def test_backend_falls_back_to_single_filesystem_image(tmp_path) -> None:
    source = tmp_path / "partition.img"
    source.write_bytes(b"image")
    runner = FixtureRunner(
        [
            CommandResult((), "", "no volume system", 1),
            CommandResult((), "File System Type: Ext4\nVolume Name: evidence\n", "", 0),
        ]
    )
    inspection = TskBackend(capability(), runner).inspect(source)
    assert inspection.volume_system == "SINGLE_FILESYSTEM_IMAGE"
    assert inspection.volumes[0].start_sector == 0
    assert inspection.volumes[0].filesystem == "Ext4"
    assert runner.commands[1][0] == ("/usr/bin/fsstat", str(source))


def test_backend_reports_missing_ewf_support(tmp_path) -> None:
    source = tmp_path / "case.E01"
    source.write_bytes(b"image")
    runner = FixtureRunner(
        [
            CommandResult((), "", "unsupported image type", 1),
            CommandResult((), "", "unsupported image type", 1),
        ]
    )
    with pytest.raises(TskCommandError, match="EWF support unavailable"):
        TskBackend(capability(), runner).inspect(source)


@pytest.mark.parametrize(("cancelled", "code"), [(True, "CANCELLED"), (False, "TIMEOUT")])
def test_binary_runner_terminates_only_its_child(monkeypatch, tmp_path, cancelled, code) -> None:
    processes = []

    class Process:
        returncode = None

        def __init__(self, arguments, *, stdout, stderr, text):
            self.arguments = arguments
            self.terminated = False
            self.killed = False
            processes.append(self)

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def kill(self):
            self.killed = True
            self.returncode = -9

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr("forensic_image_scanner.recovery.tsk.runner.subprocess.Popen", Process)
    cancel = threading.Event()
    if cancelled:
        cancel.set()
    with pytest.raises(TskCommandError) as caught:
        TskRunner().extract(
            ["/usr/bin/icat", "image.dd", "42"],
            tmp_path / "output.part",
            timeout=0.1,
            cancel=cancel,
        )
    assert caught.value.code == code
    assert len(processes) == 1 and processes[0].terminated


@pytest.mark.tsk
def test_installed_tsk_probe() -> None:
    capability = probe_tsk()
    if not capability.available:
        pytest.skip("system TSK commands are not installed")
    assert capability.version
    assert all(capability.tools[name] is not None for name in REQUIRED_TOOLS)
