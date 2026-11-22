"""Deterministic lsblk JSON parsing without access to real disks."""

import json
import tempfile
from pathlib import Path
from subprocess import CompletedProcess

from forensic_image_scanner.workflow.device_discovery import discover_physical_devices


def fixture_runner(payload):
    def run(command, **kwargs):
        assert command[:3] == ["lsblk", "--json", "--bytes"]
        assert kwargs == {
            "capture_output": True,
            "text": True,
            "check": True,
            "timeout": 5,
            "shell": False,
            "cwd": Path(tempfile.gettempdir()),
        }
        return CompletedProcess(command, 0, json.dumps(payload), "")

    return run


def test_linux_device_types_mounts_and_missing_fields() -> None:
    payload = {
        "blockdevices": [
            {
                "name": "sda",
                "path": "/dev/sda",
                "type": "disk",
                "size": 1000,
                "model": "HDD One",
                "serial": "A",
                "tran": "sata",
                "rota": 1,
                "rm": 0,
                "children": [{"type": "part", "fstype": "ext4", "mountpoints": ["/evidence"]}],
            },
            {
                "name": "sdb",
                "path": "/dev/sdb",
                "type": "disk",
                "size": "2000",
                "model": "SSD Two",
                "tran": "sata",
                "rota": 0,
                "rm": 1,
                "mountpoints": [None],
            },
            {
                "name": "nvme0n1",
                "path": "/dev/nvme0n1",
                "type": "disk",
                "model": "NVMe Three",
                "tran": "nvme",
                "rota": 0,
                "rm": 0,
            },
            {"name": "mystery", "type": "disk"},
            {"name": "loop0", "type": "loop", "size": 5},
            {"name": "zram0", "path": "/dev/zram0", "type": "disk", "size": 5},
        ]
    }
    result = discover_physical_devices(fixture_runner(payload))
    assert result.warning is None
    assert [device.metadata["device_type"] for device in result.devices] == [
        "hdd",
        "sata_ssd",
        "nvme_ssd",
        "unknown",
    ]
    assert result.devices[0].metadata["mountpoints"] == ("/evidence",)
    assert result.devices[0].metadata["filesystems"] == ("ext4",)
    assert result.devices[0].display_name == "HDD One"
    assert result.devices[0].metadata["transport"] == "sata"
    assert result.devices[1].metadata["removable"] is True
    assert result.devices[3].metadata["capacity_bytes"] is None


def test_discovery_failure_is_nonfatal() -> None:
    def failing_runner(*_args, **_kwargs):
        raise FileNotFoundError("lsblk")

    result = discover_physical_devices(failing_runner)
    assert result.devices == ()
    assert "unavailable" in result.warning.lower()
