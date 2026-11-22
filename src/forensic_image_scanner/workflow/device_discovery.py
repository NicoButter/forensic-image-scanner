"""Linux block-device discovery using read-only lsblk metadata."""

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forensic_image_scanner.workflow.models import SourceDescriptor, SourceKind

LSBLK_COLUMNS = "NAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA,RM,FSTYPE,MOUNTPOINTS"


@dataclass(frozen=True, slots=True)
class DeviceDiscoveryResult:
    devices: tuple[SourceDescriptor, ...]
    warning: str | None = None


def discover_physical_devices(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> DeviceDiscoveryResult:
    if not sys.platform.startswith("linux"):
        return DeviceDiscoveryResult((), "Physical-device discovery is available on Linux hosts.")
    try:
        completed = runner(
            ["lsblk", "--json", "--bytes", "--output", LSBLK_COLUMNS],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
            shell=False,
            cwd=Path(tempfile.gettempdir()),
        )
        payload = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError) as exc:
        return DeviceDiscoveryResult((), f"Device discovery unavailable: {type(exc).__name__}")
    roots = payload.get("blockdevices") if isinstance(payload, dict) else None
    if not isinstance(roots, list):
        return DeviceDiscoveryResult((), "Device discovery returned an invalid response.")
    devices = tuple(
        _descriptor(item) for item in roots if isinstance(item, dict) and _is_candidate_disk(item)
    )
    return DeviceDiscoveryResult(devices)


def _is_candidate_disk(item: dict[str, Any]) -> bool:
    if item.get("type") != "disk":
        return False
    name = str(item.get("name") or "").casefold()
    return not name.startswith(("loop", "ram", "zram"))


def _descriptor(item: dict[str, Any]) -> SourceDescriptor:
    path = str(item.get("path") or f"/dev/{item.get('name', 'unknown')}")
    transport = _text(item.get("tran"))
    rotational = _boolean(item.get("rota"))
    removable = _boolean(item.get("rm"))
    mountpoints, filesystems = _descendant_metadata(item)
    device_type = _device_type(transport, rotational)
    model = _display_text(item.get("model")) or Path(path).name
    metadata: dict[str, object] = {
        "model": model,
        "serial": _display_text(item.get("serial")),
        "capacity_bytes": _integer(item.get("size")),
        "transport": transport or "unknown",
        "rotational": rotational,
        "removable": removable,
        "filesystems": filesystems,
        "mountpoints": mountpoints,
        "device_type": device_type,
        "raw_readable": os.access(path, os.R_OK),
    }
    return SourceDescriptor(
        SourceKind.PHYSICAL_DEVICE, path, model, Path(path).exists(), True, metadata
    )


def _device_type(transport: str | None, rotational: bool | None) -> str:
    if rotational is True:
        return "hdd"
    if rotational is False and transport == "nvme":
        return "nvme_ssd"
    if rotational is False and transport == "sata":
        return "sata_ssd"
    return "unknown"


def _descendant_metadata(item: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    mountpoints: set[str] = set()
    filesystems: set[str] = set()
    stack = [item]
    while stack:
        current = stack.pop()
        values = current.get("mountpoints")
        if isinstance(values, list):
            mountpoints.update(str(value) for value in values if value)
        elif current.get("mountpoint"):
            mountpoints.add(str(current["mountpoint"]))
        if current.get("fstype"):
            filesystems.add(str(current["fstype"]))
        children = current.get("children")
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, dict))
    return tuple(sorted(mountpoints)), tuple(sorted(filesystems))


def _text(value: object) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text.casefold() if text else None


def _display_text(value: object) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _boolean(value: object) -> bool | None:
    if value in (True, 1, "1"):
        return True
    if value in (False, 0, "0"):
        return False
    return None


def _integer(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
