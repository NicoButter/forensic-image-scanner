"""Fail-closed Linux block-device and target separation checks."""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from forensic_image_scanner.acquisition.models import SafetyResult

_PSEUDO_FILESYSTEMS = frozenset(
    {
        "autofs",
        "binfmt_misc",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "efivarfs",
        "fusectl",
        "hugetlbfs",
        "mqueue",
        "nsfs",
        "proc",
        "pstore",
        "ramfs",
        "rpc_pipefs",
        "securityfs",
        "selinuxfs",
        "sysfs",
        "tmpfs",
        "tracefs",
    }
)


def _run_json(arguments: list[str]) -> dict:
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
        shell=False,
        cwd=Path("/"),
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("invalid system metadata")
    return value


def _existing_parent(path: Path) -> Path:
    while not path.exists() and path != path.parent:
        path = path.parent
    return path


def _physical_disk(identity: str) -> bool:
    """Reject virtual block devices and any disk missing from sysfs."""
    path = Path("/sys/dev/block") / identity
    resolved = path.resolve(strict=True)
    return not resolved.is_relative_to(Path("/sys/devices/virtual"))


def _flatten(nodes, parents=()):
    for node in nodes:
        if not isinstance(node, dict) or not node.get("maj:min"):
            raise ValueError("incomplete block device metadata")
        disks = parents + ((str(node["maj:min"]),) if node.get("type") == "disk" else ())
        yield node, disks
        children = node.get("children", [])
        if not isinstance(children, list):
            raise ValueError("invalid block device tree")
        yield from _flatten(children, disks)


def _active_swap_ids() -> set[str]:
    """Map active swap devices/files to their block identities."""
    identities = set()
    with Path("/proc/swaps").open(encoding="utf-8") as swap_file:
        next(swap_file)
        for line in swap_file:
            name = line.split()[0]
            name = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), name)
            item = os.stat(name)
            device = item.st_rdev if stat.S_ISBLK(item.st_mode) else item.st_dev
            identities.add(f"{os.major(device)}:{os.minor(device)}")
    return identities


def _btrfs_devices(uuid: str) -> set[str]:
    """Resolve every member device, including multi-device Btrfs filesystems."""
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid):
        raise ValueError("BTRFS_BACKING_UNKNOWN")
    directory = Path("/sys/fs/btrfs") / uuid / "devices"
    devices = {
        entry.joinpath("dev").read_text(encoding="ascii").strip() for entry in directory.iterdir()
    }
    if not devices or any(not re.fullmatch(r"\d+:\d+", device) for device in devices):
        raise ValueError("BTRFS_BACKING_UNKNOWN")
    return devices


def _mount_disks(mount: dict, ancestry: dict[str, set[str]]) -> set[str]:
    device = str(mount.get("maj:min"))
    if ancestry.get(device):
        return ancestry[device]
    if mount.get("fstype") == "btrfs":
        members = _btrfs_devices(str(mount.get("uuid") or ""))
        if any(not ancestry.get(member) for member in members):
            raise ValueError("BTRFS_BACKING_UNKNOWN")
        return set().union(*(ancestry[member] for member in members))
    source = str(mount.get("source") or "").split("[", 1)[0]
    if source.startswith("/dev/"):
        info = os.stat(source)
        if not stat.S_ISBLK(info.st_mode):
            raise ValueError("MOUNT_BACKING_UNKNOWN")
        device = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        if not ancestry.get(device):
            raise ValueError("MOUNT_BACKING_UNKNOWN")
        return ancestry[device]
    filesystem = str(mount.get("fstype") or "")
    if filesystem and filesystem not in _PSEUDO_FILESYSTEMS:
        raise ValueError("MOUNT_BACKING_UNKNOWN")
    return set()


def check_acquisition_safety(
    source: Path, target: Path, required_space: int | None = None
) -> SafetyResult:
    """Inspect device topology and mounts. Any unresolved relationship blocks acquisition."""
    errors: list[str] = []
    warnings: list[str] = ["HARDWARE_WRITE_BLOCKER_NOT_VERIFIED"]
    try:
        if not sys.platform.startswith("linux"):
            raise ValueError("LINUX_REQUIRED")
        source = source.expanduser().resolve(strict=True)
        if source.name.casefold().startswith(("loop", "ram", "zram")):
            raise ValueError("SOURCE_NOT_WHOLE_PHYSICAL_DISK")
        info = source.stat()
        if not stat.S_ISBLK(info.st_mode):
            raise ValueError("SOURCE_NOT_BLOCK_DEVICE")
        if not os.access(source, os.R_OK):
            raise ValueError("SOURCE_NOT_READABLE")
        identity = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        if not _physical_disk(identity):
            raise ValueError("SOURCE_NOT_WHOLE_PHYSICAL_DISK")
        target = target.expanduser().resolve()
        parent = _existing_parent(target)
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            raise ValueError("TARGET_NOT_WRITABLE")
        tree = _run_json(
            [
                "lsblk",
                "--json",
                "--bytes",
                "--paths",
                "--tree",
                "--output",
                "PATH,TYPE,MAJ:MIN,SIZE,MODEL,SERIAL,TRAN",
            ]
        )
        roots = tree.get("blockdevices")
        if not isinstance(roots, list):
            raise ValueError("BLOCK_TOPOLOGY_UNKNOWN")
        entries = list(_flatten(roots))
        matches = [(node, disks) for node, disks in entries if str(node["maj:min"]) == identity]
        if len(matches) != 1 or matches[0][0].get("type") != "disk":
            raise ValueError("SOURCE_NOT_WHOLE_PHYSICAL_DISK")
        disk = matches[0][0]
        if len(matches[0][1]) != 1 or not disk.get("size"):
            raise ValueError("SOURCE_IDENTITY_UNKNOWN")
        ancestry: dict[str, set[str]] = {}
        for node, disks in entries:
            ancestry.setdefault(str(node["maj:min"]), set()).update(disks)
        mounts = _run_json(
            ["findmnt", "--json", "--list", "--output", "TARGET,MAJ:MIN,OPTIONS,SOURCE,FSTYPE,UUID"]
        ).get("filesystems")
        if not isinstance(mounts, list):
            raise ValueError("MOUNTS_UNKNOWN")
        root = [m for m in mounts if m.get("target") == "/"]
        if len(root) != 1:
            raise ValueError("ROOT_BACKING_UNKNOWN")
        root_disks = _mount_disks(root[0], ancestry)
        if not root_disks or not all(_physical_disk(disk_id) for disk_id in root_disks):
            raise ValueError("ROOT_BACKING_UNKNOWN")
        if identity in root_disks:
            errors.append("SOURCE_IS_SYSTEM_DISK")
        target_mount = _run_json(
            [
                "findmnt",
                "--json",
                "--target",
                str(parent),
                "--output",
                "TARGET,MAJ:MIN,SOURCE,FSTYPE,UUID",
            ]
        ).get("filesystems")
        if not isinstance(target_mount, list) or len(target_mount) != 1:
            raise ValueError("TARGET_BACKING_UNKNOWN")
        target_disks = _mount_disks(target_mount[0], ancestry)
        if not target_disks:
            raise ValueError("TARGET_BACKING_UNKNOWN")
        if not all(_physical_disk(disk_id) for disk_id in target_disks):
            raise ValueError("TARGET_BACKING_UNKNOWN")
        if identity in target_disks:
            errors.append("SOURCE_TARGET_SAME_DISK")
        for mount in mounts:
            if identity not in _mount_disks(mount, ancestry):
                continue
            options = set(str(mount.get("options") or "").split(","))
            if "rw" in options:
                errors.append("SOURCE_RW_MOUNTED")
            elif "ro" in options:
                warnings.append(f"SOURCE_RO_MOUNTED: {mount.get('target')}")
            else:
                errors.append("SOURCE_MOUNT_STATE_UNKNOWN")
            mountpoint = str(mount.get("target"))
            if mountpoint == "/" or any(
                mountpoint == system or mountpoint.startswith(system + "/")
                for system in ("/boot", "/usr", "/var", "/etc")
            ):
                errors.append("SOURCE_CONTAINS_SYSTEM_FILESYSTEM")
        for swap in _active_swap_ids():
            swap_disks = ancestry.get(swap) or set().union(
                *(
                    _mount_disks(mount, ancestry)
                    for mount in mounts
                    if str(mount.get("maj:min")) == swap
                )
            )
            if not swap_disks:
                raise ValueError("SWAP_BACKING_UNKNOWN")
            if identity in swap_disks:
                errors.append("SOURCE_CONTAINS_ACTIVE_SWAP")
        capacity = int(disk["size"])
        required = capacity if required_space is None else required_space
        if capacity <= 0 or required < 0 or shutil.disk_usage(parent).free < required:
            errors.append("INSUFFICIENT_TARGET_SPACE")
        return SafetyResult(
            not errors,
            tuple(dict.fromkeys(errors)),
            tuple(warnings),
            str(source),
            identity,
            tuple(sorted(target_disks)),
            disk.get("model"),
            disk.get("serial"),
            capacity,
            disk.get("tran"),
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        StopIteration,
        subprocess.SubprocessError,
    ) as exc:
        return SafetyResult(False, (str(exc) or type(exc).__name__,), tuple(warnings))
