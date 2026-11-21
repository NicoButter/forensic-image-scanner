"""PhotoRec scripted-command construction using real format-family identifiers."""

from dataclasses import dataclass

from forensic_image_scanner.recovery.models import MediaKind, RecoveryVolume, SourceInspection

# PhotoRec enables signature families rather than arbitrary extensions. Some
# families cover more than one extension; normalization applies FIS's narrower policy.
IMAGE_GROUPS = ("jpg", "png", "gif", "bmp", "tif", "raf", "orf", "rw2")
VIDEO_GROUPS = ("mov", "riff", "mkv", "mpg", "asf", "m2ts", "ts")
FREESPACE_FILESYSTEMS = ("ntfs", "fat12", "fat16", "fat32", "ext2", "ext3", "ext4")


@dataclass(frozen=True, slots=True)
class PhotoRecPlan:
    command: str
    format_groups: tuple[str, ...]
    scan_scope: str
    partition_number: int | None


def build_plan(
    inspection: SourceInspection | None,
    volume: RecoveryVolume,
    media: frozenset[MediaKind],
) -> PhotoRecPlan:
    groups: list[str] = []
    if MediaKind.IMAGE in media:
        groups.extend(IMAGE_GROUPS)
    if MediaKind.VIDEO in media:
        groups.extend(VIDEO_GROUPS)
    if not groups:
        raise ValueError("select images, videos, or both")
    filesystem = (volume.filesystem or "").casefold().replace(" ", "")
    scan_scope = (
        "freespace"
        if any(filesystem.startswith(item) for item in FREESPACE_FILESYSTEMS)
        else "wholespace"
    )
    volume_system = inspection.volume_system if inspection else "SINGLE_FILESYSTEM_IMAGE"
    partition_type = {
        "GPT": "partition_gpt",
        "MBR": "partition_i386",
    }.get(volume_system, "partition_none")
    partition_number = _partition_number(volume.partition_slot)
    parts = [partition_type]
    if filesystem.startswith("ext"):
        parts += ["options", "mode_ext2"]
    parts += ["fileopt", "everything", "disable"]
    for group in groups:
        parts += [group, "enable"]
    parts.append(scan_scope)
    if partition_number is not None and partition_type != "partition_none":
        parts.append(str(partition_number))
    parts.append("search")
    return PhotoRecPlan(",".join(parts), tuple(groups), scan_scope, partition_number)


def _partition_number(slot: str | None) -> int | None:
    if not slot:
        return None
    try:
        return int(slot.rsplit(":", 1)[-1]) + (1 if ":" in slot else 0)
    except ValueError:
        return None
