"""Parsers for bounded TSK textual output."""

import re
from datetime import UTC, datetime
from pathlib import PurePosixPath

from forensic_image_scanner.recovery.media_types import candidate_media_kind
from forensic_image_scanner.recovery.models import DeletedMediaEntry

_MMLS_ROW = re.compile(
    r"^\s*(?P<slot>\d+):\s+(?:(?P<table>\S+)\s+)?(?P<start>\d+)\s+"
    r"(?P<end>\d+)\s+(?P<length>\d+)\s+(?P<description>.+?)\s*$"
)
_FLS_PREFIX = re.compile(r"^(?P<file_type>\S+)\s+\*\s+(?P<meta>[^:]+):\s*(?P<body>.*)$")


def parse_mmls(output: str) -> tuple[str, int, tuple[dict[str, object], ...]]:
    volume_system = "UNKNOWN"
    sector_size = 512
    rows: list[dict[str, object]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("DOS Partition Table"):
            volume_system = "MBR"
        elif stripped.startswith("GUID Partition Table"):
            volume_system = "GPT"
        unit = re.search(r"Units are in (\d+)-byte sectors", line, re.IGNORECASE)
        if unit:
            sector_size = int(unit.group(1))
        match = _MMLS_ROW.match(line)
        if not match:
            continue
        description = match.group("description")
        table = (match.group("table") or "").casefold()
        if table in {"meta", "-----"} or description.casefold().startswith(("meta", "unallocated")):
            continue
        rows.append(
            {
                "slot": match.group("slot"),
                "start_sector": int(match.group("start")),
                "length_sectors": int(match.group("length")),
                "description": description,
            }
        )
    return volume_system, sector_size, tuple(rows)


def parse_fsstat(output: str) -> tuple[str | None, str | None]:
    filesystem = None
    label = None
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        normalized = key.strip().casefold()
        if normalized == "file system type":
            filesystem = value.strip() or None
        elif normalized in {"volume name", "volume label"}:
            label = value.strip() or None
    return filesystem, label


def parse_fls(output: str, volume_id: str, filesystem: str) -> tuple[DeletedMediaEntry, ...]:
    entries: list[DeletedMediaEntry] = []
    for line in output.splitlines():
        long_fields = line.rstrip().split("\t")
        if len(long_fields) >= 10:
            raw_type, metadata, path, *values = long_fields
            file_type = raw_type.lstrip("+").strip().replace("*", "").strip()
        else:
            match = _FLS_PREFIX.match(line.rstrip().lstrip("+"))
            if not match:
                continue
            file_type = match.group("file_type")
            fields = match.group("body").split("\t")
            path = fields[0]
            metadata = match.group("meta").strip()
            values = fields[1:]
        if not file_type.endswith("/r"):
            continue
        reallocated = "(realloc)" in metadata.casefold() or "(realloc)" in path.casefold()
        metadata = re.sub(r"\s*\(realloc\)\s*", "", metadata, flags=re.IGNORECASE)
        path = re.sub(r"\s*\(realloc\)\s*", "", path, flags=re.IGNORECASE)
        orphan = path.startswith("$OrphanFiles/") or "/$OrphanFiles/" in path
        name = PurePosixPath(path).name
        kind = candidate_media_kind(name)
        if kind is None:
            continue
        values = values + [""] * 7
        entries.append(
            DeletedMediaEntry(
                volume_id=volume_id,
                filesystem=filesystem,
                metadata_address=metadata,
                original_name=name,
                original_path=None if orphan else path,
                size_bytes=_integer(values[4]),
                modified_time=_timestamp(values[0]),
                accessed_time=_timestamp(values[1]),
                changed_time=_timestamp(values[2]),
                created_time=_timestamp(values[3]),
                extension=PurePosixPath(name).suffix.casefold(),
                media_kind=kind,
                reallocated=reallocated,
                orphan=orphan,
                file_type=file_type,
                uid=_integer(values[5]),
                gid=_integer(values[6]),
            )
        )
    return tuple(entries)


def _timestamp(value: str) -> datetime | None:
    value = value.strip()
    if not value or value in {"0", "-"}:
        return None
    try:
        return datetime.fromtimestamp(int(value), UTC)
    except (ValueError, OverflowError, OSError):
        pass
    for pattern in ("%Y-%m-%d %H:%M:%S (%Z)", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(value, pattern)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _integer(value: str) -> int | None:
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return None
