"""Atomic canonical recovery JSON and spreadsheet-safe CSV reports."""

import csv
import json
import os
import tempfile
from pathlib import Path

from forensic_image_scanner import __version__
from forensic_image_scanner.recovery.models import (
    CarvedMedia,
    RecoveredMedia,
    RecoverySessionSummary,
    RecoveryStatus,
)
from forensic_image_scanner.reports.csv_report import _safe_cell


def write_recovery_reports(summary: RecoverySessionSummary) -> tuple[Path, Path]:
    reports = summary.target / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    json_path = reports / "recovery.json"
    csv_path = reports / "recovery.csv"
    if json_path.exists() or csv_path.exists():
        raise FileExistsError("a recovery report already exists in this target")
    records = [record.to_dict() for record in summary.records]
    methods = sorted({record.method.value for record in summary.records})
    session_method = (
        methods[0] if len(methods) == 1 else "mixed" if methods else summary.method.value
    )
    payload = {
        "fis_version": __version__,
        "timestamp": summary.completed_at.isoformat(),
        "started_at": summary.started_at.isoformat(),
        "completed_at": summary.completed_at.isoformat(),
        "source": str(summary.source),
        "source_kind": "forensic_image",
        "source_sha256": summary.source_sha256 or "UNKNOWN",
        "source_stat_unchanged": summary.source_stat_unchanged,
        "target": str(summary.target),
        "operation": "recover",
        "recovery_method": session_method,
        "recovery_methods": methods or [summary.method.value],
        "tsk_version": summary.tsk_version,
        "volumes_inspected": summary.volumes_inspected,
        "filesystems_detected": summary.filesystems_detected,
        "deleted_entries_discovered": summary.deleted_entries,
        "media_candidates": summary.media_candidates,
        "recovered": summary.count(RecoveryStatus.RECOVERED),
        "filesystem_recovered": sum(
            isinstance(record, RecoveredMedia) and record.status is RecoveryStatus.RECOVERED
            for record in summary.records
        ),
        "carved": sum(
            isinstance(record, CarvedMedia)
            and record.status is RecoveryStatus.RECOVERED
            and record.duplicate_of is None
            for record in summary.records
        ),
        "duplicates": sum(
            isinstance(record, CarvedMedia) and record.duplicate_of is not None
            for record in summary.records
        ),
        "partial": summary.count(RecoveryStatus.PARTIAL),
        "failed": summary.count(RecoveryStatus.FAILED),
        "skipped": summary.count(RecoveryStatus.SKIPPED),
        "cancelled": summary.cancelled,
        "metadata": dict(summary.metadata),
        "records": records,
    }
    _atomic_json(json_path, payload)
    _atomic_csv(csv_path, records)
    return json_path, csv_path


def _atomic_json(destination: Path, payload: dict[str, object]) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".recovery.", suffix=".tmp", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_csv(destination: Path, records: list[dict[str, object]]) -> None:
    fields = (
        tuple(dict.fromkeys(key for record in records for key in record))
        if records
        else (
            "recovery_id",
            "volume_id",
            "metadata_address",
            "original_name",
            "recovery_status",
        )
    )
    descriptor, name = tempfile.mkstemp(prefix=".recovery.", suffix=".tmp", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            for record in records:
                writer.writerow({key: _safe_cell(value) for key, value in record.items()})
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
