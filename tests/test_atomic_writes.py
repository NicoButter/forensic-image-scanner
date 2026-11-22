"""Critical JSON writers retain prior artifacts when atomic replacement fails."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from forensic_image_scanner.acquisition import (
    AcquisitionMethod,
    AcquisitionResult,
    VerificationStatus,
)
from forensic_image_scanner.case import CaseService
from forensic_image_scanner.case.report import _atomic_write
from forensic_image_scanner.media.catalog import MediaCatalogService
from forensic_image_scanner.pipeline.service import _write as write_pipeline
from forensic_image_scanner.recovery.reports import _atomic_json as write_recovery
from forensic_image_scanner.reports.json_report import write_json_report


def _result(path: Path) -> AcquisitionResult:
    now = datetime.now(UTC)
    return AcquisitionResult(
        source="/dev/mock",
        source_identity="8:16",
        model=None,
        serial=None,
        capacity_bytes=1,
        transport=None,
        method=AcquisitionMethod.RAW,
        tool="ddrescue",
        tool_version="fixture",
        started_at=now,
        completed_at=now,
        output=str(path),
        bytes_acquired=1,
        sha256=None,
        verification=VerificationStatus.NOT_PERFORMED,
        completed=False,
        errors=("CANCELLED",),
        cancelled=True,
    )


def _assert_replace_failure_preserves(
    monkeypatch, destination: Path, writer
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    original = b'{"previous": true}\n'
    destination.write_bytes(original)

    def fail_replace(*_args):
        raise OSError("simulated interrupted replace")

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", fail_replace)
        with pytest.raises(OSError, match="simulated interrupted replace"):
            writer()

    assert destination.read_bytes() == original
    assert not list(destination.parent.glob(f".{destination.name}.*.tmp"))


def test_critical_json_writers_preserve_previous_files(tmp_path, monkeypatch):
    case = CaseService.create(tmp_path / "case")
    case_manifest = case.root / "case.json"
    original_case = case_manifest.read_bytes()

    def fail_case_write(*_args):
        raise OSError("simulated interrupted replace")

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", fail_case_write)
        with pytest.raises(OSError, match="simulated interrupted replace"):
            case.update_metadata(title="uncommitted")
    assert case_manifest.read_bytes() == original_case

    from forensic_image_scanner.acquisition.service import _write_record
    from forensic_image_scanner.case import report as case_report

    target = tmp_path / "reports"
    target.mkdir()
    _assert_replace_failure_preserves(
        monkeypatch,
        target / "acquisition.json",
        lambda: _write_record(target / "acquisition.json", _result(target / "image.raw")),
    )
    _assert_replace_failure_preserves(
        monkeypatch,
        target / "recovery.json",
        lambda: write_recovery(target / "recovery.json", {"records": []}),
    )
    _assert_replace_failure_preserves(
        monkeypatch,
        target / "analysis.json",
        lambda: write_json_report([], target / "analysis.json"),
    )
    _assert_replace_failure_preserves(
        monkeypatch,
        target / "pipeline_root" / "reports" / "pipeline_summary.json",
        lambda: write_pipeline(target / "pipeline_root", {"cancelled": True}),
    )
    _assert_replace_failure_preserves(
        monkeypatch,
        target / "forensic_report.json",
        lambda: case_report._atomic_write(
            target / "forensic_report.json", json.dumps({"case_id": case.case_id})
        ),
    )
    _assert_replace_failure_preserves(
        monkeypatch,
        target / "media_root" / "reports" / "media_catalog.json",
        lambda: MediaCatalogService()._write(target / "media_root", [], False),
    )
    _assert_replace_failure_preserves(
        monkeypatch,
        target / "forensic_report.html",
        lambda: _atomic_write(target / "forensic_report.html", "<html></html>"),
    )
