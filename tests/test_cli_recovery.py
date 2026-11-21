"""CLI routing for inspection and filesystem recovery."""

import json
from datetime import UTC, datetime

from forensic_image_scanner.cli import main
from forensic_image_scanner.recovery import (
    RecoverySessionSummary,
    RecoveryStatus,
    RecoveryVolume,
    SourceInspection,
)


def test_inspect_source_json_uses_recovery_service(monkeypatch, tmp_path, capsys) -> None:
    source = tmp_path / "case.dd"
    volume = RecoveryVolume("volume-01", 2048, 1000, "Basic data", "NTFS", True, 512, "case.dd")
    inspection = SourceInspection(source, "GPT", 512, (volume,), "TSK fixture")

    class Service:
        def inspect_source(self, requested):
            assert requested == source
            return inspection

    monkeypatch.setattr("forensic_image_scanner.cli.FilesystemRecoveryService", Service)
    assert main(["inspect-source", str(source), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["volume_system"] == "GPT"
    assert payload["volumes"][0]["filesystem"] == "NTFS"


def test_recover_cli_routes_options_and_prints_reports(monkeypatch, tmp_path, capsys) -> None:
    source = tmp_path / "case.dd"
    target = tmp_path / "target"
    summary = RecoverySessionSummary(
        source,
        target,
        "TSK fixture",
        datetime.now(UTC),
        datetime.now(UTC),
        1,
        1,
        3,
        1,
        (),
        False,
        json_path=target / "reports" / "recovery.json",
        csv_path=target / "reports" / "recovery.csv",
    )
    captured = {}

    class Service:
        def recover(self, request, *, progress):
            captured["request"] = request
            progress("RECOVERING", 1, 1, "photo.jpg")
            return summary

    monkeypatch.setattr("forensic_image_scanner.cli.FilesystemRecoveryService", Service)
    assert (
        main(
            [
                "recover",
                str(source),
                "--target",
                str(target),
                "--volume",
                "volume-02",
                "--no-videos",
            ]
        )
        == 0
    )
    request = captured["request"]
    assert request.volume_ids == ("volume-02",)
    assert request.images and not request.videos
    output = capsys.readouterr().out
    assert "RECOVERING 1/1" in output
    assert str(summary.json_path) in output
    assert summary.count(RecoveryStatus.RECOVERED) == 0
