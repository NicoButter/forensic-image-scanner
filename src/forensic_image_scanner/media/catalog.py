"""Canonical per-hash catalog with preserved recovery provenance."""

import csv
import json
import os
import re
import tempfile
from dataclasses import fields
from pathlib import Path
from threading import Event

from forensic_image_scanner.media.image_validator import validate_image
from forensic_image_scanner.media.models import MediaIntegrity, MediaRecord
from forensic_image_scanner.media.video_validator import validate_video
from forensic_image_scanner.recovery.models import RecoverySessionSummary
from forensic_image_scanner.reports.csv_report import _safe_cell


class MediaCatalogService:
    def build(self, summary: RecoverySessionSummary, *, progress=None, cancel=None):
        return self.build_records(summary.target, [r.to_dict() for r in summary.records],
                                  progress=progress, cancel=cancel)

    def build_from_report(self, target: Path, *, progress=None, cancel=None):
        target = target.expanduser().resolve()
        with (target / "reports" / "recovery.json").open(encoding="utf-8") as source:
            data = json.load(source)
        return self.build_records(target, data["records"], progress=progress, cancel=cancel)

    def build_records(self, target: Path, records: list[dict], *, progress=None, cancel=None):
        target = target.resolve()
        cancel = cancel or Event()
        grouped = {}
        for source in records:
            digest, relative = source.get("recovered_sha256"), source.get("recovered_relative_path")
            if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
                continue
            if not isinstance(relative, str):
                continue
            path = (target / relative).resolve()
            if not path.is_relative_to(target / "recovered") or not path.is_file():
                raise ValueError(f"invalid recovered artifact path: {relative}")
            grouped.setdefault(digest.lower(), []).append(source)
        output = []
        for index, (digest, sources) in enumerate(sorted(grouped.items()), 1):
            if cancel.is_set():
                break
            sources = sorted(sources, key=lambda item: str(item.get("recovery_id") or ""))
            source = sources[0]
            path = (target / source["recovered_relative_path"]).resolve()
            record = MediaRecord(
                digest, digest, source["recovered_relative_path"], path.stat().st_size,
                source["candidate_media_kind"], source["candidate_extension"],
            )
            for item in sources:
                record.provenance.append(item)
                if item.get("method") not in record.recovery_methods:
                    record.recovery_methods.append(item.get("method"))
                record.recovery_ids.append(item.get("recovery_id"))
                original = item.get("original_path")
                if original and original != "UNKNOWN" and original not in record.original_paths:
                    record.original_paths.append(original)
            record.recovery_methods.sort()
            record.recovery_ids.sort()
            record.original_paths.sort()
            if record.media_kind == "image":
                validate_image(path, record)
            elif record.media_kind == "video":
                validate_video(path, record)
            else:
                record.integrity = MediaIntegrity.UNSUPPORTED
                record.errors.append("UNSUPPORTED_MEDIA_KIND")
            if record.integrity == MediaIntegrity.VALID and any(
                item.get("size_match") is False or item.get("recovery_status") == "partial"
                for item in sources
            ):
                record.integrity = MediaIntegrity.PARTIAL
                record.warnings.append("recovery reported incomplete bytes")
            output.append(record)
            if progress:
                counts = {state.value: sum(r.integrity == state for r in output)
                          for state in MediaIntegrity}
                progress("VALIDATING MEDIA", index, len(grouped), json.dumps(counts))
        self._write(target, output, cancel.is_set())
        return output

    def _write(self, target: Path, records: list[MediaRecord], cancelled: bool) -> None:
        reports = target / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        payload = {"cancelled": cancelled, "records": [record.to_dict() for record in records]}
        for name in ("media_catalog.json", "media_catalog.csv"):
            descriptor, tmp = tempfile.mkstemp(prefix=".media-", dir=reports)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as out:
                    if name.endswith("json"):
                        json.dump(payload, out, indent=2, ensure_ascii=False)
                        out.write("\n")
                    else:
                        writer = csv.DictWriter(
                            out, fieldnames=[f.name for f in fields(MediaRecord)]
                        )
                        writer.writeheader()
                        for record in records:
                            writer.writerow({k: _safe_cell(json.dumps(v, ensure_ascii=False)
                                            if isinstance(v, (list, dict)) else v)
                                             for k, v in record.to_dict().items()})
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(tmp, reports / name)
            finally:
                Path(tmp).unlink(missing_ok=True)
