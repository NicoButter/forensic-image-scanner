"""Persistent case metadata, provenance references, and lifecycle."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import threading
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from forensic_image_scanner.acquisition.models import AcquisitionResult
from forensic_image_scanner.case.audit import append_event, read_events
from forensic_image_scanner.case.models import CaseMetadata, CaseStatus, SourceSummary

_CASE_ID = re.compile(r"FIS-\d{8}-[0-9A-F]{8}\Z")
_METADATA_FIELDS = frozenset(
    {
        "case_number",
        "title",
        "description",
        "examiner",
        "organization",
        "evidence_number",
        "notes",
    }
)
_REFERENCE_PATH_FIELDS = frozenset({"path", "image", "record", "acquired_image"})


class CaseService:
    def __init__(self, root: Path, data: dict[str, object]) -> None:
        self.root = root
        self.case_file = root / "case.json"
        self.data = data
        self._lock = threading.RLock()

    @classmethod
    def create(
        cls,
        directory: str | Path,
        *,
        case_number: str | None = None,
        title: str | None = None,
        description: str | None = None,
        examiner: str | None = None,
        organization: str | None = None,
        evidence_number: str | None = None,
        notes: str | None = None,
    ) -> CaseService:
        location = Path(directory).expanduser()
        if location.is_symlink():
            raise ValueError("case directory must not be a symlink")
        location.mkdir(parents=True, exist_ok=True)
        root = location.resolve()
        case_file = root / "case.json"
        if case_file.exists() or case_file.is_symlink():
            raise FileExistsError("case.json already exists")
        for name in ("acquisition", "recovered", "findings", "reports", "logs"):
            (root / name).mkdir(exist_ok=True)
        now = _timestamp()
        metadata = CaseMetadata(
            case_id=f"FIS-{datetime.now(UTC):%Y%m%d}-{uuid.uuid4().hex[:8].upper()}",
            case_number=case_number,
            title=title,
            description=description,
            examiner=examiner,
            organization=organization,
            evidence_number=evidence_number,
            notes=notes,
            created_at=now,
            updated_at=now,
            status=CaseStatus.OPEN,
        )
        data: dict[str, object] = {
            "schema_version": 1,
            **metadata.to_dict(),
            "sources": [],
            "acquisitions": [],
            "recoveries": [],
            "media_catalog": None,
            "pipeline_summary": None,
            "reports": [],
            "references": {"audit_log": "logs/audit.jsonl"},
            "active_operations": [],
        }
        service = cls(root, data)
        audit_path = root / "logs" / "audit.jsonl"
        audit_descriptor = os.open(
            audit_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        os.close(audit_descriptor)
        append_event(
            audit_path,
            case_id=metadata.case_id,
            event="case created",
            component="case",
        )
        service._write()
        return service

    @classmethod
    def open(cls, directory: str | Path) -> CaseService:
        location = Path(directory).expanduser()
        if location.is_symlink() or not location.is_dir():
            raise ValueError("case directory is missing or unsafe")
        root = location.resolve()
        case_file = root / "case.json"
        if case_file.is_symlink() or not case_file.is_file():
            raise ValueError("case.json is missing or unsafe")
        try:
            with case_file.open(encoding="utf-8") as input_file:
                data = json.load(input_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("case.json is malformed or unreadable") from exc
        service = cls(root, data)
        service._validate()
        service._validate_layout()
        return service

    @property
    def metadata(self) -> CaseMetadata:
        return CaseMetadata.from_dict(self.data)

    @property
    def case_id(self) -> str:
        return self.metadata.case_id

    @property
    def audit_path(self) -> Path:
        references = self.data["references"]
        assert isinstance(references, dict)
        return self._resolve_reference(references["audit_log"])

    @property
    def active_operations(self) -> tuple[dict[str, object], ...]:
        operations = self.data["active_operations"]
        assert isinstance(operations, list)
        return tuple(dict(item) for item in operations)

    def ensure_writable(self) -> None:
        self._ensure_current_manifest()
        self._validate_layout()
        if self.metadata.status in {CaseStatus.COMPLETED, CaseStatus.ARCHIVED}:
            raise ValueError("case is finalized; explicitly reopen it before making changes")

    def update_metadata(self, **values: str | None) -> CaseMetadata:
        self.ensure_writable()
        unknown = set(values) - _METADATA_FIELDS
        if unknown:
            raise ValueError(f"unsupported case metadata: {', '.join(sorted(unknown))}")
        if any(value is not None and not isinstance(value, str) for value in values.values()):
            raise TypeError("case metadata values must be strings or null")
        with self._lock:
            self.data.update(values)
            self.data["updated_at"] = _timestamp()
            self._write()
            self._append("case metadata updated", "case", {"fields": sorted(values)})
        return self.metadata

    def add_audit_event(
        self,
        event: str,
        component: str,
        details: Mapping[str, object] | None = None,
    ) -> None:
        self.ensure_writable()
        self._append(event, component, details)

    def record_source(
        self,
        source_kind: str,
        original_location: str | Path,
        *,
        model: str | None = None,
        serial: str | None = None,
        capacity: int | None = None,
        transport: str | None = None,
        sha256: str | None = None,
    ) -> SourceSummary:
        self.ensure_writable()
        if not source_kind.strip() or not str(original_location).strip():
            raise ValueError("source kind and original location are required")
        with self._lock:
            sources = self._list("sources")
            for index, item in enumerate(sources):
                if (
                    item["source_kind"] == source_kind
                    and item["original_location"] == str(original_location)
                ):
                    updated = dict(item)
                    for key, value in {
                        "model": model,
                        "serial": serial,
                        "capacity": capacity,
                        "transport": transport,
                        "sha256": sha256,
                    }.items():
                        if value is not None:
                            updated[key] = value
                    sources[index] = updated
                    source = SourceSummary(**updated)
                    self._write()
                    self._append(
                        "source selected",
                        "source",
                        {"source_id": source.source_id, "source_kind": source_kind},
                    )
                    return source
            source = SourceSummary(
                source_id=str(uuid.uuid4()),
                source_kind=source_kind,
                original_location=str(original_location),
                model=model,
                serial=serial,
                capacity=capacity,
                transport=transport,
            )
            sources.append(source.to_dict())
            self._write()
            self._append(
                "source selected",
                "source",
                {"source_id": source.source_id, "source_kind": source_kind},
            )
            return source

    def record_acquisition(
        self, result: AcquisitionResult, *, source_id: str | None = None
    ) -> None:
        self.ensure_writable()
        output = Path(result.output)
        image = self._relative_artifact(output) if output.is_file() else None
        record_path = self.root / "acquisition" / "acquisition.json"
        record = self._relative_artifact(record_path) if record_path.is_file() else None
        with self._lock:
            sources = self._list("sources")
            source = next(
                (
                    item
                    for item in sources
                    if (source_id is None or item["source_id"] == source_id)
                    and item["source_kind"] == "physical_device"
                ),
                None,
            )
            if source is None:
                source_record = self.record_source(
                    "physical_device",
                    result.source,
                    model=result.model,
                    serial=result.serial,
                    capacity=result.capacity_bytes,
                    transport=result.transport,
                )
                source = next(
                    item
                    for item in self._list("sources")
                    if item["source_id"] == source_record.source_id
                )
            for key, value in {
                "model": result.model,
                "serial": result.serial,
                "capacity": result.capacity_bytes,
                "transport": result.transport,
            }.items():
                if value is not None:
                    source[key] = value
            source["acquisition_method"] = result.method.value
            if image is not None:
                source["acquired_image"] = image
            acquisitions = self._list("acquisitions")
            acquisitions.append(
                {
                    "source_id": source["source_id"],
                    "method": result.method.value,
                    "verification": result.verification.value,
                    "completed": result.completed,
                    "cancelled": result.cancelled,
                    "image": image,
                    "record": record,
                    "sha256": result.sha256,
                    "bytes_acquired": result.bytes_acquired,
                    "errors": list(result.errors),
                }
            )
            self._write()
            acquisition_completed = result.completed or (
                result.method.value == "e01"
                and result.verification.value == "failed"
                and image is not None
            )
            self._append(
                "acquisition completed" if acquisition_completed else "acquisition failed",
                "acquisition",
                {"source_id": source["source_id"], "image": image},
            )
            if result.verification.value == "failed":
                self._append(
                    "verification failed",
                    "acquisition",
                    {"source_id": source["source_id"], "image": image},
                )
            elif result.verification.value == "verified":
                self._append(
                    "verification completed",
                    "acquisition",
                    {"source_id": source["source_id"], "image": image},
                )

    def record_recovery(
        self, path: str | Path, *, details: Mapping[str, object] | None = None
    ) -> None:
        self.ensure_writable()
        reference = {"path": self._relative_artifact(path), "kind": "recovery"}
        if details:
            reference["details"] = dict(details)
        with self._lock:
            recoveries = self._list("recoveries")
            recoveries[:] = [
                item for item in recoveries if item.get("path") != reference["path"]
            ]
            recoveries.append(reference)
            self._write()

    def record_analysis(self, path: str | Path) -> None:
        self.add_report_reference(path, kind="analysis")

    def record_media_catalog(self, path: str | Path) -> None:
        self.ensure_writable()
        with self._lock:
            self.data["media_catalog"] = {
                "path": self._relative_artifact(path),
                "kind": "media_catalog",
            }
            self._write()

    def record_pipeline_summary(self, path: str | Path) -> None:
        self.ensure_writable()
        with self._lock:
            self.data["pipeline_summary"] = {
                "path": self._relative_artifact(path),
                "kind": "pipeline_summary",
            }
            self._write()

    def add_report_reference(self, path: str | Path, *, kind: str) -> None:
        self.ensure_writable()
        reference = {"path": self._relative_artifact(path), "kind": kind}
        with self._lock:
            reports = self._list("reports")
            reports[:] = [item for item in reports if item.get("kind") != kind]
            reports.append(reference)
            self._write()

    def sync_artifact_references(self) -> None:
        self.ensure_writable()
        acquisition_record = self.root / "acquisition" / "acquisition.json"
        if acquisition_record.is_file() and not any(
            item.get("record") == self._relative_artifact(acquisition_record)
            for item in self._list("acquisitions")
        ):
            from forensic_image_scanner.acquisition.models import (
                AcquisitionMethod,
                VerificationStatus,
            )

            try:
                data = json.loads(acquisition_record.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("REPORT_INCONSISTENT: malformed acquisition record") from exc
            if not isinstance(data, dict):
                raise ValueError("REPORT_INCONSISTENT: malformed acquisition record")
            output = data.get("output")
            if output and Path(output).is_file():
                image = self._relative_artifact(output)
                acquisition = {
                    "source_id": None,
                    "method": data.get("method"),
                    "verification": data.get("verification"),
                    "completed": data.get("completed", False),
                    "cancelled": data.get("cancelled", False),
                    "image": image,
                    "record": self._relative_artifact(acquisition_record),
                    "sha256": data.get("sha256"),
                    "bytes_acquired": data.get("bytes_acquired"),
                    "errors": data.get("errors", []),
                }
                AcquisitionMethod(acquisition["method"])
                VerificationStatus(acquisition["verification"])
                self._list("acquisitions").append(acquisition)
                self._write()
                self.record_source(
                    "physical_device",
                    data["source"],
                    model=data.get("model"),
                    serial=data.get("serial"),
                    capacity=data.get("capacity_bytes"),
                    transport=data.get("transport"),
                )
                source = next(
                    item
                    for item in self._list("sources")
                    if item["source_kind"] == "physical_device"
                    and item["original_location"] == data["source"]
                )
                source.update(
                    acquisition_method=data["method"],
                    acquired_image=image,
                )
                self._write()
                acquisition_completed = bool(acquisition["completed"]) or (
                    acquisition["method"] == "e01"
                    and acquisition["verification"] == "failed"
                    and image is not None
                )
                self._append(
                    "acquisition completed" if acquisition_completed else "acquisition failed",
                    "acquisition",
                    {"image": image},
                )
                if acquisition["verification"] == "verified":
                    self._append("verification completed", "acquisition", {"image": image})
                elif acquisition["verification"] == "failed":
                    self._append("verification failed", "acquisition", {"image": image})
        candidates = (
            (
                "reports/recovery.json",
                "recoveries",
                {"path": "reports/recovery.json", "kind": "recovery"},
            ),
            (
                "reports/media_catalog.json",
                "media_catalog",
                {"path": "reports/media_catalog.json", "kind": "media_catalog"},
            ),
            (
                "reports/pipeline_summary.json",
                "pipeline_summary",
                {"path": "reports/pipeline_summary.json", "kind": "pipeline_summary"},
            ),
            (
                "reports/analysis.json",
                "reports",
                {"path": "reports/analysis.json", "kind": "analysis"},
            ),
            (
                "reports/analysis.csv",
                "reports",
                {"path": "reports/analysis.csv", "kind": "analysis_csv"},
            ),
        )
        for relative, field, reference in candidates:
            artifact = self.root / relative
            if not artifact.is_file() or artifact.is_symlink():
                continue
            if field == "recoveries":
                try:
                    payload = json.loads(artifact.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise ValueError("REPORT_INCONSISTENT: malformed recovery report") from exc
                if not isinstance(payload, dict):
                    raise ValueError("REPORT_INCONSISTENT: malformed recovery report")
                references = self._list(field)
                if not any(item.get("path") == relative for item in references):
                    references.append(reference)
                source_path = payload.get("source")
                source_hash = payload.get("source_sha256")
                if source_path and source_hash and source_hash != "UNKNOWN":
                    for source in self._list("sources"):
                        if (
                            source["source_kind"] == "forensic_image"
                            and source["original_location"] == source_path
                        ):
                            source["sha256"] = source_hash
            elif field in {"media_catalog", "pipeline_summary"}:
                if self.data[field] is None:
                    self.data[field] = reference
            else:
                reports = self._list("reports")
                if not any(item.get("kind") == reference["kind"] for item in reports):
                    reports.append(reference)
        self._write()

    @contextmanager
    def operation(self, component: str) -> Iterator[None]:
        self.ensure_writable()
        token = self.begin_operation(component)
        try:
            yield
        except BaseException:
            self.finish_operation(token, component, success=False)
            raise
        else:
            self.finish_operation(token, component, success=True)

    def begin_operation(self, component: str) -> str:
        self.ensure_writable()
        token = str(uuid.uuid4())
        with self._lock:
            operations = self._list("active_operations")
            operations.append(
                {"operation_id": token, "component": component, "started_at": _timestamp()}
            )
            self.data["status"] = CaseStatus.IN_PROGRESS.value
            self.data["updated_at"] = _timestamp()
            self._write()
            self._append(f"{component} started", component)
        return token

    def finish_operation(self, token: str, component: str, *, success: bool) -> None:
        self._ensure_current_manifest()
        with self._lock:
            operations = self._list("active_operations")
            remaining = [item for item in operations if item.get("operation_id") != token]
            if len(remaining) == len(operations):
                raise ValueError("unknown or already finished case operation")
            operations[:] = remaining
            self.data["updated_at"] = _timestamp()
            self._write()
            self._append(
                f"{component} {'completed' if success else 'failed'}",
                component,
            )

    def complete(self) -> CaseMetadata:
        self._ensure_current_manifest()
        if self.metadata.status in {CaseStatus.COMPLETED, CaseStatus.ARCHIVED}:
            raise ValueError("case is already finalized")
        if self.active_operations:
            raise ValueError("cannot complete a case with active operations")
        with self._lock:
            self.data["status"] = CaseStatus.COMPLETED.value
            self.data["updated_at"] = _timestamp()
            self._write()
            self._append("case completed", "case")
        return self.metadata

    def reopen(self) -> CaseMetadata:
        self._ensure_current_manifest()
        if self.metadata.status is not CaseStatus.COMPLETED:
            raise ValueError("only a completed case can be reopened")
        with self._lock:
            stale = len(self._list("active_operations"))
            self.data["active_operations"] = []
            self.data["status"] = CaseStatus.IN_PROGRESS.value
            self.data["updated_at"] = _timestamp()
            self._write()
            self._append("case reopened", "case", {"cleared_stale_operations": stale})
        return self.metadata

    def archive(self) -> CaseMetadata:
        self._ensure_current_manifest()
        if self.metadata.status is not CaseStatus.COMPLETED:
            raise ValueError("only a completed case can be archived")
        with self._lock:
            self.data["status"] = CaseStatus.ARCHIVED.value
            self.data["updated_at"] = _timestamp()
            self._write()
            self._append("case archived", "case")
        return self.metadata

    def generate_report(self) -> tuple[Path, Path]:
        self.ensure_writable()
        self.sync_artifact_references()
        from forensic_image_scanner.case.report import write_reports

        _payload, json_path, html_path = write_reports(self)
        self.add_report_reference(json_path, kind="forensic_report_json")
        self.add_report_reference(html_path, kind="forensic_report_html")
        self._append(
            "report generated",
            "report",
            {
                "json": self._relative_artifact(json_path),
                "html": self._relative_artifact(html_path),
            },
        )
        self.data["updated_at"] = _timestamp()
        self._write()
        return json_path, html_path

    def _append(
        self,
        event: str,
        component: str,
        details: Mapping[str, object] | None = None,
    ) -> None:
        self._ensure_current_manifest()
        references = self.data["references"]
        assert isinstance(references, dict)
        read_events(self.audit_path, self.case_id)
        append_event(
            self.audit_path,
            case_id=self.case_id,
            event=event,
            component=component,
            details=details,
        )

    def _list(self, key: str) -> list[dict[str, object]]:
        value = self.data.get(key)
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ValueError(f"invalid case {key} collection")
        return value

    def _relative_artifact(self, path: str | Path) -> str:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = self.root / candidate
        normalized = Path(os.path.abspath(candidate))
        if not normalized.is_relative_to(self.root):
            raise ValueError("case artifact path escapes the case directory")
        current = self.root
        for component in normalized.relative_to(self.root).parts:
            current /= component
            if current.is_symlink():
                raise ValueError("case artifact paths must not traverse symlinks")
        resolved = normalized.resolve()
        info = resolved.stat()
        if not resolved.is_relative_to(self.root):
            raise ValueError("case artifact path escapes the case directory")
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("case artifact must be a single-link regular file")
        return resolved.relative_to(self.root).as_posix()

    def _resolve_reference(self, relative: object) -> Path:
        if not isinstance(relative, str) or not relative:
            raise ValueError("case reference path is invalid")
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("case references must be relative")
        candidate = self.root / path
        current = self.root
        for component in path.parts:
            current /= component
            if current.is_symlink():
                raise ValueError("case references must not traverse symlinks")
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.root):
            raise ValueError("case reference escapes the case directory")
        return resolved

    def _validate(self) -> None:
        if not isinstance(self.data, dict) or self.data.get("schema_version") != 1:
            raise ValueError("unsupported case schema")
        metadata = self.metadata
        if not _CASE_ID.fullmatch(metadata.case_id):
            raise ValueError("invalid case_id")
        try:
            datetime.fromisoformat(metadata.created_at)
            datetime.fromisoformat(metadata.updated_at)
        except ValueError as exc:
            raise ValueError("invalid case timestamps") from exc
        references = self.data.get("references")
        if not isinstance(references, dict):
            raise ValueError("invalid case references")
        audit_path = self._resolve_reference(references.get("audit_log"))
        read_events(audit_path, metadata.case_id)
        for key in ("sources", "acquisitions", "recoveries", "reports", "active_operations"):
            self._list(key)
        for source in self._list("sources"):
            acquired_image = source.get("acquired_image")
            if acquired_image is not None:
                self._validate_existing_reference(acquired_image)
        for key in ("acquisitions", "recoveries", "reports"):
            for item in self._list(key):
                for field in _REFERENCE_PATH_FIELDS:
                    if item.get(field) is not None:
                        self._validate_existing_reference(item[field])
        for key in ("media_catalog", "pipeline_summary"):
            reference = self.data.get(key)
            if reference is not None:
                if not isinstance(reference, dict):
                    raise ValueError(f"invalid {key} reference")
                self._validate_existing_reference(reference.get("path"))

    def _validate_layout(self) -> None:
        for name in ("acquisition", "recovered", "findings", "reports", "logs"):
            directory = self.root / name
            if directory.is_symlink():
                raise ValueError(f"case {name} directory is unsafe")
            if directory.exists():
                resolved = directory.resolve(strict=True)
                if not resolved.is_relative_to(self.root) or not resolved.is_dir():
                    raise ValueError(f"case {name} directory is unsafe")

    def _validate_existing_reference(self, relative: object) -> None:
        path = self._resolve_reference(relative)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("referenced case artifact is missing or unsafe")

    def _write(self) -> None:
        self.data["updated_at"] = _timestamp()
        descriptor, name = tempfile.mkstemp(prefix=".case-", dir=self.root)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(self.data, output, ensure_ascii=False, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, self.case_file)
        finally:
            Path(name).unlink(missing_ok=True)

    def _ensure_current_manifest(self) -> None:
        if self.case_file.is_symlink() or not self.case_file.is_file():
            raise ValueError("case.json is missing or unsafe")
        try:
            with self.case_file.open(encoding="utf-8") as input_file:
                current = json.load(input_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("case.json is malformed or unreadable") from exc
        if not isinstance(current, dict) or current.get("case_id") != self.case_id:
            raise ValueError("case_id mismatch")
        if current != self.data:
            raise ValueError("case.json changed; reopen the case before continuing")
        read_events(self.audit_path, self.case_id)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()
