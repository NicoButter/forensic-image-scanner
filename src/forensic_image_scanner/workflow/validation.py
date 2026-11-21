"""Central capability and safety validation for configured workflows."""

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from forensic_image_scanner.workflow.models import OperationMode, SourceKind, WorkflowRequest


class FindingSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    code: str
    severity: FindingSeverity
    message: str


@dataclass(frozen=True, slots=True)
class WorkflowCapability:
    supported: bool
    reason: str


@dataclass(frozen=True, slots=True)
class WorkflowValidation:
    findings: tuple[ValidationFinding, ...]
    capability: WorkflowCapability
    physical_collision_checked: bool = False

    @property
    def executable(self) -> bool:
        return self.capability.supported and not any(
            finding.severity is FindingSeverity.ERROR for finding in self.findings
        )


def capability_for(
    kind: SourceKind, operation: OperationMode, *, tsk_available: bool = False
) -> WorkflowCapability:
    if kind is SourceKind.DIRECTORY and operation is OperationMode.ANALYZE:
        return WorkflowCapability(True, "Directory analysis is supported.")
    if kind is SourceKind.FORENSIC_IMAGE and operation is OperationMode.RECOVER:
        if tsk_available:
            return WorkflowCapability(True, "Filesystem metadata recovery is supported by TSK.")
        return WorkflowCapability(
            False, "Filesystem recovery requires The Sleuth Kit: mmls, fsstat, fls, icat."
        )
    if operation is OperationMode.RECOVER_ANALYZE:
        return WorkflowCapability(False, "Recovery + analysis will be enabled in FIS-015.")
    if operation in {OperationMode.RECOVER, OperationMode.RECOVER_ANALYZE}:
        return WorkflowCapability(
            False,
            "Filesystem recovery is not enabled for this source type.",
        )
    return WorkflowCapability(False, "Analysis for this source type is not implemented yet.")


def validate_workflow(
    request: WorkflowRequest, *, tsk_available: bool = False
) -> WorkflowValidation:
    findings: list[ValidationFinding] = []
    source = request.source
    target = request.target.path.expanduser().resolve()
    capability = capability_for(source.kind, request.operation, tsk_available=tsk_available)

    if not source.exists:
        findings.append(
            ValidationFinding("source_missing", FindingSeverity.ERROR, "Source does not exist.")
        )
    if target.exists() and not target.is_dir():
        findings.append(
            ValidationFinding(
                "target_not_directory", FindingSeverity.ERROR, "Target is not a directory."
            )
        )
    parent = target if target.exists() else _existing_parent(target)
    if parent is None or not os.access(parent, os.W_OK):
        findings.append(
            ValidationFinding(
                "target_not_writable", FindingSeverity.ERROR, "Target is not writable."
            )
        )

    if source.kind is SourceKind.DIRECTORY:
        source_path = Path(source.location).resolve()
        if target == source_path:
            findings.append(
                ValidationFinding(
                    "target_equals_source",
                    FindingSeverity.ERROR,
                    "Target equals the source directory.",
                )
            )
        elif target.is_relative_to(source_path):
            findings.append(
                ValidationFinding(
                    "target_inside_source",
                    FindingSeverity.ERROR,
                    "Target is inside the source directory.",
                )
            )
    elif source.kind is SourceKind.PHYSICAL_DEVICE:
        findings.append(
            ValidationFinding(
                "physical_collision_unknown",
                FindingSeverity.WARNING,
                "Target backing-device collision has not been verified.",
            )
        )

    device_type = source.metadata.get("device_type")
    if device_type in {"sata_ssd", "nvme_ssd"}:
        findings.append(
            ValidationFinding(
                "trim_warning",
                FindingSeverity.WARNING,
                "SSD/NVMe source: deleted recovery may be affected by TRIM and garbage collection.",
            )
        )
    if not capability.supported:
        findings.append(
            ValidationFinding("operation_unsupported", FindingSeverity.ERROR, capability.reason)
        )
    if not findings:
        findings.append(
            ValidationFinding("workflow_ready", FindingSeverity.INFO, capability.reason)
        )
    return WorkflowValidation(tuple(findings), capability, physical_collision_checked=False)


def _existing_parent(path: Path) -> Path | None:
    candidate = path
    while candidate != candidate.parent and not candidate.exists():
        candidate = candidate.parent
    return candidate if candidate.is_dir() else None
