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
    kind: SourceKind,
    operation: OperationMode,
    *,
    tsk_available: bool = False,
    carving_available: bool = False,
    analysis_available: bool = False,
    acquisition_available: bool = False,
    acquisition_safe: bool = False,
) -> WorkflowCapability:
    if kind is SourceKind.DIRECTORY and operation is OperationMode.ANALYZE:
        return WorkflowCapability(True, "Directory analysis is supported.")
    if kind is SourceKind.PHYSICAL_DEVICE and operation in {
        OperationMode.RECOVER,
        OperationMode.RECOVER_ANALYZE,
    }:
        if not acquisition_available or not acquisition_safe:
            return WorkflowCapability(False, "Safe acquisition and its tools are required.")
        if not (tsk_available or carving_available):
            return WorkflowCapability(False, "A recovery engine is required.")
        if operation is OperationMode.RECOVER_ANALYZE and not analysis_available:
            return WorkflowCapability(False, "A usable analysis profile is required.")
        return WorkflowCapability(True, "Acquire the device before recovery.")
    if kind is SourceKind.FORENSIC_IMAGE and operation in {
        OperationMode.RECOVER,
        OperationMode.RECOVER_ANALYZE,
    }:
        if operation is OperationMode.RECOVER_ANALYZE and not analysis_available:
            return WorkflowCapability(False, "A usable analysis profile is required.")
        if tsk_available or carving_available:
            methods = []
            if tsk_available:
                methods.append("TSK filesystem metadata recovery")
            if carving_available:
                methods.append("PhotoRec multimedia carving")
            return WorkflowCapability(True, " and ".join(methods) + " is available.")
        return WorkflowCapability(False, "Recovery requires The Sleuth Kit and/or PhotoRec.")
    if operation is OperationMode.RECOVER_ANALYZE:
        return WorkflowCapability(False, "Recovery + analysis will be enabled in FIS-015.")
    if operation in {OperationMode.RECOVER, OperationMode.RECOVER_ANALYZE}:
        return WorkflowCapability(
            False,
            "Filesystem recovery is not enabled for this source type.",
        )
    return WorkflowCapability(False, "Analysis for this source type is not implemented yet.")


def validate_workflow(
    request: WorkflowRequest,
    *,
    tsk_available: bool = False,
    carving_available: bool = False,
    analysis_available: bool = False,
    acquisition_available: bool = False,
    acquisition_safety=None,
) -> WorkflowValidation:
    findings: list[ValidationFinding] = []
    source = request.source
    target = request.target.path.expanduser().resolve()
    capability = capability_for(
        source.kind,
        request.operation,
        tsk_available=tsk_available,
        carving_available=carving_available,
        analysis_available=analysis_available,
        acquisition_available=acquisition_available,
        acquisition_safe=bool(acquisition_safety and acquisition_safety.allowed),
    )

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
        if acquisition_safety is None:
            findings.append(
                ValidationFinding(
                    "physical_collision_unknown",
                    FindingSeverity.ERROR,
                    "Acquisition safety has not been verified.",
                )
            )
        else:
            findings.extend(
                ValidationFinding(code, FindingSeverity.ERROR, code)
                for code in acquisition_safety.errors
            )
            findings.extend(
                ValidationFinding(code, FindingSeverity.WARNING, code)
                for code in acquisition_safety.warnings
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
    return WorkflowValidation(
        tuple(findings),
        capability,
        physical_collision_checked=bool(acquisition_safety and acquisition_safety.target_disks),
    )


def _existing_parent(path: Path) -> Path | None:
    candidate = path
    while candidate != candidate.parent and not candidate.exists():
        candidate = candidate.parent
    return candidate if candidate.is_dir() else None
