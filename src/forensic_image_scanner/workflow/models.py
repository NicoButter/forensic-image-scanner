"""Qt-independent immutable workflow value objects."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class SourceKind(StrEnum):
    DIRECTORY = "directory"
    FORENSIC_IMAGE = "forensic_image"
    PHYSICAL_DEVICE = "physical_device"


class OperationMode(StrEnum):
    RECOVER = "recover"
    RECOVER_ANALYZE = "recover_analyze"
    ANALYZE = "analyze"


class CandidateImageFormat(StrEnum):
    RAW = "raw"
    EWF = "ewf"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SourceDescriptor:
    kind: SourceKind
    location: str
    display_name: str
    exists: bool
    read_only_required: bool
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SourceKind):
            raise TypeError("source kind must be SourceKind")
        if type(self.exists) is not bool or type(self.read_only_required) is not bool:
            raise TypeError("source state flags must be bool")
        if not self.location.strip() or not self.display_name.strip():
            raise ValueError("source location and display name are required")
        if self.kind is not SourceKind.DIRECTORY and not self.read_only_required:
            raise ValueError("forensic images and physical devices require read-only access")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class TargetDescriptor:
    path: Path

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("target path must be pathlib.Path")
        if str(self.path) in {"", "."}:
            raise ValueError("target path is required")


@dataclass(frozen=True, slots=True)
class WorkflowRequest:
    source: SourceDescriptor
    target: TargetDescriptor
    operation: OperationMode
    case_metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceDescriptor):
            raise TypeError("workflow source must be SourceDescriptor")
        if not isinstance(self.target, TargetDescriptor):
            raise TypeError("workflow target must be TargetDescriptor")
        if not isinstance(self.operation, OperationMode):
            raise TypeError("operation must be OperationMode")
        object.__setattr__(self, "case_metadata", MappingProxyType(dict(self.case_metadata)))
