"""Typed workflow models, capability boundaries and target safety."""

from pathlib import Path

import pytest

from forensic_image_scanner.scoring.ensemble import AnalysisProfile
from forensic_image_scanner.workflow import (
    CandidateImageFormat,
    FindingSeverity,
    OperationMode,
    SourceDescriptor,
    SourceKind,
    TargetDescriptor,
    WorkflowRequest,
    capability_for,
    validate_workflow,
)
from forensic_image_scanner.workflow.source_inspection import (
    candidate_image_format,
    inspect_directory,
    inspect_forensic_image,
)


def test_enum_values_are_stable() -> None:
    assert [item.value for item in SourceKind] == [
        "directory",
        "forensic_image",
        "physical_device",
    ]
    assert [item.value for item in OperationMode] == [
        "recover",
        "recover_analyze",
        "analyze",
    ]


def test_descriptors_are_immutable_and_validate_state(tmp_path) -> None:
    source = inspect_directory(tmp_path)
    target = TargetDescriptor(tmp_path.parent / "case")
    request = WorkflowRequest(source, target, OperationMode.ANALYZE, {"case_id": "future"})
    assert request.source.metadata["access"] == "read_only"
    with pytest.raises(TypeError):
        request.source.metadata["changed"] = True
    with pytest.raises(TypeError):
        SourceDescriptor("directory", "/x", "x", True, True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="read-only"):
        SourceDescriptor(SourceKind.PHYSICAL_DEVICE, "/dev/x", "x", True, False)
    with pytest.raises(ValueError, match="target"):
        TargetDescriptor(Path(""))
    with pytest.raises(TypeError, match="operation"):
        WorkflowRequest(source, target, "analyze")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="source"):
        WorkflowRequest("/x", target, OperationMode.ANALYZE)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="target"):
        WorkflowRequest(source, Path("/x"), OperationMode.ANALYZE)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kind", "operation", "supported"),
    [
        (SourceKind.DIRECTORY, OperationMode.ANALYZE, True),
        (SourceKind.DIRECTORY, OperationMode.RECOVER, False),
        (SourceKind.DIRECTORY, OperationMode.RECOVER_ANALYZE, False),
        (SourceKind.FORENSIC_IMAGE, OperationMode.RECOVER, False),
        (SourceKind.FORENSIC_IMAGE, OperationMode.ANALYZE, False),
        (SourceKind.PHYSICAL_DEVICE, OperationMode.RECOVER, False),
        (SourceKind.PHYSICAL_DEVICE, OperationMode.ANALYZE, False),
    ],
)
def test_capability_matrix(kind, operation, supported) -> None:
    capability = capability_for(kind, operation)
    assert capability.supported is supported
    assert capability.reason


def test_target_collision_and_separate_target(tmp_path) -> None:
    source_path = tmp_path / "evidence"
    source_path.mkdir()
    source = inspect_directory(source_path)

    equal = WorkflowRequest(source, TargetDescriptor(source_path), OperationMode.ANALYZE)
    child = WorkflowRequest(
        source, TargetDescriptor(source_path / "reports"), OperationMode.ANALYZE
    )
    separate = WorkflowRequest(source, TargetDescriptor(tmp_path / "case"), OperationMode.ANALYZE)
    assert {finding.code for finding in validate_workflow(equal).findings} >= {
        "target_equals_source"
    }
    assert {finding.code for finding in validate_workflow(child).findings} >= {
        "target_inside_source"
    }
    validation = validate_workflow(separate)
    assert validation.executable
    assert validation.findings[0].severity is FindingSeverity.INFO


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("case.dd", CandidateImageFormat.RAW),
        ("case.RAW", CandidateImageFormat.RAW),
        ("case.img", CandidateImageFormat.RAW),
        ("case.E01", CandidateImageFormat.EWF),
        ("case.Ex01", CandidateImageFormat.EWF),
        ("case.zip", CandidateImageFormat.UNKNOWN),
    ],
)
def test_forensic_image_candidate_format_is_explicitly_unverified(tmp_path, name, expected) -> None:
    path = tmp_path / name
    path.write_bytes(b"candidate only")
    descriptor = inspect_forensic_image(path)
    assert candidate_image_format(path) is expected
    assert descriptor.metadata["candidate_format"] == expected.value
    assert descriptor.metadata["format_verified"] is False
    assert descriptor.read_only_required


def test_physical_collision_is_reported_unknown(tmp_path) -> None:
    source = SourceDescriptor(
        SourceKind.PHYSICAL_DEVICE,
        "/dev/fake",
        "Fake SSD",
        True,
        True,
        {"device_type": "nvme_ssd"},
    )
    validation = validate_workflow(
        WorkflowRequest(source, TargetDescriptor(tmp_path / "case"), OperationMode.RECOVER)
    )
    codes = {finding.code for finding in validation.findings}
    assert {"physical_collision_unknown", "trim_warning", "operation_unsupported"} <= codes
    assert not validation.physical_collision_checked
    assert not validation.executable


def test_supported_workflow_adapts_to_existing_analysis_request(tmp_path) -> None:
    source_path = tmp_path / "evidence"
    source_path.mkdir()
    target_path = tmp_path / "case"
    workflow = WorkflowRequest(
        inspect_directory(source_path), TargetDescriptor(target_path), OperationMode.ANALYZE
    )
    from forensic_image_scanner.workflow import analysis_request_from_workflow

    request = analysis_request_from_workflow(
        workflow,
        model="Falconsai/nsfw_image_detection",
        profile=AnalysisProfile.FALCONSAI,
        nudenet_variant="320n",
    )
    assert request.source == source_path
    assert request.output == target_path


def test_unsupported_workflow_cannot_reach_analysis_request(tmp_path) -> None:
    workflow = WorkflowRequest(
        inspect_directory(tmp_path),
        TargetDescriptor(tmp_path.parent / "case"),
        OperationMode.RECOVER,
    )
    from forensic_image_scanner.workflow import analysis_request_from_workflow

    with pytest.raises(ValueError, match="cannot be executed"):
        analysis_request_from_workflow(
            workflow,
            model="unused",
            profile=AnalysisProfile.FALCONSAI,
            nudenet_variant="320n",
        )


def test_forensic_image_recovery_requires_tsk_and_valid_target(tmp_path) -> None:
    image = tmp_path / "case.dd"
    image.write_bytes(b"image")
    workflow = WorkflowRequest(
        inspect_forensic_image(image),
        TargetDescriptor(tmp_path / "case-output"),
        OperationMode.RECOVER,
    )
    assert not validate_workflow(workflow).executable
    assert validate_workflow(workflow, tsk_available=True).executable
    assert validate_workflow(workflow, carving_available=True).executable
    assert not capability_for(
        SourceKind.PHYSICAL_DEVICE, OperationMode.RECOVER, tsk_available=True
    ).supported
    assert not capability_for(
        SourceKind.FORENSIC_IMAGE, OperationMode.RECOVER_ANALYZE, tsk_available=True
    ).supported
