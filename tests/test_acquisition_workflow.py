"""Physical handoff never invokes analysis on the physical device."""

from pathlib import Path
from types import SimpleNamespace

from forensic_image_scanner.acquisition import (
    AcquisitionMethod,
    AcquisitionRequest,
    VerificationStatus,
)
from forensic_image_scanner.acquisition.workflow import PhysicalAcquisitionWorkflow
from forensic_image_scanner.pipeline import PipelineRequest
from forensic_image_scanner.workflow import OperationMode


def test_acquired_image_is_pipeline_source(tmp_path, monkeypatch):
    import forensic_image_scanner.acquisition.workflow as workflow

    target = tmp_path / "case"
    image = target / "acquisition/source.E01"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"image")
    acquisition = SimpleNamespace(
        completed=True,
        cancelled=False,
        output=str(image),
        method=AcquisitionMethod.E01,
        verification=VerificationStatus.VERIFIED,
    )
    calls = []

    class Acquirer:
        def acquire(self, *args, **kwargs):
            return acquisition

    class Pipeline:
        def run(self, request, **kwargs):
            calls.append(request.source)
            return "done"

    monkeypatch.setattr(workflow, "AcquisitionService", Acquirer)
    monkeypatch.setattr(workflow, "RecoveryAnalysisPipeline", Pipeline)
    request = AcquisitionRequest(Path("/dev/fake"), target, AcquisitionMethod.E01)
    result = PhysicalAcquisitionWorkflow().run(
        request,
        OperationMode.RECOVER_ANALYZE,
        filesystem=False,
        carving=True,
        pipeline=PipelineRequest(Path("/dev/fake"), target, tmp_path / "models"),
    )
    assert result.downstream == "done" and calls == [image.resolve()]
    acquisition.completed = False
    result = PhysicalAcquisitionWorkflow().run(
        request,
        OperationMode.RECOVER_ANALYZE,
        filesystem=False,
        carving=True,
        pipeline=PipelineRequest(Path("/dev/fake"), target, tmp_path / "models"),
    )
    assert result.downstream is None and calls == [image.resolve()]
