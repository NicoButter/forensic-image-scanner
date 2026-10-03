"""Offline-only Falconsai ViT classifier."""

import os
import platform
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Protocol

from PIL import Image

from forensic_image_scanner import __version__
from forensic_image_scanner.detectors.base import Detector, DetectorOutput
from forensic_image_scanner.detectors.exceptions import InferenceError
from forensic_image_scanner.models.manifest import ProvenanceStatus
from forensic_image_scanner.models.registry import VerifiedModel
from forensic_image_scanner.results import Detection

MODEL_STATUS = ProvenanceStatus.PARTIAL


class FalconsaiRuntime(Protocol):
    """Minimal local runtime boundary, allowing offline unit tests without Torch."""

    def predict(self, image: Image.Image) -> list[float]:
        """Return probabilities ordered as the verified manifest labels."""

    def metadata(self) -> dict[str, Any]:
        """Return local runtime context."""


RuntimeFactory = Callable[[VerifiedModel], FalconsaiRuntime]


class FalconsaiDetector(Detector):
    """Classify one in-memory RGB image using only registry-verified local artifacts."""

    def __init__(
        self, model: VerifiedModel, *, runtime_factory: RuntimeFactory | None = None
    ) -> None:
        self.model = model
        self._runtime_factory = runtime_factory or _load_local_runtime
        self._runtime: FalconsaiRuntime | None = None

    def analyze(self, image: Image.Image) -> DetectorOutput:
        """Run CPU inference and return only the model's normal/nsfw categories."""
        runtime = self._runtime or self._runtime_factory(self.model)
        self._runtime = runtime
        try:
            probabilities = runtime.predict(image.convert("RGB"))
        except InferenceError:
            raise
        except Exception as exc:
            raise InferenceError(f"Falconsai local inference failed: {exc}") from exc

        labels = self.model.manifest.labels
        if len(probabilities) != len(labels):
            raise InferenceError(
                f"model returned {len(probabilities)} scores for {len(labels)} verified labels"
            )
        scores = dict(zip(labels, probabilities, strict=True))
        top_label = max(scores, key=scores.__getitem__)
        confidence = scores[top_label]
        return DetectorOutput(
            detector_name="falconsai-nsfw-image-detection",
            detector_version=__version__,
            model_name=self.model.manifest.model_id,
            model_version=self.model.manifest.model_version,
            model_sha256=self.model.manifest.sha256,
            detections=[Detection(label=top_label, confidence=confidence)],
            scores=scores,
            top_label=top_label,
            confidence=confidence,
            provenance_status=self.model.manifest.provenance_status.value,
            runtime=runtime.metadata(),
        )


def _load_local_runtime(model: VerifiedModel) -> FalconsaiRuntime:
    """Load only local, verified Safetensors and JSON configuration on CPU."""
    _set_offline_environment()
    try:
        import torch
        from transformers import AutoImageProcessor, AutoModelForImageClassification
    except ImportError as exc:
        raise InferenceError(
            "Falconsai runtime requires Transformers/Safetensors plus a CPU PyTorch wheel; "
            "see README.md"
        ) from exc

    required = {"config.json", "preprocessor_config.json"}
    missing = required - model.auxiliary_paths.keys()
    if missing:
        raise InferenceError(
            f"verified model is missing required artifacts: {', '.join(sorted(missing))}"
        )

    model_directory = model.path.parent
    try:
        torch.use_deterministic_algorithms(True, warn_only=True)
        torch.set_grad_enabled(False)
        processor = AutoImageProcessor.from_pretrained(
            model_directory,
            local_files_only=True,
            trust_remote_code=False,
        )
        loaded_model = AutoModelForImageClassification.from_pretrained(
            model_directory,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
        loaded_model.to("cpu")
        loaded_model.eval()
    except Exception as exc:
        raise InferenceError(f"unable to load verified local Falconsai artifacts: {exc}") from exc
    return _TransformersRuntime(torch, processor, loaded_model)


class _TransformersRuntime:
    """CPU inference implementation isolated from the public detector API."""

    def __init__(self, torch: Any, processor: Any, model: Any) -> None:
        self._torch = torch
        self._processor = processor
        self._model = model

    def predict(self, image: Image.Image) -> list[float]:
        """Preprocess in memory and return a normalized CPU softmax vector."""
        try:
            inputs = self._processor(images=image, return_tensors="pt")
            inputs = {name: value.to("cpu") for name, value in inputs.items()}
            with self._torch.inference_mode():
                logits = self._model(**inputs).logits
                probabilities = self._torch.softmax(logits, dim=-1)[0].cpu().tolist()
        except Exception as exc:
            raise InferenceError(f"Falconsai CPU inference failed: {exc}") from exc
        return [float(value) for value in probabilities]

    def metadata(self) -> dict[str, Any]:
        """Return versions relevant to reproducibility, excluding host-sensitive details."""
        return {
            "device": "cpu",
            "python_version": platform.python_version(),
            "forensic_image_scanner_version": __version__,
            "torch_version": _installed_version("torch"),
            "transformers_version": _installed_version("transformers"),
            "safetensors_version": _installed_version("safetensors"),
            "pillow_version": _installed_version("Pillow"),
            "offline": True,
            "deterministic_algorithms_requested": True,
        }


def _set_offline_environment() -> None:
    """Disable Hugging Face/Transformers network behavior before importing them."""
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"


def _installed_version(distribution: str) -> str | None:
    """Return a package version when present without importing unrelated packages."""
    try:
        return version(distribution)
    except PackageNotFoundError:
        return None
