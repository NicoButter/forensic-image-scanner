"""Core-side client for the optional NudeNet process. No runtime imports."""

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from queue import Empty, Queue

from forensic_image_scanner.detectors.exceptions import DetectorError
from forensic_image_scanner.models.references import load_reference_manifest
from forensic_image_scanner.models.registry import ModelRegistry
from forensic_image_scanner.results import AnatomicalDetection, NudeNetResult

NUDENET_VARIANTS = ("320n", "640m")
DEFAULT_VARIANT = NUDENET_VARIANTS[0]
NUDENET_VERSION = "3.4.2"
STARTUP_TIMEOUT = 30.0
INFERENCE_TIMEOUT = 20.0
MAX_RESPONSE = 1024 * 1024
LOGGER = logging.getLogger(__name__)


class BackendError(DetectorError):
    """A sanitized NudeNet process, transport or protocol failure."""


def runtime_directory(root: Path) -> Path:
    return root / "runtime" / "nudenet"


def runtime_python(directory: Path) -> Path:
    return directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def backend_disabled(root: Path, variant: str) -> bool:
    return not (runtime_directory(root) / f"enabled-{variant}").is_file()


def set_backend_enabled(root: Path, variant: str, enabled: bool) -> None:
    if variant not in NUDENET_VARIANTS:
        raise ValueError("unknown NudeNet variant")
    directory = runtime_directory(root)
    marker = directory / f"enabled-{variant}"
    if enabled:
        directory.mkdir(parents=True, exist_ok=True)
        marker.touch()
    else:
        marker.unlink(missing_ok=True)


class NudeNetClient:
    """One child and one request at a time, with a deadline covering all pipe I/O."""

    def __init__(
        self,
        command: list[str],
        variant: str,
        digest: str,
        labels: tuple[str, ...],
        *,
        startup_timeout: float = STARTUP_TIMEOUT,
        inference_timeout: float = INFERENCE_TIMEOUT,
    ) -> None:
        self.command = command
        self.variant = variant
        self.digest = digest
        self.labels = frozenset(labels)
        self.startup_timeout = startup_timeout
        self.inference_timeout = inference_timeout
        self.process: subprocess.Popen | None = None
        self.health: dict = {}

    @classmethod
    def from_registry(
        cls, root: Path, variant: str, source: Path, *, require_enabled: bool = True
    ) -> "NudeNetClient":
        if variant not in NUDENET_VARIANTS:
            raise BackendError("NudeNet variant is unavailable")
        interpreter = runtime_python(runtime_directory(root) / "env")
        if not interpreter.is_file():
            raise BackendError("NudeNet runtime is not installed")
        model_id = f"nudenet-{variant}"
        if not (root / model_id / "manifest.json").is_file():
            raise BackendError("NudeNet model is not installed")
        if require_enabled and backend_disabled(root, variant):
            raise BackendError("NudeNet backend is disabled")
        reference = load_reference_manifest(model_id)
        model = ModelRegistry(root).load(model_id)
        if (
            model.manifest.sha256 != reference.sha256
            or model.manifest.filename != reference.filename
            or model.manifest.input_size != reference.input_size
        ):
            raise BackendError("NudeNet artifact differs from the audited reference")
        worker = Path(__file__).resolve().parents[2] / "fis_nudenet_backend" / "worker.py"
        return cls(
            [
                str(interpreter),
                "-I",
                str(worker),
                str(model.path),
                reference.sha256,
                str(reference.input_size[0]),
                str(source.resolve()),
            ],
            variant,
            reference.sha256,
            reference.labels,
        )

    def __enter__(self) -> "NudeNetClient":
        LOGGER.debug("Starting NudeNet %s", self.variant)
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise BackendError("Could not start NudeNet runtime") from exc
        try:
            self.health = self._exchange("health", self.startup_timeout)
            expected = {
                "status": "ready",
                "backend": "nudenet",
                "backend_version": NUDENET_VERSION,
                "model": self.variant,
                "model_sha256": self.digest,
                "license": "AGPL-3.0",
            }
            if any(self.health.get(key) != value for key, value in expected.items()):
                raise BackendError("NudeNet health check failed")
        except BaseException:
            self.close()
            raise
        LOGGER.info("NudeNet ready: %s %s", self.variant, self.digest)
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def close(self) -> None:
        process, self.process = self.process, None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for pipe in (process.stdin, process.stdout):
            if pipe is not None:
                pipe.close()

    def analyze(self, path: Path) -> NudeNetResult:
        start = time.monotonic()
        try:
            response = self._exchange("analyze", self.inference_timeout, image_path=str(path))
            if response.get("status") != "ok":
                raise BackendError("NudeNet inference failed")
            raw = response.get("detections")
            if not isinstance(raw, list):
                raise BackendError("Malformed NudeNet detections")
            detections = tuple(self._detection(row) for row in raw)
            LOGGER.debug("NudeNet %s request OK in %.3fs", self.variant, time.monotonic() - start)
            return NudeNetResult(
                self.variant,
                "OK",
                detections,
                model_sha256=self.digest,
                backend_version=self.health["backend_version"],
            )
        except BackendError as exc:
            LOGGER.warning("NudeNet %s: %s", self.variant, exc)
            return NudeNetResult(
                self.variant,
                "ERROR",
                error=str(exc),
                model_sha256=self.digest,
                backend_version=self.health.get("backend_version"),
            )

    def _detection(self, row) -> AnatomicalDetection:
        if not isinstance(row, dict):
            raise BackendError("Malformed NudeNet detection")
        label, score, box = row.get("class"), row.get("confidence"), row.get("box")
        if (
            not isinstance(label, str)
            or label not in self.labels
            or type(score) not in {int, float}
            or not 0 <= score <= 1
            or not isinstance(box, list)
            or len(box) != 4
            or any(type(value) is not int or value < 0 for value in box)
        ):
            raise BackendError("Invalid NudeNet class, confidence or box")
        return AnatomicalDetection(label, float(score), tuple(box))

    def _exchange(self, operation: str, timeout: float, **fields) -> dict:
        process = self.process
        if process is None or process.poll() is not None:
            raise BackendError("NudeNet backend stopped")
        assert process.stdin is not None and process.stdout is not None
        request = json.dumps({"schema_version": 1, "operation": operation, **fields})
        responses: Queue = Queue(maxsize=1)

        def transfer():
            try:
                process.stdin.write(request.encode() + b"\n")
                process.stdin.flush()
                responses.put(process.stdout.readline(MAX_RESPONSE + 1))
            except (OSError, ValueError):
                responses.put(b"")

        threading.Thread(target=transfer, daemon=True).start()
        try:
            line = responses.get(timeout=timeout)
        except Empty:
            self.close()
            raise BackendError(f"NudeNet {operation} timed out") from None
        try:
            if not line.endswith(b"\n") or len(line) > MAX_RESPONSE:
                raise ValueError
            data = json.loads(line)
            if (
                not isinstance(data, dict)
                or type(data.get("schema_version")) is not int
                or data["schema_version"] != 1
            ):
                raise ValueError
        except (UnicodeError, ValueError, RecursionError):
            self.close()
            raise BackendError("Malformed or missing NudeNet response") from None
        return data



def enable_verified_backend(root: Path, variant: str, source: Path) -> dict:
    """Persist opt-in after a successful health exchange."""
    with NudeNetClient.from_registry(root, variant, source, require_enabled=False) as backend:
        health = backend.health
    set_backend_enabled(root, variant, True)
    return health
