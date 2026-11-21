"""Explicit installation of the audited NudeNet wheel in a separate environment."""

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from forensic_image_scanner.detectors.nudenet import (
    DEFAULT_VARIANT,
    enable_verified_backend,
    runtime_directory,
    runtime_python,
)
from forensic_image_scanner.models.downloader import download_verified
from forensic_image_scanner.models.exceptions import ModelDownloadCancelled, ModelDownloadError
from forensic_image_scanner.models.installation import ModelInstallationService
from forensic_image_scanner.models.references import load_reference_manifest

WHEEL = "nudenet-3.4.2-py3-none-any.whl"
WHEEL_URL = (
    "https://files.pythonhosted.org/packages/1c/ee/"
    "1aa02d44ba958cc77e16ff1e41a0aac5e721037db7bf62b9c9d124917f87/" + WHEEL
)
WHEEL_SIZE = 10595223
WHEEL_SHA256 = "5937dbd84e5d8e5de038f08ffea5a1bb50a08475776bf2b4795914ce0eaf0331"


def install_nudenet(
    root: Path,
    variant: str = DEFAULT_VARIANT,
    *,
    python: str | None = None,
    progress=None,
    phase=None,
    cancelled=None,
) -> dict:
    """Download on explicit request, verify artifacts and publish the runtime."""
    root = root.expanduser().resolve()
    if any((parent / ".git").exists() for parent in (root, *root.parents)):
        raise ValueError("NudeNet runtime must be installed outside a Git repository")
    model_id = f"nudenet-{variant}"
    manifest = load_reference_manifest(model_id)
    base = runtime_directory(root)
    base.mkdir(parents=True, exist_ok=True)
    target = base / "env"
    installer = ModelInstallationService(root)
    with tempfile.TemporaryDirectory(prefix=".install-", dir=base) as temporary:
        stage = Path(temporary)
        wheel = stage / WHEEL
        if phase is not None:
            phase("downloading")
        download_verified(
            WHEEL_URL, wheel, WHEEL_SIZE, WHEEL_SHA256, progress=progress, cancelled=cancelled
        )
        if phase is not None:
            phase("installing")
        staged_env = stage / "env"
        if not runtime_python(target).is_file():
            interpreter = python or os.environ.get("FORENSIC_IMAGE_SCANNER_NUDENET_PYTHON")
            _run_install([interpreter or sys.executable, "-I", "-m", "venv", str(staged_env)])
            _run_install(
                [
                    str(runtime_python(staged_env)),
                    "-I",
                    "-m",
                    "pip",
                    "--isolated",
                    "--disable-pip-version-check",
                    "install",
                    "--only-binary=:all:",
                    "--index-url",
                    "https://pypi.org/simple",
                    str(wheel),
                ]
            )
        if cancelled is not None and cancelled():
            raise ModelDownloadCancelled("NudeNet setup cancelled")
        if not installer.is_installed(model_id):
            payload = stage / manifest.filename
            if variant == "320n":
                with (
                    zipfile.ZipFile(wheel) as archive,
                    archive.open("nudenet/320n.onnx") as source,
                    payload.open("xb") as output,
                ):
                    shutil.copyfileobj(source, output)
            else:
                assert manifest.source_url and manifest.size_bytes
                if phase is not None:
                    phase("downloading")
                download_verified(
                    manifest.source_url,
                    payload,
                    manifest.size_bytes,
                    manifest.sha256,
                    progress=progress,
                    cancelled=cancelled,
                )
            installer.install_from_file(model_id, stage, phase=phase)
        if staged_env.is_dir():
            try:
                os.rename(staged_env, target)
            except OSError:
                if not runtime_python(target).is_file():
                    raise
        return enable_verified_backend(root, variant, base)


def _run_install(command: list[str]) -> None:
    try:
        subprocess.run(
            command,
            check=True,
            timeout=240,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ModelDownloadError(
            "NudeNet runtime setup failed; select a Python with ONNX Runtime wheels"
        ) from exc
