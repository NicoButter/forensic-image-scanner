"""Administrative model installation tests with no external network access."""

from __future__ import annotations

import hashlib
import io
import threading
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

import pytest

import forensic_image_scanner.models.downloader as downloader_module
import forensic_image_scanner.models.installation as installation_module
from forensic_image_scanner.models.downloader import SafeRedirectHandler
from forensic_image_scanner.models.exceptions import (
    InvalidManifestError,
    ModelAlreadyInstalledError,
    ModelArtifactMissingError,
    ModelBlockedError,
    ModelDownloadCancelled,
    ModelDownloadError,
    ModelHashMismatchError,
    ModelIntegrityError,
    ModelNotInstalledError,
)
from forensic_image_scanner.models.installation import ModelInstallationService
from forensic_image_scanner.models.manifest import ModelManifest
from forensic_image_scanner.models.registry import ModelRegistry


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class FakeOpener:
    payloads: dict[str, bytes]

    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.payloads = payloads

    def open(self, request: Request, timeout: float) -> FakeResponse:
        parsed = urlparse(request.full_url)
        if parsed.port == 1:
            raise URLError("simulated network failure")
        if parsed.path not in self.payloads:
            raise HTTPError(request.full_url, 404, "Not Found", {}, None)
        return FakeResponse(self.payloads[parsed.path])


@pytest.fixture
def mock_http(monkeypatch):
    payloads: dict[str, bytes] = {}
    monkeypatch.setattr(
        downloader_module, "build_opener", lambda *_handlers: FakeOpener(payloads)
    )
    return "http://127.0.0.1:8765", payloads


def make_manifest(base_url: str, model: bytes, config: bytes = b"config") -> ModelManifest:
    return ModelManifest.from_dict(
        {
            "schema_version": 1,
            "model_id": "dummy-model",
            "model_version": "immutable-revision",
            "filename": "dummy.safetensors",
            "sha256": hashlib.sha256(model).hexdigest(),
            "source": base_url,
            "source_revision": "immutable-revision",
            "source_url": f"{base_url}/dummy.safetensors",
            "code_license": "Apache-2.0",
            "weights_license": "Apache-2.0",
            "framework": "test",
            "input_size": [2, 2],
            "labels": ["normal", "nsfw"],
            "provenance_status": "partial",
            "size_bytes": len(model),
            "artifacts": [
                {
                    "filename": "config.json",
                    "sha256": hashlib.sha256(config).hexdigest(),
                    "size_bytes": len(config),
                    "source_url": f"{base_url}/config.json",
                }
            ],
        }
    )


def service_for(monkeypatch, tmp_path: Path, manifest: ModelManifest) -> ModelInstallationService:
    monkeypatch.setattr(installation_module, "load_reference_manifest", lambda _model_id: manifest)
    return ModelInstallationService(tmp_path / "models")


def assert_transactions_clean(root: Path) -> None:
    for name in (".downloads", ".installing"):
        directory = root / name
        assert not directory.exists() or not any(directory.iterdir())


def test_valid_download_installs_and_registry_detects(mock_http, monkeypatch, tmp_path) -> None:
    local_server, payloads = mock_http
    model = b"dummy weights"
    config = b'{"model_type":"test"}'
    payloads.update({"/dummy.safetensors": model, "/config.json": config})
    manifest = make_manifest(local_server, model, config)
    service = service_for(monkeypatch, tmp_path, manifest)
    progress: list[tuple[int, int]] = []

    installed = service.install_from_url(
        "dummy-model", progress=lambda done, total: progress.append((done, total))
    )

    assert installed.path.read_bytes() == model
    assert progress[-1] == (len(model) + len(config), len(model) + len(config))
    assert ModelRegistry(service.model_root).load("dummy-model").path == installed.path
    assert_transactions_clean(service.model_root)


@pytest.mark.parametrize(
    ("wrong_field", "expected_error"),
    [("sha256", ModelHashMismatchError), ("size", ModelIntegrityError)],
)
def test_invalid_download_is_rejected_and_cleaned(
    mock_http, monkeypatch, tmp_path, wrong_field, expected_error
) -> None:
    local_server, payloads = mock_http
    actual = b"actual model"
    payloads.update({"/dummy.safetensors": actual, "/config.json": b"config"})
    expected = b"x" * len(actual) if wrong_field == "sha256" else actual + b"larger"
    manifest = make_manifest(local_server, expected)
    service = service_for(monkeypatch, tmp_path, manifest)

    with pytest.raises(expected_error):
        service.install_from_url("dummy-model")

    assert not (service.model_root / "dummy-model").exists()
    assert_transactions_clean(service.model_root)


def test_cancelled_download_is_cleaned(mock_http, monkeypatch, tmp_path) -> None:
    local_server, payloads = mock_http
    model = b"x" * (2 * 1024 * 1024)
    payloads.update({"/dummy.safetensors": model, "/config.json": b"config"})
    service = service_for(monkeypatch, tmp_path, make_manifest(local_server, model))
    cancel = threading.Event()

    with pytest.raises(ModelDownloadCancelled):
        service.install_from_url(
            "dummy-model",
            progress=lambda received, _total: cancel.set() if received else None,
            cancelled=cancel.is_set,
        )

    assert_transactions_clean(service.model_root)


@pytest.mark.parametrize("path", ["/missing", "/config.json"])
def test_http_and_network_failures_are_cleaned(mock_http, monkeypatch, tmp_path, path) -> None:
    local_server, payloads = mock_http
    model = b"model"
    payloads["/config.json"] = b"config"
    manifest = make_manifest(local_server, model)
    source_url = f"{local_server}{path}" if path == "/missing" else "http://127.0.0.1:1/model"
    manifest = ModelManifest.from_dict(
        {
            "schema_version": 1,
            "model_id": "dummy-model",
            "model_version": "1",
            "filename": "dummy.safetensors",
            "sha256": hashlib.sha256(model).hexdigest(),
            "source": local_server,
            "source_revision": "1",
            "source_url": source_url,
            "code_license": "Apache-2.0",
            "weights_license": "Apache-2.0",
            "framework": "test",
            "input_size": [2, 2],
            "labels": [],
            "provenance_status": "partial",
            "size_bytes": len(model),
        }
    )
    service = service_for(monkeypatch, tmp_path, manifest)

    with pytest.raises(ModelDownloadError):
        service.install_from_url("dummy-model")
    assert_transactions_clean(service.model_root)


def test_unknown_and_blocked_models_are_rejected(tmp_path) -> None:
    service = ModelInstallationService(tmp_path)
    with pytest.raises(ModelNotInstalledError):
        service.install_from_url("unknown-model")
    with pytest.raises(ModelBlockedError):
        service.install_from_url("nudenet-320n")


def test_manifest_rejects_path_traversal(mock_http) -> None:
    local_server, _payloads = mock_http
    raw = {
        "schema_version": 1,
        "model_id": "dummy",
        "model_version": "1",
        "filename": "../model.bin",
        "sha256": "0" * 64,
        "source": local_server,
        "source_revision": "1",
        "code_license": "x",
        "weights_license": "x",
        "framework": "x",
        "input_size": [1, 1],
        "labels": [],
        "provenance_status": "partial",
    }
    with pytest.raises(InvalidManifestError):
        ModelManifest.from_dict(raw)


def test_https_downgrade_is_rejected() -> None:
    with pytest.raises(ModelDownloadError, match="downgrade"):
        SafeRedirectHandler().redirect_request(
            Request("https://example.invalid/model"),
            None,
            302,
            "Found",
            {},
            "http://example.invalid/model",
        )


def test_existing_model_is_protected(mock_http, monkeypatch, tmp_path) -> None:
    local_server, payloads = mock_http
    model = b"model"
    payloads.update({"/dummy.safetensors": model, "/config.json": b"config"})
    service = service_for(monkeypatch, tmp_path, make_manifest(local_server, model))
    service.install_from_url("dummy-model")
    with pytest.raises(ModelAlreadyInstalledError, match="already installed"):
        service.install_from_url("dummy-model")


def test_local_directory_import_and_remove(mock_http, monkeypatch, tmp_path) -> None:
    local_server, _payloads = mock_http
    model = b"local model"
    config = b"local config"
    manifest = make_manifest(local_server, model, config)
    service = service_for(monkeypatch, tmp_path, manifest)
    source = tmp_path / "source"
    source.mkdir()
    (source / "dummy.safetensors").write_bytes(model)
    (source / "config.json").write_bytes(config)

    service.install_from_file("dummy-model", source)
    assert service.verify_installed("dummy-model").path.is_file()
    service.remove("dummy-model")
    assert not service.is_installed("dummy-model")


def test_bad_or_symlinked_local_import_is_rejected(mock_http, monkeypatch, tmp_path) -> None:
    local_server, _payloads = mock_http
    model = b"local model"
    service = service_for(monkeypatch, tmp_path, make_manifest(local_server, model))
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(model)
    (source / "dummy.safetensors").symlink_to(outside)
    (source / "config.json").write_bytes(b"config")

    with pytest.raises(ModelArtifactMissingError):
        service.install_from_file("dummy-model", source)
    assert_transactions_clean(service.model_root)
