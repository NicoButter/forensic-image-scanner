"""Bounded, streaming HTTP downloader for explicit model administration."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from forensic_image_scanner.models.exceptions import (
    ModelDownloadCancelled,
    ModelDownloadError,
    ModelHashMismatchError,
    ModelIntegrityError,
)

LOGGER = logging.getLogger(__name__)
DEFAULT_CHUNK_SIZE = 1024 * 1024


class SafeRedirectHandler(HTTPRedirectHandler):
    """Limit redirects and forbid HTTPS-to-HTTP downgrade."""

    def __init__(self, max_redirects: int = 5) -> None:
        super().__init__()
        self.max_redirects = max_redirects

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirects = int(req.headers.get("X-Fis-Redirect-Count", "0"))
        if redirects >= self.max_redirects:
            raise ModelDownloadError("too many HTTP redirects")
        resolved = urljoin(req.full_url, newurl)
        old_scheme = urlparse(req.full_url).scheme.lower()
        new_scheme = urlparse(resolved).scheme.lower()
        if new_scheme not in {"http", "https"}:
            raise ModelDownloadError(f"unsupported redirect scheme: {new_scheme}")
        if old_scheme == "https" and new_scheme != "https":
            raise ModelDownloadError("HTTPS downgrade redirect rejected")
        redirected = super().redirect_request(req, fp, code, msg, headers, resolved)
        if redirected is not None:
            redirected.add_header("X-Fis-Redirect-Count", str(redirects + 1))
        return redirected


def download_verified(
    url: str,
    destination: Path,
    expected_size: int,
    expected_sha256: str,
    *,
    progress: Callable[[int, int], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    timeout: float = 30.0,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Stream one artifact to a temporary file and verify size and SHA-256."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ModelDownloadError("model URL must use HTTP or HTTPS")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ModelDownloadError("unencrypted model downloads are restricted to loopback tests")

    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    received = 0
    finished = False
    request = Request(url, headers={"User-Agent": "forensic-image-scanner/0.1"})
    opener = build_opener(SafeRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response, destination.open("xb") as output:
            while True:
                if cancelled is not None and cancelled():
                    raise ModelDownloadCancelled("model download cancelled")
                block = response.read(chunk_size)
                if not block:
                    break
                output.write(block)
                digest.update(block)
                received += len(block)
                if received > expected_size:
                    raise ModelIntegrityError(
                        f"download exceeds declared size {expected_size} bytes"
                    )
                if progress is not None:
                    progress(received, expected_size)
            finished = True
    except ModelDownloadCancelled:
        raise
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ModelDownloadError(f"download failed for {url}: {exc}") from exc
    finally:
        if destination.exists() and (
            not finished
            or received != expected_size
            or digest.hexdigest() != expected_sha256
        ):
            destination.unlink()

    if received != expected_size:
        raise ModelIntegrityError(
            f"download size mismatch: expected {expected_size}, found {received}"
        )
    if digest.hexdigest() != expected_sha256:
        raise ModelHashMismatchError(
            f"download SHA-256 mismatch: expected {expected_sha256}, found {digest.hexdigest()}"
        )
    LOGGER.info("download completed: %s (%d bytes)", destination.name, received)
