"""Versioned model manifest parsing and validation."""

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from forensic_image_scanner.models.exceptions import InvalidManifestError

SUPPORTED_SCHEMA_VERSION = 1
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ProvenanceStatus(StrEnum):
    """Audit state controlling whether a model may be loaded."""

    VERIFIED = "verified"
    PARTIAL = "partial"
    BLOCKED_PROVENANCE = "blocked_provenance"
    BLOCKED_LICENSE = "blocked_license"

    @property
    def is_blocked(self) -> bool:
        """Return whether policy forbids loading this model."""
        return self in {self.BLOCKED_PROVENANCE, self.BLOCKED_LICENSE}


@dataclass(frozen=True, slots=True)
class ArtifactManifest:
    """Integrity metadata for one auxiliary local artifact."""

    filename: str
    sha256: str
    size_bytes: int
    source_url: str | None = None


@dataclass(frozen=True, slots=True)
class ModelManifest:
    """Validated schema-v1 metadata for exactly one primary model artifact."""

    schema_version: int
    model_id: str
    model_version: str
    filename: str
    sha256: str
    source: str
    source_revision: str
    code_license: str
    weights_license: str
    framework: str
    input_size: tuple[int, int]
    labels: tuple[str, ...]
    provenance_status: ProvenanceStatus
    size_bytes: int | None = None
    artifacts: tuple[ArtifactManifest, ...] = ()
    source_url: str | None = None

    @classmethod
    def from_file(cls, path: Path) -> "ModelManifest":
        """Read and validate a UTF-8 JSON manifest."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise InvalidManifestError(f"Cannot read manifest {path}: {exc}") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Any) -> "ModelManifest":
        """Validate an untrusted decoded JSON value."""
        if not isinstance(raw, dict):
            raise InvalidManifestError("manifest root must be a JSON object")

        required = {
            "schema_version",
            "model_id",
            "model_version",
            "filename",
            "sha256",
            "source",
            "source_revision",
            "code_license",
            "weights_license",
            "framework",
            "input_size",
            "labels",
            "provenance_status",
        }
        optional = {"size_bytes", "artifacts", "source_url"}
        missing = required - raw.keys()
        unknown = raw.keys() - required - optional
        if missing:
            raise InvalidManifestError(f"missing manifest fields: {', '.join(sorted(missing))}")
        if unknown:
            raise InvalidManifestError(f"unknown manifest fields: {', '.join(sorted(unknown))}")

        if raw["schema_version"] != SUPPORTED_SCHEMA_VERSION:
            raise InvalidManifestError(
                f"unsupported schema_version {raw['schema_version']!r}; "
                f"expected {SUPPORTED_SCHEMA_VERSION}"
            )

        string_fields = required - {"schema_version", "input_size", "labels"}
        for field_name in string_fields:
            if not isinstance(raw[field_name], str) or not raw[field_name].strip():
                raise InvalidManifestError(f"{field_name} must be a non-empty string")

        filename = raw["filename"]
        if Path(filename).name != filename or filename in {".", ".."}:
            raise InvalidManifestError("filename must be a plain filename without directories")
        if not SHA256_PATTERN.fullmatch(raw["sha256"]):
            raise InvalidManifestError(
                "sha256 must contain exactly 64 lowercase hexadecimal digits"
            )

        input_size = raw["input_size"]
        if (
            not isinstance(input_size, list)
            or len(input_size) != 2
            or any(
                not isinstance(value, int) or isinstance(value, bool) or value <= 0
                for value in input_size
            )
        ):
            raise InvalidManifestError("input_size must contain two positive integers")

        labels = raw["labels"]
        if not isinstance(labels, list) or any(
            not isinstance(label, str) or not label for label in labels
        ):
            raise InvalidManifestError("labels must be a list of non-empty strings")

        size_bytes = raw.get("size_bytes")
        if size_bytes is not None and (
            not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0
        ):
            raise InvalidManifestError("size_bytes must be a non-negative integer")

        artifacts = cls._parse_artifacts(raw.get("artifacts", []), filename)
        source_url = cls._parse_source_url(raw.get("source_url"), "source_url")

        try:
            status = ProvenanceStatus(raw["provenance_status"])
        except ValueError as exc:
            raise InvalidManifestError(
                f"unknown provenance_status {raw['provenance_status']!r}"
            ) from exc

        return cls(
            schema_version=raw["schema_version"],
            model_id=raw["model_id"],
            model_version=raw["model_version"],
            filename=filename,
            sha256=raw["sha256"],
            source=raw["source"],
            source_revision=raw["source_revision"],
            code_license=raw["code_license"],
            weights_license=raw["weights_license"],
            framework=raw["framework"],
            input_size=(input_size[0], input_size[1]),
            labels=tuple(labels),
            provenance_status=status,
            size_bytes=size_bytes,
            artifacts=artifacts,
            source_url=source_url,
        )

    @staticmethod
    def _parse_artifacts(raw: Any, primary_filename: str) -> tuple[ArtifactManifest, ...]:
        """Validate auxiliary artifacts without allowing paths outside a model directory."""
        if not isinstance(raw, list):
            raise InvalidManifestError("artifacts must be a list")

        artifacts: list[ArtifactManifest] = []
        filenames: set[str] = {primary_filename}
        for artifact in raw:
            if not isinstance(artifact, dict) or not {
                "filename",
                "sha256",
                "size_bytes",
            }.issubset(artifact) or set(artifact) - {
                "filename",
                "sha256",
                "size_bytes",
                "source_url",
            }:
                raise InvalidManifestError(
                    "every artifact must contain filename, sha256, and size_bytes"
                )
            filename = artifact["filename"]
            sha256 = artifact["sha256"]
            size_bytes = artifact["size_bytes"]
            if not isinstance(filename, str) or Path(filename).name != filename:
                raise InvalidManifestError("artifact filename must be a plain filename")
            if filename in filenames:
                raise InvalidManifestError(f"duplicate artifact filename: {filename}")
            if not isinstance(sha256, str) or not SHA256_PATTERN.fullmatch(sha256):
                raise InvalidManifestError("artifact sha256 must contain 64 lowercase hex digits")
            if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
                raise InvalidManifestError("artifact size_bytes must be a non-negative integer")
            filenames.add(filename)
            source_url = ModelManifest._parse_source_url(
                artifact.get("source_url"), f"artifact {filename} source_url"
            )
            artifacts.append(ArtifactManifest(filename, sha256, size_bytes, source_url))
        return tuple(artifacts)

    @staticmethod
    def _parse_source_url(raw: Any, field_name: str) -> str | None:
        if raw is None:
            return None
        if not isinstance(raw, str) or not raw:
            raise InvalidManifestError(f"{field_name} must be a non-empty URL")
        parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise InvalidManifestError(f"{field_name} must use HTTP or HTTPS")
        if parsed.username or parsed.password or parsed.fragment:
            raise InvalidManifestError(f"{field_name} cannot contain credentials or a fragment")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise InvalidManifestError(f"{field_name} must use HTTPS except for loopback tests")
        return raw
