"""Command-line entry point for local-only model management and single-image analysis."""

import argparse
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from forensic_image_scanner import __version__
from forensic_image_scanner.analysis import analyze_image_file
from forensic_image_scanner.detectors.exceptions import DetectorError
from forensic_image_scanner.detectors.falconsai import FalconsaiDetector
from forensic_image_scanner.model_paths import ENVIRONMENT_VARIABLE, resolve_model_directory
from forensic_image_scanner.models.exceptions import (
    ModelArtifactMissingError,
    ModelBlockedError,
    ModelDownloadCancelled,
    ModelDownloadError,
    ModelHashMismatchError,
    ModelIntegrityError,
    ModelNotInstalledError,
    ModelRegistryError,
)
from forensic_image_scanner.models.installation import ModelInstallationService
from forensic_image_scanner.models.references import load_reference_manifest, reference_model_ids
from forensic_image_scanner.models.registry import ModelRegistry
from forensic_image_scanner.scanner import ScannerNotImplementedError, scan_directory

LOGGER = logging.getLogger(__name__)

EXIT_MODEL_MISSING = 3
EXIT_MODEL_INTEGRITY = 4
EXIT_MODEL_BLOCKED = 5
EXIT_ANALYSIS = 6
EXIT_MODEL_DOWNLOAD = 7


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser without side effects."""
    parser = argparse.ArgumentParser(
        prog="forensic-image-scanner",
        description="Local, read-only image content triage (experimental).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--model-dir",
        type=Path,
        help=(
            "controlled model directory; overrides "
            f"{ENVIRONMENT_VARIABLE} and the platform default"
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan", help="scan a directory (pipeline placeholder in this release)"
    )
    scan_parser.add_argument("directory", type=Path)

    model_parser = subparsers.add_parser("model", help="manage explicitly imported local models")
    model_subparsers = model_parser.add_subparsers(dest="model_command", required=True)
    download_parser = model_subparsers.add_parser(
        "download", help="explicitly download and install an audited model"
    )
    download_parser.add_argument("model_id")
    import_parser = model_subparsers.add_parser(
        "import", help="verify and import a local model directory"
    )
    import_parser.add_argument("model_id")
    import_parser.add_argument("model_path", type=Path)
    list_parser = model_subparsers.add_parser(
        "list", help="list audited models and local verification state"
    )
    verify_parser = model_subparsers.add_parser("verify", help="recalculate local artifact hashes")
    verify_parser.add_argument("model_id")
    remove_parser = model_subparsers.add_parser("remove", help="remove local model artifacts")
    remove_parser.add_argument("model_id")
    info_parser = model_subparsers.add_parser(
        "info", help="display audited and local model metadata"
    )
    info_parser.add_argument("model_id")

    analyze_parser = subparsers.add_parser("analyze", help="analyze one local image")
    analyze_parser.add_argument("image", type=Path)
    analyze_parser.add_argument(
        "--detector",
        required=True,
        choices=["falconsai-nsfw-image-detection"],
    )
    analyze_parser.add_argument("--json", action="store_true", dest="as_json")
    for command_parser in (
        download_parser,
        import_parser,
        list_parser,
        verify_parser,
        remove_parser,
        info_parser,
        analyze_parser,
    ):
        command_parser.add_argument(
            "--model-dir",
            type=Path,
            dest="command_model_dir",
            help="controlled model directory for this command",
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    model_root = resolve_model_directory(getattr(args, "command_model_dir", None) or args.model_dir)

    try:
        if args.command is None:
            parser.print_help()
            return 0
        if args.command == "scan":
            return _run_scan(args.directory)
        if args.command == "model":
            return _run_model_command(args, model_root)
        if args.command == "analyze":
            return _run_analyze(args, model_root)
    except ModelBlockedError as exc:
        LOGGER.error("Model blocked: %s", exc)
        return EXIT_MODEL_BLOCKED
    except (ModelHashMismatchError, ModelIntegrityError) as exc:
        LOGGER.error("Model verification failed: %s", exc)
        return EXIT_MODEL_INTEGRITY
    except (ModelNotInstalledError, ModelArtifactMissingError) as exc:
        LOGGER.error("Model is unavailable: %s", exc)
        return EXIT_MODEL_MISSING
    except (DetectorError, FileNotFoundError) as exc:
        LOGGER.error("Analysis failed: %s", exc)
        return EXIT_ANALYSIS
    except ModelDownloadCancelled as exc:
        LOGGER.warning("%s", exc)
        return EXIT_MODEL_DOWNLOAD
    except ModelDownloadError as exc:
        LOGGER.error("Model download failed: %s", exc)
        return EXIT_MODEL_DOWNLOAD
    except ModelRegistryError as exc:
        LOGGER.error("Model operation failed: %s", exc)
        return EXIT_MODEL_MISSING
    return 0


def _run_scan(directory: Path) -> int:
    try:
        scan_directory(directory, detectors=[])
    except ScannerNotImplementedError as exc:
        LOGGER.warning("%s", exc)
        return 0
    except NotADirectoryError:
        LOGGER.error("Not a directory: %s", directory)
        return 2
    return 0


def _run_model_command(args: argparse.Namespace, model_root: Path) -> int:
    service = ModelInstallationService(model_root)
    if args.model_command == "download":
        last_percent = -1

        def report_progress(received: int, total: int) -> None:
            nonlocal last_percent
            percent = int(received * 100 / total) if total else 0
            if percent != last_percent:
                print(f"\rDownloading {percent:3d}% ({received}/{total} bytes)", end="", flush=True)
                last_percent = percent

        installed = service.install_from_url(args.model_id, progress=report_progress)
        print(f"\nInstalled and verified {installed.manifest.model_id}: {installed.path.parent}")
        return 0
    if args.model_command == "import":
        imported = service.install_from_file(args.model_id, args.model_path)
        print(f"Imported {imported.manifest.model_id} into {imported.path.parent}")
        return 0
    if args.model_command == "list":
        _print_model_list(model_root)
        return 0
    if args.model_command == "verify":
        verified = service.verify_installed(args.model_id)
        print(f"Verified {verified.manifest.model_id}: {verified.path}")
        return 0
    if args.model_command == "remove":
        service.remove(args.model_id)
        print(f"Removed local model: {args.model_id}")
        return 0
    if args.model_command == "info":
        _print_model_info(args.model_id, model_root)
        return 0
    raise AssertionError(f"unexpected model command: {args.model_command}")


def _run_analyze(args: argparse.Namespace, model_root: Path) -> int:
    model = ModelRegistry(model_root).load(args.detector)
    analysis = analyze_image_file(args.image, FalconsaiDetector(model))
    if args.as_json:
        print(json.dumps(analysis.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_analysis(analysis.to_dict())
    return 0


def _print_model_list(model_root: Path) -> None:
    registry = ModelRegistry(model_root)
    print(f"{'MODEL':<38} {'STATUS':<22} {'INSTALLED':<10} VERIFIED")
    for model_id in reference_model_ids():
        manifest = load_reference_manifest(model_id)
        installed = (model_root / model_id / "manifest.json").is_file()
        verified = False
        if installed and not manifest.provenance_status.is_blocked:
            try:
                registry.load(model_id)
            except ModelRegistryError:
                verified = False
            else:
                verified = True
        print(
            f"{model_id:<38} {manifest.provenance_status.value:<22} "
            f"{'yes' if installed else 'no':<10} {'yes' if verified else 'no'}"
        )


def _print_model_info(model_id: str, model_root: Path) -> None:
    manifest = load_reference_manifest(model_id)
    local_path = model_root / model_id / manifest.filename
    actual_sha256: str | None = None
    verification = "not installed"
    if local_path.is_file() and not manifest.provenance_status.is_blocked:
        try:
            verified = ModelRegistry(model_root).load(model_id)
        except ModelRegistryError as exc:
            verification = f"failed: {exc}"
        else:
            actual_sha256 = verified.manifest.sha256
            verification = "verified"
    print(f"Model id:             {manifest.model_id}")
    print(f"Version/revision:     {manifest.model_version}")
    print(f"Filename:             {manifest.filename}")
    print(f"Size:                 {manifest.size_bytes}")
    print(f"SHA-256 expected:     {manifest.sha256}")
    print(f"SHA-256 actual:       {actual_sha256 or 'unavailable'}")
    print(f"Provenance status:    {manifest.provenance_status.value}")
    print(f"Weights license:      {manifest.weights_license}")
    print(f"Framework:            {manifest.framework}")
    print(f"Input resolution:     {manifest.input_size[0]}x{manifest.input_size[1]}")
    print(f"Labels:               {', '.join(manifest.labels)}")
    print(f"Local path:           {local_path}")
    print(f"Verification status:  {verification}")


def _print_analysis(data: dict[str, Any]) -> None:
    detector = data["detector"]
    print(f"File:        {data['file']}")
    print(f"SHA-256:     {data['sha256']}")
    print(f"Detector:    {detector['detector_name']}")
    print(f"Model hash:  {detector['model_sha256']}")
    print(f"Provenance:  {detector['provenance_status']}")
    print()
    for label, score in detector["scores"].items():
        print(f"{label}:      {score:.4f}")
    print()
    print(f"Top label:   {detector['top_label']}")
    print(f"Confidence:  {detector['confidence']:.4f}")
    print()
    print("Human review required.")


if __name__ == "__main__":
    raise SystemExit(main())
