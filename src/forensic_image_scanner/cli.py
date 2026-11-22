"""Command-line entry point for model management, analysis and offline calibration."""

import argparse
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from forensic_image_scanner import __version__
from forensic_image_scanner.acquisition import (
    AcquisitionMethod,
    AcquisitionRequest,
    AcquisitionService,
)
from forensic_image_scanner.acquisition.workflow import PhysicalAcquisitionWorkflow
from forensic_image_scanner.analysis import analyze_image_file
from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService
from forensic_image_scanner.calibration.runner import calibrate_controls, calibrate_corpus
from forensic_image_scanner.case import CaseService
from forensic_image_scanner.detectors.exceptions import DetectorError
from forensic_image_scanner.detectors.falconsai import FalconsaiDetector
from forensic_image_scanner.detectors.nudenet import (
    DEFAULT_VARIANT,
    NUDENET_VARIANTS,
    BackendError,
    NudeNetClient,
    enable_verified_backend,
    set_backend_enabled,
)
from forensic_image_scanner.media import MediaCatalogService
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
from forensic_image_scanner.models.nudenet_installation import install_nudenet
from forensic_image_scanner.models.references import load_reference_manifest, reference_model_ids
from forensic_image_scanner.models.registry import ModelRegistry
from forensic_image_scanner.pipeline import PipelineRequest, RecoveryAnalysisPipeline
from forensic_image_scanner.recovery import (
    FilesystemRecoveryService,
    RecoveryMethod,
    RecoveryRequest,
    RecoveryStatus,
)
from forensic_image_scanner.recovery.carving import (
    CarvingRequest,
    PhotoRecCarvingService,
    probe_photorec,
)
from forensic_image_scanner.recovery.carving.photorec_runner import PhotoRecError
from forensic_image_scanner.recovery.tsk.probe import probe_tsk
from forensic_image_scanner.recovery.tsk.runner import TskCommandError
from forensic_image_scanner.scoring.ensemble import FALCONSAI_MODEL, AnalysisProfile

LOGGER = logging.getLogger(__name__)

EXIT_MODEL_MISSING = 3
EXIT_MODEL_INTEGRITY = 4
EXIT_MODEL_BLOCKED = 5
EXIT_ANALYSIS = 6
EXIT_MODEL_DOWNLOAD = 7
EXIT_RECOVERY = 8


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
            f"controlled model directory; overrides {ENVIRONMENT_VARIABLE} and the platform default"
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan", help="analyze a directory sequentially with a verified local model"
    )
    scan_parser.add_argument("directory", type=Path)
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument("--case", type=Path)
    scan_parser.add_argument(
        "--model", default="falconsai-nsfw-image-detection", help="audited local model ID"
    )
    scan_parser.add_argument("--recursive", action="store_true")
    scan_parser.add_argument("--model-dir", type=Path, dest="command_model_dir")

    inspect_parser = subparsers.add_parser(
        "inspect-source", help="inspect a forensic image with The Sleuth Kit"
    )
    inspect_parser.add_argument("source", type=Path)
    inspect_parser.add_argument("--json", action="store_true", dest="as_json")

    recover_parser = subparsers.add_parser(
        "recover", help="recover filesystem-recoverable deleted image/video candidates"
    )
    recover_parser.add_argument("source", type=Path)
    recover_parser.add_argument("--target", type=Path)
    recover_parser.add_argument("--case", type=Path)
    recover_parser.add_argument("--volume", action="append", default=[])
    methods = recover_parser.add_mutually_exclusive_group()
    methods.add_argument("--filesystem-only", action="store_true")
    methods.add_argument("--carve-only", action="store_true")
    media = recover_parser.add_mutually_exclusive_group()
    media.add_argument("--images-only", action="store_true")
    media.add_argument("--videos-only", action="store_true")

    validate_parser = subparsers.add_parser(
        "validate-media", help="rebuild recovered media catalog"
    )
    validate_parser.add_argument("target", type=Path, nargs="?")
    validate_parser.add_argument("--case", type=Path)

    acquire_parser = subparsers.add_parser("acquire", help="acquire a physical disk")
    acquire_parser.add_argument("source", type=Path)
    acquire_parser.add_argument("--target", type=Path)
    acquire_parser.add_argument("--case", type=Path)
    acquire_parser.add_argument("--format", choices=["e01", "raw"], required=True)
    acquire_parser.add_argument("--resume", action="store_true")
    for option in ("case-number", "evidence-number", "examiner", "description", "notes"):
        acquire_parser.add_argument("--" + option)
    acquire_parser.add_argument("--then", choices=["recover", "recover-analyze"])
    acquire_parser.add_argument(
        "--profile",
        type=AnalysisProfile,
        choices=list(AnalysisProfile),
        default=AnalysisProfile.COMBINED,
    )
    acquire_parser.add_argument("--variant", default=DEFAULT_VARIANT, choices=NUDENET_VARIANTS)
    acquire_parser.add_argument("--video-sample-seconds", type=float, default=5.0)
    acquire_parser.add_argument("--video-max-frames", type=int, default=1000)

    run_parser = subparsers.add_parser("run", help="recover, validate and analyze a forensic image")
    run_parser.add_argument("source", type=Path)
    run_parser.add_argument("--target", type=Path)
    run_parser.add_argument("--case", type=Path)
    run_parser.add_argument("--operation", choices=["recover-analyze"], required=True)
    run_parser.add_argument(
        "--profile",
        type=AnalysisProfile,
        choices=list(AnalysisProfile),
        default=AnalysisProfile.COMBINED,
    )
    run_parser.add_argument("--variant", default=DEFAULT_VARIANT, choices=NUDENET_VARIANTS)
    run_parser.add_argument("--video-sample-seconds", type=float, default=5.0)
    run_parser.add_argument("--video-max-frames", type=int, default=1000)

    case_parser = subparsers.add_parser("case", help="create and manage forensic cases")
    case_commands = case_parser.add_subparsers(dest="case_command", required=True)
    create_case_parser = case_commands.add_parser("create", help="create a forensic case")
    create_case_parser.add_argument("case_dir", type=Path)
    for option in (
        "case-number",
        "title",
        "description",
        "examiner",
        "organization",
        "evidence-number",
        "notes",
    ):
        create_case_parser.add_argument("--" + option)
    for command in ("info", "report", "complete", "reopen"):
        command_parser = case_commands.add_parser(command)
        command_parser.add_argument("case_dir", type=Path)

    calibrate_parser = subparsers.add_parser(
        "calibrate", help="measure local corpus or synthetic-control scores offline"
    )
    calibrate_parser.add_argument("corpus", type=Path, nargs="?")
    calibrate_parser.add_argument(
        "--synthetic-controls", action="store_true", help="score generated negative controls"
    )
    calibrate_parser.add_argument(
        "--model",
        default="falconsai-nsfw-image-detection",
        choices=["falconsai-nsfw-image-detection"],
        help="audited local model ID",
    )
    calibrate_parser.add_argument("--output", type=Path, help="create a JSON calibration report")

    for profile_parser in (scan_parser, calibrate_parser):
        profile_parser.add_argument(
            "--profile",
            type=AnalysisProfile,
            choices=list(AnalysisProfile),
            default=AnalysisProfile.FALCONSAI,
        )
        profile_parser.add_argument("--variant", default=DEFAULT_VARIANT, choices=NUDENET_VARIANTS)

    detector_parser = subparsers.add_parser("detector", help="manage optional offline backends")
    detector_commands = detector_parser.add_subparsers(dest="detector_command", required=True)
    backend_parsers = []
    for command in ("status", "install", "enable", "disable"):
        backend_parser = detector_commands.add_parser(command)
        backend_parser.add_argument(
            "--variant",
            default=None if command == "status" else DEFAULT_VARIANT,
            choices=NUDENET_VARIANTS,
        )
        if command == "install":
            backend_parser.add_argument("--python", help="base Python for the isolated runtime")
        backend_parsers.append(backend_parser)

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
        calibrate_parser,
        detector_parser,
        *backend_parsers,
    ):
        command_parser.add_argument(
            "--model-dir",
            type=Path,
            dest="command_model_dir",
            default=argparse.SUPPRESS,
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
        if args.command == "case":
            return _run_case(args)
        if args.command == "scan":
            return _run_scan(args, model_root)
        if args.command == "inspect-source":
            return _run_inspect_source(args)
        if args.command == "recover":
            return _run_recover(args)
        if args.command == "acquire":
            return _run_acquire(args, model_root)
        if args.command == "validate-media":
            return _run_validate_media(args)
        if args.command == "run":
            return _run_pipeline(args, model_root)
        if args.command == "calibrate":
            return _run_calibrate(args, model_root)
        if args.command == "detector":
            return _run_detector(args, model_root)
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
    except (ValueError, NotADirectoryError) as exc:
        LOGGER.error("Invalid request: %s", exc)
        return 2
    except TskCommandError as exc:
        LOGGER.error("Recovery failed [%s]: %s", exc.code, exc)
        return EXIT_RECOVERY
    except PhotoRecError as exc:
        LOGGER.error("Carving failed [%s]: %s", exc.code, exc)
        return EXIT_RECOVERY
    except RuntimeError as exc:
        if args.command != "acquire":
            raise
        LOGGER.error("Acquisition failed: %s", exc)
        return EXIT_RECOVERY
    return 0


def _run_case(args: argparse.Namespace) -> int:
    if args.case_command == "create":
        case = CaseService.create(
            args.case_dir,
            case_number=args.case_number,
            title=args.title,
            description=args.description,
            examiner=args.examiner,
            organization=args.organization,
            evidence_number=args.evidence_number,
            notes=args.notes,
        )
        print(json.dumps(case.metadata.to_dict(), indent=2, ensure_ascii=False))
        return 0
    case = CaseService.open(args.case_dir)
    if args.case_command == "info":
        print(json.dumps(case.metadata.to_dict(), indent=2, ensure_ascii=False))
    elif args.case_command == "report":
        json_path, html_path = case.generate_report()
        print(f"JSON: {json_path}")
        print(f"HTML: {html_path}")
    elif args.case_command == "complete":
        print(case.complete().status.value)
    elif args.case_command == "reopen":
        print(case.reopen().status.value)
    return 0


def _run_validate_media(args: argparse.Namespace) -> int:
    case = _case_for_target(args)
    token = case.begin_operation("media validation") if case is not None else None
    try:
        records = MediaCatalogService().build_from_report(args.target)
        if case is not None and token is not None:
            catalog = case.root / "reports" / "media_catalog.json"
            case.record_media_catalog(catalog)
            case.add_audit_event(
                "media validation completed",
                "media",
                {"path": "reports/media_catalog.json"},
            )
            case.finish_operation(token, "media validation", success=True)
        print(f"Validated {len(records)} media items")
        return 0
    except BaseException:
        if case is not None and token is not None:
            case.finish_operation(token, "media validation", success=False)
        raise


def _case_for_target(args: argparse.Namespace, field: str = "target") -> CaseService | None:
    case_directory = getattr(args, "case", None)
    target = getattr(args, field, None)
    if case_directory is None:
        if target is None:
            raise ValueError(f"--{field.replace('_', '-')} is required unless --case is used")
        return None
    case = CaseService.open(case_directory)
    case.ensure_writable()
    if field == "output":
        case_output = case.root / "reports"
        if target is not None and Path(target).expanduser().resolve() != case_output:
            raise ValueError("--output must be the case reports directory when --case is used")
        setattr(args, field, case_output)
    else:
        if target is not None and Path(target).expanduser().resolve() != case.root:
            raise ValueError("--target must be the case directory when --case is used")
        setattr(args, field, case.root)
    return case


def _finish_case_operations(
    case: CaseService | None, tokens: list[tuple[str, str]], *, success: bool
) -> None:
    if case is None:
        return
    for token, component in reversed(tokens):
        case.finish_operation(token, component, success=success)


def _finish_case_component(
    case: CaseService | None,
    tokens: list[tuple[str, str]],
    component: str,
    *,
    success: bool,
) -> None:
    if case is None:
        return
    for index, (token, name) in enumerate(tokens):
        if name == component:
            case.finish_operation(token, name, success=success)
            tokens.pop(index)
            return


def _run_acquire(args, model_root: Path) -> int:
    if args.resume and args.format != "raw":
        raise ValueError("--resume requires RAW acquisition")
    case = _case_for_target(args)
    if case is not None:
        supplied_metadata = {
            "case_number": args.case_number,
            "evidence_number": args.evidence_number,
            "examiner": args.examiner,
            "description": args.description,
            "notes": args.notes,
        }
        updates = {key: value for key, value in supplied_metadata.items() if value is not None}
        if updates:
            case.update_metadata(**updates)
    source_id = (
        case.record_source("physical_device", args.source).source_id if case is not None else None
    )
    metadata = {
        key: value
        for key in ("case_number", "evidence_number", "examiner", "description", "notes")
        if (value := getattr(args, key))
    }
    if case is not None:
        metadata["case_id"] = case.case_id
    request = AcquisitionRequest(
        args.source,
        args.target,
        AcquisitionMethod(args.format),
        resume=args.resume,
        case_metadata=metadata,
    )
    tokens: list[tuple[str, str]] = []
    if case is not None:
        tokens.append((case.begin_operation("acquisition"), "acquisition"))

    def progress(phase: str, current: int, total: int, name: str) -> None:
        if case is not None and phase == "CHECKING SAFETY":
            case.add_audit_event(
                "safety check",
                "acquisition",
                {"source_id": source_id, "source": str(args.source)},
            )
        component = None
        if case is not None and phase == "ACQUISITION COMPLETE" and args.then:
            component = "recovery"
        elif (
            case is not None
            and args.then == "recover-analyze"
            and phase in {"ANALYZING IMAGES", "ANALYZING VIDEOS"}
        ):
            component = "analysis"
        if case is not None and component is not None and not any(
            existing == component for _token, existing in tokens
        ):
            tokens.append((case.begin_operation(component), component))
        print(f"{phase} {current}/{total} · {name}")

    try:
        if not args.then:
            acquired = AcquisitionService().acquire(
                request, **({"progress": progress} if case is not None else {})
            )
            if case is not None:
                case.record_acquisition(acquired, source_id=source_id)
                acquisition_success = acquired.completed or (
                    acquired.method is AcquisitionMethod.E01
                    and acquired.verification.value == "failed"
                    and Path(acquired.output).is_file()
                )
                _finish_case_component(
                    case, tokens, "acquisition", success=acquisition_success
                )
            print(f"Acquisition: {acquired.output} · verification {acquired.verification.value}")
            status = 0 if acquired.completed and not acquired.cancelled else EXIT_RECOVERY
        else:
            from forensic_image_scanner.workflow import OperationMode

            tsk, photo = probe_tsk(), probe_photorec()
            if not tsk.available and not photo.available:
                raise ValueError("no recovery engine is available")
            operation = (
                OperationMode.RECOVER if args.then == "recover" else OperationMode.RECOVER_ANALYZE
            )
            pipeline = PipelineRequest(
                args.source,
                args.target,
                model_root,
                profile=args.profile,
                variant=args.variant,
                filesystem=tsk.available,
                carving=photo.available,
                sample_seconds=args.video_sample_seconds,
                max_frames=args.video_max_frames,
            )
            result = PhysicalAcquisitionWorkflow().run(
                request,
                operation,
                filesystem=tsk.available,
                carving=photo.available,
                pipeline=pipeline,
                progress=progress if case is not None else None,
            )
            if case is not None:
                case.record_acquisition(result.acquisition, source_id=source_id)
                acquisition_success = result.acquisition.completed or (
                    result.acquisition.method is AcquisitionMethod.E01
                    and result.acquisition.verification.value == "failed"
                    and Path(result.acquisition.output).is_file()
                )
                _finish_case_component(
                    case, tokens, "acquisition", success=acquisition_success
                )
                case.sync_artifact_references()
                if (case.root / "reports" / "media_catalog.json").is_file():
                    case.add_audit_event(
                        "media validation completed",
                        "media",
                        {"path": "reports/media_catalog.json"},
                    )
                if (
                    result.downstream is not None
                    and args.then == "recover-analyze"
                    and not any(existing == "analysis" for _token, existing in tokens)
                ):
                    tokens.append((case.begin_operation("analysis"), "analysis"))
            print(f"Acquisition: {result.acquisition.output}")
            if result.downstream is None or not result.acquisition.completed:
                status = EXIT_RECOVERY
            else:
                summary = getattr(result.downstream, "summary", {})
                failed = bool(summary.get("errors") or summary.get("cancelled"))
                if hasattr(result.downstream, "count"):
                    failed = failed or bool(
                        result.downstream.count(RecoveryStatus.FAILED)
                        or result.downstream.cancelled
                    )
                status = EXIT_RECOVERY if failed else 0
        _finish_case_operations(case, tokens, success=status == 0)
        return status
    except BaseException:
        _finish_case_operations(case, tokens, success=False)
        raise


def _run_inspect_source(args: argparse.Namespace) -> int:
    inspection = FilesystemRecoveryService().inspect_source(args.source)
    payload = {
        "source": str(inspection.source),
        "tsk_version": inspection.tsk_version,
        "volume_system": inspection.volume_system,
        "sector_size": inspection.sector_size,
        "volumes": [
            {
                "volume_id": volume.volume_id,
                "start_sector": volume.start_sector,
                "length_sectors": volume.length_sectors,
                "description": volume.description,
                "filesystem": volume.filesystem,
                "label": volume.label,
                "supported": volume.filesystem_detected,
            }
            for volume in inspection.volumes
        ],
    }
    if args.as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"Source: {inspection.source.name}")
        print(f"TSK: {inspection.tsk_version}")
        print(f"Volume system: {inspection.volume_system}")
        for volume in inspection.volumes:
            filesystem = volume.filesystem or "UNSUPPORTED OR UNRECOGNIZED"
            print(f"{volume.volume_id}: {filesystem} · start {volume.start_sector}")
    return 0


def _run_recover(args: argparse.Namespace) -> int:
    case = _case_for_target(args)
    if case is None:
        return _execute_recover(args)
    source_id = case.record_source("forensic_image", args.source).source_id
    token = case.begin_operation("recovery")
    try:
        status = _execute_recover(args)
        source_hash = None
        recovery_path = case.root / "reports" / "recovery.json"
        if recovery_path.is_file():
            payload = json.loads(recovery_path.read_text(encoding="utf-8"))
            source_hash = payload.get("source_sha256")
            case.record_recovery(
                recovery_path,
                details={"source_id": source_id, "cancelled": bool(payload.get("cancelled"))},
            )
        case.sync_artifact_references()
        if source_hash and source_hash != "UNKNOWN":
            case.record_source(
                "forensic_image",
                args.source,
                sha256=source_hash,
            )
        catalog = case.root / "reports" / "media_catalog.json"
        if catalog.is_file():
            case.add_audit_event(
                "media validation completed",
                "media",
                {"path": "reports/media_catalog.json"},
            )
        case.finish_operation(token, "recovery", success=status == 0)
        return status
    except BaseException:
        case.finish_operation(token, "recovery", success=False)
        raise


def _execute_recover(args: argparse.Namespace) -> int:
    tsk = probe_tsk()
    photorec = probe_photorec()
    use_filesystem = not args.carve_only and tsk.available
    use_carving = not args.filesystem_only and photorec.available
    if args.filesystem_only and not tsk.available:
        raise TskCommandError("TSK_NOT_AVAILABLE", "required tools: mmls, fsstat, fls, icat")
    if args.carve_only and not photorec.available:
        raise PhotoRecError("PHOTOREC_NOT_AVAILABLE", "system PhotoRec is not available")
    if not use_filesystem and not use_carving:
        raise ValueError("no recovery engine is available")
    images = not args.videos_only
    videos = not args.images_only

    def progress(phase: str, current: int, total: int, name: str) -> None:
        print(f"{phase} {current}/{total} · {name}")

    inspection = None
    filesystem_service = FilesystemRecoveryService()
    if tsk.available:
        inspection = filesystem_service.inspect_source(args.source)
    summary = None
    if use_filesystem:
        summary = filesystem_service.recover(
            RecoveryRequest(
                args.source,
                args.target,
                tuple(args.volume),
                images=images,
                videos=videos,
            ),
            inspection=inspection,
            progress=progress,
            write_reports=not use_carving,
        )
    if use_carving:
        summary = PhotoRecCarvingService().carve(
            CarvingRequest(
                args.source,
                args.target,
                tuple(args.volume),
                images=images,
                videos=videos,
            ),
            inspection=inspection,
            base_summary=summary,
            progress=progress,
        )
    assert summary is not None
    if not summary.cancelled:
        MediaCatalogService().build(summary, progress=progress)
    carved = sum(
        record.method is RecoveryMethod.FILE_CARVING and record.status is RecoveryStatus.RECOVERED
        for record in summary.records
    )
    duplicates = sum(
        getattr(record, "duplicate_of", None) is not None for record in summary.records
    )
    print(
        f"Deleted entries {summary.deleted_entries} · "
        f"media candidates {summary.media_candidates} · "
        f"recovered {summary.count(RecoveryStatus.RECOVERED)} · "
        f"partial {summary.count(RecoveryStatus.PARTIAL)} · "
        f"failed {summary.count(RecoveryStatus.FAILED)} · "
        f"carved {carved} · duplicates {duplicates}"
    )
    print(f"JSON: {summary.json_path}")
    print(f"CSV:  {summary.csv_path}")
    return EXIT_RECOVERY if summary.cancelled else 0


def _run_scan(args: argparse.Namespace, model_root: Path) -> int:
    case = _case_for_target(args, "output")
    if case is None:
        return _execute_scan(args, model_root)
    case.record_source("directory", args.directory)
    token = case.begin_operation("analysis")
    try:
        status = _execute_scan(args, model_root)
        analysis_path = Path(args.output) / "analysis.json"
        if analysis_path.is_file():
            case.record_analysis(analysis_path)
        case.sync_artifact_references()
        case.finish_operation(token, "analysis", success=status == 0)
        return status
    except BaseException:
        case.finish_operation(token, "analysis", success=False)
        raise


def _execute_scan(args: argparse.Namespace, model_root: Path) -> int:
    request = AnalysisRequest(
        source=args.directory,
        output=args.output,
        model=args.model,
        recursive=args.recursive,
        profile=args.profile,
        nudenet_variant=args.variant,
    )

    current = 0
    total = 0

    def set_total(discovered: int) -> None:
        nonlocal total
        total = discovered

    def print_result(result) -> None:
        nonlocal current
        current += 1
        category = "ERROR" if result.status == "error" else result.triage.value
        score = "—" if result.nsfw_score is None else f"{result.nsfw_score:.2f}"
        print(f"[{current}/{total}] {result.relative_path:<40} {category:<7} {score}")

    summary = AnalysisService(model_root).run(
        request, started=set_total, file_completed=print_result
    )
    print(
        f"Processed {summary.processed}/{summary.discovered} · LOW {summary.low} · "
        f"REVIEW {summary.review} · HIGH {summary.high} · ERRORS {summary.errors} · "
        f"{summary.elapsed_seconds:.2f}s ({summary.images_per_second:.2f} images/s)"
    )
    if request.profile is not AnalysisProfile.FALCONSAI:
        print(f"NudeNet backend errors: {summary.nudenet_errors}")
    print(f"JSON: {summary.json_path}")
    print(f"CSV:  {summary.csv_path}")
    return 0


def _run_pipeline(args: argparse.Namespace, model_root: Path) -> int:
    case = _case_for_target(args)
    if case is None:
        return _execute_pipeline(args, model_root)
    source_id = case.record_source("forensic_image", args.source).source_id
    tokens = [
        (case.begin_operation("recovery"), "recovery"),
        (case.begin_operation("analysis"), "analysis"),
    ]
    try:
        status = _execute_pipeline(args, model_root)
        recovery_path = case.root / "reports" / "recovery.json"
        if recovery_path.is_file():
            case.record_recovery(recovery_path, details={"source_id": source_id})
            recovery_data = json.loads(recovery_path.read_text(encoding="utf-8"))
            source_hash = recovery_data.get("source_sha256")
            if source_hash and source_hash != "UNKNOWN":
                case.record_source("forensic_image", args.source, sha256=source_hash)
        case.sync_artifact_references()
        if (case.root / "reports" / "media_catalog.json").is_file():
            case.add_audit_event(
                "media validation completed",
                "media",
                {"path": "reports/media_catalog.json"},
            )
        _finish_case_operations(case, tokens, success=status == 0)
        return status
    except BaseException:
        _finish_case_operations(case, tokens, success=False)
        raise


def _execute_pipeline(args: argparse.Namespace, model_root: Path) -> int:
    tsk, photo = probe_tsk(), probe_photorec()
    if not tsk.available and not photo.available:
        raise ValueError("no recovery engine is available")
    result = RecoveryAnalysisPipeline().run(
        PipelineRequest(
            args.source,
            args.target,
            model_root,
            profile=args.profile,
            variant=args.variant,
            filesystem=tsk.available,
            carving=photo.available,
            sample_seconds=args.video_sample_seconds,
            max_frames=args.video_max_frames,
        ),
        progress=lambda phase, current, total, name: print(
            f"{phase} {current}/{total} · {name}"
        ),
    )
    print(json.dumps(result.summary, indent=2, default=str))
    return EXIT_RECOVERY if result.summary["errors"] or result.summary["cancelled"] else 0


def _run_calibrate(args: argparse.Namespace, model_root: Path) -> int:
    if (args.corpus is not None) == args.synthetic_controls:
        raise ValueError("provide either a calibration corpus or --synthetic-controls")

    corpus = args.corpus.expanduser().resolve() if args.corpus is not None else None
    destination = args.output.expanduser() if args.output is not None else None
    if destination is not None:
        resolved = destination.resolve()
        if corpus is not None and resolved.is_relative_to(corpus):
            raise ValueError("calibration output cannot be inside the corpus")
        if resolved.is_relative_to(model_root.resolve()):
            raise ValueError("calibration output cannot be inside the model directory")
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"calibration output already exists: {destination}")

    if corpus is None:
        report = calibrate_controls(
            model_root, args.model, profile=args.profile, variant=args.variant
        )
    else:
        report = calibrate_corpus(
            corpus, model_root, args.model, profile=args.profile, variant=args.variant
        )
    print(report.format_summary())
    if destination is not None:
        try:
            report.write_json(destination)
        except OSError as exc:
            LOGGER.error("Could not write calibration report: %s", exc)
            return EXIT_ANALYSIS
        print(f"JSON: {destination}")
    return EXIT_ANALYSIS if report.error_count else 0


def _run_detector(args: argparse.Namespace, model_root: Path) -> int:
    if args.detector_command == "status":
        return _report_detector_status(model_root, args.variant)
    variant = args.variant
    if args.detector_command == "install":
        print(
            f"Installing optional NudeNet {variant} · GNU AGPL-3.0 · Experimental · "
            "Training provenance partial"
        )
        health = install_nudenet(model_root, variant, python=args.python)
    elif args.detector_command == "disable":
        set_backend_enabled(model_root, variant, False)
        print(f"NudeNet {variant}: DISABLED")
        return 0
    else:
        health = enable_verified_backend(model_root, variant, Path.cwd())
    _print_nudenet_health(health)
    return 0


def _report_detector_status(model_root: Path, variant: str | None) -> int:
    try:
        ModelRegistry(model_root).load(FALCONSAI_MODEL)
    except ModelRegistryError:
        print("Falconsai: UNAVAILABLE")
        any_ready = False
    else:
        print("Falconsai: VERIFIED · PARTIAL")
        any_ready = variant is None

    for candidate in (variant,) if variant is not None else NUDENET_VARIANTS:
        try:
            with NudeNetClient.from_registry(model_root, candidate, Path.cwd()) as backend:
                _print_nudenet_health(backend.health)
        except (BackendError, ModelRegistryError) as exc:
            print(f"NudeNet {candidate}: UNAVAILABLE ({exc})")
        else:
            any_ready = True
    return 0 if any_ready else EXIT_ANALYSIS


def _print_nudenet_health(health: dict) -> None:
    print(f"NudeNet {health['model']}: READY · EXPERIMENTAL · PARTIAL")
    print(json.dumps(health))


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
    if manifest.operational_status:
        print(f"Operational status:   {manifest.operational_status}")
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
