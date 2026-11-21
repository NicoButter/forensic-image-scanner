"""Coordinate existing recovery, catalog, and detection services."""

import json
import os
import tempfile
import threading
from pathlib import Path

from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService
from forensic_image_scanner.media import MediaCatalogService, MediaIntegrity
from forensic_image_scanner.pipeline.models import PipelineRequest, PipelineResult
from forensic_image_scanner.pipeline.video import sample_video
from forensic_image_scanner.recovery import (
    FilesystemRecoveryService,
    RecoveryRequest,
    RecoveryStatus,
)
from forensic_image_scanner.recovery.carving import CarvingRequest, PhotoRecCarvingService
from forensic_image_scanner.recovery.reports import write_recovery_reports
from forensic_image_scanner.recovery.tsk.probe import probe_tsk
from forensic_image_scanner.reports.json_report import write_json_report


def aggregate_video(media, results, interval):
    rank = {"LOW": 0, "REVIEW": 1, "HIGH": 2}
    useful = [r for r in results if r.triage is not None and r.status != "error"]
    best = max(useful, key=lambda r: rank[r.triage.value], default=None)
    details = []
    for index, result in enumerate(results):
        if result.triage is not None and result.triage.value in {"HIGH", "REVIEW"}:
            details.append(
                {"frame_index": index, "timestamp": index * interval, "result": result.to_dict()}
            )
    return {
        "media_id": media.media_id,
        "sampled_frames": len(results),
        "triage": best.triage.value if best else None,
        "highest_risk_timestamp": results.index(best) * interval if best else None,
        "sampling_interval": interval,
        "relevant_frames": details,
    }


class RecoveryAnalysisPipeline:
    def run(self, request: PipelineRequest, *, cancel=None, progress=None, inspection=None):
        cancel = cancel or threading.Event()
        progress = progress or (lambda *args: None)
        target = request.target.expanduser().resolve()
        source = request.source.expanduser().resolve()
        if not source.is_file() or target in {source, source.parent}:
            raise ValueError("source must be a forensic image separate from the target")
        if request.sample_seconds <= 0 or request.max_frames <= 0:
            raise ValueError("video sampling parameters must be positive")
        counts = {
            key: 0
            for key in (
                "recovered",
                "catalogued",
                "valid",
                "partial",
                "corrupt",
                "unsupported",
                "analyzed_images",
                "analyzed_videos",
                "sampled_frames",
                "low",
                "review",
                "high",
                "skipped",
                "errors",
            )
        }
        counts.update({"cancelled": False, "media": [], "videos": [], "skips": [], "failures": []})
        analysis = None
        try:
            recovery = None
            filesystem = FilesystemRecoveryService()
            if inspection is None and probe_tsk().available:
                inspection = filesystem.inspect_source(request.source)
            if request.filesystem and not cancel.is_set():
                progress("RECOVERING", 0, 1, "filesystem")
                recovery = filesystem.recover(
                    RecoveryRequest(
                        request.source,
                        target,
                        request.volume_ids,
                        images=request.images,
                        videos=request.videos,
                    ),
                    inspection=inspection,
                    cancel=cancel,
                    progress=progress,
                    write_reports=not request.carving,
                )
                if cancel.is_set() and request.carving:
                    write_recovery_reports(recovery)
            if request.carving and not cancel.is_set():
                progress("CARVING", 0, 1, "PhotoRec")
                recovery = PhotoRecCarvingService().carve(
                    CarvingRequest(
                        request.source,
                        target,
                        request.volume_ids,
                        images=request.images,
                        videos=request.videos,
                    ),
                    inspection=inspection,
                    base_summary=recovery,
                    cancel=cancel,
                    progress=progress,
                )
            if recovery is None:
                if not cancel.is_set():
                    raise ValueError("no recovery engine selected")
                return PipelineResult(counts, None)
            counts["recovered"] = recovery.count(RecoveryStatus.RECOVERED)
            if cancel.is_set() or recovery.cancelled:
                return PipelineResult(counts, None)
            catalog = MediaCatalogService().build(recovery, progress=progress, cancel=cancel)
            counts["catalogued"] = len(catalog)
            for item in catalog:
                counts[item.integrity.value] += 1
            eligible = []
            for item in catalog:
                if item.integrity not in {MediaIntegrity.VALID, MediaIntegrity.PARTIAL}:
                    counts["skipped"] += 1
                    counts["skips"].append(
                        {"media_id": item.media_id, "reason": item.integrity.value}
                    )
                elif item.media_kind == "image":
                    eligible.append(item)
            engine = AnalysisService(request.model_root)
            if eligible and not cancel.is_set():
                progress("ANALYZING IMAGES", 0, len(eligible), "images")
                source = target / "recovered"
                analysis = engine.run(
                    AnalysisRequest(
                        source,
                        target / "reports",
                        request.model,
                        profile=request.profile,
                        nudenet_variant=request.variant,
                    ),
                    files=[target / item.relative_path for item in eligible],
                    cancelled=cancel.is_set,
                    progress=lambda n, total: progress("ANALYZING IMAGES", n, total, "images"),
                )
                by_path = {(target / item.relative_path).resolve(): item for item in eligible}
                for result in analysis.results:
                    item = by_path[result.path.resolve()]
                    record = {
                        key: getattr(item, key)
                        for key in (
                            "media_id",
                            "sha256",
                            "integrity",
                            "relative_path",
                            "recovery_ids",
                            "recovery_methods",
                            "original_paths",
                        )
                    }
                    record["analysis"] = result.to_dict()
                    counts["media"].append(record)
                    counts["analyzed_images"] += 1
                    if result.triage is not None:
                        counts[result.triage.value.lower()] += 1
                    if result.status == "error":
                        counts["errors"] += 1
                        counts["skipped"] += 1
                        counts["skips"].append(
                            {"media_id": item.media_id, "reason": result.error or "ANALYSIS_ERROR"}
                        )
            videos = [
                item
                for item in catalog
                if item.media_kind == "video"
                and item.integrity in {MediaIntegrity.VALID, MediaIntegrity.PARTIAL}
            ]
            for index, item in enumerate(videos, 1):
                if cancel.is_set():
                    break
                progress("ANALYZING VIDEOS", index, len(videos), item.relative_path)
                try:
                    temp_parent = target / ".fis-tmp"
                    temp_parent.mkdir(exist_ok=True)
                    with tempfile.TemporaryDirectory(prefix="video-", dir=temp_parent) as temporary:
                        root = Path(temporary)
                        frames = sample_video(
                            target / item.relative_path,
                            root / "frames",
                            interval=request.sample_seconds,
                            max_frames=request.max_frames,
                            cancel=cancel,
                        )
                        if not frames:
                            raise ValueError("NO_SAMPLED_FRAMES")
                        frame_summary = engine.run(
                            AnalysisRequest(
                                root / "frames",
                                root / "reports",
                                request.model,
                                profile=request.profile,
                                nudenet_variant=request.variant,
                            ),
                            files=frames,
                            cancelled=cancel.is_set,
                        )
                        video = aggregate_video(
                            item, list(frame_summary.results), request.sample_seconds
                        )
                        video.update(
                            {
                                key: getattr(item, key)
                                for key in (
                                    "sha256",
                                    "integrity",
                                    "relative_path",
                                    "recovery_ids",
                                    "recovery_methods",
                                    "original_paths",
                                )
                            }
                        )
                        video["sampling_cap"] = request.max_frames
                        counts["videos"].append(video)
                        counts["sampled_frames"] += video["sampled_frames"]
                        counts["errors"] += frame_summary.errors
                        if video["triage"]:
                            counts["analyzed_videos"] += 1
                            counts[video["triage"].lower()] += 1
                        else:
                            counts["skipped"] += 1
                            counts["skips"].append(
                                {"media_id": item.media_id, "reason": "NO_VALID_FRAME_RESULTS"}
                            )
                except InterruptedError:
                    cancel.set()
                except Exception as exc:
                    counts["skipped"] += 1
                    counts["skips"].append({"media_id": item.media_id, "reason": str(exc)})
                    if str(exc) != "FFMPEG_NOT_AVAILABLE":
                        counts["errors"] += 1
        except Exception as exc:
            counts["errors"] += 1
            counts["failures"].append(str(exc))
            if recovery is not None and not (target / "reports" / "recovery.json").exists():
                write_recovery_reports(recovery)
        finally:
            counts["cancelled"] = cancel.is_set() or bool(
                recovery is not None and recovery.cancelled
            )
            analysis_path = target / "reports" / "analysis.json"
            if not analysis_path.exists():
                analysis_path.parent.mkdir(parents=True, exist_ok=True)
                write_json_report([], analysis_path)
            progress("FINALIZING", 1, 1, "pipeline_summary.json")
            _write(target, counts)
        return PipelineResult(counts, analysis)


def _write(target: Path, counts: dict) -> None:
    reports = target / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".pipeline-", dir=reports)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(counts, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, reports / "pipeline_summary.json")
    finally:
        Path(name).unlink(missing_ok=True)
