"""Consolidated, offline-safe case reports."""

import html
import json
import os
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forensic_image_scanner.case.service import CaseService

_LIMITATIONS = [
    "Human review required.",
    "Triage labels are FIS prioritization labels, not legal conclusions.",
    "Video analysis is sampled, not exhaustive.",
]


def build_report(case: CaseService) -> dict[str, object]:
    data = case.data
    sources = [dict(item) for item in data["sources"]]
    acquisitions = [dict(item) for item in data["acquisitions"]]
    recovery_references = [dict(item) for item in data["recoveries"]]
    recovery_payloads = [_read_json(case.root, item["path"]) for item in recovery_references]
    catalog_reference = data.get("media_catalog")
    catalog = (
        _read_json(case.root, catalog_reference["path"])
        if isinstance(catalog_reference, dict)
        else None
    )
    pipeline_reference = data.get("pipeline_summary")
    pipeline = (
        _read_json(case.root, pipeline_reference["path"])
        if isinstance(pipeline_reference, dict)
        else None
    )
    analysis_payload = _analysis_payload(case.root, data["reports"])
    findings = _findings(analysis_payload)
    recovery_summary = _recovery_summary(recovery_payloads)
    integrity = _integrity_summary(catalog)
    analysis_summary = _analysis_summary(analysis_payload, pipeline)
    video = pipeline.get("videos", []) if isinstance(pipeline, dict) else []
    tool_versions = _tool_versions(case.root, acquisitions, recovery_payloads)
    report_references = [dict(item) for item in data["reports"]]
    for reference in (
        {"path": "reports/forensic_report.json", "kind": "forensic_report_json"},
        {"path": "reports/forensic_report.html", "kind": "forensic_report_html"},
    ):
        if not any(item.get("kind") == reference["kind"] for item in report_references):
            report_references.append(reference)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "case": case.metadata.to_dict(),
        "source_evidence": sources,
        "acquisition": acquisitions,
        "recovery_summary": recovery_summary,
        "media_integrity_summary": integrity,
        "analysis_summary": analysis_summary,
        "findings": findings,
        "video_sampled_analysis": {
            "videos_analyzed": len(video),
            "sampled_frames": sum(
                item.get("sampled_frames", 0) for item in video if isinstance(item, dict)
            ),
            "items": [
                {
                    key: item.get(key)
                    for key in ("relative_path", "triage", "sampled_frames", "sampling_cap")
                }
                for item in video
                if isinstance(item, dict)
            ],
        },
        "limitations": list(_LIMITATIONS),
        "tool_versions": tool_versions,
        "references": {
            "recovery": recovery_references,
            "media_catalog": catalog_reference,
            "pipeline_summary": pipeline_reference,
            "reports": report_references,
            "audit_log": data["references"]["audit_log"],
        },
    }


def write_reports(case: CaseService) -> tuple[dict[str, object], Path, Path]:
    reports = case.root / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    json_path = reports / "forensic_report.json"
    html_path = reports / "forensic_report.html"
    payload = build_report(case)
    _atomic_write(json_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    _atomic_write(html_path, _render_html(payload))
    return payload, json_path, html_path


def _read_json(root: Path, relative: str) -> object:
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"unsafe report artifact path: {relative}")
    path = root / relative_path
    current = root
    for component in relative_path.parts:
        current /= component
        if current.is_symlink():
            raise ValueError(f"unsafe report artifact path: {relative}")
    path = path.resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"unsafe or missing report artifact: {relative}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f"unsafe or missing report artifact: {relative}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed report artifact: {relative}") from exc


def _analysis_payload(root: Path, references: list[dict[str, object]]) -> list[object]:
    reference = next((item for item in references if item.get("kind") == "analysis"), None)
    if reference is None:
        return []
    payload = _read_json(root, reference["path"])
    if not isinstance(payload, list):
        raise ValueError("analysis report must contain a list")
    return payload


def _findings(analysis: list[object]) -> dict[str, list[dict[str, object]]]:
    output: dict[str, list[dict[str, object]]] = {"high": [], "review": []}
    for item in analysis:
        if not isinstance(item, dict):
            continue
        classification = str(item.get("triage") or "").casefold()
        if classification not in output:
            continue
        source = item.get("source")
        relative = source.get("relative_path") if isinstance(source, dict) else item.get(
            "relative_path"
        )
        output[classification].append(
            {
                "reference": str(relative or item.get("filename") or "UNKNOWN"),
                "sha256": source.get("sha256") if isinstance(source, dict) else item.get("sha256"),
                "priority": classification.upper(),
                "nsfw_score": item.get("nsfw_score"),
            }
        )
    return output


def _recovery_summary(payloads: list[object]) -> dict[str, object]:
    totals = {
        key: 0
        for key in (
            "recovered",
            "filesystem_recovered",
            "carved",
            "partial",
            "failed",
            "skipped",
            "media_candidates",
            "deleted_entries_discovered",
        )
    }
    for payload in payloads:
        if isinstance(payload, dict):
            for key in totals:
                value = payload.get(key)
                if isinstance(value, int):
                    totals[key] += value
    return totals


def _integrity_summary(catalog: object) -> dict[str, int]:
    counts = {"valid": 0, "partial": 0, "corrupt": 0, "unsupported": 0}
    if not isinstance(catalog, dict) or not isinstance(catalog.get("records"), list):
        return counts
    for record in catalog["records"]:
        if isinstance(record, dict):
            integrity = str(record.get("integrity", "")).casefold()
            if integrity in counts:
                counts[integrity] += 1
    return counts


def _analysis_summary(analysis: list[object], pipeline: object) -> dict[str, object]:
    counts = {"low": 0, "review": 0, "high": 0, "errors": 0}
    for item in analysis:
        if not isinstance(item, dict):
            continue
        triage = str(item.get("triage") or "").casefold()
        if triage in counts:
            counts[triage] += 1
        if item.get("status") == "error":
            counts["errors"] += 1
    if isinstance(pipeline, dict):
        for key in ("low", "review", "high", "errors", "analyzed_images", "analyzed_videos"):
            if isinstance(pipeline.get(key), int):
                counts[key] = pipeline[key]
    return counts


def _tool_versions(
    root: Path, acquisitions: list[dict[str, object]], recoveries: list[object]
) -> dict[str, object]:
    tools: dict[str, object] = {}
    if acquisitions:
        path = acquisitions[-1].get("record")
        if isinstance(path, str):
            record = _read_json(root, path)
            if isinstance(record, dict):
                tools["acquisition"] = record.get("tool_version")
    for payload in recoveries:
        if isinstance(payload, dict) and payload.get("tsk_version"):
            tools["tsk"] = payload["tsk_version"]
    return tools


def _render_html(payload: dict[str, object]) -> str:
    case = payload["case"]
    assert isinstance(case, dict)
    sources = payload["source_evidence"]
    acquisition = payload["acquisition"]
    recovery = payload["recovery_summary"]
    integrity = payload["media_integrity_summary"]
    analysis = payload["analysis_summary"]
    findings = payload["findings"]
    video = payload["video_sampled_analysis"]
    references = payload["references"]
    sections = [
        _section("Evidence summary", _table(sources)),
        _section("Acquisition status", _table(acquisition)),
        _section("Recovery counts", _table(recovery)),
        _section("Media integrity", _table(integrity)),
        _section("LOW / REVIEW / HIGH counts", _table(analysis)),
        _section("REVIEW findings", _table(findings["review"])),
        _section("HIGH findings", _table(findings["high"])),
        _section("Video sampled analysis", _table(video)),
        _section("Limitations", _list(payload["limitations"])),
        _section("Audit / report references", _table(references)),
    ]
    title = html.escape(str(case.get("title") or case["case_id"]))
    metadata = " · ".join(
        html.escape(f"{label}: {case.get(key) or 'Not provided'}")
        for key, label in (
            ("case_id", "Case ID"),
            ("case_number", "Case number"),
            ("examiner", "Examiner"),
            ("status", "Status"),
        )
    )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{title} · Forensic report</title><style>"
        "body{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;"
        "padding:0 1rem;color:#172033;background:#f4f6f9}header,section{background:white;"
        "padding:1.2rem;margin:1rem 0;border:1px solid #d5dbe5;border-radius:8px}"
        "h1,h2{color:#152d4d}table{border-collapse:collapse;width:100%;overflow-wrap:anywhere}"
        "th,td{text-align:left;vertical-align:top;padding:.45rem;border-bottom:1px solid #e3e7ed}"
        "th{width:28%;color:#44536a}small{color:#536174}</style></head><body>"
        f"<header><h1>{title}</h1><p>{metadata}</p>"
        f"<small>Generated {html.escape(str(payload['generated_at']))}</small></header>"
        + "".join(sections)
        + "</body></html>\n"
    )


def _section(title: str, content: str) -> str:
    return f"<section><h2>{html.escape(title)}</h2>{content}</section>"


def _table(value: object) -> str:
    if isinstance(value, dict):
        rows = value.items()
    elif isinstance(value, list):
        rows = enumerate(value)
    else:
        rows = [("Summary", value)]
    rendered = "".join(
        "<tr><th>"
        + html.escape(str(key))
        + "</th><td>"
        + html.escape(json.dumps(item, ensure_ascii=False, default=str))
        + "</td></tr>"
        for key, item in rows
    )
    return "<table>" + (rendered or "<tr><td>None recorded</td></tr>") + "</table>"


def _list(values: object) -> str:
    if not isinstance(values, list):
        return "<p>None recorded</p>"
    return "<ul>" + "".join(f"<li>{html.escape(str(item))}</li>" for item in values) + "</ul>"


def _atomic_write(destination: Path, content: str) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, destination)
    finally:
        Path(name).unlink(missing_ok=True)
