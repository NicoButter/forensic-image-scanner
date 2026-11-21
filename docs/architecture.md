# Architecture

The package uses a `src` layout and keeps evidence ingestion, normalization,
detection, scoring, and reporting behind separate boundaries.

```text
CLI ──┐
      ├── Application Services ── Core
GUI ──┘

Source Inspection -> Workflow Validation -> Operation Router
                                              |
                         +--------------------+--------------------+
                         |                    |                    |
                      Analysis            Recovery       Recovery + Analysis
                     (FIS-011)             (future)              (future)

explicit download/import -> ModelInstallationService -> temporary `.part`
 -> size + SHA-256 -> `.installing` staging -> atomic rename
 -> model registry -> VerifiedModel -> FalconsaiDetector
CLI -> original SHA-256 -> read-only image loader -> in-memory RGB -> result
GUI -> services -> model registry + settings + analysis state -> read-only displays
directory -> AnalysisService -> sequential images -> JSON + CSV
local labelled corpus -> calibration -> ModelRegistry + analyze_image_file
                                     -> raw scores -> threshold sweep + optional JSON
ResultsPage -> ExportService -> verified `.part` copy -> SHA-256 -> atomic export
                                      -> AuditService -> audit.log
```

- `hashing.py` hashes original bytes using bounded-memory reads.
- `image_loader.py` handles standard formats and creates an independent RGB
  representation in memory.
- `formats/` contains standard, HEIF, and RAW concerns. Optional codecs are
  imported lazily.
- `detectors/` exposes one common interface. The scanner must depend only on
  this interface for in-process inference. The NudeNet client speaks a local
  protocol to a separate environment containing the upstream distribution.
- `models/installation.py` is the high-level installation API. It delegates
  explicit administrative streaming to `models/downloader.py`, verifies every
  artifact, stages it, and atomically renames the complete model. Directory
  imports use the same path and reject symlinks.
- `models/registry.py` remains network-free. It validates manifests, policy,
  existence, size, and SHA-256 and returns a `VerifiedModel` for a detector.
- `analysis.py` hashes one original file before creating a read-only in-memory
  representation. It does not recurse, create thumbnails, or emit reports.
- `analysis_service.py` verifies the model, discovers regular non-symlink image
  files, and processes them one at a time. Per-file failures are recorded while
  scanning continues. Completed results are atomically finalized as JSON/CSV.
- `detectors/falconsai.py` uses registry-verified `model.safetensors`,
  `config.json`, and `preprocessor_config.json` exclusively from the local
  model directory. It runs CPU inference with local-only framework loading.
- `results.py` defines the auditable interchange types.
- `export_service.py` performs explicit post-analysis transfers only. It safely
  reconstructs destinations from `relative_path`, rejects traversal and source
  or destination escapes, verifies both source and copied destination hashes,
  and permits source deletion exclusively for `SourceMode.WORKING_COPY`.
- `audit_service.py` appends local transfer events to `<output>/audit.log`.
- `scoring/` owns the immutable experimental `TriagePolicy`. It maps the raw
  NSFW score to `LOW` below 0.60, `REVIEW` from 0.60 up to 0.85, and `HIGH` from
  0.85. These project priorities are separate from Falconsai's binary
  `normal` and `nsfw` output. `AnalysisService` accepts a policy dependency,
  and a saved NSFW probability can be passed directly to a different policy.
- `calibration/` uses the regular image discovery rules, registry verification,
  and single-image inference pipeline. It evaluates binary thresholds against
  labelled corpus folders or generated negative controls, records per-file
  scores and errors, and leaves production thresholds intact.
- `reports/` owns atomic JSON and spreadsheet-safe CSV serialization; HTML
  remains intentionally unimplemented.
- `workflow/` is the Qt-independent source/target/operation boundary. Immutable
  descriptors carry source evidence semantics; centralized validation returns
  structured findings and the capability matrix. Linux device enumeration uses
  read-only `lsblk` JSON metadata outside GUI code. The operation adapter routes
  only `DIRECTORY + ANALYZE` into the established `AnalysisRequest`; every
  recovery combination remains configured-but-non-executable.

CLI and GUI use the same `AnalysisService`. The GUI runs it in a cooperative
`QThread`; cancellation stops before the next file and exports completed work.
Results use a metadata-only `QAbstractListModel`, with sensitive previews hidden.
The default filters show `HIGH` and `REVIEW`, and all visible rows are sorted
by descending raw NSFW score. Filters affect the list only. Both reports
continue to carry all processed rows and the two raw model probabilities.

GUI downloads and hashing run in a cooperative `QObject` worker on a `QThread`.
It reports real byte progress and phases; cancellation removes transaction data.

Physical-source target backing-device collision is deliberately `UNKNOWN` in
FIS-011. It must be made strict before recovery is enabled. Planned integrations
are The Sleuth Kit (FIS-012), PhotoRec (FIS-013), recovered-media validation
(FIS-014), recovery plus detection (FIS-015), and forensic acquisition
(FIS-016). No recovery engine, mount action, device write, or privilege escalation
is part of the current architecture.


## Detector process protocol

The core starts one worker per sequential NudeNet session with an argument
list and private standard I/O pipes. The worker runs in the provisioned
environment and rechecks the exact artifact bytes before loading them. Requests
are UTF-8 newline-delimited JSON. Schema version 1 supports
`{"schema_version":1,"operation":"health"}` and
`{"schema_version":1,"operation":"analyze","image_path":"/absolute/path.png"}`.
Image paths must resolve to regular files under the session source. Health
returns backend, version, variant, model hash and license. An analysis response
contains `status: "ok"` and raw `class`, `confidence`, and integer
`box: [x, y, width, height]` entries. The box coordinate system is the decoded
image used by NudeNet. Invalid inputs return a sanitized `status: "error"`.

The core validates the response version, health identity, class allowlist,
confidence and box fields. Startup and inference use 30 s and 20 s deadlines.
Timeouts and invalid transport responses terminate the process. The rest of a
Combined scan can continue with Falcon-only priority and explicit backend error
records. The worker disables ONNX Runtime telemetry, blocks Python network
operations and uses only locally verified weights. The core passes no shell
commands, performs no runtime download and writes results outside the evidence
directory. The runtime is a separate process under the same user account.

`scoring/ensemble.py` applies experimental triage rules without changing the
raw outputs. JSON stores individual detector results and explanations. CSV
appends profile, detector status, count, labels, and explanations to its existing
columns. Safe Review remains metadata-only.
