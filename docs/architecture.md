# Architecture

The package uses a `src` layout and keeps evidence ingestion, normalization,
detection, scoring, and reporting behind separate boundaries.

```text
CLI ──┐
      ├── Application Services ── Core
GUI ──┘

explicit download/import -> ModelInstallationService -> temporary `.part`
 -> size + SHA-256 -> `.installing` staging -> atomic rename
 -> model registry -> VerifiedModel -> FalconsaiDetector
CLI -> original SHA-256 -> read-only image loader -> in-memory RGB -> result
GUI -> services -> model registry + settings + analysis state -> read-only displays
directory -> AnalysisService -> sequential images -> JSON + CSV
ResultsPage -> ExportService -> verified `.part` copy -> SHA-256 -> atomic export
                                      -> AuditService -> audit.log
```

- `hashing.py` hashes original bytes using bounded-memory reads.
- `image_loader.py` handles standard formats and creates an independent RGB
  representation in memory.
- `formats/` contains standard, HEIF, and RAW concerns. Optional codecs are
  imported lazily.
- `detectors/` exposes one common interface. The scanner must depend only on
  this interface, never on NudeNet or OpenNSFW2 directly.
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
- `scoring/` applies project policy to the raw NSFW score: `<0.30 LOW`,
  `0.30..<0.70 REVIEW`, and `>=0.70 HIGH`.
- `reports/` owns atomic JSON and spreadsheet-safe CSV serialization; HTML
  remains intentionally unimplemented.

CLI and GUI use the same `AnalysisService`. The GUI runs it in a cooperative
`QThread`; cancellation stops before the next file and exports completed work.
Results use a metadata-only `QAbstractListModel`, with sensitive previews hidden.

GUI downloads and hashing run in a cooperative `QObject` worker on a `QThread`.
It reports real byte progress and phases; cancellation removes transaction data.
