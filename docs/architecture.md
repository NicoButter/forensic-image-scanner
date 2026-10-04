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
- `detectors/falconsai.py` uses registry-verified `model.safetensors`,
  `config.json`, and `preprocessor_config.json` exclusively from the local
  model directory. It runs CPU inference with local-only framework loading.
- `results.py` defines the auditable interchange types.
- `scoring/` converts detector output into triage priorities.
- `reports/` owns serialization; HTML remains intentionally unimplemented.

The bootstrap release does not recursively discover or analyze files. Its CLI
reports that limitation explicitly.

GUI downloads and hashing run in a cooperative `QObject` worker on a `QThread`.
It reports real byte progress and phases; cancellation removes transaction data.
