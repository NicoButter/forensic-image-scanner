# Architecture

The package uses a `src` layout and keeps evidence ingestion, normalization,
detection, scoring, and reporting behind separate boundaries.

```text
manual import -> manifest + SHA-256 -> controlled model directory
                                      -> model registry -> VerifiedModel
                                                          -> FalconsaiDetector
CLI -> original SHA-256 -> read-only image loader -> in-memory RGB -> result
```

- `hashing.py` hashes original bytes using bounded-memory reads.
- `image_loader.py` handles standard formats and creates an independent RGB
  representation in memory.
- `formats/` contains standard, HEIF, and RAW concerns. Optional codecs are
  imported lazily.
- `detectors/` exposes one common interface. The scanner must depend only on
  this interface, never on NudeNet or OpenNSFW2 directly.
- `models/` validates a versioned manifest, policy status, file existence,
  byte size, and SHA-256 for the primary and auxiliary artifacts. Its importer
  stages verified copies then atomically registers them. It has no network
  client and returns a `VerifiedModel` that must be injected into a detector.
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
