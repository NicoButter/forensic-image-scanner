# FIS-010 · DET-02 — NudeNet Experimental Backend & Ensemble Triage

| Field | Value |
| --- | --- |
| Status | Implemented, validated locally |
| Opened | 2026-11-21 |
| Baseline | `main`, HEAD started at `698be61` |
| Commit | Pending |
| Tag | Pending |

## Backend and artifacts

FIS launches one NudeNet process for a sequential session and communicates by
versioned JSON lines over its private pipes. The process runs in a separate
Python environment under the model-data directory. Startup has a 30-second
deadline and each inference has a 20-second deadline. Timeout and malformed
transport responses stop the child. Safe Review exposes metadata only. The
bridge and core are Apache-2.0. The upstream NudeNet wheel includes the
AGPL-3.0 license despite the PyPI MIT metadata. NudeNet weights and runtime
remain separately installed and tracked as experimental with partial training
provenance.

| Artifact | Source | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| NudeNet 3.4.2 wheel | [Pinned PyPI wheel](https://files.pythonhosted.org/packages/1c/ee/1aa02d44ba958cc77e16ff1e41a0aac5e721037db7bf62b9c9d124917f87/nudenet-3.4.2-py3-none-any.whl) | 10,595,223 | `5937dbd84e5d8e5de038f08ffea5a1bb50a08475776bf2b4795914ce0eaf0331` |
| 320n, 320×320 YOLOv8n | [v3.4-weights](https://github.com/notAI-tech/NudeNet/releases/download/v3.4-weights/320n.onnx), obtained from the pinned wheel | 12,150,158 | `c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f` |
| 640m, 640×640 YOLOv8m | [v3.4-weights release asset 176832019](https://api.github.com/repos/notAI-tech/NudeNet/releases/assets/176832019), requested as binary | 103,538,690 | `04fe3d77980780c1f8297dc6d7f942fd5b3abe6942a188f742a85241e4f634eb` |

Both ONNX artifacts list the following 18 classes in this order.

```text
FEMALE_GENITALIA_COVERED
FACE_FEMALE
BUTTOCKS_EXPOSED
FEMALE_BREAST_EXPOSED
FEMALE_GENITALIA_EXPOSED
MALE_BREAST_EXPOSED
ANUS_EXPOSED
FEET_EXPOSED
BELLY_COVERED
FEET_COVERED
ARMPITS_COVERED
ARMPITS_EXPOSED
FACE_MALE
BELLY_EXPOSED
MALE_GENITALIA_EXPOSED
ANUS_COVERED
FEMALE_BREAST_COVERED
BUTTOCKS_COVERED
```

The GUI requests confirmation and records the approved operation. The CLI
requires an explicit `detector install`. Downloaded bytes stage in a temporary
directory and undergo size and SHA-256 checks. The verified model directory
is published atomically. Setup health verifies version, variant, license and
hash before persisting opt-in for that variant. Existing Falcon-only workflows
still run without the optional runtime.

## Experimental triage

| Profile | Policy |
| --- | --- |
| Falconsai Only | REVIEW ≥ 0.60 and HIGH ≥ 0.85 on raw NSFW probability |
| NudeNet Only | REVIEW ≥ 0.60 and HIGH ≥ 0.85 on maximum eligible detection confidence |
| Combined | HIGH when Falconsai is HIGH and an eligible detection has confidence ≥ 0.60. Falconsai HIGH without corroboration becomes REVIEW. An eligible detection at or above 0.60 promotes Falcon LOW to REVIEW. Falcon REVIEW becomes HIGH with an eligible detection at or above 0.85. |
| Combined, backend error | Retain Falcon-only priority and report the backend failure explicitly. NudeNet Only records an error if inference fails. |

Eligible classes are exposed female breast, exposed male or female genitalia,
exposed buttocks and exposed anus. All raw classes, confidences, and boxes are
preserved. Bounding boxes are integer `[x, y, width, height]` in decoded image
coordinates. The JSON records detector results and reasons separately. The CSV
extends existing columns with a compact detector summary.

## Validation and calibration

Explicitly installed both variants under a temporary local model root with
Python 3.12 and ONNX Runtime CPU 1.32.0. Both reported `READY`, NudeNet 3.4.2,
AGPL-3.0, and their exact expected hashes. Falconsai reused its already
installed verified model. The integration tests exercised both NudeNet Only
and Combined, including rejection of a path outside the session root and
SHA-256 comparison on the source image. All five calibration runs also
passed with IP socket creation blocked at the process-library boundary and
recorded zero IP socket attempts.

All five configurations ran on the same 13 synthetic negative controls.
Both NudeNet variants returned zero detections. Blank white, black and gray,
the gradients, checkerboard and the geometric patterns all remained LOW. The
Falconsai NSFW scores were 0.00917902 for white, 0.02144173 for black,
0.00570027 for gray, 0.00326627 for the horizontal gradient, 0.00478503 for the
vertical gradient and 0.00104955 for the checkerboard.

| Configuration | TN | FP | FN | TP | Specificity | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Falconsai | 13 | 0 | 0 | 0 | 1.000 | 0.000 |
| NudeNet 320n | 13 | 0 | 0 | 0 | 1.000 | 0.000 |
| NudeNet 640m | 13 | 0 | 0 | 0 | 1.000 | 0.000 |
| Combined 320n | 13 | 0 | 0 | 0 | 1.000 | 0.000 |
| Combined 640m | 13 | 0 | 0 | 0 | 1.000 | 0.000 |

Precision, recall, FNR and F1 are undefined on these runs because the controls
contained neither positives nor positive predictions. These runs show no
observed reduction in false positives. A regression simulating a Falcon score
of 240/255 and a successful empty NudeNet response verifies HIGH → REVIEW.
The same Falcon score with a backend failure retains HIGH.

The CLI compares profiles over a labelled corpus using precision, recall,
specificity, FPR, FNR, F1, and confusion counts. Single detectors also report
the FIS-008 threshold sweep. Combined reports its actual rule decisions.
Comparative metrics count REVIEW and HIGH as positive and exclude recorded
inference failures. Calibration leaves the corpus and policy intact.

| Check | Result |
| --- | --- |
| Default `pytest` | 98 passed, 3 opt-in cases deselected |
| `pytest -m nudenet` | 2 passed with real isolated runtimes |
| `pytest -m model` | 1 passed with verified Falconsai |
| `ruff check .` and `git diff --check` | Passed |
| `pip check` | Passed in the core and isolated runtime environments |
| CLI `scan` | All three profiles produced JSON and CSV. All 13 input hashes matched afterward. |

## Remaining issues

Benchmarks require a representative authorized corpus with labelled positives
and real-world false positives. The synthetic runs support workflow validation
and cannot rank the variants. License records retain the discrepancy between
the distribution's AGPL-3.0 license and PyPI metadata, and the limitations
around separate weights terms and training data.


## Files

Paths in the core groups are relative to `src/forensic_image_scanner/`.

| Change | Files |
| --- | --- |
| Created | `docs/iterations/FIS-010-DET-02.md`, `docs/model_manifests/nudenet-640m.json`, `src/fis_nudenet_backend/__init__.py`, `src/fis_nudenet_backend/worker.py`, `tests/test_nudenet_backend.py`, `tests/test_nudenet_real.py` |
| Created in core | `model_manifests/nudenet-640m.json`, `models/nudenet_installation.py`, `scoring/ensemble.py` |
| Modified outside core | `MODEL_LICENSES.md`, `MODEL_PROVENANCE.md`, `README.md`, `THIRD_PARTY_NOTICES.md`, `docs/architecture.md`, `docs/iterations/INDEX.md`, `docs/model_audit.md`, `docs/model_manifests/nudenet-320n.json`, `docs/model_policy.md`, `pyproject.toml`, `tests/test_gui_smoke.py`, `tests/test_model_installation.py` |
| Modified in core | `analysis.py`, `analysis_service.py`, `calibration/metrics.py`, `calibration/report.py`, `calibration/runner.py`, `cli.py`, `detectors/nudenet.py`, `gui/main_window.py`, `gui/pages/analyze_page.py`, `gui/pages/models_page.py`, `gui/pages/results_page.py`, `gui/state/application_state.py`, `gui/workers/model_installation_worker.py`, `model_manifests/nudenet-320n.json`, `models/downloader.py`, `models/importer.py`, `models/installation.py`, `models/manifest.py`, `reports/csv_report.py`, `results.py` |
