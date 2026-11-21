# FIS-008 · CAL-01 — Precision & False Positive Calibration

| Field | Value |
| --- | --- |
| Iteration ID | FIS-008 |
| Work package | CAL-01 |
| Title | Precision & False Positive Calibration |
| Status | Implemented and verified locally |
| Date opened | 2026-11-21 |
| Baseline | `main` after FIS-007 · EXP-01 |
| Git commit | Pending |
| Git tag | Pending |

## Problem

Results opened with all categories visible, so files already assessed as
`LOW` could be mistaken for items requiring review. The experimental
thresholds came from project judgment. The model test checked three solid
colors for valid probabilities and offered little diagnostic visibility.

## Objective

Show the review queue by default, retain the raw probabilities and full
reports, and provide a reproducible offline procedure for measuring how
thresholds affect both types of classification error.

## Scope

Centralize triage, update the Results workflow, add deterministic synthetic
controls, and measure a local labelled corpus with the verified Falconsai model
and a binary threshold sweep.

## Out of scope

Model training, model replacement, a second detector, persisted GUI threshold
settings, automatic threshold selection, GPU execution, and multiprocessing.

## Baseline behavior

| Behavior | FIS-007 | FIS-008 initial policy |
| --- | --- | --- |
| LOW | NSFW score < 0.30 | NSFW score < 0.60 |
| REVIEW | 0.30 ≤ NSFW score < 0.70 | 0.60 ≤ NSFW score < 0.85 |
| HIGH | NSFW score ≥ 0.70 | NSFW score ≥ 0.85 |
| Results filters on launch | HIGH, REVIEW, LOW, ERROR | HIGH, REVIEW |
| Model integration test | 3 solid colors | 13 generated controls, with diagnostic scores |

Both sets of thresholds are experimental. The model integration test at the
unmodified baseline passed against the installed model.

## Implementation decisions

- The immutable `TriagePolicy` takes the raw NSFW score. The detector's
  `confidence` still denotes the score of its top class. A caller can inject a
  different policy into `AnalysisService` or apply one directly to scores
  retained in prior reports.
- The Results summary counts every processed record as analyzed, including
  errors. Requires review counts `HIGH + REVIEW` across the whole batch.
  Per-category checkboxes and the two view modes affect visible rows only.
- Calibration reuses standard image discovery, registry verification, the
  production detector, and the read-only image pipeline. The report uses
  `nsfw_score >= threshold`. JSON per-file predictions use 0.50 independently
  of the project triage policy. The sweep evaluates ten thresholds from 0.50
  through 0.95 in increments of 0.05.
- Metrics include TP, FP, TN, FN, precision, recall/sensitivity, specificity,
  FPR, FNR, F1, and accuracy. Confusion matrices place predictions on rows and
  expected classes on columns. Undefined ratios are recorded as null and
  displayed with a dash. Errors have individual rows and are excluded from
  metric denominators. The output reports each threshold for human review.
- The optional output is a new JSON file. The corpus and the controlled model
  directory are excluded as report destinations. Calibration CSV and policy
  thresholds in the result detail were optional and deferred. The detail
  identifies the raw NSFW probability.

## Acceptance criteria

- [x] HIGH and REVIEW are visible initially, with descending NSFW ordering.
- [x] Show All Results and Show Relevant Only are reversible. LOW and ERROR
      remain available through individual filters.
- [x] JSON and CSV retain all analysis rows and raw scores.
- [x] Initial policy is centralized at 0.60 / 0.85 and can be replaced explicitly.
- [x] Synthetic scores can be produced and inspected.
- [x] The CLI scores a local corpus and reports a correct threshold sweep.
- [x] Model and calibration checks ran offline with Python network operations
      blocked. Corpus SHA-256 and integration evidence hashes were unchanged.
- [x] Default pytest, opt-in model pytest, Ruff, and pip check passed.

## Tests

- Policy defaults, threshold edges, invalid thresholds and scores, and
  reinterpretation under the earlier policy.
- List model filtering and ordering, Results view modes, and review totals.
- Full report retention, raw score preservation, and triage from NSFW while
  the model's top-class confidence was high.
- Hand-calculated confusion matrices and metrics, zero denominators, and CLI
  report, per-file error, and destination validation.
- An opt-in real Falconsai test checks normalization, finite probabilities,
  CPU device, absence of file errors, and preservation of original files.

## Results

| Check | Result |
| --- | --- |
| `pytest` | 83 passed, 1 model test deselected |
| `pytest -m model -s` | 1 passed, 83 deselected |
| `ruff check .` | Passed |
| `pip check` | No broken requirements |
| Real `calibrate --synthetic-controls` | 13 scored, 0 errors |
| Real `calibrate <temporary-corpus>` | 7 scored, 0 errors, all original hashes verified |

The run used the locally installed Falconsai revision
`96cb0d0342c7afb80cab76ecc58b265fa44da256` with model SHA-256
`97b2ce64ec146884b37f98ee7944ca4891aa72f6827dc0cb10684a1cbecd5830`.
The table displays eight decimal places. The JSON reports retain the raw values.

| Synthetic control | Normal | NSFW |
| --- | ---: | ---: |
| solid-white | 0.99082106 | 0.00917902 |
| solid-black | 0.97855830 | 0.02144173 |
| solid-gray | 0.99429977 | 0.00570027 |
| solid-red | 0.99715507 | 0.00284497 |
| solid-green | 0.99867767 | 0.00132234 |
| solid-blue | 0.99754936 | 0.00245067 |
| horizontal-gradient | 0.99673378 | 0.00326627 |
| vertical-gradient | 0.99521494 | 0.00478503 |
| checkerboard | 0.99895042 | 0.00104955 |
| circles | 0.99969125 | 0.00030883 |
| rectangles | 0.99870062 | 0.00129939 |
| lines | 0.99584156 | 0.00415840 |
| simple-noise | 0.99750972 | 0.00249026 |

All 13 controls fall into `LOW` under both triage policies. In the diagnostic
sweep all ten thresholds returned TN 13, FN 0, FP 0, and TP 0. Specificity and
accuracy were 1.000 and FPR was 0.000. Recall and other ratios requiring
positive cases or positive predictions were undefined.

The real CLI smoke-test corpus contained seven synthetic controls. Four were
filed under `normal/` and three under `nsfw/` to exercise the protocol. The
labels in this corpus were fixtures. At every swept threshold, the smoke test
reported TN 4, FN 3, FP 0, TP 0, recall 0.000, specificity 1.000, FPR 0.000,
FNR 1.000, F1 0.000, accuracy 0.571, and undefined precision.

The metrics unit test used known scores for both classes. At 0.70 it reported
TP 3, FP 1, TN 2, FN 0, precision 0.750, recall 1.000, FPR 0.333, and F1 0.857.
At 0.85 it reported TP 2, FP 0, TN 3, FN 1, precision 1.000, recall 0.667,
FPR 0.000, and F1 0.800.

## Open issues

A representative authorized corpus is still needed to measure operational
precision and recall. Include the reported false positives, such as bottles,
everyday objects, and near-white images, together with authorized positive
examples. Measure both error rates against an explicitly agreed review
criterion before adjusting policy again.

For FIS-009 · DET-02, use the same labelled corpus and compare the secondary
detector's incremental effect on missed positives and review workload.
