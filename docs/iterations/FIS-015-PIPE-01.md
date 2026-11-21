# FIS-015 · PIPE-01 — Recovery + Detection Pipeline

Forensic-image recovery can feed the media catalog and existing image detector
profiles. The pipeline records integrity and all catalog recovery provenance with
each image finding. Corrupt and unsupported items are skipped, never rated LOW.
Physical-device recovery remains disabled.

Videos are sampled with the system ffmpeg at five-second intervals, capped at
1,000 frames by default. The highest sampled-frame triage represents the video;
this is sampled video analysis, not exhaustive inspection. REVIEW/HIGH frame
results and timestamps are retained in `reports/pipeline_summary.json`.
Temporary frames are removed after processing or cancellation.

The CLI supports `run IMAGE --target CASE --operation recover-analyze --profile
combined`; sampling interval and cap can be configured. A missing ffmpeg skips
video sampling. Completed recovery, catalog, and analysis reports are preserved
on cancellation and the pipeline summary records partial results.

Validation: 191 tests passed, one TSK integration test was skipped because TSK
is unavailable, and three optional model tests were deselected. Ruff, pip check,
and git diff --check passed. The default tests use mocked recovery and detectors;
real combined TSK/PhotoRec and model execution remain environment-dependent.
