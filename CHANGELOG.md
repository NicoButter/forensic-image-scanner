# Changelog

## 0.1.0 — Alpha release candidate (unreleased)

- Added local image triage with SHA-256 provenance, explicit human review, and
  metadata-only Safe Review Mode by default.
- Added filesystem recovery and PhotoRec carving as optional external workflows,
  followed by media integrity validation and consolidated reports.
- Added physical acquisition through optional libewf or GNU ddrescue tools,
  explicit safety gates, resumable RAW acquisition, and E01 verification.
- Added persistent forensic cases with stable identity, provenance references,
  append-only audit events, and offline JSON/HTML reports.
- Documented that video review is sampled, recovery may be incomplete, models
  may produce false positives and false negatives, and external tools are
  optional.

This pre-release candidate is not a claim of production readiness or a
substitute for independent evidence-handling procedures.
