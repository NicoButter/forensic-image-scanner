# FIS-017 CASE-01 — Forensic Case Management

**Status: DONE**

FIS-017 gives acquisition, recovery, media validation, and analysis work a
persistent case identity. A case stores optional examiner-supplied metadata in
`case.json`, source and artifact references as paths relative to its root, and
an append-only JSON Lines audit trail under `logs/audit.jsonl`.

The stable case ID has the form `FIS-YYYYMMDD-XXXXXXXX`; it is generated once
and persisted independently of the directory name. Case metadata values not
provided by the examiner remain null. Case updates replace `case.json`
atomically. Referenced artifacts must remain regular files inside the case
directory, and audit entries must match the case ID.

The consolidated JSON and offline HTML report live in `reports/`. Findings
contain references and concise triage data; the report does not embed evidence
images. It states that human review is required, FIS triage is not a legal
conclusion, and video analysis samples frames rather than examining every
frame.

```bash
forensic-image-scanner case create /cases/incident-001 \
  --case-number INC-001 --examiner "Examiner"
forensic-image-scanner run /evidence/disk.E01 --case /cases/incident-001 \
  --operation recover-analyze
forensic-image-scanner case report /cases/incident-001
forensic-image-scanner case complete /cases/incident-001
```

Completed cases reject further mutation until explicitly reopened with
`forensic-image-scanner case reopen CASE_DIR`. Completion finalizes case
metadata but does not make evidence immutable at the operating-system level.

Standalone operation targets remain supported. With `--case`, an existing
case directory is used as the output root; directory analysis writes under its
`reports/` directory. FIS-017 does not replace acquisition, recovery, or
analysis services.
