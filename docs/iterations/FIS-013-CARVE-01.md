# FIS-013 · CARVE-01 — Multimedia File Carving

| Field | Value |
| --- | --- |
| Status | Active; implementation and local PhotoRec validation complete |
| Opened | 2026-11-21 |
| Platform | Fedora Linux 45 (KDE Plasma Desktop Edition) |
| PhotoRec detected | 7.2 at `/usr/bin/photorec` |
| TSK detected | Not installed; real combined-engine validation unavailable |
| Commit | Pending |
| Tag | Pending |

## Capability delivered

FIS can execute `FORENSIC_IMAGE + RECOVER` with a system-installed PhotoRec,
whether or not TSK is available. It never downloads, installs, vendors, or
shell-invokes PhotoRec. Physical-device recovery, directory carving, semantic
media validation, and Recovery + Analyze remain disabled.

The Qt-independent carving path is:

```text
forensic image + selected FIS-012 volume
  -> PhotoRec scripted command (media signature families only)
  -> TARGET/.fis-tmp/photorec-*
  -> FIS extension policy + non-zero/basic containment checks
  -> streaming SHA-256 + cross-engine deduplication
  -> recovered/carved/volume-NN/{images,videos}
  -> recovery JSON + CSV + sanitized logs
```

All subprocesses receive argument arrays; `shell=True` is absent. Cancellation
and timeout terminate only the FIS-owned child process. Completed normalized
files are preserved, incomplete temporary output is removed, and a partial
session report is written.

## PhotoRec configuration and scope

FIS enables identifiers accepted by the installed PhotoRec 7.2 scripted-command
parser, not arbitrary filename extensions:

- images: `jpg`, `png`, `gif`, `bmp`, `tif`, `raf`, `orf`, `rw2`;
- videos: `mov`, `riff`, `mkv`, `mpg`, `asf`, `m2ts`, `ts`.

These are PhotoRec signature families and can cover multiple extensions. FIS
normalization then retains only the narrower project image/video allowlist. It
does not represent that every requested extension has its own PhotoRec family.

For NTFS, FAT12/16/32, and Ext2/3/4 volumes, the plan requests PhotoRec free-space
scanning. Other or unknown filesystems use whole-space scanning and expose that
scope in the GUI and canonical report. GPT and MBR partition selection reuses the
FIS-012 volume-table slot; a raw/single-filesystem image uses `partition_none`.

## Records, reports, and deduplication

Every carved record has `method = file_carving`, engine identity, volume,
candidate kind and extension, recovered size, SHA-256, target-relative path,
and status. `original_name`, `original_path`, and `metadata_address` are exactly
`UNKNOWN`; no filesystem identity is inferred from PhotoRec output names.

`recovery.json` remains canonical. JSON and CSV distinguish filesystem recovered,
carved, duplicate, partial, failed, and skipped counts. When a PhotoRec hash
matches an artifact already recovered through TSK, FIS removes the redundant
carved copy, points its carving record at the canonical artifact, marks the
record as a duplicate, and preserves both provenance records. A combined report
uses `recovery_method = mixed` and lists both methods.

FIS-013 performs only basic sanity checks: the candidate must be a regular,
non-symlink media-policy file, non-empty, hashable, and normalizable below the
target. It makes no claim that the bytes form a complete or semantically valid
image/video; that belongs to FIS-014.

## Output

```text
TARGET/
├── recovered/carved/volume-NN/images/
├── recovered/carved/volume-NN/videos/
├── reports/recovery.json
├── reports/recovery.csv
├── logs/recovery.log
└── logs/photorec-volume-NN.log
```

The target is checked before and during normalization using the same conservative
free-space floor as filesystem recovery. `ENOSPC` stops further carving, preserves
completed files, removes session temporary output, and records the failure.

## Local disposable-image validation

A 96 MiB Ext4 image was created outside Git without mounting it. It contained an
existing JPEG, a deleted PNG with metadata, a deleted WEBP whose inode metadata
was cleared, a deleted MP4, and a deleted text file. Since TSK was unavailable,
FIS could not obtain reliable filesystem/partition context and accurately used
`partition_none` plus `wholespace`; this was not a deleted-only scan.

PhotoRec produced four accepted media candidates. FIS normalized one JPEG, one
PNG, one WEBP, and one MP4, and ignored the non-media text output. All four
recovered SHA-256 values matched the original fixture bytes. The report recorded:

| Metric | Result |
| --- | ---: |
| Volumes inspected | 1 |
| Media candidates | 4 |
| Carved | 4 |
| Duplicates | 0 |
| Partial | 0 |
| Failed | 0 |

A deterministic cross-engine unit session recovered one canonical filesystem
artifact and then encountered identical PhotoRec bytes. The output retained one
artifact and two records: the filesystem record plus a carving duplicate record
linked by SHA-256.

## Validation record

Tests cover capability probing, version parsing, safe argument arrays, real
format-family configuration, partition selection, scope selection, output
normalization, image/video filtering, non-media rejection, zero-byte rejection,
SHA-256, cross-engine deduplication, containment, cancellation, timeout, disk-full
handling, UNKNOWN carving identity, mixed reports, and child-process ownership.

| Check | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | 179 passed, 1 TSK integration skipped, 3 real-model tests deselected |
| `.venv/bin/python -m pytest -q -m photorec` | 1 passed, 182 deselected |
| `.venv/bin/python -m pytest -q -m tsk` | 1 skipped because system TSK is absent, 182 deselected |
| `ruff check .` | Passed |
| `python -m pip check` | No broken requirements |
| `git diff --check` | Passed |

The optional real-engine marker probes the installed PhotoRec without placing
large forensic images in Git. The TSK marker remains skipped because the four
required TSK commands are absent. The global user-level `pytest` launcher was
stale and lacked its `_pytest` module, so validation used the project's working
virtual environment explicitly.

## Known limitations

- TSK is unavailable on this host, so no real combined TSK + PhotoRec run or
  free-space partition run is claimed; cross-engine deduplication is deterministic
  unit validation.
- Broad PhotoRec families such as `riff`, `mov`, and `tif` can emit formats outside
  the requested media policy. FIS discards those files during normalization.
- Free-space scanning is requested only for the explicitly recognized filesystem
  families. Unknown layouts are intentionally reported and scanned as whole space.
- PhotoRec recovery names and offsets do not establish original filenames, paths,
  filesystem metadata, deletion state, or semantic integrity.
- EWF support depends on the installed PhotoRec build and input handling. No E01
  or split-image carving result is claimed in this iteration.
- Source SHA-256 remains caller-supplied; FIS records a before/after size and mtime
  guard but does not automatically hash a large source image.

## Preparation for FIS-014

Every canonical artifact now has a stable target-relative path, size, SHA-256,
candidate media kind, recovery method, and provenance record. FIS-014 can decode,
signature-check, and classify integrity without changing the honest carving
identity boundary or rerunning recovery.

