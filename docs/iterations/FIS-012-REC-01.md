# FIS-012 · REC-01 — Filesystem Deleted Media Recovery

| Field | Value |
| --- | --- |
| Status | Active; implementation and mocked validation complete |
| Opened | 2026-11-21 |
| Platform | Fedora Linux 45 (KDE Plasma Desktop Edition) |
| TSK detected | Not installed; `mmls`, `fsstat`, `fls`, and `icat` absent |
| Commit | Pending |
| Tag | Pending |

## Capability delivered

FIS can execute `FORENSIC_IMAGE + RECOVER` when the system TSK probe finds all
four required commands and source inspection identifies at least one supported
filesystem. `DIRECTORY + ANALYZE` remains executable. Directory recovery,
physical-device recovery, and Recovery + Analyze remain disabled.

The Qt-independent `FilesystemRecoveryService` and `TskBackend` implement:

```text
forensic image -> mmls -> fsstat -> fls deleted entries
               -> image/video extension filter -> icat -r
               -> TARGET/.fis-tmp -> size check -> streaming SHA-256
               -> atomic recovered file -> JSON + CSV + log
```

TSK receives the image only as an input argument. FIS never opens the source for
write, mounts it, repairs it, or invokes a package manager. Every subprocess uses
an argument array with a deadline; `shell=True` and shell redirection are absent.
Cancellation terminates only the current FIS-owned `icat` process, removes its
partial file, preserves completed recoveries, and writes the partial report.

## Recovery semantics

- Method: `filesystem_metadata`; this is not raw carving.
- Candidate selection: centralized image/video extension policy, case-insensitive.
- Extension means candidate media only; signature validation is deferred to FIS-014.
- Reallocated metadata is recorded and skipped by default.
- Orphans retain `original_path = null`; no path is invented.
- Original TSK metadata addresses, paths, timestamps, UID/GID, sizes, filesystem,
  partition offset, and deletion/reallocation state are retained.
- Output names are sanitized and deterministic. Original forensic paths remain
  unmodified in canonical JSON.
- A zero-byte extraction fails. A byte-count mismatch is `partial`, not recovered.
- Existing recovery reports are never overwritten.
- Source size and mtime are compared before and after as a non-cryptographic guard.

## Output

```text
TARGET/
├── recovered/filesystem/volume-NN/images/
├── recovered/filesystem/volume-NN/videos/
├── reports/recovery.json
├── reports/recovery.csv
└── logs/recovery.log
```

JSON preserves original strings. CSV applies the project's spreadsheet-formula
protection. Logs contain structured events and diagnostics, never recovered bytes.

## Validation record

The host did not contain TSK, so no real forensic image was generated and no
claim of real NTFS, FAT/exFAT, EXT4, or EWF recovery is made.

Deterministic tests covered:

- GPT and MBR `mmls` output, sector size, metadata/unallocated filtering, unicode,
  malformed rows, and the single-filesystem-image fallback;
- NTFS and Ext4 `fsstat` fixtures plus unsupported/EWF handling;
- `fls` paths containing spaces/unicode, NTFS address `1304-128-1`, reallocated
  entries, orphans, zero sizes, uppercase image/video extensions, and ignored files;
- exact offset-bearing argument arrays for `fsstat`, `fls`, and `icat`;
- successful, partial, empty, failed, timed-out, cancelled, and reallocated recovery;
- hostile path sanitization, collision-safe destinations, SHA-256, temporary cleanup,
  atomic reports, report non-overwrite, and source-stat preservation.

Fixture session totals: one filesystem volume, three deleted entries, one media
candidate, one recovered, zero partial, and zero failed in the success case.
Separate tests exercise partial and failure outcomes. These are simulated bytes,
not evidence of real filesystem recovery quality.

| Check | Result |
| --- | --- |
| Default `pytest -q` | 166 passed, 1 TSK integration skipped, 3 real-model tests deselected |
| `pytest -q -m tsk` | 1 skipped because system TSK is absent; 169 deselected |
| `ruff check .` | Passed |
| `python -m pip check` | No broken requirements |
| `git diff --check` | Passed |
| CLI missing-dependency path | `TSK_NOT_AVAILABLE`, exit 8, no installation attempted |

## Known limitations and unresolved validation

- Real `pytest -m tsk`, CLI inspection, and CLI recovery were skipped because TSK
  is absent. TSK version is therefore **UNKNOWN / NOT AVAILABLE**.
- No real NTFS, FAT32/exFAT, EXT4, E01, or split-image result is claimed.
- Long `fls` parsing is tested against the documented field model and fixtures;
  installed-version output must be validated when TSK becomes available.
- Candidate media are not decoded or signature-validated until FIS-014.
- Source SHA-256 is recorded only when supplied; FIS does not hash a large image
  automatically.
- Target free space uses a conservative runtime floor because total recoverable
  bytes cannot be predicted reliably.
- Cross-engine deduplication is deferred, but every output carries SHA-256 and
  `filesystem_metadata` provenance for FIS-013 merging.

## Upstream references

- [TSK `fls` manual](https://www.sleuthkit.org/sleuthkit/man/fls.html)
- [TSK license overview](https://www.sleuthkit.org/sleuthkit/licenses.php)

## Preparation for FIS-013

The report model separates recovery method from status, preserves source volume
and metadata identity, and hashes every finalized output. PhotoRec/file-carving
results can therefore use a distinct `file_carving` method and later deduplicate
against filesystem recovery without conflating provenance.
