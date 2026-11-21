# FIS-014 · MEDIA-01 — Recovered Media Validation & Catalog

The media layer groups recovered artifacts by their recorded SHA-256, preserves
all recovery provenance, and writes `media_catalog.json` and spreadsheet-safe
`media_catalog.csv` under the case reports directory. Recovery status remains
independent from media integrity. The CLI `validate-media TARGET` rebuilds the
catalog from the existing recovery report without repeating recovery.

Images are opened, verified, and decoded with Pillow or the optional HEIF/RAW
integrations. A successful truncated decode is partial; unavailable optional
decoders are unsupported. Video validation uses a bounded, system-installed
`ffprobe` JSON process. Readable streams with probe warnings, missing duration,
or incomplete recovery are partial. A missing ffprobe is unsupported. These
checks do not guarantee complete playback or semantic integrity.

Validation reads recovered artifacts and leaves them in place. A media item
retains its candidate extension, detected format, metadata, recovery IDs,
methods, original paths where known, warnings, and errors. FIS-015 can consume
the canonical catalog while continuing to preserve recovery provenance.

Validation: 185 tests passed, one TSK integration test skipped because TSK was
not installed, and three optional model tests were deselected. Ruff, pip check,
and git diff --check passed. Video validation inspects container metadata and
does not decode every frame.
