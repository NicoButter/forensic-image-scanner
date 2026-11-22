# FIS-016 · ACQ-01 — Forensic Device Acquisition

Physical recovery first acquires a forensic image with system libewf or GNU
ddrescue, then passes that image to recovery or recovery and analysis. E01 must
pass ewfverify. RAW rescue preserves its mapfile for validated resume.

Safety checks block unresolved backing disks, source/target collisions, system
disks and read-write mounts. Source access is read-only; a hardware write blocker
is not verified. SSD/NVMe TRIM can limit deleted-data recovery. External tools
are not installed automatically.

The default test suite mocks acquisition tools and does not require real disks.
