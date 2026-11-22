# Security policy

This project is an alpha pre-release candidate (0.1.0); it has no supported
stable production release. Please report suspected vulnerabilities privately
to the repository owner rather than opening a public issue. Include affected
versions, reproduction steps, impact, and any suggested mitigation; do not
attach sensitive or evidentiary images.

The tool does not replace evidence-handling procedures. Run it in an appropriately
isolated environment with least privilege and read-only mounts where available.
Dependency installation may access package indexes, but runtime analysis must not
send images, hashes, metadata, or results to external services.

FIS does not automatically invoke sudo or provide a hardware write blocker.
Physical-device acquisition must be performed with an independently verified
write-protection procedure. Optional tools run as separate local processes;
their versions, build options, permissions, and licensing remain the operator's
responsibility.
