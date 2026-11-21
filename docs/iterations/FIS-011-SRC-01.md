# FIS-011 · SRC-01 — Evidence Source & Target Workflow

Status: **ACTIVE**

## Objective

FIS-011 introduces an explicit, Qt-independent operation model:

```text
SOURCE → TARGET → OPERATION
```

It prepares the application for later recovery engines without claiming that
deleted-file recovery exists. The sole executable combination in this iteration
is `DIRECTORY + ANALYZE`.

## Architecture delivered

- `workflow/models.py` defines immutable `SourceDescriptor`, `TargetDescriptor`
  and `WorkflowRequest` values plus stable `SourceKind`, `OperationMode`, and
  candidate image-format enums.
- `workflow/validation.py` owns the compatibility matrix and structured
  `INFO`, `WARNING`, and `ERROR` findings.
- `workflow/source_inspection.py` describes directories and extension-based
  forensic-image candidates. An extension is never reported as verified format.
- `workflow/device_discovery.py` invokes `lsblk` with an argument list and parses
  JSON into source descriptors outside the GUI.
- `workflow/adapters.py` is the only route from a supported `WorkflowRequest` to
  the existing `AnalysisRequest` and `AnalysisService` pipeline.

The application state now exposes typed source, target, operation, and
capability notifications. Compatibility aliases remain for result/export code.
Changing a source invalidates old discovery readiness but does not delete or
discard completed result objects or files.

## Source and operation values

`SourceKind`:

- `directory`
- `forensic_image`
- `physical_device`

`OperationMode`:

- `recover`
- `recover_analyze`
- `analyze`

## Capability boundary

| Source | Analyze | Recover | Recover + analyze |
| --- | --- | --- | --- |
| Directory | **Supported** | Not yet supported | Not yet supported |
| Forensic image | Not yet supported | Not yet supported | Not yet supported |
| Physical device | Not yet supported | Not yet supported | Not yet supported |

Unsupported recovery selections remain configurable and visible, but their
start action is disabled. The UI identifies The Sleuth Kit and PhotoRec as
planned engines; neither is installed, invoked, or simulated here.

## Linux device discovery

Discovery uses:

```text
lsblk --json --bytes --output NAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA,RM,FSTYPE,MOUNTPOINTS
```

Only read-only host metadata is requested. FIS does not open devices for write,
mount or unmount filesystems, run repair tools, invoke TRIM, or request sudo.
Missing metadata is tolerated. Where the kernel reports enough information,
devices are labelled HDD, SATA SSD, or NVMe SSD; otherwise the type is unknown.
The descriptor also reports normal-user raw-read availability. SSD/NVMe sources
receive a TRIM/garbage-collection warning without a recoverability claim.

## Target safety

The target is explicit and validated independently of Qt. Validation blocks a
target equal to or nested under a directory source and rejects a non-directory
or unwritable target. Physical-source backing-device collision resolution is
reported as **unknown**, not safe. Strict resolution must land before physical
recovery is enabled.

## GUI

The existing internal `analyze` route now presents a scrollable **New
Operation** page with:

1. Folder, forensic-image, and physical-drive source cards.
2. An explicit target picker and future directory-layout preview.
3. Three mutually exclusive operation cards and an operation summary.
4. **Inspect Source** and a workflow-aware, capability-gated start action.

The home action is **New Operation**, the sidebar label is **Operación**, and
the header badge changes between **EVIDENCE READ-ONLY** and **WORKING COPY**.
Physical devices and forensic images always force evidence semantics.

## Test coverage

Automated coverage includes:

- immutable workflow models and enum values;
- the full FIS-011 capability matrix;
- source/target collision validation;
- unverified RAW/DD/IMG/E01/Ex01 candidate classification;
- deterministic `lsblk` JSON fixtures for HDD, SATA SSD, NVMe SSD, removable,
  mounted, and incomplete devices;
- GUI source/target/operation controls, recovery gating, typed state signals,
  stale-discovery invalidation, result preservation, and header semantics;
- adaptation of only `DIRECTORY + ANALYZE` to `AnalysisRequest`.

Delivery validation on 2026-11-21:

- `pytest -q`: **125 passed, 3 deselected** (opt-in real-model tests)
- `ruff check .`: **All checks passed**
- `python -m pip check`: **No broken requirements found**

## Technical decisions and deviations

- `MappingProxyType` makes descriptor metadata immutable at the workflow
  boundary rather than exposing a mutable dictionary.
- Existing `selected_source` and `output_directory` properties remain temporary
  compatibility views; typed descriptors are authoritative.
- Physical backing-device collision protection remains unresolved and is
  honestly returned as unknown. No physical workflow is executable.
- No recovery CLI was added. The model is ready for a future `run` command while
  the existing `scan` command remains unchanged.
- No new recovery, media, or acquisition dependency was introduced. `lsblk` is
  an optional Linux host capability.

## Forward path

- **FIS-012:** The Sleuth Kit metadata recovery
- **FIS-013:** PhotoRec file carving
- **FIS-014:** recovered-media validation
- **FIS-015:** recovery-to-detection pipeline
- **FIS-016:** forensic acquisition

Before any physical recovery action is enabled, the router must have a real
engine, strict source/target backing-device collision protection, appropriate
read-permission handling, and auditable recovered-file validation.
