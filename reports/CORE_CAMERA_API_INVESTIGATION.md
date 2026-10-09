# Core Camera / Lens / Sensor / Media API Investigation

Research scope: Sony ILCE-6000 firmware 3.21; offline, descriptive only.
This report distinguishes **known static artifacts** from **unknown API semantics**.
The private firmware database, ELF files, Ghidra JSONL and physical camera observations
are not included or copied into the public repository.

## Existing leads and their evidence limits

| Research area | Static lead | What is actually supported | Still missing |
|---|---|---|---|
| Camera / ModelCamera | `ModelCamera.selector_dispatch` associated with `libObj.so` in the older local architecture atlas | A named state-machine observation with a module association; publicly summarized state transitions are static only | Exact dispatcher function entry, independent branch-to-action and payload evidence, camera-ready/first-shot causality |
| Lens / focus | Lens/focus lexical symbol review queue | Candidate names and individually inventoried ELF entry locations, if present in a local database | Independently established focus ABI, callback/queue causality and lens hardware effect |
| Sensor / ISP | `libObj.so` lists a `libsencore.so` dynamic dependency in the older local atlas | A module-level loader dependency, **not** proof of an imager-control call | Unique symbol provider, sensor register/payload semantics and validated dataflow |
| Media / imaging | `libObj.so` lists `libInfraMediaCommon.so` as a dependency in the older local atlas | A module-level loader dependency only | Image pipeline callsites, buffers, ownership, thread context and return/error semantics |
| UI / readiness | Separate UI-ready and camera-ready concepts in existing state-machine research | Distinct symbolic states in research records | Verified transition from user event to camera prepare, ready and first shot |

The architecture atlas is a historical local metadata snapshot from 2026-10-08,
not a newly reproduced Ghidra analysis. It reported 709 ELF records and 707
structurally analyzed, while Ghidra CFG analysis had been executed on a much
smaller sample set. ELF indexing **must not** be described as full function
semantic recovery. The public phase-three camera report summarizes two state
machines and 28 transitions; that does not establish on-device behavior.

## Evidence-first procedure

Use a **backed-up private database copy**. All commands below query evidence
and do not call or patch camera firmware:

```powershell
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk investigate --domain Camera --limit 25 --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk investigate --domain Lens --include-internal --limit 50 --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk investigate --domain Sensor --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk investigate --domain Media --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk inspect --function-id 12345 --json
```

The final command uses **an example database-local function ID**, not an actual
Sony function/address. Take a real ID from the local `sdk investigate` output,
Ghidra import, or a database function query. For stripped functions, ID-based
inspection is preferred to assigning a domain by a generated name.

For each interface proposed as core SDK work, independently gather and verify:

1. ELF SHA-256, address space, normalized entry and Ghidra body/CFG proof.
2. Exact caller/callee function IDs with source evidence (not name-only matching).
3. Calling convention, parameter layout, return/error behavior and independent
   instruction or callsite evidence (Ghidra prototypes alone are not ABI).
4. OSAL queue namespace, command/payload, function-id producer/consumer and
   callback relationships **only** when expressly supported; JNI requires
   exact native/DEX method linkage.
5. Camera selector state and readiness links only where a direct causal edge is
   independently established; otherwise mark as **UNKNOWN**.

## Current status

- **Implementation:** `sdk investigate`, `sdk inspect`, bounded direct-reference
  retrieval and synthetic provenance tests are in the pull request.
- **Static API candidate discovery:** available, with ELF/linkage evidence and
  explicit ambiguity handling.
- **Real Camera/Lens/Sensor ABI recovery:** **NOT ESTABLISHED** by available public evidence.
- **Real device runtime/callability/safety:** **UNKNOWN**; no physical-device
  or firmware write operations are implemented here.
- **Full core API denominator:** **UNKNOWN**; there is no justified completion
  percentage and no published complete executable Sony SDK.
