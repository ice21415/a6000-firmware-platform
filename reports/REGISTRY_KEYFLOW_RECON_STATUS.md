# Phase 4.21 — Registry Key / Record Pointer Targeted Probe

This checkpoint was implemented directly through the connected GitHub repository,
without Codex. The actual Sony firmware ELF **was not available** to the
assistant's current environment; therefore **no new PRIMARY_ELF_VERIFIED
relationship, verified store, runtime API or resolved blocker is claimed**.

## Reproducible offline read-only analysis

On an authorized local machine with a privately retained firmware 3.21 ELF:

```bash
python -m fwplatform.camera_registry_keyflow_probe --elf /private/path/to/libObj.so
```

The probe rejects a SHA-256 mismatch against the expected Sony A6000 v3.21
ELF. It uses the existing ARM/Thumb bounded CFG and finite-set dataflow engine,
and runs only against file-backed ELF VMAs. It neither executes the firmware
nor accesses a camera. Do not commit or upload private ELF input or raw outputs.

Targeted VMA entry windows:

| Function hypothesis | Entry VMA | Intended observation |
|---|---|---|
| Camera registration configuration | `0x401f78` | IdGenerator / IdSoTable call arguments |
| IdSoTable add | `0x7f08a0` | integer-key insertion helper |
| Tree key lookup | `0x7f063c` | comparison/return helper |
| Registry record registration | `0x7ec8a4` | constructor and insert calls |
| Registry lookup | `0x7eb8fa` | key and returned record path |
| Generic Consumer | `0x7ed49c` | Lookup and State Machine handoff |
| Record State Machine | `0x7eac60` | symbolic r1 → object-relative stores |
| Loader | `0x7f11ca` | instance pointer store `+0x1c` |
| Forwarder | `0x7f124a` | instance use |

For the State Machine, r1 is initialized to a synthetic marker 0x40000000
and writes to the marker's +8 offset are reported as **intra-function
argument-relative aliases**. This is a bounded analytical device, not a real
camera pointer or proof of registration-to-lookup record equivalence. Other
objects writing +8 are never automatically joined. Value provenance and CFG
limitations are retained; IT blocks, unknown stack/heap, indirect branches,
and mutable memory cause fail-closed incompleteness.

Synthetic regression tests test direct aliases, unrelated bases, unknown
aliases, unsupported IT blocks, invalid inputs and SHA rejection.

## Outstanding proof obligations

1. Show `0x402090` IdGenerator's return value is the key passed into
   `0x4020a0`, including intermediate register and calling-convention steps.
2. Establish the exact key/record mapping at `0x7f08a0`, `0x7f063c`,
   `0x7ec8a4` and `0x7eb8fa`, with pointer identity and failure branches.
3. Establish the same returned record is loaded and later used as
   `+0x1c` by `0x7f124a`, and the factory result is stored on that record.
4. Bound the `0x7eac60` state transitions with explicit path predicates;
   equality of a symbolic argument is *not* equality of runtime instances.
5. Keep the runtime `modelCamera.so` identity UNKNOWN unless a separate
   legitimate proof is produced.

Primary status remains **57/67 tracked relations**, with 5 inferred and
5 unresolved. Runtime-verified APIs and safe-to-invoke APIs stay zero.
