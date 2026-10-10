# Camera Core progress (Phase 4.6)

The private SHA-pinned chain probe now records 39 primary-ELF edges, 7
static-inferred edges and 5 unresolved edges. Phase 4.8 added two bounded
loader-helper relations at `0x7f11d8` and `0x7f11e6`. A relocation audit
showed these are internal helpers; their relationship to the separate
`dlopen`/`dlsym` PLT candidates is not proven. This does not promote any
consumer, callback or runtime ABI claim. The
machine-readable scope is
`sdk/camera_core_progress_3_21.json`.

The reusable `camera_candidate_ranking` helper ranks indirect targets by
address-space, binary hash, vtable-slot and instruction/relocation evidence.
It explicitly keeps every result unresolved until a unique primary proof exists.
The highest-value next target remains the registry/loader condition connecting
the ModelCamera factory and the EventManager dispatch receiver.

The Phase 4.7 loader audit found the configured library/factory strings in the
pinned ELF but no separate `modelCamera.so` file in the authorized extracted
filesystem. This excludes one filesystem candidate, but does not establish the
runtime alias or registry instance identity.

The Phase 4.8 loader dataflow probe also verifies record fields `+0x10`
(dlopen input), `+0x14` (dlsym symbol), `+0x18` (handle), `+0x1c` (factory
result) and `+0x20` (factory argument), including null failure branches.
Runtime DSO selection and Registry to ModelCamera identity remain UNKNOWN.
