# Camera Core progress (Phase 4.6)

The private SHA-pinned chain probe was rerun against the authorized `libObj.so`
and reproduced 39 primary-ELF edges, 5 static-inferred edges and 5 unresolved
edges. This run added no new primary edge and therefore did not promote any
consumer, callback or runtime ABI claim. The machine-readable scope is
`sdk/camera_core_progress_3_21.json`.

The reusable `camera_candidate_ranking` helper ranks indirect targets by
address-space, binary hash, vtable-slot and instruction/relocation evidence.
It explicitly keeps every result unresolved until a unique primary proof exists.
The highest-value next target remains the registry/loader condition connecting
the ModelCamera factory and the EventManager dispatch receiver.
