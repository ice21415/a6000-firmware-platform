# EventManager Provider Status — Phase 4.11

The SHA-pinned private `libObj.so` was analyzed offline by
`fwplatform.event_manager_provider_probe`. The getter entry `0x7ef1e4`
contains the verified Thumb sequence at `0x7ef234`, `0x7ef23a` and
`0x7ef23c`: load a table offset, load a function pointer through the table,
and call it with `blx r3`.

The table slot is `0x1032238`. Its dynamic relocation is `.rel.dyn`
`R_ARM_RELATIVE`, with the initial value pointing at BSS cell `0x10a8930`.
This proves the indirection and its address space, but not the runtime writer
or the eventual callback implementation.

The executable literal scan found no direct writer for `0x10a8930`. The
negative result is bounded to absolute literals in executable PT_LOAD data;
register-derived stores, PC-relative stores, aliases and external DSO writers
remain unsearched. `.init_array` metadata is present, but no constructor-to-
cell write was established.

`EventManager::push` at `0x7ef988` therefore remains an unresolved indirect
dispatch with static ABI `callback([state + 0x04], Event*)`. Provider instance
identity, vtable `+0x30` implementation, AppConfigAC selection and the
ModelCamera consumer are UNKNOWN. No runtime or safe-callable API is claimed.

The AppConfigAC candidate was independently checked. `getConfig` (`0x106c6c`)
returns the singleton at BSS `0x10a8a9c`; `initializeConfig` (`0x106da8`)
allocates and stores that singleton, and vtable slot `0x1007558` contains the
Thumb target `0x45ee64`. These are configuration facts, but no static writer
or selection condition connects this singleton to provider cell `0x10a8930`;
the candidate is therefore not promoted to the main dispatch callback.
