## Phase 4.13 correction ? current evidence takes precedence

The Phase 4.11/4.12 BSS-provider premise is disproven. Thumb ADD at
0x7ef1f6 uses PC 0x7ef1fa; literal 0x83d9d6 gives base 0x102cbd0.
Adding 0x5068 gives 0x1031c38, not 0x1032238. Its unique R_ARM_GLOB_DAT
relocation names getConfig. The load/call has one indirection and does not
read 0x10a8930. Historical records below are retained as superseded evidence.

Primary ELF re-read verifies getConfig -> singleton 0x10a8a9c;
initializeConfig store 0x106dbc; constructor vptr store 0x106c98 ->
0xfe9b70; slot +0x30 at 0xfe9ba0 -> 0x106900; GOT 0x1030f6c with
R_ARM_RELATIVE pointer 0x11130d -> callback entry 0x11130c.
This is a conditional static chain: AppConfig.so branch, successful
initialization, local symbol binding and unchanged object identity are
required. Main dispatch is not unconditionally resolved, and the route from
0x11130c to Application Router 0x7eedf0 remains unknown.

The requested 0x10a8930 writer has not been established, but it no longer
blocks this provider path. No runtime or safe-to-invoke API was added.
Tracked graph remains 41 primary / 5 inferred / 5 unresolved, total 51.

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

Phase 4.12 adds a reproducible `.init_array` inventory. The table at
`0xfd25a4` contains 263 ARM/Thumb pointer entries. Each entry is retained as
an address-only record with relocation and symbol-match metadata; constructor
bodies and indirect callees are deliberately not promoted without a bounded
dataflow proof. No constructor-to-`0x10a8930` writer is confirmed in this
inventory.

The reproducible entry-plus-100-byte pass examined 780 store instructions
across the 263 entry bodies and found no direct-target store candidate. This
bounded count is an analysis-coverage metric, not a claim that all constructor
control flow was recovered.

The bounded Thumb store scan decoded 160 instructions before the available
code/data boundary and found zero explicit-target store candidates. This is
not whole-image coverage: ARM-mode regions, mixed-mode boundaries, computed
aliases and external writers remain unresolved. It is a bounded negative
observation, not proof that no writer exists.

The complete inventory contains 263 unique entries, each backed by an
`R_ARM_RELATIVE` relocation. The target cell has no relocation of its own and
is outside the file-backed portion of its PT_LOAD (`p_memsz` contains it,
`p_filesz` does not). A bounded constructor pass found no direct literal,
MOVW/MOVT or store proof for the cell. The `initializeConfig` init path writes
`0x10a8a90`, not `0x10a8930`, so it is explicitly excluded as this cell's
writer.

Phase 4.13 CFG effective-address run: 263 init entries plus getter,
initializeConfig and getConfig = 266 analyses; 3,631 reachable instructions,
287 stores. Zero proven writes to 0x10a8930 in analyzed CFGs. At 0x106dbc,
function 0x106da8, register origins 0x106db8/0x106dba prove destination
0x10a8a9c; written value remains UNKNOWN after allocator/constructor calls.
264 entries lacked symbol sizes and used bounded 512-byte windows; these
are partial CFGs, not full function boundaries. Indirect callees, stack
aliases and external writers remain unresolved.
