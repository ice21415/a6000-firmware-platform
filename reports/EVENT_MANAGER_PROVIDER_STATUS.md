## Phase 4.15 Request scope correction

The initial Camera Core Request is class0 / destination2 and takes Queue0
at0x7ef9e0. Its normal local route bypasses0x7ef988 and0x11130c. Provider
selection and optional hook remain relevant to class1 events, not mandatory
prerequisites for this initial Request. Transfer0x7ef910 moves at most one
Event per invocation. Router mask0x02 and Consumer receiver+0xa4 gate are
explicit conditions; details are in CAMERA_END_TO_END_STATUS.md.

## Phase 4.14 current result

Callback `0x11130c` is a conditional pre-enqueue descriptor/destination
adapter, not the direct Application Router. EHABI interval is
`0x11130c..0x11141c`; executable body ends at `0x111400`, excluding its
literal pool. Reachable CFG: 96 instructions, 28 blocks, 105 flow edges.
Incoming r0 is the queue/list context retained in r6; r1 is Event* retained
in r5. It allocates 20 local stack bytes and has no proven stable status
return. EventManager ignores the callback result before inserting the Event.

Its descriptor helper `0x10fa04` admits Event ID `0x11013008` and queries
parameter key `0x17`, discriminator 6. It compares descriptors against
`0x17005002` and matches their low-nibble tags. A conditional path adds key
`0x1b` to the incoming Event and calls Event::setDest(0) on a peer Event.
Request `0x11004003` does not enter this descriptor arm without a preceding
transformation. Optional pre-hook `0x111324` reads actual BSS cell
`0x10a8c6c` through GOT `0x1034b90`; its writer/target remains UNKNOWN.
The mutable enable flag is at `0x10355bc` and is never assumed enabled.

Provider selection is `strncmp("AppConfig.so", incoming_name, 20)==0`:
compare calls `0x7ef216` and `0x7ef22e`, branches `0x7ef21a` and
`0x7ef232`, name literal `0xd87f27`. The name's runtime value, symbol
interposition and successful singleton initialization remain conditions.
Vtable +0x30 at `0x7ef8b0` returns a pointer stored at EventManager +8 by
`0x7ef8b2`; main callsite is `0x7ef988`. The conditional candidate remains
`0x11130c`, not an unconditional runtime identity.

The independent queue bridge is now instruction-verified:

`push -> queue1 append (0x7ef990) -> transfer (0x7ef910) -> queue0 ->
 dequeue (0x7ef940) -> application loop (0x7eeee8) -> router (0x7eed0c)
 -> generic consumer (callsite 0x7eedf0 -> 0x7ed49c)`.

Transfer pops at `0x7ef92a` and appends at `0x7ef932`. Application-loop
calls are `0x7ef03a` (transfer), `0x7eefda` (dequeue), `0x7eefe2` (router).
`0x7eedf0` is a CALLSITE, not a function entry. Event class byte +9,
same-owner EventManager identity, transfer guards/scheduling and destination
bit 2 remain explicit prerequisites. Enqueue is not proof of consumer execution.

Six new direct-call edges are tracked: 41 -> 47 primary, inferred 5 -> 5,
unresolved 5 -> 5; total 51 -> 57 because six real relations were added.
No former unresolved relation was silently removed. Runtime-verified and
safe-to-invoke APIs remain 0. ModelCamera loader identity remains UNKNOWN.
The disproven `0x10a8930` dependency is retained only as SUPERSEDED_DISPROVEN.

The ARM veneer resolver now handles Capstone's rotated-immediate form
`#80,#20`; original ELF relocations confirm allocation, addParameter,
setDest and logging imports. Full private instruction/CFG exports remain
local. Ghidra camera-main-dispatch profile is prepared; no new headless run
is claimed (launcher was not found in the inspected installation paths).
Next priority: actual hook cell `0x10a8c6c` writer/target and Request Event
class/destination flags at factory, followed by queue scheduling prerequisites.

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

## Phase 4.16 receiver/registry boundary

The current consumer evidence is independent of the superseded provider-cell
hypothesis. `0x7eaa14` reads a four-byte receiver-relative field at `+0xa4`
and normalizes it to zero/nonzero; `0x7ed4b2` passes the router owner's
receiver candidate. Setter `0x7eb118` stores caller `r1` at `r0+0xa4` at
`0x7eb12a`, but the five observed state-machine callers have not been proven
to be that router object.

After `0x7ed5fc` returns a registry record, `0x7ed606` rejects null and
requires unsigned `record[+8]` in `0x10001..0x6ffff` before `0x7f124a`.
The record initializer starts this field at `0x10000` and instance `+0x1c` at
zero. This is a validity gate, not a Model ID 11 proof; record identity,
runtime loader alias and instance selection remain UNKNOWN.
## Phase 4.17 state and provenance additions

The router's owner `+4` pointer is loaded at `0x7eedec` and passed to the
generic consumer at `0x7eedf0`; the consumer retains it in `r4` for the
`+0xa4` getter. Request `0x11004003` does not execute the observed setter
branches, so setter-to-request object identity remains conditional.

The lookup result now has direct provenance into state machine `0x7eac60`:
`0x7ed71e` calls lookup, `0x7ed722` moves its return to `r1`, and `0x7ed72e`
calls the state machine. The state machine preserves that record in `r4`,
reads `+8`, and conditionally writes `0x40000` at `0x7eaf4a` or `0x70000`
at `0x7eafce`. Forwarder calls use the same state-machine record pointer;
instance non-null and state branch conditions remain required.

The `@M00B` registration path is instruction-verified at `0x402090` and
`0x4020a0`; it supplies `modelCamera.so` and `ModelCameraToInstance` to the
registration API. IdGenerator's numeric return, lookup record identity and
runtime DSO alias remain unresolved. Runtime and safe-callable counts remain
zero.
