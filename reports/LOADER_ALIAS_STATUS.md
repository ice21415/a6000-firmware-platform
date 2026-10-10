# ModelCamera loader alias evidence (Phase 4.7)

The pinned private `libObj.so` was verified at SHA-256
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. A bounded
ELF string/symbol audit confirms that the image contains the configured strings
`modelCamera.so` and `ModelCameraToInstance`, and that the factory symbol name
is present in its symbol tables.

The authorized extracted 3.21 filesystem search found no separate file named
`modelCamera.so` or `modelcameratoinstance.so`. This narrows the search but does
not prove that `libObj.so` is the runtime `dlopen` target: loader search paths,
relocation binding, `dlsym` return value, and registry population remain
unresolved. No edge was promoted from this observation.

The reusable analyzer is `fwplatform/camera_loader_alias.py`; it requires a
SHA-pinned ELF and never emits firmware bytes or decompiler text.

## Phase 4.8 bounded loader dataflow

`fwplatform/camera_loader_dataflow.py` now decodes the loader body at
`0x7f11ca` and verifies its bounded callsites and record-field flow.  The
internal helper identities are kept separate from imported PLT candidates.
The pinned ELF proves:

| VMA | Fact | Status |
|---|---|---|
| `0x7f11d8` | call to internal helper `0xe0cec`; input is record `+0x10` | `STATIC_INFERRED` |
| `0x7f11dc` | returned handle stored at record `+0x18` | `PRIMARY_ELF_VERIFIED` |
| `0x7f11e6` | call to internal helper `0xdfed0`; symbol name is record `+0x14` | `STATIC_INFERRED` |
| `0x7f11f2` | indirect call through the `dlsym` result, with record `+0x20` as `r1` | `PRIMARY_ELF_VERIFIED` |
| `0x7f11f4` | factory return stored at record `+0x1c` | `PRIMARY_ELF_VERIFIED` |

The record initializer at `0x7f1156` writes the factory argument and DSO
argument into `+0x14` and `+0x20`; registration at `0x7ec8a4` calls that
initializer at `0x7ec91c`.  Null handle, symbol, dlsym result and factory
result branches are retained as failure paths.  These facts establish the
loader dataflow only.  The selected runtime DSO, registry key-to-instance
mapping and ModelCamera vtable identity remain `UNKNOWN`.

## Phase 4.9 helper veneer audit

The exact SHA-pinned bytes at `0xe0cec` and `0xdfed0` decode as ARM-mode
three-instruction veneers (`add ip,pc`, `add ip,ip`, `ldr pc,[ip,#imm]!`).
They are not Thumb function bodies and the bounded probe now records their
mode and instruction evidence. Their computed indirect table destinations do
not, by themselves, identify the `dlopen`/`dlsym` imports; the helper-to-import
binding remains `UNKNOWN`. This narrows the loader hypothesis without proving
runtime DSO identity.

## Phase 4.10 ARM veneer relocation resolution

Using ARM-state PC arithmetic (`instruction address + 8`), the private ELF
resolves both loader veneers uniquely:

| Veneer | Effective GOT VMA | Relocation | Dynamic symbol | Status |
|---|---:|---|---|---|
| `0xe0cec` | `0x102e808` | `R_ARM_JUMP_SLOT` | `dlopen` | `PRIMARY_ELF_VERIFIED` |
| `0xdfed0` | `0x102e398` | `R_ARM_JUMP_SLOT` | `dlsym` | `PRIMARY_ELF_VERIFIED` |

The resolver checks the full ELF hash, instruction mode, file-backed GOT
range, relocation section and dynamic symbol index. Runtime DSO identity and
factory object type remain UNKNOWN.

The same bounded decode also verifies the post-factory path: `0x7f11d2`
loads `0x101` into `r1` before the loader helper, `0x7f120e` reads the
returned instance vtable slot `+0x28`, and `0x7f1210` invokes it. A null
factory result branches to cleanup at `0x7f1238`; the cleanup helper is
therefore not evidence that the factory object was a particular runtime DSO.
