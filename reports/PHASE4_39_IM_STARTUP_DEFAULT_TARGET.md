# Phase 4.39 — im.elf target defaults and conditional 0x4000 config selection

Source: original user-supplied ARM ELF `im-vendor-original.elf`, SHA256 `f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`; cross-check source `libIMDB.so`, SHA256 `9ceb21092a4987ec782fd980818aee687cde649af0999608bd6c40e1f46a84ea`. All findings are **offline static**, not verified execution.

## New concrete evidence

1. Original `im.elf` writable `.data` global base at `0x153e4` has a zero-valued target-string pointer at **base+0x10 = 0x153f4**. Its parser accepts a `target=` string at **0xa7f0–0xa800**, using `strncmp(...,7)` and storing the suffix pointer at `0xa7fe`. Main calls this parser at **0x9af2**; at **0x9b44–0x9b54** it reads that same target pointer through helper `0xa550`, falls back to static string **`default` at `0xc0af`** if zero, and uses the selected target for initializer setup.
2. `IMDB_find_target_bit` in original `libIMDB.so` names mask bit zero **`default`**, thus the lookup mask is **`0x1`** if the default string is used. The two IMDB rows for ID `0x83` are mutually exclusive under this mask: row 99 (`appFw.so`, mask `0xffffff9f`) matches; row 100 (`subapp.so`, mask `0x40`) does not. Row selection and execution remain conditional on the full dispatcher path.
3. Original `im.elf` parser at **0xa860–0xa872** compares a command-line token prefix with static **`cho`** at `0xc312` via `strncmp(...,3)`, and ORs `0x4000` into global flags at **base+0x9c**. Another parser condition at `0xa8f4–0xa90a` for prefix `cipa` clears `0xc000`, showing flags can be revised by later options; do not treat the `cho` observation as a guaranteed final flag state.
4. Main at **0x9b64–0x9b6c** passes parser flags into initializer-setup helper `0xac88`, which saves them at a separate structure `0x15484+0x1c` at **0xaccc** on the successful non-NULL, recognized-target path. Loader `0xb21a` calls getter `0xad78`, which tests bit **`0x4000`** of that saved field. The conditional `0xb220/0xb224` selects descriptor `+0x24/+0x28` for the guarded call at `0xb22c`.
5. The original `im.elf` direct `DT_NEEDED` list does **not** name `libObj.so`. The source ELF `libObj.so` exports `Application_System_Init`, but this is not proof that the `dlopen(NULL)` loader handle can actually see that symbol in the running process. Preload, namespace, transitive dependencies and boot-time availability remain unverified.

## Conditional interpretation

With target name `default`, no later overriding flags, and a successful traversal/lookup of IMDB ID `0x83`, the static registry masks admit the `appFw.so` row, and exclude the `subapp.so` row. For selected row 99, the dispatcher statically uses `dlopen(NULL)`, then `dlsym(...,"Application_System_Init")`. **If** lookup succeeds and its function pointer is invoked, it receives `AppConfig.so` for clear flag `0x4000`, or `AdjChkConfig.so` when set. The runtime process target, argument order, loader bindings and selected flags are UNKNOWN.

No device communication or firmware execution is involved. **Camera Core tracker unchanged:** 74 primary / 5 inferred / 5 unresolved = 84 tracked; no runtime API verification. Supporting cross-ELF evidence is kept separately in `sdk/im_bootstrap_3_21.json`.
