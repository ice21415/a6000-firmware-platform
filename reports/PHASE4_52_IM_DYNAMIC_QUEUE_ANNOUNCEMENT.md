# Phase 4.52 — `im.elf` publishes its dynamically allocated receiver ID in UIPC control message 0x94001a

## Provenance and scope

Sony A6000 Firmware 3.21. Direct **read-only** Thumb machine-code review and PC-relative literal checks against user-provided original `im-vendor-original.elf` (**23,108 bytes**, SHA256 **`f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`**). `libosal_uipc_fw321.so` SHA `0c6b87a012eb757dbe0a5b9b7b19fb91fc27c1dafc0e78facb126114416cf1ef` and `osal_uipc_fw321.ko` SHA `82a92bd4bd00d7e28237b647c93278f57d53dee241f96075798fad8a87926ab1` support the OSAL ABI and successfully allocated ID pool already described in Phases 4.45/4.46.

These are conditional **original ELF VMAs**, not runtime instruction traces. Vendor binaries/disassembly are not committed.

## 1. Decisive new dataflow: im announces its actual queue ID

Prior Phase 4.46 proved original `osal_dynamic_id(0x2a,0x94,...)` can allocate the im main receiver in `0x946000..0x946fff` on success; the `im.elf` stage sender uses fixed `0x94016a`, which is numerically distinct. This phase proves these are **not entirely independent uncommunicated addresses**: im itself **publishes the newly allocated receiver ID inside a control message sent to the fixed 0x94016a destination**.

In im main:

1. **0x9e30** computes output pointer, **0x9e34** calls wrapper **0x92bc**, which passes `r0=0x2a`, `r1=0x94`, `r2=output_ptr` to `osal_dynamic_id` PLT **0x9074** at **0x92c6**. On return **0x9e38** reads the allocated ID, **0x9e3a** stores it through setter `0xa570` into global `0x153e4+0x2c`.
2. **0x9e4e** sets callback state **5**, callback Thumb pointer **0x9339**, through helper `0xac08`.
3. **0x9e5a** obtains a global parameter via `a600`; **0x9e60** loads PC-relative literal **0x9f14 = 0x0094001a** into **r1**; **0x9e64** loads the **just allocated ID** from `[r7,#0x28]` into **r3**; **0x9e68** loads fixed destination literal **0x9f18 = 0x0094016a** into **r0**; **0x9e62** places numeric **3** in the first caller stack argument. **0x9e6c** calls sender wrapper **0x91a4**.
4. `0x91a4` allocates a **16-byte** OSAL message via `osal_valloc_msg_wait` at **0x91bc**, then writes exactly **four** little-endian message words:
   - **+0x00**: `0x0094001a` at **0x91d2**;
   - **+0x04**: value from global+0x24 / `a600()` at **0x91d4**;
   - **+0x08**: freshly allocated dynamic receiver ID at **0x91d6**;
   - **+0x0c**: numeric **3** at **0x91da**.
   It invokes **`osal_snd_msg`** PLT **0x8fc8** at **0x91dc**, with `r0=0x94016a`, then frees the allocated buffer if sending returns an error.

**The queue ID relationship is therefore richer than the previously ruled-out numerical equality**: `0x94016a != 0x946xxx`, but the sender can **convey the 0x946xxx value in a message** so that some other program could learn where to send replies/events. A **recipient that actually interprets this message has not yet been identified**. In particular, the registered `im.elf` sync callback at `0x95b0` does not have an explicit handler for `0x94001a` in its direct switch; it must not be silently designated as the consumer.

## 2. Second constructor emits the same control message with a different tag

The independent Thumb routine `0x9698` has an environment/argument-gated path:

- **0x96cc–0x96d4** again invokes `0x92bc osal_dynamic_id` and stores the resulting ID via `a570`.
- **0x96de–0x96e2** selects callback state **5** and Thumb function **0x9339**.
- At **0x96ea**, the first extra argument is **2**; **0x96ec** loads literal **0x9728 = 0x0094001a**, **0x96f0** obtains the allocated ID as **r3**, **0x96f4** loads destination literal **0x972c = 0x0094016a**, and **0x96f8** invokes the exact same `0x91a4` send wrapper.

The two statically proven formats are:

| Origin | Destination | Message word 0 | Word 1 | Word 2 | Word 3 |
|---|---|---|---|---|---|
| main **0x9e6c** | `0x94016a` | **`0x94001a`** | `a600()` value | dynamic receiver ID | **3** |
| helper **0x96f8** | `0x94016a` | **`0x94001a`** | value from helper's preceding call | dynamic receiver ID | **2** |

We call this a **registration-like queue-ID advertisement**, not an established protocol name or a proven registration success. The two tags **2** and **3** are direct written values; their broader semantics remain UNKNOWN.

Note a third literal `0x94001a` at `im.elf 0xa494` also occurs in a separate send path; it does not itself prove an additional dynamic-ID announcement and is **not** counted as such.

## 3. Callback state machine explains another delivery gate

The sender-side existence does not remove the receiver callback gate. Original `im.elf` has mutable callback pointer storage:

- **0xac08** writes caller-provided **callback Thumb pointer** to global `0x153e4+0x08` and state value to `global+0`.
- **0xac18** loads the callback pointer.
- Initial main path **0x9ade..0x9ae2** installs **state 3 / callback 0xa06d**.
- Main **0x9e4a..0x9e4e** installs **state 5 / callback 0x9339**, before the main announcement.
- Main's actual receive loop (**0x9e94 → 0xa580` dynamic receiver handle, `0x9e9a→ac18` handler, `0x9eaa` `osal_rcv_msg_tmo`**, then on zero status **`0x9eb2 BLX r5`**) uses the **current pointer**, not an immutable hard-coded 0xa06d.
- State-5 handler `0x9338` explicitly compares the message word with **`0x940007`** at **0x933e** and **`0x940001`** at **0x9362**. Its `0x940001` branch **0x937e..0x9382** changes to **state 1 / callback 0x9265**. Neither is direct stage `0x940036/037` handling.
- Separately, main code **0x9edc..0x9ef2** can re-install **state 3 / callback 0xa06d**, under control flow reached from **0x9cb6** after an earlier OSAL message send success. It then re-enters the looping path.

Hence it is incorrect to assume that simply setting CLI `i` and `a` flags, allocating a queue, or publishing that ID guarantees immediate processing by stage callback 0xa06c. **One also needs event delivery at a time when callback pointer 0xa06d is active, or other proven equivalent handler logic.**

## 4. Current precise blocker and next offline search

The missing piece is now **identify who consumes `0x94001a` at fixed port `0x94016a` and uses its word+8 (dynamic ID)**. That consumer could explain how other producers learn the dynamically allocated receiver address and route control events. The current original `im.elf` callback `0x95b0` does not explicitly handle `0x94001a`; a handler or mediator in other ELF modules remains possible. The original kernel `osal_snd_msg` low16 queue lookup does not intrinsically perform such a remap.

A read-only scan over **all 649** unpacked firmware ELFs for the literal `0x94001a`, the fixed destination `0x94016a`, and OSAL send/receive APIs, followed by real Thumb/relocation cross-reference verification, is the most efficient next candidate discovery. If no raw literal is found elsewhere, dynamic/computed message comparisons still remain possible.

Unproven: actual camera launch mode and argv, OSAL call success/delivery, consumer recognition of word+8, callback active state during the actual stage messages, `libObj.so` successfully loaded in the same process before `dlsym("Application_System_Init")`, or ModelCamera/Model ID11 mapping.

**Core static graph remains 74 primary / 5 inferred / 5 unresolved = 84 tracked; zero runtime-verified or safe-to-invoke APIs.** Evidence: `sdk/im_dynamic_queue_announcement_3_21.json`.
