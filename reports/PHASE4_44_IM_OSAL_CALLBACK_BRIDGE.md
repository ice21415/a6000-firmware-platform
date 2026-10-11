# Phase 4.44 — Runtime-dispatch *code* bridge: current handler pointer → OSAL receive loop → indirect BLX

**Source:** user-uploaded `im-vendor-original.elf` (Sony A6000 firmware 3.21), ELF32 ARM, SHA-256 **`f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`**, 23,108 bytes. This report concerns **static executable instructions only**; real device delivery is not observed. No device commands or firmware modification.

## 1. Handler registration actually connects to executable indirect dispatch

Disassembly of the original executable provides both ends of the callback field:

- At **0x9ade** main loads the literal 32-bit Thumb pointer **0xA06D** from 0x9B2C; at **0x9ae0** it sets **r0=3**; at **0x9ae2** it invokes local helper **0xAC08** with r1=0xA06D.
- Helper **0xAC08** stores **r1 at global[0x153E4+0x08]** via **0xAC0E**, and r0 at the global base via **0xAC10**.
- Helper **0xAC18** loads the callback from the **same global+0x08** at **0xAC1E** and returns it in r0.
- At **0x9e9a**, main invokes `0xAC18`; at **0x9ea6** it saves the returned callback pointer in **r5**.
- At **0x9eaa**, main invokes the relocations-resolved OSAL API **`osal_rcv_msg_tmo`**, passing a handle from `0xA580`, an output message pointer slot at stack+0x24, and **r2=0xFFFFFFFF** as timeout.
- At **0x9eae**, nonzero receive status jumps past the callback. Otherwise **0x9eb0** loads the received message pointer into r0 and **0x9eb2 executes `BLX r5`**; **0x9eba** frees the message via `osal_free_msg`.

**Proven static implication:** IF the callback slot still contains 0xA06D when the receive loop reads it, and IF `osal_rcv_msg_tmo` successfully returns a message, the program passes that message pointer to **0xA06C**, the concrete handler previously shown to compare stage event IDs 0x940031..0x940037. This moves the previous handler/receive-loop connection from hypothesis to **primary instruction evidence**.

It is not proof of **which** message arrives, whether it arrives at all, or what callback value the process actually uses on camera.

## 2. Callback is mutable: several distinct states exist

The static code contains other writes through **0xAC08**:

| Callsite | State r0 | Handler pointer | Origin |
|---|---:|---|---|
| 0x9AE2 | 3 | **0xA06D** | literal 0x9B2C |
| 0x9E4E | 5 | **0x9339** | literal 0x9F10 |
| 0x9EF2 | 3 | **0xA06D** | literal 0x9F30 |
| 0x9382 | 1 | **0x9265** | literal 0x93A8 |

Therefore 0x9EB2 is **not** an unconditional call to 0xA06C. The callback actually called is the value captured at 0x9E9A, potentially updated in other states. A direct function-pointer-flow proof is stronger than merely showing the literal 0xA06D, but it does **not** establish runtime state.

## 3. Two OSAL queue-handle storage paths — avoid false equivalence

There are separate file-proven handle fields under global base 0x153E4:

- **Registered synchronous queue callback:** at **0x9BA2** main calls `osal_reg_sync_msg_queue_cb` for **ID 0x94016A** (literal 0x9DD0), callback **Thumb 0x95B1** (literal 0x9DCC). The returned handle placed in a stack slot is saved via **0x9BBC → 0xA590 → global+0x28**, address **0x1540C**.
- **Main receive loop:** `0x9E34 → 0x92BC` obtains a dynamic OSAL ID; the output is saved via **0x9E3A → 0xA570 → global+0x2C**, address **0x15410**. Getter **0xA580** reads this **+0x2C** field and passes it to `osal_rcv_msg_tmo` at 0x9EAA.

The separately registered sync callback **0x95B0** is NOT the IMDB stage callback **0xA06C**. The former reads incoming message code at **0x95BA**, has direct branches for 0x940021 and 0x940022 and a special event family based on **0x920143**, while the latter compares 0x940031..0x940037. At **0x9628**, the sync callback may forward certain events through the wrapper `0x91A4` to destination **0x94016A**, but this does **not** prove that emitted 0x940036/37 messages reach the main receiver.

**Interpretation limit:** the +0x28 and +0x2C handles are separate fields and originate from different OSAL code paths. This by itself does not prove they represent different final queues in the OSAL implementation. Because OSAL routing code is not in the uploaded im.elf, do not claim guaranteed FIFO stage order or actual delivery.

## 4. Next direct evidence target

The highest-value next input is a **read-only copy** of the original, same-firmware-version `libosal_uipc.so` (its name appears in the im.elf DT_NEEDED list). Disassemble `osal_snd_msg`, `osal_reg_sync_msg_queue_cb` and `osal_rcv_msg_tmo` against the two distinct handle paths to prove or reject event routing; if functions delegate into another module, follow their dynamic dependencies. A whole-firmware offline launch configuration/argv source is a separate target.

The cross-ELF startup hypothesis is increasingly grounded, but there is **no observed runtime evidence** for event arrival, successful libObj global dlopen/dlsym or ModelCamera ID 11 registration.

## Accounting

Original Camera Core: **74 primary static + 5 inferred + 5 unresolved = 84 tracked**, unchanged. All five end-to-end blockers open, zero runtime-verified and zero safe-to-invoke SDK APIs.

Machine-code and field witnesses are pinned separately in `sdk/im_callback_bridge_3_21.json`. This new evidence is intentionally not mislabeled as a proof of a camera-runtime call.
