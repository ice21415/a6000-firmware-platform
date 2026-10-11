# Phase 4.46 — UIPC kernel module establishes ioctl dispatch and disproves direct sender/receiver queue-ID equality

**Firmware:** Sony A6000 3.21. **Original kernel module:** `osal_uipc_fw321.ko`, SHA-256 `82a92bd4bd00d7e28237b647c93278f57d53dee241f96075798fad8a87926ab1`, 37,264 bytes, unstripped ELF32 little-endian ARM EABI5 **ET_REL** (Build ID `572a8cb878ae35897b51056397bd98caa67e5435`). All addresses below are **section-relative original ELF offsets**, not live kernel virtual addresses. Examined offline via `readelf`, ARM-mode `llvm-objdump -d -r`, literal verification. No code execution or device interaction.

Related ELF sources independently pinned: `libosal_uipc_fw321.so` SHA-256 `0c6b87a012eb757dbe0a5b9b7b19fb91fc27c1dafc0e78facb126114416cf1ef`; `im-vendor-original.elf` SHA-256 `f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`.

## 1. Exact ioctl dispatcher and executable handlers

The kernel module itself contains all functions:

- `__k_uipc_cdev_ioctl` at **.text+0x05a0**, which strips request bit 31 at **0x060c** (`bic r6,r6,#0x80000000`), checks command index against 16, loads a relocation-backed function pointer from the `.rodata` table based at **+0x28**, and invokes it at **0x067c `blx r3`**.
- Four precise `.rel.rodata` **`R_ARM_ABS32`** entries specify:

| User-space ioctl | Decoded index | Table offset | Kernel target | Target .text offset |
| --- | ---: | --- | --- | --- |
| `0x80000004` send | 4 | `.rodata+0x38` | `__k_4u_snd_msg` | **0x1b58** |
| `0x80000007` receive | 7 | `.rodata+0x44` | `__k_4u_rcv_msg_tmo` | **0x19fc** |
| `0x80000008` callback registration | 8 | `.rodata+0x48` | `__k_4u_reg_msg_queue_cb` | **0x077c** |
| `0x8000000c` dynamic-ID request | 12 | `.rodata+0x58` | `__k_4u_dynamic_id` | **0x069c** |

Further the kernel handlers link by direct `R_ARM_CALL`: `__k_4u_snd_msg` calls kernel-exported `osal_snd_msg` at **0x1b90**; `__k_4u_rcv_msg_tmo` calls kernel `osal_rcv_msg_tmo` at **0x1a6c**; `__k_4u_dynamic_id` calls kernel `osal_dynamic_id` at **0x0710/0x0724**. Callback registration prepares a kernel callback object, then calls either `reg_sync_msg_queue_cb` at **0x0874** or `reg_msg_queue_cb` at **0x0880**, depending on the supplied registration field.

This concretely closes the old *unknown ioctl target* branch from Phase 4.45: userspace `libosal_uipc.so` delegates into these independently verified kernel entry points.

## 2. Kernel sender looks up the low 16 bits of a queue ID

At `.text+0x3bd4`, kernel `osal_snd_msg` tests the `0x8000` bit and, for the UIPC-eligible branch, uses **`uxth r8,r0` at 0x3bf4** before calls to its queue-lookup helpers at **0x3c08/0x3c18**. The code checks queue properties and has a linked-message enqueue path at **0x3cb0..0x3d38** followed by notification. These are *conditional* operations contingent on finding an appropriate queue and OSAL state; they do not demonstrate a send actually succeeded.

The im.elf producer sends event IDs `0x940036` and `0x940037` to a fixed destination **`0x0094016a`**, whose low 16 bits are **`0x016a`**.

## 3. **New decisive negative proof:** the main receive queue is not ID 0x94016a

Independent `im.elf` Thumb at **0x92bc..0x92c6** invokes `osal_dynamic_id(r0=0x2a,r1=0x94,r2=output)`, and main at **0x9e34** calls that helper to populate its dynamic receive ID.

The kernel's **unstripped** `osal_dynamic_id` (function **.text+0x4454**) reveals exactly how this option selects a pool:

- At **0x4464**, `r0&0x2` nonzero means no extra `0x8000` ID bit.
- At **0x4490**, `r0&0x10=0`, selecting the descriptor loaded from `.data+0x17c`; at **0x449c..0x44a8** `r0&0x4=0`, selecting that descriptor's **+0x10** subpool, i.e., **`.data+0x18c`**.
- Verified little-endian source data: **`.data+0x190 = 0x6000`** (pool base), **`.data+0x194 = 0x1000`** (pool size). The branch at **0x44b4** finds a free bitmap bit, and at **0x4584..0x45a8** combines `(r1<<16)`, the chosen pool base and bitmap index into the output ID. `r1` was `0x94` from the im.elf callsite.
- **On a successful call with the observed arguments**, the resulting main receiver queue ID must be in the range **`0x00946000..0x00946FFF`** (low 16 bits `0x6000..0x6fff`), not **`0x0094016A`**.

This is a *direct static **non-equality proof*** for the two IDs; it does not require seeing an actual allocated index. **The receiver ID is not simply the fixed sender destination.** The only remaining way for those exact stage events to reach that receiver is a **separate forwarding or callback route, or a different message producer that addresses its dynamic ID**. Such a route has **not yet been proven**.

Important: The kernel UIPC layer is shared but sharing the driver or the high-word namespace `0x94` is insufficient to equate queues. If dynamic allocation fails, the receive queue may not exist at all; the range claim is explicitly conditioned on successful dynamic allocation.

## 4. Callback nuance

Kernel `__k_4u_reg_msg_queue_cb` at 0x077c allocates a callback object (`alloc_cb` at **0x07ec**), stores a pointer to kernel **`__k_user_msg_cb`** at **0x080c**, and forwards registration to kernel `reg_sync_msg_queue_cb` or `reg_msg_queue_cb`. Independently, original im.elf stores **0x95b1** as its registered synchronous callback at destination **0x94016a**, but the main loop stores **0xa06d** as its *stage* handler and invokes it only on a successful receive from the dynamically allocated queue.

No original code in the current evidence establishes that `0x95b0` forwards stage event values `0x940036/037` to the queue `0x946000..0x946fff`. This is now the specific missing static routing link, rather than an undifferentiated generic UIPC uncertainty.

## 5. Consequences and accounting

**Proven:** OSAL user/kernel ioctl ABI, actual kernel implementations for four requests, kernel queue-lookup key, and **non-equality of fixed send ID and dynamic receiver ID**. **Unproven:** runtime sender flags, successful kernel queue registration/delivery, callback forwarding between IDs, the actual current callback, prior `libObj.so` success and `dlsym(Application_System_Init)`, and Model ID 11 → ModelCamera DSO identity. No firmware or kernel module was executed or modified.

JSON with separate section offsets and instruction/relocation witnesses: `sdk/uipc_kernel_dispatch_3_21.json`.

Camera Core tracking **unchanged**: 74 primary static / 5 inferred / 5 unresolved = 84 tracked; runtime-verified and safe-to-invoke API counts both zero. This phase adds new cross-module proof but **does not** promote runtime API claims.

### Reproduce offline

```bash
sha256sum osal_uipc_fw321.ko
readelf -hSW -sW -rW osal_uipc_fw321.ko
llvm-objdump -d -r --triple=armv7-none-eabi osal_uipc_fw321.ko
```
