# Phase 4.47 — Fixed UIPC sync callback is not a direct 0x940036/037-to-dynamic-ID forwarder

**Sony A6000 Firmware 3.21.** All primary evidence from the user-uploaded original ELF files, inspected read-only:

- `im-vendor-original.elf` SHA256 `f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`
- `osal_uipc_fw321.ko` SHA256 `82a92bd4bd00d7e28237b647c93278f57d53dee241f96075798fad8a87926ab1`
- `libosal_uipc_fw321.so` SHA256 `0c6b87a012eb757dbe0a5b9b7b19fb91fc27c1dafc0e78facb126114416cf1ef`

Phase 4.46 directly proved that `osal_dynamic_id(0x2a,0x94,...)` allocates the main im.elf receiver in **0x946000..0x946fff** on success, distinct from the producer's static destination **0x94016a**. This phase tests the natural intervening hypothesis: *does the registered synchronous callback at 0x95b0 forward stage messages into the dynamically allocated receiver?*

## 1. Exhaustive direct message equality cases inside im.elf callback 0x95b0

The synchronous queue callback used in `osal_reg_sync_msg_queue_cb(0x94016a,...,0x95b1,...)` is the Thumb routine **0x95b0**. At **0x95ba** it loads `r1=[r0]` (message ID), then:

| Direct ID | Comparison | Local action |
|---|---|---|
| `0x9400e1` | `0x95bc` | `0xabf8` |
| `0x940021` | `0x95ce` | `0xb530` |
| `0x940022` | `0x95e0` | `0xb740` |

A subsequent chain begins with literal `0x00920143` at **0x9658**, and compares the IDs **`0x920143`**, **`0x92015a`**, **`0x92014b`**, **`0x92014d`**, **`0x92014f`**, **`0x920152`**, **`0x92015c`** (exact successive add/sub operations at `0x95f2..0x961a`). Only this family reaches **0x9628**, a call to the generic send wrapper 0x91a4; the wrapper's **r0** is the fixed destination literal at **0x965c**, **`0x0094016a`** — **NOT** a computed dynamic ID `0x946xxx`.

All other IDs (including **`0x940036`** and **`0x940037`**) fall into the default branch **`0x962e..0x963a`**, which calls `printf` (PLT resolved as `0x8fe4`). The format string at **`0xc009`** is:

```text
imelf_sync_api_cb: err: cmd:0x%x
```

This is an **instruction-bounded negative result**: *if the registered sync callback 0x95b0 directly receives message IDs 0x940036/037, they do not take any of its named stage-processing or forwarding branches.* It does **not** prove these messages were sent or received at all, nor that no other producer or intermediary can deliver stage events to the main loop.

## 2. Kernel sender looks up the original low-16 ID; there is no general implicit ID remapping at this point

Within the unstripped original kernel module, `osal_snd_msg` begins at **.text+0x3bd4**, extracts **`uxth r8,r0` at +0x3bf4**, and does queue lookup at **+0x3c08 / +0x3c18**. Successful paths enqueue or dispatch under the found queue's rules at **+0x3cb0..+0x3d50**; there is no direct re-expression of input low-16 ID **0x016a** as allocated low-16 IDs **0x6000..0x6fff** in this routine.

The kernel *may* invoke registered callbacks for the fixed queue, but this does not confer an automatic translation from that callback to the application's other, separately allocated receive ID. The additional no-forwarding observation in section 1 is why the direct callback hypothesis is now unsupported by the uploaded code.

## 3. What is now known and unknown about the lifecycle

**Proven, conditional executable code:** `im.elf` main posts 0x940036/037 to fixed queue 0x94016a under boot flags, and it separately receives messages on a dynamic 0x946xxx queue, choosing stage handler 0xa06c only when callback state is 3 and the receive succeeds. The fixed queue's registered user callback 0x95b0 does not directly bridge those message IDs to that dynamic queue. A failure to find the bridge means **do not claim any end-to-end stage delivery**.

The remaining investigative target must change from re-reading UIPC allocation arithmetic to identifying the **independent producer or forwarding subsystem**, if present, that sends stage event IDs to the dynamic queue. Candidate avenues are the full offline firmware's other ELFs that import `osal_snd_msg` and contain stage event message literals, or relevant boot-launch setup. Mere raw occurrence of 0x940036 is a **candidate only** (Phase 4.42 found an unrelated log-literal collision in `libmpr.so`).

**No runtime verified APIs; five unresolved end-to-end blockers.** Original Camera Core count remains **74 primary static + 5 inferred + 5 unknown = 84**. Stage delivery and libObj load/dlsym binding remain unproven. Original ELF data are not committed; evidence metadata lives in `sdk/im_ipc_forwarder_boundary_3_21.json`.
