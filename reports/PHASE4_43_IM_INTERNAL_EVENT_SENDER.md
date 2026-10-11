# Phase 4.43 — im.elf sends stage events; boot= CLI parser controls emission

**Source:** uploaded original 23,108-byte `im-vendor-original.elf`, SHA256 `f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`. Analyzed exclusively as an ELF32 ARM executable, offline; not run on hardware. This is a correction to Phase 4.42, which had not yet identified any sender of 0x940036/037.

## Confirmed publisher in the im.elf main function

The 0x91a4 helper has four initial register arguments: **r0 queue/destination ID, r1 event word, r2 additional field, r3 additional field**. It calls the relocations-identified `osal_valloc_msg_wait` at **0x91bc** (PLT 0x8f98), populates four 32-bit message fields at **0x91d2–0x91da**, then calls **`osal_snd_msg` at 0x91dc** (PLT 0x8fc8), and frees the allocated message through `osal_free_msg` on send error at 0x91e8. The 0x91a4 helper returns a status; the seven main event-send callsites do not test the returned status.

Main uses a constant r0 **0x0094016a**, from ELF literal slot `0x9dd0`, and event IDs from literal slots **0x9e00..0x9e18**. The seven ascending literal IDs 0x00940031 to 0x00940037 are each passed to **0x91a4** under distinct flags:

| Event | Required option bit | Getter | Gate | Main send call | Constant slot |
| --- | --- | --- | --- | --- | --- |
| 0x940031 | 0x10000 | 0xab4c | 0x9cf2 | 0x9d04 | 0x9e00 |
| 0x940032 | 0x20000 | 0xab60 | 0x9d08 | 0x9d1a | 0x9e04 |
| 0x940033 | 0x40000 | 0xab74 | 0x9d1e | 0x9d30 | 0x9e08 |
| 0x940034 | 0x80000 | 0xab88 | 0x9d34 | 0x9d46 | 0x9e0c |
| 0x940035 | 0x100000 | 0xab9c | 0x9d4a | 0x9d5c | 0x9e10 |
| **0x940036** | **0x200000** | **0xabb0** | **0x9d60** | **0x9d72** | **0x9e14** |
| **0x940037** | **0x400000** | **0xabc4** | **0x9d76** | **0x9d88** | **0x9e18** |

Main also checks that one or more stage flags are present at `0x9cc2–0x9cee` and branches away if none is set. Original `.data` has configuration flags **0x00000003** at **0x153f0**, none of the seven stage bits; later parsed arguments can change the value. Static ordering of calls from the same thread is numeric ascending when multiple bits are set; this is *not an OSAL FIFO/delivery/handler execution guarantee*. There is no proof that all or any calls succeed on a real camera.

## Exact argument parsing exposes a stage-selection mechanism

At **0xa63a–0xa640**, parser `0xa628` uses `strncmp(argv, "boot=", 5)` with a pointer to `0xc2a9`. At 0xa648 it reads the next character (`argv[5]`), case-insensitively maps s,u,l,i,a etc. to stage bits. Code witnesses:

| Argument form / property | OR bit at instruction |
| --- | --- |
| `boot=s` / uppercase S | `0xa6b2: 0x10000` |
| `boot=u` / uppercase U | `0xa724: 0x80000` |
| `boot=l` / uppercase L | `0xa742: 0x100000` |
| **`boot=i` / uppercase I** | **`0xa760: 0x200000`** |
| **`boot=a` / uppercase A** | **`0xa77e: 0x400000`** |
| `bootall` (compared `strncmp(...,7)`) | `0xa794: 0x7f0000` |

The exact char values `g,d,r` (and uppercase forms) in this parser currently branch without setting a new bit at `0xa652..0xa674`; **do not invent an option assignment** for the separate 0x20000 or 0x40000 stage flags. Do not equate a particular command-line option to actual device startup until original launch configuration is found.

## Same ELF also includes a stage handler, but its bridge needs proof

The separately identified event handler at **0xa06c** checks the *same* event words via constants at `0xa308..0xa320`. Upon 0x940036 it conditionally processes IMDB marker **5→7** (30 candidate earlier libObj loads); upon 0x940037 it conditionally processes marker **7→8** (row99 appFw initializer metadata).

The `im.elf` main at **0x9ae2** does save a pointer to `0xa06d` as a callback using internal setter `0xac08`. Separately, its call to **`osal_reg_sync_msg_queue_cb`** at **0x9ba2** registers queue ID 0x94016a with Thumb function pointer **0x95b1** (not 0xa06d). These are distinct callback contexts! Consequently **sending event words to 0x94016a does not alone prove that handler 0xa06c is their eventual receiver**. Runtime OSAL routing, internal state callback dispatch and actual message delivery need more proof.

## Effect on prior startup conclusions

The previous statement "source of the 0x940036/037 messages is unknown" is now *partially resolved*: an exact **internal event emission path exists** in im.elf main, backed by PLT calls and original literal bytes. It is **not demonstrated to be the only source** of such messages, nor that those messages are delivered to the matching stage handler. Programmatic send order cannot be equated with successful prior `dlopen("/usr/lib/libObj.so",0x101)`, nor guaranteed `dlsym(Application_System_Init)` after appFw.

Original Core SDK edge tracker remains **74 direct / 5 inferred / 5 unresolved = 84**, zero runtime-verified and zero safe-to-invoke APIs. This cross-ELF discovery is stored separately as `sdk/im_event_sender_3_21.json`. No firmware patching, camera execution or device communication was performed.
