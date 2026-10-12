# Phase 4.53 — IM synchronous callback excludes the announcement code

## Source and method

Sony ILCE-6000 firmware 3.21, original `bin/im.elf` pinned to SHA-256
`f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`.
Offline Thumb disassembly, VMA literal extraction and `printf` symbol lookup.
No device I/O, execution of vendor firmware or runtime trace is claimed.

## Evidence

- The synchronous queue registered at `0x94016a` uses callback Thumb pointer `0x95b1`, corresponding to entry `0x95b0`.
- At `0x95ba`, the callback reads the message ID from `[r0]`.
- Direct comparisons: `0x9400e1`, `0x940021`, `0x940022`.
- The arithmetic comparison family beginning at `0x920143` yields `0x920143`, `0x92015a`, `0x92014b`, `0x92014d`, `0x92014f`, `0x920152`, `0x92015c`.
- Message ID `0x94001a` matches none of these values. Its local control flow reaches `0x962e` and the `0x963a` tail branch to the `printf` PLT at `0x8fe0`.
- The literal at `0x9660` points to VMA `0xc009`, whose NUL-terminated string is `imelf_sync_api_cb: err: cmd:0x%x\n`.
- The conditional forwarding call at `0x9628` is **not** reached by message ID `0x94001a` along this tested dispatch path.

## Limits

This proves a **negative local-dispatch fact only**. It does not establish
actual delivery of `0x94001a`, other subscribers, queue kernel behavior,
or the existence/absence of computed handlers in other modules. The announcement
format and its dynamic ID at word `+0x08` remain as described in Phase 4.52.
Do not promote any Camera Core API to runtime verified or safe-to-call.

## Reproduce

`python tools/verify_im_sync_callback.py --elf <authorized-original-im.elf>`

`python -m unittest discover -s tests -p "test_*.py" -q`

The executable verifier fails closed on a hash, literal, instruction, format
string or symbol discrepancy and does not export Sony firmware bytes.

## Next independent question

Trace consumers of `0x94001a` or the word `+0x08` dynamic queue address
through OSAL and any additional full, provenance-matched firmware partitions.
Aligned literal hits alone do not prove message handling.
