# Unofficial Firmware SDK (descriptive, v0.3 development)

This SDK is generated from the evidence database. It separates indexed
functions, CFG-recovered functions, semantically understood interfaces,
runtime-verified interfaces and mock-tested interfaces for firmware 3.21. It
does not provide a raw memory call wrapper or imply that an inferred function
is safe to invoke. Use `python -m fwplatform.cli sdk build` to regenerate
`sdk/sdk-index.json` after database updates. The public repository ships a
schema-only index because populated firmware databases remain private.
