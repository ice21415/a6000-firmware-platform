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
