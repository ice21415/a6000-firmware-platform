"""Bounded loader/alias evidence for the private Camera Core ELF.

The analyzer reports co-located strings/symbols and filesystem candidates. It
does not claim that a dlopen/dlsym target was selected at runtime.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

EXPECTED_FACTORY = "ModelCameraToInstance"
EXPECTED_LIBRARY = "modelCamera.so"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_loader_alias(elf_path: Path, *, expected_sha256: str,
                         search_root: Path | None = None) -> dict[str, Any]:
    actual = _sha256(elf_path)
    if actual != expected_sha256:
        raise ValueError("ELF SHA-256 does not match the pinned input")
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        dyn_symbols = {symbol.name for section in elf.iter_sections()
                       if section.name in {".dynsym", ".symtab"}
                       for symbol in section.iter_symbols()}
        strings = set()
        for section in elf.iter_sections():
            if section.name.startswith(".rodata") or section.name == ".dynstr":
                data = section.data()
                for token in (EXPECTED_LIBRARY.encode(), EXPECTED_FACTORY.encode()):
                    if token in data:
                        strings.add(token.decode())
    filesystem_candidates: list[dict[str, Any]] = []
    if search_root and search_root.exists():
        for path in search_root.rglob("*"):
            if path.is_file() and path.name.lower() in {EXPECTED_LIBRARY.lower(), "modelcameratoinstance.so"}:
                filesystem_candidates.append({"name": path.name, "size": path.stat().st_size,
                                              "sha256": _sha256(path)})
    return {"status": "PRIMARY_ELF_EVIDENCE_ONLY", "elf_sha256": actual,
            "configured_library": EXPECTED_LIBRARY if EXPECTED_LIBRARY in strings else "UNKNOWN",
            "factory_symbol_string": EXPECTED_FACTORY if EXPECTED_FACTORY in strings else "UNKNOWN",
            "exported_factory_symbol": EXPECTED_FACTORY in dyn_symbols,
            "filesystem_candidates": filesystem_candidates,
            "resolved_binary_identity": "UNKNOWN",
            "alias_proven": False,
            "evidence_level": "PRIMARY_ELF_VERIFIED_FOR_STRINGS_ONLY",
            "unresolved_conditions": ["dlopen search path and runtime loader selection",
                                       "dlsym result and relocation binding",
                                       "registry population and instance success"]}


__all__ = ["analyze_loader_alias"]
