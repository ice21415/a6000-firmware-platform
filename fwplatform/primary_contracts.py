"""Validate descriptive helper specifications without granting call authority."""
from __future__ import annotations

from typing import Any

from .private_thumb_research import EXPECTED_LIBOBJ_SHA


def validate_primary_contracts(contract: dict[str, Any]) -> dict[str, int | bool]:
    """Reject mismatched identity, mixed addresses and unsupported safety claims."""
    if contract.get("binary_sha256") != EXPECTED_LIBOBJ_SHA:
        raise ValueError("Pinned ELF identity mismatch")
    if contract.get("address_space") != "ELF_VMA":
        raise ValueError("Contract addresses must remain ELF VMAs")
    if contract.get("runtime_verified") is not False or contract.get("callable") is not False:
        raise ValueError("Offline helper contracts cannot grant runtime authority")
    interfaces = contract.get("interfaces", [])
    if not interfaces:
        raise ValueError("Missing interfaces")
    seen: set[int] = set()
    for api in interfaces:
        entry = int(api["entry"], 16)
        if entry & 1 or entry in seen:
            raise ValueError("Duplicate entry or Thumb tag mixed with VMA")
        seen.add(entry)
        if api.get("safe_to_call") is not False or not api.get("evidence_locators"):
            raise ValueError("Missing evidence or unsupported safety claim")
        if api.get("declared_return_type", "UNKNOWN").startswith("UNKNOWN") is False:
            raise ValueError("Declared C++ return type is not recovered")
    return {"descriptive_interfaces": len(interfaces), "callable_interfaces": 0,
            "runtime_verified": False}
