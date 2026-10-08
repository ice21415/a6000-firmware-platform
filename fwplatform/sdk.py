from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import Database, utc_now


def build_sdk_index(db: Database, output: Path, firmware_version: str = "3.21") -> dict[str, Any]:
    """Emit a descriptive SDK index; it never labels an unverified function safe to call."""
    interfaces = {
        "lifecycle_callbacks": {
            "status": "VERIFIED_STATIC",
            "names": ["init", "exit", "suspend", "resume", "inactivate", "activate"],
            "calling_convention": "unknown",
            "side_effects": "module-specific; recover from evidence before invocation",
        },
        "imdb_entry": {
            "status": "VERIFIED_STATIC", "layout": "raw uint32 words",
            "known_fields": ["index", "address", "phase", "entry_type", "flags", "target_mask", "id", "kind", "library"],
            "unknown_fields": ["callback_fields semantics", "word[4..10] ABI"],
            "source": "<private-research>/boot-static-analysis/imdb-entries.json",
        },
        "model_camera_selector_dispatch": {
            "status": "VERIFIED_STATIC", "selector_namespace": "camera_selector",
            "state_machine": "ModelCamera.selector_dispatch",
            "runtime_safety": "descriptive only; no direct call wrapper",
            "source": "<private-research>/boot-static-analysis/camera-state-transitions.json",
        },
        "vtable_methods": {
            "status": "VERIFIED_STATIC", "dispatch": "candidate virtual dispatch slots",
            "runtime_safety": "descriptive only; imported slots require ABI validation",
            "source": ["view-boot-vtables.json", "model-camera-vtables.json"],
        },
    }
    data = {"format": "a6000-unofficial-descriptive-sdk", "version": "0.1.0",
            "firmware": {"model": "Sony ILCE-6000", "version": firmware_version},
            "generated_at": utc_now(), "interfaces": interfaces,
            "database_counts": {table: int(db.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                                for table in ("module", "function", "vtable", "event_id", "lifecycle_callback")},
            "rule": "Only VERIFIED_* evidence may be promoted to a callable API; all others remain descriptive or mock-only."}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data

