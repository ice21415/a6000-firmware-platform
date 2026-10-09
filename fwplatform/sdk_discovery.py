"""Read-only enumeration of *possible* firmware APIs from static ELF evidence.

This is an SDK review queue, not a generator of callable wrappers or a claim
that symbol names or automatically inferred Ghidra prototypes have known ABI.
"""
from __future__ import annotations

import re
from typing import Any

from .db import Database
from .sdk_contracts import DOMAINS, _proves_function_location, _address_value, _function_index


# These are strictly search hints; they do not assign a semantic SDK domain.
TOKENS: dict[str, tuple[str, ...]] = {
    "Camera": ("camera", "capture", "shoot", "shutter", "exposure"),
    "Lens": ("lens", "focus", "iris", "aperture", "zoom"),
    "Sensor": ("sensor", "imager", "bayer", "adc"),
    "Media": ("media", "image", "jpeg", "movie", "record", "playback", "codec"),
    "UI": ("ui_", "display", "lcd", "viewfinder", "touch", "menu"),
    "OSAL": ("osal", "queue", "semaphore", "mutex", "message"),
    "Android": ("android", "jni", "java", "dalvik"),
    "Networking": ("network", "wifi", "wlan", "socket", "http", "dlna"),
}
MAX_RESULTS = 1000


def _domain_hints(name: str) -> list[str]:
    lower = name.lower()
    return [domain for domain, words in TOKENS.items() if any(word in lower for word in words)]


def discover_sdk_candidates(
    db: Database, *, name: str = "", binary_sha256: str = "",
    domain: str = "", include_internal: bool = False,
    include_generated: bool = False, limit: int = 100,
) -> dict[str, Any]:
    """Select symbol-backed candidates with clear provenance and unverified ABI.

    The default search is restricted to ELF exports; internal functions are
    opt-in. Domain matches are lexical hints, never static semantic proofs.
    No sdk_interface or evidence row is created or promoted.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_RESULTS:
        raise ValueError(f"SDK discovery limit must be between 1 and {MAX_RESULTS}")
    if domain and domain not in DOMAINS:
        raise ValueError(f"SDK discovery domain must be one of: {', '.join(DOMAINS)}")
    binary_sha256 = binary_sha256.strip().lower()
    if binary_sha256 and not re.fullmatch(r"[0-9a-f]{64}", binary_sha256):
        raise ValueError("SDK discovery binary_sha256 must be a 64-character hex digest")

    filters = ["f.name IS NOT NULL", "f.name <> ''", "f.address IS NOT NULL",
               "b.sha256 IS NOT NULL", "length(b.sha256)=64"]
    args: list[Any] = []
    if not include_generated:
        filters.append("COALESCE(f.generated_name,0)=0")
        filters.append("f.name NOT GLOB 'FUN_*'")
    if not include_internal:
        filters.append("""EXISTS (SELECT 1 FROM import_export ie
            WHERE ie.binary_id=f.binary_id AND ie.name=f.name AND ie.direction='export')""")
    if name:
        # Escape LIKE metacharacters so filter remains an exact substring.
        escaped = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        filters.append("LOWER(f.name) LIKE ? ESCAPE '\\'")
        args.append(f"%{escaped.lower()}%")
    if binary_sha256:
        filters.append("lower(b.sha256)=?")
        args.append(binary_sha256)
    # Lexical-domain and export-address filters are applied after SQL.
    # Bound scanning but do not stop at limit+1 wrong-address names.
    scan_limit = MAX_RESULTS * 10
    sql = f"""SELECT f.id AS function_id,f.binary_id,f.module_id,f.name,f.address,f.prototype,
            f.status AS function_status,f.source_evidence_id,f.generated_name,
            b.sha256 AS binary_sha256,b.path AS binary_path,m.name AS module_name,
            e.status AS evidence_status,e.kind AS evidence_kind,e.excerpt AS evidence_excerpt,
            e.source_sha256 AS evidence_sha256,e.metadata_json AS evidence_metadata_json
        FROM function f JOIN binary b ON b.id=f.binary_id
        LEFT JOIN module m ON m.id=f.module_id
        LEFT JOIN evidence e ON e.id=f.source_evidence_id
        WHERE {" AND ".join(filters)}
        ORDER BY lower(b.sha256),lower(f.name),f.address,f.id LIMIT ?"""
    candidates: list[dict[str, Any]] = []
    export_cache: dict[tuple[int, str], set[int]] = {}
    function_cache: dict[int, dict[int, list[Any]]] = {}
    examined = 0
    saturated = False
    for row in db.query(sql, [*args, scan_limit]):
        examined += 1
        # An export with the same *name* but a different ELF VMA is not
        # evidence that this function entry is exported.
        if not include_internal:
            export_key = (int(row["binary_id"]), str(row["name"]))
            if export_key not in export_cache:
                export_cache[export_key] = {
                    parsed for record in db.query(
                        "SELECT address FROM import_export WHERE binary_id=? AND name=? AND direction='export'",
                        export_key,
                    )
                    if (parsed := _address_value(record["address"])) is not None
                }
            if _address_value(row["address"]) not in export_cache[export_key]:
                continue
        hints = _domain_hints(str(row["name"]))
        if domain and domain != "Other" and domain not in hints:
            continue
        if domain == "Other" and hints:
            continue
        evidence = {
            "status": row["evidence_status"], "kind": row["evidence_kind"],
            "excerpt": row["evidence_excerpt"], "source_sha256": row["evidence_sha256"],
            "metadata_json": row["evidence_metadata_json"],
        }
        numeric_address = _address_value(row["address"])
        unique_function_entry = (numeric_address is not None and len(
            _function_index(db, int(row["binary_id"]), function_cache).get(numeric_address, [])
        ) == 1)
        location_bound = (unique_function_entry and row["evidence_status"] == "VERIFIED_STATIC"
                          and _proves_function_location(
                              evidence, str(row["binary_sha256"]), str(row["address"])))
        hints_value = hints or ["Other"]
        candidates.append({
            "function_id": int(row["function_id"]),
            "binary_sha256": str(row["binary_sha256"]).lower(),
            "binary_path": row["binary_path"], "module_name": row["module_name"],
            "symbol_name": row["name"], "address": row["address"],
            "prototype_text": row["prototype"],
            "domain_search_hints": hints_value,
            "domain_confirmed": False,
            "identity_evidence_id": row["source_evidence_id"] if location_bound else None,
            "entry_location_evidence_valid": location_bound,
            "unique_function_entry": unique_function_entry,
            "api_status": "UNVERIFIED_CANDIDATE",
            "abi_status": "UNKNOWN",
            "parameter_layout_verified": False,
            "semantics_verified": False,
            "runtime_callable": False,
            "next_evidence": [
                "INDEPENDENT_ABI_AND_ARGUMENT_LAYOUT",
                "CALLER_AND_CALLEE_BEHAVIOR",
                "DOMAIN_AND_SEMANTIC_CONFIRMATION",
                "OSAL_OR_JNI_PROTOCOL_WHEN_APPLICABLE",
                "INDEPENDENT_RUNTIME_REVIEW",
            ],
        })
        if len(candidates) > limit:
            saturated = True
            candidates.pop()
            break
    if domain and examined >= scan_limit:
        saturated = True
    return {
        "status": "REVIEW_ONLY",
        "criteria": {
            "name": name, "binary_sha256": binary_sha256 or None,
            "domain_hint": domain or None, "include_internal": include_internal,
            "include_generated": include_generated, "limit": limit,
        },
        "reviewed_rows": examined,
        "returned": len(candidates),
        "more_candidates_possible": saturated or (not domain and examined > limit),
        "core_api_total_unknown": True,
        "verified_sdk_apis_discovered": 0,
        "candidates": candidates,
        "rule": "ELF export names and Ghidra prototypes are static candidates, not verified SDK API contracts.",
    }
