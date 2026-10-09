"""Offline SDK contract registry: explicit evidence, not executable camera calls."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .db import Database, sha256_file, utc_now


STATIC_STATUSES = {"UNKNOWN", "CANDIDATE", "INFERRED", "VERIFIED_STATIC"}
RUNTIME_SAFETY = "DESCRIPTIVE_ONLY"
HEX_SHA = re.compile(r"^[0-9a-fA-F]{64}$")
DOMAINS = ("Camera", "Lens", "Sensor", "Media", "UI", "OSAL", "Android", "Networking", "Other")


def _field(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"SDK {name} must be a non-empty string")
    return value.strip()


def _optional_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    raise ValueError(f"SDK {field} must be a string, object, list, or null")


def _proves_function_location(evidence: Any, sha256: str, address: str) -> bool:
    """Require an independent source locator matching BOTH binary and function.

    A generic VERIFIED_STATIC row from a different binary must not promote an
    unrelated SDK contract. Metadata-only Ghidra exports also are not proof
    of a function's ABI or semantic behavior.
    """
    if evidence is None or not sha256 or not address:
        return False
    try:
        excerpt = json.loads(evidence["excerpt"] or "{}")
        metadata = json.loads(evidence["metadata_json"] or "{}")
    except (TypeError, ValueError):
        return False
    if not isinstance(excerpt, dict):
        excerpt = {}
    if not isinstance(metadata, dict):
        metadata = {}
    referenced_digest = (excerpt.get("binary_sha256") or metadata.get("binary_sha256")
                         or evidence["source_sha256"] or "")
    if str(referenced_digest).lower() != sha256.lower():
        return False
    reference_address = (excerpt.get("function_entry") or excerpt.get("entry_vma")
                         or excerpt.get("function_address") or excerpt.get("address")
                         or metadata.get("function_entry") or metadata.get("function_address"))
    if reference_address is None:
        return False
    try:
        return int(str(reference_address), 0) == int(address, 0)
    except ValueError:
        return False


def _contract_value(value: Any) -> str:
    """Compare JSON layouts canonically, retaining human-readable ABI strings."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return value.strip()
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _proves_signature(evidence: Any, values: dict[str, Any]) -> bool:
    """A primary static record must contain the same ABI and full call layout.

    Address-level disassembly evidence alone is not evidence for a proposed
    calling convention, parameter layout or return contract.
    """
    if evidence is None:
        return False
    try:
        excerpt = json.loads(evidence["excerpt"] or "{}")
    except (TypeError, ValueError):
        return False
    if not isinstance(excerpt, dict):
        return False
    for field in ("abi", "parameter_layout", "return_semantics"):
        if field not in excerpt or excerpt[field] is None or not values.get(field):
            return False
        if _contract_value(excerpt[field]) != _contract_value(values[field]):
            return False
    return True


def _lookup_function(db: Database, binary_sha: str, address: str) -> tuple[int | None, int | None, int | None]:
    binaries = db.query("SELECT id FROM binary WHERE lower(sha256)=?", (binary_sha,))
    if len(binaries) != 1:
        return None, None, None
    bid = int(binaries[0]["id"])
    functions = db.query("SELECT id,module_id FROM function WHERE binary_id=? AND address=?", (bid, address))
    if len(functions) != 1:
        return bid, None, None
    return bid, int(functions[0]["id"]), functions[0]["module_id"]


def import_sdk_contracts(db: Database, fixture: Path) -> dict[str, Any]:
    """Import explicitly documented API hypotheses from a local JSON fixture.

    Static verification needs an existing independent evidence row and exact
    binary+function resolution. Runtime safety can never be enabled here.
    An incomplete reference remains CANDIDATE and is never guessed from names.
    """
    fixture = fixture.resolve()
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("SDK fixture requires schema_version=1")
    firmware = _field(payload.get("firmware_version"), "firmware_version")
    entries = payload.get("interfaces")
    if not isinstance(entries, list):
        raise ValueError("SDK fixture requires interfaces array")
    if len(entries) > 10000:
        raise ValueError("SDK fixture exceeds 10000 interfaces")
    # Preflight every interface before any SQLite changes.
    prepared: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"SDK interfaces[{index}] must be an object")
        name = _field(entry.get("name"), "name")
        domain = _field(entry.get("domain"), "domain")
        if domain not in DOMAINS:
            raise ValueError(f"SDK domain {domain!r} is unsupported")
        binary_sha = str(entry.get("binary_sha256") or "").lower()
        if binary_sha and not HEX_SHA.fullmatch(binary_sha):
            raise ValueError("SDK binary_sha256 must be a 64-digit SHA-256")
        address = str(entry.get("address") or "")
        if address:
            try:
                address = hex(int(address, 0))
            except ValueError as exc:
                raise ValueError(f"SDK {name}: address must be hexadecimal or decimal") from exc
        if address and not binary_sha:
            raise ValueError(f"SDK {name}: address requires binary_sha256")
        requested = entry.get("verification_status", "CANDIDATE")
        if requested not in STATIC_STATUSES:
            raise ValueError(f"SDK {name}: offline fixture cannot assert runtime verification")
        if entry.get("runtime_safety", RUNTIME_SAFETY) != RUNTIME_SAFETY:
            raise ValueError(f"SDK {name}: offline contracts must be DESCRIPTIVE_ONLY")
        if "source_evidence_id" in entry and (not isinstance(entry["source_evidence_id"], int)
                                               or isinstance(entry["source_evidence_id"], bool)
                                               or entry["source_evidence_id"] <= 0):
            raise ValueError(f"SDK {name}: invalid source_evidence_id")
        key = (domain, name, firmware, binary_sha, address)
        if key in seen:
            raise ValueError(f"SDK duplicate interface identity: {domain}:{name}")
        seen.add(key)
        text_fields = {}
        for field in ("abi", "calling_convention", "parameter_layout", "return_semantics",
                      "preconditions", "thread_context", "state_requirements",
                      "side_effects", "event_dependencies"):
            text_fields[field] = _optional_text(entry.get(field), field)
        prepared.append({
            "name": name, "domain": domain, "binary_sha": binary_sha, "address": address,
            "requested": requested, "primary_evidence": entry.get("source_evidence_id"),
            "fields": text_fields,
        })

    db.connection.execute("SAVEPOINT sdk_contract_import")
    try:
        fixture_evidence = db.evidence(
            str(fixture), sha256_file(fixture), "sdk_contract_fixture",
            "document", json.dumps(payload, ensure_ascii=False, sort_keys=True),
            "CANDIDATE", {"schema_version": 1, "firmware_version": firmware},
            evidence_type="sdk_contract", status_basis="fixture_assertion",
        )
        counts = {"interfaces": 0, "function_resolved": 0, "unresolved": 0,
                  "verified_static": 0, "downgraded": 0}
        for item in prepared:
            binary_id, function_id, module_id = (
                _lookup_function(db, item["binary_sha"], item["address"])
                if item["binary_sha"] and item["address"] else (None, None, None)
            )
            source_id = item["primary_evidence"]
            source = (db.connection.execute(
                "SELECT status,source_sha256,excerpt,metadata_json FROM evidence WHERE id=?",
                (source_id,)).fetchone()
                      if source_id is not None else None)
            if source_id is not None and source is None:
                raise ValueError(f"SDK {item['name']}: source_evidence_id does not exist")
            # A self-describing fixture is not primary proof of the ABI.
            eligible_static = bool(
                function_id is not None and source is not None
                and source["status"] == "VERIFIED_STATIC"
                and _proves_function_location(source, item["binary_sha"], item["address"])
                and _proves_signature(source, item["fields"])
                and item["requested"] == "VERIFIED_STATIC"
            )
            status = "VERIFIED_STATIC" if eligible_static else (
                "CANDIDATE" if item["requested"] == "VERIFIED_STATIC" else item["requested"]
            )
            if item["requested"] == "VERIFIED_STATIC" and not eligible_static:
                counts["downgraded"] += 1
            if eligible_static:
                counts["verified_static"] += 1
            if function_id is None:
                counts["unresolved"] += 1
            else:
                counts["function_resolved"] += 1
            identity = ("sdk:" + json.dumps(
                [firmware, item["domain"], item["name"], item["binary_sha"], item["address"]],
                separators=(",", ":"), ensure_ascii=False
            ))
            evidence_id = source_id or fixture_evidence
            db.upsert("sdk_interface", {
                "identity_key": identity, "name": item["name"], "domain": item["domain"],
                "module_id": module_id, "binary_id": binary_id, "function_id": function_id,
                "address": item["address"] or None, **item["fields"],
                "firmware_version": firmware,
                "evidence_references": json.dumps([evidence_id]),
                "verification_status": status, "runtime_safety": RUNTIME_SAFETY,
                "mock_status": "NOT_TESTED", "source_evidence_id": evidence_id,
                "analyzer_version": "sdk-contracts:1",
                "metadata_json": json.dumps({
                    "requested_status": item["requested"],
                    "resolution": "EXACT_FUNCTION" if function_id is not None else "UNRESOLVED",
                    "fixture_evidence_id": fixture_evidence,
                }, sort_keys=True),
            }, ("identity_key",))
            counts["interfaces"] += 1
        db.connection.execute("RELEASE SAVEPOINT sdk_contract_import")
        db.commit()
        return {**counts, "status": "COMPLETE", "fixture_evidence_id": fixture_evidence}
    except Exception:
        db.connection.execute("ROLLBACK TO SAVEPOINT sdk_contract_import")
        db.connection.execute("RELEASE SAVEPOINT sdk_contract_import")
        raise


def audit_sdk_contracts(db: Database) -> dict[str, Any]:
    """Review evidence/ABI/identity gaps without promoting any runtime claim."""
    records: list[dict[str, Any]] = []
    complete_static = 0
    for row in db.query("""SELECT s.*,e.status AS evidence_status,e.kind AS evidence_kind,
            e.source_sha256 AS evidence_sha256,e.excerpt AS evidence_excerpt,
            e.metadata_json AS evidence_metadata_json,
            f.binary_id AS function_binary_id,f.address AS function_address,
            b.sha256 AS binary_sha256
            FROM sdk_interface s LEFT JOIN evidence e ON e.id=s.source_evidence_id
            LEFT JOIN function f ON f.id=s.function_id
            LEFT JOIN binary b ON b.id=s.binary_id ORDER BY s.domain,s.name,s.id"""):
        issues: list[str] = []
        if row["source_evidence_id"] is None or row["evidence_status"] is None:
            issues.append("MISSING_PRIMARY_EVIDENCE")
        elif row["verification_status"] == "VERIFIED_STATIC" and row["evidence_status"] != "VERIFIED_STATIC":
            issues.append("STATIC_STATUS_WITHOUT_STATIC_EVIDENCE")
        if row["verification_status"] == "VERIFIED_STATIC" and row["evidence_status"] == "VERIFIED_STATIC":
            proof = {"source_sha256": row["evidence_sha256"], "excerpt": row["evidence_excerpt"],
                     "metadata_json": row["evidence_metadata_json"]}
            if not _proves_function_location(proof, str(row["binary_sha256"] or ""), str(row["address"] or "")):
                issues.append("PRIMARY_EVIDENCE_NOT_BOUND_TO_FUNCTION")
            if not _proves_signature(proof, {
                "abi": row["abi"], "parameter_layout": row["parameter_layout"],
                "return_semantics": row["return_semantics"],
            }):
                issues.append("PRIMARY_EVIDENCE_NOT_BOUND_TO_ABI")
        if row["binary_id"] is None:
            issues.append("UNRESOLVED_BINARY")
        if row["function_id"] is None or row["function_binary_id"] is None:
            issues.append("UNRESOLVED_FUNCTION")
        elif row["function_binary_id"] != row["binary_id"]:
            issues.append("FUNCTION_BINARY_MISMATCH")
        if row["function_address"] is not None and row["address"] != row["function_address"]:
            issues.append("FUNCTION_ADDRESS_MISMATCH")
        if not row["abi"]:
            issues.append("ABI_UNKNOWN")
        if not row["parameter_layout"] or not row["return_semantics"]:
            issues.append("PARAMETER_OR_RETURN_LAYOUT_UNKNOWN")
        if row["runtime_safety"] != RUNTIME_SAFETY:
            issues.append("UNSUPPORTED_RUNTIME_SAFETY_CLAIM")
        if row["verification_status"] == "VERIFIED_RUNTIME":
            issues.append("RUNTIME_CLAIM_REQUIRES_INDEPENDENT_VALIDATION")
        static_ready = (not issues and row["verification_status"] == "VERIFIED_STATIC"
                        and row["evidence_status"] == "VERIFIED_STATIC")
        if static_ready:
            complete_static += 1
        records.append({
            "id": row["id"], "name": row["name"], "domain": row["domain"],
            "verification_status": row["verification_status"],
            "static_contract_complete": static_ready,
            "callable_validated": False, "issues": issues,
        })
    # Never derive firmware reverse-engineering completeness from a symbol
    # inventory: the true number of core APIs is not known in public data.
    domain_matrix = {}
    for domain in DOMAINS:
        matching = [row for row in records if row["domain"] == domain]
        complete = sum(1 for row in matching if row["static_contract_complete"])
        domain_matrix[domain] = {
            "documented": len(matching),
            "static_contract_complete": complete,
            "unresolved_or_incomplete": len(matching) - complete,
            "runtime_callable_validated": None,
            "core_reverse_engineering_complete": None,
            "required_api_denominator": None,
        }
    return {
        "status": "AUDITED", "interfaces": len(records), "static_contract_complete": complete_static,
        "domain_matrix": domain_matrix,
        "runtime_callable_validated": None,
        "unresolved_or_incomplete": len(records) - complete_static,
        "records": records,
        "rule": "Offline evidence audits never authorize execution on a camera; runtime callability remains UNKNOWN.",
    }
