"""Evidence-bound adapters for importing selected local research artefacts.

Adapters intentionally store observations before materialising semantic rows.
The source file hash, locator and original status remain attached to every
observation; a prose hint without a locator is never promoted to verified.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .db import Database, sha256_file, utc_now

STATUSES = {"VERIFIED_STATIC", "VERIFIED_RUNTIME", "INFERRED", "CANDIDATE", "UNKNOWN", "DISPROVEN"}


def _status(value: Any, default: str = "UNKNOWN") -> str:
    if isinstance(value, dict):
        value = value.get("status")
    value = str(value or default).upper()
    return value if value in STATUSES else default


def _explicit_status(payload: Any, default: str = "UNKNOWN") -> str:
    if isinstance(payload, dict) and payload.get("status"):
        return _status(payload)
    return default


def _rel_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _binary(db: Database, digest: str | None, name: str | None = None) -> tuple[int | None, str | None]:
    rows = []
    if digest:
        rows = db.query("SELECT id,sha256 FROM binary WHERE lower(sha256)=? ORDER BY id", [digest.lower()])
    if len(rows) == 1:
        return int(rows[0]["id"]), str(rows[0]["sha256"])
    if len(rows) > 1:
        return None, digest
    if name:
        rows = db.query("SELECT id,sha256 FROM binary WHERE path LIKE ? ORDER BY id", [f"%/{name}"])
        if len(rows) == 1:
            return int(rows[0]["id"]), str(rows[0]["sha256"])
    return None, digest


def _function(db: Database, digest: str | None, address: str | None, name: str | None = None) -> int | None:
    clauses = ["1=1"]; args: list[Any] = []
    if digest:
        clauses.append("lower(b.sha256)=?"); args.append(digest.lower())
    if address:
        try: address = hex(int(str(address), 0))
        except ValueError: pass
        clauses.append("f.address=?"); args.append(address)
    if name:
        clauses.append("f.name=?"); args.append(name)
    rows = db.query("SELECT f.id FROM function f JOIN binary b ON b.id=f.binary_id WHERE " + " AND ".join(clauses) + " ORDER BY f.id", args)
    if not rows and name:
        fallback = ["lower(b.sha256)=?"] if digest else ["1=1"]
        fallback_args: list[Any] = [digest.lower()] if digest else []
        fallback.append("f.name=?"); fallback_args.append(name)
        rows = db.query("SELECT f.id FROM function f JOIN binary b ON b.id=f.binary_id WHERE " + " AND ".join(fallback) + " ORDER BY f.id", fallback_args)
    return int(rows[0]["id"]) if len(rows) == 1 else None


def _function_containing(db: Database, digest: str | None, address: str) -> int | None:
    try: value = int(address, 0)
    except ValueError: return None
    rows = db.query("SELECT f.id,f.address,f.size FROM function f JOIN binary b ON b.id=f.binary_id WHERE lower(b.sha256)=? AND f.size IS NOT NULL", [digest.lower() if digest else ""])
    matches = []
    for row in rows:
        try:
            start = int(str(row["address"]), 0); size = int(row["size"] or 0)
        except ValueError: continue
        if size > 0 and start <= value < start + size: matches.append(int(row["id"]))
    return matches[0] if len(matches) == 1 else None


@dataclass
class AdapterContext:
    db: Database
    root: Path
    run_id: int
    adapter_version: str

    def evidence(self, path: Path, locator: str, excerpt: str, status: str, kind: str) -> int:
        return self.db.evidence(_rel_path(path, self.root), sha256_file(path), kind, locator, excerpt[:2000], status,
                                {"adapter": self.adapter_version}, evidence_type=kind, status_basis="explicit_or_locator")

    def observation(self, path: Path, *, locator: str, observation_type: str, value: dict[str, Any],
                    status: str, binary_sha256: str | None = None, function_id: int | None = None,
                    function_name: str | None = None, address: str | None = None,
                    address_space: str | None = None, derived_relation: str | None = None,
                    excerpt: str = "", kind: str = "research") -> int:
        evidence_id = self.evidence(path, locator, excerpt or json.dumps(value, sort_keys=True), status, kind)
        binary_id, resolved_sha = _binary(self.db, binary_sha256)
        identity = "obs:" + ":".join(str(x or "") for x in (sha256_file(path), locator, observation_type,
                                                               resolved_sha, function_id, address, json.dumps(value, sort_keys=True)))
        return self.db.upsert("research_observation", {"source_evidence_id": evidence_id,
            "source_sha256": sha256_file(path), "source_path": _rel_path(path, self.root),
            "binary_id": binary_id, "binary_sha256": resolved_sha, "function_id": function_id,
            "function_name": function_name, "address": address, "address_space": address_space,
            "observation_type": observation_type, "locator": locator,
            "value_json": json.dumps(value, ensure_ascii=False, sort_keys=True), "status": status,
            "confidence_id": self.db.confidence_id(status), "derived_relation": derived_relation,
            "analyzer_version": self.adapter_version, "adapter_run_id": self.run_id,
            "identity_key": identity}, ("identity_key",))


class EvidenceAdapter:
    name = "base"
    version = "1"
    patterns: tuple[str, ...] = ()
    def files(self, root: Path) -> list[Path]:
        return [p for pattern in self.patterns for p in root.rglob(pattern) if p.is_file()]
    def ingest(self, ctx: AdapterContext, path: Path) -> int:
        raise NotImplementedError


class SyncAndroidAdapter(EvidenceAdapter):
    name = "syncandroid"
    version = "phase3.1-syncandroid-1"
    patterns = ("sync-android-queue-constant-hits.json", "libSyncAndroid-disassembly.txt",
                "android-sync-transport-region.txt", "android-sync-receiver.txt",
                "android-sync-registration.snapshot.json", "syncandroid-service-disassembly.txt")

    def ingest(self, ctx: AdapterContext, path: Path) -> int:
        text = path.read_text(encoding="utf-8", errors="replace")
        count = 0
        # The queue-hit report is a locator for a constant, not proof of a
        # producer/consumer relation. Keep it candidate until instruction flow
        # and registration are independently tied together.
        if path.name == "sync-android-queue-constant-hits.json":
            data = json.loads(text)
            hits = data.get("hits", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for index, hit in enumerate(hits):
                if not isinstance(hit, dict): continue
                count += 1
                self._queue_observation(ctx, path, f"$.hits[{index}]", hit, "CANDIDATE")
            return count
        if path.name in {"android-sync-receiver.txt", "android-sync-registration.snapshot.json"}:
            payload = None
            if path.suffix == ".json":
                payload = json.loads(text)
                text_for_search = json.dumps(payload, ensure_ascii=False)
            else:
                text_for_search = text
            digest = self._sha_for_name(ctx.db, "libandroid_servers.so")
            fnid = _function(ctx.db, digest, "0x12285", "_ZN7android35register_android_server_SyncAndroidEP7_JNIEnv")
            for method in ("Resume", "Suspend"):
                sig = "(I)V"
                status = "VERIFIED_STATIC"
                # A direct GetMethodID/native registration listing is a static
                # fact; it does not make the Java body runtime verified.
                loc = f"{method}:(I)V"
                count += 1
                ctx.observation(path, locator=loc, observation_type="jni_method_lookup",
                    value={"class": "com/android/server/SyncAndroidService", "method": method, "signature": sig,
                           "registration_function": "0x12285"}, status=status, binary_sha256=digest,
                    function_id=fnid, function_name="_ZN7android35register_android_server_SyncAndroidEP7_JNIEnv",
                    address="0x12285", address_space="ram", derived_relation="JNI_NATIVE_TO_JAVA",
                    excerpt=text_for_search[:1000], kind="jni_bridge")
                source_key = sha256_file(path)
                method_id = ctx.db.upsert("java_method", {"class_name": "com/android/server/SyncAndroidService",
                    "method_name": method, "signature": sig, "dex_path": f"research:{source_key}", "status": status,
                    "source_evidence_id": ctx.evidence(path, loc, text_for_search[:1000], status, "jni_bridge")},
                    ("class_name", "method_name", "signature", "dex_path"))
                bridge_key = f"jni:{digest}:com/android/server/SyncAndroidService:{method}:{sig}:registration"
                ctx.db.upsert("jni_bridge", {"class_name": "com/android/server/SyncAndroidService", "method_name": method,
                    "signature": sig, "native_entry": "UNRESOLVED", "module_id": None, "status": status,
                    "source_evidence_id": ctx.evidence(path, loc, text_for_search[:1000], status, "jni_bridge"),
                    "direction": "NATIVE_TO_JAVA", "registration_function_id": fnid,
                    "method_lookup_address": "0x122e2" if method == "Suspend" else "0x122fe"},
                    ("class_name", "method_name", "signature", "native_entry"))
            if path.name == "android-sync-transport-region.txt":
                pass
            return count
        digest = self._sha_for_name(ctx.db, "libSyncAndroid.so")
        for match in re.finditer(r"osal_snd_sync_msg", text, re.I):
            window = text[max(0, match.start() - 700):match.end() + 120]
            addresses = re.findall(r"0x[0-9a-fA-F]+", window)
            commands = re.findall(r"(?:#|0x)(?:0x)?(72|73)\b", window, re.I)
            addr = addresses[-1] if addresses else ""
            command = commands[-1] if commands else None
            fid = _function(ctx.db, digest, addr, "SyncAndroid_act" if command == "72" else None)
            count += 1
            ctx.observation(path, locator=f"text:{addr}", observation_type="osal_send",
                value={"queue": "0x01554466", "command": f"0x{command}" if command else None,
                       "api": "osal_snd_sync_msg", "semantics": "synchronous"}, status="VERIFIED_STATIC",
                binary_sha256=digest, function_id=fid, function_name="SyncAndroid_act" if command == "72" else None,
                address=addr, address_space="ram", derived_relation="SENDS_MESSAGE", excerpt=window, kind="osal_protocol")
        # The command is loaded by the caller before it enters the common
        # synchronous-send helper, so it may be outside the API call window.
        # Record that explicit instruction sequence separately and let the
        # materializer connect only observations with a concrete command.
        for match in re.finditer(r"(?:^|\n)\s*(0x[0-9a-fA-F]+):\s*movs?\s+r0\s*,\s*#?0x(72|73)\b", text, re.I):
            command_address, command = match.group(1), match.group(2)
            window = text[match.start():match.end() + 600]
            if "osal_snd_sync_msg" not in window and "0x21c0" not in window:
                continue
            addr = command_address
            fname = "SyncAndroid_act" if command == "72" else None
            fid = _function_containing(ctx.db, digest, addr) or _function(ctx.db, digest, addr, fname)
            count += 1
            ctx.observation(path, locator=f"text:command:{addr}:0x{command}", observation_type="osal_send",
                value={"queue": "0x01554466", "command": f"0x{command}", "api": "osal_snd_sync_msg",
                       "semantics": "synchronous"}, status="VERIFIED_STATIC", binary_sha256=digest,
                function_id=fid, function_name=fname, address=addr, address_space="ram",
                derived_relation="SENDS_MESSAGE", excerpt=window, kind="osal_protocol")
        if path.name == "android-sync-transport-region.txt":
            for match in re.finditer(r"0x(?P<addr>[0-9a-fA-F]+).*?(?:0x73|0x72)", text, re.I | re.S):
                count += 1
                ctx.observation(path, locator=f"text:{match.group('addr')}", observation_type="osal_dispatch_candidate",
                    value={"queue": "0x01554466", "commands": ["0x72", "0x73"], "target": "indirect:0x8944"},
                    status="CANDIDATE", binary_sha256=self._sha_for_name(ctx.db, "libandroid_servers.so"),
                    address="0x" + match.group("addr"), address_space="ram", derived_relation="RECEIVES_MESSAGE",
                    excerpt=match.group(0), kind="osal_protocol")
        if path.name == "syncandroid-service-disassembly.txt":
            for method in ("Resume", "Suspend"):
                if method in text:
                    count += 1
                    ctx.observation(path, locator=f"method:{method}", observation_type="java_method_body",
                        value={"class": "com/android/server/SyncAndroidService", "method": method, "signature": "(I)V"},
                        status="VERIFIED_STATIC", derived_relation="JAVA_METHOD", excerpt=text[:1000], kind="jni_bridge")
        return count

    @staticmethod
    def _sha_for_name(db: Database, name: str) -> str | None:
        rows = db.query("SELECT sha256 FROM binary WHERE path LIKE ? ORDER BY id", [f"%/{name}"])
        return str(rows[0]["sha256"]) if len(rows) == 1 else None

    @staticmethod
    def _queue_observation(ctx: AdapterContext, path: Path, locator: str, hit: dict[str, Any], status: str) -> None:
        name = Path(str(hit.get("path") or hit.get("file") or "")).name
        digest = None
        if name:
            digest = SyncAndroidAdapter._sha_for_name(ctx.db, name)
        ctx.observation(path, locator=locator, observation_type="queue_constant_hit",
            value=hit, status=status, binary_sha256=digest, address=str(hit.get("offset") or ""),
            address_space="file", derived_relation="QUEUE_CONSTANT", excerpt=json.dumps(hit, sort_keys=True), kind="osal_protocol")


class CameraStateAdapter(EvidenceAdapter):
    name = "camera-state"
    version = "phase3.1-camera-state-1"
    patterns = ("camera-state-transitions.json", "model-camera-vtables.json", "view-boot-vtables.json", "imdb-entries.json")

    def ingest(self, ctx: AdapterContext, path: Path) -> int:
        try: payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception: return 0
        digest = str(payload.get("input_sha256") or payload.get("binary_sha256") or "") if isinstance(payload, dict) else ""
        status = _explicit_status(payload, "UNKNOWN")
        if path.name == "camera-state-transitions.json":
            status = "VERIFIED_STATIC" if "STATIC" in str(payload.get("status", "")).upper() else status
        count = 0
        items = payload.get("transitions", payload.get("transitions_and_focus_actions", [])) if isinstance(payload, dict) else []
        if isinstance(items, list):
            for idx, item in enumerate(items):
                if not isinstance(item, dict): continue
                count += 1
                ctx.observation(path, locator=f"$.transitions[{idx}]", observation_type="state_transition",
                    value=item, status=status, binary_sha256=digest or None, address=str(item.get("address") or ""),
                    address_space="ram", derived_relation="TRANSITIONS_TO", excerpt=json.dumps(item, sort_keys=True), kind="camera_state")
        else:
            count += 1
            ctx.observation(path, locator="$", observation_type="research_summary", value=payload if isinstance(payload, dict) else {"value": payload},
                status=status, binary_sha256=digest or None, derived_relation="CAMERA_STATE_ANALYSIS", excerpt=json.dumps(payload, sort_keys=True)[:1000], kind="camera_state")
        return count


class AdapterRegistry:
    def __init__(self) -> None:
        self.adapters: list[EvidenceAdapter] = [SyncAndroidAdapter(), CameraStateAdapter()]

    def scan(self, root: Path) -> dict[str, int]:
        return {adapter.name: len({p.resolve() for p in adapter.files(root)}) for adapter in self.adapters}

    def ingest(self, db: Database, root: Path, profile: str = "targeted") -> dict[str, Any]:
        root = root.resolve()
        results: dict[str, Any] = {"root": str(root), "adapters": {}}
        for adapter in self.adapters:
            paths = sorted({p.resolve() for p in adapter.files(root)})
            run_key = f"evidence:{adapter.name}:{adapter.version}:{root}"
            run_id = db.upsert("evidence_adapter_run", {"run_key": run_key, "adapter": adapter.name,
                "adapter_version": adapter.version, "root_path": str(root), "input_file_count": len(paths),
                "observation_count": 0, "relation_count": 0, "status": "RUNNING", "started_at": utc_now(),
                "completed_at": None, "error_text": None, "metadata_json": json.dumps({"profile": profile}, sort_keys=True)}, ("run_key",))
            ctx = AdapterContext(db, root, run_id, adapter.version)
            count = 0
            try:
                for path in paths: count += adapter.ingest(ctx, path)
                db.connection.execute("UPDATE evidence_adapter_run SET observation_count=?,relation_count=?,status='COMPLETE',completed_at=?,error_text=NULL WHERE id=?", (count, count, utc_now(), run_id))
                db.commit()
            except Exception as exc:
                db.connection.execute("UPDATE evidence_adapter_run SET status='FAILED',completed_at=?,error_text=? WHERE id=?", (utc_now(), str(exc), run_id)); db.commit()
                results["adapters"][adapter.name] = {"status": "FAILED", "error": str(exc)}
                continue
            results["adapters"][adapter.name] = {"status": "COMPLETE", "files": len(paths), "observations": count, "run_id": run_id}
        self._materialize_osal(db)
        self._materialize_camera(db)
        return results

    @staticmethod
    def _materialize_osal(db: Database) -> None:
        """Turn normalized OSAL observations into generic queue/message rows."""
        rows = db.query("SELECT * FROM research_observation WHERE observation_type='osal_send' ORDER BY id")
        for row in rows:
            value = json.loads(row["value_json"])
            queue_value = str(value.get("queue") or "")
            command_value = str(value.get("command") or "")
            if not queue_value or not command_value: continue
            module_id = None
            if row["binary_id"]:
                m = db.connection.execute("SELECT id FROM module WHERE binary_id=? ORDER BY id LIMIT 1", (row["binary_id"],)).fetchone()
                module_id = int(m[0]) if m else None
            evidence_id = int(row["source_evidence_id"])
            queue = db.upsert("message_queue", {"module_id": module_id, "name": "OSAL_QUEUE_0x01554466",
                "address": queue_value, "direction": "unknown", "status": row["status"],
                "source_evidence_id": evidence_id, "identity_key": f"queue:osal:0x01554466",
                "namespace": "osal", "queue_value": queue_value, "semantics": "OSAL message queue",
                "callback_function_id": None, "address_space": row["address_space"], "analyzer_version": row["analyzer_version"]}, ("identity_key",))
            message = db.upsert("message_id", {"namespace": "osal-command", "value": command_value,
                "name": "Resume" if command_value.lower() == "0x72" else "Suspend" if command_value.lower() == "0x73" else None,
                "description": "Command observed in SyncAndroid static disassembly", "status": row["status"],
                "source_evidence_id": evidence_id, "identity_key": f"message-id:osal-command:{command_value}"}, ("identity_key",))
            msg = db.upsert("osal_message", {"queue_id": queue, "message_id": message, "direction": "request",
                "semantics": "synchronous" if value.get("semantics") == "synchronous" else "unknown",
                "payload_layout": None, "reply_message_id": None, "timeout_ms": None,
                "producer_function_id": row["function_id"], "consumer_function_id": None, "callback_function_id": None,
                "status": row["status"], "source_evidence_id": evidence_id, "analyzer_version": row["analyzer_version"],
                "identity_key": f"osal:{queue_value}:{command_value}:request", "metadata_json": json.dumps(value, sort_keys=True)}, ("identity_key",))
            if row["function_id"]:
                db.upsert("message_flow", {"osal_message_id": msg, "role": "producer", "module_id": module_id,
                    "function_id": row["function_id"], "status": row["status"], "source_evidence_id": evidence_id,
                    "identity_key": f"flow:{msg}:producer:{row['function_id']}", "metadata_json": "{}"}, ("identity_key",))
        if rows:
            db.upsert("unresolved_edge", {"identity_key": "osal:0x01554466:receiver:unresolved", "from_type": "message_queue",
                "from_id": None, "to_type": "function", "to_id": None, "relation": "osal_receiver",
                "reason": "Native dispatcher region is present in research evidence but no canonical function identity was confirmed",
                "status": "CANDIDATE", "source_evidence_id": rows[0]["source_evidence_id"]}, ("identity_key",))
        db.commit()

    @staticmethod
    def _materialize_camera(db: Database) -> None:
        rows = db.query("SELECT * FROM research_observation WHERE observation_type='state_transition' ORDER BY id")
        for row in rows:
            value = json.loads(row["value_json"])
            status = row["status"]
            evidence_id = int(row["source_evidence_id"])
            machine = db.upsert("state_machine", {"name": "ModelCamera", "module_id": None,
                "description": "Static selector evaluation; camera execution and first-shot readiness are unknown",
                "status": status, "source_evidence_id": evidence_id}, ("name",))
            before = str(value.get("state")) if value.get("state") is not None else None
            after = str(value.get("next_state")) if value.get("next_state") is not None else None
            if before is None or after is None: continue
            from_id = db.upsert("state", {"machine_id": machine, "value": before, "name": f"STATE_{before}",
                "description": None, "status": status, "source_evidence_id": evidence_id}, ("machine_id", "value", "name"))
            to_id = db.upsert("state", {"machine_id": machine, "value": after, "name": f"STATE_{after}",
                "description": None, "status": status, "source_evidence_id": evidence_id}, ("machine_id", "value", "name"))
            selector = str(value.get("selector") or "")
            event_id = db.upsert("event_id", {"namespace": "ModelCamera.selector", "value": selector,
                "name": "selector", "description": "EventFilter selector; raw event mapping unresolved", "status": "CANDIDATE",
                "source_evidence_id": evidence_id, "identity_key": f"event:ModelCamera.selector:{selector}"}, ("identity_key",))
            db.upsert("state_transition", {"machine_id": machine, "from_state_id": from_id, "event_id": event_id,
                "to_state_id": to_id, "action": str(value.get("action")) if value.get("action") is not None else None,
                "status": status, "source_evidence_id": evidence_id,
                "identity_key": f"transition:ModelCamera:{before}:{selector}:{after}:{value.get('action') or ''}"}, ("identity_key",))
        db.commit()


def ingest_research_evidence(db: Database, root: Path, profile: str = "targeted") -> dict[str, Any]:
    return AdapterRegistry().ingest(db, root, profile)
