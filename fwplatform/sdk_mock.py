"""Pure offline SDK protocol simulator; never imports or invokes camera binaries."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


MAX_TRANSITIONS = 4096
MAX_STEPS = 10000


def _name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"mock {field} must be a non-empty string")
    return value.strip()


def simulate_protocol(scenario: Path) -> dict[str, Any]:
    """Replay an explicit, synthetic transition table without hardware access.

    This is a test double, not an implementation or discovery of Sony OSAL.
    A transition exists only because the scenario explicitly defines it.
    """
    payload = json.loads(scenario.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("mock scenario must have schema_version=1")
    initial = _name(payload.get("initial_state"), "initial_state")
    transitions = payload.get("transitions")
    steps = payload.get("steps")
    if not isinstance(transitions, list) or not isinstance(steps, list):
        raise ValueError("mock scenario requires transitions and steps arrays")
    if len(transitions) > MAX_TRANSITIONS or len(steps) > MAX_STEPS:
        raise ValueError("mock scenario exceeds safe transition/step limits")
    rules: dict[tuple[str, str, str], dict[str, str | None]] = {}
    for index, transition in enumerate(transitions):
        if not isinstance(transition, dict):
            raise ValueError(f"mock transition[{index}] is not an object")
        source = _name(transition.get("from"), "transition.from")
        target = _name(transition.get("to"), "transition.to")
        namespace = _name(transition.get("namespace"), "transition.namespace")
        command = _name(transition.get("command"), "transition.command")
        reply = transition.get("reply")
        if reply is not None:
            reply = _name(reply, "transition.reply")
        key = (source, namespace, command)
        if key in rules:
            raise ValueError(f"mock ambiguous transition[{index}]: {key!r}")
        rules[key] = {"to": target, "reply": reply}
    state = initial
    trace: list[dict[str, Any]] = []
    failures = 0
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError(f"mock step[{index}] is not an object")
        namespace = _name(step.get("namespace"), "step.namespace")
        command = _name(step.get("command"), "step.command")
        current = state
        rule = rules.get((state, namespace, command))
        if rule is None:
            trace.append({
                "step": index, "from": current, "to": current,
                "namespace": namespace, "command": command, "reply": None,
                "status": "UNRESOLVED_TRANSITION",
            })
            failures += 1
            continue
        state = str(rule["to"])
        reply = rule["reply"]
        expected_state = step.get("expect_state")
        expected_reply = step.get("expect_reply")
        if expected_state is not None:
            expected_state = _name(expected_state, "step.expect_state")
        if expected_reply is not None:
            expected_reply = _name(expected_reply, "step.expect_reply")
        passed = ((expected_state is None or expected_state == state)
                  and (expected_reply is None or expected_reply == reply))
        if not passed:
            failures += 1
        trace.append({
            "step": index, "from": current, "to": state,
            "namespace": namespace, "command": command, "reply": reply,
            "status": "PASS" if passed else "EXPECTED_RESULT_MISMATCH",
        })
    return {
        "status": "PASS" if failures == 0 else "FAIL",
        "engine": "offline-explicit-mock",
        "hardware_access": False,
        "firmware_semantics_verified": False,
        "initial_state": initial, "final_state": state,
        "steps": len(trace), "failures": failures, "trace": trace,
        "limitations": [
            "Explicit scenario transitions only; no recovered Sony camera behavior",
            "No OSAL transport, ELF invocation, native library loading or device writes",
        ],
    }
