from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.sdk_mock import simulate_protocol


class OfflineSdkProtocolMockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.scenario = self.root / "scenario.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _scenario(self, *, steps: list[dict], transitions: list[dict] | None = None) -> Path:
        self.scenario.write_text(json.dumps({
            "schema_version": 1, "initial_state": "idle",
            "transitions": transitions if transitions is not None else [
                {"from": "idle", "to": "pending", "namespace": "camera-mock",
                 "command": "prepare", "reply": "accepted"},
                {"from": "pending", "to": "ready", "namespace": "camera-mock",
                 "command": "complete", "reply": "ready"},
                {"from": "idle", "to": "ui-active", "namespace": "ui-mock",
                 "command": "prepare", "reply": "rendering"},
            ],
            "steps": steps,
        }), encoding="utf-8")
        return self.scenario

    def test_replay_validates_states_and_namespace(self) -> None:
        scenario = self._scenario(steps=[
            {"namespace": "camera-mock", "command": "prepare",
             "expect_state": "pending", "expect_reply": "accepted"},
            {"namespace": "camera-mock", "command": "complete",
             "expect_state": "ready", "expect_reply": "ready"},
        ])
        result = simulate_protocol(scenario)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["final_state"], "ready")
        self.assertFalse(result["hardware_access"])
        self.assertFalse(result["firmware_semantics_verified"])
        self.assertEqual([x["status"] for x in result["trace"]], ["PASS", "PASS"])

    def test_same_command_in_different_namespace_does_not_alias(self) -> None:
        result = simulate_protocol(self._scenario(steps=[
            {"namespace": "ui-mock", "command": "prepare", "expect_state": "ui-active"},
        ]))
        self.assertEqual(result["final_state"], "ui-active")

    def test_missing_or_wrong_transition_is_explicit_failure(self) -> None:
        result = simulate_protocol(self._scenario(steps=[
            {"namespace": "camera-mock", "command": "missing"},
            {"namespace": "camera-mock", "command": "prepare", "expect_state": "ready"},
        ]))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["failures"], 2)
        self.assertEqual([x["status"] for x in result["trace"]],
                         ["UNRESOLVED_TRANSITION", "EXPECTED_RESULT_MISMATCH"])

    def test_reject_duplicate_rules_and_malformed_inputs(self) -> None:
        rule = {"from": "idle", "to": "pending", "namespace": "mock", "command": "go"}
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            simulate_protocol(self._scenario(steps=[], transitions=[rule, rule]))
        self.scenario.write_text('{"schema_version": 1, "initial_state":"idle", "transitions":{}}',
                                 encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "arrays"):
            simulate_protocol(self.scenario)

    def test_cli_failure_returns_nonzero_and_never_requires_camera(self) -> None:
        scenario = self._scenario(steps=[{"namespace": "camera-mock", "command": "unknown"}])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--db", str(self.root / "study.sqlite"), "sdk", "mock",
                         "--scenario", str(scenario), "--json"])
        self.assertEqual(code, 2)
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["hardware_access"])


if __name__ == "__main__":
    unittest.main()
