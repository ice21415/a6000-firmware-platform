from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


def load_runtime():
    path = Path(__file__).parents[1] / "modding-framework" / "mock_runtime.py"
    spec = importlib.util.spec_from_file_location("a6000_mock_runtime", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ModdingFrameworkTests(unittest.TestCase):
    def test_dependency_and_rollback(self) -> None:
        runtime_module = load_runtime()
        runtime = runtime_module.MockModdingRuntime("a" * 64)
        runtime.register(runtime_module.ModuleSpec("base", "1", "a" * 64))
        runtime.register(runtime_module.ModuleSpec("feature", "1", "a" * 64, dependencies=("base",)))
        with self.assertRaises(RuntimeError):
            runtime.enable("feature")
        runtime.enable("base")
        with runtime.transaction():
            runtime.enable("feature")
        self.assertTrue(runtime.modules["feature"].enabled)
        with self.assertRaises(RuntimeError):
            with runtime.transaction():
                runtime.disable("base")
