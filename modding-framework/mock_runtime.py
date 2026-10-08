from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class ModuleSpec:
    module_id: str
    version: str
    firmware_sha256: str
    dependencies: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    entrypoint: Callable[[], None] | None = None
    exitpoint: Callable[[], None] | None = None


@dataclass
class ModuleState:
    spec: ModuleSpec
    enabled: bool = False
    diagnostic: str = "registered"


class MockModdingRuntime:
    """Offline registry used to test activation and rollback without firmware writes."""

    def __init__(self, firmware_sha256: str):
        self.firmware_sha256 = firmware_sha256
        self.modules: dict[str, ModuleState] = {}
        self.events: list[str] = []

    def register(self, spec: ModuleSpec) -> None:
        if spec.module_id in self.modules:
            raise ValueError(f"module already registered: {spec.module_id}")
        if spec.firmware_sha256 != self.firmware_sha256:
            raise ValueError(f"firmware hash mismatch for {spec.module_id}")
        self.modules[spec.module_id] = ModuleState(spec)

    def enable(self, module_id: str) -> None:
        state = self.modules[module_id]
        for dependency in state.spec.dependencies:
            if dependency not in self.modules or not self.modules[dependency].enabled:
                raise RuntimeError(f"dependency is not enabled: {dependency}")
        for conflict in state.spec.conflicts:
            if conflict in self.modules and self.modules[conflict].enabled:
                raise RuntimeError(f"module conflict: {module_id} vs {conflict}")
        if state.spec.entrypoint:
            state.spec.entrypoint()
        state.enabled = True
        state.diagnostic = "enabled"
        self.events.append(f"enable:{module_id}")

    def disable(self, module_id: str) -> None:
        state = self.modules[module_id]
        dependents = [s.spec.module_id for s in self.modules.values() if state.spec.module_id in s.spec.dependencies and s.enabled]
        if dependents:
            raise RuntimeError(f"enabled dependents: {','.join(dependents)}")
        if state.spec.exitpoint:
            state.spec.exitpoint()
        state.enabled = False
        state.diagnostic = "disabled"
        self.events.append(f"disable:{module_id}")

    def diagnostics(self) -> dict[str, object]:
        return {"firmware_sha256": self.firmware_sha256,
                "modules": {key: {"enabled": value.enabled, "diagnostic": value.diagnostic}
                            for key, value in self.modules.items()}, "events": list(self.events)}

    def transaction(self):
        return _Transaction(self)


class _Transaction:
    def __init__(self, runtime: MockModdingRuntime):
        self.runtime = runtime
        self.before: set[str] = set()

    def __enter__(self) -> MockModdingRuntime:
        self.before = {key for key, state in self.runtime.modules.items() if state.enabled}
        return self.runtime

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None:
            for key, state in self.runtime.modules.items():
                if state.enabled and key not in self.before:
                    state.enabled = False
                    state.diagnostic = "rolled back"
            self.runtime.events.append("rollback")
        return False

