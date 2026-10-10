"""C++17 compile and target-width layout checks for the descriptive header."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CameraCoreHeaderCompileTests(unittest.TestCase):
    def test_header_compiles_as_cxx17_and_keeps_arm32_layout(self) -> None:
        requested = os.environ.get("CXX")
        compiler = shutil.which(requested) if requested else None
        if compiler is None:
            for candidate in ("c++", "g++", "clang++"):
                compiler = shutil.which(candidate)
                if compiler:
                    break
        if compiler is None:
            self.skipTest("C++17 compiler unavailable on this host")

        source = """
#include <cstdint>
#include "sdk/camera_core_3_21.hpp"
using namespace a6000_research::camera_core_3_21;
static_assert(sizeof(Arm32Word) == 4);
static_assert(sizeof(RequestEventEnvelopeObservation) == 16);
static_assert(sizeof(RequestEventEnvelopeHostObservation) >=
              sizeof(RequestEventEnvelopeObservation));
int main() { return 0; }
"""
        with tempfile.TemporaryDirectory() as temp:
            source_path = Path(temp) / "camera_core_header.cpp"
            object_path = Path(temp) / "camera_core_header.o"
            source_path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    f"-I{ROOT}",
                    "-c",
                    str(source_path),
                    "-o",
                    str(object_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                msg=f"C++17 compile failed:\nstdout={result.stdout}\nstderr={result.stderr}",
            )
            self.assertTrue(object_path.exists())


if __name__ == "__main__":
    unittest.main()
