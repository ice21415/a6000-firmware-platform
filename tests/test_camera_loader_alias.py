import hashlib
import tempfile
import unittest
from pathlib import Path

from fwplatform.camera_loader_alias import analyze_loader_alias


class CameraLoaderAliasTests(unittest.TestCase):
    def test_hash_pin_rejects_unrelated_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake.so"
            path.write_bytes(b"not an ELF")
            with self.assertRaises(ValueError):
                analyze_loader_alias(path, expected_sha256=hashlib.sha256(b"different").hexdigest())
