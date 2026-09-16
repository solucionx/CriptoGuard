from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cryptoguard.container_v4 import verify_container  # noqa: E402


class PermanentFormatVectorTests(unittest.TestCase):
    def test_committed_v4_vectors_remain_readable_and_byte_stable(self) -> None:
        base = ROOT / "tests" / "vectors"
        manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
        password = manifest["password"]
        for vector in manifest["vectors"]:
            with self.subTest(vector=vector["file"]):
                path = base / vector["file"]
                raw = path.read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), vector["container_sha256"])
                metadata, digest = verify_container(path, password)
                self.assertEqual(metadata.original_name, vector["original_name"])
                self.assertEqual(digest, vector["plaintext_sha256"])


if __name__ == "__main__":
    unittest.main()
