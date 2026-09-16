from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "python"))

from cryptoguard import CryptoError, decrypt_path, encrypt_path  # noqa: E402
from cryptoguard import container_v4  # noqa: E402
from cryptoguard.secure_delete import overwrite_file, shred_and_delete, validate_shred_passes  # noqa: E402


class ExtremeModeTests(unittest.TestCase):
    PASSWORD = "CryptoGuard-Extreme-123!"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cryptoguard_extreme_test_"))
        self.fast = patch.multiple(
            container_v4,
            ARGON2_MEMORY_KIB=32 * 1024,
            ARGON2_ITERATIONS=2,
            ARGON2_PARALLELISM=1,
            DEFAULT_CHUNK_SIZE=64 * 1024,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_validate_passes_is_strict(self) -> None:
        for value in (1, 2, 3, 7):
            self.assertEqual(validate_shred_passes(value), value)
        for value in (0, 4, 8, True, "2"):
            with self.assertRaises(CryptoError):
                validate_shred_passes(value)  # type: ignore[arg-type]

    def test_overwrite_file_changes_bytes_without_changing_size(self) -> None:
        path = self.tmp / "plain.bin"
        original = b"A" * 8192
        path.write_bytes(original)
        overwrite_file(path, passes=1)
        self.assertTrue(path.exists())
        self.assertEqual(path.stat().st_size, len(original))
        self.assertNotEqual(path.read_bytes(), original)

    def test_shred_and_delete_directory_removes_tree(self) -> None:
        folder = self.tmp / "tree"
        (folder / "sub").mkdir(parents=True)
        (folder / "a.bin").write_bytes(b"A" * 1024)
        (folder / "sub" / "b.bin").write_bytes(b"B" * 2048)
        shred_and_delete(folder, passes=1)
        self.assertFalse(folder.exists())

    def test_extreme_mode_round_trip_keeps_verified_container(self) -> None:
        source = self.tmp / "secret.bin"
        payload = bytes(range(256)) * 512
        source.write_bytes(payload)
        with self.fast:
            encrypted = encrypt_path(
                source,
                self.PASSWORD,
                delete_original=True,
                advanced_mode=True,
                shred_passes=1,
            )
        self.assertFalse(source.exists())
        self.assertTrue(encrypted.exists())
        restored = decrypt_path(encrypted, self.PASSWORD, delete_encrypted=False)
        self.assertEqual(restored.read_bytes(), payload)

    def test_extreme_mode_rejects_keep_original(self) -> None:
        source = self.tmp / "keep.txt"
        source.write_text("keep", encoding="utf-8")
        with self.assertRaises(CryptoError):
            encrypt_path(
                source,
                self.PASSWORD,
                delete_original=False,
                advanced_mode=True,
                shred_passes=1,
            )
        self.assertTrue(source.exists())

    def test_verification_failure_never_calls_extreme_delete(self) -> None:
        source = self.tmp / "critical.txt"
        source.write_text("must survive", encoding="utf-8")
        with self.fast, \
             patch("cryptoguard.engine.verify_container", side_effect=CryptoError("forced")), \
             patch("cryptoguard.engine.shred_and_delete") as shred:
            with self.assertRaises(CryptoError):
                encrypt_path(
                    source,
                    self.PASSWORD,
                    delete_original=True,
                    advanced_mode=True,
                    shred_passes=1,
                )
        shred.assert_not_called()
        self.assertTrue(source.exists())
        self.assertFalse((self.tmp / "critical.txt.cguard").exists())

    def test_extreme_delete_failure_preserves_verified_container(self) -> None:
        source = self.tmp / "locked.txt"
        source.write_text("still here", encoding="utf-8")
        with self.fast, patch("cryptoguard.engine.shred_and_delete", side_effect=CryptoError("blocked")):
            with self.assertRaises(CryptoError):
                encrypt_path(
                    source,
                    self.PASSWORD,
                    delete_original=True,
                    advanced_mode=True,
                    shred_passes=1,
                )
        self.assertTrue(source.exists())
        self.assertTrue((self.tmp / "locked.txt.cguard").exists())


if __name__ == "__main__":
    unittest.main()
