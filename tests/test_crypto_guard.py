from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "python"))

from cryptoguard import CryptoCancelled, CryptoError, decrypt_path, encrypt_path  # noqa: E402
from cryptoguard import container_v4  # noqa: E402


class FastKdfMixin:
    def fast_kdf(self):
        return patch.multiple(
            container_v4,
            ARGON2_MEMORY_KIB=32 * 1024,
            ARGON2_ITERATIONS=2,
            ARGON2_PARALLELISM=1,
            DEFAULT_CHUNK_SIZE=64 * 1024,
        )


class CryptoGuardRoundTripTests(FastKdfMixin, unittest.TestCase):
    PASSWORD = "CryptoGuard-Teste-123!"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cryptoguard_v4_test_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_file_round_trip(self) -> None:
        source = self.tmp / "arquivo.txt"
        payload = ("Crypto Guard v4\n" * 4096).encode("utf-8")
        source.write_bytes(payload)

        with self.fast_kdf():
            encrypted = encrypt_path(source, self.PASSWORD, delete_original=True)
        self.assertFalse(source.exists())
        self.assertTrue(encrypted.exists())
        self.assertTrue(encrypted.name.endswith(".cguard"))

        restored = decrypt_path(encrypted, self.PASSWORD, delete_encrypted=True)
        self.assertTrue(restored.exists())
        self.assertFalse(encrypted.exists())
        self.assertEqual(restored.read_bytes(), payload)

    def test_empty_file_round_trip(self) -> None:
        source = self.tmp / "empty.bin"
        source.write_bytes(b"")
        with self.fast_kdf():
            encrypted = encrypt_path(source, self.PASSWORD, delete_original=True)
        restored = decrypt_path(encrypted, self.PASSWORD, delete_encrypted=True)
        self.assertEqual(restored.read_bytes(), b"")

    def test_wrong_password_does_not_restore(self) -> None:
        source = self.tmp / "segredo.bin"
        source.write_bytes(b"abc" * 2048)
        with self.fast_kdf():
            encrypted = encrypt_path(source, self.PASSWORD, delete_original=True)

        with self.assertRaises(CryptoError):
            decrypt_path(encrypted, "Senha-Errada-999!", delete_encrypted=False)
        self.assertTrue(encrypted.exists())
        self.assertFalse(source.exists())

    def test_directory_round_trip(self) -> None:
        source = self.tmp / "pasta"
        (source / "sub").mkdir(parents=True)
        (source / "a.txt").write_text("A", encoding="utf-8")
        (source / "sub" / "b.txt").write_text("B", encoding="utf-8")
        (source / "empty").mkdir()

        with self.fast_kdf():
            encrypted = encrypt_path(source, self.PASSWORD, delete_original=True)
        self.assertFalse(source.exists())

        restored = decrypt_path(encrypted, self.PASSWORD, delete_encrypted=True)
        self.assertEqual((restored / "a.txt").read_text(encoding="utf-8"), "A")
        self.assertEqual((restored / "sub" / "b.txt").read_text(encoding="utf-8"), "B")
        self.assertTrue((restored / "empty").is_dir())

    def test_directory_round_trip_preserves_empty_dirs_and_exact_file_bytes(self) -> None:
        source = self.tmp / "tree"
        (source / "nested" / "empty").mkdir(parents=True)
        payload = bytes(range(256)) * 257
        (source / "nested" / "blob.bin").write_bytes(payload)
        (source / "unicode-á.txt").write_text("conteúdo exato", encoding="utf-8")

        with self.fast_kdf():
            encrypted = encrypt_path(source, self.PASSWORD, delete_original=True)
        restored = decrypt_path(encrypted, self.PASSWORD, delete_encrypted=False)
        self.assertEqual((restored / "nested" / "blob.bin").read_bytes(), payload)
        self.assertEqual((restored / "unicode-á.txt").read_text(encoding="utf-8"), "conteúdo exato")
        self.assertTrue((restored / "nested" / "empty").is_dir())

    def test_password_minimum_is_12_for_new_container(self) -> None:
        source = self.tmp / "a.txt"
        source.write_text("x", encoding="utf-8")
        with self.assertRaises(CryptoError):
            encrypt_path(source, "12345678901", delete_original=False)

    def test_cancel_preserves_original_and_no_final_container(self) -> None:
        source = self.tmp / "cancel.bin"
        source.write_bytes(b"A" * (256 * 1024))

        def progress(_processed: int, _total: int, stage: str) -> None:
            if stage == "encrypt":
                raise CryptoCancelled("cancel test")

        with self.fast_kdf(), self.assertRaises(CryptoCancelled):
            encrypt_path(source, self.PASSWORD, delete_original=True, progress_callback=progress)
        self.assertTrue(source.exists())
        self.assertFalse((self.tmp / "cancel.bin.cguard").exists())

    def test_verification_failure_never_deletes_original(self) -> None:
        source = self.tmp / "critical.txt"
        source.write_text("do not delete", encoding="utf-8")
        with self.fast_kdf(), patch("cryptoguard.engine.verify_container", side_effect=CryptoError("forced")):
            with self.assertRaises(CryptoError):
                encrypt_path(source, self.PASSWORD, delete_original=True)
        self.assertTrue(source.exists())
        self.assertFalse((self.tmp / "critical.txt.cguard").exists())


if __name__ == "__main__":
    unittest.main()
