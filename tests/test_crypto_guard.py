from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from crypto_guard import CryptoError, decrypt_path, encrypt_path  # noqa: E402


class CryptoGuardRoundTripTests(unittest.TestCase):
    PASSWORD = "CryptoGuard-Teste-123!"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cryptoguard_test_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_file_round_trip(self) -> None:
        source = self.tmp / "arquivo.txt"
        payload = ("Crypto Guard\n" * 4096).encode("utf-8")
        source.write_bytes(payload)

        encrypted = encrypt_path(source, self.PASSWORD, delete_original=True)
        self.assertFalse(source.exists())
        self.assertTrue(encrypted.exists())
        self.assertTrue(encrypted.name.endswith(".cguard"))

        restored = decrypt_path(encrypted, self.PASSWORD, delete_encrypted=True)
        self.assertTrue(restored.exists())
        self.assertFalse(encrypted.exists())
        self.assertEqual(restored.read_bytes(), payload)

    def test_wrong_password_does_not_restore(self) -> None:
        source = self.tmp / "segredo.bin"
        source.write_bytes(b"abc" * 2048)
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

        encrypted = encrypt_path(source, self.PASSWORD, delete_original=True)
        self.assertFalse(source.exists())

        restored = decrypt_path(encrypted, self.PASSWORD, delete_encrypted=True)
        self.assertEqual((restored / "a.txt").read_text(encoding="utf-8"), "A")
        self.assertEqual((restored / "sub" / "b.txt").read_text(encoding="utf-8"), "B")


if __name__ == "__main__":
    unittest.main()
