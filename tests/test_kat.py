from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from cryptoguard.kdf import derive_keys  # noqa: E402
from cryptoguard.memory import wipe_buffer  # noqa: E402


class KnownAnswerTests(unittest.TestCase):
    def test_aes_256_gcm_nist_vector_empty_plaintext(self) -> None:
        # AES-256, key=0^256, IV=0^96, P="", AAD="".
        result = AESGCM(bytes(32)).encrypt(bytes(12), b"", b"")
        self.assertEqual(result.hex(), "530f8afbc74536b9a963b4f1c4cb738b")

    def test_aes_256_gcm_nist_vector_one_block(self) -> None:
        result = AESGCM(bytes(32)).encrypt(bytes(12), bytes(16), b"")
        self.assertEqual(
            result.hex(),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
        )

    def test_hkdf_sha256_rfc5869_case_1(self) -> None:
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = HKDF(algorithm=hashes.SHA256(), length=42, salt=salt, info=info).derive(ikm)
        self.assertEqual(
            okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        )

    def test_argon2id_plus_hkdf_crypto_guard_kat(self) -> None:
        content_key, metadata_key = derive_keys(
            "CryptoGuard-KAT",
            b"0123456789ABCDEF",
            b"FEDCBA9876543210",
            memory_kib=32 * 1024,
            iterations=2,
            parallelism=1,
        )
        try:
            self.assertEqual(content_key.hex(), "429f0b4d65dd0d33a3f698400551768b6cd76ae91f71150dd4cfd9ace7477d98")
            self.assertEqual(metadata_key.hex(), "06c46acf95402b76ec006ebbc3a7c68b45ee498366e4b45050c2e149f2dc8230")
        finally:
            wipe_buffer(content_key)
            wipe_buffer(metadata_key)


if __name__ == "__main__":
    unittest.main()
