from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "python"))

from cryptoguard import CryptoError, encrypt_path  # noqa: E402
from cryptoguard import container_v4  # noqa: E402
from cryptoguard.constants import MAGIC, OLD_MAGIC, TAG_SIZE  # noqa: E402
from cryptoguard.container_v4 import create_container_temp, verify_container  # noqa: E402
from cryptoguard.format_v4 import build_metadata, parse_header_bytes_for_creation, read_header  # noqa: E402
from cryptoguard.strict_json import dumps_canonical, loads_strict  # noqa: E402


class V4SecurityTests(unittest.TestCase):
    PASSWORD = "CryptoGuard-Security-123!"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cryptoguard_v4_security_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fast_kdf(self):
        return patch.multiple(
            container_v4,
            ARGON2_MEMORY_KIB=32 * 1024,
            ARGON2_ITERATIONS=2,
            ARGON2_PARALLELISM=1,
            DEFAULT_CHUNK_SIZE=64 * 1024,
        )

    def _make(self, name: str = "secret-name.txt", payload: bytes = b"payload") -> Path:
        source = self.tmp / name
        source.write_bytes(payload)
        with self.fast_kdf():
            return encrypt_path(source, self.PASSWORD, delete_original=False)

    def _parsed(self, path: Path):
        with path.open("rb") as stream:
            return read_header(stream, path.stat().st_size)

    def test_public_header_does_not_expose_original_filename(self) -> None:
        encrypted = self._make("private-contract-name.txt", b"classified")
        parsed = self._parsed(encrypted)
        self.assertNotIn(b"private-contract-name.txt", parsed.header_bytes)
        self.assertNotIn("original_name", parsed.header)

    def test_same_password_and_plaintext_get_distinct_salt_nonce_and_ciphertext(self) -> None:
        source = self.tmp / "same.bin"
        source.write_bytes(b"same content" * 100)
        with self.fast_kdf():
            first = encrypt_path(source, self.PASSWORD, delete_original=False)
        first_saved = self.tmp / "first.cguard"
        first.rename(first_saved)
        with self.fast_kdf():
            second = encrypt_path(source, self.PASSWORD, delete_original=False)

        a, b = self._parsed(first_saved), self._parsed(second)
        self.assertNotEqual(a.salt, b.salt)
        self.assertNotEqual(a.nonce_prefix, b.nonce_prefix)
        self.assertNotEqual(a.container_id, b.container_id)
        self.assertNotEqual(first_saved.read_bytes(), second.read_bytes())

    def test_round_trip_verification_compares_source_bytes_directly(self) -> None:
        source = self.tmp / "source.bin"
        source.write_bytes(b"A" * 4096)
        output = self.tmp / "source.bin.cguard"
        metadata = build_metadata(kind="file", original_name=source.name)
        with self.fast_kdf():
            temp_container, digest, _ = create_container_temp(
                source, output, self.PASSWORD, metadata
            )
        try:
            # Mantém o mesmo tamanho: um teste baseado apenas em tamanho não detectaria.
            source.write_bytes(b"B" * 4096)
            with self.assertRaisesRegex(CryptoError, "byte a byte"):
                verify_container(
                    temp_container,
                    self.PASSWORD,
                    expected_digest=digest,
                    expected_metadata=metadata,
                    expected_plaintext_path=source,
                )
        finally:
            temp_container.unlink(missing_ok=True)

    def test_authenticated_header_tamper_is_rejected(self) -> None:
        encrypted = self._make(payload=b"header binding test" * 100)
        parsed = self._parsed(encrypted)
        mutated_header = json.loads(parsed.header_bytes.decode("utf-8"))
        mutated_header["kdf_params"]["iterations"] = 3
        mutated_bytes = dumps_canonical(mutated_header, label="test", max_size=16 * 1024)
        self.assertEqual(len(mutated_bytes), parsed.header_len)

        raw = bytearray(encrypted.read_bytes())
        start = len(MAGIC) + 4
        raw[start:start + parsed.header_len] = mutated_bytes
        bad = self.tmp / "bad-header.cguard"
        bad.write_bytes(raw)
        with self.assertRaises(CryptoError):
            verify_container(bad, self.PASSWORD)

    def test_metadata_tamper_is_rejected(self) -> None:
        encrypted = self._make(payload=b"A" * 1000)
        parsed = self._parsed(encrypted)
        data = bytearray(encrypted.read_bytes())
        data[parsed.metadata_offset] ^= 0x01
        bad = self.tmp / "bad-meta.cguard"
        bad.write_bytes(data)
        with self.assertRaises(CryptoError):
            verify_container(bad, self.PASSWORD)

    def test_ciphertext_or_tag_tamper_is_rejected(self) -> None:
        encrypted = self._make(payload=b"A" * 1000)
        parsed = self._parsed(encrypted)
        data = bytearray(encrypted.read_bytes())
        data[parsed.content_offset + 10] ^= 0x80
        bad = self.tmp / "bad-content.cguard"
        bad.write_bytes(data)
        with self.assertRaises(CryptoError):
            verify_container(bad, self.PASSWORD)

    def test_truncation_and_trailing_bytes_are_rejected_before_kdf(self) -> None:
        encrypted = self._make(payload=b"A" * 1000)
        raw = encrypted.read_bytes()
        for suffix, mutated in (("truncated", raw[:-1]), ("extra", raw + b"X")):
            bad = self.tmp / f"{suffix}.cguard"
            bad.write_bytes(mutated)
            with self.assertRaises(CryptoError):
                verify_container(bad, self.PASSWORD)

    def test_reordered_and_duplicated_chunks_are_rejected(self) -> None:
        payload = bytes(range(256)) * 768  # 196608 bytes = 3 chunks de 64 KiB
        encrypted = self._make(payload=payload)
        parsed = self._parsed(encrypted)
        self.assertEqual(parsed.chunk_count, 3)
        block_len = parsed.chunk_size + TAG_SIZE
        raw = bytearray(encrypted.read_bytes())
        start = parsed.content_offset
        c0 = bytes(raw[start:start + block_len])
        c1 = bytes(raw[start + block_len:start + 2 * block_len])

        swapped = bytearray(raw)
        swapped[start:start + block_len] = c1
        swapped[start + block_len:start + 2 * block_len] = c0
        swapped_path = self.tmp / "swapped.cguard"
        swapped_path.write_bytes(swapped)
        with self.assertRaises(CryptoError):
            verify_container(swapped_path, self.PASSWORD)

        duplicated = bytearray(raw)
        duplicated[start + block_len:start + 2 * block_len] = c0
        duplicated_path = self.tmp / "duplicated.cguard"
        duplicated_path.write_bytes(duplicated)
        with self.assertRaises(CryptoError):
            verify_container(duplicated_path, self.PASSWORD)

    def test_old_magic_is_explicitly_rejected(self) -> None:
        path = self.tmp / "old.cguard"
        path.write_bytes(OLD_MAGIC + struct.pack(">I", 2) + b"{}" + b"0" * 16)
        with self.assertRaisesRegex(CryptoError, "formato antigo"):
            verify_container(path, self.PASSWORD)

    def test_strict_header_rejects_extra_field_and_wrong_type(self) -> None:
        encrypted = self._make()
        parsed = self._parsed(encrypted)
        extra = dict(parsed.header)
        extra["future_magic"] = True
        raw = dumps_canonical(extra, label="test", max_size=16 * 1024)
        with self.assertRaisesRegex(CryptoError, "Schema inválido"):
            parse_header_bytes_for_creation(raw)

        wrong = json.loads(parsed.header_bytes.decode("utf-8"))
        wrong["chunk_size"] = True
        raw = dumps_canonical(wrong, label="test", max_size=16 * 1024)
        with self.assertRaises(CryptoError):
            parse_header_bytes_for_creation(raw)

    def test_strict_header_rejects_missing_nonfinite_inconsistent_and_absurd_values(self) -> None:
        encrypted = self._make(payload=b"A" * 1000)
        parsed = self._parsed(encrypted)

        missing = dict(parsed.header)
        del missing["cipher"]
        with self.assertRaises(CryptoError):
            parse_header_bytes_for_creation(dumps_canonical(missing, label="test", max_size=16 * 1024))

        inconsistent = dict(parsed.header)
        inconsistent["chunk_count"] = inconsistent["chunk_count"] + 1
        with self.assertRaisesRegex(CryptoError, "inconsistente"):
            parse_header_bytes_for_creation(dumps_canonical(inconsistent, label="test", max_size=16 * 1024))

        absurd_chunk = dict(parsed.header)
        absurd_chunk["chunk_size"] = 2**63
        with self.assertRaises(CryptoError):
            parse_header_bytes_for_creation(dumps_canonical(absurd_chunk, label="test", max_size=16 * 1024))

        absurd_kdf = json.loads(parsed.header_bytes.decode("utf-8"))
        absurd_kdf["kdf_params"]["memory_kib"] = 2**31
        with self.assertRaises(CryptoError):
            parse_header_bytes_for_creation(dumps_canonical(absurd_kdf, label="test", max_size=16 * 1024))

        with self.assertRaises(CryptoError):
            loads_strict(b'{"x":NaN}', label="Teste")
        with self.assertRaises(CryptoError):
            loads_strict(b'{"x":Infinity}', label="Teste")

    def test_strict_json_rejects_duplicate_keys(self) -> None:
        with self.assertRaises(CryptoError):
            loads_strict(b'{"version":4,"version":4}', label="Teste")


if __name__ == "__main__":
    unittest.main()
