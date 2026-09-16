from __future__ import annotations

import io
import os
import random
import struct
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cryptoguard import CryptoError  # noqa: E402
from cryptoguard.constants import MAGIC, MAX_HEADER_SIZE  # noqa: E402
from cryptoguard.format_v4 import parse_header_bytes_for_creation, read_header  # noqa: E402


class ParserFuzzSmokeTests(unittest.TestCase):
    def test_random_headers_fail_closed_without_unexpected_exception(self) -> None:
        rng = random.Random(0xC6A4D)
        corpus = [b"", b"{}", b"[]", b"null", b"{", b"\xff\xfe"]
        for _ in range(250):
            size = rng.randint(0, 512)
            corpus.append(os.urandom(size))

        for raw in corpus:
            with self.subTest(size=len(raw)):
                try:
                    parse_header_bytes_for_creation(raw)
                except CryptoError:
                    pass
                except Exception as exc:  # qualquer outra exceção é bug de parser
                    self.fail(f"Parser lançou exceção inesperada {type(exc).__name__}: {exc}")
                else:
                    self.fail("Header aleatório foi aceito inesperadamente")

    def test_random_full_containers_fail_closed_without_unexpected_exception(self) -> None:
        rng = random.Random(0xC6A4D04)
        corpus = [
            b"",
            MAGIC,
            MAGIC + b"\x00\x00\x00\x00",
            MAGIC + struct.pack(">I", MAX_HEADER_SIZE + 1),
            MAGIC + struct.pack(">I", 2) + b"{}",
            MAGIC + struct.pack(">I", 1) + b"{",
        ]
        for _ in range(300):
            size = rng.randint(0, 2048)
            corpus.append(os.urandom(size))

        for raw in corpus:
            with self.subTest(size=len(raw)):
                try:
                    read_header(io.BytesIO(raw), len(raw))
                except CryptoError:
                    pass
                except Exception as exc:
                    self.fail(f"Parser físico lançou exceção inesperada {type(exc).__name__}: {exc}")
                else:
                    self.fail("Contêiner aleatório/malformado foi aceito inesperadamente")


if __name__ == "__main__":
    unittest.main()
