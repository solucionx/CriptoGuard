from __future__ import annotations

# Maintainer utility. The generated files under tests/vectors are committed and
# tests assert their SHA-256. Do not regenerate them casually: changing a vector
# is a deliberate format-compatibility event.

import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cryptoguard.format_v4 import (  # noqa: E402
    build_header,
    build_metadata,
    chunk_aad,
    chunk_nonce,
    chunk_plaintext_length,
    metadata_aad,
    parse_header_bytes_for_creation,
)
from cryptoguard.kdf import derive_keys  # noqa: E402
from cryptoguard.memory import wipe_buffer  # noqa: E402
from cryptoguard.constants import MAGIC  # noqa: E402

PASSWORD = "CryptoGuard-Vector-Password!"
OUT = ROOT / "tests" / "vectors"
OUT.mkdir(parents=True, exist_ok=True)

CASES = [
    ("v4-empty.cguard", "empty.bin", b"", 0x11),
    ("v4-one-byte.cguard", "one-byte.bin", b"X", 0x22),
    ("v4-one-chunk.cguard", "one-chunk.txt", (b"Crypto Guard v4 vector\n" * 200), 0x33),
    ("v4-multi-chunk.cguard", "multi.bin", bytes(range(256)) * 600, 0x44),
]

manifest = {"format": "CGUARD v4", "password": PASSWORD, "vectors": []}
for filename, original_name, plaintext, marker in CASES:
    salt = bytes([marker]) * 16
    container_id = bytes([(marker + 1) & 0xFF]) * 16
    metadata_nonce = bytes([(marker + 2) & 0xFF]) * 12
    nonce_prefix = bytes([(marker + 3) & 0xFF]) * 4
    metadata_plain = build_metadata(kind="file", original_name=original_name)
    _header, header_bytes = build_header(
        salt=salt,
        container_id=container_id,
        metadata_nonce=metadata_nonce,
        nonce_prefix=nonce_prefix,
        plaintext_size=len(plaintext),
        metadata_ciphertext_size=len(metadata_plain) + 16,
        chunk_size=64 * 1024,
        memory_kib=32 * 1024,
        iterations=2,
        parallelism=1,
    )
    parsed = parse_header_bytes_for_creation(header_bytes)
    content_key, metadata_key = derive_keys(
        PASSWORD,
        parsed.salt,
        parsed.container_id,
        memory_kib=parsed.memory_kib,
        iterations=parsed.iterations,
        parallelism=parsed.parallelism,
    )
    try:
        body = bytearray()
        body += MAGIC
        body += struct.pack(">I", len(header_bytes))
        body += header_bytes
        body += AESGCM(bytes(metadata_key)).encrypt(parsed.metadata_nonce, metadata_plain, metadata_aad(parsed))
        aead = AESGCM(bytes(content_key))
        pos = 0
        for index in range(parsed.chunk_count):
            length = chunk_plaintext_length(parsed, index)
            chunk = plaintext[pos:pos + length]
            pos += length
            body += aead.encrypt(chunk_nonce(parsed, index), chunk, chunk_aad(parsed, index))
        path = OUT / filename
        path.write_bytes(body)
        manifest["vectors"].append({
            "file": filename,
            "original_name": original_name,
            "plaintext_size": len(plaintext),
            "chunk_count": parsed.chunk_count,
            "container_sha256": hashlib.sha256(body).hexdigest(),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        })
    finally:
        wipe_buffer(content_key)
        wipe_buffer(metadata_key)

(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps(manifest, indent=2, ensure_ascii=False))
