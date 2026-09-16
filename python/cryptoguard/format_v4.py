from __future__ import annotations

import base64
import binascii
import hashlib
import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Any

from .constants import (
    ARGON2_ITERATIONS,
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    CIPHER_NAME,
    CONTAINER_ID_SIZE,
    DEFAULT_CHUNK_SIZE,
    HKDF_NAME,
    KDF_NAME,
    KEY_SIZE,
    MAGIC,
    MAX_CHUNKS,
    MAX_HEADER_SIZE,
    MAX_METADATA_CIPHERTEXT_SIZE,
    MAX_METADATA_PLAINTEXT_SIZE,
    MAX_PLAINTEXT_SIZE,
    MAX_CHUNK_SIZE,
    META_NONCE_SIZE,
    MIN_CHUNK_SIZE,
    NONCE_PREFIX_SIZE,
    OLD_LEGACY_MAGIC,
    OLD_MAGIC,
    SALT_SIZE,
    TAG_SIZE,
    VERSION,
)
from .errors import CryptoError
from .kdf import validate_argon2_params
from .strict_json import dumps_canonical, loads_strict, require_exact_keys, require_int

HEADER_KEYS = {
    "version",
    "cipher",
    "kdf",
    "kdf_params",
    "hkdf",
    "salt",
    "container_id",
    "metadata_nonce",
    "nonce_prefix",
    "chunk_size",
    "chunk_count",
    "plaintext_size",
    "metadata_ciphertext_size",
}

METADATA_KEYS = {"kind", "original_name", "payload_format", "directory_size", "entry_count"}


@dataclass(frozen=True)
class ParsedHeader:
    header: dict[str, Any]
    header_bytes: bytes
    header_binding: bytes
    header_len: int
    payload_offset: int
    metadata_offset: int
    content_offset: int
    salt: bytes
    container_id: bytes
    metadata_nonce: bytes
    nonce_prefix: bytes
    memory_kib: int
    iterations: int
    parallelism: int
    chunk_size: int
    chunk_count: int
    plaintext_size: int
    metadata_ciphertext_size: int
    expected_file_size: int


@dataclass(frozen=True)
class ProtectedMetadata:
    kind: str
    original_name: str
    payload_format: str
    directory_size: int | None
    entry_count: int | None


def b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64decode_exact(value: object, expected_size: int, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise CryptoError(f"{label} deve ser Base64 textual.")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise CryptoError(f"{label} Base64 inválido.") from exc
    if len(raw) != expected_size:
        raise CryptoError(f"{label} possui tamanho inválido.")
    return raw


def _safe_original_name(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CryptoError("Nome original inválido nos metadados protegidos.")
    if len(value.encode("utf-8")) > 4096:
        raise CryptoError("Nome original excede o limite permitido.")
    if value in {".", ".."} or Path(value).name != value or any(sep in value for sep in ("/", "\\")):
        raise CryptoError("Nome original contém caminho inseguro.")
    return value


def expected_chunk_count(plaintext_size: int, chunk_size: int) -> int:
    if plaintext_size == 0:
        return 1
    return (plaintext_size + chunk_size - 1) // chunk_size


def build_metadata(
    *,
    kind: str,
    original_name: str,
    directory_size: int | None = None,
    entry_count: int | None = None,
) -> bytes:
    original_name = _safe_original_name(original_name)
    if kind == "file":
        if directory_size is not None or entry_count is not None:
            raise CryptoError("Metadados de arquivo inconsistentes.")
        value = {
            "kind": "file",
            "original_name": original_name,
            "payload_format": "raw",
            "directory_size": None,
            "entry_count": None,
        }
    elif kind == "directory":
        if type(directory_size) is not int or directory_size < 0:
            raise CryptoError("Tamanho lógico da pasta inválido.")
        if type(entry_count) is not int or entry_count < 0:
            raise CryptoError("Quantidade de itens da pasta inválida.")
        value = {
            "kind": "directory",
            "original_name": original_name,
            "payload_format": "zip-deflate",
            "directory_size": directory_size,
            "entry_count": entry_count,
        }
    else:
        raise CryptoError("Tipo de conteúdo inválido.")
    return dumps_canonical(value, label="metadados protegidos", max_size=MAX_METADATA_PLAINTEXT_SIZE)


def parse_metadata(raw: bytes) -> ProtectedMetadata:
    if not 0 < len(raw) <= MAX_METADATA_PLAINTEXT_SIZE:
        raise CryptoError("Metadados protegidos possuem tamanho inválido.")
    value = loads_strict(raw, label="Metadados protegidos")
    require_exact_keys(value, METADATA_KEYS, label="metadados protegidos")

    kind = value["kind"]
    original_name = _safe_original_name(value["original_name"])
    payload_format = value["payload_format"]
    if kind == "file":
        if payload_format != "raw" or value["directory_size"] is not None or value["entry_count"] is not None:
            raise CryptoError("Metadados protegidos de arquivo são inconsistentes.")
        return ProtectedMetadata("file", original_name, "raw", None, None)
    if kind == "directory":
        if payload_format != "zip-deflate":
            raise CryptoError("Formato interno de pasta não suportado.")
        directory_size = require_int(
            value["directory_size"], label="directory_size", minimum=0, maximum=MAX_PLAINTEXT_SIZE
        )
        entry_count = require_int(
            value["entry_count"], label="entry_count", minimum=0, maximum=1_000_000
        )
        return ProtectedMetadata("directory", original_name, "zip-deflate", directory_size, entry_count)
    raise CryptoError("Tipo de conteúdo desconhecido nos metadados protegidos.")


def build_header(
    *,
    salt: bytes,
    container_id: bytes,
    metadata_nonce: bytes,
    nonce_prefix: bytes,
    plaintext_size: int,
    metadata_ciphertext_size: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    memory_kib: int = ARGON2_MEMORY_KIB,
    iterations: int = ARGON2_ITERATIONS,
    parallelism: int = ARGON2_PARALLELISM,
) -> tuple[dict[str, Any], bytes]:
    if not 0 <= plaintext_size <= MAX_PLAINTEXT_SIZE:
        raise CryptoError("Tamanho do conteúdo fora dos limites do formato v4.")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise CryptoError("Tamanho de chunk fora dos limites do formato v4.")
    if metadata_ciphertext_size < TAG_SIZE or metadata_ciphertext_size > MAX_METADATA_CIPHERTEXT_SIZE:
        raise CryptoError("Tamanho dos metadados cifrados é inválido.")
    chunk_count = expected_chunk_count(plaintext_size, chunk_size)
    if chunk_count > MAX_CHUNKS:
        raise CryptoError("O conteúdo exigiria chunks demais para o formato configurado.")

    params = {
        "memory_kib": memory_kib,
        "iterations": iterations,
        "parallelism": parallelism,
        "length": KEY_SIZE,
    }
    validate_argon2_params(params)

    if len(salt) != SALT_SIZE or len(container_id) != CONTAINER_ID_SIZE:
        raise CryptoError("Salt/container_id inválido ao criar o cabeçalho.")
    if len(metadata_nonce) != META_NONCE_SIZE or len(nonce_prefix) != NONCE_PREFIX_SIZE:
        raise CryptoError("Nonce inválido ao criar o cabeçalho.")

    header: dict[str, Any] = {
        "version": VERSION,
        "cipher": CIPHER_NAME,
        "kdf": KDF_NAME,
        "kdf_params": params,
        "hkdf": HKDF_NAME,
        "salt": b64encode(salt),
        "container_id": b64encode(container_id),
        "metadata_nonce": b64encode(metadata_nonce),
        "nonce_prefix": b64encode(nonce_prefix),
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
        "plaintext_size": plaintext_size,
        "metadata_ciphertext_size": metadata_ciphertext_size,
    }
    raw = dumps_canonical(header, label="cabeçalho v4", max_size=MAX_HEADER_SIZE)
    return header, raw


def _validate_header_dict(header: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes, int, int, int, int, int, int, int]:
    require_exact_keys(header, HEADER_KEYS, label="cabeçalho v4")
    version = require_int(header["version"], label="version", minimum=VERSION, maximum=VERSION)
    if version != VERSION:
        raise CryptoError(f"Versão de contêiner não suportada: {version}")
    if header["cipher"] != CIPHER_NAME:
        raise CryptoError("Cipher do contêiner v4 não é suportado.")
    if header["kdf"] != KDF_NAME:
        raise CryptoError("KDF do contêiner v4 não é suportado.")
    if header["hkdf"] != HKDF_NAME:
        raise CryptoError("Expansão de chave do contêiner v4 não é suportada.")

    memory_kib, iterations, parallelism, _length = validate_argon2_params(header["kdf_params"])
    salt = b64decode_exact(header["salt"], SALT_SIZE, label="salt")
    container_id = b64decode_exact(header["container_id"], CONTAINER_ID_SIZE, label="container_id")
    metadata_nonce = b64decode_exact(header["metadata_nonce"], META_NONCE_SIZE, label="metadata_nonce")
    nonce_prefix = b64decode_exact(header["nonce_prefix"], NONCE_PREFIX_SIZE, label="nonce_prefix")

    chunk_size = require_int(
        header["chunk_size"], label="chunk_size", minimum=MIN_CHUNK_SIZE, maximum=MAX_CHUNK_SIZE
    )
    plaintext_size = require_int(
        header["plaintext_size"], label="plaintext_size", minimum=0, maximum=MAX_PLAINTEXT_SIZE
    )
    chunk_count = require_int(header["chunk_count"], label="chunk_count", minimum=1, maximum=MAX_CHUNKS)
    expected_count = expected_chunk_count(plaintext_size, chunk_size)
    if chunk_count != expected_count:
        raise CryptoError("chunk_count é inconsistente com plaintext_size/chunk_size.")
    metadata_ciphertext_size = require_int(
        header["metadata_ciphertext_size"],
        label="metadata_ciphertext_size",
        minimum=TAG_SIZE,
        maximum=MAX_METADATA_CIPHERTEXT_SIZE,
    )
    return (
        salt, container_id, metadata_nonce, nonce_prefix,
        memory_kib, iterations, parallelism,
        chunk_size, chunk_count, plaintext_size, metadata_ciphertext_size,
    )


def read_header(stream: BinaryIO, file_size: int) -> ParsedHeader:
    if file_size < len(MAGIC) + 4:
        raise CryptoError("Arquivo não é um contêiner CGUARD v4 válido.")
    magic = stream.read(len(MAGIC))
    if magic != MAGIC:
        if magic in {OLD_MAGIC, OLD_LEGACY_MAGIC}:
            raise CryptoError("Este arquivo usa um formato antigo do Crypto Guard. A v1.6 trabalha somente com CGUARD v4.")
        raise CryptoError("Arquivo não reconhecido como CGUARD v4.")

    raw_len = stream.read(4)
    if len(raw_len) != 4:
        raise CryptoError("Cabeçalho v4 truncado.")
    header_len = struct.unpack(">I", raw_len)[0]
    if not 0 < header_len <= MAX_HEADER_SIZE:
        raise CryptoError("Tamanho do cabeçalho v4 inválido.")
    header_bytes = stream.read(header_len)
    if len(header_bytes) != header_len:
        raise CryptoError("Cabeçalho v4 truncado.")

    header = loads_strict(header_bytes, label="Cabeçalho v4")
    (
        salt, container_id, metadata_nonce, nonce_prefix,
        memory_kib, iterations, parallelism,
        chunk_size, chunk_count, plaintext_size, metadata_ciphertext_size,
    ) = _validate_header_dict(header)

    prefix_len = len(MAGIC) + 4 + header_len
    metadata_offset = prefix_len
    content_offset = metadata_offset + metadata_ciphertext_size
    content_ciphertext_size = plaintext_size + (chunk_count * TAG_SIZE)
    expected_file_size = content_offset + content_ciphertext_size
    if expected_file_size != file_size:
        if expected_file_size > file_size:
            raise CryptoError("Contêiner v4 truncado ou com tamanhos inconsistentes.")
        raise CryptoError("Contêiner v4 contém bytes extras ou tamanhos inconsistentes.")

    binding = hashlib.sha256(MAGIC + raw_len + header_bytes).digest()
    return ParsedHeader(
        header=header,
        header_bytes=header_bytes,
        header_binding=binding,
        header_len=header_len,
        payload_offset=prefix_len,
        metadata_offset=metadata_offset,
        content_offset=content_offset,
        salt=salt,
        container_id=container_id,
        metadata_nonce=metadata_nonce,
        nonce_prefix=nonce_prefix,
        memory_kib=memory_kib,
        iterations=iterations,
        parallelism=parallelism,
        chunk_size=chunk_size,
        chunk_count=chunk_count,
        plaintext_size=plaintext_size,
        metadata_ciphertext_size=metadata_ciphertext_size,
        expected_file_size=expected_file_size,
    )


def metadata_aad(parsed: ParsedHeader) -> bytes:
    return b"CGUARD/v4/metadata\x00" + parsed.container_id + parsed.header_binding


def chunk_aad(parsed: ParsedHeader, index: int) -> bytes:
    if not 0 <= index < parsed.chunk_count:
        raise CryptoError("Índice de chunk inválido.")
    return (
        b"CGUARD/v4/chunk\x00"
        + parsed.container_id
        + parsed.header_binding
        + struct.pack(">Q", index)
        + struct.pack(">Q", parsed.chunk_count)
        + struct.pack(">Q", parsed.plaintext_size)
    )


def chunk_nonce(parsed: ParsedHeader, index: int) -> bytes:
    if not 0 <= index < parsed.chunk_count:
        raise CryptoError("Índice de chunk inválido.")
    return parsed.nonce_prefix + struct.pack(">Q", index)


def chunk_plaintext_length(parsed: ParsedHeader, index: int) -> int:
    if not 0 <= index < parsed.chunk_count:
        raise CryptoError("Índice de chunk inválido.")
    if parsed.plaintext_size == 0:
        return 0
    if index < parsed.chunk_count - 1:
        return parsed.chunk_size
    used = parsed.chunk_size * (parsed.chunk_count - 1)
    return parsed.plaintext_size - used


def parse_header_bytes_for_creation(header_bytes: bytes) -> ParsedHeader:
    """Valida o cabeçalho recém-criado usando exatamente as regras do parser.

    É usado pela escrita para evitar que o caminho de criação e o caminho de
    leitura evoluam de forma divergente.
    """
    if not 0 < len(header_bytes) <= MAX_HEADER_SIZE:
        raise CryptoError("Tamanho do cabeçalho v4 inválido.")
    header = loads_strict(header_bytes, label="Cabeçalho v4")
    (
        salt, container_id, metadata_nonce, nonce_prefix,
        memory_kib, iterations, parallelism,
        chunk_size, chunk_count, plaintext_size, metadata_ciphertext_size,
    ) = _validate_header_dict(header)
    raw_len = struct.pack(">I", len(header_bytes))
    prefix_len = len(MAGIC) + 4 + len(header_bytes)
    metadata_offset = prefix_len
    content_offset = metadata_offset + metadata_ciphertext_size
    expected_file_size = content_offset + plaintext_size + (chunk_count * TAG_SIZE)
    binding = hashlib.sha256(MAGIC + raw_len + header_bytes).digest()
    return ParsedHeader(
        header=header,
        header_bytes=header_bytes,
        header_binding=binding,
        header_len=len(header_bytes),
        payload_offset=prefix_len,
        metadata_offset=metadata_offset,
        content_offset=content_offset,
        salt=salt,
        container_id=container_id,
        metadata_nonce=metadata_nonce,
        nonce_prefix=nonce_prefix,
        memory_kib=memory_kib,
        iterations=iterations,
        parallelism=parallelism,
        chunk_size=chunk_size,
        chunk_count=chunk_count,
        plaintext_size=plaintext_size,
        metadata_ciphertext_size=metadata_ciphertext_size,
        expected_file_size=expected_file_size,
    )
