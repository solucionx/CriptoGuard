from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import (
    ARGON2_ITERATIONS,
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    CONTAINER_ID_SIZE,
    DEFAULT_CHUNK_SIZE,
    MAGIC,
    MAX_PLAINTEXT_SIZE,
    META_NONCE_SIZE,
    NONCE_PREFIX_SIZE,
    SALT_SIZE,
    TAG_SIZE,
)
from .errors import CryptoError
from .format_v4 import (
    ParsedHeader,
    ProtectedMetadata,
    build_header,
    chunk_aad,
    chunk_nonce,
    chunk_plaintext_length,
    metadata_aad,
    parse_header_bytes_for_creation,
    parse_metadata,
    read_header,
)
from .io_utils import make_temp_file
from .kdf import derive_keys
from .memory import wipe_buffer

ProgressCallback = Callable[[int, int, str], None]


def _progress(callback: ProgressCallback | None, processed: int, total: int, stage: str) -> None:
    if callback is not None:
        callback(processed, total, stage)


def _derive_for_parsed(password: str, parsed: ParsedHeader) -> tuple[bytearray, bytearray]:
    _progress(None, 0, 0, "kdf")
    return derive_keys(
        password,
        parsed.salt,
        parsed.container_id,
        memory_kib=parsed.memory_kib,
        iterations=parsed.iterations,
        parallelism=parsed.parallelism,
    )


def create_container_temp(
    plaintext_path: Path,
    output: Path,
    password: str,
    metadata_plaintext: bytes,
    *,
    progress_callback: ProgressCallback | None = None,
) -> tuple[Path, str, ParsedHeader]:
    plaintext_size = plaintext_path.stat().st_size
    if plaintext_size < 0 or plaintext_size > MAX_PLAINTEXT_SIZE:
        raise CryptoError("Conteúdo excede o limite do formato CGUARD v4.")

    salt = os.urandom(SALT_SIZE)
    container_id = os.urandom(CONTAINER_ID_SIZE)
    metadata_nonce = os.urandom(META_NONCE_SIZE)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    metadata_ciphertext_size = len(metadata_plaintext) + TAG_SIZE

    _header, header_bytes = build_header(
        salt=salt,
        container_id=container_id,
        metadata_nonce=metadata_nonce,
        nonce_prefix=nonce_prefix,
        plaintext_size=plaintext_size,
        metadata_ciphertext_size=metadata_ciphertext_size,
        chunk_size=DEFAULT_CHUNK_SIZE,
        memory_kib=ARGON2_MEMORY_KIB,
        iterations=ARGON2_ITERATIONS,
        parallelism=ARGON2_PARALLELISM,
    )
    parsed = parse_header_bytes_for_creation(header_bytes)

    _progress(progress_callback, 0, 0, "kdf")
    content_key, metadata_key = derive_keys(
        password,
        parsed.salt,
        parsed.container_id,
        memory_kib=parsed.memory_kib,
        iterations=parsed.iterations,
        parallelism=parsed.parallelism,
    )

    fd, temp_output = make_temp_file(output.parent, f".{output.name}.v4-", ".tmp")
    digest = hashlib.sha256()
    processed = 0
    try:
        metadata_cipher = AESGCM(bytes(metadata_key)).encrypt(
            parsed.metadata_nonce,
            metadata_plaintext,
            metadata_aad(parsed),
        )
        if len(metadata_cipher) != parsed.metadata_ciphertext_size:
            raise CryptoError("Tamanho dos metadados cifrados ficou inconsistente.")

        content_aead = AESGCM(bytes(content_key))
        with os.fdopen(fd, "wb") as dst, plaintext_path.open("rb") as src:
            dst.write(MAGIC)
            dst.write(struct.pack(">I", parsed.header_len))
            dst.write(parsed.header_bytes)
            dst.write(metadata_cipher)

            for index in range(parsed.chunk_count):
                expected_plain = chunk_plaintext_length(parsed, index)
                chunk = src.read(expected_plain) if expected_plain else b""
                if len(chunk) != expected_plain:
                    raise CryptoError("O conteúdo de origem mudou ou foi truncado durante a criptografia.")
                digest.update(chunk)
                encrypted_chunk = content_aead.encrypt(
                    chunk_nonce(parsed, index),
                    chunk,
                    chunk_aad(parsed, index),
                )
                if len(encrypted_chunk) != expected_plain + TAG_SIZE:
                    raise CryptoError("Tamanho de chunk cifrado inesperado.")
                dst.write(encrypted_chunk)
                processed += expected_plain
                _progress(progress_callback, processed, parsed.plaintext_size, "encrypt")

            if src.read(1):
                raise CryptoError("O conteúdo de origem mudou de tamanho durante a criptografia.")
            dst.flush()
            os.fsync(dst.fileno())

        actual_size = temp_output.stat().st_size
        if actual_size != parsed.expected_file_size:
            raise CryptoError("O contêiner escrito possui tamanho inconsistente.")
        _progress(progress_callback, parsed.plaintext_size, parsed.plaintext_size, "encrypt")
        return temp_output, digest.hexdigest(), parsed
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temp_output.unlink(missing_ok=True)
        raise
    finally:
        wipe_buffer(content_key)
        wipe_buffer(metadata_key)


def _decrypt_metadata(src, parsed: ParsedHeader, metadata_key: bytearray) -> tuple[ProtectedMetadata, bytes]:
    src.seek(parsed.metadata_offset)
    metadata_cipher = src.read(parsed.metadata_ciphertext_size)
    if len(metadata_cipher) != parsed.metadata_ciphertext_size:
        raise CryptoError("Metadados protegidos truncados.")
    try:
        metadata_plain = AESGCM(bytes(metadata_key)).decrypt(
            parsed.metadata_nonce,
            metadata_cipher,
            metadata_aad(parsed),
        )
    except InvalidTag as exc:
        raise CryptoError("Senha incorreta ou cabeçalho/metadados do contêiner foram alterados.") from exc
    metadata = parse_metadata(metadata_plain)
    return metadata, metadata_plain


def verify_container(
    encrypted: Path,
    password: str,
    *,
    expected_digest: str | None = None,
    expected_metadata: bytes | None = None,
    expected_plaintext_path: Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> tuple[ProtectedMetadata, str]:
    file_size = encrypted.stat().st_size
    with encrypted.open("rb") as src:
        parsed = read_header(src, file_size)
        _progress(progress_callback, 0, 0, "kdf")
        content_key, metadata_key = _derive_for_parsed(password, parsed)
        try:
            metadata, metadata_plain = _decrypt_metadata(src, parsed, metadata_key)
            if expected_metadata is not None and metadata_plain != expected_metadata:
                raise CryptoError("Metadados do contêiner recém-criado não correspondem à origem.")

            content_aead = AESGCM(bytes(content_key))
            src.seek(parsed.content_offset)
            digest = hashlib.sha256()
            restored = 0
            expected_src = None
            if expected_plaintext_path is not None:
                try:
                    expected_src = expected_plaintext_path.open("rb")
                except OSError as exc:
                    raise CryptoError("Não foi possível reabrir a origem para a verificação byte a byte.") from exc

            try:
                for index in range(parsed.chunk_count):
                    plain_len = chunk_plaintext_length(parsed, index)
                    cipher_len = plain_len + TAG_SIZE
                    encrypted_chunk = src.read(cipher_len)
                    if len(encrypted_chunk) != cipher_len:
                        raise CryptoError("Contêiner truncado durante a verificação.")
                    try:
                        plain = content_aead.decrypt(
                            chunk_nonce(parsed, index),
                            encrypted_chunk,
                            chunk_aad(parsed, index),
                        )
                    except InvalidTag as exc:
                        raise CryptoError("Falha de autenticação em um chunk do contêiner.") from exc
                    if len(plain) != plain_len:
                        raise CryptoError("Chunk restaurado possui tamanho inconsistente.")

                    # Na criação, a validação não depende apenas de um hash: cada
                    # bloco restaurado é comparado diretamente aos bytes da origem.
                    if expected_src is not None:
                        expected_plain = expected_src.read(plain_len) if plain_len else b""
                        if expected_plain != plain:
                            raise CryptoError("Round-trip do contêiner não corresponde byte a byte à origem.")

                    digest.update(plain)
                    restored += len(plain)
                    _progress(progress_callback, restored, parsed.plaintext_size, "verify")

                if expected_src is not None and expected_src.read(1):
                    raise CryptoError("A origem mudou de tamanho durante a verificação byte a byte.")
            finally:
                if expected_src is not None:
                    expected_src.close()

            if restored != parsed.plaintext_size or src.read(1):
                raise CryptoError("Contêiner possui truncamento ou bytes extras.")
            result_digest = digest.hexdigest()
            if expected_digest is not None and result_digest != expected_digest:
                raise CryptoError("Hash do round-trip não corresponde à origem.")
            _progress(progress_callback, parsed.plaintext_size, parsed.plaintext_size, "verify")
            return metadata, result_digest
        finally:
            wipe_buffer(content_key)
            wipe_buffer(metadata_key)


def decrypt_container_to_temp(
    encrypted: Path,
    password: str,
    *,
    progress_callback: ProgressCallback | None = None,
) -> tuple[ProtectedMetadata, Path, str]:
    file_size = encrypted.stat().st_size
    with encrypted.open("rb") as src:
        parsed = read_header(src, file_size)
        _progress(progress_callback, 0, 0, "kdf")
        content_key, metadata_key = _derive_for_parsed(password, parsed)
        temp_payload: Path | None = None
        fd: int | None = None
        try:
            metadata, _metadata_plain = _decrypt_metadata(src, parsed, metadata_key)
            destination = encrypted.parent / metadata.original_name
            if destination.exists():
                raise CryptoError(f"Já existe um item com o nome original: {destination}")

            fd, temp_payload = make_temp_file(
                encrypted.parent,
                f".{metadata.original_name}.cguard-v4-",
                ".tmp",
            )
            content_aead = AESGCM(bytes(content_key))
            src.seek(parsed.content_offset)
            digest = hashlib.sha256()
            restored = 0

            with os.fdopen(fd, "wb") as dst:
                fd = None
                for index in range(parsed.chunk_count):
                    plain_len = chunk_plaintext_length(parsed, index)
                    cipher_len = plain_len + TAG_SIZE
                    encrypted_chunk = src.read(cipher_len)
                    if len(encrypted_chunk) != cipher_len:
                        raise CryptoError("Contêiner truncado durante a restauração.")
                    try:
                        plain = content_aead.decrypt(
                            chunk_nonce(parsed, index),
                            encrypted_chunk,
                            chunk_aad(parsed, index),
                        )
                    except InvalidTag as exc:
                        raise CryptoError("Senha incorreta ou contêiner alterado/corrompido.") from exc
                    if len(plain) != plain_len:
                        raise CryptoError("Chunk restaurado possui tamanho inconsistente.")
                    if plain:
                        dst.write(plain)
                        digest.update(plain)
                    restored += len(plain)
                    _progress(progress_callback, restored, parsed.plaintext_size, "decrypt")

                if restored != parsed.plaintext_size or src.read(1):
                    raise CryptoError("Contêiner possui truncamento ou bytes extras.")
                dst.flush()
                os.fsync(dst.fileno())

            _progress(progress_callback, parsed.plaintext_size, parsed.plaintext_size, "decrypt")
            return metadata, temp_payload, digest.hexdigest()
        except BaseException:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if temp_payload is not None:
                temp_payload.unlink(missing_ok=True)
            raise
        finally:
            wipe_buffer(content_key)
            wipe_buffer(metadata_key)
