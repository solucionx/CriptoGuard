from __future__ import annotations

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import (
    ARGON2_MAX_ITERATIONS,
    ARGON2_MAX_MEMORY_KIB,
    ARGON2_MAX_PARALLELISM,
    ARGON2_MIN_ITERATIONS,
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    CONTAINER_ID_SIZE,
    KEY_SIZE,
    SALT_SIZE,
)
from .errors import CryptoError
from .memory import wipe_buffer
from .strict_json import require_exact_keys, require_int

KDF_PARAM_KEYS = {"memory_kib", "iterations", "parallelism", "length"}


def validate_argon2_params(params: object) -> tuple[int, int, int, int]:
    if not isinstance(params, dict):
        raise CryptoError("Parâmetros Argon2id inválidos.")
    require_exact_keys(params, KDF_PARAM_KEYS, label="kdf_params")
    memory_kib = require_int(
        params["memory_kib"], label="Argon2id memory_kib",
        minimum=ARGON2_MIN_MEMORY_KIB, maximum=ARGON2_MAX_MEMORY_KIB,
    )
    iterations = require_int(
        params["iterations"], label="Argon2id iterations",
        minimum=ARGON2_MIN_ITERATIONS, maximum=ARGON2_MAX_ITERATIONS,
    )
    parallelism = require_int(
        params["parallelism"], label="Argon2id parallelism",
        minimum=ARGON2_MIN_PARALLELISM, maximum=ARGON2_MAX_PARALLELISM,
    )
    length = require_int(params["length"], label="Argon2id length", minimum=KEY_SIZE, maximum=KEY_SIZE)
    if memory_kib < 8 * parallelism:
        raise CryptoError("Parâmetros Argon2id inconsistentes.")
    return memory_kib, iterations, parallelism, length


def derive_keys(
    password: str,
    salt: bytes,
    container_id: bytes,
    *,
    memory_kib: int,
    iterations: int,
    parallelism: int,
) -> tuple[bytearray, bytearray]:
    if len(salt) != SALT_SIZE or len(container_id) != CONTAINER_ID_SIZE:
        raise CryptoError("Material de derivação inválido.")

    password_buffer = bytearray(password.encode("utf-8"))
    master = bytearray()
    expanded = bytearray()
    try:
        # hash_secret_raw exige bytes e pode manter cópias internas; o buffer
        # externo é zerado logo após o uso como mitigação best-effort.
        master_bytes = hash_secret_raw(
            secret=bytes(password_buffer),
            salt=salt,
            time_cost=iterations,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=KEY_SIZE,
            type=Type.ID,
            version=ARGON2_VERSION,
        )
        master = bytearray(master_bytes)
        del master_bytes

        expanded_bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE * 2,
            salt=container_id,
            info=b"CryptoGuard/v4/key-schedule",
        ).derive(bytes(master))
        expanded = bytearray(expanded_bytes)
        del expanded_bytes

        content_key = bytearray(expanded[:KEY_SIZE])
        metadata_key = bytearray(expanded[KEY_SIZE:])
        return content_key, metadata_key
    except (ValueError, MemoryError) as exc:
        raise CryptoError("Não foi possível derivar a chave Argon2id com os parâmetros do contêiner.") from exc
    finally:
        wipe_buffer(password_buffer)
        wipe_buffer(master)
        wipe_buffer(expanded)
