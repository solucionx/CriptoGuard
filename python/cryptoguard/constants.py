from __future__ import annotations

# Formato CGUARD v4. O magic é deliberadamente diferente do formato v1-v3.
MAGIC = b"CGUARD0040"
OLD_MAGIC = b"CGUARD0010"
OLD_LEGACY_MAGIC = b"SOLXCRYPT1"
VERSION = 4
EXTENSION = ".cguard"

CIPHER_NAME = "AES-256-GCM-CHUNKED"
KDF_NAME = "argon2id"
HKDF_NAME = "HKDF-SHA256"

SALT_SIZE = 16
CONTAINER_ID_SIZE = 16
META_NONCE_SIZE = 12
NONCE_PREFIX_SIZE = 4
KEY_SIZE = 32
TAG_SIZE = 16

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
MIN_CHUNK_SIZE = 64 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_CHUNKS = 10_000_000
MAX_PLAINTEXT_SIZE = (1 << 63) - 1

MAX_HEADER_SIZE = 16 * 1024
MAX_METADATA_PLAINTEXT_SIZE = 64 * 1024
MAX_METADATA_CIPHERTEXT_SIZE = MAX_METADATA_PLAINTEXT_SIZE + TAG_SIZE
MAX_ZIP_ENTRIES = 1_000_000

# Perfil v4 padrão. A leitura aceita somente uma faixa defensiva; a escrita usa
# exatamente estes valores. Isso permite evolução dentro da v4 sem aceitar
# parâmetros absurdos vindos de um arquivo hostil.
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1
ARGON2_MIN_MEMORY_KIB = 32 * 1024
ARGON2_MAX_MEMORY_KIB = 256 * 1024
ARGON2_MIN_ITERATIONS = 2
ARGON2_MAX_ITERATIONS = 10
ARGON2_MIN_PARALLELISM = 1
ARGON2_MAX_PARALLELISM = 8

PASSWORD_MIN_LENGTH = 12
# Modo extremo de remoção local. A sobrescrita é best-effort e não constitui
# garantia de eliminação física em SSD/NVMe, sistemas com snapshots, journaling,
# wear-leveling ou cópias sincronizadas.
DEFAULT_SHRED_PASSES = 2
ALLOWED_SHRED_PASSES = (1, 2, 3, 7)
SHRED_CHUNK_SIZE = 4 * 1024 * 1024

