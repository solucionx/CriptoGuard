from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import shutil
import stat
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CGUARD0010"
LEGACY_MAGIC = b"SOLXCRYPT1"
VERSION = 3
EXTENSION = ".cguard"
LEGACY_EXTENSION = ".sxcrypt"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
MAX_HEADER_SIZE = 64 * 1024

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
MIN_SCRYPT_N = 2**14
MAX_SCRYPT_N = 2**18
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 4
MAX_SCRYPT_MEMORY = 512 * 1024 * 1024
MAX_ZIP_ENTRIES = 1_000_000

INPLACE_MAX_SIZE = 256 * 1024 * 1024
DEFAULT_SHRED_PASSES = 2
MAX_SHRED_PASSES = 7

ProgressCallback = Callable[[int, int, str], None]


class CryptoError(Exception):
    pass


class CryptoCancelled(CryptoError):
    """Operação interrompida de forma cooperativa e segura."""
    pass


def _progress(callback: ProgressCallback | None, processed: int, total: int, stage: str) -> None:
    if callback is not None:
        callback(processed, total, stage)


def _validate_password(password: str, *, for_encryption: bool = False) -> None:
    if not isinstance(password, str) or not password:
        raise CryptoError("A senha não pode ficar vazia.")
    if for_encryption and len(password) < 8:
        raise CryptoError("Use uma senha com pelo menos 8 caracteres; 12 ou mais é recomendado.")


def _validate_scrypt_params(n: int, r: int, p: int) -> tuple[int, int, int]:
    try:
        n, r, p = int(n), int(r), int(p)
    except (TypeError, ValueError) as exc:
        raise CryptoError("Parâmetros Scrypt inválidos.") from exc

    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or n & (n - 1):
        raise CryptoError("Parâmetro Scrypt N fora dos limites permitidos.")
    if not 1 <= r <= MAX_SCRYPT_R:
        raise CryptoError("Parâmetro Scrypt r fora dos limites permitidos.")
    if not 1 <= p <= MAX_SCRYPT_P:
        raise CryptoError("Parâmetro Scrypt p fora dos limites permitidos.")
    estimated_memory = 128 * n * r
    if estimated_memory > MAX_SCRYPT_MEMORY:
        raise CryptoError("Parâmetros Scrypt exigem memória excessiva e foram recusados.")
    if n * r * p > (2**20) * 8:
        raise CryptoError("Parâmetros Scrypt exigem processamento excessivo e foram recusados.")
    return n, r, p


def _derive_key(password: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    n, r, p = _validate_scrypt_params(n, r, p)
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def _b64decode_exact(value: object, expected_size: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise CryptoError(f"{label} inválido no cabeçalho.")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise CryptoError(f"{label} inválido no cabeçalho.") from exc
    if len(raw) != expected_size:
        raise CryptoError(f"{label} possui tamanho inválido.")
    return raw


def _safe_original_name(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CryptoError("Nome original inválido no contêiner.")
    if value in {".", ".."} or Path(value).name != value:
        raise CryptoError("Nome original contém caminho inseguro.")
    if any(sep in value for sep in ("/", "\\")):
        raise CryptoError("Nome original contém separadores de caminho inseguros.")
    return value


def _encode_header(header: dict) -> bytes:
    header_bytes = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not 0 < len(header_bytes) <= MAX_HEADER_SIZE:
        raise CryptoError("Cabeçalho criptográfico excede o tamanho permitido.")
    return header_bytes


def _read_header(stream: BinaryIO, file_size: int) -> tuple[dict, bytes, int]:
    prefix = stream.read(len(MAGIC) + 4)
    if len(prefix) != len(MAGIC) + 4 or prefix[:len(MAGIC)] not in {MAGIC, LEGACY_MAGIC}:
        raise CryptoError("Arquivo não reconhecido como um contêiner Crypto Guard válido.")

    header_len = struct.unpack(">I", prefix[len(MAGIC):])[0]
    if not 0 < header_len <= MAX_HEADER_SIZE:
        raise CryptoError("Cabeçalho criptográfico possui tamanho inválido.")

    header_bytes = stream.read(header_len)
    if len(header_bytes) != header_len:
        raise CryptoError("Cabeçalho criptográfico truncado.")
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoError("Cabeçalho criptográfico corrompido.") from exc
    if not isinstance(header, dict):
        raise CryptoError("Cabeçalho criptográfico inválido.")

    payload_offset = len(MAGIC) + 4 + header_len
    if file_size < payload_offset + TAG_SIZE:
        raise CryptoError("Contêiner truncado ou sem tag de autenticação.")
    return header, header_bytes, payload_offset


def _header_crypto_fields(header: dict) -> tuple[int, bytes, bytes, int, int, int, str, str]:
    try:
        version = int(header.get("version", 1))
        if version not in {1, 2, 3}:
            raise CryptoError(f"Versão de contêiner não suportada: {version}")
        if header.get("cipher") != "AES-256-GCM" or header.get("kdf") != "scrypt":
            raise CryptoError("Algoritmo criptográfico não suportado.")
        params = header["kdf_params"]
        if not isinstance(params, dict):
            raise CryptoError("Parâmetros KDF inválidos.")
        n, r, p = _validate_scrypt_params(params.get("n"), params.get("r"), params.get("p"))
        salt = _b64decode_exact(header.get("salt"), SALT_SIZE, "Salt")
        nonce = _b64decode_exact(header.get("nonce"), NONCE_SIZE, "Nonce")
        kind = header.get("kind")
        if kind not in {"file", "directory"}:
            raise CryptoError("Tipo de conteúdo desconhecido no contêiner.")
        original_name = _safe_original_name(header.get("original_name"))
        return version, salt, nonce, n, r, p, kind, original_name
    except KeyError as exc:
        raise CryptoError("Metadados criptográficos incompletos.") from exc


def _make_temp_file(parent: Path, prefix: str, suffix: str = ".tmp") -> tuple[int, Path]:
    parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=str(parent))
    return fd, Path(name)


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _atomic_replace(temp_path: Path, destination: Path) -> None:
    os.replace(temp_path, destination)
    _fsync_directory(destination.parent)


def _shred_fd(fd: int, size: int, passes: int) -> None:
    """Sobrescreve o conteúdo de um descritor de arquivo aberto com dados
    aleatórios, `passes` vezes, sincronizando o disco a cada passada."""
    if size <= 0 or passes <= 0:
        return
    for _ in range(passes):
        os.lseek(fd, 0, os.SEEK_SET)
        remaining = size
        while remaining > 0:
            chunk = min(CHUNK_SIZE, remaining)
            os.write(fd, os.urandom(chunk))
            remaining -= chunk
        os.fsync(fd)
    os.lseek(fd, 0, os.SEEK_SET)


def _shred_and_unlink_file(path: Path, passes: int) -> None:
    """Sobrescreve o conteúdo do arquivo com dados aleatórios embaralhados
    antes de remover a entrada dele do sistema de arquivos. Isso reduz (mas,
    especialmente em SSDs com wear-leveling, não elimina totalmente) a chance
    de recuperação por ferramentas de undelete/forense."""
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if size > 0:
        try:
            fd = os.open(str(path), os.O_WRONLY)
            try:
                _shred_fd(fd, size, passes)
            finally:
                os.close(fd)
        except OSError:
            pass  # melhor esforço: mesmo se a sobrescrita falhar, ainda removemos a entrada
    path.unlink(missing_ok=True)


def shred_and_delete(path: Path, *, passes: int = DEFAULT_SHRED_PASSES) -> None:
    """Remove um arquivo ou pasta de forma segura: cada arquivo tem seu
    conteúdo sobrescrito com dados aleatórios antes de ser apagado."""
    path = path.expanduser()
    if path.is_dir() and not path.is_symlink():
        for item in path.rglob("*"):
            if item.is_symlink():
                continue
            if item.is_file():
                _shred_and_unlink_file(item, passes)
        shutil.rmtree(path, ignore_errors=True)
    else:
        _shred_and_unlink_file(path, passes)
    _fsync_directory(path.parent)


def _zip_directory(
    source: Path,
    zip_path: Path,
    *,
    progress_callback: ProgressCallback | None = None,
) -> tuple[int, int]:
    logical_size = 0
    entry_count = 0
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for item in source.rglob("*"):
            if item.is_symlink():
                raise CryptoError(f"Link simbólico não é suportado por segurança: {item}")
            relative = item.relative_to(source)
            if item.is_file():
                item_size = item.stat().st_size
                logical_size += item_size
                entry_count += 1
                zf.write(item, relative)
                # total=0 sinaliza uma etapa cujo total ainda não é conhecido;
                # além de informar a UI, isso cria pontos seguros de cancelamento.
                _progress(progress_callback, logical_size, 0, "pack")
            elif item.is_dir() and not any(item.iterdir()):
                entry_count += 1
                info = zipfile.ZipInfo(str(relative).replace(os.sep, "/") + "/")
                zf.writestr(info, b"")
                _progress(progress_callback, logical_size, 0, "pack")
    return logical_size, entry_count


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _validate_zip(
    zf: zipfile.ZipFile,
    destination: Path,
    *,
    expected_size: int | None,
    expected_entries: int | None,
) -> tuple[list[zipfile.ZipInfo], int]:
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise CryptoError("Pasta criptografada contém itens demais para extração segura.")
    if expected_entries is not None and len(infos) != expected_entries:
        raise CryptoError("Quantidade de itens da pasta não corresponde aos metadados autenticados.")

    base = destination.resolve()
    total_size = 0
    for info in infos:
        if _is_zip_symlink(info):
            raise CryptoError(f"Link simbólico interno não é permitido: {info.filename}")
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or "\x00" in name:
            raise CryptoError("Arquivo compactado contém caminho inseguro.")
        parts = [part for part in name.split("/") if part not in {"", "."}]
        if any(part == ".." for part in parts):
            raise CryptoError("Arquivo compactado contém tentativa de sair da pasta de destino.")
        target = (destination / Path(*parts)).resolve()
        try:
            common = os.path.commonpath([str(base), str(target)])
        except ValueError as exc:
            raise CryptoError("Arquivo compactado contém caminho inválido.") from exc
        if common != str(base):
            raise CryptoError("Arquivo compactado contém caminho inseguro.")
        if not info.is_dir():
            if info.file_size < 0:
                raise CryptoError("Arquivo compactado contém tamanho inválido.")
            total_size += info.file_size

    if expected_size is not None and total_size != expected_size:
        raise CryptoError("Tamanho restaurado da pasta não corresponde aos metadados autenticados.")
    return infos, total_size


def _safe_extract(
    zf: zipfile.ZipFile,
    destination: Path,
    *,
    expected_size: int | None,
    expected_entries: int | None,
    progress_callback: ProgressCallback | None = None,
) -> None:
    infos, total_size = _validate_zip(
        zf, destination, expected_size=expected_size, expected_entries=expected_entries
    )
    processed = 0
    for info in infos:
        name = info.filename.replace("\\", "/")
        parts = [part for part in name.split("/") if part not in {"", "."}]
        target = destination / Path(*parts)
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            _progress(progress_callback, processed, total_size, "extract")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info, "r") as src, target.open("wb") as dst:
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(chunk)
                processed += len(chunk)
                _progress(progress_callback, processed, total_size, "extract")
        try:
            os.chmod(target, (info.external_attr >> 16) & 0o777)
        except OSError:
            pass
    _progress(progress_callback, total_size, total_size, "extract")

def _inplace_encrypt_file(
    source: Path,
    header_bytes: bytes,
    key: bytes,
    nonce: bytes,
    *,
    shred_passes: int,
    progress_callback: ProgressCallback | None = None,
) -> tuple[str, int, Path]:
    """Criptografa um arquivo reescrevendo-o no próprio lugar: nenhuma cópia
    separada é criada em nenhum momento. Antes de gravar o texto cifrado, o
    conteúdo original é sobrescrito `shred_passes` vezes com dados aleatórios.

    ATENÇÃO: se o processo for interrompido no meio (queda de energia, erro,
    encerramento forçado), o arquivo pode ficar corrompido e IRRECUPERÁVEL —
    não existe um original de backup como no modo padrão."""
    size = source.stat().st_size
    if size > INPLACE_MAX_SIZE:
        raise CryptoError(
            "Arquivo excede o limite do modo em-loco "
            f"({INPLACE_MAX_SIZE // (1024 * 1024)} MB). Use o modo padrão para este arquivo."
        )

    with source.open("rb") as f:
        plaintext = f.read()
    if len(plaintext) != size:
        raise CryptoError("Falha ao ler o conteúdo completo do arquivo original.")

    digest = hashlib.sha256(plaintext).hexdigest()
    _progress(progress_callback, 0, size, "shred")

    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, header_bytes)
    del plaintext

    output = source.with_name(source.name + EXTENSION)
    fd = os.open(str(source), os.O_RDWR)
    try:
        _shred_fd(fd, size, shred_passes)
        _progress(progress_callback, size // 2, size, "encrypt")

        payload = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext_and_tag
        os.lseek(fd, 0, os.SEEK_SET)
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:written + CHUNK_SIZE])
        os.ftruncate(fd, len(payload))
        os.fsync(fd)
    finally:
        os.close(fd)

    os.replace(source, output)
    _fsync_directory(source.parent)
    _progress(progress_callback, size, size, "encrypt")
    return digest, size, output


def _stream_encrypt_file(
    plaintext_path: Path,
    output: Path,
    header_bytes: bytes,
    key: bytes,
    nonce: bytes,
    *,
    progress_callback: ProgressCallback | None = None,
) -> tuple[str, int]:
    total = plaintext_path.stat().st_size
    fd, temp_output = _make_temp_file(output.parent, f".{output.name}.cguard-", ".tmp")
    digest = hashlib.sha256()
    processed = 0
    try:
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(header_bytes)
        with os.fdopen(fd, "wb") as dst, plaintext_path.open("rb") as src:
            dst.write(MAGIC)
            dst.write(struct.pack(">I", len(header_bytes)))
            dst.write(header_bytes)
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                dst.write(encryptor.update(chunk))
                processed += len(chunk)
                _progress(progress_callback, processed, total, "encrypt")
            dst.write(encryptor.finalize())
            dst.write(encryptor.tag)
            dst.flush()
            os.fsync(dst.fileno())
        _atomic_replace(temp_output, output)
        _progress(progress_callback, total, total, "encrypt")
        return digest.hexdigest(), total
    except BaseException:
        temp_output.unlink(missing_ok=True)
        raise


def _stream_decrypt_to_file(
    encrypted: Path,
    password: str,
    output_path: Path,
    *,
    progress_callback: ProgressCallback | None = None,
    atomic: bool = True,
) -> tuple[dict, str, int]:
    file_size = encrypted.stat().st_size
    with encrypted.open("rb") as src:
        header, header_bytes, payload_offset = _read_header(src, file_size)
        _version, salt, nonce, n, r, p, _kind, _original_name = _header_crypto_fields(header)
        key = _derive_key(password, salt, n=n, r=r, p=p)
        ciphertext_len = file_size - payload_offset - TAG_SIZE
        src.seek(file_size - TAG_SIZE)
        tag = src.read(TAG_SIZE)
        if len(tag) != TAG_SIZE:
            raise CryptoError("Tag de autenticação ausente.")
        src.seek(payload_offset)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header_bytes)
        digest = hashlib.sha256()
        processed = 0

        if atomic:
            fd, temp_output = _make_temp_file(output_path.parent, f".{output_path.name}.cguard-", ".tmp")
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(output_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            temp_output = output_path

        try:
            with os.fdopen(fd, "wb") as dst:
                remaining = ciphertext_len
                while remaining:
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise CryptoError("Contêiner truncado durante a leitura.")
                    remaining -= len(chunk)
                    plain = decryptor.update(chunk)
                    if plain:
                        digest.update(plain)
                        dst.write(plain)
                    processed += len(chunk)
                    _progress(progress_callback, processed, ciphertext_len, "decrypt")
                try:
                    tail = decryptor.finalize()
                except InvalidTag as exc:
                    raise CryptoError("Senha incorreta ou arquivo criptografado foi alterado/corrompido.") from exc
                if tail:
                    digest.update(tail)
                    dst.write(tail)
                dst.flush()
                os.fsync(dst.fileno())
            if atomic:
                _atomic_replace(temp_output, output_path)
            _progress(progress_callback, ciphertext_len, ciphertext_len, "decrypt")
            return header, digest.hexdigest(), output_path.stat().st_size
        except BaseException:
            temp_output.unlink(missing_ok=True)
            raise


def _verify_container(
    encrypted: Path,
    password: str,
    expected_digest: str,
    expected_size: int,
    *,
    progress_callback: ProgressCallback | None = None,
) -> None:
    file_size = encrypted.stat().st_size
    with encrypted.open("rb") as src:
        header, header_bytes, payload_offset = _read_header(src, file_size)
        _version, salt, nonce, n, r, p, _kind, _original_name = _header_crypto_fields(header)
        key = _derive_key(password, salt, n=n, r=r, p=p)
        ciphertext_len = file_size - payload_offset - TAG_SIZE
        src.seek(file_size - TAG_SIZE)
        tag = src.read(TAG_SIZE)
        src.seek(payload_offset)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header_bytes)
        digest = hashlib.sha256()
        restored_size = 0
        remaining = ciphertext_len
        processed = 0
        try:
            while remaining:
                chunk = src.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise CryptoError("Contêiner truncado durante a verificação.")
                remaining -= len(chunk)
                processed += len(chunk)
                plain = decryptor.update(chunk)
                digest.update(plain)
                restored_size += len(plain)
                _progress(progress_callback, processed, ciphertext_len, "verify")
            tail = decryptor.finalize()
        except InvalidTag as exc:
            raise CryptoError("Falha na autenticação do contêiner recém-criado. O original foi preservado.") from exc
        digest.update(tail)
        restored_size += len(tail)
        _progress(progress_callback, ciphertext_len, ciphertext_len, "verify")

    if digest.hexdigest() != expected_digest or restored_size != expected_size:
        raise CryptoError("Falha na verificação do arquivo criptografado. O original foi preservado.")


def encrypt_path(
    source: Path,
    password: str,
    *,
    delete_original: bool = True,
    advanced_mode: bool = False,
    shred_passes: int = DEFAULT_SHRED_PASSES,
    progress_callback: ProgressCallback | None = None,
) -> Path:
    _validate_password(password, for_encryption=True)
    source = source.expanduser().resolve()
    if not source.exists():
        raise CryptoError("Arquivo ou pasta não encontrado.")
    if source.name.lower().endswith((EXTENSION, LEGACY_EXTENSION)):
        raise CryptoError("O item selecionado já parece estar criptografado.")
    if source.is_symlink():
        raise CryptoError("Links simbólicos não são suportados por segurança.")

    shred_passes = max(1, min(int(shred_passes or DEFAULT_SHRED_PASSES), MAX_SHRED_PASSES))
    is_dir = source.is_dir()
    output = source.with_name(source.name + EXTENSION)
    if output.exists():
        raise CryptoError(f"O destino já existe: {output}")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)

    # Modo avançado + arquivo único dentro do limite: reescreve o próprio
    # arquivo, sem nunca criar uma cópia separada em disco.
    if advanced_mode and not is_dir and source.is_file() and source.stat().st_size <= INPLACE_MAX_SIZE:
        header = {
            "version": VERSION,
            "cipher": "AES-256-GCM",
            "kdf": "scrypt",
            "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "kind": "file",
            "original_name": source.name,
            "plaintext_size": source.stat().st_size,
        }
        header_bytes = _encode_header(header)
        try:
            expected_digest, expected_size, result = _inplace_encrypt_file(
                source, header_bytes, key, nonce, shred_passes=shred_passes, progress_callback=progress_callback
            )
        except BaseException as exc:
            raise CryptoError(
                "Falha no modo em-loco: o arquivo pode estar corrompido, pois não há uma cópia de segurança. "
                f"Detalhe: {exc}"
            ) from exc
        # Verificação pós-gravação: se o próprio arquivo já criptografado não
        # decodificar corretamente, ao menos avisamos — não há original para recuperar.
        _verify_container(result, password, expected_digest, expected_size, progress_callback=progress_callback)
        return result

    archive_path: Path | None = None
    plaintext_path = source
    logical_size: int | None = None
    entry_count: int | None = None
    try:
        if is_dir:
            fd, temp_name = tempfile.mkstemp(prefix="cguard_archive_", suffix=".zip")
            os.close(fd)
            archive_path = Path(temp_name)
            logical_size, entry_count = _zip_directory(source, archive_path, progress_callback=progress_callback)
            plaintext_path = archive_path
            kind = "directory"
        elif source.is_file():
            kind = "file"
        else:
            raise CryptoError("O caminho selecionado não é um arquivo ou pasta comum.")

        header = {
            "version": VERSION,
            "cipher": "AES-256-GCM",
            "kdf": "scrypt",
            "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "kind": kind,
            "original_name": source.name,
            "plaintext_size": plaintext_path.stat().st_size,
        }
        if is_dir:
            header["directory_size"] = logical_size
            header["entry_count"] = entry_count

        header_bytes = _encode_header(header)
        expected_digest, expected_size = _stream_encrypt_file(
            plaintext_path, output, header_bytes, key, nonce, progress_callback=progress_callback
        )

        # Segunda passagem independente: autentica e lê todo o contêiner antes da remoção do original.
        _verify_container(output, password, expected_digest, expected_size, progress_callback=progress_callback)

        if delete_original:
            if advanced_mode:
                # Sobrescreve o conteúdo original com dados aleatórios antes de remover
                # a entrada do arquivo/pasta, dificultando recuperação por undelete/forense.
                shred_and_delete(source, passes=shred_passes)
            elif is_dir:
                shutil.rmtree(source)
                _fsync_directory(source.parent)
            else:
                source.unlink()
                _fsync_directory(source.parent)
        return output
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    finally:
        if archive_path is not None:
            if advanced_mode:
                _shred_and_unlink_file(archive_path, shred_passes)
            else:
                archive_path.unlink(missing_ok=True)


def decrypt_path(
    encrypted: Path,
    password: str,
    *,
    delete_encrypted: bool = True,
    progress_callback: ProgressCallback | None = None,
) -> Path:
    _validate_password(password)
    encrypted = encrypted.expanduser().resolve()
    if not encrypted.is_file() or encrypted.is_symlink():
        raise CryptoError("Arquivo criptografado não encontrado ou inválido.")

    file_size = encrypted.stat().st_size
    with encrypted.open("rb") as src:
        header, _header_bytes, _payload_offset = _read_header(src, file_size)
    version, _salt, _nonce, _n, _r, _p, kind, original_name = _header_crypto_fields(header)

    destination = encrypted.parent / original_name
    if destination.exists():
        raise CryptoError(f"Já existe um item com o nome original: {destination}")

    declared_plaintext_size = header.get("plaintext_size") if version >= 2 else None
    if declared_plaintext_size is not None:
        try:
            declared_plaintext_size = int(declared_plaintext_size)
        except (TypeError, ValueError) as exc:
            raise CryptoError("Tamanho de conteúdo inválido no cabeçalho.") from exc
        if declared_plaintext_size < 0:
            raise CryptoError("Tamanho de conteúdo inválido no cabeçalho.")

    if kind == "file":
        _header, _digest, restored_size = _stream_decrypt_to_file(
            encrypted, password, destination, progress_callback=progress_callback, atomic=True
        )
        if declared_plaintext_size is not None and restored_size != declared_plaintext_size:
            destination.unlink(missing_ok=True)
            raise CryptoError("O tamanho restaurado não corresponde aos metadados autenticados.")
    else:
        fd, temp_zip_name = tempfile.mkstemp(prefix="cguard_restore_", suffix=".zip", dir=str(encrypted.parent))
        os.close(fd)
        temp_zip = Path(temp_zip_name)
        temp_dir = Path(tempfile.mkdtemp(prefix=f".{original_name}.cguard-", dir=str(encrypted.parent)))
        try:
            _header, _digest, restored_size = _stream_decrypt_to_file(
                encrypted, password, temp_zip, progress_callback=progress_callback, atomic=False
            )
            if declared_plaintext_size is not None and restored_size != declared_plaintext_size:
                raise CryptoError("O tamanho do arquivo interno não corresponde aos metadados autenticados.")

            expected_size = header.get("directory_size") if version >= 2 else None
            expected_entries = header.get("entry_count") if version >= 2 else None
            if expected_size is not None:
                try:
                    expected_size = int(expected_size)
                    expected_entries = int(expected_entries)
                except (TypeError, ValueError) as exc:
                    raise CryptoError("Metadados da pasta são inválidos.") from exc
                if expected_size < 0 or expected_entries < 0 or expected_entries > MAX_ZIP_ENTRIES:
                    raise CryptoError("Metadados da pasta estão fora dos limites permitidos.")

            with zipfile.ZipFile(temp_zip, "r") as zf:
                bad = zf.testzip()
                if bad is not None:
                    raise CryptoError(f"Arquivo interno corrompido: {bad}")
                _safe_extract(
                    zf, temp_dir, expected_size=expected_size, expected_entries=expected_entries,
                    progress_callback=progress_callback
                )
            _atomic_replace(temp_dir, destination)
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise CryptoError("Conteúdo de pasta criptografada está corrompido.") from exc
        except BaseException:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise
        finally:
            temp_zip.unlink(missing_ok=True)

    if delete_encrypted:
        encrypted.unlink()
        _fsync_directory(encrypted.parent)
    return destination


def _ask_new_password() -> str:
    while True:
        password = getpass.getpass("Digite a senha desejada: ")
        confirmation = getpass.getpass("Digite a senha novamente para confirmar: ")
        if password != confirmation:
            print("❌ As senhas não coincidem. Tente novamente.\n")
            continue
        try:
            _validate_password(password, for_encryption=True)
            return password
        except CryptoError as exc:
            print(f"❌ {exc}")


def interactive() -> None:
    print("\n=== Crypto Guard ===")
    print("1 - Criptografar arquivo ou pasta")
    print("2 - Descriptografar arquivo .cguard")
    print("0 - Sair")
    choice = input("Escolha uma opção: ").strip()

    try:
        if choice == "1":
            raw = input("Caminho do arquivo ou pasta: ").strip().strip('"')
            result = encrypt_path(Path(raw), _ask_new_password(), delete_original=True)
            print("\n✅ Criptografia concluída, autenticada e verificada.")
            print(f"🔒 Arquivo protegido: {result}")
            print("🗑️  O original foi removido somente depois da verificação completa.")
        elif choice == "2":
            raw = input("Caminho do arquivo .cguard: ").strip().strip('"')
            password = getpass.getpass("Digite a senha: ")
            result = decrypt_path(Path(raw), password, delete_encrypted=True)
            print("\n✅ Descriptografia concluída.")
            print(f"📂 Restaurado em: {result}")
        elif choice == "0":
            return
        else:
            print("❌ Opção inválida.")
    except CryptoError as exc:
        print(f"\n❌ {exc}")
    except KeyboardInterrupt:
        print("\nOperação cancelada. O original foi preservado sempre que a operação não foi concluída.")
    except Exception as exc:
        print(f"\n❌ Erro inesperado: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Criptografador/descriptografador por senha para arquivos e pastas.")
    sub = parser.add_subparsers(dest="command")
    enc = sub.add_parser("encrypt", help="Criptografar um arquivo ou pasta")
    enc.add_argument("path", type=Path)
    enc.add_argument("--keep-original", action="store_true")
    dec = sub.add_parser("decrypt", help="Descriptografar um arquivo .cguard")
    dec.add_argument("path", type=Path)
    dec.add_argument("--keep-encrypted", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            print(f"✅ Criptografado: {encrypt_path(args.path, _ask_new_password(), delete_original=not args.keep_original)}")
        elif args.command == "decrypt":
            password = getpass.getpass("Digite a senha: ")
            print(f"✅ Restaurado: {decrypt_path(args.path, password, delete_encrypted=not args.keep_encrypted)}")
        else:
            interactive()
    except CryptoError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
