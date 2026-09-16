from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path
from typing import Callable

from .constants import DEFAULT_CHUNK_SIZE, MAX_ZIP_ENTRIES
from .errors import CryptoError

ProgressCallback = Callable[[int, int, str], None]


def _progress(callback: ProgressCallback | None, processed: int, total: int, stage: str) -> None:
    if callback is not None:
        callback(processed, total, stage)


def zip_directory(source: Path, zip_path: Path, *, progress_callback: ProgressCallback | None = None) -> tuple[int, int]:
    logical_size = 0
    entry_count = 0
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for item in source.rglob("*"):
            if item.is_symlink():
                raise CryptoError(f"Link simbólico não é suportado por segurança: {item}")
            relative = item.relative_to(source)
            if item.is_file():
                logical_size += item.stat().st_size
                entry_count += 1
                if entry_count > MAX_ZIP_ENTRIES:
                    raise CryptoError("A pasta contém itens demais para o limite de segurança configurado.")
                zf.write(item, relative)
                _progress(progress_callback, logical_size, 0, "pack")
            elif item.is_dir() and not any(item.iterdir()):
                entry_count += 1
                if entry_count > MAX_ZIP_ENTRIES:
                    raise CryptoError("A pasta contém itens demais para o limite de segurança configurado.")
                info = zipfile.ZipInfo(str(relative).replace(os.sep, "/") + "/")
                zf.writestr(info, b"")
                _progress(progress_callback, logical_size, 0, "pack")
    return logical_size, entry_count


def verify_zip_matches_directory(
    source: Path,
    zip_path: Path,
    *,
    progress_callback: ProgressCallback | None = None,
) -> None:
    """Confirma que o ZIP temporário representa exatamente a pasta de origem.

    A comparação é byte a byte para arquivos e também valida o conjunto de
    caminhos (arquivos + diretórios vazios) antes que a origem possa ser
    removida. Isso complementa o round-trip criptográfico do próprio .cguard.
    """
    expected: dict[str, Path | None] = {}
    expected_size = 0
    for item in source.rglob("*"):
        if item.is_symlink():
            raise CryptoError(f"Link simbólico não é suportado por segurança: {item}")
        relative = item.relative_to(source).as_posix()
        if item.is_file():
            expected[relative] = item
            expected_size += item.stat().st_size
        elif item.is_dir() and not any(item.iterdir()):
            expected[relative.rstrip("/") + "/"] = None
        if len(expected) > MAX_ZIP_ENTRIES:
            raise CryptoError("A pasta contém itens demais para o limite de segurança configurado.")

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            actual_names = [info.filename.replace("\\", "/") for info in infos]
            if len(actual_names) != len(set(actual_names)):
                raise CryptoError("O pacote temporário contém caminhos duplicados.")
            if set(actual_names) != set(expected):
                raise CryptoError("O pacote temporário não corresponde à estrutura da pasta de origem.")

            processed = 0
            for info in infos:
                name = info.filename.replace("\\", "/")
                original = expected[name]
                if original is None:
                    if not info.is_dir():
                        raise CryptoError("Diretório vazio foi serializado de forma inconsistente.")
                    continue
                if info.is_dir():
                    raise CryptoError("Arquivo da origem foi serializado como diretório.")
                try:
                    original_size = original.stat().st_size
                except OSError as exc:
                    raise CryptoError("A pasta de origem mudou durante a verificação.") from exc
                if info.file_size != original_size:
                    raise CryptoError("Um arquivo da pasta mudou de tamanho durante a verificação.")

                with original.open("rb") as src, zf.open(info, "r") as packed:
                    while True:
                        a = src.read(DEFAULT_CHUNK_SIZE)
                        b = packed.read(DEFAULT_CHUNK_SIZE)
                        if a != b:
                            raise CryptoError("O pacote temporário não corresponde byte a byte à pasta de origem.")
                        if not a:
                            break
                        processed += len(a)
                        _progress(progress_callback, processed, expected_size, "pack_verify")
            _progress(progress_callback, expected_size, expected_size, "pack_verify")
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise CryptoError("O pacote temporário da pasta ficou corrompido.") from exc


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _validate_zip(
    zf: zipfile.ZipFile,
    destination: Path,
    *,
    expected_size: int,
    expected_entries: int,
) -> tuple[list[zipfile.ZipInfo], int]:
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES or len(infos) != expected_entries:
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
            if total_size > expected_size:
                raise CryptoError("Conteúdo da pasta excede o tamanho autenticado.")

    if total_size != expected_size:
        raise CryptoError("Tamanho restaurado da pasta não corresponde aos metadados autenticados.")
    return infos, total_size


def safe_extract(
    zf: zipfile.ZipFile,
    destination: Path,
    *,
    expected_size: int,
    expected_entries: int,
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
                chunk = src.read(DEFAULT_CHUNK_SIZE)
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
