from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Callable

from .archive import safe_extract, verify_zip_matches_directory, zip_directory
from .constants import DEFAULT_SHRED_PASSES, EXTENSION, PASSWORD_MIN_LENGTH
from .container_v4 import create_container_temp, decrypt_container_to_temp, verify_container
from .errors import CryptoError
from .format_v4 import build_metadata
from .io_utils import atomic_replace, fsync_directory
from .secure_delete import preflight_shred_target, shred_and_delete, validate_shred_passes

ProgressCallback = Callable[[int, int, str], None]


_DISK_RESERVE_BYTES = 256 * 1024 * 1024


def _write_status(status_file: Path | None, payload: dict) -> None:
    if status_file is None:
        return
    try:
        status_file = status_file.expanduser()
        status_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = status_file.with_name(status_file.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=True, separators=(",", ":")), encoding="ascii")
        os.replace(tmp, status_file)
    except OSError:
        # O journal melhora recuperacao/diagnostico, mas nunca deve enfraquecer
        # a operacao criptografica principal.
        pass


def _directory_logical_size(source: Path) -> int:
    total = 0
    for item in source.rglob("*"):
        if item.is_symlink():
            raise CryptoError(f"Link simbólico não é suportado por segurança: {item}")
        if item.is_file():
            try:
                total += item.stat().st_size
            except OSError as exc:
                raise CryptoError(f"Não foi possível inspecionar o tamanho de {item}: {exc}") from exc
    return total


def _ensure_working_space(parent: Path, payload_size: int, *, directory: bool) -> None:
    try:
        free = shutil.disk_usage(parent).free
    except OSError:
        return
    # Pasta precisa coexistir como ZIP temporario + CGUARD temporario. Para
    # arquivo comum basta o CGUARD. Reserva adicional cobre metadata/overhead.
    multiplier = 2 if directory else 1
    required = payload_size * multiplier + _DISK_RESERVE_BYTES
    if free < required:
        need_gib = required / (1024 ** 3)
        free_gib = free / (1024 ** 3)
        raise CryptoError(
            f"Espaço livre insuficiente para concluir a operação com segurança. "
            f"Necessário aproximadamente {need_gib:.2f} GiB; disponível {free_gib:.2f} GiB."
        )


def _validate_password(password: str, *, for_encryption: bool = False) -> None:
    if not isinstance(password, str) or not password:
        raise CryptoError("A senha não pode ficar vazia.")
    if "\x00" in password:
        raise CryptoError("A senha contém um caractere não permitido.")
    if for_encryption and len(password) < PASSWORD_MIN_LENGTH:
        raise CryptoError(f"Use uma senha com pelo menos {PASSWORD_MIN_LENGTH} caracteres.")
    if len(password.encode("utf-8")) > 4096:
        raise CryptoError("A senha excede o tamanho máximo permitido.")


def encrypt_path(
    source: Path,
    password: str,
    *,
    delete_original: bool = True,
    advanced_mode: bool = False,
    shred_passes: int = DEFAULT_SHRED_PASSES,
    progress_callback: ProgressCallback | None = None,
    status_file: Path | None = None,
    protected_roots: list[Path] | tuple[Path, ...] | None = None,
) -> Path:
    """Cria um CGUARD v4 e faz round-trip completo antes de remover a origem.

    O arquivo final só recebe o nome definitivo depois que todo o contêiner foi
    reaberto, autenticado e comparado ao payload de origem por SHA-256.
    """
    _validate_password(password, for_encryption=True)
    if advanced_mode and not delete_original:
        raise CryptoError("O modo extremo exige que ‘Manter o original’ esteja desativado.")
    if advanced_mode:
        shred_passes = validate_shred_passes(shred_passes)
    source = source.expanduser().resolve()
    if not source.exists():
        raise CryptoError("Arquivo ou pasta não encontrado.")
    if source.is_symlink():
        raise CryptoError("Links simbólicos não são suportados por segurança.")
    if source.name.lower().endswith(EXTENSION):
        raise CryptoError("O item selecionado já parece ser um contêiner Crypto Guard.")

    # O modo extremo é destrutivo. Antes de criar qualquer contêiner ou escrever
    # qualquer byte, validamos a árvore inteira contra junctions/reparse points,
    # hard links e caminhos protegidos da instalação/motor.
    if advanced_mode:
        preflight_shred_target(source, protected_roots=protected_roots)

    output = source.with_name(source.name + EXTENSION)
    if output.exists():
        raise CryptoError(f"O destino já existe: {output}")

    _write_status(status_file, {
        "phase": "started",
        "source": str(source),
        "output": str(output),
        "delete_original": bool(delete_original),
        "advanced_mode": bool(advanced_mode),
    })

    if source.is_file():
        try:
            source_size = source.stat().st_size
        except OSError as exc:
            raise CryptoError(f"Não foi possível ler o tamanho do arquivo: {exc}") from exc
        _ensure_working_space(source.parent, source_size, directory=False)
    elif source.is_dir():
        logical_size_estimate = _directory_logical_size(source)
        _ensure_working_space(source.parent, logical_size_estimate, directory=True)

    archive_path: Path | None = None
    container_temp: Path | None = None
    try:
        if source.is_file():
            payload_path = source
            metadata_bytes = build_metadata(kind="file", original_name=source.name)
        elif source.is_dir():
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{source.name}.cguard-pack-", suffix=".zip", dir=str(source.parent)
            )
            os.close(fd)
            archive_path = Path(temp_name)
            logical_size, entry_count = zip_directory(
                source, archive_path, progress_callback=progress_callback
            )
            verify_zip_matches_directory(
                source, archive_path, progress_callback=progress_callback
            )
            payload_path = archive_path
            metadata_bytes = build_metadata(
                kind="directory",
                original_name=source.name,
                directory_size=logical_size,
                entry_count=entry_count,
            )
        else:
            raise CryptoError("O caminho selecionado não é um arquivo ou pasta comum.")

        container_temp, expected_digest, _parsed = create_container_temp(
            payload_path,
            output,
            password,
            metadata_bytes,
            progress_callback=progress_callback,
        )

        # Round-trip completo: reabre o arquivo recém-criado, autentica cada
        # chunk e compara o payload restaurado ao payload exato de origem.
        verify_container(
            container_temp,
            password,
            expected_digest=expected_digest,
            expected_metadata=metadata_bytes,
            expected_plaintext_path=payload_path,
            progress_callback=progress_callback,
        )

        atomic_replace(container_temp, output)
        container_temp = None
        _write_status(status_file, {
            "phase": "container_verified",
            "source": str(source),
            "output": str(output),
            "delete_original": bool(delete_original),
            "advanced_mode": bool(advanced_mode),
        })

        # Em pastas, o ZIP temporário contém plaintext. No modo extremo ele é
        # sobrescrito antes de seguirmos para a remoção da árvore original.
        if archive_path is not None and advanced_mode:
            try:
                shred_and_delete(
                    archive_path,
                    passes=shred_passes,
                    progress_callback=progress_callback,
                )
                archive_path = None
            except CryptoError as exc:
                raise CryptoError(
                    f"O contêiner foi criado e verificado em {output}, mas o pacote temporário não pôde ser sobrescrito com segurança best-effort. "
                    f"O original foi preservado. Detalhe: {exc}"
                ) from exc

        if delete_original:
            if advanced_mode:
                try:
                    shred_and_delete(
                        source,
                        passes=shred_passes,
                        progress_callback=progress_callback,
                    )
                except CryptoError as exc:
                    # O .cguard já está completo e verificado. Mantemos o
                    # contêiner e informamos claramente se a remoção extrema
                    # não pôde ser concluída.
                    raise CryptoError(
                        f"O contêiner foi criado e verificado em {output}, mas o modo extremo não conseguiu remover completamente o original. "
                        f"Detalhe: {exc}"
                    ) from exc
            else:
                try:
                    if source.is_dir():
                        shutil.rmtree(source)
                    else:
                        source.unlink()
                    fsync_directory(source.parent)
                except OSError as exc:
                    # O contêiner já foi validado. Não o removemos por causa de uma
                    # falha posterior ao apagar o original.
                    raise CryptoError(
                        f"O contêiner foi criado e verificado em {output}, mas o original não pôde ser removido: {exc}"
                    ) from exc
        _write_status(status_file, {
            "phase": "complete",
            "source": str(source),
            "output": str(output),
            "delete_original": bool(delete_original),
            "advanced_mode": bool(advanced_mode),
            "original_exists": source.exists(),
        })
        return output
    finally:
        if container_temp is not None:
            container_temp.unlink(missing_ok=True)
        if archive_path is not None:
            # Se uma sobrescrita extrema do temporário falhou, ainda removemos
            # a entrada temporária como limpeza de emergência; isso não é
            # apresentado como apagamento físico garantido.
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

    metadata, temp_payload, _digest = decrypt_container_to_temp(
        encrypted,
        password,
        progress_callback=progress_callback,
    )
    destination = encrypted.parent / metadata.original_name
    temp_dir: Path | None = None
    try:
        if destination.exists():
            raise CryptoError(f"Já existe um item com o nome original: {destination}")

        if metadata.kind == "file":
            atomic_replace(temp_payload, destination)
            temp_payload = None
        else:
            if metadata.directory_size is None or metadata.entry_count is None:
                raise CryptoError("Metadados autenticados da pasta estão incompletos.")
            temp_dir = Path(tempfile.mkdtemp(prefix=f".{metadata.original_name}.cguard-restore-", dir=str(encrypted.parent)))
            try:
                with zipfile.ZipFile(temp_payload, "r") as zf:
                    bad = zf.testzip()
                    if bad is not None:
                        raise CryptoError(f"Arquivo interno corrompido: {bad}")
                    safe_extract(
                        zf,
                        temp_dir,
                        expected_size=metadata.directory_size,
                        expected_entries=metadata.entry_count,
                        progress_callback=progress_callback,
                    )
            except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
                raise CryptoError("Conteúdo interno da pasta está corrompido.") from exc
            atomic_replace(temp_dir, destination)
            temp_dir = None

        if delete_encrypted:
            encrypted.unlink()
            fsync_directory(encrypted.parent)
        return destination
    finally:
        if temp_payload is not None:
            temp_payload.unlink(missing_ok=True)
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)
