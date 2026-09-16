from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable

from .constants import ALLOWED_SHRED_PASSES, DEFAULT_SHRED_PASSES, SHRED_CHUNK_SIZE
from .errors import CryptoError
from .io_utils import fsync_directory

ProgressCallback = Callable[[int, int, str], None]


def validate_shred_passes(passes: int) -> int:
    if type(passes) is not int or passes not in ALLOWED_SHRED_PASSES:
        allowed = ", ".join(str(v) for v in ALLOWED_SHRED_PASSES)
        raise CryptoError(f"Quantidade de passadas inválida. Valores permitidos: {allowed}.")
    return passes


def _progress(callback: ProgressCallback | None, processed: int, total: int) -> None:
    if callback is not None:
        callback(processed, total, "shred")


def _scan_directory(path: Path) -> list[tuple[Path, int]]:
    files: list[tuple[Path, int]] = []
    for base, dirs, names in os.walk(path, topdown=True, followlinks=False):
        base_path = Path(base)
        # Não seguimos nem apagamos silenciosamente links surgidos depois da
        # verificação do pacote. Mudança da árvore durante a operação é erro.
        for name in list(dirs):
            candidate = base_path / name
            try:
                mode = candidate.lstat().st_mode
            except OSError as exc:
                raise CryptoError(f"Não foi possível inspecionar {candidate}: {exc}") from exc
            if stat.S_ISLNK(mode):
                raise CryptoError(f"Link simbólico encontrado antes da sobrescrita: {candidate}")
            if not stat.S_ISDIR(mode):
                raise CryptoError(f"Entrada inesperada na pasta antes da sobrescrita: {candidate}")
        for name in names:
            candidate = base_path / name
            try:
                st = candidate.lstat()
            except OSError as exc:
                raise CryptoError(f"Não foi possível inspecionar {candidate}: {exc}") from exc
            if stat.S_ISLNK(st.st_mode):
                raise CryptoError(f"Link simbólico encontrado antes da sobrescrita: {candidate}")
            if not stat.S_ISREG(st.st_mode):
                raise CryptoError(f"Somente arquivos regulares podem ser sobrescritos: {candidate}")
            files.append((candidate, st.st_size))
    return files


def overwrite_file(
    path: Path,
    *,
    passes: int = DEFAULT_SHRED_PASSES,
    progress_callback: ProgressCallback | None = None,
    processed_base: int = 0,
    total_work: int | None = None,
) -> int:
    """Sobrescreve best-effort um arquivo regular, sem removê-lo.

    Retorna a quantidade de bytes de trabalho contabilizada (tamanho * passadas).
    O tamanho é verificado durante o processo para evitar apagar silenciosamente
    um arquivo que mudou enquanto estava sendo sobrescrito.
    """
    passes = validate_shred_passes(passes)
    path = path.expanduser()
    try:
        st = path.lstat()
    except OSError as exc:
        raise CryptoError(f"Não foi possível acessar o arquivo para sobrescrita: {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise CryptoError(f"A sobrescrita exige um arquivo regular: {path}")

    size = st.st_size
    work = size * passes
    total = total_work if total_work is not None else max(1, work)
    if size == 0:
        _progress(progress_callback, processed_base + work, total)
        return work

    try:
        with path.open("r+b", buffering=0) as handle:
            for pass_index in range(passes):
                current_size = os.fstat(handle.fileno()).st_size
                if current_size != size:
                    raise CryptoError("O arquivo mudou de tamanho durante a sobrescrita; ele não foi removido.")
                handle.seek(0)
                remaining = size
                written_in_pass = 0
                while remaining:
                    amount = min(SHRED_CHUNK_SIZE, remaining)
                    block = os.urandom(amount)
                    view = memoryview(block)
                    offset = 0
                    while offset < amount:
                        n = handle.write(view[offset:])
                        if n is None or n <= 0:
                            raise OSError("gravação incompleta durante a sobrescrita")
                        offset += n
                    remaining -= amount
                    written_in_pass += amount
                    _progress(
                        progress_callback,
                        processed_base + pass_index * size + written_in_pass,
                        total,
                    )
                handle.flush()
                os.fsync(handle.fileno())

            if os.fstat(handle.fileno()).st_size != size:
                raise CryptoError("O arquivo mudou de tamanho durante a sobrescrita; ele não foi removido.")
    except CryptoError:
        raise
    except OSError as exc:
        raise CryptoError(f"Falha ao sobrescrever {path}: {exc}. O item não foi removido.") from exc
    return work


def shred_and_delete(
    path: Path,
    *,
    passes: int = DEFAULT_SHRED_PASSES,
    progress_callback: ProgressCallback | None = None,
) -> None:
    """Sobrescreve e remove arquivo/pasta em modo extremo.

    A sobrescrita é uma mitigação best-effort. Em SSD/NVMe, TRIM, wear-leveling,
    snapshots, journaling, backups e sincronização podem preservar cópias físicas.
    Se uma gravação falhar, o item correspondente não é removido silenciosamente.
    """
    passes = validate_shred_passes(passes)
    path = path.expanduser()
    try:
        st = path.lstat()
    except OSError as exc:
        raise CryptoError(f"Não foi possível acessar o original para remoção extrema: {path}: {exc}") from exc

    if stat.S_ISLNK(st.st_mode):
        raise CryptoError("O modo extremo não opera sobre links simbólicos.")

    if stat.S_ISREG(st.st_mode):
        total = max(1, st.st_size * passes)
        overwrite_file(path, passes=passes, progress_callback=progress_callback, total_work=total)
        try:
            path.unlink()
            fsync_directory(path.parent)
        except OSError as exc:
            raise CryptoError(f"O arquivo foi sobrescrito, mas não pôde ser removido: {exc}") from exc
        _progress(progress_callback, total, total)
        return

    if not stat.S_ISDIR(st.st_mode):
        raise CryptoError("O modo extremo suporta apenas arquivos e pastas comuns.")

    files = _scan_directory(path)
    total = sum(size * passes for _file, size in files)
    progress_total = max(1, total)
    processed = 0
    for file_path, size in files:
        overwrite_file(
            file_path,
            passes=passes,
            progress_callback=progress_callback,
            processed_base=processed,
            total_work=progress_total,
        )
        processed += size * passes
        try:
            file_path.unlink()
        except OSError as exc:
            raise CryptoError(f"{file_path} foi sobrescrito, mas não pôde ser removido: {exc}") from exc

    # Agora só devem restar diretórios. Remoção bottom-up sem seguir links.
    try:
        for base, dirs, _names in os.walk(path, topdown=False, followlinks=False):
            base_path = Path(base)
            for name in dirs:
                (base_path / name).rmdir()
        path.rmdir()
        fsync_directory(path.parent)
    except OSError as exc:
        raise CryptoError(f"Os arquivos foram sobrescritos, mas a estrutura da pasta não pôde ser removida por completo: {exc}") from exc
    _progress(progress_callback, progress_total, progress_total)
