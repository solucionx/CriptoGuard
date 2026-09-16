from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable, Iterable

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


def _is_windows_junction(path: Path) -> bool:
    checker = getattr(os.path, "isjunction", None)
    if checker is None:
        return False
    try:
        return bool(checker(path))
    except OSError:
        return False


def _is_reparse_point(path: Path, st: os.stat_result | None = None) -> bool:
    if _is_windows_junction(path):
        return True
    try:
        st = st or path.lstat()
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & flag)


def _resolved(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CryptoError(f"Não foi possível resolver o caminho para sobrescrita: {path}: {exc}") from exc


def _norm(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _is_same_or_descendant(path: Path, root: Path) -> bool:
    p = _norm(path)
    r = _norm(root)
    try:
        return os.path.commonpath([p, r]) == r
    except ValueError:
        return False


def _related(path: Path, protected: Path) -> bool:
    return _is_same_or_descendant(path, protected) or _is_same_or_descendant(protected, path)


def _normalize_protected_roots(paths: Iterable[Path] | None) -> tuple[Path, ...]:
    roots: list[Path] = []
    for raw in paths or ():
        try:
            candidate = Path(raw).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if candidate.is_file():
            candidate = candidate.parent
        if all(_norm(candidate) != _norm(existing) for existing in roots):
            roots.append(candidate)
    return tuple(roots)


def _validate_not_protected(path: Path, protected_roots: tuple[Path, ...], *, allow_ancestor: bool = False) -> None:
    for protected in protected_roots:
        if _is_same_or_descendant(path, protected):
            raise CryptoError(
                f"Modo extremo bloqueado: o caminho selecionado faz parte de uma área protegida do Crypto Guard: {path}"
            )
        if not allow_ancestor and _is_same_or_descendant(protected, path):
            raise CryptoError(
                f"Modo extremo bloqueado: o caminho selecionado contém uma área protegida do Crypto Guard: {protected}"
            )


def _validate_entry(root: Path, candidate: Path, protected_roots: tuple[Path, ...]) -> os.stat_result:
    try:
        st = candidate.lstat()
    except OSError as exc:
        raise CryptoError(f"Não foi possível inspecionar {candidate}: {exc}") from exc

    if stat.S_ISLNK(st.st_mode) or _is_reparse_point(candidate, st):
        raise CryptoError(
            f"O modo extremo não segue links, junctions ou reparse points. Remova ou mova esta entrada antes de continuar: {candidate}"
        )

    resolved = _resolved(candidate)
    if not _is_same_or_descendant(resolved, root):
        raise CryptoError(f"Entrada fora da pasta selecionada detectada; operação extrema bloqueada: {candidate}")
    _validate_not_protected(resolved, protected_roots)
    return st


def preflight_shred_target(path: Path, *, protected_roots: Iterable[Path] | None = None) -> None:
    """Valida todo o alvo antes de qualquer byte ser sobrescrito.

    O preflight falha fechado para junctions/reparse points, hard links e qualquer
    caminho que possa alcançar a instalação/motor do Crypto Guard. Isso evita que
    o modo extremo atravesse aliases do sistema de arquivos e apague conteúdo fora
    da árvore explicitamente selecionada pelo usuário.
    """
    path = _resolved(path)
    roots = _normalize_protected_roots(protected_roots)
    _validate_not_protected(path, roots)

    try:
        root_st = path.lstat()
    except OSError as exc:
        raise CryptoError(f"Não foi possível inspecionar o alvo do modo extremo: {path}: {exc}") from exc

    if stat.S_ISLNK(root_st.st_mode) or _is_reparse_point(path, root_st):
        raise CryptoError("O modo extremo não opera sobre links, junctions ou reparse points.")

    if stat.S_ISREG(root_st.st_mode):
        if getattr(root_st, "st_nlink", 1) > 1:
            raise CryptoError("O modo extremo recusou um arquivo com múltiplos hard links para evitar sobrescrever outra cópia física do mesmo arquivo.")
        return

    if not stat.S_ISDIR(root_st.st_mode):
        raise CryptoError("O modo extremo suporta apenas arquivos e pastas comuns.")

    # Fazemos uma varredura completa antes de começar a escrever. Se houver uma
    # única entrada perigosa, nada é sobrescrito.
    for base, dirs, names in os.walk(path, topdown=True, followlinks=False):
        base_path = Path(base)
        base_resolved = _resolved(base_path)
        if not _is_same_or_descendant(base_resolved, path):
            raise CryptoError(f"A árvore selecionada escapou do diretório original: {base_path}")
        _validate_not_protected(base_resolved, roots)

        for name in list(dirs):
            candidate = base_path / name
            st = _validate_entry(path, candidate, roots)
            if not stat.S_ISDIR(st.st_mode):
                raise CryptoError(f"Entrada inesperada na pasta antes da sobrescrita: {candidate}")

        for name in names:
            candidate = base_path / name
            st = _validate_entry(path, candidate, roots)
            if not stat.S_ISREG(st.st_mode):
                raise CryptoError(f"Somente arquivos regulares podem ser sobrescritos: {candidate}")
            if getattr(st, "st_nlink", 1) > 1:
                raise CryptoError(
                    f"Modo extremo bloqueado: arquivo com múltiplos hard links detectado: {candidate}"
                )


def _scan_directory(path: Path, protected_roots: tuple[Path, ...]) -> list[tuple[Path, int]]:
    files: list[tuple[Path, int]] = []
    for base, dirs, names in os.walk(path, topdown=True, followlinks=False):
        base_path = Path(base)
        for name in list(dirs):
            candidate = base_path / name
            st = _validate_entry(path, candidate, protected_roots)
            if not stat.S_ISDIR(st.st_mode):
                raise CryptoError(f"Entrada inesperada na pasta antes da sobrescrita: {candidate}")
        for name in names:
            candidate = base_path / name
            st = _validate_entry(path, candidate, protected_roots)
            if not stat.S_ISREG(st.st_mode):
                raise CryptoError(f"Somente arquivos regulares podem ser sobrescritos: {candidate}")
            if getattr(st, "st_nlink", 1) > 1:
                raise CryptoError(f"Modo extremo bloqueado: arquivo com múltiplos hard links detectado: {candidate}")
            files.append((candidate, st.st_size))
    return files


def overwrite_file(
    path: Path,
    *,
    passes: int = DEFAULT_SHRED_PASSES,
    progress_callback: ProgressCallback | None = None,
    processed_base: int = 0,
    total_work: int | None = None,
    root: Path | None = None,
    protected_roots: Iterable[Path] | None = None,
) -> int:
    """Sobrescreve best-effort um arquivo regular, sem removê-lo."""
    passes = validate_shred_passes(passes)
    path = _resolved(path)
    roots = _normalize_protected_roots(protected_roots)
    if root is not None:
        root = _resolved(root)
        if not _is_same_or_descendant(path, root):
            raise CryptoError("A sobrescrita tentou sair da árvore selecionada e foi bloqueada.")
    _validate_not_protected(path, roots)

    try:
        st = path.lstat()
    except OSError as exc:
        raise CryptoError(f"Não foi possível acessar o arquivo para sobrescrita: {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or _is_reparse_point(path, st) or not stat.S_ISREG(st.st_mode):
        raise CryptoError(f"A sobrescrita exige um arquivo regular sem links/reparse points: {path}")
    if getattr(st, "st_nlink", 1) > 1:
        raise CryptoError(f"A sobrescrita recusou um arquivo com múltiplos hard links: {path}")

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
                    _progress(progress_callback, processed_base + pass_index * size + written_in_pass, total)
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
    protected_roots: Iterable[Path] | None = None,
) -> None:
    """Sobrescreve e remove arquivo/pasta em modo extremo, com contenção de caminho.

    A sobrescrita é best-effort. Em SSD/NVMe, TRIM, wear-leveling, snapshots,
    journaling, backups e sincronização podem preservar cópias físicas.
    """
    passes = validate_shred_passes(passes)
    path = _resolved(path)
    roots = _normalize_protected_roots(protected_roots)
    preflight_shred_target(path, protected_roots=roots)

    st = path.lstat()
    if stat.S_ISREG(st.st_mode):
        total = max(1, st.st_size * passes)
        overwrite_file(
            path,
            passes=passes,
            progress_callback=progress_callback,
            total_work=total,
            root=path.parent,
            protected_roots=roots,
        )
        try:
            path.unlink()
            fsync_directory(path.parent)
        except OSError as exc:
            raise CryptoError(f"O arquivo foi sobrescrito, mas não pôde ser removido: {exc}") from exc
        _progress(progress_callback, total, total)
        return

    files = _scan_directory(path, roots)
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
            root=path,
            protected_roots=roots,
        )
        processed += size * passes
        try:
            file_path.unlink()
        except OSError as exc:
            raise CryptoError(f"{file_path} foi sobrescrito, mas não pôde ser removido: {exc}") from exc

    try:
        for base, dirs, _names in os.walk(path, topdown=False, followlinks=False):
            base_path = Path(base)
            for name in dirs:
                candidate = base_path / name
                if _is_windows_junction(candidate) or _is_reparse_point(candidate):
                    raise CryptoError(f"Junction/reparse point apareceu durante a remoção: {candidate}")
                candidate.rmdir()
        path.rmdir()
        fsync_directory(path.parent)
    except CryptoError:
        raise
    except OSError as exc:
        raise CryptoError(f"Os arquivos foram sobrescritos, mas a estrutura da pasta não pôde ser removida por completo: {exc}") from exc
    _progress(progress_callback, progress_total, progress_total)
