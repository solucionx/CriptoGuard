from __future__ import annotations

import os
import tempfile
from pathlib import Path


def make_temp_file(parent: Path, prefix: str, suffix: str = ".tmp") -> tuple[int, Path]:
    parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=str(parent))
    return fd, Path(name)


def fsync_directory(directory: Path) -> None:
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


def atomic_replace(temp_path: Path, destination: Path) -> None:
    os.replace(temp_path, destination)
    fsync_directory(destination.parent)
