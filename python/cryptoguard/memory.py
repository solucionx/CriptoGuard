from __future__ import annotations


def wipe_buffer(buffer: bytearray | memoryview | None) -> None:
    """Sobrescrita best-effort de um buffer mutável.

    Python e bibliotecas nativas podem criar cópias internas. Portanto esta
    função reduz a janela de exposição, mas não é uma garantia de eliminação de
    todos os vestígios de memória.
    """
    if buffer is None:
        return
    try:
        view = memoryview(buffer)
        if view.readonly:
            return
        view[:] = b"\x00" * len(view)
    except (TypeError, ValueError, BufferError):
        pass
