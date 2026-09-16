from __future__ import annotations

import errno
import json
import sys
from pathlib import Path

from cryptoguard import CryptoCancelled, CryptoError, decrypt_path, encrypt_path


def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _permission_details(exc: BaseException) -> tuple[bool, str | None]:
    seen: set[int] = set()
    current: BaseException | None = exc
    fallback_path: str | None = None

    while current is not None and id(current) not in seen:
        seen.add(id(current))
        filename = getattr(current, "filename", None) or getattr(current, "filename2", None)
        if filename:
            fallback_path = str(filename)

        winerror = getattr(current, "winerror", None)
        err_no = getattr(current, "errno", None)
        text = str(current).lower()
        denied = (
            isinstance(current, PermissionError)
            or winerror in {5, 1314}
            or err_no in {errno.EACCES, errno.EPERM}
            or "access is denied" in text
            or "permission denied" in text
            or "acesso negado" in text
            or "privilégio" in text
        )
        if denied:
            return True, fallback_path
        current = current.__cause__ or current.__context__

    text = str(exc).lower()
    denied = "[winerror 5]" in text or "acesso negado" in text or "permission denied" in text
    return denied, fallback_path


def _emit_error(exc: BaseException, *, prefix: str = "") -> None:
    permission_denied, denied_path = _permission_details(exc)
    message = f"{prefix}{exc}" if prefix else str(exc)
    payload: dict = {
        "type": "result",
        "ok": False,
        "error": message,
        "error_code": "permission_denied" if permission_denied else "crypto_error",
    }
    if denied_path:
        payload["permission_path"] = denied_path
    emit(payload)


def main() -> None:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise CryptoError("Requisição inválida.")

        action = request.get("action")
        path = Path(str(request.get("path", "")))
        password = str(request.get("password", ""))
        keep_original = bool(request.get("keep_original", False))
        keep_encrypted = bool(request.get("keep_encrypted", False))
        advanced_mode = bool(request.get("advanced_mode", False))
        shred_passes_raw = request.get("shred_passes", 2)
        if type(shred_passes_raw) is not int:
            raise CryptoError("Quantidade de passadas inválida.")
        shred_passes = shred_passes_raw
        allow_cancel = bool(request.get("allow_cancel", True))
        cancel_file_raw = request.get("cancel_file")
        cancel_file = Path(str(cancel_file_raw)) if cancel_file_raw else None

        def progress(processed: int, total: int, stage: str) -> None:
            if allow_cancel and cancel_file is not None and cancel_file.exists():
                raise CryptoCancelled("Operação cancelada em um ponto seguro. Resultados temporários foram removidos.")
            emit({"type": "progress", "processed": processed, "total": total, "stage": stage})

        if action == "encrypt":
            result = encrypt_path(
                path,
                password,
                delete_original=not keep_original,
                advanced_mode=advanced_mode,
                shred_passes=shred_passes,
                progress_callback=progress,
            )
        elif action == "decrypt":
            result = decrypt_path(
                path,
                password,
                delete_encrypted=not keep_encrypted,
                progress_callback=progress,
            )
        else:
            raise CryptoError("Ação inválida.")

        emit({"type": "result", "ok": True, "result": str(result)})
    except CryptoCancelled as exc:
        emit({"type": "result", "ok": False, "cancelled": True, "error": str(exc), "error_code": "cancelled"})
        sys.exit(130)
    except CryptoError as exc:
        _emit_error(exc)
        sys.exit(2)
    except KeyboardInterrupt:
        emit({
            "type": "result",
            "ok": False,
            "cancelled": True,
            "error_code": "cancelled",
            "error": "Operação cancelada. Resultados temporários foram removidos quando possível.",
        })
        sys.exit(130)
    except Exception as exc:
        _emit_error(exc, prefix="Erro inesperado: ")
        sys.exit(1)


if __name__ == "__main__":
    main()
