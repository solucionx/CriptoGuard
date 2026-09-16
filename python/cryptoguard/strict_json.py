from __future__ import annotations

import json
from typing import Any

from .errors import CryptoError


class _DuplicateKey(ValueError):
    pass


def _pairs_to_dict(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            raise _DuplicateKey("Chave JSON inválida.")
        if key in result:
            raise _DuplicateKey(f"Chave JSON duplicada: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Constante JSON não permitida: {value}")


def loads_strict(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs_to_dict,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, _DuplicateKey) as exc:
        raise CryptoError(f"{label} JSON inválido ou corrompido.") from exc
    if not isinstance(value, dict):
        raise CryptoError(f"{label} deve ser um objeto JSON.")
    return value


def dumps_canonical(value: dict[str, Any], *, label: str, max_size: int) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CryptoError(f"Não foi possível serializar {label}.") from exc
    if not 0 < len(raw) <= max_size:
        raise CryptoError(f"{label} excede o tamanho permitido.")
    return raw


def require_exact_keys(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("ausentes=" + ",".join(sorted(missing)))
        if extra:
            details.append("extras=" + ",".join(sorted(extra)))
        raise CryptoError(f"Schema inválido em {label} ({'; '.join(details)}).")


def require_int(value: object, *, label: str, minimum: int, maximum: int) -> int:
    # bool é subclass de int em Python e deve ser recusado explicitamente.
    if type(value) is not int:
        raise CryptoError(f"{label} deve ser um inteiro.")
    if value < minimum or value > maximum:
        raise CryptoError(f"{label} está fora dos limites permitidos.")
    return value
