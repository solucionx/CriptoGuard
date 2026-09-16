from __future__ import annotations


class CryptoError(Exception):
    """Erro de criptografia/formato apresentado de forma controlada ao usuário."""


class CryptoCancelled(CryptoError):
    """Operação interrompida cooperativamente em um ponto seguro."""
