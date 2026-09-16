from __future__ import annotations

"""CLI e camada de compatibilidade de imports do Crypto Guard 1.6 / CGUARD v4."""

import argparse
import getpass
from pathlib import Path

from cryptoguard import CryptoError, decrypt_path, encrypt_path
from cryptoguard.constants import EXTENSION, MAGIC, VERSION


def _ask_new_password() -> str:
    while True:
        password = getpass.getpass("Digite a senha desejada: ")
        confirmation = getpass.getpass("Digite a senha novamente para confirmar: ")
        if password != confirmation:
            print("❌ As senhas não coincidem. Tente novamente.\n")
            continue
        try:
            # A validação completa acontece dentro de encrypt_path.
            if len(password) < 12:
                raise CryptoError("Use uma senha com pelo menos 12 caracteres.")
            return password
        except CryptoError as exc:
            print(f"❌ {exc}")


def interactive() -> None:
    print("\n=== Crypto Guard 1.6 — CGUARD v4 ===")
    print("1 - Criptografar arquivo ou pasta")
    print("2 - Descriptografar arquivo .cguard v4")
    print("0 - Sair")
    choice = input("Escolha uma opção: ").strip()

    try:
        if choice == "1":
            raw = input("Caminho do arquivo ou pasta: ").strip().strip('"')
            password = _ask_new_password()
            extreme = input("Ativar modo extremo de sobrescrita antes de apagar? [s/N]: ").strip().lower() in {"s", "sim", "y", "yes"}
            passes = 2
            if extreme:
                raw_passes = input("Passadas (1, 2, 3 ou 7) [2]: ").strip() or "2"
                try:
                    passes = int(raw_passes)
                except ValueError:
                    raise CryptoError("Quantidade de passadas inválida.")
            result = encrypt_path(
                Path(raw), password, delete_original=True, advanced_mode=extreme, shred_passes=passes
            )
            print("\n✅ Criptografia CGUARD v4 concluída e verificada por round-trip.")
            print(f"🔒 Arquivo protegido: {result}")
        elif choice == "2":
            raw = input("Caminho do arquivo .cguard: ").strip().strip('"')
            password = getpass.getpass("Digite a senha: ")
            result = decrypt_path(Path(raw), password, delete_encrypted=True)
            print("\n✅ Descriptografia concluída.")
            print(f"📂 Restaurado em: {result}")
        elif choice != "0":
            print("❌ Opção inválida.")
    except CryptoError as exc:
        print(f"\n❌ {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Crypto Guard 1.6 — CGUARD v4")
    sub = parser.add_subparsers(dest="command")
    enc = sub.add_parser("encrypt", help="Criptografar arquivo ou pasta em CGUARD v4")
    enc.add_argument("path", type=Path)
    enc.add_argument("--keep-original", action="store_true")
    enc.add_argument("--extreme", action="store_true", help="Sobrescrever best-effort o original antes de apagar")
    enc.add_argument("--shred-passes", type=int, default=2, choices=[1, 2, 3, 7])
    dec = sub.add_parser("decrypt", help="Descriptografar arquivo CGUARD v4")
    dec.add_argument("path", type=Path)
    dec.add_argument("--keep-encrypted", action="store_true")
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            if args.extreme and args.keep_original:
                raise CryptoError("--extreme não pode ser usado junto com --keep-original.")
            result = encrypt_path(
                args.path,
                _ask_new_password(),
                delete_original=not args.keep_original,
                advanced_mode=args.extreme,
                shred_passes=args.shred_passes,
            )
            print(f"✅ Criptografado: {result}")
        elif args.command == "decrypt":
            password = getpass.getpass("Digite a senha: ")
            result = decrypt_path(args.path, password, delete_encrypted=not args.keep_encrypted)
            print(f"✅ Restaurado: {result}")
        else:
            interactive()
    except CryptoError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
