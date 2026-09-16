from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(engine: Path, payload: dict) -> dict:
    proc = subprocess.run(
        [str(engine)],
        input=json.dumps(payload, ensure_ascii=False),
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    result = None
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("type") == "result":
            result = item
    if result is None:
        raise RuntimeError(f"Engine não retornou resultado JSON. rc={proc.returncode}; stderr={proc.stderr}")
    if not result.get("ok"):
        raise RuntimeError(f"Engine falhou: {result.get('error')}")
    return result


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("uso: smoke-engine.py <crypto_guard_engine.exe>")
    engine = Path(sys.argv[1]).resolve()
    if not engine.is_file():
        raise SystemExit(f"engine não encontrado: {engine}")

    root = Path(tempfile.mkdtemp(prefix="cryptoguard_engine_smoke_"))
    password = "CryptoGuard-Smoke-Password-123!"
    try:
        source = root / "smoke.bin"
        expected = (b"Crypto Guard v4 engine smoke test\n" * 4096)
        source.write_bytes(expected)

        enc = run(engine, {
            "action": "encrypt",
            "path": str(source),
            "password": password,
            "keep_original": True,
            "allow_cancel": False,
        })
        encrypted = Path(enc["result"])
        if not encrypted.is_file():
            raise RuntimeError("Engine não criou o contêiner esperado.")

        source.unlink()
        dec = run(engine, {
            "action": "decrypt",
            "path": str(encrypted),
            "password": password,
            "keep_encrypted": True,
            "allow_cancel": False,
        })
        restored = Path(dec["result"])
        if restored.read_bytes() != expected:
            raise RuntimeError("Round-trip do engine compilado alterou os bytes.")
        print("OK: engine compilado executou CGUARD v4 round-trip.")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
