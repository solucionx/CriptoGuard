from __future__ import annotations

import hashlib
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
        timeout=180,
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


def bundle_manifest(bundle: Path) -> dict[str, tuple[int, str]]:
    manifest: dict[str, tuple[int, str]] = {}
    for file in sorted(p for p in bundle.rglob("*") if p.is_file()):
        digest = hashlib.sha256()
        with file.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        manifest[file.relative_to(bundle).as_posix()] = (file.stat().st_size, digest.hexdigest())
    return manifest


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("uso: smoke-engine.py <crypto_guard_engine.exe>")
    engine = Path(sys.argv[1]).resolve()
    if not engine.is_file():
        raise SystemExit(f"engine não encontrado: {engine}")

    engine_bundle = engine.parent
    before_manifest = bundle_manifest(engine_bundle)
    if not before_manifest:
        raise RuntimeError("Bundle do engine está vazio antes do smoke test.")

    root = Path(tempfile.mkdtemp(prefix="cryptoguard_engine_smoke_"))
    password = "CryptoGuard-Smoke-Password-123!"
    protected = [str(engine_bundle), str(engine_bundle.parent), str(engine_bundle.parent.parent)]
    try:
        # Round-trip padrão.
        source = root / "smoke.bin"
        expected = (b"Crypto Guard v4 engine smoke test\n" * 4096)
        source.write_bytes(expected)

        enc = run(engine, {
            "action": "encrypt",
            "path": str(source),
            "password": password,
            "keep_original": True,
            "allow_cancel": False,
            "protected_paths": protected,
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
            "protected_paths": protected,
        })
        restored = Path(dec["result"])
        if restored.read_bytes() != expected:
            raise RuntimeError("Round-trip do engine compilado alterou os bytes.")

        # Smoke test específico do modo extremo em PASTA. Esse teste existe
        # para impedir regressão em que a sobrescrita destrutiva alcance o
        # próprio bundle instalado do motor.
        extreme_dir = root / "extreme-folder"
        (extreme_dir / "sub").mkdir(parents=True)
        expected_a = b"A" * (256 * 1024)
        expected_b = b"B" * (128 * 1024)
        (extreme_dir / "a.bin").write_bytes(expected_a)
        (extreme_dir / "sub" / "b.bin").write_bytes(expected_b)

        extreme_enc = run(engine, {
            "action": "encrypt",
            "path": str(extreme_dir),
            "password": password,
            "keep_original": False,
            "advanced_mode": True,
            "shred_passes": 1,
            "allow_cancel": False,
            "protected_paths": protected,
        })
        extreme_cguard = Path(extreme_enc["result"])
        if extreme_dir.exists():
            raise RuntimeError("Modo extremo não removeu a pasta de teste.")
        if not extreme_cguard.is_file():
            raise RuntimeError("Modo extremo não preservou o contêiner verificado.")
        if not engine.is_file():
            raise RuntimeError("REGRESSÃO CRÍTICA: modo extremo removeu o executável do motor.")

        extreme_dec = run(engine, {
            "action": "decrypt",
            "path": str(extreme_cguard),
            "password": password,
            "keep_encrypted": True,
            "allow_cancel": False,
            "protected_paths": protected,
        })
        restored_dir = Path(extreme_dec["result"])
        if (restored_dir / "a.bin").read_bytes() != expected_a:
            raise RuntimeError("Modo extremo alterou a.bin após round-trip.")
        if (restored_dir / "sub" / "b.bin").read_bytes() != expected_b:
            raise RuntimeError("Modo extremo alterou b.bin após round-trip.")

        after_manifest = bundle_manifest(engine_bundle)
        if before_manifest != after_manifest:
            missing = sorted(set(before_manifest) - set(after_manifest))
            added = sorted(set(after_manifest) - set(before_manifest))
            changed = sorted(k for k in set(before_manifest) & set(after_manifest) if before_manifest[k] != after_manifest[k])
            raise RuntimeError(
                "REGRESSÃO CRÍTICA: modo extremo modificou o bundle do motor. "
                f"missing={missing[:5]} added={added[:5]} changed={changed[:5]}"
            )

        print("OK: engine compilado executou round-trip padrão e modo extremo em pasta sem alterar o próprio bundle.")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
