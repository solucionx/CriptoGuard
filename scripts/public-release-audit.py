from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "release", "dist", ".build", "engine"}
TEXT_EXTS = {".js", ".json", ".py", ".ps1", ".bat", ".md", ".yml", ".yaml", ".txt", ".html", ".css", ".toml", ".ini", ".cfg"}
FORBIDDEN_NAMES = {".env", "id_rsa", "id_ed25519"}
FORBIDDEN_SUFFIXES = {".pfx", ".p12", ".key", ".jks", ".keystore"}
SECRET_PATTERNS = {
    "GitHub token": re.compile(r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})"),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Slack token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

errors: list[str] = []
warnings: list[str] = []


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def iter_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        yield path


for path in iter_files():
    if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        errors.append(f"arquivo sensível não pode ser versionado: {rel(path)}")
    if path.suffix.lower() == ".exe":
        errors.append(f"executável não deve ser commitado na árvore fonte: {rel(path)}")
    if path.suffix.lower() not in TEXT_EXTS and path.name not in {".gitignore", ".gitattributes", ".npmrc", ".nvmrc"}:
        continue
    try:
        text = path.read_text("utf-8", errors="replace")
    except OSError as exc:
        errors.append(f"não foi possível ler {rel(path)}: {exc}")
        continue
    # Exemplos/documentação podem conter apenas prefixos curtos; os padrões exigem forma plausível completa.
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            errors.append(f"possível {label} encontrado em {rel(path)}")

required = [
    "SECURITY.md", "SOURCE_AVAILABLE_NOTICE.md", "docs/THREAT_MODEL.md",
    "docs/CRYPTOGRAPHY.md", "scripts/after-pack.mjs", ".github/CODEOWNERS", ".github/dependabot.yml",
    ".github/workflows/ci.yml", ".github/workflows/codeql.yml",
    ".github/workflows/dependency-review.yml", ".github/workflows/release-windows.yml",
]
for name in required:
    if not (ROOT / name).exists():
        errors.append(f"arquivo obrigatório ausente: {name}")

package_path = ROOT / "package.json"
try:
    package = json.loads(package_path.read_text("utf-8"))
    if package.get("private") is not True:
        errors.append("package.json deve manter private=true para impedir publicação acidental no npm")
    if package.get("license") != "UNLICENSED":
        warnings.append("package.json não está marcado como UNLICENSED; confirme a licença antes de publicar")
    if package.get("devDependencies", {}).get("@electron/fuses") != "2.1.3":
        errors.append("@electron/fuses deve estar fixado na versão revisada 2.1.3")
    if package.get("build", {}).get("afterPack") != "scripts/after-pack.mjs":
        errors.append("hook afterPack de Electron Fuses ausente")
except Exception as exc:
    errors.append(f"package.json inválido: {exc}")

if not (ROOT / "package-lock.json").exists():
    errors.append("package-lock.json ausente: execute PREPARE_PUBLIC_REPO.bat e versione o lockfile antes de tornar público")

main_js = (ROOT / "src/main.js").read_text("utf-8", errors="replace")
for required_snippet in ("contextIsolation: true", "nodeIntegration: false", "sandbox: true", "webSecurity: true", "allowRunningInsecureContent: false", "webviewTag: false"):
    if required_snippet not in main_js:
        errors.append(f"hardening Electron ausente: {required_snippet}")
if ".loadURL(" in main_js:
    warnings.append("main.js contém loadURL(); revise qualquer conteúdo remoto antes da publicação")


# GitHub Actions: third-party/reusable actions must be pinned to a 40-char commit SHA.
workflow_dir = ROOT / ".github" / "workflows"
uses_re = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
sha_ref_re = re.compile(r"^[^/\s]+/[^@\s]+@[0-9a-fA-F]{40}$")
for workflow in workflow_dir.glob("*.yml"):
    text = workflow.read_text("utf-8", errors="replace")
    if re.search(r"^\s*permissions:\s*(?:write-all|read-all)\s*$", text, re.MULTILINE):
        errors.append(f"permissão ampla proibida em {rel(workflow)}")
    for match in uses_re.finditer(text):
        ref = match.group(1).strip().strip("'\"")
        if ref.startswith("./"):
            continue
        if not sha_ref_re.match(ref):
            errors.append(f"GitHub Action não fixada em SHA completo em {rel(workflow)}: {ref}")

index_html = (ROOT / "src/index.html").read_text("utf-8", errors="replace")
if "Content-Security-Policy" not in index_html:
    errors.append("CSP ausente em src/index.html")
if "'unsafe-eval'" in index_html or "'unsafe-inline'" in index_html:
    errors.append("CSP contém unsafe-eval/unsafe-inline")

print("Crypto Guard — auditoria pré-publicação")
for item in warnings:
    print(f"[AVISO] {item}")
for item in errors:
    print(f"[ERRO] {item}")
if errors:
    print(f"\nFalhou com {len(errors)} erro(s). Corrija antes de tornar o repositório público.")
    sys.exit(1)
print("\nOK: nenhuma condição bloqueadora foi encontrada.")
