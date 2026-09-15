# Crypto Guard

**Encrypt / Decrypt Software — desenvolvido pela Solucionx**

Crypto Guard é um aplicativo desktop para Windows que criptografa e descriptografa arquivos e pastas localmente. Arquivos e senhas não são enviados para servidores pelo fluxo criptográfico do aplicativo.


## Segurança

O motor utiliza AES-256-GCM com chave derivada por Scrypt, salt/nonce aleatórios, streaming para arquivos grandes e autenticação do contêiner. A senha não é armazenada e não existe chave mestra. O Electron mantém `contextIsolation`, `sandbox` e `nodeIntegration: false`.

A documentação técnica está em:

- `SECURITY.md` — reporte privado de vulnerabilidades;
- `docs/CRYPTOGRAPHY.md` — parâmetros e formato criptográfico;
- `docs/THREAT_MODEL.md` — ameaças tratadas e limites;
- `docs/ARCHITECTURE.md` — fronteiras Electron ↔ engine;
- `docs/UPDATE_SECURITY.md` — modelo do futuro atualizador seguro.

## Arquitetura

```text
Renderer HTML/CSS/JS
        │ IPC mínimo via preload
        ▼
Electron Main
        │ stdin/stdout JSON
        ▼
Crypto Engine (Python empacotado)
        │
        └── AES-256-GCM + Scrypt + .cguard
```

## Desenvolvimento

Ambiente recomendado para builds reproduzíveis do Windows:

- Windows 10/11 x64;
- Node.js 24.20.x;
- Python 3.12.x.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\python\requirements.txt
npm install
npm start
```

## Testes

```powershell
python -m unittest discover -s tests -v
node --check .\src\main.js
node --check .\src\preload.js
node --check .\src\renderer.js
python .\scripts\public-release-audit.py
```

## Build Windows — single EXE

```powershell
npm run build:win
```

Saída de distribuição:

```text
release/
├── CryptoGuard.exe
└── CryptoGuard.exe.sha256
```

Executáveis de build não são commitados na `main`; releases oficiais devem ser produzidas pelo workflow de release.

## GitHub público

A edição pública foi preparada para Secret Scanning/Push Protection, Dependabot, Dependency Review, CodeQL, CI e provenance/attestation de Release. Algumas proteções são configurações do GitHub e precisam ser ativadas conforme `docs/GITHUB_SECURITY_SETTINGS.md`.

## Atualizações

O app não deve simplesmente baixar e executar o EXE mais recente. O futuro updater exigirá manifesto assinado, SHA-256, anti-downgrade e, quando disponível, Authenticode da Solucionx. Veja `docs/UPDATE_SECURITY.md`.

## Estrutura

```text
.github/       CI, CodeQL, dependency review, release, templates
build/         recursos e metadados de build
docs/          arquitetura, criptografia, threat model e procedimentos
python/        motor criptográfico
scripts/       build e auditoria pré-publicação
security/      somente material público/placeholder de verificação
src/           Electron e interface
tests/         testes automatizados
```

## Marca e direitos

Produto: **Crypto Guard**  
Desenvolvido por: **Solucionx**  
App ID: `com.solucionx.cryptoguard`  
Extensão atual: `.cguard`  
Compatibilidade legada: `.sxcrypt`

