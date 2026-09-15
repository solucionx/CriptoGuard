# Arquitetura

## Visão geral

```text
Renderer (HTML/CSS/JS)
        │ IPC limitado via preload
        ▼
Electron Main
        │ stdin/stdout JSON
        ▼
Crypto Engine (Python empacotado)
        │
        ├─ AES-256-GCM
        ├─ Scrypt
        ├─ streaming
        └─ contêiner .cguard
```

## Fronteiras de confiança

- O renderer não recebe acesso direto ao Node.js.
- `contextIsolation` e `sandbox` permanecem ativos.
- A senha não é enviada por argumento de linha de comando.
- O engine valida cabeçalhos, caminhos, ZIPs e parâmetros KDF antes de operar.
- O original só é removido depois da criação e verificação do contêiner no modo normal.

## Distribuição

O usuário baixa `CryptoGuard-Setup.exe` e instala o aplicativo por usuário através do NSIS. O engine Python permanece incorporado nos recursos do aplicativo.

O processo principal também contém o módulo de atualização. Ele consulta apenas a origem de update configurada no build (`solucionx/CryptoGuard`) e não recebe tokens ou URLs de atualização do renderer.

## Repositório público e supply chain

A segurança não depende de esconder o código. O repositório público não contém chaves privadas. Actions oficiais usadas pelo CI são fixadas em commits SHA completos, workflows recebem permissões mínimas e releases são geradas por runner Windows a partir de tags versionadas. A proveniência do build é atestada no GitHub.

O updater da v1.5.1 usa o fluxo NSIS suportado pelo `electron-updater`, com metadata/hashes da Release, bloqueio de downgrade e instalação apenas fora de operações criptográficas. Limites e próximas camadas estão em `UPDATE_SECURITY.md`.
