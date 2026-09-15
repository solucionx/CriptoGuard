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

O usuário recebe somente `CryptoGuard.exe`. O Electron portable extrai recursos temporários durante a execução; o engine Python está incorporado no pacote.

## Repositório público e supply chain

A segurança não depende de esconder o código. O repositório público não contém chaves privadas. Actions oficiais usadas pelo CI são fixadas em commits SHA completos, workflows recebem permissões mínimas e releases são geradas por runner Windows a partir de tags versionadas. A proveniência do build é atestada no GitHub.

O futuro updater tratará GitHub/HTTP como transporte e descoberta; a autorização final de um update dependerá de verificações criptográficas independentes descritas em `UPDATE_SECURITY.md`.
