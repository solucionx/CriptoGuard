# Arquitetura — Crypto Guard 1.6

## Processos

```text
Renderer Electron
    │ API mínima via preload
    ▼
Electron Main
    │ JSON por stdin/stdout
    ▼
bridge.py
    │
    ▼
cryptoguard.engine
    ├─ format_v4 / strict_json
    ├─ kdf (Argon2id + HKDF-SHA-256)
    ├─ container_v4 (AES-256-GCM por chunk)
    ├─ secure_delete (modo extremo best-effort, pós-verificação)
    ├─ archive (pastas)
    └─ io_utils / memory / errors
```

O renderer não possui acesso direto ao Node. O processo principal valida ações e caminhos, cria o subprocesso do motor e transmite senha pelo `stdin`, evitando colocá-la na linha de comando.

## Fronteiras de segurança

A UI é código não privilegiado em sandbox. O `preload` expõe apenas operações necessárias. Navegação externa, criação de novas janelas e permissões do Chromium são bloqueadas pelo `main.js` salvo exceções explícitas do aplicativo.

O motor Python trata todo `.cguard` como input hostil. Parsing barato e limites estruturais ocorrem antes de Argon2id. O arquivo final é criado transacionalmente.

## Cancelamento

O processo Electron cria um arquivo-sinal temporário. O callback de progresso do bridge verifica o sinal entre etapas/chunks e lança `CryptoCancelled`. Caminhos temporários são removidos pelos blocos `finally` do motor.

## Atualizações

O updater permanece separado do motor criptográfico. A instalação de uma atualização baixada só ocorre quando não existem jobs criptográficos ativos. Consulte `UPDATE_SECURITY.md`.
