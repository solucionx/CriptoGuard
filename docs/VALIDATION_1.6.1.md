# Crypto Guard 1.6.1 — Validation record

Esta revisão restaura integrações de desktop/UX sem alterar o formato criptográfico CGUARD v4.

## Verificações desta revisão

- Sintaxe JavaScript de `main.js`, `preload.js` e `renderer.js`.
- Suíte Python criptográfica, de Modo Extremo e integração desktop: **37 testes passaram**.
- Associação `.cguard` declarada no Electron Builder com ícone do Crypto Guard.
- Caminho de abertura externa `.cguard`: argumento de processo → instância única → IPC restrito → tela **Descriptografar**.
- Reutilização da janela existente ao abrir um segundo `.cguard`.
- Relançamento UAC continua fora do bloqueio de instância única.
- Correção de alinhamento do status lateral e do crédito Solucionx.
- Workflow de Release preserva execução UTF-8 para `pip inspect`.
- Auditoria pré-publicação: **OK — nenhuma condição bloqueadora**.

O instalador NSIS final deve ser testado em Windows para confirmar visualmente o registro do ícone/nome da extensão e o duplo clique no Explorer.
