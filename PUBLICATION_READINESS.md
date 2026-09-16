# Publicação pública — estado de prontidão

Esta árvore é a base de publicação do Crypto Guard 1.6.5 / CGUARD v4.

## Automatizado no repositório

- CI de sintaxe JavaScript/Python.
- Suíte CGUARD v4 com round-trip, KATs, adulteração, chunking, schema estrito, fuzz-smoke, vetores permanentes e testes específicos do modo extremo.
- Auditoria pré-publicação contra segredos comuns, chaves privadas, executáveis commitados e regressões de hardening.
- CodeQL para JavaScript/TypeScript e Python.
- Dependency Review em Pull Requests e Dependabot para npm/pip/GitHub Actions.
- Actions de segurança/release fixadas em commits SHA completos.
- Electron Fuses no build final.
- Build Windows NSIS com `electron-updater`.
- SHA-256, provenance attestation quando o repositório permite, SBOM npm, inventário Python e `build-info.json` na Release.
- Política privada para vulnerabilidades, threat model e especificação criptográfica.

## Obrigatório antes de publicar v1.6.5

1. Execute `python -m unittest discover -s tests -v`; todos os testes devem passar.
2. Execute `python scripts/public-release-audit.py`; o resultado deve ser `OK`.
3. Execute `npm ci` e `npm run check:js` no mesmo commit que será publicado.
4. Confirme que `package-lock.json` está commitado e que `package.json` está em `1.6.5`.
5. Faça o build em Windows e confirme que o engine PyInstaller `onedir` inclui `argon2-cffi`, `_argon2_cffi_bindings` e aparece em `release/win-unpacked/resources/engine/crypto_guard_engine/` antes do empacotamento final.
6. Confirme que o smoke test Windows do engine executa uma pasta real em **Modo Extremo** e que o manifesto SHA-256 do bundle do motor permanece idêntico antes/depois.
7. Faça um teste manual: arquivo pequeno, arquivo > 1 chunk, pasta > 2 GiB, senha errada, cancelamento, modo extremo em arquivo/pasta descartável e atualização do aplicativo.
8. Revise todo o histórico Git; qualquer credencial antiga deve ser revogada/rotacionada.
9. Confirme as configurações de segurança descritas em `docs/GITHUB_SECURITY_SETTINGS.md`.

## Itens ainda externos ao código

- Authenticode/Publisher verificado depende de um certificado de code signing da Solucionx.
- O updater já existe, mas a identidade criptográfica do publisher fica mais forte quando Authenticode for incorporado ao pipeline.
- A configuração `publish` precisa apontar para o nome real do repositório GitHub usado para Releases antes do build final.
