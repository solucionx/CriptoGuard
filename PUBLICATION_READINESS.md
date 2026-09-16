# Publicação pública — estado de prontidão

Esta árvore é a base de publicação do Crypto Guard 1.6.1 / CGUARD v4.

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

## Obrigatório antes de publicar v1.6.1

1. Execute `python -m unittest discover -s tests -v`; todos os testes devem passar.
2. Execute `python scripts/public-release-audit.py`; o resultado deve ser `OK`.
3. Execute `npm ci` e `npm run check:js` no mesmo commit que será publicado.
4. Confirme que `package-lock.json` está commitado e que `package.json` está em `1.6.1`.
5. Faça o build em Windows e confirme que o engine PyInstaller inclui `argon2-cffi` e `_argon2_cffi_bindings`.
6. Faça um teste manual: arquivo pequeno, arquivo > 1 chunk, pasta, senha errada, cancelamento, modo extremo em arquivo/pasta de teste e atualização do aplicativo.
7. Revise todo o histórico Git; qualquer credencial antiga deve ser revogada/rotacionada.
8. Confirme as configurações de segurança descritas em `docs/GITHUB_SECURITY_SETTINGS.md`.

## Itens ainda externos ao código

- Authenticode/Publisher verificado depende de um certificado de code signing da Solucionx.
- O updater já existe, mas a identidade criptográfica do publisher fica mais forte quando Authenticode for incorporado ao pipeline.
- A configuração `publish` precisa apontar para o nome real do repositório GitHub usado para Releases antes do build final.
