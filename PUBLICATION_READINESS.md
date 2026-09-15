# Publicação pública — estado de prontidão

Esta árvore foi preparada para ser a base pública oficial de `Solucionx/CryptoGuard`.

## Automatizado no repositório

- CI de sintaxe e testes de round-trip.
- auditoria local/CI contra segredos comuns, chaves privadas, executáveis commitados e regressões de hardening Electron;
- CodeQL para JavaScript/TypeScript e Python;
- Dependency Review para Pull Requests;
- Dependabot para npm, pip e GitHub Actions;
- Actions de segurança/release fixadas em commits SHA completos;
- permissões mínimas de workflows;
- Electron Fuses no build final;
- SHA-256, provenance attestation, SBOM npm, inventário Python e build-info na Release;
- política privada para vulnerabilidades;
- threat model, documentação criptográfica e política do futuro updater.

## Obrigatório antes de mudar a visibilidade

1. Execute `PREPARE_PUBLIC_REPO.bat` em Windows conectado à internet.
2. Confirme que `package-lock.json` foi criado e adicione-o ao commit.
3. Execute novamente `python scripts/public-release-audit.py`; ele deve terminar em `OK`.
4. Revise todo o histórico Git. Se qualquer segredo já foi commitado em algum momento, **revogue/rotacione primeiro**; apagar o arquivo não torna o segredo seguro.
5. Configure no GitHub os controles descritos em `docs/GITHUB_SECURITY_SETTINGS.md`.
6. Só então altere Visibility para Public.

## Pendências deliberadas

- Authenticode/Publisher verificado depende de um certificado de code signing da Solucionx.
- O updater automático ainda não está habilitado; antes disso será implementada verificação de manifesto assinado + hash + anti-downgrade + Authenticode.
