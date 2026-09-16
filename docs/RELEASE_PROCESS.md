# Processo de Release

Releases oficiais não devem ser produzidas manualmente e depois anexadas ao GitHub. O binário oficial deve nascer do workflow versionado `.github/workflows/release-windows.yml`.

## Antes da release

1. Trabalhe em branch e abra Pull Request para `main`.
2. Aguarde CI, CodeQL, Dependency Review e Public Repository Audit.
3. Atualize `package.json` e `CHANGELOG.md`.
4. Revise cuidadosamente mudanças em `python/`, `src/main.js`, `src/preload.js`, `scripts/`, `.github/workflows/` e `docs/UPDATE_SECURITY.md`.
5. Faça merge somente com os checks exigidos pelo Ruleset.
6. Garanta que `main` esteja limpa e que o `package-lock.json` esteja commitado.

## Tag

A tag precisa corresponder exatamente à versão do `package.json`:

```powershell
git checkout main
git pull --ff-only
git tag -s v1.6.1 -m "Crypto Guard v1.6.1"
git push origin v1.6.1
```

Se você ainda não usa assinatura GPG/SSH de tags, configure-a antes da primeira release pública quando possível. Nunca mova uma tag já publicada.

## Workflow oficial

O workflow:

- faz checkout do commit exato da tag;
- verifica tag ↔ `package.json`;
- exige `package-lock.json`;
- executa auditoria pré-publicação e testes;
- instala dependências Node pelo lockfile;
- compila o engine Python e o instalador NSIS em runner Windows;
- gera `CryptoGuard-Setup.exe`, `.blockmap`, `latest.yml` e SHA-256;
- gera SBOM npm, inventário Python e `build-info.json`;
- gera provenance/attestation do executável;
- publica os artefatos na GitHub Release.

## Imutabilidade

Uma Release já publicada nunca deve ser silenciosamente substituída. Se houver problema em `v1.6.0`, corrija e publique uma nova versão, por exemplo `v1.6.1`. O Ruleset de tags `v*` deve bloquear alteração e exclusão.

## Assinatura Authenticode

Enquanto não houver certificado de code signing da Solucionx, o Windows pode exibir publisher desconhecido. Quando o certificado estiver disponível, a assinatura deve entrar no pipeline **antes** do SHA-256/attestation final e deve ser verificada pelo workflow. A v1.5.0 já suporta auto-update NSIS com verificação de metadata/hash. Authenticode deve ser adicionado assim que houver certificado da Solucionx para fortalecer a identidade criptográfica do publisher.
