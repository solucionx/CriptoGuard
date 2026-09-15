# Checklist para tornar o repositório público

Antes de mudar a visibilidade para **Public**, execute `PREPARE_PUBLIC_REPO.bat` e confirme todos os itens abaixo.

## Código e segredos

- [ ] `python scripts/public-release-audit.py` termina com sucesso.
- [ ] Não existe `.env`, token, PAT, PFX/P12, chave privada ou credencial no histórico Git.
- [ ] Se algum segredo já esteve no histórico, ele foi **revogado/rotacionado**, não apenas apagado.
- [ ] `package-lock.json` está commitado.
- [ ] Dependências Node foram instaladas com `npm ci` no CI.
- [ ] Versões Python de build/runtime estão fixadas no repositório.

## GitHub

- [ ] 2FA/passkey habilitado na conta/organização Solucionx.
- [ ] Secret scanning e push protection habilitados.
- [ ] Private vulnerability reporting habilitado.
- [ ] Dependabot alerts e security updates habilitados.
- [ ] Branch `main` protegida por Ruleset.
- [ ] Force-push e exclusão da `main` bloqueados.
- [ ] CI, CodeQL e Dependency Review exigidos para merge.
- [ ] Tags `v*` protegidas contra alteração/exclusão.
- [ ] GitHub Actions configurado para permitir somente Actions confiáveis e, quando disponível, exigir SHA completo.
- [ ] Workflow permissions padrão configuradas como **Read repository contents**.

## Release

- [ ] A tag `vX.Y.Z` corresponde ao `package.json`.
- [ ] Release é produzida exclusivamente pelo workflow oficial em runner Windows.
- [ ] `CryptoGuard-Setup.exe.sha256`, `latest.yml` e `.blockmap` acompanham o instalador.
- [ ] Build provenance/attestation gerada.
- [ ] Nenhum executável é commitado na branch principal.
- [ ] Quando code signing estiver disponível, Authenticode deve ser obrigatório antes de atualizações automáticas silenciosas.
