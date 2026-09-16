# Checklist de Release pública — Crypto Guard 1.6

## CGUARD v4

- [ ] `python -m unittest discover -s tests -v` passa integralmente.
- [ ] KATs AES-256-GCM, HKDF-SHA-256 e Argon2id+HKDF passam.
- [ ] Vetores em `tests/vectors/manifest.json` mantêm os hashes esperados.
- [ ] Tamper tests rejeitam metadata, ciphertext/tag, chunks reordenados/duplicados, truncamento e bytes extras.
- [ ] Parser rejeita campos extras, ausentes, tipos errados e chaves JSON duplicadas.
- [ ] Fuzz-smoke não produz crash/aceitação inesperada.
- [ ] Teste manual confirma que a origem só é removida depois do round-trip completo com comparação byte a byte.
- [ ] Teste de pasta confirma que o ZIP temporário corresponde à estrutura e aos bytes da origem antes da criptografia.
- [ ] Teste manual de cancelamento preserva a origem e remove temporários.

## Código e segredos

- [ ] `python scripts/public-release-audit.py` termina com sucesso.
- [ ] Não existe `.env`, token, PAT, PFX/P12, chave privada ou credencial no histórico Git.
- [ ] `package-lock.json` está commitado.
- [ ] Dependências Node são instaladas por `npm ci` no CI.
- [ ] `argon2-cffi`, `cryptography` e dependências de build estão fixadas.

## GitHub

- [ ] 2FA/passkey habilitado na conta/organização Solucionx.
- [ ] Secret scanning e push protection habilitados.
- [ ] Private vulnerability reporting habilitado.
- [ ] Dependabot alerts/security updates habilitados.
- [ ] `main` protegida; force-push e exclusão bloqueados.
- [ ] CI, CodeQL e Dependency Review exigidos para merge.
- [ ] Tags `v*` protegidas contra alteração/exclusão.
- [ ] Nome do repositório no `package.json` corresponde ao repositório real que contém as Releases.

## Release Windows

- [ ] A tag `vX.Y.Z` corresponde ao `package.json`.
- [ ] Release é produzida pelo workflow oficial em runner Windows.
- [ ] Engine PyInstaller inicia e executa teste de arquivo/pasta no artefato compilado.
- [ ] `CryptoGuard-Setup.exe.sha256`, `latest.yml` e `.blockmap` acompanham o instalador.
- [ ] SBOM/inventário/build-info são gerados.
- [ ] Build provenance/attestation é gerada quando disponível.
- [ ] Nenhum executável é commitado na branch principal.
- [ ] Quando code signing estiver disponível, Authenticode é aplicado antes dos hashes/attestation finais.

## Modo extremo

- [ ] Confirmar que a sobrescrita só começa após round-trip completo do `.cguard`.
- [ ] Testar 1/2/3/7 passadas em arquivo e pasta.
- [ ] Confirmar que `Manter o original` + modo extremo é rejeitado.
- [ ] Confirmar que falha de verificação nunca chama a remoção extrema.
- [ ] Confirmar aviso de que SSD/NVMe/snapshots/backups não oferecem garantia de apagamento físico.
