# Changelog

## 1.5.1 — 2026-09-15

- Simplifica Aparência para apenas temas Claro e Escuro.
- Remove personalização de paleta, cor de destaque, arredondamento e densidade.
- Reorganiza a tela Sobre e corrige o alinhamento do crédito “Desenvolvido pela Solucionx”.
- Refina o estado visual de atualização e os rótulos técnicos em português.
- Mantém o instalador NSIS com branding personalizado e o fluxo de autoatualização via GitHub Releases.


## 1.5.0 — Auto Update

- Migração da distribuição Windows de portable para instalador NSIS per-user.
- Verificação automática de atualização ao iniciar.
- Download automático de Releases estáveis pelo `electron-updater`.
- Bloqueio de pre-release e downgrade.
- Atualização aguarda operações de criptografia/descriptografia terminarem antes de instalar.
- Geração de `latest.yml` e `.blockmap` no pipeline.
- Botão manual “Verificar atualização agora” na tela Sobre.
- Site deve apontar para `CryptoGuard-Setup.exe` a partir desta versão.

Todas as alterações relevantes do Crypto Guard serão registradas aqui.

## [1.4.1] - 2026-09-15

### Corrigido
- Build do engine PyInstaller agora usa caminhos absolutos.
- Evita resolução incorreta de `engine_version_info.txt` a partir do diretório de spec.

### Mantido
- Distribuição Windows em um único `CryptoGuard.exe` portátil.
- Marca Crypto Guard, desenvolvido pela Solucionx.
- AES-256-GCM + Scrypt, streaming e compatibilidade com `.sxcrypt` legado.

## Unreleased — Public repository hardening

- CodeQL para JavaScript/TypeScript e Python.
- Dependency Review em Pull Requests.
- GitHub Actions fixadas por commit SHA nos workflows de segurança/release.
- Dependências diretas críticas atualizadas.
- Release com provenance attestation, SHA-256, inventário Python, build-info e SBOM npm.

