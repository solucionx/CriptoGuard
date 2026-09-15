# Changelog

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

