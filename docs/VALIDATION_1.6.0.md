# Crypto Guard 1.6.0 — Validation record

Validation performed on the source tree before packaging this delivery.

## Automated checks completed

- Python bytecode compilation: `python -m compileall -q python tests scripts`
- JavaScript syntax: `node --check` for `src/main.js`, `src/preload.js`, and `src/renderer.js`
- Crypto/security suite: **34 tests passed**
- Public repository audit: **no blocking condition found**

The automated suite covers file/folder/empty-file round-trips, wrong passwords,
cancellation, preservation of the original on failure, strict schema parsing,
duplicate JSON keys, non-finite JSON values, KDF/chunk bounds, header/metadata/
ciphertext tampering, chunk reordering/duplication, truncation/trailing bytes,
CSPRNG uniqueness checks, byte-for-byte creation verification, fuzz-smoke tests,
known-answer tests for AES-256-GCM, HKDF-SHA-256 and Argon2id+HKDF, and permanent
CGUARD v4 format vectors, plus modo-extremo validation for pass-count policy, post-round-trip deletion ordering, source preservation on verification failure, verified-container preservation on overwrite failure, and file/directory overwrite-delete behavior.

## Windows build still required

This delivery is the complete source project. The final Windows NSIS artifact must
be produced on Windows (or the repository's Windows GitHub Actions runner), because
the project builds the Python engine with PyInstaller and the desktop installer
with Electron Builder/NSIS. `scripts/build-installer.ps1` includes a smoke test of
the compiled engine before packaging.

Passing this validation is not a substitute for an independent third-party
security audit, code signing, or testing on representative Windows machines.

