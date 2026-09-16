# Crypto Guard 1.6.5 — Validation record

## Scope

This release hardens **Extreme Mode** after a field report in which the installed cryptographic engine disappeared only when destructive overwrite mode was enabled. The CGUARD v4 file format, Argon2id parameters, HKDF derivation and AES-256-GCM chunk format are unchanged.

## Extreme-mode containment changes

- A full preflight runs **before any byte is overwritten**.
- The installed Crypto Guard directory, `resources`, the engine bundle and the engine executable are passed as protected paths by Electron.
- A frozen PyInstaller engine independently derives and protects its own installed roots even if the caller omits them.
- The shredder rejects symlinks, Windows junctions/reparse points and files with multiple hard links.
- Every candidate path must resolve inside the exact source tree selected by the user.
- Selecting an installation directory, a child of a protected directory, or a parent that contains a protected directory is rejected.
- A post-operation Electron guard verifies that the packaged engine executable still exists after an Extreme Mode operation.

## Automated validation

- 49 Python tests pass, including CGUARD v4 KATs, tamper tests, fuzz-smoke, Extreme Mode containment, hard-link rejection, protected-root rejection, desktop integration and recovery behavior.
- `node --check` passes for `src/main.js`, `src/preload.js` and `src/renderer.js`.
- `python scripts/public-release-audit.py` reports no blocking condition.
- Windows release builds execute `scripts/smoke-engine.py`, which now performs a real **folder encryption in Extreme Mode** and compares a SHA-256 manifest of the complete engine bundle before and after the operation. Any engine file removed or modified blocks the Release.

## Required Windows validation

1. Build the release through GitHub Actions/Windows.
2. Confirm `resources\engine\crypto_guard_engine\crypto_guard_engine.exe` exists after installation.
3. Before testing, record that the complete `resources\engine\crypto_guard_engine` bundle exists.
4. Encrypt a disposable folder in **Extreme Mode** with one pass.
5. Confirm the `.cguard` restores byte-for-byte and the original folder was removed.
6. Confirm the installed engine bundle remains present and unchanged after the operation.
7. Repeat with a disposable folder larger than 2 GiB.
8. Confirm a folder containing a junction/reparse point is rejected before overwriting begins.
9. Confirm normal mode still encrypts/decrypts the same test data successfully.
10. Confirm auto-update from 1.6.4 to 1.6.5 and application restart.

Do not publish the release if the Windows Extreme Mode smoke test modifies or removes any file from the installed engine bundle.
