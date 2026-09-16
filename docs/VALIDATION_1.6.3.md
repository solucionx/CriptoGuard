# Crypto Guard 1.6.3 — Validation record

## Scope

This release is a focused updater reliability fix over 1.6.2. No CGUARD v4 cryptographic code was changed.

## Update behavior

- automatic check on startup: preserved
- automatic background download: preserved
- immediate silent install after download: removed
- explicit **Install and restart** action: added
- NSIS install call: `quitAndInstall(false, true)`
- `autoInstallOnAppQuit`: disabled
- updater-owned quit sequence is not pre-empted by `window-all-closed`

## Required Windows validation

1. Install an older signed/released build.
2. Publish a newer test release.
3. Confirm the older build discovers and downloads it without closing unexpectedly.
4. Click **Instalar e reiniciar**.
5. Confirm the NSIS installer runs, updates the app, and Crypto Guard reopens on the new version.
6. Confirm `.cguard` association, Extreme Mode and UAC flows still work.

The final restart/install behavior must be validated on Windows with real release artifacts; static/unit tests cannot fully emulate NSIS process replacement.
