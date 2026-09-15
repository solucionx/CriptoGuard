$ErrorActionPreference = "Stop"
Write-Warning "build-portable.ps1 foi mantido apenas por compatibilidade. Desde a v1.5.0 o Crypto Guard usa NSIS para atualização automática."
& (Join-Path $PSScriptRoot "build-installer.ps1")
