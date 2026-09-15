$ErrorActionPreference = "Stop"

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)
    $Resolved = (Resolve-Path $Path).Path
    $Stream = [System.IO.File]::OpenRead($Resolved)
    try {
        $Sha256 = [System.Security.Cryptography.SHA256]::Create()
        try { $Bytes = $Sha256.ComputeHash($Stream) }
        finally { $Sha256.Dispose() }
    }
    finally { $Stream.Dispose() }
    return ([System.BitConverter]::ToString($Bytes)).Replace("-", "")
}

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

if ($env:OS -ne "Windows_NT") {
    throw "O instalador do Crypto Guard para Windows deve ser compilado no Windows."
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor DarkBlue
$Package = Get-Content (Join-Path $Root "package.json") -Raw | ConvertFrom-Json
$Version = [string]$Package.version
Write-Host " Crypto Guard $Version - Build Windows" -ForegroundColor Blue
Write-Host " Desenvolvido pela Solucionx" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor DarkBlue
Write-Host ""

# 1) Motor Python autônomo
& (Join-Path $PSScriptRoot "build-engine.ps1")

# 2) Dependências Electron fixadas no package-lock.
if (-not (Test-Path (Join-Path $Root "node_modules\electron\dist\electron.exe"))) {
    Write-Host "[Crypto Guard] Instalando dependências Electron..." -ForegroundColor Cyan
    if (-not (Test-Path (Join-Path $Root "package-lock.json"))) { throw "package-lock.json ausente." }
    & npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci falhou." }
}

# 3) NSIS per-user. Esse target gera latest.yml e blockmap usados pelo electron-updater.
Remove-Item .\release -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[Crypto Guard] Gerando instalador NSIS autoatualizável..." -ForegroundColor Cyan
& npx electron-builder --win nsis --x64 --publish never
if ($LASTEXITCODE -ne 0) { throw "electron-builder falhou." }

$Installer = Join-Path $Root "release\CryptoGuard-Setup.exe"
$Latest = Join-Path $Root "release\latest.yml"
$Blockmap = Join-Path $Root "release\CryptoGuard-Setup.exe.blockmap"
foreach ($File in @($Installer, $Latest, $Blockmap)) {
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        throw "Artefato de atualização não encontrado: $File"
    }
}

# win-unpacked é artefato de trabalho; não entra na Release.
Get-ChildItem .\release -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

$Hash = Get-Sha256Hex -Path $Installer
Set-Content -Path (Join-Path $Root "release\CryptoGuard-Setup.exe.sha256") -Value "$Hash  CryptoGuard-Setup.exe" -Encoding ASCII

Write-Host ""
Write-Host "Build concluído." -ForegroundColor Green
Write-Host "Instalador: $Installer" -ForegroundColor Green
Write-Host "Metadata:   $Latest" -ForegroundColor Green
Write-Host "Blockmap:   $Blockmap" -ForegroundColor Green
Write-Host "SHA-256:    $Hash" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Após a instalação, o Crypto Guard verifica GitHub Releases automaticamente ao iniciar." -ForegroundColor Cyan
