$ErrorActionPreference = "Stop"

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Resolved = (Resolve-Path $Path).Path
    $Stream = [System.IO.File]::OpenRead($Resolved)
    try {
        $Sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $Bytes = $Sha256.ComputeHash($Stream)
        }
        finally {
            $Sha256.Dispose()
        }
    }
    finally {
        $Stream.Dispose()
    }

    return ([System.BitConverter]::ToString($Bytes)).Replace("-", "")
}


$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

if ($env:OS -ne "Windows_NT") {
    throw "O CryptoGuard.exe para Windows deve ser compilado no Windows."
}

Write-Host "" 
Write-Host "==========================================" -ForegroundColor DarkBlue
Write-Host " Crypto Guard 1.4.1 - Build Single EXE" -ForegroundColor Blue
Write-Host " Desenvolvido pela Solucionx" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor DarkBlue
Write-Host ""

# 1) Motor Python autônomo
& (Join-Path $PSScriptRoot "build-engine.ps1")

# 2) Dependências Electron (somente na máquina de desenvolvimento/build)
if (-not (Test-Path (Join-Path $Root "node_modules\electron\dist\electron.exe"))) {
    Write-Host "[Crypto Guard] Instalando dependências Electron..." -ForegroundColor Cyan
    if (-not (Test-Path (Join-Path $Root "package-lock.json"))) { throw "package-lock.json ausente. Execute PREPARE_PUBLIC_REPO.bat primeiro." }
    & npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci falhou." }
}

# 3) Gera apenas o alvo portable: um único CryptoGuard.exe
Remove-Item .\release -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[Crypto Guard] Gerando CryptoGuard.exe portátil..." -ForegroundColor Cyan
& npx electron-builder --win portable --x64 --publish never
if ($LASTEXITCODE -ne 0) { throw "electron-builder falhou." }

$Output = Join-Path $Root "release\CryptoGuard.exe"
if (-not (Test-Path $Output)) {
    throw "Build final não encontrado em release\CryptoGuard.exe."
}

# O electron-builder mantém uma pasta win-unpacked para trabalho. Ela não faz
# parte da distribuição: o usuário/site recebe somente CryptoGuard.exe.
Get-ChildItem .\release -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Get-ChildItem .\release -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "CryptoGuard.exe" } | Remove-Item -Force

$Hash = Get-Sha256Hex -Path $Output
Set-Content -Path (Join-Path $Root "release\CryptoGuard.exe.sha256") -Value "$Hash  CryptoGuard.exe" -Encoding ASCII

Write-Host ""
Write-Host "Build concluído." -ForegroundColor Green
Write-Host "Arquivo: $Output" -ForegroundColor Green
Write-Host "SHA-256: $Hash" -ForegroundColor DarkGray
Write-Host ""
Write-Host "O usuário final precisa apenas do CryptoGuard.exe." -ForegroundColor Cyan
