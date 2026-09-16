$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

if ($env:OS -ne "Windows_NT") {
    throw "O engine Windows precisa ser compilado no Windows."
}

# Caminhos absolutos. O PyInstaller pode mudar a base de resolucao quando
# --specpath e usado; por isso nao usamos caminhos relativos nos argumentos.
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
$Requirements = Join-Path $Root "python\requirements.txt"
$BuildRequirements = Join-Path $Root "python\requirements-build.txt"
$BridgeFile = Join-Path $Root "python\bridge.py"
$IconFile = Join-Path $Root "build\icon.ico"
$VersionFile = Join-Path $Root "build\engine_version_info.txt"
$EngineDir = Join-Path $Root "engine"
$BuildDir = Join-Path $Root ".build\pyinstaller"
$SpecDir = Join-Path $BuildDir "spec"
$WorkDir = Join-Path $BuildDir "work"
$EngineBundle = Join-Path $EngineDir "crypto_guard_engine"
$Engine = Join-Path $EngineBundle "crypto_guard_engine.exe"

foreach ($RequiredFile in @($Requirements, $BuildRequirements, $BridgeFile, $IconFile, $VersionFile)) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Arquivo necessario para o build nao encontrado: $RequiredFile"
    }
}

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    Write-Host "[Crypto Guard] Criando .venv..." -ForegroundColor Cyan
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv (Join-Path $Root ".venv")
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python -m venv (Join-Path $Root ".venv")
    } else {
        throw "Python 3.10+ nao foi encontrado para compilar o projeto. O usuario final nao precisara de Python."
    }
    if ($LASTEXITCODE -ne 0) { throw "Falha ao criar a .venv." }
}

Write-Host "[Crypto Guard] Instalando dependencias de build fixadas..." -ForegroundColor Cyan
& $VenvPython -m pip install --disable-pip-version-check --no-input -r $Requirements -r $BuildRequirements
if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar dependencias Python." }

Remove-Item -LiteralPath $BuildDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $EngineDir | Out-Null
New-Item -ItemType Directory -Force -Path $SpecDir | Out-Null
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
Remove-Item -LiteralPath $EngineDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $EngineDir | Out-Null

Write-Host "[Crypto Guard] Gerando motor criptografico autonomo..." -ForegroundColor Cyan
$PyInstallerArgs = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onedir",
    "--console",
    "--name", "crypto_guard_engine",
    "--icon", $IconFile,
    "--version-file", $VersionFile,
    "--distpath", $EngineDir,
    "--workpath", $WorkDir,
    "--specpath", $SpecDir,
    "--paths", (Join-Path $Root "python"),
    "--collect-all", "argon2",
    "--collect-all", "_argon2_cffi_bindings",
    $BridgeFile
)

& $VenvPython @PyInstallerArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falhou ao gerar o motor criptografico." }

if (-not (Test-Path -LiteralPath $Engine -PathType Leaf)) {
    throw "O PyInstaller nao gerou engine\crypto_guard_engine\crypto_guard_engine.exe."
}

$EngineSize = (Get-Item -LiteralPath $Engine).Length
if ($EngineSize -lt 128KB) {
    throw "O executavel do motor gerado parece invalido (arquivo muito pequeno: $EngineSize bytes)."
}
$BundleSize = (Get-ChildItem -LiteralPath $EngineBundle -Recurse -File | Measure-Object -Property Length -Sum).Sum
if ($BundleSize -lt 5MB) {
    throw "O bundle do motor parece incompleto (tamanho total: $BundleSize bytes)."
}

Write-Host "[Crypto Guard] Engine onedir pronto: $Engine" -ForegroundColor Green
