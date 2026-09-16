@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ==========================================
echo  Crypto Guard 1.6.5 - Build Installer
echo  Auto Update via GitHub Releases
echo  Desenvolvido pela Solucionx
echo ==========================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\build-installer.ps1"
echo.
if errorlevel 1 (
  echo O build falhou. Leia o erro acima.
) else (
  echo Pronto: release\CryptoGuard-Setup.exe
  echo Metadata: release\latest.yml
)
pause
