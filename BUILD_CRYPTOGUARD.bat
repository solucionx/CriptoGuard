@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ==========================================
echo  Crypto Guard - Build Single EXE
echo  Desenvolvido pela Solucionx
echo ==========================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\build-portable.ps1"
echo.
if errorlevel 1 (
  echo O build falhou. Leia o erro acima.
) else (
  echo Pronto: release\CryptoGuard.exe
)
pause
