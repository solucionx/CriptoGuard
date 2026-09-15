@echo off
setlocal
cd /d "%~dp0"
echo.
echo ==============================================
echo  Crypto Guard - Preparar repositorio publico
echo  Desenvolvido pela Solucionx
echo ==============================================
echo.

where node >nul 2>&1 || (echo ERRO: Node.js nao encontrado.& exit /b 1)
where npm >nul 2>&1 || (echo ERRO: npm nao encontrado.& exit /b 1)
where py >nul 2>&1 || where python >nul 2>&1 || (echo ERRO: Python nao encontrado.& exit /b 1)

echo [1/4] Gerando/atualizando package-lock.json sem executar scripts de pacotes...
call npm install --package-lock-only --ignore-scripts
if errorlevel 1 exit /b 1

echo [2/4] Instalando dependencias Node a partir do lockfile...
call npm ci
if errorlevel 1 exit /b 1

echo [3/4] Validando codigo e testes...
call npm run check:js
if errorlevel 1 exit /b 1
call npm run test:python
if errorlevel 1 exit /b 1

echo [4/4] Auditoria de publicacao...
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" scripts\public-release-audit.py
) else (
  py -3 scripts\public-release-audit.py 2>nul || python scripts\public-release-audit.py
)
if errorlevel 1 exit /b 1

echo.
echo PRONTO. Revise docs\PUBLIC_RELEASE_CHECKLIST.md antes de mudar para Public.
exit /b 0
