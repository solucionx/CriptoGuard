const { app, BrowserWindow, dialog, ipcMain, Menu, Notification, session: electronSession } = require('electron');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');


const APP_ID = 'com.solucionx.cryptoguard';
const APP_NAME = 'Crypto Guard';
const DEVELOPER = 'Solucionx';

app.setName(APP_NAME);
if (process.platform === 'win32') {
  // Deve ser definido antes de criar janelas/notificações.
  app.setAppUserModelId(APP_ID);
}

const ICON_PATH = app.isPackaged
  ? path.join(process.resourcesPath, 'app-icon.png')
  : path.join(__dirname, 'assets', 'app-icon.png');
const activeJobs = new Map();

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 920,
    minHeight: 660,
    title: 'Crypto Guard',
    autoHideMenuBar: true,
    backgroundColor: '#0A2E6D',
    icon: ICON_PATH,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false
    }
  });
  // Bloqueia novas janelas e navegação remota. A UI distribuída é totalmente local.
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, targetUrl) => {
    try {
      const parsed = new URL(targetUrl);
      if (parsed.protocol !== 'file:') event.preventDefault();
    } catch {
      event.preventDefault();
    }
  });
  win.loadFile(path.join(__dirname, 'index.html'));
  return win;
}

function buildMenu() {
  const viewSubmenu = [
    { role: 'resetZoom', label: 'Zoom padrão' },
    { role: 'zoomIn', label: 'Aumentar zoom' },
    { role: 'zoomOut', label: 'Diminuir zoom' },
    { type: 'separator' },
    { role: 'togglefullscreen', label: 'Tela cheia' }
  ];
  if (!app.isPackaged) {
    viewSubmenu.unshift(
      { role: 'reload', label: 'Recarregar' },
      { role: 'toggleDevTools', label: 'Ferramentas do desenvolvedor' },
      { type: 'separator' }
    );
  }

  Menu.setApplicationMenu(Menu.buildFromTemplate([
    {
      label: 'Editar',
      submenu: [
        { role: 'undo', label: 'Desfazer' }, { role: 'redo', label: 'Refazer' },
        { type: 'separator' },
        { role: 'cut', label: 'Recortar' }, { role: 'copy', label: 'Copiar' },
        { role: 'paste', label: 'Colar' }, { role: 'selectAll', label: 'Selecionar tudo' }
      ]
    },
    { label: 'Exibir', submenu: viewSubmenu },
    {
      label: 'Ajuda',
      submenu: [{
        label: 'Sobre o Crypto Guard',
        click: () => dialog.showMessageBox({
          type: 'info', title: 'Crypto Guard', message: `Crypto Guard ${app.getVersion()}`,
          detail: `Encrypt / Decrypt Software\nDesenvolvido pela ${DEVELOPER}\nAES-256-GCM · Scrypt\nCriptografia local: seus arquivos não são enviados para servidores.`,
          icon: ICON_PATH
        })
      }]
    }
  ]));
}

function pythonDir() {
  return path.join(__dirname, '..', 'python');
}

function enginePath() {
  return app.isPackaged
    ? path.join(process.resourcesPath, 'engine', 'crypto_guard_engine.exe')
    : path.join(__dirname, '..', 'engine', 'crypto_guard_engine.exe');
}

function pythonCandidates() {
  const projectRoot = path.join(__dirname, '..');
  const localCandidates = process.platform === 'win32'
    ? [path.join(projectRoot, '.venv', 'Scripts', 'python.exe'), path.join(projectRoot, 'venv', 'Scripts', 'python.exe')]
    : [path.join(projectRoot, '.venv', 'bin', 'python'), path.join(projectRoot, 'venv', 'bin', 'python')];
  const existingLocal = localCandidates.filter((candidate) => fs.existsSync(candidate));
  return process.platform === 'win32'
    ? [...existingLocal, 'python', 'py']
    : [...existingLocal, 'python3', 'python'];
}

function isProcessElevated() {
  if (process.platform !== 'win32') return false;
  try {
    const command = '([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)';
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], {
      encoding: 'utf8', windowsHide: true, timeout: 5000
    });
    return String(result.stdout || '').trim().toLowerCase() === 'true';
  } catch {
    return false;
  }
}

function psQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function launchElevatedCopy() {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ ok: false, reason: 'unsupported-platform' });
    if (isProcessElevated()) return resolve({ ok: true, alreadyElevated: true });

    // No alvo portable, process.execPath aponta para a cópia extraída em TEMP.
    // PORTABLE_EXECUTABLE_FILE aponta para o CryptoGuard.exe baixado pelo usuário.
    const executable = (app.isPackaged && process.env.PORTABLE_EXECUTABLE_FILE)
      ? process.env.PORTABLE_EXECUTABLE_FILE
      : process.execPath;
    const args = app.isPackaged ? [] : [app.getAppPath()];
    args.push('--crypto-guard-elevated');
    const argList = args.length ? ` -ArgumentList @(${args.map(psQuote).join(',')})` : '';
    const script = `Start-Process -FilePath ${psQuote(executable)}${argList} -Verb RunAs`;
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true, stdio: ['ignore', 'ignore', 'pipe']
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    child.once('error', (err) => resolve({ ok: false, reason: err.message }));
    child.once('close', (code) => {
      if (code === 0) {
        resolve({ ok: true });
        setTimeout(() => app.quit(), 450);
      } else {
        const cancelled = /canceled|cancelled|cancelada|cancelado/i.test(stderr);
        resolve({ ok: false, cancelled, reason: stderr.trim() || 'O Windows não concedeu a elevação.' });
      }
    });
  });
}

function spawnBackend(command, args, payload, onProgress, { retryable = false, onRetry = null } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
      env: { ...process.env, PYTHONUTF8: '1' }
    });

    let stderr = '';
    let buffer = '';
    let started = false;
    let settled = false;
    let finalResult = null;

    const handleLine = (line) => {
      if (!line.trim()) return;
      let data;
      try { data = JSON.parse(line); } catch { return; }
      if (data.type === 'progress') {
        if (typeof onProgress === 'function') onProgress(data);
      } else if (data.type === 'result') {
        finalResult = data;
      }
    };

    child.once('spawn', () => {
      started = true;
      child.stdin.end(JSON.stringify(payload));
    });
    child.stdout.on('data', (d) => {
      buffer += d.toString('utf8');
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';
      lines.forEach(handleLine);
    });
    child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });
    child.once('error', (err) => {
      if (!started && retryable && (err.code === 'ENOENT' || err.code === 'UNKNOWN') && typeof onRetry === 'function') {
        settled = true;
        return onRetry(err);
      }
      if (!settled) { settled = true; reject(err); }
    });
    child.once('close', () => {
      if (!started || settled) return;
      if (buffer.trim()) handleLine(buffer);
      settled = true;
      if (!finalResult) return reject(new Error(stderr || 'Resposta inválida do motor criptográfico.'));
      if (!finalResult.ok) {
        const err = new Error(finalResult.error || stderr || 'Falha no motor criptográfico.');
        err.cancelled = !!finalResult.cancelled;
        err.code = finalResult.error_code || 'crypto_error';
        err.permissionPath = finalResult.permission_path || null;
        return reject(err);
      }
      resolve(finalResult);
    });
  });
}

function runBridge(payload, onProgress) {
  // Na versão distribuída não há Python externo: o engine PyInstaller viaja
  // dentro do CryptoGuard.exe portátil e é extraído pelo próprio Electron.
  if (app.isPackaged) {
    const engine = enginePath();
    if (!fs.existsSync(engine)) {
      return Promise.reject(new Error('Motor criptográfico interno não encontrado. Rebaixe o CryptoGuard.exe.'));
    }
    return spawnBackend(engine, [], payload, onProgress);
  }

  const bridge = path.join(pythonDir(), 'bridge.py');
  if (!fs.existsSync(bridge)) return Promise.reject(new Error('Motor criptográfico de desenvolvimento não encontrado.'));

  const candidates = pythonCandidates();
  let lastError = null;
  return new Promise((resolve, reject) => {
    const tryNext = () => {
      const command = candidates.shift();
      if (!command) return reject(lastError || new Error('Python não encontrado. Crie/ative a .venv do projeto.'));
      const args = path.basename(command).toLowerCase() === 'py' ? ['-3', bridge] : [bridge];
      spawnBackend(command, args, payload, onProgress, {
        retryable: true,
        onRetry: (err) => { lastError = err; tryNext(); }
      }).then(resolve).catch(reject);
    };
    tryNext();
  });
}

function statInfo(p) {
  try {
    const stat = fs.statSync(p);
    return { path: p, name: path.basename(p), size: stat.isDirectory() ? null : stat.size, isDirectory: stat.isDirectory() };
  } catch {
    return { path: p, name: path.basename(p), size: null, isDirectory: false };
  }
}

function notify(title, body) {
  // Um executável portátil não instala o atalho/AUMID necessário para um toast
  // do Windows com identidade confiável. Evitamos o rótulo electron.app.Electron;
  // a interface já exibe seu próprio toast/modal de conclusão.
  const isWindowsPortable = process.platform === 'win32' && !!process.env.PORTABLE_EXECUTABLE_FILE;
  if (process.platform === 'win32' && (!app.isPackaged || isWindowsPortable)) return;
  if (Notification.isSupported()) new Notification({ title, body, icon: ICON_PATH }).show();
}

ipcMain.handle('pick-files', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({ properties: ['openFile', 'multiSelections'] });
  return canceled ? [] : filePaths.map(statInfo);
});
ipcMain.handle('pick-folder', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({ properties: ['openDirectory'] });
  return canceled || !filePaths[0] ? null : statInfo(filePaths[0]);
});
ipcMain.handle('pick-encrypted-files', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    properties: ['openFile', 'multiSelections'],
    filters: [
      { name: 'Crypto Guard', extensions: ['cguard', 'sxcrypt'] },
      { name: 'Todos os arquivos', extensions: ['*'] }
    ]
  });
  return canceled ? [] : filePaths.map(statInfo);
});
ipcMain.handle('paths-info', async (_event, paths) => Array.isArray(paths) ? paths.slice(0, 500).map(statInfo) : []);
ipcMain.handle('app-info', async () => ({ version: app.getVersion(), platform: process.platform, elevated: isProcessElevated(), packaged: app.isPackaged, developer: DEVELOPER }));
ipcMain.handle('request-elevation', async () => launchElevatedCopy());

ipcMain.handle('crypto-cancel', async (event) => {
  const session = activeJobs.get(event.sender.id);
  if (!session) return { ok: false, reason: 'no-active-job' };
  if (!session.cancellable) return { ok: false, reason: 'unsafe-stage' };
  session.cancelRequested = true;
  try {
    fs.writeFileSync(session.cancelFile, 'cancel', { encoding: 'utf8' });
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
});

ipcMain.handle('crypto-run', async (event, payload) => {
  if (!payload || !['encrypt', 'decrypt'].includes(payload.action)) throw new Error('Operação inválida.');
  const paths = Array.isArray(payload.paths) ? payload.paths.filter((p) => typeof p === 'string').slice(0, 500) : [];
  if (!paths.length) throw new Error('Selecione ao menos um arquivo ou pasta.');
  if (typeof payload.password !== 'string' || !payload.password) throw new Error('Digite a senha.');
  if (activeJobs.has(event.sender.id)) throw new Error('Já existe uma operação em andamento nesta janela.');

  const cancelFile = path.join(os.tmpdir(), `crypto-guard-cancel-${crypto.randomUUID()}.flag`);
  const session = {
    cancelFile,
    cancelRequested: false,
    cancellable: !payload.advancedMode
  };
  activeJobs.set(event.sender.id, session);

  const results = [];
  try {
    for (let i = 0; i < paths.length; i++) {
      if (session.cancelRequested) break;
      const itemPayload = {
        action: payload.action,
        path: paths[i],
        password: payload.password,
        keep_original: !!payload.keepOriginal,
        keep_encrypted: !!payload.keepEncrypted,
        advanced_mode: !!payload.advancedMode,
        shred_passes: Number.isInteger(payload.shredPasses) ? payload.shredPasses : 2,
        allow_cancel: session.cancellable,
        cancel_file: cancelFile
      };
      try {
        const data = await runBridge(itemPayload, ({ processed, total, stage }) => {
          const itemFraction = total > 0 ? Math.min(1, Math.max(0, processed / total)) : 0;
          event.sender.send('crypto-progress', {
            index: i,
            totalItems: paths.length,
            itemPath: paths[i],
            itemName: path.basename(paths[i]),
            processed,
            totalBytes: total,
            stage,
            itemFraction,
            fraction: (i + itemFraction) / paths.length,
            cancellable: session.cancellable
          });
        });
        results.push({ ok: true, path: paths[i], result: data.result });
      } catch (err) {
        results.push({ ok: false, cancelled: !!err.cancelled, path: paths[i], error: err.message, errorCode: err.code || 'crypto_error', permissionPath: err.permissionPath || null });
        if (err.cancelled || session.cancelRequested) break;
      }
      event.sender.send('crypto-progress', {
        index: i + 1, totalItems: paths.length, itemPath: paths[i], itemName: path.basename(paths[i]),
        fraction: (i + 1) / paths.length, itemFraction: 1, processed: 0, totalBytes: 0,
        stage: 'done', cancellable: session.cancellable
      });
    }
  } finally {
    activeJobs.delete(event.sender.id);
    try { fs.unlinkSync(cancelFile); } catch { /* arquivo pode não existir */ }
  }

  const cancelled = session.cancelRequested || results.some((r) => r.cancelled);
  const okCount = results.filter((r) => r.ok).length;
  if (!cancelled) {
    notify('Crypto Guard', `${okCount} de ${paths.length} item(ns) ${payload.action === 'encrypt' ? 'protegido(s)' : 'restaurado(s)'} com sucesso.`);
  }
  return { results, cancelled, requested: paths.length };
});

app.whenReady().then(() => {
  // O renderer não precisa de câmera, microfone, geolocalização, MIDI etc.
  // Nega permissões web por padrão para reduzir a superfície de ataque.
  electronSession.defaultSession.setPermissionCheckHandler(() => false);
  electronSession.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  buildMenu();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
