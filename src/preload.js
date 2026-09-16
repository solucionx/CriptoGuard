const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('cryptoGuard', {
  pickFiles: () => ipcRenderer.invoke('pick-files'),
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  pickEncryptedFiles: () => ipcRenderer.invoke('pick-encrypted-files'),
  pathsInfo: (paths) => ipcRenderer.invoke('paths-info', paths),
  runCrypto: (payload) => ipcRenderer.invoke('crypto-run', payload),
  cancelCrypto: () => ipcRenderer.invoke('crypto-cancel'),
  getAppInfo: () => ipcRenderer.invoke('app-info'),
  checkForUpdates: () => ipcRenderer.invoke('update-check'),
  installUpdate: () => ipcRenderer.invoke('update-install'),
  requestElevation: () => ipcRenderer.invoke('request-elevation'),
  consumeOpenFiles: () => ipcRenderer.invoke('consume-open-files'),
  getPathForFile: (file) => webUtils.getPathForFile(file),
  onProgress: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on('crypto-progress', listener);
    return () => ipcRenderer.removeListener('crypto-progress', listener);
  },
  onUpdateStatus: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on('update-status', listener);
    return () => ipcRenderer.removeListener('update-status', listener);
  },
  onOpenEncryptedFiles: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on('open-cguard-files', listener);
    return () => ipcRenderer.removeListener('open-cguard-files', listener);
  }
});
