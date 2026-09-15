const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('cryptoGuard', {
  pickFiles: () => ipcRenderer.invoke('pick-files'),
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  pickEncryptedFiles: () => ipcRenderer.invoke('pick-encrypted-files'),
  pathsInfo: (paths) => ipcRenderer.invoke('paths-info', paths),
  runCrypto: (payload) => ipcRenderer.invoke('crypto-run', payload),
  cancelCrypto: () => ipcRenderer.invoke('crypto-cancel'),
  getAppInfo: () => ipcRenderer.invoke('app-info'),
  requestElevation: () => ipcRenderer.invoke('request-elevation'),
  getPathForFile: (file) => webUtils.getPathForFile(file),
  onProgress: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on('crypto-progress', listener);
    return () => ipcRenderer.removeListener('crypto-progress', listener);
  }
});
