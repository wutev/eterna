const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('storage', {
  get: (key) => ipcRenderer.invoke('storage:get', key),
  set: (key, value) => ipcRenderer.invoke('storage:set', key, value),
  delete: (key) => ipcRenderer.invoke('storage:delete', key)
});

contextBridge.exposeInMainWorld('windowControls', {
  minimize: () => ipcRenderer.invoke('window:minimize'),
  maximize: () => ipcRenderer.invoke('window:maximize'),
  close: () => ipcRenderer.invoke('window:close'),
  isMaximized: () => ipcRenderer.invoke('window:isMaximized'),
  onMaximizeChange: (callback) => {
    ipcRenderer.on('window-maximized', (event, isMaximized) => callback(isMaximized));
  },
  onLockVault: (callback) => {
    ipcRenderer.on('lock-vault', () => callback());
  }
});

contextBridge.exposeInMainWorld('appInfo', {
  getVersion: () => ipcRenderer.invoke('app:getVersion'),
  openExternal: (url) => ipcRenderer.invoke('app:openExternal', url),
  quit: () => ipcRenderer.invoke('app:quit')
});

contextBridge.exposeInMainWorld('autoUpdater', {
  checkForUpdates: () => ipcRenderer.invoke('update:check'),
  downloadUpdate: () => ipcRenderer.invoke('update:download'),
  installUpdate: () => ipcRenderer.invoke('update:install'),
  onUpdateStatus: (callback) => {
    ipcRenderer.on('update-status', (event, data) => callback(data));
  }
});

contextBridge.exposeInMainWorld('vault', {
  // Vault initialization and authentication
  isInitialized: () => ipcRenderer.invoke('vault:isInitialized'),
  initialize: (masterPassword) => ipcRenderer.invoke('vault:initialize', masterPassword),
  unlock: (masterPassword) => ipcRenderer.invoke('vault:unlock', masterPassword),
  lock: () => ipcRenderer.invoke('vault:lock'),
  isUnlocked: () => ipcRenderer.invoke('vault:isUnlocked'),

  // Master password management
  changeMasterPassword: (currentPassword, newPassword) =>
    ipcRenderer.invoke('vault:changeMasterPassword', currentPassword, newPassword),
  validatePassword: (password) => ipcRenderer.invoke('vault:validatePassword', password),
  generatePassword: (length, options) => ipcRenderer.invoke('vault:generatePassword', length, options),

  // File encryption
  encryptFile: (fileData) => ipcRenderer.invoke('vault:encryptFile', fileData),
  decryptFile: (encryptedFile) => ipcRenderer.invoke('vault:decryptFile', encryptedFile),

  // Export/Import
  exportBackup: (password) => ipcRenderer.invoke('vault:exportBackup', password),
  importBackup: (backup, password) => ipcRenderer.invoke('vault:importBackup', backup, password),

  // Private Section
  setPrivatePassword: (password) => ipcRenderer.invoke('vault:setPrivatePassword', password),
  unlockPrivate: (password) => ipcRenderer.invoke('vault:unlockPrivate', password),
  resetPrivate: () => ipcRenderer.invoke('vault:resetPrivate')
});

contextBridge.exposeInMainWorld('auditLog', {
  getEntries: (filters) => ipcRenderer.invoke('audit:getEntries', filters),
  clear: () => ipcRenderer.invoke('audit:clear'),
  export: () => ipcRenderer.invoke('audit:export')
});
