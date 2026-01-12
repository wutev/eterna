const { app, BrowserWindow, ipcMain, shell, Tray, Menu, nativeImage } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');

// Set app name for Windows task manager and dialogs
app.setName('EternaVault');

// Configure auto-updater
autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = true;

const dataPath = path.join(app.getPath('userData'), 'vault-data.json');
let mainWindow = null;
let tray = null;
let isQuitting = false;

function createTray() {
  const trayIconPath = path.join(__dirname, 'tray-icon.png');
  const iconPath = path.join(__dirname, 'icon.png');

  let trayIcon;
  if (fs.existsSync(trayIconPath)) {
    trayIcon = nativeImage.createFromPath(trayIconPath);
  } else if (fs.existsSync(iconPath)) {
    trayIcon = nativeImage.createFromPath(iconPath);
    trayIcon = trayIcon.resize({ width: 16, height: 16 });
  } else {
    trayIcon = nativeImage.createFromDataURL('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAARklEQVQ4T2NkoBAwUqifYdQABkrDgGwX/Scl4pFdQMgLyC4gJgwINoCYQEZ2ATFhgOwCYsIA2QXEhAGyC4gJA2QXEBcGAE/gDBE5mC2dAAAAAElFTkSuQmCC');
  }

  tray = new Tray(trayIcon);

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show EternaVault',
      click: () => {
        mainWindow?.show();
        mainWindow?.focus();
      }
    },
    {
      label: 'Lock Vault',
      click: () => {
        mainWindow?.webContents.send('lock-vault');
      }
    },
    { type: 'separator' },
    {
      label: 'Check for Updates',
      click: () => {
        autoUpdater.checkForUpdates();
      }
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('EternaVault');
  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    mainWindow?.show();
    mainWindow?.focus();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    title: 'EternaVault',
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    backgroundColor: '#0a0a14',
    show: false
  });

  mainWindow.loadFile('index.html');

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('maximize', () => {
    mainWindow?.webContents.send('window-maximized', true);
  });

  mainWindow.on('unmaximize', () => {
    mainWindow?.webContents.send('window-maximized', false);
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow?.hide();
      return false;
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ============ AUTO-UPDATER EVENTS ============
autoUpdater.on('checking-for-update', () => {
  mainWindow?.webContents.send('update-status', { status: 'checking' });
});

autoUpdater.on('update-available', (info) => {
  mainWindow?.webContents.send('update-status', {
    status: 'available',
    version: info.version,
    releaseNotes: info.releaseNotes
  });
});

autoUpdater.on('update-not-available', () => {
  mainWindow?.webContents.send('update-status', { status: 'not-available' });
});

autoUpdater.on('download-progress', (progress) => {
  mainWindow?.webContents.send('update-status', {
    status: 'downloading',
    percent: Math.round(progress.percent),
    transferred: progress.transferred,
    total: progress.total
  });
});

autoUpdater.on('update-downloaded', (info) => {
  mainWindow?.webContents.send('update-status', {
    status: 'downloaded',
    version: info.version
  });
});

autoUpdater.on('error', (err) => {
  mainWindow?.webContents.send('update-status', {
    status: 'error',
    message: err.message
  });
});

// ============ IPC HANDLERS ============
ipcMain.handle('window:minimize', () => {
  mainWindow?.minimize();
});

ipcMain.handle('window:maximize', () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow?.maximize();
  }
});

ipcMain.handle('window:close', () => {
  mainWindow?.hide();
});

ipcMain.handle('window:isMaximized', () => {
  return mainWindow?.isMaximized() || false;
});

ipcMain.handle('app:getVersion', () => {
  return app.getVersion();
});

ipcMain.handle('app:openExternal', (event, url) => {
  shell.openExternal(url);
});

ipcMain.handle('app:quit', () => {
  isQuitting = true;
  app.quit();
});

// Update handlers
ipcMain.handle('update:check', () => {
  autoUpdater.checkForUpdates();
});

ipcMain.handle('update:download', () => {
  autoUpdater.downloadUpdate();
});

ipcMain.handle('update:install', () => {
  isQuitting = true;
  autoUpdater.quitAndInstall();
});

// Storage handlers
ipcMain.handle('storage:get', async (event, key) => {
  try {
    if (fs.existsSync(dataPath)) {
      const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      return { value: data[key] || null };
    }
    return { value: null };
  } catch (err) {
    return { value: null };
  }
});

ipcMain.handle('storage:set', async (event, key, value) => {
  try {
    let data = {};
    if (fs.existsSync(dataPath)) {
      data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    }
    data[key] = value;
    fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('storage:delete', async (event, key) => {
  try {
    if (fs.existsSync(dataPath)) {
      let data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      delete data[key];
      fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ============ APP LIFECYCLE ============
app.whenReady().then(() => {
  createWindow();
  createTray();

  // Check for updates on startup (if auto-update enabled in settings)
  setTimeout(() => {
    autoUpdater.checkForUpdates().catch(() => {});
  }, 3000);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    } else {
      mainWindow?.show();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform === 'darwin') {
    // On macOS, keep the app running
  }
});

app.on('before-quit', () => {
  isQuitting = true;
});
