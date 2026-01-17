const { app, BrowserWindow, ipcMain, shell, Tray, Menu, nativeImage } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const encryption = require('./encryption');
const { SecureSessionKey, clearString } = require('./secure-memory');
const AuditLog = require('./audit-log');

// Set app name for Windows task manager and dialogs
app.setName('Eterna');

// Set Windows App User Model ID for notifications
if (process.platform === 'win32') {
  app.setAppUserModelId('com.eterna.app');
}

// Window and tray references
let mainWindow = null;
let tray = null;
let isQuitting = false;

// Single instance lock - only allow one instance of Eterna to run
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  // Another instance is already running, quit this one
  app.quit();
} else {
  // Handle second instance attempt - focus the existing window
  app.on('second-instance', (_event, _commandLine, _workingDirectory) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// Configure auto-updater
autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = true;

const dataPath = path.join(app.getPath('userData'), 'vault-data.json');
const configPath = path.join(app.getPath('userData'), 'vault-config.json');
const auditLogPath = path.join(app.getPath('userData'), 'audit-log.json');

// Session storage (in-memory, cleared on app restart)
const secureSessionKey = new SecureSessionKey(); // Secure session key manager
let isVaultUnlocked = false;

// Audit logging
const auditLog = new AuditLog(auditLogPath);

// Rate limiting for IPC handlers
class RateLimiter {
  constructor(maxAttempts, windowMs) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.attempts = new Map(); // key -> { count, resetTime }
  }

  tryAcquire(key) {
    const now = Date.now();
    const record = this.attempts.get(key);

    if (!record || now > record.resetTime) {
      // New window
      this.attempts.set(key, { count: 1, resetTime: now + this.windowMs });
      return { allowed: true };
    }

    if (record.count >= this.maxAttempts) {
      // Rate limited
      const remainingMs = record.resetTime - now;
      return {
        allowed: false,
        remainingSeconds: Math.ceil(remainingMs / 1000)
      };
    }

    // Increment count
    record.count++;
    return { allowed: true };
  }

  reset(key) {
    this.attempts.delete(key);
  }
}

// Rate limiters for different operations
const encryptionRateLimiter = new RateLimiter(100, 60000); // 100 per minute
const storageRateLimiter = new RateLimiter(1000, 60000); // 1000 per minute
const passwordChangeRateLimiter = new RateLimiter(5, 300000); // 5 per 5 minutes
const privateUnlockRateLimiter = new RateLimiter(5, 300000); // 5 per 5 minutes

// Rate limiting for sensitive operations
const rateLimiter = {
  failedAttempts: 0,
  lockoutUntil: null,
  maxAttempts: 5,
  lockoutDuration: 5 * 60 * 1000, // 5 minutes

  isLocked() {
    if (this.lockoutUntil && Date.now() < this.lockoutUntil) {
      return true;
    }
    if (this.lockoutUntil && Date.now() >= this.lockoutUntil) {
      // Lockout expired, reset
      this.reset();
    }
    return false;
  },

  recordFailure() {
    this.failedAttempts++;
    if (this.failedAttempts >= this.maxAttempts) {
      this.lockoutUntil = Date.now() + this.lockoutDuration;
    }
  },

  reset() {
    this.failedAttempts = 0;
    this.lockoutUntil = null;
  },

  getRemainingTime() {
    if (!this.lockoutUntil) return 0;
    const remaining = this.lockoutUntil - Date.now();
    return Math.max(0, Math.ceil(remaining / 1000));
  }
};

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
      label: 'Show Eterna',
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

  tray.setToolTip('Eterna');
  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    mainWindow?.show();
    mainWindow?.focus();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    title: 'Eterna',
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    backgroundColor: '#0a0a14',
    show: false
  });

  // Set stricter CSP headers
  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; " +
          "script-src 'self' 'unsafe-inline'; " +
          "style-src 'self' 'unsafe-inline'; " +
          "img-src 'self' data: blob:; " +
          "media-src 'self' data: blob:; " +
          "object-src 'none'; " +
          "base-uri 'self'; " +
          "form-action 'self'; " +
          "frame-ancestors 'none'; " +
          "upgrade-insecure-requests"
        ]
      }
    });
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
  // Validate URL to prevent dangerous protocols
  try {
    const parsedUrl = new URL(url);
    const allowedProtocols = ['http:', 'https:'];

    if (!allowedProtocols.includes(parsedUrl.protocol)) {
      console.warn('Blocked attempt to open URL with dangerous protocol:', parsedUrl.protocol);
      return { success: false, error: 'Invalid URL protocol' };
    }

    shell.openExternal(url);
    return { success: true };
  } catch (_err) {
    console.warn('Invalid URL provided to openExternal:', url);
    return { success: false, error: 'Invalid URL' };
  }
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

// ============ VAULT SETUP & AUTHENTICATION ============

/**
 * Check if vault is initialized (has master password set)
 */
ipcMain.handle('vault:isInitialized', async () => {
  try {
    return { initialized: fs.existsSync(configPath) };
  } catch (err) {
    return { initialized: false, error: err.message };
  }
});

/**
 * Initialize vault with master password
 */
ipcMain.handle('vault:initialize', async (event, masterPassword) => {
  try {
    // Accept any password - no validation
    if (!masterPassword || masterPassword.length === 0) {
      return { success: false, error: 'Password required' };
    }

    // Generate salt for key derivation
    const salt = crypto.randomBytes(encryption.constants.SALT_LENGTH);

    // Hash master password for verification (NOT for encryption)
    const passwordHash = encryption.hashPassword(masterPassword, salt);

    // Store config (salt and password hash)
    const config = {
      version: '1.0',
      salt: salt.toString('hex'),
      passwordHash,
      createdAt: new Date().toISOString()
    };

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    // Create empty encrypted vault
    const emptyVault = {};
    const { key } = encryption.deriveKey(masterPassword, salt);
    const { encrypted, iv, tag } = encryption.encrypt(emptyVault, key);

    const vaultData = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm'
    };

    fs.writeFileSync(dataPath, JSON.stringify(vaultData, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Unlock vault with master password
 */
ipcMain.handle('vault:unlock', async (event, masterPassword) => {
  try {
    // Check rate limiting
    if (rateLimiter.isLocked()) {
      const remainingSeconds = rateLimiter.getRemainingTime();
      // Log rate limit trigger
      auditLog.logRateLimitTriggered(remainingSeconds);
      return {
        success: false,
        error: 'Too many failed attempts',
        locked: true,
        remainingSeconds
      };
    }

    // Check if vault is initialized
    if (!fs.existsSync(configPath)) {
      return { success: false, error: 'Vault not initialized' };
    }

    // Load config
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    // Verify master password
    const passwordHash = encryption.hashPassword(masterPassword, config.salt);
    if (passwordHash !== config.passwordHash) {
      rateLimiter.recordFailure();
      // Log failed password attempt
      auditLog.logFailedUnlock(rateLimiter.failedAttempts);
      return { success: false, error: 'Invalid master password' };
    }

    // Derive session key
    const salt = Buffer.from(config.salt, 'hex');
    const { key } = encryption.deriveKey(masterPassword, salt);

    // Store session key securely
    secureSessionKey.set(key);
    isVaultUnlocked = true;

    // Set audit log encryption key
    auditLog.setEncryptionKey(key);

    // Reset rate limiter on successful unlock
    rateLimiter.reset();

    // Log successful unlock
    auditLog.logUnlock(true, rateLimiter.failedAttempts);

    // Clear master password from memory
    clearString(masterPassword);

    return { success: true };
  } catch (_err) {
    rateLimiter.recordFailure();
    // Log failed unlock
    auditLog.logFailedUnlock(rateLimiter.failedAttempts);
    // Clear master password even on failure
    clearString(masterPassword);
    return { success: false, error: 'Failed to unlock vault' };
  }
});

/**
 * Lock vault (clear session key)
 */
ipcMain.handle('vault:lock', async () => {
  // Log lock event before clearing
  auditLog.logLock();

  // Clear audit log encryption key
  auditLog.clearEncryptionKey();

  // Securely clear session key from memory
  secureSessionKey.clear();
  isVaultUnlocked = false;
  return { success: true };
});

/**
 * Check if vault is unlocked
 */
ipcMain.handle('vault:isUnlocked', async () => {
  return { unlocked: isVaultUnlocked };
});

/**
 * Completely reset vault (delete all data and config)
 */
ipcMain.handle('vault:reset', async () => {
  try {
    // Clear session
    secureSessionKey.clear();
    isVaultUnlocked = false;
    auditLog.clearEncryptionKey();

    // Delete vault files
    if (fs.existsSync(configPath)) {
      fs.unlinkSync(configPath);
    }
    if (fs.existsSync(dataPath)) {
      fs.unlinkSync(dataPath);
    }
    if (fs.existsSync(auditLogPath)) {
      fs.unlinkSync(auditLogPath);
    }

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Change master password
 */
ipcMain.handle('vault:changeMasterPassword', async (event, currentPassword, newPassword) => {
  // Check rate limiting
  const rateCheck = passwordChangeRateLimiter.tryAcquire('password-change');
  if (!rateCheck.allowed) {
    auditLog.log('PASSWORD_CHANGE_RATE_LIMITED', { remainingSeconds: rateCheck.remainingSeconds });
    return {
      success: false,
      error: 'Too many password change attempts',
      locked: true,
      remainingSeconds: rateCheck.remainingSeconds
    };
  }

  try {
    // Verify current password
    if (!fs.existsSync(configPath)) {
      return { success: false, error: 'Vault not initialized' };
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const currentPasswordHash = encryption.hashPassword(currentPassword, config.salt);

    if (currentPasswordHash !== config.passwordHash) {
      return { success: false, error: 'Current password is incorrect' };
    }

    // Accept any new password - no validation
    if (!newPassword || newPassword.length === 0) {
      return { success: false, error: 'New password required' };
    }

    // Decrypt vault with old password
    const oldSalt = Buffer.from(config.salt, 'hex');
    const { key: oldKey } = encryption.deriveKey(currentPassword, oldSalt);

    const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const vaultData = encryption.decrypt(
      encryptedVault.data,
      encryptedVault.iv,
      encryptedVault.tag,
      oldKey
    );

    // Re-encrypt with new password
    const newSalt = crypto.randomBytes(encryption.constants.SALT_LENGTH);
    const { key: newKey } = encryption.deriveKey(newPassword, newSalt);
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, newKey);

    // Update config
    config.salt = newSalt.toString('hex');
    config.passwordHash = encryption.hashPassword(newPassword, newSalt);
    config.updatedAt = new Date().toISOString();

    // Save everything
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    fs.writeFileSync(dataPath, JSON.stringify({ data: encrypted, iv, tag, version: '1.0', algorithm: 'aes-256-gcm' }, null, 2));

    // Update session key securely
    secureSessionKey.set(newKey);

    // Update audit log encryption key
    auditLog.setEncryptionKey(newKey);

    // Log password change
    auditLog.logPasswordChange();

    // Reset rate limiter on success
    passwordChangeRateLimiter.reset('password-change');

    // Clear passwords from memory
    clearString(currentPassword);
    clearString(newPassword);

    return { success: true };
  } catch (err) {
    // Clear passwords even on failure
    clearString(currentPassword);
    clearString(newPassword);
    return { success: false, error: err.message };
  }
});

/**
 * Validate password strength
 */
ipcMain.handle('vault:validatePassword', async (event, password) => {
  try {
    const validation = encryption.validatePasswordStrength(password);
    return { ...validation, success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Generate secure password
 */
ipcMain.handle('vault:generatePassword', async (event, length = 32, options = {}) => {
  try {
    const password = encryption.generateSecurePassword(length, options);
    return { success: true, password };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ============ ENCRYPTED STORAGE HANDLERS ============

/**
 * Get value from encrypted vault
 */
ipcMain.handle('storage:get', async (event, key) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    if (!fs.existsSync(dataPath)) {
      return { success: true, value: null };
    }

    // Load and decrypt vault
    const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const vaultData = encryption.decrypt(
      encryptedVault.data,
      encryptedVault.iv,
      encryptedVault.tag,
      secureSessionKey.get()
    );

    return { success: true, value: vaultData[key] || null };
  } catch (err) {
    return { success: false, error: 'Failed to retrieve data', details: err.message };
  }
});

/**
 * Set value in encrypted vault
 */
ipcMain.handle('storage:set', async (event, key, value) => {
  try {
    // Rate limiting
    const rateLimitResult = storageRateLimiter.tryAcquire('storage:set');
    if (!rateLimitResult.allowed) {
      return {
        success: false,
        error: 'Rate limit exceeded',
        locked: true,
        remainingSeconds: rateLimitResult.remainingSeconds
      };
    }

    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const currentKey = secureSessionKey.get();

    // Load and decrypt current vault
    let vaultData = {};
    if (fs.existsSync(dataPath)) {
      const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      vaultData = encryption.decrypt(
        encryptedVault.data,
        encryptedVault.iv,
        encryptedVault.tag,
        currentKey
      );
    }

    // Update value
    vaultData[key] = value;

    // Re-encrypt and save
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, secureSessionKey.get());
    const encryptedVault = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(encryptedVault, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to save data', details: err.message };
  }
});

/**
 * Delete value from encrypted vault
 */
ipcMain.handle('storage:delete', async (event, key) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    if (!fs.existsSync(dataPath)) {
      return { success: true };
    }

    // Load and decrypt vault
    const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const vaultData = encryption.decrypt(
      encryptedVault.data,
      encryptedVault.iv,
      encryptedVault.tag,
      secureSessionKey.get()
    );

    // Delete key
    delete vaultData[key];

    // Re-encrypt and save
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, secureSessionKey.get());
    const newEncryptedVault = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(newEncryptedVault, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to delete data', details: err.message };
  }
});

// ============ FILE ENCRYPTION HANDLERS ============

/**
 * Encrypt file data
 */
ipcMain.handle('vault:encryptFile', async (event, fileData) => {
  try {
    // Rate limiting
    const rateLimitResult = encryptionRateLimiter.tryAcquire('vault:encryptFile');
    if (!rateLimitResult.allowed) {
      return {
        success: false,
        error: 'Rate limit exceeded. Please wait before encrypting more files.',
        remainingSeconds: rateLimitResult.remainingSeconds
      };
    }

    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const { encrypted, iv, tag } = encryption.encrypt(fileData, secureSessionKey.get());

    return {
      success: true,
      encrypted: {
        data: encrypted,
        iv,
        tag
      }
    };
  } catch (err) {
    return { success: false, error: 'Failed to encrypt file', details: err.message };
  }
});

/**
 * Decrypt file data
 */
ipcMain.handle('vault:decryptFile', async (event, encryptedFile) => {
  try {
    // Rate limiting
    const rateLimitResult = encryptionRateLimiter.tryAcquire('vault:decryptFile');
    if (!rateLimitResult.allowed) {
      return {
        success: false,
        error: 'Rate limit exceeded. Please wait before decrypting more files.',
        remainingSeconds: rateLimitResult.remainingSeconds
      };
    }

    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const decrypted = encryption.decrypt(
      encryptedFile.data,
      encryptedFile.iv,
      encryptedFile.tag,
      secureSessionKey.get()
    );

    return { success: true, data: decrypted };
  } catch (err) {
    return { success: false, error: 'Failed to decrypt file', details: err.message };
  }
});

// ============ EXPORT/IMPORT HANDLERS ============

/**
 * Export encrypted backup
 */
ipcMain.handle('vault:exportBackup', async (event, password) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    // Load current vault data
    const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const vaultData = encryption.decrypt(
      encryptedVault.data,
      encryptedVault.iv,
      encryptedVault.tag,
      secureSessionKey.get()
    );

    // Encrypt backup with separate password if provided
    if (password) {
      const { key, salt } = encryption.deriveKey(password);
      const { encrypted, iv, tag } = encryption.encrypt(vaultData, key);

      // Calculate checksum for integrity verification
      const checksum = crypto.createHash('sha256').update(encrypted + iv + tag).digest('hex');

      return {
        success: true,
        backup: {
          encrypted: true,
          data: encrypted,
          iv,
          tag,
          salt: salt.toString('hex'),
          version: '1.0',
          checksum,
          createdAt: new Date().toISOString(),
          appVersion: app.getVersion()
        }
      };
    }

    // Return unencrypted backup
    const dataString = JSON.stringify(vaultData);
    const checksum = crypto.createHash('sha256').update(dataString).digest('hex');

    return {
      success: true,
      backup: {
        encrypted: false,
        data: vaultData,
        version: '1.0',
        checksum,
        createdAt: new Date().toISOString(),
        appVersion: app.getVersion()
      }
    };
  } catch (err) {
    return { success: false, error: 'Failed to export backup', details: err.message };
  }
});

/**
 * Import encrypted backup
 */
ipcMain.handle('vault:importBackup', async (event, backup, password) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    // Validate backup structure
    if (!backup || !backup.version) {
      return { success: false, error: 'Invalid backup file structure' };
    }

    // Verify checksum if present
    if (backup.checksum) {
      let calculatedChecksum;
      if (backup.encrypted) {
        calculatedChecksum = crypto.createHash('sha256')
          .update(backup.data + backup.iv + backup.tag)
          .digest('hex');
      } else {
        calculatedChecksum = crypto.createHash('sha256')
          .update(JSON.stringify(backup.data))
          .digest('hex');
      }

      if (calculatedChecksum !== backup.checksum) {
        return { success: false, error: 'Backup integrity check failed. File may be corrupted or tampered.' };
      }
    }

    let importedData;

    if (backup.encrypted) {
      // Decrypt with provided password
      if (!password) {
        return { success: false, error: 'Password required for encrypted backup' };
      }

      // Validate salt format
      if (!backup.salt || !/^[0-9a-f]{64}$/i.test(backup.salt)) {
        return { success: false, error: 'Invalid backup: corrupted salt' };
      }

      const salt = Buffer.from(backup.salt, 'hex');
      const { key } = encryption.deriveKey(password, salt);

      try {
        importedData = encryption.decrypt(
          backup.data,
          backup.iv,
          backup.tag,
          key
        );
      } catch (_err) {
        return { success: false, error: 'Failed to decrypt backup. Incorrect password or corrupted data.' };
      }
    } else {
      // Unencrypted backup
      importedData = backup.data;
    }

    // Re-encrypt with current vault key and save
    const { encrypted, iv, tag } = encryption.encrypt(importedData, secureSessionKey.get());
    const vaultData = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(vaultData, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to import backup', details: err.message };
  }
});

// ============ PRIVATE SECTION ============

/**
 * Set private section password
 */
ipcMain.handle('vault:setPrivatePassword', async (event, password) => {
  if (!isVaultUnlocked || !secureSessionKey.exists()) {
    return { success: false, error: 'Vault is locked' };
  }

  try {
    // Generate salt and hash the private section password
    const privateSalt = crypto.randomBytes(encryption.constants.SALT_LENGTH);
    const hash = encryption.hashPassword(password, privateSalt);

    // Load and decrypt current vault
    let vaultData = {};
    if (fs.existsSync(dataPath)) {
      const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      vaultData = encryption.decrypt(
        encryptedVault.data,
        encryptedVault.iv,
        encryptedVault.tag,
        secureSessionKey.get()
      );
    }

    // Get current data or create new structure
    const currentData = vaultData['eterna-v2'] ? JSON.parse(vaultData['eterna-v2']) : {};

    // Store the hash and salt in the data
    currentData.privatePasswordHash = hash;
    currentData.privatePasswordSalt = privateSalt.toString('hex');

    // Update vault data
    vaultData['eterna-v2'] = JSON.stringify(currentData);

    // Re-encrypt and save
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, secureSessionKey.get());
    const encryptedVaultData = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(encryptedVaultData, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to set private password', details: err.message };
  }
});

/**
 * Unlock private section
 */
ipcMain.handle('vault:unlockPrivate', async (event, password) => {
  if (!isVaultUnlocked || !secureSessionKey.exists()) {
    return { success: false, error: 'Vault is locked' };
  }

  // Check rate limiting
  const rateCheck = privateUnlockRateLimiter.tryAcquire('private-unlock');
  if (!rateCheck.allowed) {
    auditLog.log('PRIVATE_UNLOCK_RATE_LIMITED', { remainingSeconds: rateCheck.remainingSeconds });
    return {
      success: false,
      error: 'Too many failed attempts',
      locked: true,
      remainingSeconds: rateCheck.remainingSeconds
    };
  }

  try {
    // Load and decrypt vault
    const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const vaultData = encryption.decrypt(
      encryptedVault.data,
      encryptedVault.iv,
      encryptedVault.tag,
      secureSessionKey.get()
    );

    // Get current data
    const currentData = vaultData['eterna-v2'] ? JSON.parse(vaultData['eterna-v2']) : {};

    // Check if private password is set
    if (!currentData.privatePasswordHash || !currentData.privatePasswordSalt) {
      return { success: false, error: 'Private section not set up' };
    }

    // Hash the provided password with stored salt and compare
    const hash = encryption.hashPassword(password, currentData.privatePasswordSalt);
    if (hash === currentData.privatePasswordHash) {
      // Reset rate limiter on success
      privateUnlockRateLimiter.reset('private-unlock');
      return { success: true };
    }

    return { success: false, error: 'Incorrect password' };
  } catch (err) {
    return { success: false, error: 'Failed to unlock private section', details: err.message };
  }
});

/**
 * Reset private section
 */
ipcMain.handle('vault:resetPrivate', async (_event) => {
  if (!isVaultUnlocked || !secureSessionKey.exists()) {
    return { success: false, error: 'Vault is locked' };
  }

  try {
    // Load and decrypt current vault
    let vaultData = {};
    if (fs.existsSync(dataPath)) {
      const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      vaultData = encryption.decrypt(
        encryptedVault.data,
        encryptedVault.iv,
        encryptedVault.tag,
        secureSessionKey.get()
      );
    }

    // Get current data
    const currentData = vaultData['eterna-v2'] ? JSON.parse(vaultData['eterna-v2']) : {};

    // Remove private password hash
    delete currentData.privatePasswordHash;

    // Update vault data
    vaultData['eterna-v2'] = JSON.stringify(currentData);

    // Re-encrypt and save
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, secureSessionKey.get());
    const encryptedVaultData = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(encryptedVaultData, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to reset private section', details: err.message };
  }
});

// ============ AUDIT LOG HANDLERS ============

/**
 * Get audit log entries
 */
ipcMain.handle('audit:getEntries', async (_event, filters = {}) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const entries = auditLog.getEntries(filters);
    return { success: true, entries };
  } catch (err) {
    return { success: false, error: 'Failed to retrieve audit log', details: err.message };
  }
});

/**
 * Clear audit log
 */
ipcMain.handle('audit:clear', async (_event) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const success = auditLog.clear();
    return { success };
  } catch (err) {
    return { success: false, error: 'Failed to clear audit log', details: err.message };
  }
});

/**
 * Export audit log
 */
ipcMain.handle('audit:export', async (_event) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const jsonData = auditLog.export();
    return { success: true, data: jsonData };
  } catch (err) {
    return { success: false, error: 'Failed to export audit log', details: err.message };
  }
});

// ============ CODE INTEGRITY CHECKING ============

/**
 * Verify integrity of critical application files
 */
function verifyCodeIntegrity() {
  const integrityPath = path.join(app.getPath('userData'), 'integrity.json');
  const criticalFiles = ['index.html', 'main.js', 'preload.js', 'encryption.js'];

  try {
    const currentHashes = {};

    // Calculate current file hashes
    for (const file of criticalFiles) {
      const filePath = path.join(__dirname, file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath);
        currentHashes[file] = crypto.createHash('sha256').update(content).digest('hex');
      }
    }

    // Check if integrity file exists
    if (fs.existsSync(integrityPath)) {
      const storedHashes = JSON.parse(fs.readFileSync(integrityPath, 'utf8'));

      // Verify hashes match
      for (const file of criticalFiles) {
        if (storedHashes[file] && currentHashes[file] !== storedHashes[file]) {
          console.warn(`[SECURITY WARNING] File integrity check failed for: ${file}`);
          console.warn('File may have been tampered with or updated.');
          // Log integrity failure
          auditLog.logIntegrityFailure(file);
          // In production, you might want to exit the app here
          // For development, we just warn
        }
      }
    } else {
      // First run - store hashes
      fs.writeFileSync(integrityPath, JSON.stringify(currentHashes, null, 2));
      console.log('[INTEGRITY] Baseline file hashes stored');
    }
  } catch (err) {
    console.error('[INTEGRITY] Failed to verify code integrity:', err);
  }
}

// ============ APP LIFECYCLE ============
app.whenReady().then(() => {
  // Verify code integrity on startup
  verifyCodeIntegrity();

  createWindow();
  createTray();

  // Don't auto-check for updates on startup
  // Users can manually check via Settings if they want

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
