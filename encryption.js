const crypto = require('crypto');

/**
 * Eterna Encryption Module
 * Provides AES-256-GCM encryption for sensitive data storage
 */

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32;
const TAG_LENGTH = 16; // eslint-disable-line no-unused-vars -- kept for documentation
const PBKDF2_ITERATIONS = 310000; // Bitwarden standard, ~3x OWASP minimum

/**
 * Derives a cryptographic key from a master password using PBKDF2
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - Salt for key derivation (generate if not provided)
 * @returns {Object} { key: Buffer, salt: Buffer }
 */
function deriveKey(masterPassword, salt = null) {
  // Accept any password - no validation
  if (!masterPassword) {
    throw new Error('Master password required');
  }

  // Generate salt if not provided
  if (!salt) {
    salt = crypto.randomBytes(SALT_LENGTH);
  }

  // Derive key using PBKDF2 with SHA-256
  const key = crypto.pbkdf2Sync(
    masterPassword,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    'sha256'
  );

  return { key, salt };
}

/**
 * Encrypts data using AES-256-GCM
 * @param {string|object} data - Data to encrypt (will be JSON stringified)
 * @param {Buffer} key - Encryption key
 * @returns {Object} { encrypted: string, iv: string, tag: string }
 */
function encrypt(data, key) {
  if (!key || key.length !== KEY_LENGTH) {
    throw new Error('Invalid encryption key');
  }

  // Convert data to JSON string if it's an object
  const plaintext = typeof data === 'string' ? data : JSON.stringify(data);

  // Generate random IV
  const iv = crypto.randomBytes(IV_LENGTH);

  // Create cipher
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  // Encrypt data
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Get authentication tag
  const tag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

/**
 * Decrypts data encrypted with AES-256-GCM
 * @param {string} encryptedData - Hex-encoded encrypted data
 * @param {string} ivHex - Hex-encoded IV
 * @param {string} tagHex - Hex-encoded authentication tag
 * @param {Buffer} key - Decryption key
 * @returns {string|object} Decrypted data (parsed from JSON if possible)
 */
function decrypt(encryptedData, ivHex, tagHex, key) {
  if (!key || key.length !== KEY_LENGTH) {
    throw new Error('Invalid decryption key');
  }

  try {
    // Convert hex strings to buffers
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');

    // Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    // Decrypt data
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Try to parse as JSON, otherwise return as string
    try {
      return JSON.parse(decrypted);
    } catch (_e) {
      return decrypted;
    }
  } catch (_err) {
    throw new Error('Decryption failed: Invalid key or corrupted data');
  }
}

/**
 * Encrypts an entire vault data object
 * @param {object} vaultData - The entire vault data object
 * @param {string} masterPassword - User's master password
 * @returns {Object} { encryptedVault: object, salt: string }
 */
function encryptVault(vaultData, masterPassword) {
  // Derive key from master password
  const { key, salt } = deriveKey(masterPassword);

  // Encrypt the entire vault data
  const { encrypted, iv, tag } = encrypt(vaultData, key);

  return {
    encryptedVault: {
      data: encrypted,
      iv,
      tag,
      version: '1.0', // For future migration compatibility
      algorithm: ALGORITHM,
      iterations: PBKDF2_ITERATIONS
    },
    salt: salt.toString('hex')
  };
}

/**
 * Decrypts an entire vault data object
 * @param {object} encryptedVault - Encrypted vault object
 * @param {string} saltHex - Hex-encoded salt
 * @param {string} masterPassword - User's master password
 * @returns {object} Decrypted vault data
 */
function decryptVault(encryptedVault, saltHex, masterPassword) {
  // Derive key from master password and stored salt
  const salt = Buffer.from(saltHex, 'hex');
  const { key } = deriveKey(masterPassword, salt);

  // Decrypt the vault
  const decrypted = decrypt(
    encryptedVault.data,
    encryptedVault.iv,
    encryptedVault.tag,
    key
  );

  return decrypted;
}

/**
 * Generates a cryptographically secure random password
 * @param {number} length - Password length (default: 32)
 * @param {object} options - Character set options
 * @returns {string} Generated password
 */
function generateSecurePassword(length = 32, options = {}) {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true
  } = options;

  let charset = '';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeNumbers) charset += '0123456789';
  if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (charset.length === 0) {
    throw new Error('At least one character type must be included');
  }

  let password = '';
  const randomBytes = crypto.randomBytes(length);

  for (let i = 0; i < length; i++) {
    const randomIndex = randomBytes[i] % charset.length;
    password += charset[randomIndex];
  }

  return password;
}

/**
 * Validates master password strength
 * @param {string} password - Password to validate
 * @returns {Object} { valid: boolean, strength: string, feedback: string[] }
 */
function validatePasswordStrength(password) {
  const feedback = [];
  let strength = 'weak';

  if (!password || password.length < 8) {
    feedback.push('Password must be at least 8 characters long');
    return { valid: false, strength: 'very-weak', feedback };
  }

  if (password.length < 12) {
    feedback.push('Consider using at least 12 characters for better security');
    strength = 'weak';
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSymbols = /[^A-Za-z0-9]/.test(password);

  const varietyScore = [hasUppercase, hasLowercase, hasNumbers, hasSymbols].filter(Boolean).length;

  if (!hasUppercase || !hasLowercase) {
    feedback.push('Use both uppercase and lowercase letters');
  }
  if (!hasNumbers) {
    feedback.push('Include numbers');
  }
  if (!hasSymbols) {
    feedback.push('Include special characters');
  }

  // Determine strength
  if (password.length >= 16 && varietyScore >= 3) {
    strength = 'very-strong';
  } else if (password.length >= 12 && varietyScore >= 3) {
    strength = 'strong';
  } else if (password.length >= 10 && varietyScore >= 2) {
    strength = 'medium';
  }

  return {
    valid: password.length >= 8,
    strength,
    feedback: feedback.length > 0 ? feedback : ['Password strength: ' + strength]
  };
}

/**
 * Hash a password for verification (not for encryption)
 * @param {string} password - Password to hash
 * @returns {string} Hex-encoded hash
 */
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

module.exports = {
  deriveKey,
  encrypt,
  decrypt,
  encryptVault,
  decryptVault,
  generateSecurePassword,
  validatePasswordStrength,
  hashPassword,
  constants: {
    ALGORITHM,
    KEY_LENGTH,
    IV_LENGTH,
    SALT_LENGTH,
    PBKDF2_ITERATIONS
  }
};
