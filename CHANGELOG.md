# Changelog

All notable changes to Eterna will be documented in this file.

## [2.0.0] - 2026-01-17

### Security Enhancements
- **Increased PBKDF2 iterations** from 100,000 to 310,000 (Bitwarden standard)
- **Added backend rate limiting** to all authentication endpoints:
  - `vault:unlock` - 5 attempts per 5 minutes
  - `vault:unlockPrivate` - 5 attempts per 5 minutes
  - `vault:changeMasterPassword` - 5 attempts per 5 minutes
- **Added configurable file size limits** in Settings:
  - Max file size: 10/25/50/100/250 MB (default 50 MB)
  - Max vault size: 100/250/500/1000/2000 MB (default 500 MB)
- **Removed master key from renderer memory** - password only sent to backend during unlock

### Code Quality
- Added ESLint configuration and fixed all linting issues
- Added `npm run lint` and `npm run lint:fix` scripts
- Added `npm test` script for running encryption tests

### Documentation
- Updated README with accurate security information
- Cleaned up development documentation files

---

## [1.0.0] - Prior

### Features
- Secure Journal with version history
- Password Manager with strength analysis
- 2FA/TOTP Authenticator with QR code scanning
- Encrypted file storage
- Private section with separate password
- System tray integration
- Auto-updates via GitHub releases
- Audit logging

### Security
- AES-256-GCM encryption for all data
- PBKDF2 key derivation
- Context isolation enabled
- Node integration disabled in renderer
- Secure IPC via contextBridge
- Encrypted audit logging

---

## Security Architecture

| Component | Implementation |
|-----------|----------------|
| Encryption | AES-256-GCM |
| Key Derivation | PBKDF2 with 310,000 iterations |
| Session Keys | Managed in main process only |
| Process Isolation | Context isolation + no node in renderer |
| Rate Limiting | 5 attempts / 5 minutes on auth endpoints |

## Data Storage

- **Location:** `%APPDATA%/eterna/`
- **Vault Data:** Encrypted with AES-256-GCM
- **Audit Log:** Encrypted
- **Config:** Contains salt and password hash only
