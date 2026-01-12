# EternaVault

A personal fortress for digital privacy. Securely store your journal entries, passwords, 2FA codes, and encrypted files - all protected by strong encryption.

## Features

- **Secure Journal** - Private encrypted journal entries
- **Password Manager** - Store and organize passwords with strength analysis
- **2FA Authenticator** - Generate TOTP codes, scan QR codes
- **Encrypted Files** - Securely store sensitive documents
- **System Tray** - Quick access and background operation
- **Auto Updates** - Stay up to date automatically
- **Offline First** - All data stored locally, no cloud required

## Installation

### From Release
Download the latest installer from the [Releases](../../releases) page.

### From Source
```bash
git clone https://github.com/wutev/eternavault.git
cd eternavault
npm install
npm start
```

## Building

```bash
# Build Windows installer
npm run build

# Build portable version
npm run build:portable
```

## Security

- AES-256 encryption for all stored data
- PBKDF2 key derivation
- Data never leaves your device
- No telemetry or tracking

## License

MIT
