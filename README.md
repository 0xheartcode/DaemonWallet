# Daemon Wallet

**A secure Ethereum wallet using Chrome Native Messaging**

> **Heavily vibecoded project, use at your own risk.** Sometimes I type bugs by hand in here, to be a bit real.

## Overview

Daemon Wallet implements a secure wallet architecture where private keys are managed by a CLI application that communicates with a Chrome extension via Native Messaging. This follows the security model pioneered by KeePassXC.

### Architecture

```
Browser DApp -> Chrome Extension -> Native Messaging -> Daemon Service -> Keystore
```

- **Browser DApp**: Any Web3-enabled website
- **Chrome Extension**: Injects Web3 provider, forwards requests
- **Daemon Service**: Terminal application handling approvals
- **Keystore**: Encrypted wallet storage on local filesystem

## Installation

```shell
# Install all dependencies
$ make install

# Create a new wallet (enforces one wallet maximum)
$ make create-wallet

# Start the daemon (with auto-reload keystore)
$ make start-daemon

# Create additional accounts (HD derivation)
$ make create-account

# Export all wallet data (dangerous!)
$ make export-wallet
```

## Quick Start

1. **Create a wallet**
   ```shell
   $ cd packages/cli
   $ ./bin/wallet-cli create
   ```

2. **Start the daemon**
   ```shell
   $ cd packages/daemon
   $ ./bin/daemon-wallet-service
   ```

3. **Install Chrome extension** (see extension package)

4. **Connect to a DApp** and approve transactions in your terminal

## Project Structure

```
daemonWallet/
├── packages/
│   ├── core/       # Shared libraries (keystore, crypto, config)
│   ├── cli/        # Wallet management CLI tool
│   ├── daemon/     # Native messaging daemon service
│   └── extension/  # Chrome extension (not included)
├── scripts/        # Build and installation scripts
└── docs/          # Documentation
```

## Development

```shell
# Run all tests
$ make test

# Start daemon in development mode
$ make dev

# Check daemon status
$ make daemon-status

# See all commands
$ make help
```

## Security Model

1. **Private keys never leave the CLI** - The browser extension cannot access keys
2. **Terminal-based approval** - All transactions require explicit approval
3. **Encrypted storage** - Keys are encrypted with scrypt + AES-256-GCM
4. **Manual lock only** - No auto-lock timeout (unlock persists until manual lock or restart)
5. **State machine validation** - All requests validated through security pipeline
6. **Circuit breakers** - Automatic error recovery and protection
7. **Account visibility control** - Hide/show accounts without deleting them

## Configuration

Configuration is stored in `~/.daemon-wallet/config.json`:

```json
{
  "networks": {
    "mainnet": { "rpc": "...", "chainId": 1 },
    "sepolia": { "rpc": "...", "chainId": 11155111 }
  },
  "security": {
    "unlockTimeout": 900,
    "allowBrowserUnlock": false,
    "requireApproval": true
  }
}
```

## Native Messaging Setup

The daemon must be registered as a native messaging host:

1. Create host manifest at:
   - Linux: `~/.config/google-chrome/NativeMessagingHosts/`
   - macOS: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`

2. Host manifest format:
   ```json
   {
     "name": "com.daemonwallet.host",
     "description": "Daemon Wallet Native Host",
     "path": "/absolute/path/to/daemon-wallet-service",
     "type": "stdio",
     "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
   }
   ```

## API Reference

See individual package READMEs:
- [Core API](packages/core/README.md) - Keystore and utilities
- [CLI Commands](packages/cli/README.md) - Wallet management
- [Daemon API](packages/daemon/README.md) - Native messaging protocol

## Contributing

This is a proof of concept. Contributions are welcome:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT