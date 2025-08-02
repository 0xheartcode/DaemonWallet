import { Command } from 'commander';
import chalk from 'chalk';
import { Keystore, Config, IPCClient } from '@daemon-wallet/core';
import { WalletCommands } from './commands/wallet.js';
import { DaemonCommands } from './commands/daemon.js';

const program = new Command();

program
  .name('wallet-cli')
  .description('Daemon Wallet CLI Management Tool')
  .version('0.1.0');

// Create global instances
const keystore = new Keystore();
const config = new Config();

// Initialize
await config.load();
await keystore.init();

// Create IPC client
const ipcClient = new IPCClient(config.getDaemonSocket());

// Initialize command modules
const walletCommands = new WalletCommands(keystore, config);
const daemonCommands = new DaemonCommands(ipcClient);
