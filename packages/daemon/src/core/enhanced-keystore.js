import { Keystore } from '@daemon-wallet/core';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import chalk from 'chalk';

const KEYSTORE_DIR = path.join(os.homedir(), '.daemon-wallet', 'keystore');

export const KEYSTORE_EVENTS = {
  LOADED: 'loaded',
  CHANGED: 'changed',
  UNLOCKED: 'unlocked',
  LOCKED: 'locked',
  ERROR: 'error'
};

export class EnhancedKeystore extends EventEmitter {
  constructor() {
    super();
    this.keystore = new Keystore();
    this.watcher = null;
    this.isWatching = false;
    this.lastModified = null;
  }

  async init() {
    try {
      // Initialize base keystore
      await this.keystore.init();
      
      // Start watching for changes
      await this.startWatching();
      
      // Check current state
      if (this.keystore.hasKeystore()) {
        console.log(chalk.green('✅ Keystore loaded and watching for changes'));
        console.log(chalk.blue('📊 Keystore state:'), {
          hasKeystore: this.keystore.hasKeystore(),
          isLocked: this.keystore.isLocked,
          encryptedData: !!this.keystore.encryptedData,
          keystorePath: this.keystore.keystorePath
        });
        this.emit(KEYSTORE_EVENTS.LOADED);
      } else {
        console.log(chalk.yellow('📭 No keystore found, watching for creation'));
      }
      
    } catch (error) {
      console.error(chalk.red('❌ Keystore initialization failed:'), error.message);
      this.emit(KEYSTORE_EVENTS.ERROR, error);
      throw error;
    }
  }

  async startWatching() {
    if (this.isWatching) {
      return;
    }

    try {
      // Ensure directory exists
      await fs.mkdir(KEYSTORE_DIR, { recursive: true });
      
      // Get initial state
      await this.updateLastModified();
      
      // Start polling for changes (fs.watch can be unreliable)
      this.startPolling();
      this.isWatching = true;
      
      console.log(chalk.blue('👁️  Watching keystore directory:'), KEYSTORE_DIR);
      
    } catch (error) {
      console.error(chalk.red('❌ Failed to start keystore watching:'), error.message);
      this.emit(KEYSTORE_EVENTS.ERROR, error);
    }
  }

  startPolling() {
    // Poll every 2 seconds for changes
    this.pollInterval = setInterval(async () => {
      try {
        const currentModified = await this.getLatestModified();
        
        if (currentModified !== this.lastModified) {
          console.log(chalk.yellow('🔄 Keystore change detected, reloading...'));
          await this.reload();
          this.lastModified = currentModified;
        }
      } catch (error) {
        // Ignore polling errors (directory might not exist yet)
      }
    }, 2000);
  }

  async updateLastModified() {
    try {
      this.lastModified = await this.getLatestModified();
    } catch (error) {
      this.lastModified = null;
    }
  }

  async getLatestModified() {
    try {
      const files = await fs.readdir(KEYSTORE_DIR);
      const keystoreFiles = files.filter(f => f.endsWith('.json'));
      
      if (keystoreFiles.length === 0) {
        return null;
      }

      let latest = 0;
      for (const file of keystoreFiles) {
        const filePath = path.join(KEYSTORE_DIR, file);
        const stats = await fs.stat(filePath);
        if (stats.mtime.getTime() > latest) {
          latest = stats.mtime.getTime();
        }
      }
      
      return latest;
    } catch (error) {
      return null;
    }
  }

  async reload() {
    try {
      const wasLocked = this.keystore.isLocked;
      const hadKeystore = this.keystore.hasKeystore();
      
      // Reload the keystore
      await this.keystore.load();
      
      const hasKeystore = this.keystore.hasKeystore();
      
      // Emit appropriate events
      if (!hadKeystore && hasKeystore) {
        console.log(chalk.green('✅ New keystore detected and loaded'));
        this.emit(KEYSTORE_EVENTS.LOADED);
      } else if (hadKeystore && !hasKeystore) {
        console.log(chalk.yellow('📭 Keystore removed'));
        this.emit(KEYSTORE_EVENTS.CHANGED, { removed: true });
      } else if (hasKeystore) {
        console.log(chalk.blue('🔄 Keystore updated'));
        this.emit(KEYSTORE_EVENTS.CHANGED, { updated: true });
      }
      
      // If was unlocked and still has keystore, it's now locked
      if (!wasLocked && hasKeystore && this.keystore.isLocked) {
        this.emit(KEYSTORE_EVENTS.LOCKED);
      }
      
    } catch (error) {
      console.error(chalk.red('❌ Keystore reload failed:'), error.message);
      this.emit(KEYSTORE_EVENTS.ERROR, error);
    }
  }

  async unlock(password) {
    try {
      const result = await this.keystore.unlock(password);
      
      if (result) {
        console.log(chalk.green('🔓 Keystore unlocked'));
        this.emit(KEYSTORE_EVENTS.UNLOCKED, {
          accounts: this.keystore.getAccounts()
        });
      }
      
      return result;
    } catch (error) {
      console.error(chalk.red('❌ Unlock failed:'), error.message);
      this.emit(KEYSTORE_EVENTS.ERROR, error);
      throw error;
    }
  }

  lock() {
    try {
      this.keystore.lock();
      console.log(chalk.yellow('🔒 Keystore locked'));
      this.emit(KEYSTORE_EVENTS.LOCKED);
    } catch (error) {
      console.error(chalk.red('❌ Lock failed:'), error.message);
      this.emit(KEYSTORE_EVENTS.ERROR, error);
      throw error;
    }
  }

  // Proxy methods to underlying keystore
  hasKeystore() {
    return this.keystore.hasKeystore();
  }

  get isLocked() {
    return this.keystore.isLocked;
  }

  getAccounts() {
    return this.keystore.getAccounts();
  }

  async signTransaction(tx, address) {
    return await this.keystore.signTransaction(tx, address);
  }

  async signMessage(message, address) {
    return await this.keystore.signMessage(message, address);
  }

  // Proxy all the advanced account management methods
  async createNextAccount(password) {
    return await this.keystore.createNextAccount(password);
  }

  async hideAccount(address, password) {
    return await this.keystore.hideAccount(address, password);
  }

  async showAccount(address, password) {
    return await this.keystore.showAccount(address, password);
  }

  async setAccountLabel(address, label, password) {
    return await this.keystore.setAccountLabel(address, label, password);
  }

  getAccountDetails(address) {
    return this.keystore.getAccountDetails(address);
  }

  getAllAccountDetails(includeHidden = false) {
    return this.keystore.getAllAccountDetails(includeHidden);
  }

  get encryptedData() {
    return this.keystore.encryptedData;
  }

  get walletData() {
    return this.keystore.walletData;
  }

  get wallets() {
    return this.keystore.wallets;
  }

  async countKeystoreFiles() {
    try {
      await fs.mkdir(KEYSTORE_DIR, { recursive: true });
      const files = await fs.readdir(KEYSTORE_DIR);
      const keystoreFiles = files.filter(f => f.endsWith('.json'));
      return keystoreFiles.length;
    } catch (error) {
      console.error(chalk.red('❌ Error counting keystore files:'), error.message);
      return 0;
    }
  }

  async destroy() {
    this.isWatching = false;
    
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    
    this.removeAllListeners();
    console.log(chalk.blue('🛑 Keystore watching stopped'));
  }
}