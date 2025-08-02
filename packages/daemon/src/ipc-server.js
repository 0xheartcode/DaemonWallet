import { IPCServer, IPCMessage, IPC_MESSAGE_TYPES } from '@daemon-wallet/core';

export class DaemonIPCServer {
  constructor(socketPath, sessionManager, keystore, approvalUI) {
    this.server = new IPCServer(socketPath);
    this.sessionManager = sessionManager;
    this.keystore = keystore;
    this.approvalUI = approvalUI;
    
    this.setupEventHandlers();
  }

  setupEventHandlers() {
    this.server.on('message', async (message, socket) => {
      try {
        await this.handleMessage(message, socket);
      } catch (err) {
        console.error('IPC Error:', err);
        const errorResponse = new IPCMessage(IPC_MESSAGE_TYPES.ERROR, {
          message: err.message
        });
        this.server.sendToClient(socket, errorResponse);
      }
    });

    this.server.on('error', (err) => {
      console.error('IPC Server Error:', err);
    });
  }

  async handleMessage(message, socket) {
    switch (message.type) {
      case IPC_MESSAGE_TYPES.GET_STATUS:
        await this.handleGetStatus(message, socket);
        break;

      case IPC_MESSAGE_TYPES.UNLOCK_KEYSTORE:
        await this.handleUnlockKeystore(message, socket);
        break;

      case IPC_MESSAGE_TYPES.LOCK_KEYSTORE:
        await this.handleLockKeystore(message, socket);
        break;

      case IPC_MESSAGE_TYPES.SHUTDOWN:
        await this.handleShutdown(message, socket);
        break;

      case 'debug_state':
        await this.handleDebugState(message, socket);
        break;

      default:
        throw new Error(`Unknown IPC message type: ${message.type}`);
    }
  }

  async handleGetStatus(message, socket) {
    const status = this.sessionManager.getStatus();
    
    // Count keystore files on disk
    let keystoreCount = 0;
    try {
      if (this.keystore.countKeystoreFiles) {
        keystoreCount = await this.keystore.countKeystoreFiles();
      } else {
        // Fallback for regular keystore
        const fs = await import('node:fs/promises');
        const path = await import('node:path');
        const os = await import('node:os');
        
        const keystoreDir = path.default.join(os.default.homedir(), '.daemon-wallet', 'keystore');
        const files = await fs.default.readdir(keystoreDir);
        keystoreCount = files.filter(f => f.endsWith('.json')).length;
      }
    } catch (err) {
      // Directory doesn't exist or other error - keystore count remains 0
    }
    
    const response = new IPCMessage(IPC_MESSAGE_TYPES.STATUS_RESPONSE, {
      ...status,
      hasKeystore: this.keystore.hasKeystore(),
      keystoreCount
    });
    
    // Use the same ID as the request
    response.id = message.id;
    
    this.server.sendToClient(socket, response);
  }

  async handleUnlockKeystore(message, socket) {
    try {
      const { password } = message.data;
      
      if (!password) {
        throw new Error('Password required');
      }

      const success = await this.keystore.unlock(password);
      
      if (success) {
        const accounts = this.keystore.getAccounts();
        this.sessionManager.unlock(accounts);
        
        const response = new IPCMessage(IPC_MESSAGE_TYPES.UNLOCK_RESPONSE, {
          success: true,
          accounts
        });
        
        response.id = message.id;
        this.server.sendToClient(socket, response);
      } else {
        const response = new IPCMessage(IPC_MESSAGE_TYPES.UNLOCK_RESPONSE, {
          success: false,
          error: 'Invalid password'
        });
        
        response.id = message.id;
        this.server.sendToClient(socket, response);
      }

    } catch (err) {
      const response = new IPCMessage(IPC_MESSAGE_TYPES.UNLOCK_RESPONSE, {
        success: false,
        error: err.message
      });
      
      response.id = message.id;
      this.server.sendToClient(socket, response);
    }
  }

  async handleLockKeystore(message, socket) {
    this.keystore.lock();
    this.sessionManager.lock();
    
    // No response needed for lock
  }

  async handleShutdown(message, socket) {
    // Graceful shutdown
    this.keystore.lock();
    this.sessionManager.destroy();
    
    setTimeout(() => {
      process.exit(0);
    }, 100);
  }

  async start() {
    await this.server.start();
  }

  async handleDebugState(message, socket) {
    const debugInfo = {
      keystore: {
        hasKeystore: this.keystore.hasKeystore(),
        isLocked: this.keystore.isLocked,
        encryptedData: !!this.keystore.encryptedData,
        accounts: this.keystore.isLocked ? '(locked)' : this.keystore.getAccounts(),
        walletData: this.keystore.isLocked ? '(locked)' : !!this.keystore.walletData
      },
      session: this.sessionManager.getStatus(),
      keystoreFiles: await this.keystore.countKeystoreFiles?.() || 'N/A'
    };
    
    const response = new IPCMessage('debug_state_response', debugInfo);
    response.id = message.id;
    this.server.sendToClient(socket, response);
  }

  async stop() {
    await this.server.stop();
  }
}