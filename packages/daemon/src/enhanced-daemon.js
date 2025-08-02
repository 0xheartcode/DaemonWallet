import { DaemonStateManager, DAEMON_STATES, DAEMON_EVENTS } from './core/daemon-state.js';
import { ValidationPipeline, ValidationError } from './core/validation-pipeline.js';
import { EnhancedKeystore, KEYSTORE_EVENTS } from './core/enhanced-keystore.js';
import { SessionManager } from './session.js';
import { DaemonIPCServer } from './ipc-server.js';
import { NativeMessaging } from './messaging.js';
import { ApprovalUI } from './approval.js';
import { Config } from '@daemon-wallet/core';
import { ethers } from 'ethers';
import chalk from 'chalk';

export class EnhancedDaemonService {
  constructor() {
    // Core components
    this.stateManager = new DaemonStateManager();
    this.keystore = new EnhancedKeystore();
    this.sessionManager = new SessionManager({ autoLock: false }); // No auto-lock by default
    this.config = new Config();
    this.validationPipeline = new ValidationPipeline(this.stateManager, this.keystore);
    
    // Services
    this.ipcServer = null;
    this.nativeMessaging = new NativeMessaging();
    this.approvalUI = new ApprovalUI();
    this.provider = null;
    
    // State
    this.startTime = Date.now();
    
    this.setupEventHandlers();
  }

  setupEventHandlers() {
    // State manager events
    this.stateManager.on(DAEMON_EVENTS.STATE_CHANGED, ({ from, to, metadata }) => {
      console.log(chalk.blue('🔄 State:'), chalk.gray(from), '→', this._getStateColor(to));
    });

    this.stateManager.on(DAEMON_EVENTS.ERROR, (error) => {
      console.error(chalk.red('❌ Daemon error:'), error.message);
    });

    // Keystore events
    this.keystore.on(KEYSTORE_EVENTS.LOADED, () => {
      console.log(chalk.green('📦 Keystore loaded'));
      this.stateManager.emit(DAEMON_EVENTS.KEYSTORE_LOADED);
      // Don't update state here - wait for init to complete
    });

    this.keystore.on(KEYSTORE_EVENTS.CHANGED, (details) => {
      console.log(chalk.yellow('🔄 Keystore changed:'), details);
      this.stateManager.emit(DAEMON_EVENTS.KEYSTORE_CHANGED, details);
      this._updateStateFromKeystore();
    });

    this.keystore.on(KEYSTORE_EVENTS.UNLOCKED, (data) => {
      // Only update session if we're not already in the correct state
      if (this.stateManager.getCurrentState() !== DAEMON_STATES.UNLOCKED) {
        this.sessionManager.unlock(data.accounts);
        this.stateManager.transition(DAEMON_STATES.UNLOCKED, { 
          accounts: data.accounts,
          unlockTime: Date.now()
        });
      }
    });

    this.keystore.on(KEYSTORE_EVENTS.LOCKED, () => {
      // Only update session if we're not already in the correct state
      if (this.stateManager.getCurrentState() !== DAEMON_STATES.LOCKED) {
        this.sessionManager.lock();
        this.stateManager.transition(DAEMON_STATES.LOCKED);
      }
    });

    this.keystore.on(KEYSTORE_EVENTS.ERROR, (error) => {
      this.stateManager.handleError(error, { component: 'keystore' });
    });

    // Session manager events
    this.sessionManager.on('unlocked', (accounts) => {
      console.log(chalk.green(`🔓 Session unlocked: ${accounts.length} accounts`));
    });

    this.sessionManager.on('locked', () => {
      console.log(chalk.yellow('🔒 Session locked'));
    });
  }

  async start() {
    try {
      console.log(chalk.blue('🚀 Starting Enhanced Daemon Service...'));
      
      this.stateManager.transition(DAEMON_STATES.STARTING, { 
        startTime: this.startTime 
      });

      // Initialize configuration
      await this.config.load();
      console.log(chalk.green('✅ Configuration loaded'));

      // Initialize keystore with auto-reload
      await this.keystore.init();
      console.log(chalk.green('✅ Keystore initialized with auto-reload'));

      // Setup Ethereum provider
      const network = this.config.getDefaultNetwork();
      this.provider = new ethers.JsonRpcProvider(network.rpc);
      console.log(chalk.green('✅ Ethereum provider connected'));

      // Start IPC server
      await this.startIPCServer();
      
      // Determine daemon mode
      await this.setupDaemonMode();

      // Update state based on keystore
      this._updateStateFromKeystore();

      // Setup graceful shutdown
      this.setupGracefulShutdown();

      console.log(chalk.green('🎉 Enhanced Daemon Service started successfully!'));

    } catch (error) {
      console.error(chalk.red('❌ Failed to start daemon:'), error.message);
      this.stateManager.handleError(error, { phase: 'startup' });
      throw error;
    }
  }

  async startIPCServer() {
    try {
      const socketPath = this.config.getDaemonSocket();
      console.log(chalk.yellow('🔧 Setting up IPC server at:'), socketPath);
      
      this.ipcServer = new DaemonIPCServer(
        socketPath,
        this.sessionManager,
        this.keystore,
        this.approvalUI
      );

      // Enhanced IPC server with validation pipeline
      this._setupEnhancedIPCHandlers();
      
      await this.ipcServer.start();
      console.log(chalk.green('✅ Enhanced IPC server started'));
      
    } catch (error) {
      console.error(chalk.red('❌ Failed to start IPC server:'), error.message);
      throw error;
    }
  }

  _setupEnhancedIPCHandlers() {
    // Override the message handler to use validation pipeline
    const originalHandleMessage = this.ipcServer.handleMessage.bind(this.ipcServer);
    
    this.ipcServer.handleMessage = async (message, socket) => {
      try {
        // Create request object for validation
        const request = {
          id: message.id,
          type: message.type,
          data: message.data,
          origin: 'cli', // IPC requests are from CLI
          timestamp: Date.now()
        };

        // Run through validation pipeline
        await this.validationPipeline.validate(request);
        
        // If validation passes, proceed with original handler
        return await originalHandleMessage(message, socket);
        
      } catch (error) {
        console.error(chalk.red('❌ Request validation failed:'), error.message);
        
        // Send validation error response
        const { IPCMessage, IPC_MESSAGE_TYPES } = await import('@daemon-wallet/core');
        const errorResponse = new IPCMessage(IPC_MESSAGE_TYPES.ERROR, {
          code: error.code || 'VALIDATION_ERROR',
          message: error.message,
          context: error.context || {}
        });
        errorResponse.id = message.id;
        
        this.ipcServer.server.sendToClient(socket, errorResponse);
      }
    };
  }

  async setupDaemonMode() {
    // Check if running in Chrome native messaging mode or background mode
    const isNativeMessaging = !process.stdin.isTTY || process.env.DAEMON_MODE === 'background';
    
    if (process.env.DAEMON_MODE === 'background') {
      // Background daemon mode - minimal output, no native messaging setup
      console.log(chalk.blue('🔧 Running in background mode'));
      console.log(chalk.blue('📡 IPC server:'), this.config.getDaemonSocket());
    } else if (!process.stdin.isTTY) {
      // Chrome native messaging mode
      console.log(chalk.blue('🌐 Running in native messaging mode'));
      this.setupNativeMessaging();
      this.nativeMessaging.connect();
    } else {
      // Development/manual mode
      console.log(chalk.blue('🛠️  Running in development mode'));
      console.log(chalk.blue('📡 IPC server:'), this.config.getDaemonSocket());
      console.log(chalk.gray('Run "wallet-cli daemon status" to test'));
    }
  }

  setupNativeMessaging() {
    this.nativeMessaging.on('connect', () => {
      this.approvalUI.showConnectionStatus(true);
      this.sessionManager.addSession();
    });

    this.nativeMessaging.on('disconnect', () => {
      this.approvalUI.showConnectionStatus(false);
      this.sessionManager.removeSession();
    });

    this.nativeMessaging.on('message', async (message) => {
      try {
        // Create request object for validation
        const request = {
          id: message.id,
          type: message.method,
          data: { params: message.params },
          origin: message.origin || 'unknown',
          timestamp: Date.now()
        };

        // Run through validation pipeline
        await this.validationPipeline.validate(request);
        
        // If validation passes, handle the message
        await this.handleNativeMessage(message);
        
      } catch (error) {
        console.error(chalk.red('❌ Native message validation failed:'), error.message);
        this.nativeMessaging.sendError(message.id, -1, error.message);
      }
    });

    this.nativeMessaging.on('error', (err) => {
      this.approvalUI.showError(err.message);
      this.stateManager.handleError(err, { component: 'native-messaging' });
    });
  }

  async handleNativeMessage(message) {
    const { id, method, params = [] } = message;
    console.log(chalk.blue('📨 Native message:'), method, chalk.gray(`(id: ${id})`));

    try {
      switch (method) {
        case 'wallet_status':
          return await this.handleWalletStatus(id);

        case 'wallet_unlock':
          return await this.handleWalletUnlock(id);

        case 'eth_accounts':
          return await this.handleEthAccounts(id);

        case 'eth_requestAccounts':
          return await this.handleEthRequestAccounts(id, params);

        case 'eth_sendTransaction':
          return await this.handleEthSendTransaction(id, params);

        case 'eth_sign':
          return await this.handleEthSign(id, params);

        case 'personal_sign':
          return await this.handlePersonalSign(id, params);

        default:
          throw new Error(`Unsupported method: ${method}`);
      }
    } catch (error) {
      console.error(chalk.red('❌ Native message handler error:'), error.message);
      this.nativeMessaging.sendError(id, -1, error.message);
    }
  }

  async handleWalletStatus(id) {
    const daemonStatus = this.getStatus();
    const keystoreCount = await this.keystore.countKeystoreFiles();
    
    const status = {
      locked: daemonStatus.locked,
      accounts: daemonStatus.locked ? [] : this.keystore.getAccounts(),
      activeSessions: daemonStatus.activeSessions,
      hasKeystore: daemonStatus.hasKeystore,
      keystoreCount,
      state: daemonStatus.state
    };

    console.log(chalk.green('📊 Wallet status:'), 
      chalk.gray(`locked: ${status.locked}, accounts: ${status.accounts.length}`));
    
    this.nativeMessaging.sendResponse(id, status);
  }

  async handleWalletUnlock(id) {
    try {
      if (!this.keystore.hasKeystore()) {
        throw new Error('No wallet found. Create one with the CLI first.');
      }

      if (!this.stateManager.isState(DAEMON_STATES.LOCKED)) {
        // Already unlocked
        const accounts = this.keystore.getAccounts();
        console.log(chalk.yellow('🔓 Wallet already unlocked'));
        return this.nativeMessaging.sendResponse(id, {
          success: true,
          accounts
        });
      }

      console.log(chalk.blue('🔓 Extension requesting wallet unlock...'));
      const password = await this.approvalUI.promptUnlock();
      
      const success = await this.keystore.unlock(password);

      if (success) {
        const accounts = this.keystore.getAccounts();
        this.sessionManager.unlock(accounts);
        
        console.log(chalk.green('✅ Wallet unlocked via extension'));
        this.nativeMessaging.sendResponse(id, {
          success: true,
          accounts
        });
      } else {
        console.log(chalk.red('❌ Invalid password'));
        this.nativeMessaging.sendResponse(id, {
          success: false,
          error: 'Invalid password'
        });
      }
    } catch (error) {
      console.error(chalk.red('❌ Unlock failed:'), error.message);
      this.nativeMessaging.sendError(id, -1, error.message);
    }
  }

  async handleEthAccounts(id) {
    try {
      if (this.stateManager.isState(DAEMON_STATES.LOCKED)) {
        console.log(chalk.yellow('🔒 eth_accounts: Wallet locked'));
        return this.nativeMessaging.sendResponse(id, []);
      }

      const accounts = this.keystore.getAccounts();
      console.log(chalk.green('👥 eth_accounts:'), `${accounts.length} accounts`);
      this.nativeMessaging.sendResponse(id, accounts);
      
    } catch (error) {
      console.error(chalk.red('❌ eth_accounts error:'), error.message);
      this.nativeMessaging.sendResponse(id, []);
    }
  }

  async handleEthRequestAccounts(id, params) {
    try {
      // Check if wallet is unlocked
      if (this.stateManager.isState(DAEMON_STATES.LOCKED)) {
        throw new Error('Wallet is locked. Unlock first.');
      }

      // Get origin from params if available
      const origin = params[0]?.origin || 'Unknown DApp';
      
      console.log(chalk.blue('🌐 Account access request from:'), chalk.bold(origin));
      
      // Ask user for permission
      const approved = await this.approvalUI.promptAccountAccess(origin);
      
      if (approved) {
        const accounts = this.keystore.getAccounts();
        console.log(chalk.green('✅ Account access approved'));
        this.nativeMessaging.sendResponse(id, accounts);
      } else {
        console.log(chalk.red('❌ Account access denied'));
        this.nativeMessaging.sendError(id, 4001, 'User rejected the request');
      }
    } catch (error) {
      console.error(chalk.red('❌ eth_requestAccounts error:'), error.message);
      this.nativeMessaging.sendError(id, -1, error.message);
    }
  }

  async handleEthSendTransaction(id, params) {
    try {
      if (this.stateManager.isState(DAEMON_STATES.LOCKED)) {
        throw new Error('Wallet is locked. Unlock first.');
      }
      
      const txRequest = params[0];
      if (!txRequest) {
        throw new Error('Transaction parameters required');
      }

      console.log(chalk.blue('💸 Transaction request:'));
      console.log(chalk.gray(`  From: ${txRequest.from}`));
      console.log(chalk.gray(`  To: ${txRequest.to}`));
      console.log(chalk.gray(`  Value: ${txRequest.value || '0x0'}`));

      // Show approval UI
      const approved = await this.approvalUI.promptTransactionApproval(txRequest);
      
      if (!approved) {
        console.log(chalk.red('❌ Transaction rejected'));
        this.approvalUI.showTransactionResult(false);
        return this.nativeMessaging.sendError(id, 4001, 'User rejected the request');
      }

      // Sign and send transaction
      try {
        const signedTx = await this.keystore.signTransaction(txRequest, txRequest.from);
        const txResponse = await this.provider.broadcastTransaction(signedTx);
        
        console.log(chalk.green('✅ Transaction sent:'), txResponse.hash);
        this.approvalUI.showTransactionResult(true, txResponse.hash);
        this.nativeMessaging.sendResponse(id, txResponse.hash);
        
      } catch (error) {
        console.error(chalk.red('❌ Transaction failed:'), error.message);
        this.approvalUI.showTransactionResult(false, null, error.message);
        throw error;
      }

    } catch (error) {
      console.error(chalk.red('❌ eth_sendTransaction error:'), error.message);
      this.nativeMessaging.sendError(id, -1, error.message);
    }
  }

  async handleEthSign(id, params) {
    try {
      if (this.stateManager.isState(DAEMON_STATES.LOCKED)) {
        throw new Error('Wallet is locked. Unlock first.');
      }
      
      const [address, message] = params;
      if (!address || !message) {
        throw new Error('Address and message required');
      }

      console.log(chalk.blue('✍️  Message signing request:'));
      console.log(chalk.gray(`  Address: ${address}`));
      console.log(chalk.gray(`  Message: ${message}`));

      // Show approval UI
      const approved = await this.approvalUI.promptMessageSignature({
        address,
        message
      });
      
      if (!approved) {
        console.log(chalk.red('❌ Message signing rejected'));
        return this.nativeMessaging.sendError(id, 4001, 'User rejected the request');
      }

      // Sign message
      const signature = await this.keystore.signMessage(message, address);
      console.log(chalk.green('✅ Message signed'));
      this.nativeMessaging.sendResponse(id, signature);

    } catch (error) {
      console.error(chalk.red('❌ eth_sign error:'), error.message);
      this.nativeMessaging.sendError(id, -1, error.message);
    }
  }

  async handlePersonalSign(id, params) {
    try {
      if (this.stateManager.isState(DAEMON_STATES.LOCKED)) {
        throw new Error('Wallet is locked. Unlock first.');
      }
      
      const [message, address] = params;
      if (!address || !message) {
        throw new Error('Address and message required');
      }

      console.log(chalk.blue('✍️  Personal message signing request:'));
      console.log(chalk.gray(`  Address: ${address}`));
      console.log(chalk.gray(`  Message: ${message}`));

      // Show approval UI
      const approved = await this.approvalUI.promptMessageSignature({
        address,
        message,
        type: 'personal_sign'
      });
      
      if (!approved) {
        console.log(chalk.red('❌ Personal message signing rejected'));
        return this.nativeMessaging.sendError(id, 4001, 'User rejected the request');
      }

      // Sign message
      const signature = await this.keystore.signMessage(message, address);
      console.log(chalk.green('✅ Personal message signed'));
      this.nativeMessaging.sendResponse(id, signature);

    } catch (error) {
      console.error(chalk.red('❌ personal_sign error:'), error.message);
      this.nativeMessaging.sendError(id, -1, error.message);
    }
  }

  _updateStateFromKeystore() {
    const currentState = this.stateManager.getCurrentState();
    
    // Don't update if we're still starting
    if (currentState === DAEMON_STATES.STARTING) {
      return;
    }
    
    if (!this.keystore.hasKeystore()) {
      // Only transition if not already in READY state
      if (currentState !== DAEMON_STATES.READY) {
        this.stateManager.transition(DAEMON_STATES.READY, { 
          hasKeystore: false 
        });
      }
    } else if (this.keystore.isLocked) {
      // Only transition if not already in LOCKED state
      if (currentState !== DAEMON_STATES.LOCKED) {
        this.stateManager.transition(DAEMON_STATES.LOCKED, { 
          hasKeystore: true 
        });
      }
    } else {
      // Only transition if not already in UNLOCKED state
      if (currentState !== DAEMON_STATES.UNLOCKED) {
        this.stateManager.transition(DAEMON_STATES.UNLOCKED, { 
          hasKeystore: true,
          accounts: this.keystore.getAccounts()
        });
      }
    }
  }

  getStatus() {
    const daemonStatus = this.stateManager.getStatus();
    const sessionStatus = this.sessionManager.getStatus();
    
    // Get actual accounts from keystore (not from session)
    const accounts = this.keystore.isLocked ? [] : this.keystore.getAccounts();
    
    return {
      ...daemonStatus,
      ...sessionStatus,
      hasKeystore: this.keystore.hasKeystore(),
      accounts: accounts, // Override session accounts with actual keystore accounts
      keystoreCount: 0, // Will be filled by IPC handler
      uptime: Date.now() - this.startTime,
      version: '0.2.0-enhanced'
    };
  }

  setupGracefulShutdown() {
    const shutdown = async () => {
      console.log(chalk.yellow('\n🛑 Shutting down Enhanced Daemon Service...'));
      
      try {
        // Lock wallet
        if (!this.keystore.isLocked) {
          this.keystore.lock();
        }
        
        // Destroy components
        if (this.sessionManager) {
          this.sessionManager.destroy();
        }
        
        if (this.keystore) {
          await this.keystore.destroy();
        }
        
        if (this.ipcServer) {
          await this.ipcServer.stop();
        }
        
        console.log(chalk.green('✅ Enhanced Daemon shutdown complete'));
        process.exit(0);
      } catch (error) {
        console.error(chalk.red('❌ Error during shutdown:'), error.message);
        process.exit(1);
      }
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  }

  _getStateColor(state) {
    const colors = {
      [DAEMON_STATES.STARTING]: chalk.yellow(state),
      [DAEMON_STATES.READY]: chalk.blue(state),
      [DAEMON_STATES.LOCKED]: chalk.red(state),
      [DAEMON_STATES.UNLOCKED]: chalk.green(state),
      [DAEMON_STATES.ERROR]: chalk.bgRed.white(state)
    };
    return colors[state] || chalk.gray(state);
  }
}