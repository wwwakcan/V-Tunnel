#!/usr/bin/env node

/**
 * V-Tunnel - Lightweight Tunnel Routing Solution
 *
 * A 100% free and open-source alternative to commercial tunneling solutions
 * like Ngrok, Cloudflare Tunnel, and others.
 *
 * @file        client.js
 * @description Enhanced Tunnel Routing Client with JWT Authentication
 * @author      Cengiz AKCAN <me@cengizakcan.com>
 * @copyright   Copyright (c) 2025, Cengiz AKCAN
 * @license     MIT
 * @link        https://github.com/wwwakcan/V-Tunnel
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

'use strict';

const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);
const mkdirAsync = promisify(fs.mkdir);
const child_process = require('child_process');
const os = require('os');

// Advanced CLI packages
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const inquirer = require('inquirer');
const Table = require('cli-table3');
const colors = require('colors/safe');

// Configuration
const CONFIG_DIR    = path.join(__dirname, '.vtunnel-client');
const AUTH_FILE     = path.join(CONFIG_DIR, 'auth.json');
const TUNNELS_FILE  = path.join(CONFIG_DIR, 'tunnels.json');
const API_PID_FILE = path.join(CONFIG_DIR, 'api.pid');
const apiServer = require('./api');

// Constants
const HEARTBEAT_INTERVAL = 30000; // ms
const CONNECTION_TIMEOUT = 10000; // ms
const MAX_RECONNECTION_ATTEMPTS = 5;
const RECONNECTION_BASE_DELAY = 2000; // ms

// Color themes
colors.setTheme({
    info: 'blue',
    success: 'green',
    warning: 'yellow',
    error: 'red',
    title: ['cyan', 'bold'],
    highlight: ['yellow', 'bold'],
    muted: 'grey'
});

// Logger
const logger = {
    info: (message) => console.log(colors.info(`[INFO] ${new Date().toISOString()} - ${message}`)),
    success: (message) => console.log(colors.success(`[SUCCESS] ${new Date().toISOString()} - ${message}`)),
    warning: (message) => console.log(colors.warning(`[WARNING] ${new Date().toISOString()} - ${message}`)),
    error: (message) => console.error(colors.error(`[ERROR] ${new Date().toISOString()} - ${message}`)),
    debug: (message) => process.env.DEBUG && console.log(colors.muted(`[DEBUG] ${new Date().toISOString()} - ${message}`)),
    plain: (message) => console.log(message)
};

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';

    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));

    return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
}

// Ensure config directory exists
async function ensureConfigDir() {
    try {
        if (!fs.existsSync(CONFIG_DIR)) {
            await mkdirAsync(CONFIG_DIR, { recursive: true });
        }
        return true;
    } catch (err) {
        logger.error('Could not create configuration directory: ' + err);
        return false;
    }
}

// Load credentials
async function loadAuth() {
    try {
        if (fs.existsSync(AUTH_FILE)) {
            const data = await readFileAsync(AUTH_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (err) {
        logger.error('Could not load credentials: ' + err);
    }
    return null;
}

// Save credentials
async function saveAuth(auth) {
    try {
        await ensureConfigDir();
        await writeFileAsync(AUTH_FILE, JSON.stringify(auth, null, 2));
        return true;
    } catch (err) {
        logger.error('Could not save credentials: ' + err);
        return false;
    }
}

// Load active tunnels
async function loadActiveTunnels() {
    try {
        if (fs.existsSync(TUNNELS_FILE)) {
            const data = await readFileAsync(TUNNELS_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (err) {
        logger.error('Could not load active tunnels: ' + err);
    }
    return { tunnels: [], active: [] };
}

// Save active tunnels
async function saveActiveTunnels(tunnelsData) {
    try {
        await ensureConfigDir();
        await writeFileAsync(TUNNELS_FILE, JSON.stringify(tunnelsData, null, 2));
        return true;
    } catch (err) {
        logger.error('Could not save active tunnels: ' + err);
        return false;
    }
}

// Check if the API server is running
async function isApiServerRunning() {
    try {
        if (fs.existsSync(API_PID_FILE)) {
            const pidData = await readFileAsync(API_PID_FILE, 'utf8');
            const pid = parseInt(pidData.trim(), 10);

            if (!isNaN(pid)) {
                return await isProcessRunning(pid);
            }
        }
        return false;
    } catch (err) {
        logger.error('Error checking if API server is running: ' + err);
        return false;
    }
}

// Start the API server
async function startApiServer() {
    try {
        // Check if API server is already running
        if (await isApiServerRunning()) {
            logger.info('API server is already running');
            return true;
        }

        // Check if user is logged in
        const auth = await loadAuth();
        if (!auth) {
            logger.error('You must be logged in to start the API server');
            logger.info('Please use "node client.js login" to authenticate first');
            return false;
        }

        logger.info('Starting API server...');

        // Start API server in a separate process
        const apiProcess = child_process.spawn(process.execPath, [
            path.join(__dirname, 'api.js')
        ], {
            detached: true,
            stdio: 'ignore'
        });

        // Detach child process from parent
        apiProcess.unref();

        logger.success(`API server started. PID: ${apiProcess.pid}`);
        return true;
    } catch (err) {
        logger.error('Error starting API server: ' + err);
        return false;
    }
}

// Stop the API server
async function stopApiServer() {
    try {
        // Check if API server is running
        if (!await isApiServerRunning()) {
            logger.info('API server is not running');
            return true;
        }

        // Get the API server PID
        const pidData = await readFileAsync(API_PID_FILE, 'utf8');
        const pid = parseInt(pidData.trim(), 10);

        if (isNaN(pid)) {
            logger.error('Invalid PID in API PID file');
            return false;
        }

        // Kill the process
        try {
            process.kill(pid);
            logger.success('API server stopped successfully');

            // Remove the PID file
            fs.unlinkSync(API_PID_FILE);
            return true;
        } catch (err) {
            logger.error(`Could not stop API server: ${err.message}`);
            return false;
        }
    } catch (err) {
        logger.error('Error stopping API server: ' + err.message);
        return false;
    }
}

// Messaging helpers
function sendMessage(socket, message) {
    if (!socket || socket.destroyed) return false;
    return socket.write(encrypt(message) + "\n");
}

function encrypt(data) {
    try {
        const dataString = typeof data === 'string' ? data : JSON.stringify(data);
        const iv = crypto.randomBytes(16);
        const key = crypto.createHash('sha256').update("vtunnel").digest();
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(dataString, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        return iv.toString('hex') + ':' + encrypted;
    } catch (err) {
        logger.error('Encryption error: ' + err.message);
        return null;
    }
}

function decrypt(text) {
    try {
        const parts = text.split(':');
        if (parts.length !== 2) {
            logger.debug('Invalid encrypted format (missing separator)');
            return null;
        }

        const iv = Buffer.from(parts[0], 'hex');
        const key = crypto.createHash('sha256').update("vtunnel").digest();
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(parts[1], 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        return JSON.parse(decrypted);
    } catch (err) {
        logger.error('Decryption error: ' + err.message);
        return null;
    }
}

// Connect to server and send/receive messages
async function connectAndSend(message, timeoutMs = 10000) {
    return new Promise(async (resolve, reject) => {
        const auth = await loadAuth();
        if (!auth && message.type !== 'login') {
            reject(new Error('Authentication required. Please use the "login" command first.'));
            return;
        }

        // Correctly convert port value
        const SERVER_HOST = auth ? auth.server : message.server || 'localhost';
        const SERVER_PORT = parseInt(auth ? auth.port : (message.port || '9012'), 10);

        // Check port validity
        if (isNaN(SERVER_PORT) || SERVER_PORT <= 0 || SERVER_PORT >= 65536) {
            reject(new Error(`Invalid port number: ${SERVER_PORT}`));
            return;
        }

        logger.debug(`Connecting to server: ${SERVER_HOST}:${SERVER_PORT}`);

        const socket = new net.Socket();
        let responseReceived = false;
        let responseData = null;
        let buffer = '';
        let timeoutId;

        socket.on('data', data => {
            try {
                buffer += data.toString();

                let newlineIndex;
                while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
                    const messageStr = buffer.substring(0, newlineIndex);
                    buffer = buffer.substring(newlineIndex + 1);

                    const response = decrypt(messageStr);
                    if (!response) continue;

                    if (response.type === 'welcome') {
                        // Send actual message after welcome message
                        if (message.type === 'login') {
                            sendMessage(socket, message);
                        } else {
                            // Authentication with token
                            sendMessage(socket, {
                                ...message,
                                token: auth.token
                            });
                        }
                    } else {
                        responseReceived = true;
                        responseData = response;
                        clearTimeout(timeoutId);
                        socket.end();
                    }
                }
            } catch (err) {
                logger.error('Data processing error: ' + err);
                reject(err);
                socket.destroy();
            }
        });

        socket.on('error', err => {
            logger.error('Connection error: ' + err.message);
            reject(err);
        });

        socket.on('close', () => {
            if (!responseReceived) {
                reject(new Error('Connection closed, no response received'));
            } else {
                resolve(responseData);
            }
        });

        timeoutId = setTimeout(() => {
            socket.destroy();
            reject(new Error('Server did not respond (timeout)'));
        }, timeoutMs);

        socket.connect(SERVER_PORT, SERVER_HOST);
    });
}

// Variables to track reconnection state
let reconnectionTimer = null;

// Enhanced tunnel client creation with improved flow control and better reconnection
async function createTunnelClient(tunnelName, localHost, localPort, options = {}) {
    const auth = await loadAuth();
    if (!auth) {
        logger.error('Authentication information not found. Please use the "login" command first.');
        return null;
    }

    logger.info(`Starting tunnel ${tunnelName}...`);
    logger.info(`Server: ${auth.server}:${auth.port}`);
    logger.info(`Target: ${localHost}:${localPort}`);

    const tunnelState = {
        reconnectionAttempts: 0,
        isReconnecting: false,
        isShuttingDown: false
    };

    // Default options
    const tunnelOptions = {
        maxReconnectionAttempts: options.maxReconnectionAttempts || MAX_RECONNECTION_ATTEMPTS,
        heartbeatInterval: options.heartbeatInterval || HEARTBEAT_INTERVAL,
        connectionTimeout: options.connectionTimeout || CONNECTION_TIMEOUT,
        autoReconnect: options.autoReconnect !== false  // Default to true
    };

    return new Promise((resolve, reject) => {
        // Safely convert port value
        const SERVER_HOST = auth.server;
        const SERVER_PORT = parseInt(auth.port, 10);

        if (isNaN(SERVER_PORT) || SERVER_PORT <= 0 || SERVER_PORT >= 65536) {
            reject(new Error(`Invalid port number: ${auth.port}`));
            return;
        }

        // Create connection and set up handlers
        const controlSocket = createControlConnection(tunnelName, localHost, localPort, tunnelState, tunnelOptions, resolve, reject);
    });
}

// Create a control connection to the server
function createControlConnection(tunnelName, localHost, localPort, tunnelState, options, resolvePromise, rejectPromise) {
    const auth = loadAuth().catch(err => {
        logger.error('Failed to load authentication information: ' + err.message);
        return null;
    });

    // Start with no auth to avoid blocking
    const SERVER_HOST = auth?.server || 'localhost';
    const SERVER_PORT = parseInt(auth?.port || '9012', 10);

    const controlSocket = new net.Socket();
    let pingInterval;
    let heartbeatInterval;
    let registered = false;
    let tunnelPort;
    let buffer = '';
    let isConnected = false;
    const clients = {}; // Track client connections
    let lastHeartbeatResponse = Date.now();

    controlSocket.on('data', data => {
        try {
            buffer += data.toString();

            let newlineIndex;
            while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
                const messageStr = buffer.substring(0, newlineIndex);
                buffer = buffer.substring(newlineIndex + 1);

                const message = decrypt(messageStr);
                if (!message) continue;

                processMessage(controlSocket, message);
            }
        } catch (err) {
            logger.error('Data processing error: ' + err);
            controlSocket.destroy();
        }
    });

    controlSocket.on('error', err => {
        logger.error('Control connection error: ' + err.message);
        // Don't reject here, let the close handler handle reconnection
    });

    controlSocket.on('close', () => {
        logger.info('Connection to tunnel server closed');
        clearInterval(pingInterval);
        clearInterval(heartbeatInterval);
        isConnected = false;

        if (tunnelState.isShuttingDown) {
            logger.info('Tunnel is shutting down, not attempting to reconnect.');
            return;
        }

        if (registered && options.autoReconnect) {
            // Only attempt to reconnect if we were previously registered
            tunnelState.isReconnecting = true;
            attemptReconnection(tunnelName, localHost, localPort, tunnelPort, tunnelState, options, resolvePromise);
        } else if (!registered) {
            rejectPromise(new Error('Failed to establish initial connection to the server.'));
        }
    });

    // Set a timeout for the connection
    controlSocket.setTimeout(options.connectionTimeout);
    controlSocket.on('timeout', () => {
        const timeSinceLastHeartbeat = Date.now() - lastHeartbeatResponse;

        if (timeSinceLastHeartbeat > options.heartbeatInterval * 2) {
            logger.warning('Connection timeout. No response from server.');
            controlSocket.destroy();
        }
    });

    controlSocket.connect(SERVER_PORT, SERVER_HOST, () => {
        logger.info('Connected to tunnel server');
        isConnected = true;
        tunnelState.reconnectionAttempts = 0; // Reset counter on successful connection

        // Start ping interval
        pingInterval = setInterval(() => {
            // Check connection status before sending ping
            if (!controlSocket.destroyed) {
                sendMessage(controlSocket, {
                    type: 'ping',
                    time: Date.now()
                });
            }
        }, 30000); // Ping every 30 seconds

        // Start heartbeat interval - more frequent than ping
        heartbeatInterval = setInterval(() => {
            if (!controlSocket.destroyed) {
                sendMessage(controlSocket, {
                    type: 'heartbeat',
                    time: Date.now(),
                    tunnel_name: tunnelName,
                    stats: {
                        clientCount: Object.keys(clients).length
                    }
                });
            }

            // Check if we haven't received a heartbeat response in a while
            const timeSinceLastHeartbeat = Date.now() - lastHeartbeatResponse;
            if (timeSinceLastHeartbeat > options.heartbeatInterval * 3) {
                logger.warning(`No heartbeat response received for ${Math.round(timeSinceLastHeartbeat/1000)}s. Connection may be stale.`);
                controlSocket.destroy(); // Force reconnection
            }
        }, options.heartbeatInterval);
    });

    // Process incoming messages
    function processMessage(socket, message) {
        switch(message.type) {
            case 'welcome':
                logger.debug(`Received server welcome, client_id: ${message.client_id}`);

                // Load auth info (should be available now)
                auth.then(authData => {
                    if (!authData) {
                        socket.destroy();
                        rejectPromise(new Error('Authentication information not found'));
                        return;
                    }

                    // Login with token
                    sendMessage(socket, {
                        type: 'login',
                        token: authData.token
                    });
                });
                break;

            case 'login_response':
                if (message.success) {
                    // Register tunnel
                    sendMessage(socket, {
                        type: 'register_tunnel',
                        tunnel_name: tunnelName,
                        description: `Local service at ${localHost}:${localPort}`
                    });
                } else {
                    logger.error(`Authentication error: ${message.message}`);
                    socket.destroy();
                    rejectPromise(new Error(`Authentication error: ${message.message}`));
                }
                break;

            case 'tunnel_registered':
                registered = true;
                tunnelState.reconnectionAttempts = 0; // Reset counter when successfully registered
                tunnelPort = message.port;
                logger.success(`Tunnel successfully registered! Your service is accessible at:`);
                logger.success(`  ${SERVER_HOST}:${message.port}`);
                resolvePromise({
                    controlSocket,
                    tunnelName,
                    tunnelPort,
                    isConnected: true,
                    clients,
                    options
                });
                break;

            case 'error':
                logger.error(`Server error: ${message.message}`);
                if (!registered) {
                    socket.destroy();
                    rejectPromise(new Error(`Server error: ${message.message}`));
                }
                break;

            case 'connection':
                handleNewConnection(socket, message.client_id, message.remote_address, message.remote_port, tunnelName);
                break;

            case 'data':
                forwardDataToLocalService(message.client_id, message.data);
                break;

            case 'client_disconnected':
                closeClientConnection(message.client_id);
                break;

            case 'pong':
            case 'heartbeat_ack':
                // Update last heartbeat response time
                lastHeartbeatResponse = Date.now();
                break;

            default:
                logger.debug(`Unknown message type: ${message.type}`);
                break;
        }
    }

    // Handler functions for client connections
    function handleNewConnection(controlSocket, clientId, remoteAddress, remotePort, tunnelName) {
        logger.info(`New connection from ${remoteAddress}:${remotePort} (ID: ${clientId})`);

        // Create connection to local service
        const localSocket = new net.Socket();

        // Save client information with queue for data
        clients[clientId] = {
            socket: localSocket,
            connected: false,
            bytesReceived: 0,
            bytesSent: 0,
            queuedData: [],
            remoteAddress,
            remotePort,
            connectionTime: Date.now()
        };

        // Correctly convert local port number
        const parsedLocalPort = parseInt(localPort, 10);
        if (isNaN(parsedLocalPort)) {
            logger.error(`Invalid local port: ${localPort}`);
            return;
        }

        // Set timeout for local connection
        localSocket.setTimeout(options.connectionTimeout);

        localSocket.on('timeout', () => {
            logger.warning(`Local connection timeout for client ${clientId}`);
            localSocket.destroy();
        });

        localSocket.connect(parsedLocalPort, localHost, () => {
            logger.info(`Connected to local service for client ${clientId}`);
            clients[clientId].connected = true;

            // Tell the server we're ready to receive data
            sendMessage(controlSocket, {
                type: 'client_ready',
                client_id: clientId,
                tunnel_name: tunnelName
            });

            // Process queued data if any
            if (clients[clientId].queuedData.length > 0) {
                logger.debug(`Processing ${clients[clientId].queuedData.length} queued data chunks for client ${clientId}`);

                while (clients[clientId].queuedData.length > 0) {
                    const data = clients[clientId].queuedData.shift();
                    localSocket.write(data);
                    clients[clientId].bytesReceived += data.length;
                }
            }
        });

        localSocket.on('data', data => {
            // Forward data from local service to client
            if (controlSocket && !controlSocket.destroyed) {
                sendMessage(controlSocket, {
                    type: 'data',
                    client_id: clientId,
                    data: data.toString('base64')
                });

                clients[clientId].bytesSent += data.length;
            }
        });

        localSocket.on('error', err => {
            logger.error(`Local service error for client ${clientId}: ${err.message}`);
            closeClientConnection(clientId);
        });

        localSocket.on('close', () => {
            logger.info(`Local service closed connection for client ${clientId}`);

            // Log transfer stats
            if (clients[clientId]) {
                logger.info(`Data transfer for client ${clientId}: Sent ${formatBytes(clients[clientId].bytesSent)}, Received ${formatBytes(clients[clientId].bytesReceived)}`);
            }

            closeClientConnection(clientId);

            // Notify server
            if (controlSocket && !controlSocket.destroyed) {
                sendMessage(controlSocket, {
                    type: 'client_disconnected',
                    client_id: clientId
                });
            }
        });
    }

    function forwardDataToLocalService(clientId, dataBase64) {
        if (!clients[clientId]) {
            logger.error(`Received data for unknown client ${clientId}`);
            return;
        }

        try {
            const data = Buffer.from(dataBase64, 'base64');

            if (clients[clientId].connected) {
                // Send data to local service
                clients[clientId].socket.write(data);
                clients[clientId].bytesReceived += data.length;

                if (process.env.DEBUG) {
                    logger.debug(`Data forwarded to local service for client ${clientId} (${data.length} bytes)`);
                }
            } else {
                // Queue data until connected
                clients[clientId].queuedData.push(data);
                logger.debug(`Data queued for client ${clientId} (${data.length} bytes), waiting for connection`);
            }
        } catch (err) {
            logger.error(`Error forwarding data to local service for client ${clientId}: ${err}`);
        }
    }

    function closeClientConnection(clientId) {
        if (!clients[clientId]) return;

        if (clients[clientId].socket && !clients[clientId].socket.destroyed) {
            clients[clientId].socket.destroy();
        }

        if (clients[clientId].connected) {
            logger.info(`Client ${clientId} disconnected. Transfer: ${formatBytes(clients[clientId].bytesSent)} sent, ${formatBytes(clients[clientId].bytesReceived)} received`);
        }

        delete clients[clientId];
    }

    return controlSocket;
}

// Function to handle reconnection attempts with exponential backoff
async function attemptReconnection(tunnelName, localHost, localPort, tunnelPort, tunnelState, options, resolveOriginalPromise) {
    if (tunnelState.reconnectionAttempts >= options.maxReconnectionAttempts) {
        logger.error(`Failed to reconnect after ${options.maxReconnectionAttempts} attempts. Stopping tunnel.`);

        // Get tunnel data to find and stop the process
        const tunnelsData = await loadActiveTunnels();
        if (tunnelsData.active) {
            const activeTunnel = tunnelsData.active.find(t => t.name === tunnelName);
            if (activeTunnel) {
                try {
                    process.kill(activeTunnel.pid);
                    logger.warning(`Tunnel ${tunnelName} stopped due to connection failures.`);

                    // Remove from active tunnels
                    tunnelsData.active = tunnelsData.active.filter(t => t.name !== tunnelName);
                    await saveActiveTunnels(tunnelsData);
                } catch (err) {
                    logger.error(`Could not stop process: ${err.message}`);
                }
            }
        }

        tunnelState.isReconnecting = false;
        return;
    }

    tunnelState.reconnectionAttempts++;
    logger.warning(`Attempting to reconnect (${tunnelState.reconnectionAttempts}/${options.maxReconnectionAttempts})...`);

    // Clear any existing reconnection timer
    if (reconnectionTimer) {
        clearTimeout(reconnectionTimer);
    }

    // Exponential backoff with jitter
    const delay = Math.min(
        RECONNECTION_BASE_DELAY * Math.pow(2, tunnelState.reconnectionAttempts - 1) * (0.5 + Math.random()),
        30000 // Cap at 30 seconds
    );

    logger.info(`Reconnecting in ${Math.round(delay/1000)} seconds...`);

    reconnectionTimer = setTimeout(async () => {
        try {
            logger.info(`Reconnecting to tunnel ${tunnelName}...`);

            // Create new control connection
            const controlSocket = createControlConnection(
                tunnelName,
                localHost,
                localPort,
                tunnelState,
                options,
                resolveOriginalPromise,
                (err) => {
                    logger.error(`Reconnection attempt failed: ${err.message}`);
                    // Try again with the next attempt
                    attemptReconnection(tunnelName, localHost, localPort, tunnelPort, tunnelState, options, resolveOriginalPromise);
                }
            );
        } catch (err) {
            logger.error(`Error during reconnection attempt: ${err.message}`);
            // Try again
            attemptReconnection(tunnelName, localHost, localPort, tunnelPort, tunnelState, options, resolveOriginalPromise);
        }
    }, delay);
}

// Modify the runTunnel function to use our enhanced tunnel client
async function runTunnel(argv) {
    try {
        if (!argv.name || !argv.port) {
            logger.error('Tunnel name and port are required');
            console.log('Usage: node client.js run --name <tunnel_name> --host <local_host> --port <local_port>');
            return;
        }

        // Safely convert port value
        const localPort = parseInt(argv.port, 10);
        if (isNaN(localPort)) {
            logger.error(`Invalid port: ${argv.port}`);
            return;
        }

        logger.info(`Starting tunnel ${argv.name} (${argv.host || 'localhost'}:${localPort})`);

        const options = {
            autoReconnect: argv.autoReconnect !== false,
            maxReconnectionAttempts: argv.maxRetries || MAX_RECONNECTION_ATTEMPTS,
            connectionTimeout: argv.timeout || CONNECTION_TIMEOUT,
            heartbeatInterval: argv.heartbeatInterval || HEARTBEAT_INTERVAL
        };

        const tunnel = await createTunnelClient(argv.name, argv.host || 'localhost', localPort, options);

        if (tunnel) {
            logger.success(`Tunnel successfully created!`);

            // Track stats
            let lastStats = {
                clientCount: 0,
                bytesSent: 0,
                bytesReceived: 0
            };

            // Set up connection health check and stats
            const healthCheck = setInterval(() => {
                if (!tunnel.controlSocket || tunnel.controlSocket.destroyed) {
                    logger.warning('Tunnel connection appears to be down.');
                    clearInterval(healthCheck);
                    return;
                }

                // Calculate current stats
                let totalBytesSent = 0;
                let totalBytesReceived = 0;
                const clientCount = Object.keys(tunnel.clients).length;

                Object.values(tunnel.clients).forEach(client => {
                    totalBytesSent += client.bytesSent || 0;
                    totalBytesReceived += client.bytesReceived || 0;
                });

                // Log stats if changed significantly
                if (clientCount !== lastStats.clientCount ||
                    Math.abs(totalBytesSent - lastStats.bytesSent) > 1024*1024 ||
                    Math.abs(totalBytesReceived - lastStats.bytesReceived) > 1024*1024) {

                    logger.info(`Tunnel stats: ${clientCount} active clients, ${formatBytes(totalBytesSent)} sent, ${formatBytes(totalBytesReceived)} received`);

                    lastStats = {
                        clientCount,
                        bytesSent: totalBytesSent,
                        bytesReceived: totalBytesReceived
                    };
                }
            }, 60000); // Check every minute

            // Catch Ctrl+C
            process.on('SIGINT', () => {
                logger.info('Closing tunnel...');
                clearInterval(healthCheck);
                if (tunnel.controlSocket && !tunnel.controlSocket.destroyed) {
                    tunnel.controlSocket.destroy();
                }
                process.exit(0);
            });

            // Keep process alive for tunnel to persist
            setInterval(() => {}, 1000000);
        }
    } catch (err) {
        logger.error('Error during tunnel run: ' + err.message);
        process.exit(1);
    }
}

// Add a new function to check all tunnels and restart any that have crashed
async function checkAndRestartTunnels() {
    try {
        const tunnelsData = await loadActiveTunnels();

        if (!tunnelsData.active || tunnelsData.active.length === 0) {
            logger.debug('No active tunnels to check.');
            return;
        }

        logger.info('Checking status of all active tunnels...');

        // Get current running tunnels
        let needsUpdate = false;

        for (const tunnel of tunnelsData.active) {
            const isRunning = await isProcessRunning(tunnel.pid);

            if (!isRunning) {
                logger.warning(`Tunnel "${tunnel.name}" (PID: ${tunnel.pid}) is not running. Attempting to restart...`);

                // Get tunnel configuration
                const tunnelConfig = tunnelsData.tunnels.find(t => t.name === tunnel.name);

                if (tunnelConfig) {
                    try {
                        // Start tunnel in background
                        const activeTunnel = await startTunnelInBackground({
                            name: tunnel.name,
                            localHost: tunnelConfig.localHost,
                            localPort: tunnelConfig.localPort
                        });

                        // Update tunnel in active list
                        const index = tunnelsData.active.findIndex(t => t.name === tunnel.name);
                        if (index !== -1) {
                            tunnelsData.active[index] = activeTunnel;
                        }

                        logger.success(`Restarted tunnel "${tunnel.name}" with new PID: ${activeTunnel.pid}`);
                        needsUpdate = true;
                    } catch (err) {
                        logger.error(`Failed to restart tunnel "${tunnel.name}": ${err.message}`);
                    }
                } else {
                    logger.error(`Could not find configuration for tunnel "${tunnel.name}"`);
                    // Remove from active tunnels
                    tunnelsData.active = tunnelsData.active.filter(t => t.name !== tunnel.name);
                    needsUpdate = true;
                }
            } else {
                logger.debug(`Tunnel "${tunnel.name}" (PID: ${tunnel.pid}) is running.`);
            }
        }

        // Save updated tunnel status
        if (needsUpdate) {
            await saveActiveTunnels(tunnelsData);
        }
    } catch (err) {
        logger.error('Error checking tunnels: ' + err.message);
    }
}

// Add a helper function to add automatic tunnel checking capability
function enableTunnelMonitoring() {
    // Check tunnels every 5 minutes
    setInterval(checkAndRestartTunnels, 5 * 60 * 1000);
    logger.info('Automatic tunnel monitoring enabled. Checks will run every 5 minutes.');
}

// Start tunnel in background
async function startTunnelInBackground(tunnelInfo) {
    return new Promise((resolve, reject) => {
        try {
            // Check and convert local port value
            const localPort = parseInt(tunnelInfo.localPort, 10);
            if (isNaN(localPort)) {
                reject(new Error(`Invalid local port: ${tunnelInfo.localPort}`));
                return;
            }

            // Build the command-line arguments
            const args = [__filename, 'run',
                '--name', tunnelInfo.name,
                '--host', tunnelInfo.localHost,
                '--port', localPort.toString()
            ];

            // Add additional options if specified
            if (tunnelInfo.autoReconnect === false) {
                args.push('--no-auto-reconnect');
            }

            if (tunnelInfo.maxRetries) {
                args.push('--max-retries', tunnelInfo.maxRetries.toString());
            }

            if (tunnelInfo.debug) {
                args.push('--debug');
            }

            // Start tunnel client in a separate process
            const childProcess = child_process.spawn(process.execPath, args, {
                detached: true,
                stdio: 'ignore'
            });

            // Detach child process from parent
            childProcess.unref();

            // Keep track of PID
            resolve({
                pid: childProcess.pid,
                name: tunnelInfo.name,
                localHost: tunnelInfo.localHost,
                localPort: localPort,
                startedAt: new Date().toISOString()
            });
        } catch (err) {
            logger.error('Could not start tunnel: ' + err);
            reject(err);
        }
    });
}

// Check if process is running
async function isProcessRunning(pid) {
    try {
        process.kill(pid, 0);
        return true;
    } catch (err) {
        return false;
    }
}

// Command: Login
async function login(argv) {
    try {
        const auth = await loadAuth();

        // Use inquirer to get login information
        const answers = await inquirer.prompt([
            {
                type: 'input',
                name: 'server',
                message: 'Server address:',
                default: argv.server || auth?.server || 'localhost'
            },
            {
                type: 'input',
                name: 'port',
                message: 'Server port:',
                default: (argv.port || auth?.port || 9012).toString(),
                validate: (input) => {
                    const port = parseInt(input, 10);
                    return !isNaN(port) && port > 0 && port < 65536 ? true : 'Enter a valid port number (1-65535)';
                }
            },
            {
                type: 'input',
                name: 'username',
                message: 'Username:',
                validate: (input) => input.trim() ? true : 'Username is required'
            },
            {
                type: 'password',
                name: 'password',
                message: 'Password:',
                mask: '*',
                validate: (input) => input.trim() ? true : 'Password is required'
            }
        ]);

        // Safely convert port value
        const port = parseInt(answers.port, 10);
        if (isNaN(port)) {
            logger.error(`Invalid port number: ${answers.port}`);
            return;
        }

        // Connect to server and login
        const response = await connectAndSend({
            type: 'login',
            username: answers.username,
            password: answers.password,
            server: answers.server,
            port: port
        });

        if (response.success) {
            // Save credentials
            const auth = {
                server: answers.server,
                port: port,
                token: response.token,
                user: response.user,
                loginTime: new Date().toISOString()
            };

            await saveAuth(auth);

            logger.success(`Successfully logged in! Welcome, ${response.user.username}`);

            // Auto-start API server after successful login
            logger.info("Starting API server in the background...");
            const apiStarted = await startApiServer();

            if (apiStarted) {
                logger.success("API server has been started successfully!");
                logger.info(`API is accessible at: http://localhost:9011/api`);
            } else {
                logger.warning("Could not start API server automatically. You can start it manually with the 'api start' command.");
            }
        } else {
            logger.error(`Login failed: ${response.message}`);
        }
    } catch (err) {
        logger.error('Error during login: ' + err.message);
    }
}

// Command: Logout
async function logout() {
    try {
        if (fs.existsSync(AUTH_FILE)) {
            await inquirer.prompt([
                {
                    type: 'confirm',
                    name: 'confirm',
                    message: 'Are you sure you want to log out?',
                    default: true
                }
            ]).then(async (answers) => {
                if (answers.confirm) {
                    fs.unlinkSync(AUTH_FILE);
                    logger.success('Successfully logged out');

                    await stopApiServer();

                } else {
                    logger.info('Logout cancelled');
                }
            });
        } else {
            logger.info('Already logged out');
        }
    } catch (err) {
        logger.error('Error during logout: ' + err.message);
    }
}

// Command: Change password
async function changePassword() {
    try {
        // Check if session is active
        const auth = await loadAuth();
        if (!auth) {
            logger.error('You must be logged in to change your password');
            console.log('To login: node client.js login');
            return;
        }

        // Get password information from user
        const answers = await inquirer.prompt([
            {
                type: 'password',
                name: 'currentPassword',
                message: 'Current password:',
                mask: '*',
                validate: (input) => input.trim() ? true : 'Current password is required'
            },
            {
                type: 'password',
                name: 'newPassword',
                message: 'New password:',
                mask: '*',
                validate: (input) => {
                    if (!input.trim()) return 'New password is required';
                    if (input.length < 6) return 'Password must be at least 6 characters';
                    return true;
                }
            },
            {
                type: 'password',
                name: 'confirmPassword',
                message: 'Confirm new password:',
                mask: '*',
                validate: (input, answers) => {
                    if (!input.trim()) return 'Password confirmation is required';
                    if (input !== answers.newPassword) return 'Passwords do not match';
                    return true;
                }
            }
        ]);

        // Double check that passwords match
        if (answers.newPassword !== answers.confirmPassword) {
            logger.error('Passwords do not match');
            return;
        }

        // Send password change request
        const response = await connectAndSend({
            type: 'change_password',
            current_password: answers.currentPassword,
            new_password: answers.newPassword
        });

        if (response.success) {
            logger.success(response.message);

            // Keep user info but ask to log in again
            const { confirmLogout } = await inquirer.prompt([
                {
                    type: 'confirm',
                    name: 'confirmLogout',
                    message: 'Your password has been changed. You need to log in again for changes to take effect. Do you want to log out now?',
                    default: true
                }
            ]);

            if (confirmLogout) {
                // Delete auth.json file
                if (fs.existsSync(AUTH_FILE)) {
                    fs.unlinkSync(AUTH_FILE);
                    logger.success('Logged out. Please log in again with your new password.');
                    console.log('To login: node client.js login');
                }
            } else {
                logger.info('Please log in again later.');
            }
        } else {
            logger.error(`Password change failed: ${response.message}`);
        }
    } catch (err) {
        logger.error('Error during password change: ' + err.message);
    }
}

// Command: Create tunnel
async function createTunnel(argv) {
    try {
        const answers = await inquirer.prompt([
            {
                type: 'input',
                name: 'name',
                message: 'Tunnel name:',
                default: argv.name,
                validate: (input) => input.trim() ? true : 'Tunnel name is required'
            },
            {
                type: 'input',
                name: 'description',
                message: 'Description (optional):'
            },
            {
                type: 'input',
                name: 'localHost',
                message: 'Local service address:',
                default: argv.host || 'localhost'
            },
            {
                type: 'input',
                name: 'localPort',
                message: 'Local service port:',
                default: argv.port ? argv.port.toString() : '',
                validate: (input) => {
                    const port = parseInt(input, 10);
                    return !isNaN(port) && port > 0 && port < 65536 ? true : 'Enter a valid port number (1-65535)';
                }
            }
        ]);

        // Request tunnel creation from server
        const response = await connectAndSend({
            type: 'register_tunnel',
            tunnel_name: answers.name,
            description: answers.description
        });

        if (response.type === 'tunnel_registered') {
            // Save tunnel information locally
            const tunnelsData = await loadActiveTunnels();

            // Check if a tunnel with the same name already exists
            const existingIndex = tunnelsData.tunnels.findIndex(t => t.name === answers.name);

            const tunnelInfo = {
                name: answers.name,
                description: answers.description,
                localHost: answers.localHost,
                localPort: parseInt(answers.localPort, 10),
                serverPort: response.port,
                createdAt: new Date().toISOString()
            };

            if (existingIndex !== -1) {
                tunnelsData.tunnels[existingIndex] = tunnelInfo;
            } else {
                tunnelsData.tunnels.push(tunnelInfo);
            }

            await saveActiveTunnels(tunnelsData);

            logger.success(`Tunnel successfully created: ${answers.name}`);

            // Show summary with table
            const table = new Table({
                head: [
                    colors.title('Property'),
                    colors.title('Value')
                ]
            });

            table.push(
                ['Tunnel Name', colors.highlight(answers.name)],
                ['Description', answers.description || '-'],
                ['Local Service', `${answers.localHost}:${answers.localPort}`],
                ['In/Port', colors.highlight(`${response.port}`)],
                ['Out/Port', colors.highlight(`${response.port}`)]
            );

            console.log(table.toString());

            // Ask if user wants to start the tunnel now
            const startAnswers = await inquirer.prompt([
                {
                    type: 'confirm',
                    name: 'startNow',
                    message: 'Would you like to start this tunnel now?',
                    default: true
                }
            ]);

            if (startAnswers.startNow) {
                await startTunnelById(tunnelInfo);
            }
        } else {
            logger.error(`Error creating tunnel: ${response.message || 'Unknown error'}`);
        }
    } catch (err) {
        logger.error('Error during tunnel creation: ' + err.message);
    }
}

// Command: List tunnels
async function listTunnels() {
    try {
        const response = await connectAndSend({
            type: 'list_tunnels'
        });

        if (response.type === 'tunnels_list') {
            if (response.tunnels.length === 0) {
                logger.info('No tunnels yet');
                return;
            }

            console.log(colors.title('\nTunnels:'));

            const table = new Table({
                head: [
                    colors.title('ID'),
                    colors.title('Name'),
                    colors.title('Out/Port'),
                    colors.title('Description'),
                    colors.title('Sent'),
                    colors.title('Received'),
                    colors.title('Connections'),
                    colors.title('Last Activity')
                ],
                colWidths: [5, 20, 10, 30, 12, 12, 12, 25]
            });

            const tunnelsData = await loadActiveTunnels();

            response.tunnels.forEach(tunnel => {
                // Check if active
                const isActive = tunnelsData.active && tunnelsData.active.some(t => t.name === tunnel.name);

                // Highlight tunnel name if active
                const tunnelName = isActive ? colors.highlight(tunnel.name) : tunnel.name;

                table.push([
                    tunnel.id,
                    tunnelName,
                    tunnel.port,
                    tunnel.description || '-',
                    formatBytes(tunnel.bytes_sent || 0),
                    formatBytes(tunnel.bytes_received || 0),
                    tunnel.active_connections || 0,
                    tunnel.lastActiveAt ? new Date(tunnel.lastActiveAt).toLocaleString() : '-'
                ]);
            });

            console.log(table.toString());
            console.log(`\nTotal: ${response.tunnels.length} tunnels\n`);

            // Show extra info about active tunnels
            const activeTunnels = tunnelsData.active && tunnelsData.active.filter(async t => await isProcessRunning(t.pid));
            if (activeTunnels && activeTunnels.length > 0) {
                console.log(colors.title('Note: Highlighted tunnels are currently active.\n'));
            }
        } else {
            logger.error('Error listing tunnels');
        }
    } catch (err) {
        logger.error('Error during tunnel listing: ' + err.message);
    }
}

// Start a specific tunnel by ID
async function startTunnelById(tunnelInfo) {
    try {
        const tunnelsData = await loadActiveTunnels();

        // Check if tunnel is already running
        const existingActiveTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === tunnelInfo.name) : null;

        if (existingActiveTunnel) {
            const isRunning = await isProcessRunning(existingActiveTunnel.pid);

            if (isRunning) {
                logger.warning(`This tunnel is already running. PID: ${existingActiveTunnel.pid}`);
                return;
            } else {
                // PID not found, clean up old record
                tunnelsData.active = tunnelsData.active.filter(t => t.name !== tunnelInfo.name);
            }
        }

        // Start tunnel in background
        logger.info(`Starting tunnel ${tunnelInfo.name}...`);

        const activeTunnel = await startTunnelInBackground(tunnelInfo);

        if (!tunnelsData.active) {
            tunnelsData.active = [];
        }

        tunnelsData.active.push(activeTunnel);
        await saveActiveTunnels(tunnelsData);

        logger.success(`Tunnel started successfully! PID: ${activeTunnel.pid}`);

        const table = new Table({
            head: [
                colors.title('Property'),
                colors.title('Value')
            ]
        });

        table.push(
            ['Tunnel Name', colors.highlight(tunnelInfo.name)],
            ['PID', activeTunnel.pid],
            ['In/Address', `${tunnelInfo.localHost}:${tunnelInfo.localPort}`],
            ['Out/Port', colors.highlight(`${tunnelInfo.serverPort}`)]
        );

        console.log(table.toString());
    } catch (err) {
        logger.error('Error during tunnel start: ' + err.message);
    }
}

// Command: Start tunnel
async function startTunnel() {
    try {
        const tunnelsData = await loadActiveTunnels();

        if (!tunnelsData.tunnels || tunnelsData.tunnels.length === 0) {
            logger.error('You need to create a tunnel first');
            console.log('To create a new tunnel: node client.js create');
            return;
        }

        // Check and update active tunnels
        if (tunnelsData.active && tunnelsData.active.length > 0) {
            const activeAndRunning = [];
            const stoppedTunnels = [];

            for (const tunnel of tunnelsData.active) {
                const isRunning = await isProcessRunning(tunnel.pid);
                if (isRunning) {
                    activeAndRunning.push(tunnel);
                } else {
                    stoppedTunnels.push(tunnel.name);
                }
            }

            if (stoppedTunnels.length > 0) {
                tunnelsData.active = activeAndRunning;
                await saveActiveTunnels(tunnelsData);
                logger.debug(`Cleaned up ${stoppedTunnels.length} stopped tunnels`);
            }
        }

        // Show tunnels to user
        const tunnelsChoices = tunnelsData.tunnels.map(t => ({
            name: `${t.name} (${t.localHost}:${t.localPort})${tunnelsData.active && tunnelsData.active.some(a => a.name === t.name) ? ' [RUNNING]' : ''}`,
            value: t,
            disabled: tunnelsData.active && tunnelsData.active.some(a => a.name === t.name)
        }));

        const { selectedTunnel } = await inquirer.prompt([
            {
                type: 'list',
                name: 'selectedTunnel',
                message: 'Select the tunnel you want to start:',
                choices: tunnelsChoices,
                pageSize: 10
            }
        ]);

        await startTunnelById(selectedTunnel);
    } catch (err) {
        logger.error('Error during tunnel start: ' + err.message);
    }
}

// Command: Stop tunnel
async function stopTunnel() {
    try {
        const tunnelsData = await loadActiveTunnels();

        if (!tunnelsData.active || tunnelsData.active.length === 0) {
            logger.error('No tunnels currently running');
            return;
        }

        // Check for actually running tunnels
        const runningTunnels = [];
        for (const tunnel of tunnelsData.active) {
            const isRunning = await isProcessRunning(tunnel.pid);
            if (isRunning) {
                runningTunnels.push(tunnel);
            }
        }

        if (runningTunnels.length === 0) {
            logger.warning('No running tunnels found');
            // Clean up all active tunnels (all processes probably terminated)
            tunnelsData.active = [];
            await saveActiveTunnels(tunnelsData);
            return;
        }

        // Show active tunnels to user
        const tunnelChoices = runningTunnels.map(t => ({
            name: `${t.name} (${t.localHost}:${t.localPort}, PID: ${t.pid})`,
            value: t
        }));

        const { selectedTunnel } = await inquirer.prompt([
            {
                type: 'list',
                name: 'selectedTunnel',
                message: 'Select the tunnel you want to stop:',
                choices: tunnelChoices
            }
        ]);

        // Ask for confirmation
        const { confirmStop } = await inquirer.prompt([
            {
                type: 'confirm',
                name: 'confirmStop',
                message: `Are you sure you want to stop the "${selectedTunnel.name}" tunnel?`,
                default: true
            }
        ]);

        if (!confirmStop) {
            logger.info('Operation cancelled');
            return;
        }

        // Stop the process
        try {
            process.kill(selectedTunnel.pid);
            logger.success(`Tunnel ${selectedTunnel.name} stopped. PID: ${selectedTunnel.pid}`);
        } catch (err) {
            logger.error(`Could not stop process: ${err.message}`);
            logger.info('Process may have already stopped, removing from registry...');
        }

        // Remove from active tunnels
        tunnelsData.active = tunnelsData.active.filter(t => t.pid !== selectedTunnel.pid);
        await saveActiveTunnels(tunnelsData);
    } catch (err) {
        logger.error('Error during tunnel stop: ' + err.message);
    }
}

// Command: Show tunnel status
async function showTunnelStatus() {
    try {
        const tunnelsData = await loadActiveTunnels();

        if (!tunnelsData.active || tunnelsData.active.length === 0) {
            logger.info('No tunnels currently running');
            return;
        }

        // Get tunnel information from server (including traffic statistics)
        const response = await connectAndSend({
            type: 'list_tunnels'
        });

        console.log(colors.title('\nActive Tunnels:'));

        const table = new Table({
            head: [
                colors.title('Name'),
                colors.title('PID'),
                colors.title('In/Address'),
                colors.title('Out/Port'),
                colors.title('Sent'),
                colors.title('Received'),
                colors.title('Connections'),
                colors.title('Status')
            ],
            colWidths: [20, 10, 30, 10, 15, 15, 15, 15]
        });

        // Process tunnel data from server
        const tunnelInfoMap = {};
        if (response.type === 'tunnels_list') {
            response.tunnels.forEach(tunnel => {
                tunnelInfoMap[tunnel.name] = tunnel;
            });
        }

        for (const tunnel of tunnelsData.active) {
            const isRunning = await isProcessRunning(tunnel.pid);
            const status = isRunning
                ? colors.success('RUNNING')
                : colors.error('STOPPED');

            // Find server port for the tunnel
            const tunnelInfo = tunnelsData.tunnels.find(t => t.name === tunnel.name);
            const serverPort = tunnelInfo ? tunnelInfo.serverPort : 'N/A';

            // Find traffic information from server
            const serverTunnelInfo = tunnelInfoMap[tunnel.name] || {};
            const bytesSent = serverTunnelInfo.bytes_sent || 0;
            const bytesReceived = serverTunnelInfo.bytes_received || 0;
            const activeConnections = serverTunnelInfo.active_connections || 0;

            table.push([
                colors.highlight(tunnel.name),
                tunnel.pid,
                `${tunnel.localHost}:${tunnel.localPort}`,
                serverPort,
                formatBytes(bytesSent),
                formatBytes(bytesReceived),
                activeConnections,
                status
            ]);
        }

        console.log(table.toString());

        // Offer to clean up stopped tunnels
        const stoppedTunnels = [];
        for (const tunnel of tunnelsData.active) {
            const isRunning = await isProcessRunning(tunnel.pid);
            if (!isRunning) {
                stoppedTunnels.push(tunnel);
            }
        }

        if (stoppedTunnels.length > 0) {
            const { cleanupStopped } = await inquirer.prompt([
                {
                    type: 'confirm',
                    name: 'cleanupStopped',
                    message: `Found ${stoppedTunnels.length} stopped tunnel records. Do you want to clean them up?`,
                    default: true
                }
            ]);

            if (cleanupStopped) {
                tunnelsData.active = tunnelsData.active.filter(t => !stoppedTunnels.some(s => s.pid === t.pid));
                await saveActiveTunnels(tunnelsData);
                logger.success(`Cleaned up ${stoppedTunnels.length} stopped tunnels`);
            }
        }
    } catch (err) {
        logger.error('Error during tunnel status display: ' + err.message);
    }
}

// Command: Show tunnel details
async function showTunnelDetails() {
    try {
        // List tunnels
        const response = await connectAndSend({
            type: 'list_tunnels'
        });

        if (response.type !== 'tunnels_list' || response.tunnels.length === 0) {
            logger.info('No tunnels found to display');
            return;
        }

        // Show tunnels to user
        const tunnelChoices = response.tunnels.map(tunnel => ({
            name: `${tunnel.name} (Port: ${tunnel.port}) - ${tunnel.description || 'No description'}`,
            value: tunnel
        }));

        const { selectedTunnel } = await inquirer.prompt([
            {
                type: 'list',
                name: 'selectedTunnel',
                message: 'Select the tunnel to view details:',
                choices: tunnelChoices,
                pageSize: 10
            }
        ]);

        // Show detailed information for selected tunnel
        console.log(colors.title(`\n"${selectedTunnel.name}" Tunnel Details:`));

        const detailsTable = new Table();

        // Check if active
        const tunnelsData = await loadActiveTunnels();
        const activeTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === selectedTunnel.name) : null;
        const isActive = activeTunnel ? await isProcessRunning(activeTunnel.pid) : false;

        // Local service information
        const tunnelInfo = tunnelsData.tunnels.find(t => t.name === selectedTunnel.name) || {};

        detailsTable.push(
            { 'Tunnel Name': colors.highlight(selectedTunnel.name) },
            { 'Status': isActive ? colors.success('RUNNING') : colors.warning('INACTIVE') },
            { 'Out/Port': selectedTunnel.port.toString() },
            { 'Description': selectedTunnel.description || '-' },
            { 'Created': new Date(selectedTunnel.createdAt).toLocaleString() },
            { 'Last Activity': selectedTunnel.lastActiveAt ? new Date(selectedTunnel.lastActiveAt).toLocaleString() : '-' },
            { 'Owner': selectedTunnel.owner },
            { 'Active Clients': selectedTunnel.active_connections || '0' }
        );

        if (tunnelInfo.localHost && tunnelInfo.localPort) {
            detailsTable.push({ 'Local Service': `${tunnelInfo.localHost}:${tunnelInfo.localPort}` });
        }

        if (isActive && activeTunnel) {
            detailsTable.push(
                { 'PID': activeTunnel.pid.toString() },
                { 'Start Time': new Date(activeTunnel.startedAt).toLocaleString() }
            );
        }

        // Traffic information
        detailsTable.push(
            { 'Data Sent': formatBytes(selectedTunnel.bytes_sent || 0) },
            { 'Data Received': formatBytes(selectedTunnel.bytes_received || 0) },
            { 'Total Traffic': formatBytes((selectedTunnel.bytes_sent || 0) + (selectedTunnel.bytes_received || 0)) }
        );

        console.log(detailsTable.toString());

        // Active connection information
        if (isActive) {
            console.log(colors.title('\nActive Connection Information:'));
            console.log(`Out/Address: ${colors.highlight(`${tunnelsData.active[0].server || 'localhost'}:${selectedTunnel.port}`)}`);
            console.log(`In/Address: ${colors.highlight(`${tunnelInfo.localHost || 'localhost'}:${tunnelInfo.localPort}`)}`);
        }

        console.log('\n');

    } catch (err) {
        logger.error('Error during tunnel details display: ' + err.message);
    }
}

// Command: Delete tunnel
async function deleteTunnel() {
    try {
        // List tunnels
        const response = await connectAndSend({
            type: 'list_tunnels'
        });

        if (response.type !== 'tunnels_list' || response.tunnels.length === 0) {
            logger.info('No tunnels found to delete');
            return;
        }

        // Show tunnels to user
        const tunnelChoices = response.tunnels.map(tunnel => ({
            name: `${tunnel.name} (Port: ${tunnel.port}) - ${tunnel.description || 'No description'}`,
            value: tunnel
        }));

        const { selectedTunnel } = await inquirer.prompt([
            {
                type: 'list',
                name: 'selectedTunnel',
                message: 'Select the tunnel you want to delete:',
                choices: tunnelChoices,
                pageSize: 10
            }
        ]);

        // Ask for confirmation
        const { confirmDelete } = await inquirer.prompt([
            {
                type: 'confirm',
                name: 'confirmDelete',
                message: `Are you sure you want to delete the "${selectedTunnel.name}" tunnel? This action cannot be undone!`,
                default: false
            }
        ]);

        if (!confirmDelete) {
            logger.info('Delete operation cancelled');
            return;
        }

        // Delete tunnel from server
        const deleteResponse = await connectAndSend({
            type: 'delete_tunnel',
            tunnel_name: selectedTunnel.name
        });

        if (deleteResponse.type === 'tunnel_deleted') {
            logger.success(`Tunnel "${selectedTunnel.name}" successfully deleted from server`);

            // Remove tunnel from local records
            const tunnelsData = await loadActiveTunnels();

            // Stop if running
            const activeTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === selectedTunnel.name) : null;
            if (activeTunnel) {
                try {
                    const isRunning = await isProcessRunning(activeTunnel.pid);
                    if (isRunning) {
                        logger.info(`Stopping active running tunnel. PID: ${activeTunnel.pid}`);
                        process.kill(activeTunnel.pid);
                    }
                } catch (err) {
                    logger.error(`Error stopping running tunnel: ${err.message}`);
                }
                // Remove from active tunnels
                tunnelsData.active = tunnelsData.active.filter(t => t.name !== selectedTunnel.name);
            }

            // Remove from defined tunnels
            tunnelsData.tunnels = tunnelsData.tunnels.filter(t => t.name !== selectedTunnel.name);

            // Save changes
            await saveActiveTunnels(tunnelsData);
            logger.success(`Tunnel "${selectedTunnel.name}" also removed from local records`);
        } else {
            logger.error(`Error deleting tunnel: ${deleteResponse.message || 'Unknown error'}`);
        }
    } catch (err) {
        logger.error('Error during tunnel deletion: ' + err.message);
    }
}

// Main function
async function main() {
    // Process command line arguments with yargs
    const argv = yargs(hideBin(process.argv))
        .scriptName('vtunnel client')
        .usage('$0 <command> [options]')
        .command('login', 'Log in to the tunnel server', (yargs) => {
            return yargs
                .option('server', {
                    alias: 's',
                    describe: 'Server address',
                    type: 'string',
                    default: 'localhost'
                })
                .option('port', {
                    alias: 'p',
                    describe: 'Server port',
                    type: 'number',
                    default: 9012
                });
        })
        .command('logout', 'Log out from the tunnel server')
        .command('password', 'Change your password')
        .command('create', 'Define a new tunnel')
        .command('list', 'List all tunnels')
        .command('details', 'Show details of a tunnel')
        .command('delete', 'Delete a tunnel')
        .command('start', 'Start a tunnel')
        .command('stop', 'Stop a running tunnel')
        .command('status', 'Show status of tunnels')
        .command('monitor', 'Enable automatic tunnel monitoring (restarts crashed tunnels)')
        .command('api', 'API server management', (yargs) => {
            return yargs
                .command('start', 'Start the API server')
                .command('stop', 'Stop the API server')
                .command('status', 'Check API server status')
                .demandCommand(1, 'Please specify an API server command');
        })
        .command('run', 'Start a tunnel directly (in background)', (yargs) => {
            return yargs
                .option('name', {
                    alias: 'n',
                    describe: 'Tunnel name',
                    type: 'string',
                    demandOption: true
                })
                .option('host', {
                    alias: 'h',
                    describe: 'Local service address',
                    type: 'string',
                    default: 'localhost'
                })
                .option('port', {
                    alias: 'lp',
                    describe: 'Local service port',
                    type: 'number',
                    demandOption: true
                })
                .option('auto-reconnect', {
                    alias: 'r',
                    describe: 'Automatically reconnect if connection is lost',
                    type: 'boolean',
                    default: true
                })
                .option('max-retries', {
                    alias: 'mr',
                    describe: 'Maximum reconnection attempts',
                    type: 'number',
                    default: MAX_RECONNECTION_ATTEMPTS
                })
                .option('timeout', {
                    alias: 't',
                    describe: 'Connection timeout in milliseconds',
                    type: 'number',
                    default: CONNECTION_TIMEOUT
                })
                .option('debug', {
                    alias: 'd',
                    describe: 'Enable debug logging',
                    type: 'boolean',
                    default: false
                });
        })
        .help()
        .alias('help', 'h')
        .version('1.2.0')
        .alias('version', 'v')
        .epilog('VTunnel Client - Secure Tunnel Routing Client')
        .argv;

    // Apply debug flag
    if (argv.debug) {
        process.env.DEBUG = 'true';
        logger.debug('Debug logging enabled');
    }

    const command = argv._[0];
    const subCommand = argv._[1]; // For nested commands like 'api start'

    try {
        switch (command) {
            case 'login':
                await login(argv);
                break;

            case 'logout':
                await logout();
                break;

            case 'create':
                await createTunnel(argv);
                break;

            case 'list':
                await listTunnels();
                break;

            case 'details':
                await showTunnelDetails();
                break;

            case 'delete':
                await deleteTunnel();
                break;

            case 'start':
                await startTunnel();
                break;

            case 'stop':
                await stopTunnel();
                break;

            case 'status':
                await showTunnelStatus();
                break;

            case 'api':
                switch (subCommand) {
                    case 'start':
                        const auth = await loadAuth();
                        if (!auth) {
                            logger.error('You must be logged in to start the API server');
                            logger.info('Please use "node client.js login" to authenticate first');
                            return false;
                        }
                        await startApiServer();
                        logger.success('API server started successfully');
                        logger.info(`API is accessible at: http://localhost:9011/api`);
                        break;
                    case 'stop':
                        await stopApiServer();
                        break;
                    case 'status':
                        const apiRunning = await isApiServerRunning();
                        if (apiRunning) {
                            logger.success('API server is running');
                            logger.info(`API is accessible at: http://localhost:9011/api`);
                        } else {
                            logger.info('API server is not running');
                            logger.info('To start the API server, use: node client.js api start');
                        }
                        break;
                    default:
                        logger.error('Unknown API server command');
                        console.log('Available commands: start, stop, status');
                        break;
                }
                break;

            case 'monitor':
                // Run initial check
                await checkAndRestartTunnels();

                // Enable continuous monitoring
                enableTunnelMonitoring();

                logger.info('Tunnel monitoring service started.');
                logger.info('Press Ctrl+C to stop monitoring.');

                // Keep process alive
                setInterval(() => {}, 1000000);
                break;

            case 'run':
                await runTunnel(argv);
                break;

            case 'password':
                await changePassword();
                break;

            default:
                yargs().showHelp();
                break;
        }
    } catch (err) {
        logger.error('Error during operation: ' + err.message);
        process.exit(1);
    }
}

main();
