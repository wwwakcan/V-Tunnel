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
 * @version     1.0.3
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

// Create Tunnel Client
async function createTunnelClient(tunnelName, localHost, localPort) {
    const auth = await loadAuth();
    if (!auth) {
        logger.error('Authentication information not found. Please use the "login" command first.');
        return null;
    }

    logger.info(`Starting tunnel ${tunnelName}...`);
    logger.info(`Server: ${auth.server}:${auth.port}`);
    logger.info(`Target: ${localHost}:${localPort}`);

    return new Promise((resolve, reject) => {
        // Safely convert port value
        const SERVER_HOST = auth.server;
        const SERVER_PORT = parseInt(auth.port, 10);

        if (isNaN(SERVER_PORT) || SERVER_PORT <= 0 || SERVER_PORT >= 65536) {
            reject(new Error(`Invalid port number: ${auth.port}`));
            return;
        }

        const controlSocket = new net.Socket();
        let pingInterval;
        let registered = false;
        let tunnelPort;
        let buffer = '';

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
                reject(err);
                controlSocket.destroy();
            }
        });

        controlSocket.on('error', err => {
            logger.error('Control connection error: ' + err.message);
            reject(err);
        });

        controlSocket.on('close', () => {
            logger.info('Connection to tunnel server closed');
            clearInterval(pingInterval);
            resolve(null);  // Clean exit
        });

        controlSocket.connect(SERVER_PORT, SERVER_HOST, () => {
            logger.info('Connected to tunnel server');

            // Start ping interval
            pingInterval = setInterval(() => {
                sendMessage(controlSocket, { type: 'ping', time: Date.now() });
            }, 30000);
        });

        // Process incoming messages
        const clients = {};

        function processMessage(socket, message) {
            switch(message.type) {
                case 'welcome':
                    logger.debug(`Received server welcome, client_id: ${message.client_id}`);
                    // Login
                    sendMessage(socket, {
                        type: 'login',
                        token: auth.token
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
                        reject(new Error(`Authentication error: ${message.message}`));
                    }
                    break;

                case 'tunnel_registered':
                    registered = true;
                    tunnelPort = message.port;
                    logger.success(`Tunnel successfully registered! Your service is accessible at:`);
                    logger.success(`  ${auth.server}:${message.port}`);
                    resolve({ controlSocket, tunnelName, tunnelPort });
                    break;

                case 'error':
                    logger.error(`Server error: ${message.message}`);
                    if (!registered) {
                        socket.destroy();
                        reject(new Error(`Server error: ${message.message}`));
                    }
                    break;

                case 'connection':
                    handleNewConnection(socket, message.client_id, message.remote_address, message.remote_port);
                    break;

                case 'data':
                    forwardDataToLocalService(message.client_id, message.data);
                    break;

                case 'client_disconnected':
                    closeClientConnection(message.client_id);
                    break;

                case 'pong':
                    // Pong received, connection is still alive
                    break;

                default:
                    logger.debug(`Unknown message type: ${message.type}`);
                    break;
            }
        }

        // Handle a new client connection
        function handleNewConnection(controlSocket, clientId, remoteAddress, remotePort) {
            logger.info(`New connection from ${remoteAddress}:${remotePort} (ID: ${clientId})`);

            // Create connection to local service
            const localSocket = new net.Socket();

            // Save client information
            clients[clientId] = {
                socket: localSocket,
                connected: false,
                bytesReceived: 0,
                bytesSent: 0,
                queuedData: null
            };

            // Correctly convert local port number
            const parsedLocalPort = parseInt(localPort, 10);
            if (isNaN(parsedLocalPort)) {
                logger.error(`Invalid local port: ${localPort}`);
                return;
            }

            localSocket.connect(parsedLocalPort, localHost, () => {
                logger.info(`Connected to local service for client ${clientId}`);
                clients[clientId].connected = true;

                // Process queued data (if we received data before connecting)
                if (clients[clientId].queuedData) {
                    localSocket.write(clients[clientId].queuedData);
                    clients[clientId].bytesReceived += clients[clientId].queuedData.length;
                    delete clients[clientId].queuedData;
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

        // Forward data from remote client to local service
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
                    if (!clients[clientId].queuedData) {
                        clients[clientId].queuedData = data;
                    } else {
                        clients[clientId].queuedData = Buffer.concat([clients[clientId].queuedData, data]);
                    }
                    logger.debug(`Data queued for client ${clientId}, waiting for connection`);
                }
            } catch (err) {
                logger.error(`Error forwarding data to local service for client ${clientId}: ${err}`);
            }
        }

        // Close client connection
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
    });
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

            // Start tunnel client in a separate process
            const childProcess = child_process.spawn(process.execPath, [__filename, 'run',
                '--name', tunnelInfo.name,
                '--host', tunnelInfo.localHost,
                '--port', localPort.toString()
            ], {
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
                    colors.title('Last Activity')
                ],
                colWidths: [5, 25, 10, 45, 15, 15, 30]
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
                colors.title('Status')
            ],
            colWidths: [25, 10, 30, 15, 15, 15, 15]
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

            table.push([
                colors.highlight(tunnel.name),
                tunnel.pid,
                `${tunnel.localHost}:${tunnel.localPort}`,
                serverPort,
                formatBytes(bytesSent),
                formatBytes(bytesReceived),
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
            { 'Active Clients': selectedTunnel.clientCount || '0' }
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

// Command: Run tunnel (for background process)
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

        const tunnel = await createTunnelClient(argv.name, argv.host || 'localhost', localPort);

        if (tunnel) {
            logger.success(`Tunnel successfully created!`);

            // Catch Ctrl+C
            process.on('SIGINT', () => {
                logger.info('Closing tunnel...');
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
                });
        })
        .help()
        .alias('help', 'h')
        .version()
        .alias('version', 'v')
        .epilog('VTunnel Client - Secure Tunnel Routing Client')
        .argv;

    const command = argv._[0];

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

// Start the program
main();
