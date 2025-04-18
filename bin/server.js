#!/usr/bin/env node

/**
 * V-Tunnel - Lightweight Tunnel Routing Solution
 *
 * A 100% free and open-source alternative to commercial tunneling solutions
 * like Ngrok, Cloudflare Tunnel, and others.
 *
 * @file        server.js
 * @description Enhanced Tunnel Routing Server with SQLite and JWT Authentication
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
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const inquirer = require('inquirer');
const Table = require('cli-table3');
const colors = require('colors/safe');
const {spawn} = require("child_process");

// Load configuration from file if it exists
let config = {
    PORT: 9012,
    TUNNEL_PORT_RANGE_START:  51200,
    TUNNEL_PORT_RANGE_END: 52200,
    CONFIG_DIR: path.join(__dirname, '.vtunnel-server'),
};

// Check if config directory exists, create if not
if (!fs.existsSync(config.CONFIG_DIR)) {
    fs.mkdirSync(config.CONFIG_DIR, { recursive: true });
}

const configFilePath = path.join(config.CONFIG_DIR, 'config.json');
const bgFilePath = path.join(config.CONFIG_DIR, 'bg.json');

if (fs.existsSync(configFilePath)) {
    try {
        const fileConfig = JSON.parse(fs.readFileSync(configFilePath, 'utf8'));
        config = { ...config, ...fileConfig };
        console.log(`Loaded configuration from ${configFilePath}`);
    } catch (err) {
        console.error(`Error loading config file: ${err}`);
    }
}

// Configuration constants
const CONFIG_DIR = config.CONFIG_DIR;
const DB_FILE = path.join(CONFIG_DIR, 'vtunnel.db');
let PORT = config.PORT;
let TUNNEL_PORT_RANGE_START = config.TUNNEL_PORT_RANGE_START;
let TUNNEL_PORT_RANGE_END = config.TUNNEL_PORT_RANGE_END;
const HEARTBEAT_INTERVAL = 30000; // ms
const CONNECTION_TIMEOUT = 10000; // ms

// Database connection
let db;

// Logger
const logger = {
    info: (message) => console.log(colors.cyan(`[INFO] ${new Date().toISOString()} - ${message}`)),
    error: (message) => console.error(colors.red(`[ERROR] ${new Date().toISOString()} - ${message}`)),
    success: (message) => console.log(colors.green(`[SUCCESS] ${new Date().toISOString()} - ${message}`)),
    warning: (message) => console.log(colors.yellow(`[WARNING] ${new Date().toISOString()} - ${message}`)),
    debug: (message) => process.env.DEBUG && console.log(colors.gray(`[DEBUG] ${new Date().toISOString()} - ${message}`))
};

// State management
let availablePorts = [];
let tunnels = {};
let clients = {};
let sessions = {};

// Background process management
function startBackgroundProcess() {
    try {
        // Check if already running
        if (fs.existsSync(bgFilePath)) {
            try {
                const bgData = JSON.parse(fs.readFileSync(bgFilePath, 'utf8'));
                try {
                    process.kill(bgData.pid, 0);
                    logger.error(`V-Tunnel is already running in background with PID ${bgData.pid}`);
                    return false;
                } catch (e) {
                    logger.warning(`Found stale PID file. Previous instance (PID: ${bgData.pid}) is not running.`);
                }
            } catch (err) {
                logger.error(`Error reading background process info: ${err}`);
            }
        }

        // Get executable info
        let execCommand, execArgs;

        // Check if running from npm global install
        if (process.env._ && process.env._.includes('npm')) {
            // When run via npm global install
            execCommand = 'vtunnel';
            execArgs = process.argv.slice(2).filter(arg => arg !== 'background' && arg !== 'start');
        } else if (__filename.includes('node_modules')) {
            // When run from global install directly
            execCommand = 'vtunnel';
            execArgs = process.argv.slice(2).filter(arg => arg !== 'background' && arg !== 'start');
        } else {
            // When run from local project
            execCommand = process.execPath;
            execArgs = [process.argv[1]].concat(
                process.argv.slice(2).filter(arg => arg !== 'background' && arg !== 'start')
            );
        }

        // Add stats flag if not present
        if (!execArgs.includes('server')) {
            execArgs.push('server');
        }

        // Log the command for debugging
        logger.info(`Starting background process with command: ${execCommand} ${execArgs.join(' ')}`);

        const out = fs.openSync(path.join(CONFIG_DIR, 'vtunnel.log'), 'a');
        const err = fs.openSync(path.join(CONFIG_DIR, 'vtunnel-error.log'), 'a');

        // Use different spawn options for Windows vs Unix
        const spawnOptions = {
            detached: true,
            stdio: ['ignore', out, err],
            shell: process.platform === 'win32'
        };

        const child = spawn(execCommand, execArgs, spawnOptions);
        child.unref();

        const bgData = {
            pid: child.pid,
            startTime: new Date().toISOString(),
            command: `${execCommand} ${execArgs.join(' ')}`,
            logFile: path.join(CONFIG_DIR, 'vtunnel.log'),
            errorLogFile: path.join(CONFIG_DIR, 'vtunnel-error.log')
        };

        fs.writeFileSync(bgFilePath, JSON.stringify(bgData, null, 2), 'utf8');

        logger.success(`V-Tunnel started in background with PID ${child.pid}`);
        logger.info(`Logs available at: ${path.join(CONFIG_DIR, 'vtunnel.log')}`);
        logger.info(`To stop the background process, run: vtunnel server background stop`);

        return true;
    } catch (err) {
        logger.error(`Failed to start background process: ${err}`);
        return false;
    }
}

function stopBackgroundProcess() {
    try {
        if (!fs.existsSync(bgFilePath)) {
            logger.error('No background process found. V-Tunnel might not be running in background.');
            return false;
        }

        const bgData = JSON.parse(fs.readFileSync(bgFilePath, 'utf8'));
        const pid = bgData.pid;

        try {
            // Try to terminate gracefully first (SIGTERM)
            process.kill(pid, 'SIGTERM');

            logger.success(`Sent termination signal to V-Tunnel process (PID: ${pid})`);

            // Give it some time to shut down gracefully
            setTimeout(() => {
                try {
                    // Check if process is still running
                    process.kill(pid, 0);

                    logger.warning(`Process ${pid} is still running. Sending force kill signal...`);
                    process.kill(pid, 'SIGKILL');

                    logger.success(`Forcefully terminated V-Tunnel process (PID: ${pid})`);
                } catch (e) {
                    // Process is already terminated, which is good
                    logger.success(`V-Tunnel process (PID: ${pid}) has terminated successfully`);
                }

                // Remove PID file
                fs.unlinkSync(bgFilePath);
            }, 5000); // Wait 5 seconds before checking if process is still alive

            return true;
        } catch (e) {
            if (e.code === 'ESRCH') {
                logger.warning(`Process with PID ${pid} not found. It may have been terminated already.`);
                // Remove PID file
                fs.unlinkSync(bgFilePath);
                return true;
            } else {
                logger.error(`Error terminating process: ${e.message}`);
                return false;
            }
        }
    } catch (err) {
        logger.error(`Error stopping background process: ${err}`);
        return false;
    }
}

function checkBackgroundStatus() {
    try {
        if (!fs.existsSync(bgFilePath)) {
            logger.info('V-Tunnel is not running in background.');
            return false;
        }

        const bgData = JSON.parse(fs.readFileSync(bgFilePath, 'utf8'));

        try {
            process.kill(bgData.pid, 0); // Signal 0 is used to check if process exists

            logger.info(`V-Tunnel is running in background with PID ${bgData.pid}`);
            logger.info(`Started at: ${bgData.startTime}`);
            logger.info(`Log file: ${bgData.logFile}`);

            return true;
        } catch (e) {
            logger.warning(`Found PID file but process ${bgData.pid} is not running.`);
            logger.warning('The server may have crashed or been terminated improperly.');
            logger.info('You can remove the stale PID file and start a new background process.');
            return false;
        }
    } catch (err) {
        logger.error(`Error checking background status: ${err}`);
        return false;
    }
}

// Setup the VTunnel server
async function setupVTunnel() {
    logger.info("Starting VTunnel setup...");

    try {
        console.log('\n' + colors.bold.cyan('=== VTunnel Server Setup ===') + '\n');

        // Step 1: Admin user setup
        console.log(colors.bold.yellow('--- Admin User Setup ---'));

        const adminAnswers = await inquirer.prompt([
            {
                type: 'input',
                name: 'username',
                message: 'Enter admin username:',
                default: 'admin',
                validate: input => input.trim() ? true : 'Username cannot be empty'
            },
            {
                type: 'password',
                name: 'password',
                message: 'Enter admin password:',
                default: 'admin',
                mask: '*',
                validate: input => input.trim() ? true : 'Password cannot be empty'
            }
        ]);

        const adminUsername = adminAnswers.username;
        const adminPassword = adminAnswers.password;

        // Step 2: Server configuration
        console.log('\n' + colors.bold.yellow('--- Server Configuration ---'));

        const serverAnswers = await inquirer.prompt([
            {
                type: 'number',
                name: 'port',
                message: 'Enter control server port:',
                default: PORT
            },
            {
                type: 'number',
                name: 'rangeStart',
                message: 'Enter tunnel port range start:',
                default: TUNNEL_PORT_RANGE_START
            },
            {
                type: 'number',
                name: 'rangeEnd',
                message: 'Enter tunnel port range end:',
                default: TUNNEL_PORT_RANGE_END
            }
        ]);

        PORT = serverAnswers.port;
        TUNNEL_PORT_RANGE_START = serverAnswers.rangeStart;
        TUNNEL_PORT_RANGE_END = serverAnswers.rangeEnd;

        // Confirm setup
        console.log('\n' + colors.bold.yellow('--- Configuration Summary ---'));

        const summaryTable = new Table({
            head: [colors.cyan('Setting'), colors.cyan('Value')],
            colWidths: [30, 40]
        });

        summaryTable.push(
            ['Admin Username', adminUsername],
            ['Control Server Port', PORT],
            ['Tunnel Port Range', `${TUNNEL_PORT_RANGE_START} - ${TUNNEL_PORT_RANGE_END}`],
            ['Configuration Directory', CONFIG_DIR]
        );

        console.log(summaryTable.toString());

        const { confirmation } = await inquirer.prompt([
            {
                type: 'confirm',
                name: 'confirmation',
                message: 'Confirm these settings?',
                default: true
            }
        ]);

        if (!confirmation) {
            logger.error('Setup canceled.');
            process.exit(1);
        }

        // Update config with new values
        config = {
            ...config,
            PORT,
            TUNNEL_PORT_RANGE_START,
            TUNNEL_PORT_RANGE_END,
            ADMIN_USERNAME: adminUsername,
            ADMIN_PASSWORD: adminPassword
        };

        // Write configuration to file
        fs.writeFileSync(configFilePath, JSON.stringify(config, null, 2), 'utf8');
        logger.success(`Configuration saved to ${configFilePath}`);

        // Create database
        await initializeDatabase(adminUsername, adminPassword);

        logger.success("Setup completed successfully!");

        return true;
    } catch (err) {
        logger.error(`Setup error: ${err.message}`);
        return false;
    }
}

// Initialize available ports
function initAvailablePorts() {
    availablePorts = [];
    for (let port = TUNNEL_PORT_RANGE_START; port <= TUNNEL_PORT_RANGE_END; port++) {
        availablePorts.push(port);
    }
}

// Create configuration directory and database
async function initializeDatabase(adminUsername = null, adminPassword = null) {
    try {
        // Open SQLite database connection
        db = await open({
            filename: DB_FILE,
            driver: sqlite3.Database
        });

        // Create users table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                                                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                 username TEXT UNIQUE NOT NULL,
                                                 password TEXT NOT NULL,
                                                 is_admin INTEGER DEFAULT 0,
                                                 created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create tunnels table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS tunnels (
                                                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                   name TEXT UNIQUE NOT NULL,
                                                   port INTEGER UNIQUE NOT NULL,
                                                   owner_id INTEGER NOT NULL,
                                                   description TEXT,
                                                   is_active INTEGER DEFAULT 0,
                                                   bytes_sent BIGINT DEFAULT 0,
                                                   bytes_received BIGINT DEFAULT 0,
                                                   active_connections INTEGER DEFAULT 0,
                                                   created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                                                   last_active_at TEXT,
                                                   FOREIGN KEY (owner_id) REFERENCES users (id)
                )
        `);

        // Check existing table structure and add new fields if necessary
        try {
            // Add bytes_sent column (if it doesn't exist)
            await db.exec(`ALTER TABLE tunnels ADD COLUMN bytes_sent BIGINT DEFAULT 0`);
            logger.info("bytes_sent column added");
        } catch (err) {
            // Ignore error if column already exists
            logger.debug("Error adding bytes_sent column: " + err.message);
        }

        try {
            // Add bytes_received column (if it doesn't exist)
            await db.exec(`ALTER TABLE tunnels ADD COLUMN bytes_received BIGINT DEFAULT 0`);
            logger.info("bytes_received column added");
        } catch (err) {
            // Ignore error if column already exists
            logger.debug("Error adding bytes_received column: " + err.message);
        }

        try {
            // Add active_connections column (if it doesn't exist)
            await db.exec(`ALTER TABLE tunnels ADD COLUMN active_connections INTEGER DEFAULT 0`);
            logger.info("active_connections column added");
        } catch (err) {
            // Ignore error if column already exists
            logger.debug("Error adding active_connections column: " + err.message);
        }

        // Check for an existing admin user
        const adminExists = await db.get('SELECT id FROM users WHERE is_admin = 1 LIMIT 1');

        if (!adminExists && adminUsername && adminPassword) {
            // Create admin user
            const hashedPassword = await hashPassword(adminPassword);
            await db.run(`
                INSERT INTO users (username, password, is_admin)
                VALUES (?, ?, 1)
            `, adminUsername, hashedPassword);

            logger.success(`Admin user created (username: ${adminUsername})`);
        }

        // Load registered tunnels
        await loadTunnelsFromDatabase();

        logger.success('Database initialized successfully');
        return true;
    } catch (err) {
        logger.error(`Database initialization error: ${err}`);
        throw err;
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

// Password hashing
async function hashPassword(password) {
    return new Promise((resolve, reject) => {
        // Generate 16 byte salt
        crypto.randomBytes(16, (err, salt) => {
            if (err) return reject(err);

            // Hash the password with PBKDF2 (100000 iterations, 64 byte output, sha512 algorithm)
            crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derivedKey) => {
                if (err) return reject(err);

                // Return in salt:hash format
                resolve(salt.toString('hex') + ':' + derivedKey.toString('hex'));
            });
        });
    });
}

async function verifyPassword(storedPassword, suppliedPassword) {
    return new Promise((resolve, reject) => {
        // Stored password is salt:hash
        const [salt, storedHash] = storedPassword.split(':');

        // Hash the password again with the same parameters
        crypto.pbkdf2(suppliedPassword, Buffer.from(salt, 'hex'), 100000, 64, 'sha512', (err, derivedKey) => {
            if (err) return reject(err);

            // Compare the hashes
            resolve(derivedKey.toString('hex') === storedHash);
        });
    });
}

// Generate JWT token
function generateToken(userId, username) {
    return jwt.sign(
        { id: userId, username: username },
        "vtunnel",
        { expiresIn: "365d" }
    );
}

// Verify JWT token
function verifyToken(token) {
    try {
        return jwt.verify(token, "vtunnel");
    } catch (error) {
        return null;
    }
}

// User authentication
async function authenticateUser(username, password) {
    try {
        // Find user
        const user = await db.get('SELECT id, username, password, is_admin FROM users WHERE username = ?', username);

        if (!user) {
            return { success: false, message: 'Username or password incorrect' };
        }

        // Verify password
        const isValid = await verifyPassword(user.password, password);
        if (!isValid) {
            return { success: false, message: 'Username or password incorrect' };
        }

        // Generate JWT token
        const token = generateToken(user.id, user.username);

        return {
            success: true,
            user: {
                id: user.id,
                username: user.username,
                isAdmin: user.is_admin === 1
            },
            token
        };
    } catch (err) {
        logger.error('Authentication error: ' + err);
        return { success: false, message: 'An error occurred during authentication' };
    }
}

// Authentication with token
async function authenticateWithToken(token) {
    try {
        const decoded = verifyToken(token);
        if (!decoded) return { success: false, message: 'Invalid or expired token' };

        const user = await db.get('SELECT id, username, is_admin FROM users WHERE id = ?', decoded.id);

        if (!user) {
            return { success: false, message: 'User not found' };
        }

        return {
            success: true,
            user: {
                id: user.id,
                username: user.username,
                isAdmin: user.is_admin === 1
            }
        };
    } catch (err) {
        logger.error('Token verification error: ' + err);
        return { success: false, message: 'An error occurred during token verification' };
    }
}

// Load tunnels from database
async function loadTunnelsFromDatabase() {
    try {
        const dbTunnels = await db.all(`
            SELECT id, name, port, owner_id, description, created_at,
                   bytes_sent, bytes_received, active_connections
            FROM tunnels
        `);

        for (const tunnel of dbTunnels) {
            // Remove this port from available ports
            const portIndex = availablePorts.indexOf(tunnel.port);
            if (portIndex !== -1) {
                availablePorts.splice(portIndex, 1);
            }

            // Store tunnel temporarily (will be active when connected)
            tunnels[tunnel.name] = {
                port: tunnel.port,
                ownerId: tunnel.owner_id,
                description: tunnel.description,
                createdAt: tunnel.created_at,
                socket: null,
                server: null,
                clients: {},
                waitingClients: [],
                isActive: false,
                trafficStats: {
                    bytesSent: tunnel.bytes_sent || 0,
                    bytesReceived: tunnel.bytes_received || 0,
                    activeConnections: tunnel.active_connections || 0
                }
            };
        }

        logger.info(`Loaded ${dbTunnels.length} tunnels from database`);
    } catch (err) {
        logger.error('Failed to load tunnels: ' + err);
    }
}

// Update traffic statistics
async function updateTrafficStats(tunnelName, bytesSent = 0, bytesReceived = 0, connectionDelta = 0) {
    if (!tunnelName) return;

    try {
        // Only update database if there are changes
        if (bytesSent || bytesReceived || connectionDelta) {
            // Update traffic statistics in database
            let query = `
                UPDATE tunnels
                SET
            `;

            const params = [];
            let updateParts = [];

            if (bytesSent) {
                updateParts.push('bytes_sent = bytes_sent + ?');
                params.push(bytesSent);
            }

            if (bytesReceived) {
                updateParts.push('bytes_received = bytes_received + ?');
                params.push(bytesReceived);
            }

            if (connectionDelta) {
                updateParts.push('active_connections = active_connections + ?');
                params.push(connectionDelta);
            }

            query += updateParts.join(', ');
            query += ` WHERE name = ?`;
            params.push(tunnelName);

            await db.run(query, params);
        }

        // Update in-memory tunnel object as well
        if (tunnels[tunnelName]) {
            if (!tunnels[tunnelName].trafficStats) {
                tunnels[tunnelName].trafficStats = {
                    bytesSent: 0,
                    bytesReceived: 0,
                    activeConnections: 0
                };
            }

            if (bytesSent) {
                tunnels[tunnelName].trafficStats.bytesSent += bytesSent;
            }

            if (bytesReceived) {
                tunnels[tunnelName].trafficStats.bytesReceived += bytesReceived;
            }

            if (connectionDelta) {
                tunnels[tunnelName].trafficStats.activeConnections += connectionDelta;
                // Ensure we don't go below zero
                if (tunnels[tunnelName].trafficStats.activeConnections < 0) {
                    tunnels[tunnelName].trafficStats.activeConnections = 0;
                }
            }
        }

        if (process.env.DEBUG) {
            logger.debug(`Traffic statistics updated: ${tunnelName}, +${bytesSent} sent, +${bytesReceived} received, connection delta: ${connectionDelta}`);
        }
    } catch (err) {
        logger.error(`Error updating traffic statistics: ${err.message}`);
    }
}

// Update tunnel status
async function updateTunnelStatus(tunnelName, isActive) {
    try {
        await db.run(`
            UPDATE tunnels
            SET is_active = ?, last_active_at = CURRENT_TIMESTAMP
            WHERE name = ?
        `, isActive ? 1 : 0, tunnelName);
    } catch (err) {
        logger.error(`Error updating tunnel status: ${err}`);
    }
}

// Create control server
let controlServer;
function createControlServer() {
    controlServer = net.createServer(socket => {
        const clientId = crypto.randomBytes(8).toString('hex');
        socket.clientId = clientId;
        socket.authenticated = false;
        socket.userId = null;
        socket.username = null;
        socket.lastHeartbeat = Date.now();

        logger.info(`New control connection: ${clientId} - ${socket.remoteAddress}:${socket.remotePort}`);

        // Process incoming data
        let buffer = '';

        socket.on('data', data => {
            try {
                buffer += data.toString();

                let newlineIndex;
                while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
                    const messageStr = buffer.substring(0, newlineIndex);
                    buffer = buffer.substring(newlineIndex + 1);

                    const message = decrypt(messageStr);
                    if (!message) continue;

                    processMessage(socket, message);
                }
            } catch (err) {
                logger.error(`Data processing error ${clientId}: ${err}`);
            }
        });

        socket.on('error', err => {
            logger.error(`Socket error ${clientId}: ${err.message}`);
        });

        socket.on('close', () => {
            logger.info(`Control connection closed: ${clientId}`);
            cleanupClient(socket);

            // Clean up session
            if (socket.sessionId && sessions[socket.sessionId]) {
                delete sessions[socket.sessionId];
            }
        });

        // Set socket timeout
        socket.setTimeout(CONNECTION_TIMEOUT);
        socket.on('timeout', () => {
            // Check last heartbeat time
            const currentTime = Date.now();
            const timeSinceLastHeartbeat = currentTime - socket.lastHeartbeat;

            if (timeSinceLastHeartbeat > HEARTBEAT_INTERVAL * 2) {
                logger.warning(`Connection timeout for client ${clientId}. No heartbeat received for ${timeSinceLastHeartbeat}ms`);
                socket.destroy();
            }
        });

        // Send welcome message
        sendMessage(socket, {
            type: 'welcome',
            server_version: '1.2.0',
            client_id: clientId,
            timestamp: Date.now()
        });
    });

    return controlServer;
}

// Process control messages
async function processMessage(socket, message) {
    // Update last heartbeat time
    socket.lastHeartbeat = Date.now();

    // Operations requiring authentication
    if (!socket.authenticated && message.type !== 'login' && message.type !== 'ping') {
        // Authentication with token
        if (message.token) {
            const authResult = await authenticateWithToken(message.token);
            if (authResult.success) {
                socket.authenticated = true;
                socket.userId = authResult.user.id;
                socket.username = authResult.user.username;
                socket.isAdmin = authResult.user.isAdmin;

                // Create session ID
                const sessionId = crypto.randomBytes(16).toString('hex');
                socket.sessionId = sessionId;
                sessions[sessionId] = {
                    userId: authResult.user.id,
                    username: authResult.user.username,
                    isAdmin: authResult.user.isAdmin,
                    createdAt: new Date().toISOString()
                };

                logger.debug(`Authentication with token successful: ${authResult.user.username} (${authResult.user.id})`);
            } else {
                sendMessage(socket, {
                    type: 'error',
                    message: 'Authentication failed: ' + authResult.message
                });
                return;
            }
        } else {
            sendMessage(socket, {
                type: 'error',
                message: 'Authentication required'
            });
            return;
        }
    }

    switch(message.type) {
        case 'login':
            await handleLogin(socket, message);
            break;
        case 'register_tunnel':
            await registerTunnel(socket, message);
            break;
        case 'list_tunnels':
            await listTunnels(socket, message);
            break;
        case 'delete_tunnel':
            await deleteTunnel(socket, message);
            break;
        case 'register_client':
            registerClient(socket, message);
            break;
        case 'data':
            handleData(socket, message);
            break;
        case 'ping':
            sendMessage(socket, {
                type: 'pong',
                time: Date.now(),
                server_time: Date.now(),
                client_time: message.time || null
            });
            break;
        case 'change_password':
            await changePassword(socket, message);
            break;
        case 'client_ready':
            handleClientReady(socket, message);
            break;
        case 'heartbeat':
            // Just update the lastHeartbeat timestamp (already done at the top of this function)
            sendMessage(socket, {
                type: 'heartbeat_ack',
                time: Date.now()
            });
            break;
        default:
            logger.debug(`Unknown message type: ${message.type}`);
    }
}

// Handle client ready message (when client is ready to receive data)
function handleClientReady(socket, message) {
    if (!message.client_id || !socket.tunnelName) {
        return;
    }

    const tunnelName = socket.tunnelName;
    const clientId = message.client_id;

    if (!tunnels[tunnelName]) {
        logger.warning(`Tunnel not found: ${tunnelName}`);
        return;
    }

    if (!tunnels[tunnelName].clients[clientId]) {
        logger.warning(`Client not found in tunnel: ${clientId}`);
        return;
    }

    logger.debug(`Client ${clientId} is ready to receive data for tunnel ${tunnelName}`);

    // Mark client as ready
    tunnels[tunnelName].clients[clientId].ready = true;

    // Resume the socket if it was paused
    const clientSocket = tunnels[tunnelName].clients[clientId].socket;
    if (clientSocket && !clientSocket.destroyed) {
        clientSocket.resume();
    }
}

// Handle user login
async function handleLogin(socket, message) {
    if (message.token) {
        // Login with token
        const authResult = await authenticateWithToken(message.token);
        if (authResult.success) {
            socket.authenticated = true;
            socket.userId = authResult.user.id;
            socket.username = authResult.user.username;
            socket.isAdmin = authResult.user.isAdmin;

            // Create session ID
            const sessionId = crypto.randomBytes(16).toString('hex');
            socket.sessionId = sessionId;
            sessions[sessionId] = {
                userId: authResult.user.id,
                username: authResult.user.username,
                isAdmin: authResult.user.isAdmin,
                createdAt: new Date().toISOString()
            };

            logger.info(`Logged in with token: ${authResult.user.username} (${authResult.user.id})`);

            sendMessage(socket, {
                type: 'login_response',
                success: true,
                user: authResult.user
            });
        } else {
            sendMessage(socket, {
                type: 'login_response',
                success: false,
                message: authResult.message
            });
        }
        return;
    }

    if (!message.username || !message.password) {
        sendMessage(socket, {
            type: 'login_response',
            success: false,
            message: 'Username and password required'
        });
        return;
    }

    const result = await authenticateUser(message.username, message.password);

    if (result.success) {
        socket.authenticated = true;
        socket.userId = result.user.id;
        socket.username = result.user.username;
        socket.isAdmin = result.user.isAdmin;

        // Create session ID
        const sessionId = crypto.randomBytes(16).toString('hex');
        socket.sessionId = sessionId;
        sessions[sessionId] = {
            userId: result.user.id,
            username: result.user.username,
            isAdmin: result.user.isAdmin,
            createdAt: new Date().toISOString()
        };

        logger.info(`User logged in: ${result.user.username} (${result.user.id})`);
    }

    sendMessage(socket, {
        type: 'login_response',
        success: result.success,
        message: result.message,
        user: result.success ? result.user : null,
        token: result.success ? result.token : null
    });
}

// Register tunnel server (service providing machine)
async function registerTunnel(socket, message) {
    const tunnelName = message.tunnel_name;
    const requestedPort = message.preferred_port;
    const description = message.description || '';

    if (!tunnelName || tunnelName.length > 64) {
        sendMessage(socket, {
            type: 'error',
            message: 'Invalid tunnel name (must be 1-64 characters)'
        });
        return;
    }

    // Check if tunnel already exists
    const existingTunnel = await db.get('SELECT id, owner_id, port FROM tunnels WHERE name = ?', tunnelName);

    let tunnelPort;

    if (existingTunnel) {
        // If not this user's tunnel or tunnel is active, reject
        if (existingTunnel.owner_id !== socket.userId && !socket.isAdmin) {
            sendMessage(socket, {
                type: 'error',
                message: 'This tunnel name is being used by another user'
            });
            return;
        }

        // Use previously registered port
        tunnelPort = existingTunnel.port;

        // If this port appears in available ports, remove it
        const portIndex = availablePorts.indexOf(tunnelPort);
        if (portIndex !== -1) {
            availablePorts.splice(portIndex, 1);
        }

        // Clean up active tunnel
        if (tunnels[tunnelName] && tunnels[tunnelName].isActive) {
            cleanupTunnel(tunnelName);
        }
    } else {
        // Port selection for new tunnel
        if (requestedPort && availablePorts.includes(requestedPort)) {
            tunnelPort = requestedPort;
            availablePorts = availablePorts.filter(p => p !== requestedPort);
        } else {
            if (availablePorts.length === 0) {
                sendMessage(socket, {
                    type: 'error',
                    message: 'No ports available'
                });
                return;
            }
            tunnelPort = availablePorts.shift();
        }
    }

    // Create a new server for this tunnel
    const server = createTunnelServer(tunnelName, tunnelPort);

    // Register this tunnel
    tunnels[tunnelName] = {
        port: tunnelPort,
        socket: socket,
        server: server,
        clients: {},
        waitingClients: [],
        ownerId: socket.userId,
        description: description,
        createdAt: new Date().toISOString(),
        isActive: true,
        trafficStats: {
            bytesSent: 0,
            bytesReceived: 0,
            activeConnections: 0
        }
    };

    // Store socket -> tunnel mapping
    socket.tunnelName = tunnelName;

    try {
        if (existingTunnel) {
            // Update tunnel
            await db.run(`
                UPDATE tunnels
                SET port = ?, description = ?, is_active = 1, last_active_at = CURRENT_TIMESTAMP, active_connections = 0
                WHERE name = ?
            `, tunnelPort, description, tunnelName);
        } else {
            // Create new tunnel
            await db.run(`
                INSERT INTO tunnels (name, port, owner_id, description, is_active, bytes_sent, bytes_received, active_connections)
                VALUES (?, ?, ?, ?, 1, 0, 0, 0)
            `, tunnelName, tunnelPort, socket.userId, description);
        }

        logger.success(`Tunnel registered: ${tunnelName} - port ${tunnelPort} (Owner: ${socket.username})`);

        // Notify tunnel owner
        sendMessage(socket, {
            type: 'tunnel_registered',
            port: tunnelPort,
            tunnel_name: tunnelName,
            description: description,
            message: `Tunnel "${tunnelName}" registered on port ${tunnelPort}`
        });
    } catch (err) {
        logger.error(`Database error when registering tunnel: ${err}`);

        sendMessage(socket, {
            type: 'error',
            message: 'An error occurred while registering the tunnel'
        });

        // Clean up resources
        if (server) {
            server.close();
        }

        if (tunnels[tunnelName]) {
            delete tunnels[tunnelName];
        }

        // Put port back if creating new tunnel
        if (!existingTunnel && !availablePorts.includes(tunnelPort)) {
            availablePorts.push(tunnelPort);
        }
    }
}

// List user's tunnels
async function listTunnels(socket, message) {
    try {
        let query = `
            SELECT t.id, t.name, t.port, t.description, t.is_active, t.created_at, t.last_active_at,
                   t.bytes_sent, t.bytes_received, t.active_connections, u.username as owner_username
            FROM tunnels t
                     JOIN users u ON t.owner_id = u.id
        `;

        const params = [];

        // Admin can see all tunnels, normal users only see their own
        if (!socket.isAdmin) {
            query += ` WHERE t.owner_id = ?`;
            params.push(socket.userId);
        }

        query += ` ORDER BY t.created_at DESC`;

        const dbTunnels = await db.all(query, params);

        const tunnelsList = dbTunnels.map(t => ({
            id: t.id,
            name: t.name,
            port: t.port,
            description: t.description || '',
            isActive: t.is_active === 1,
            owner: t.owner_username,
            createdAt: t.created_at,
            lastActiveAt: t.last_active_at,
            bytes_sent: t.bytes_sent || 0,
            bytes_received: t.bytes_received || 0,
            active_connections: t.active_connections || 0,
            clientCount: tunnels[t.name] && tunnels[t.name].clients ? Object.keys(tunnels[t.name].clients).length : 0
        }));

        sendMessage(socket, {
            type: 'tunnels_list',
            tunnels: tunnelsList
        });
    } catch (err) {
        logger.error(`Error listing tunnels: ${err}`);
        sendMessage(socket, {
            type: 'error',
            message: 'An error occurred while listing tunnels'
        });
    }
}

// Delete tunnel
async function deleteTunnel(socket, message) {
    const tunnelName = message.tunnel_name;

    try {
        // Check tunnel in database
        const tunnel = await db.get('SELECT id, owner_id FROM tunnels WHERE name = ?', tunnelName);

        if (!tunnel) {
            sendMessage(socket, {
                type: 'error',
                message: 'Tunnel not found'
            });
            return;
        }

        // Permission check
        if (!socket.isAdmin && tunnel.owner_id !== socket.userId) {
            sendMessage(socket, {
                type: 'error',
                message: 'You do not have permission to delete this tunnel'
            });
            return;
        }

        // Delete tunnel from database
        await db.run('DELETE FROM tunnels WHERE id = ?', tunnel.id);

        // Clean up active tunnel
        if (tunnels[tunnelName]) {
            cleanupTunnel(tunnelName);
        }

        sendMessage(socket, {
            type: 'tunnel_deleted',
            tunnel_name: tunnelName,
            message: `Tunnel "${tunnelName}" deleted`
        });
    } catch (err) {
        logger.error(`Error deleting tunnel: ${err}`);
        sendMessage(socket, {
            type: 'error',
            message: 'An error occurred while deleting the tunnel'
        });
    }
}

// Create server for a specific tunnel with enhanced flow control
function createTunnelServer(tunnelName, port) {
    const server = net.createServer(socket => {
        const clientId = crypto.randomBytes(8).toString('hex');
        socket.clientId = clientId;

        logger.info(`New connection to tunnel ${tunnelName} on port ${port}: ${clientId} - ${socket.remoteAddress}:${socket.remotePort}`);

        // Check if tunnel exists and is connected
        if (!tunnels[tunnelName] || !tunnels[tunnelName].socket || tunnels[tunnelName].socket.destroyed) {
            logger.error(`Tunnel ${tunnelName} does not exist or is not active`);
            socket.destroy();
            return;
        }

        // Pause socket until client is ready to handle it
        socket.pause();

        // Create client metadata
        const clientMetadata = {
            socket: socket,
            connectedAt: new Date().toISOString(),
            bytesReceived: 0,
            bytesSent: 0,
            ready: false,
            queue: [],
            ip: socket.remoteAddress,
            port: socket.remotePort
        };

        // Store this client connection
        tunnels[tunnelName].clients[clientId] = clientMetadata;

        // Update active connections count
        updateTrafficStats(tunnelName, 0, 0, 1);

        // Inform tunnel owner about new connection
        sendMessage(tunnels[tunnelName].socket, {
            type: 'connection',
            client_id: clientId,
            tunnel_name: tunnelName,
            remote_address: socket.remoteAddress,
            remote_port: socket.remotePort,
            timestamp: Date.now()
        });

        // Process data from client to tunnel
        socket.on('data', data => {
            if (tunnels[tunnelName] && tunnels[tunnelName].socket && !tunnels[tunnelName].socket.destroyed) {
                sendMessage(tunnels[tunnelName].socket, {
                    type: 'data',
                    client_id: clientId,
                    data: data.toString('base64') // Use base64 to handle binary data properly
                });

                // Update traffic statistics - data flow from outside world to tunnel
                tunnels[tunnelName].clients[clientId].bytesReceived += data.length;
                updateTrafficStats(tunnelName, data.length, 0, 0);
            } else {
                // Tunnel is gone, close this connection
                socket.destroy();
            }
        });

        socket.on('error', err => {
            logger.error(`Client socket error ${clientId} tunnel ${tunnelName}: ${err.message}`);
        });

        socket.on('close', () => {
            logger.info(`Client closed connection to tunnel ${tunnelName}: ${clientId}`);

            const client = tunnels[tunnelName]?.clients[clientId];
            if (client) {
                // Log traffic stats before removing
                const bytesSent = client.bytesSent || 0;
                const bytesReceived = client.bytesReceived || 0;
                logger.debug(`Connection closed - Traffic stats: sent ${bytesSent} bytes, received ${bytesReceived} bytes`);
            }

            // Remove client from tunnel
            if (tunnels[tunnelName] && tunnels[tunnelName].clients[clientId]) {
                delete tunnels[tunnelName].clients[clientId];

                // Update active connections count
                updateTrafficStats(tunnelName, 0, 0, -1);
            }

            // Notify tunnel owner
            if (tunnels[tunnelName] && tunnels[tunnelName].socket && !tunnels[tunnelName].socket.destroyed) {
                sendMessage(tunnels[tunnelName].socket, {
                    type: 'client_disconnected',
                    client_id: clientId,
                    tunnel_name: tunnelName,
                    timestamp: Date.now()
                });
            }
        });
    });

    server.on('error', err => {
        logger.error(`Tunnel server error ${tunnelName} port ${port}: ${err}`);

        // Clean up tunnel in critical error
        if (err.code === 'EADDRINUSE') {
            logger.error(`Port ${port} already in use, cleaning up tunnel ${tunnelName}`);
            cleanupTunnel(tunnelName);
        }
    });

    server.listen(port, () => {
        logger.success(`Tunnel server for ${tunnelName} listening on port ${port}`);
    });

    return server;
}

// Register client wanting to connect to tunnel service (optional)
function registerClient(socket, message) {
    const tunnelName = message.tunnel_name;

    if (!tunnelName) {
        sendMessage(socket, {
            type: 'error',
            message: 'Tunnel name is required'
        });
        return;
    }

    if (!tunnels[tunnelName]) {
        sendMessage(socket, {
            type: 'error',
            message: `Tunnel "${tunnelName}" not found`
        });
        return;
    }

    // Store client information
    clients[socket.clientId] = {
        socket: socket,
        tunnelName: tunnelName,
        connectedAt: new Date().toISOString()
    };

    socket.tunnelName = tunnelName;

    // Send tunnel information
    sendMessage(socket, {
        type: 'tunnel_info',
        tunnel_name: tunnelName,
        port: tunnels[tunnelName].port,
        description: tunnels[tunnelName].description || '',
        timestamp: Date.now()
    });
}

// Data transmission between tunnel owner and client connections
function handleData(socket, message) {
    if (!message.client_id || !message.data) {
        return;
    }

    const tunnelName = socket.tunnelName;
    if (!tunnelName || !tunnels[tunnelName]) {
        return;
    }

    // Decode base64 data
    try {
        const data = Buffer.from(message.data, 'base64');

        // Update traffic statistics - client -> server data flow
        if (tunnels[tunnelName].clients[message.client_id]) {
            tunnels[tunnelName].clients[message.client_id].bytesSent += data.length;
        }

        updateTrafficStats(tunnelName, 0, data.length, 0);

        // Forward data from tunnel owner to client
        if (tunnels[tunnelName].clients[message.client_id]) {
            const clientSocket = tunnels[tunnelName].clients[message.client_id].socket;
            const clientReady = tunnels[tunnelName].clients[message.client_id].ready;

            if (clientSocket && !clientSocket.destroyed) {
                if (clientReady) {
                    // Send data directly if client is ready
                    clientSocket.write(data);
                } else {
                    // Queue data if client is not ready yet
                    tunnels[tunnelName].clients[message.client_id].queue.push(data);
                    logger.debug(`Queued ${data.length} bytes for client ${message.client_id} (not ready yet)`);
                }
            }
        }
    } catch (err) {
        logger.error(`Data transmission error for client ${message.client_id}: ${err.message}`);
    }
}

// Password change operation
async function changePassword(socket, message) {
    try {
        if (!socket.authenticated) {
            sendMessage(socket, {
                type: 'error',
                message: 'Authentication required for this operation'
            });
            return;
        }

        const { current_password, new_password } = message;

        if (!current_password || !new_password) {
            sendMessage(socket, {
                type: 'password_change_response',
                success: false,
                message: 'Current password and new password are required'
            });
            return;
        }

        // Minimum 6 character check
        if (new_password.length < 6) {
            sendMessage(socket, {
                type: 'password_change_response',
                success: false,
                message: 'New password must be at least 6 characters'
            });
            return;
        }

        // Get user information
        const user = await db.get('SELECT id, username, password FROM users WHERE id = ?', socket.userId);

        if (!user) {
            sendMessage(socket, {
                type: 'password_change_response',
                success: false,
                message: 'User not found'
            });
            return;
        }

        // Check current password
        const isValidPassword = await verifyPassword(user.password, current_password);
        if (!isValidPassword) {
            sendMessage(socket, {
                type: 'password_change_response',
                success: false,
                message: 'Current password is incorrect'
            });
            return;
        }

        // Hash new password
        const hashedPassword = await hashPassword(new_password);

        // Update password
        await db.run('UPDATE users SET password = ? WHERE id = ?', hashedPassword, user.id);

        logger.success(`User ${user.username} updated their password`);

        // Return successful response
        sendMessage(socket, {
            type: 'password_change_response',
            success: true,
            message: 'Your password has been successfully updated'
        });
    } catch (err) {
        logger.error(`Password change error: ${err}`);
        sendMessage(socket, {
            type: 'password_change_response',
            success: false,
            message: 'An error occurred while changing password'
        });
    }
}

// Clean up resources when a client connection is closed
async function cleanupClient(socket) {
    const clientId = socket.clientId;
    const tunnelName = socket.tunnelName;

    if (tunnelName && tunnels[tunnelName] && tunnels[tunnelName].socket === socket) {
        // Connection closed but keep tunnel record
        tunnels[tunnelName].socket = null;
        tunnels[tunnelName].isActive = false;

        // Update tunnel status
        await updateTunnelStatus(tunnelName, false);

        // Get the count of active clients for statistics update
        const activeClientsCount = Object.keys(tunnels[tunnelName].clients).length;
        if (activeClientsCount > 0) {
            // Update connection count to zero
            await db.run(`UPDATE tunnels SET active_connections = 0 WHERE name = ?`, tunnelName);
        }

        // Close all client connections
        Object.keys(tunnels[tunnelName].clients).forEach(cId => {
            const client = tunnels[tunnelName].clients[cId];
            if (client.socket && !client.socket.destroyed) {
                client.socket.destroy();
            }
        });

        // Clear clients
        tunnels[tunnelName].clients = {};

        // Close tunnel server
        if (tunnels[tunnelName].server) {
            tunnels[tunnelName].server.close(() => {
                logger.info(`Tunnel server for ${tunnelName} closed`);
            });
            tunnels[tunnelName].server = null;
        }

        logger.warning(`Tunnel ${tunnelName} deactivated (administrator connection closed)`);
    }

    if (clients[clientId]) {
        delete clients[clientId];
    }
}

// Clean up a tunnel and all its connections
function cleanupTunnel(tunnelName) {
    const tunnel = tunnels[tunnelName];
    if (!tunnel) return;

    logger.info(`Cleaning up tunnel: ${tunnelName}`);

    // Close all client connections
    Object.keys(tunnel.clients).forEach(clientId => {
        const client = tunnel.clients[clientId];
        if (client.socket && !client.socket.destroyed) {
            client.socket.destroy();
        }
    });

    // Close tunnel server
    if (tunnel.server) {
        tunnel.server.close(() => {
            logger.info(`Tunnel server for ${tunnelName} closed`);
        });
    }

    // Update database to show zero active connections
    db.run(`UPDATE tunnels SET active_connections = 0 WHERE name = ?`, tunnelName)
        .catch(err => logger.error(`Error resetting connection count: ${err.message}`));

    // Remove tunnel but don't add port back to availablePorts
    // The tunnel will stay in DB and use the same port unless deleted
    delete tunnels[tunnelName];
}

// Display server stats
function displayServerStats() {
    const statsTable = new Table({
        head: [colors.cyan('Metric'), colors.cyan('Value')],
        colWidths: [30, 40]
    });

    const totalTunnels = Object.keys(tunnels).length;
    const activeTunnels = Object.values(tunnels).filter(t => t.isActive).length;

    let totalClients = 0;
    let totalDataSent = 0;
    let totalDataReceived = 0;

    Object.values(tunnels).forEach(tunnel => {
        const clientCount = Object.keys(tunnel.clients).length;
        totalClients += clientCount;

        if (tunnel.trafficStats) {
            totalDataSent += tunnel.trafficStats.bytesSent || 0;
            totalDataReceived += tunnel.trafficStats.bytesReceived || 0;
        }
    });

    statsTable.push(
        ['Server Port', PORT],
        ['Available Ports', availablePorts.length],
        ['Total Tunnels', totalTunnels],
        ['Active Tunnels', activeTunnels],
        ['Connected Clients', totalClients],
        ['Total Data Sent', formatBytes(totalDataSent)],
        ['Total Data Received', formatBytes(totalDataReceived)],
        ['Uptime', formatUptime(process.uptime())]
    );

    console.log('\n' + colors.bold.green('VTunnel Server Stats:'));
    console.log(statsTable.toString());

    // Show active tunnels if any
    if (activeTunnels > 0) {
        const tunnelsTable = new Table({
            head: [colors.cyan('Tunnel Name'), colors.cyan('Port'), colors.cyan('Clients'), colors.cyan('Data Sent'), colors.cyan('Data Received')],
            colWidths: [25, 10, 10, 15, 15]
        });

        Object.entries(tunnels)
            .filter(([_, tunnel]) => tunnel.isActive)
            .forEach(([name, tunnel]) => {
                tunnelsTable.push([
                    name,
                    tunnel.port,
                    Object.keys(tunnel.clients).length,
                    formatBytes(tunnel.trafficStats?.bytesSent || 0),
                    formatBytes(tunnel.trafficStats?.bytesReceived || 0)
                ]);
            });

        console.log('\n' + colors.bold.green('Active Tunnels:'));
        console.log(tunnelsTable.toString());
    }
}

// Helper function to format bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Format uptime in a readable way
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    parts.push(`${secs}s`);

    return parts.join(' ');
}

// Handle command-line arguments
async function parseCliArguments() {
    const argv = yargs(hideBin(process.argv))
        .usage('Usage: $0 [options]')
        .command('background', 'Manage background process', (yargs) => {
            return yargs
                .command('start', 'Start the server in background mode', () => {}, () => {
                    startBackgroundProcess();
                    process.exit(0);
                })
                .command('stop', 'Stop the background server process', () => {}, () => {
                    stopBackgroundProcess();
                    process.exit(0);
                })
                .command('status', 'Check background server status', () => {}, () => {
                    checkBackgroundStatus();
                    process.exit(0);
                })
                .demandCommand(1, 'You need to specify a background command: start, stop, or status')
                .help();
        })
        .option('port', {
            alias: 'p',
            description: 'Control server port',
            type: 'number'
        })
        .option('range-start', {
            alias: 's',
            description: 'Tunnel port range start',
            type: 'number'
        })
        .option('range-end', {
            alias: 'e',
            description: 'Tunnel port range end',
            type: 'number'
        })
        .option('config-dir', {
            alias: 'c',
            description: 'Configuration directory',
            type: 'string'
        })
        .option('stats', {
            description: 'Display server stats periodically',
            type: 'boolean',
            default: false
        })
        .option('debug', {
            description: 'Enable debug logging',
            type: 'boolean',
            default: false
        })
        .help()
        .alias('help', 'h')
        .version(false)
        .argv;

    // Override configuration with command-line arguments if provided
    if (argv.port) PORT = argv.port;
    if (argv.rangeStart) TUNNEL_PORT_RANGE_START = argv.rangeStart;
    if (argv.rangeEnd) TUNNEL_PORT_RANGE_END = argv.rangeEnd;
    if (argv.configDir) config.CONFIG_DIR = argv.configDir;
    if (argv.debug) process.env.DEBUG = true;

    // Enable periodic stats display if requested
    if (argv.stats) {
        // Display stats initially and then every 30 seconds
        displayServerStats();
        setInterval(displayServerStats, 30000);
    }
}

// Main function
async function main() {
    try {
        // Parse command-line arguments
        await parseCliArguments();

        // Display welcome message
        console.log('\n' + colors.bold.cyan(
            '   __     __  ___                       _   \n' +
            '   \\ \\   / / |_ _|   _ _ __  _ __   ___| |  \n' +
            '    \\ \\ / /   | || | | | \'_ \\| \'_ \\ / _ \\ |  \n' +
            '     \\ V /    | || |_| | | | | | | |  __/ |  \n' +
            '      \\_/    |___\\__,_|_| |_|_| |_|\\___|_|  \n' +
            '                                             '
        ));
        console.log(colors.yellow('   Secure Tunnel Routing Server - v1.2.0') + '\n');

        // Initialize available ports
        initAvailablePorts();

        // Check if database exists
        const needsSetup = !fs.existsSync(DB_FILE);

        if (needsSetup) {
            logger.info("Database not found. Starting setup...");
            await setupVTunnel();
        }

        // Initialize the database
        await initializeDatabase();

        // Create and start the control server
        const server = createControlServer();
        server.listen(PORT, () => {
            logger.success(`Control server listening on port ${PORT}`);
            logger.info(`Available ports: ${availablePorts.length} (${TUNNEL_PORT_RANGE_START} - ${TUNNEL_PORT_RANGE_END})`);

            // Print usage information
            console.log('\n' + colors.cyan('Server is ready. Connect with a client to create and manage tunnels.'));
            console.log(colors.cyan('Press Ctrl+C to stop the server') + '\n');
        });
    } catch (err) {
        logger.error(`Application startup error: ${err}`);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n'); // For cleaner output after Ctrl+C
    logger.info('Shutting down server...');

    // Close all tunnels
    Object.keys(tunnels).forEach(tunnelName => {
        cleanupTunnel(tunnelName);
    });

    // Close database connection
    if (db) {
        await db.close();
    }

    // Close control server
    if (controlServer) {
        controlServer.close(() => {
            logger.success('Server shutdown complete');
            process.exit(0);
        });
    } else {
        logger.success('Server shutdown complete');
        process.exit(0);
    }
});

// Periodically check tunnel health
setInterval(async () => {
    for (const tunnelName in tunnels) {
        const tunnel = tunnels[tunnelName];

        // Check if tunnel socket is still connected
        if (tunnel.isActive && (!tunnel.socket || tunnel.socket.destroyed)) {
            logger.warning(`Tunnel ${tunnelName} control connection lost, deactivating`);
            tunnel.isActive = false;
            tunnel.socket = null;

            // Update tunnel status in database
            await updateTunnelStatus(tunnelName, false);

            // Update connection count to zero
            await db.run(`UPDATE tunnels SET active_connections = 0 WHERE name = ?`, tunnelName);

            // Close tunnel server
            if (tunnel.server) {
                tunnel.server.close(() => {
                    logger.info(`Tunnel server for ${tunnelName} closed`);
                });
                tunnel.server = null;
            }

            // Close all client connections
            Object.keys(tunnel.clients).forEach(clientId => {
                const client = tunnel.clients[clientId];
                if (client.socket && !client.socket.destroyed) {
                    client.socket.destroy();
                }
            });

            // Clear clients
            tunnel.clients = {};
        }
    }
}, 60000); // Check every minute

// Start the application
main().catch(err => {
    logger.error(`Application startup error: ${err}`);
    process.exit(1);
});
