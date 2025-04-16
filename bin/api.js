#!/usr/bin/env node

/**
 * V-Tunnel - Lightweight Tunnel Routing Solution
 *
 * A 100% free and open-source alternative to commercial tunneling solutions
 * like Ngrok, Cloudflare Tunnel, and others.
 *
 * @file        api.js
 * @description Enhanced Tunnel Routing api
 * @author      Cengiz AKCAN <me@cengizakcan.com>
 * @copyright   Copyright (c) 2025, Cengiz AKCAN
 * @license     MIT
 * @version     1.1.4
 * @link        https://github.com/wwwakcan/V-Tunnel
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);
const mkdirAsync = promisify(fs.mkdir);
const net = require('net');
const crypto = require('crypto');

// Configuration paths
const CONFIG_DIR = path.join(__dirname, '.vtunnel-client');
const AUTH_FILE = path.join(CONFIG_DIR, 'auth.json');
const TUNNELS_FILE = path.join(CONFIG_DIR, 'tunnels.json');
const STATS_FILE = path.join(CONFIG_DIR, 'stats.json');
const API_PID_FILE = path.join(CONFIG_DIR, 'api.pid');

// Web UI dizini
const WEB_UI_DIR = path.join(__dirname, 'web-ui');

// API Configuration
const API_PORT = 9011;
const API_SECRET = process.env.VTUNNEL_API_SECRET || 'vtunnel-api-secret-key';
const API_TOKEN_EXPIRY = '24h';

// Package.json'dan versiyon bilgisini al
let packageVersion = '1.0.0';
try {
    const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
    packageVersion = packageJson.version || '1.0.0';
} catch (error) {
    console.error('package.json okunamadı, varsayılan versiyon kullanılıyor:', error.message);
}

// Web-UI dizinini oluştur (eğer yoksa)
if (!fs.existsSync(WEB_UI_DIR)) {
    try {
        fs.mkdirSync(WEB_UI_DIR, { recursive: true });
        console.log(`Web-UI dizini oluşturuldu: ${WEB_UI_DIR}`);
    } catch (error) {
        console.error('Web-UI dizini oluşturulamadı:', error.message);
    }
}

// Initialize express app
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Web UI için statik dosya servis etme
if (fs.existsSync(WEB_UI_DIR)) {
    app.use(express.static(WEB_UI_DIR));
} else {
    console.log(`Web UI dizini bulunamadı: ${WEB_UI_DIR}`);
}

// Temel index.html oluştur (eğer yoksa)
const indexPath = path.join(WEB_UI_DIR, 'index.html');
if (!fs.existsSync(indexPath)) {
    try {
        fs.writeFileSync(indexPath, `V-Tunnel Version ${packageVersion}`);
        console.log(`Temel index.html oluşturuldu: ${indexPath}`);
    } catch (error) {
        console.error('index.html oluşturulurken hata:', error.message);
    }
}

// Logger setup
const colors = require('colors/safe');
colors.setTheme({
    info: 'blue',
    success: 'green',
    warning: 'yellow',
    error: 'red',
    title: ['cyan', 'bold'],
    highlight: ['yellow', 'bold'],
    muted: 'grey'
});

const logger = {
    info: (message) => console.log(colors.info(`[API INFO] ${new Date().toISOString()} - ${message}`)),
    success: (message) => console.log(colors.success(`[API SUCCESS] ${new Date().toISOString()} - ${message}`)),
    warning: (message) => console.log(colors.warning(`[API WARNING] ${new Date().toISOString()} - ${message}`)),
    error: (message) => console.error(colors.error(`[API ERROR] ${new Date().toISOString()} - ${message}`)),
    debug: (message) => process.env.DEBUG && console.log(colors.muted(`[API DEBUG] ${new Date().toISOString()} - ${message}`))
};

// PID'i kaydet
function savePid() {
    try {
        if (!fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }
        fs.writeFileSync(API_PID_FILE, process.pid.toString());
        logger.debug(`PID kaydedildi: ${process.pid}`);
    } catch (err) {
        logger.error(`PID kaydedilemedi: ${err.message}`);
    }
}

// Helper functions
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

// Load tunnel statistics
async function loadTunnelStats() {
    try {
        if (fs.existsSync(STATS_FILE)) {
            const data = await readFileAsync(STATS_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (err) {
        logger.error('Could not load tunnel statistics: ' + err);
    }
    return { tunnels: {} };
}

// Save tunnel statistics
async function saveTunnelStats(statsData) {
    try {
        await ensureConfigDir();
        await writeFileAsync(STATS_FILE, JSON.stringify(statsData, null, 2));
        return true;
    } catch (err) {
        logger.error('Could not save tunnel statistics: ' + err);
        return false;
    }
}

// Update tunnel statistics
async function updateTunnelStats(tunnelName, stats) {
    try {
        const statsData = await loadTunnelStats();

        if (!statsData.tunnels[tunnelName]) {
            statsData.tunnels[tunnelName] = {
                connections: 0,
                bytesSent: 0,
                bytesReceived: 0,
                totalUptime: 0,
                lastStarted: null,
                lastStopped: null,
                history: []
            };
        }

        // Update stats with new data
        const tunnelStats = statsData.tunnels[tunnelName];
        if (stats.connections !== undefined) tunnelStats.connections += stats.connections;
        if (stats.bytesSent !== undefined) tunnelStats.bytesSent += stats.bytesSent;
        if (stats.bytesReceived !== undefined) tunnelStats.bytesReceived += stats.bytesReceived;

        if (stats.started) {
            tunnelStats.lastStarted = new Date().toISOString();
            tunnelStats.history.push({
                event: 'started',
                timestamp: tunnelStats.lastStarted
            });

            // Keep history limited to last 100 events
            if (tunnelStats.history.length > 100) {
                tunnelStats.history.shift();
            }
        }

        if (stats.stopped) {
            tunnelStats.lastStopped = new Date().toISOString();

            if (tunnelStats.lastStarted) {
                const startTime = new Date(tunnelStats.lastStarted).getTime();
                const endTime = new Date().getTime();
                const uptime = (endTime - startTime) / 1000; // in seconds
                tunnelStats.totalUptime += uptime;
            }

            tunnelStats.history.push({
                event: 'stopped',
                timestamp: tunnelStats.lastStopped
            });

            // Keep history limited to last 100 events
            if (tunnelStats.history.length > 100) {
                tunnelStats.history.shift();
            }
        }

        await saveTunnelStats(statsData);
        return true;
    } catch (err) {
        logger.error(`Could not update statistics for tunnel ${tunnelName}: ${err.message}`);
        return false;
    }
}

// JWT authentication middleware (kept for reference but not used anymore)
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication token required' });
    }

    jwt.verify(token, API_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }

        req.user = user;
        next();
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

// Start tunnel in background
async function startTunnelInBackground(tunnelInfo) {
    const { spawn } = require('child_process');

    return new Promise((resolve, reject) => {
        try {
            // Check and convert local port value
            const localPort = parseInt(tunnelInfo.localPort, 10);
            if (isNaN(localPort)) {
                reject(new Error(`Invalid local port: ${tunnelInfo.localPort}`));
                return;
            }

            // Start tunnel client in a separate process
            const childProcess = spawn(process.execPath, [
                path.join(__dirname, 'client.js'),
                'run',
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

// Helper function to format uptime
function formatUptime(seconds) {
    if (seconds < 60) {
        return `${Math.floor(seconds)} seconds`;
    } else if (seconds < 3600) {
        return `${Math.floor(seconds / 60)} minutes`;
    } else if (seconds < 86400) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours} hours, ${minutes} minutes`;
    } else {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        return `${days} days, ${hours} hours`;
    }
}

// Helper function to format bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';

    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));

    return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
}

// Connect to server and send/receive messages
async function connectAndSend(message, timeoutMs = 10000) {
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

    function sendMessage(socket, message) {
        if (!socket || socket.destroyed) return false;
        return socket.write(encrypt(message) + "\n");
    }

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

// ========================================
// API Routes
// ========================================

// API Status Endpoint
app.get('/api/status', (req, res) => {
    res.json({
        status: 'ok',
        version: packageVersion,
        timestamp: new Date().toISOString()
    });
});

// Authentication Endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password, server = 'localhost', port = 9012 } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Convert port to number
        const portNum = parseInt(port, 10);
        if (isNaN(portNum)) {
            return res.status(400).json({ error: 'Invalid port number' });
        }

        // Connect to V-Tunnel server and login
        const response = await connectAndSend({
            type: 'login',
            username,
            password,
            server,
            port: portNum
        });

        if (response.success) {
            // Save credentials
            const auth = {
                server,
                port: portNum,
                token: response.token,
                user: response.user,
                loginTime: new Date().toISOString()
            };

            await saveAuth(auth);

            // Generate API JWT token
            const apiToken = jwt.sign(
                { username: response.user.username, id: response.user.id },
                API_SECRET,
                { expiresIn: API_TOKEN_EXPIRY }
            );

            res.json({
                success: true,
                message: 'Login successful',
                user: response.user,
                token: apiToken
            });
        } else {
            res.status(401).json({
                success: false,
                error: response.message || 'Authentication failed'
            });
        }
    } catch (err) {
        logger.error('Login error: ' + err.message);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Get Tunnels List
app.get('/api/tunnels', async (req, res) => {
    try {
        // Get tunnels from server
        const response = await connectAndSend({
            type: 'list_tunnels'
        });

        console.log(response)
        if (response.type !== 'tunnels_list') {
            return res.status(500).json({ error: 'Failed to retrieve tunnels list' });
        }

        // Get local tunnel info
        const tunnelsData = await loadActiveTunnels();

        // Merge server and local data
        const tunnels = response.tunnels.map(serverTunnel => {
            // Find matching local tunnel info
            const localTunnel = tunnelsData.tunnels.find(t => t.name === serverTunnel.name) || {};
            const activeTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === serverTunnel.name) : null;

            return {
                ...serverTunnel,
                localHost: localTunnel.localHost,
                localPort: localTunnel.localPort,
                active: activeTunnel ? true : false,
                pid: activeTunnel ? activeTunnel.pid : null,
                startedAt: activeTunnel ? activeTunnel.startedAt : null
            };
        });

        res.json({
            success: true,
            tunnels
        });
    } catch (err) {
        logger.error('Error retrieving tunnels: ' + err.message);
        res.status(500).json({ error: 'Failed to retrieve tunnels' });
    }
});

// Create new tunnel
app.post('/api/tunnels', async (req, res) => {
    try {
        const { name, description = '', localHost = 'localhost', localPort } = req.body;

        if (!name) {
            return res.status(400).json({ error: 'Tunnel name is required' });
        }

        if (!localPort) {
            return res.status(400).json({ error: 'Local port is required' });
        }

        // Convert port to number
        const portNum = parseInt(localPort, 10);
        if (isNaN(portNum) || portNum <= 0 || portNum >= 65536) {
            return res.status(400).json({ error: 'Invalid local port number' });
        }

        // Register tunnel with server
        const response = await connectAndSend({
            type: 'register_tunnel',
            tunnel_name: name,
            description
        });

        if (response.type !== 'tunnel_registered') {
            return res.status(500).json({
                error: response.message || 'Failed to register tunnel with server'
            });
        }

        // Save tunnel information locally
        const tunnelsData = await loadActiveTunnels();

        // Check if a tunnel with the same name already exists
        const existingIndex = tunnelsData.tunnels.findIndex(t => t.name === name);

        const tunnelInfo = {
            name,
            description,
            localHost,
            localPort: portNum,
            serverPort: response.port,
            createdAt: new Date().toISOString()
        };

        if (existingIndex !== -1) {
            tunnelsData.tunnels[existingIndex] = tunnelInfo;
        } else {
            tunnelsData.tunnels.push(tunnelInfo);
        }

        await saveActiveTunnels(tunnelsData);

        res.json({
            success: true,
            message: 'Tunnel created successfully',
            tunnel: {
                ...tunnelInfo,
                id: response.id || null
            }
        });
    } catch (err) {
        logger.error('Error creating tunnel: ' + err.message);
        res.status(500).json({ error: 'Failed to create tunnel' });
    }
});

// Delete tunnel
app.delete('/api/tunnels/:name', async (req, res) => {
    try {
        const { name } = req.params;

        // Delete tunnel from server
        const response = await connectAndSend({
            type: 'delete_tunnel',
            tunnel_name: name
        });

        if (response.type !== 'tunnel_deleted') {
            return res.status(500).json({
                error: response.message || 'Failed to delete tunnel from server'
            });
        }

        // Remove tunnel from local records
        const tunnelsData = await loadActiveTunnels();

        // Stop if running
        const activeTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === name) : null;
        if (activeTunnel) {
            try {
                const isRunning = await isProcessRunning(activeTunnel.pid);
                if (isRunning) {
                    process.kill(activeTunnel.pid);

                    // Update statistics
                    await updateTunnelStats(name, { stopped: true });
                }
            } catch (err) {
                logger.error(`Error stopping running tunnel: ${err.message}`);
            }

            // Remove from active tunnels
            tunnelsData.active = tunnelsData.active.filter(t => t.name !== name);
        }

        // Remove from defined tunnels
        tunnelsData.tunnels = tunnelsData.tunnels.filter(t => t.name !== name);

        // Save changes
        await saveActiveTunnels(tunnelsData);

        res.json({
            success: true,
            message: `Tunnel "${name}" successfully deleted`
        });
    } catch (err) {
        logger.error(`Error deleting tunnel: ${err.message}`);
        res.status(500).json({ error: 'Failed to delete tunnel' });
    }
});

// Start tunnel
app.post('/api/tunnels/:name/start', async (req, res) => {
    try {
        const { name } = req.params;

        // Get tunnel information
        const tunnelsData = await loadActiveTunnels();
        const tunnelInfo = tunnelsData.tunnels.find(t => t.name === name);

        if (!tunnelInfo) {
            return res.status(404).json({ error: `Tunnel "${name}" not found` });
        }

        // Check if tunnel is already running
        const existingActiveTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === name) : null;

        if (existingActiveTunnel) {
            const isRunning = await isProcessRunning(existingActiveTunnel.pid);

            if (isRunning) {
                return res.json({
                    success: true,
                    message: `Tunnel "${name}" is already running`,
                    tunnel: {
                        ...tunnelInfo,
                        active: true,
                        pid: existingActiveTunnel.pid,
                        startedAt: existingActiveTunnel.startedAt
                    }
                });
            } else {
                // PID not found, clean up old record
                tunnelsData.active = tunnelsData.active.filter(t => t.name !== name);
            }
        }

        // Start tunnel in background
        const activeTunnel = await startTunnelInBackground(tunnelInfo);

        if (!tunnelsData.active) {
            tunnelsData.active = [];
        }

        tunnelsData.active.push(activeTunnel);
        await saveActiveTunnels(tunnelsData);

        // Update statistics
        await updateTunnelStats(name, {
            started: true,
            connections: 0,
            bytesSent: 0,
            bytesReceived: 0
        });

        res.json({
            success: true,
            message: `Tunnel "${name}" started successfully`,
            tunnel: {
                ...tunnelInfo,
                active: true,
                pid: activeTunnel.pid,
                startedAt: activeTunnel.startedAt
            }
        });
    } catch (err) {
        logger.error(`Error starting tunnel: ${err.message}`);
        res.status(500).json({ error: 'Failed to start tunnel' });
    }
});

// Stop tunnel
app.post('/api/tunnels/:name/stop', async (req, res) => {
    try {
        const { name } = req.params;

        // Get tunnel information
        const tunnelsData = await loadActiveTunnels();
        const tunnelInfo = tunnelsData.tunnels.find(t => t.name === name);

        if (!tunnelInfo) {
            return res.status(404).json({ error: `Tunnel "${name}" not found` });
        }

        // Check if tunnel is running
        const activeTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === name) : null;

        if (!activeTunnel) {
            return res.json({
                success: true,
                message: `Tunnel "${name}" is not running`,
                tunnel: {
                    ...tunnelInfo,
                    active: false
                }
            });
        }

        // Stop the process
        try {
            const isRunning = await isProcessRunning(activeTunnel.pid);

            if (isRunning) {
                process.kill(activeTunnel.pid);

                // Update statistics
                await updateTunnelStats(name, { stopped: true });
            }
        } catch (err) {
            logger.error(`Could not stop process: ${err.message}`);
        }

        // Remove from active tunnels
        tunnelsData.active = tunnelsData.active.filter(t => t.name !== name);
        await saveActiveTunnels(tunnelsData);

        res.json({
            success: true,
            message: `Tunnel "${name}" stopped successfully`,
            tunnel: {
                ...tunnelInfo,
                active: false
            }
        });
    } catch (err) {
        logger.error(`Error stopping tunnel: ${err.message}`);
        res.status(500).json({ error: 'Failed to stop tunnel' });
    }
});

// Get tunnel statistics
app.get('/api/tunnels/:name/stats', async (req, res) => {
    try {
        const { name } = req.params;

        // Check if tunnel exists
        const tunnelsData = await loadActiveTunnels();
        const tunnelInfo = tunnelsData.tunnels.find(t => t.name === name);

        if (!tunnelInfo) {
            return res.status(404).json({ error: `Tunnel "${name}" not found` });
        }

        // Get tunnel statistics
        const statsData = await loadTunnelStats();
        const tunnelStats = statsData.tunnels[name] || {
            connections: 0,
            bytesSent: 0,
            bytesReceived: 0,
            totalUptime: 0,
            lastStarted: null,
            lastStopped: null,
            history: []
        };

        // Check if tunnel is currently running
        const activeTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === name) : null;
        const isRunning = activeTunnel ? await isProcessRunning(activeTunnel.pid) : false;

        // Calculate current uptime if running
        let currentUptime = 0;
        if (isRunning && tunnelStats.lastStarted) {
            const startTime = new Date(tunnelStats.lastStarted).getTime();
            const currentTime = new Date().getTime();
            currentUptime = (currentTime - startTime) / 1000; // in seconds
        }

        // Get server-side stats
        const serverResponse = await connectAndSend({
            type: 'list_tunnels'
        });

        let serverStats = {};
        if (serverResponse.type === 'tunnels_list') {
            const serverTunnel = serverResponse.tunnels.find(t => t.name === name);
            if (serverTunnel) {
                serverStats = {
                    bytesSent: serverTunnel.bytes_sent || 0,
                    bytesReceived: serverTunnel.bytes_received || 0,
                    lastActiveAt: serverTunnel.lastActiveAt,
                    clientCount: serverTunnel.clientCount || 0
                };
            }
        }

        res.json({
            success: true,
            tunnelName: name,
            isActive: isRunning,
            stats: {
                ...tunnelStats,
                currentUptime: isRunning ? currentUptime : 0,
                totalUptimeFormatted: formatUptime(tunnelStats.totalUptime + (isRunning ? currentUptime : 0)),
                currentUptimeFormatted: formatUptime(currentUptime),
                activeConnections: isRunning ? (serverStats.clientCount || 0) : 0,
                server: serverStats
            }
        });
    } catch (err) {
        logger.error(`Error retrieving tunnel statistics: ${err.message}`);
        res.status(500).json({ error: 'Failed to retrieve tunnel statistics' });
    }
});

// Get all tunnel statistics
app.get('/api/stats', async (req, res) => {
    try {
        // Get all tunnels
        const tunnelsData = await loadActiveTunnels();
        const statsData = await loadTunnelStats();

        // Get server-side stats
        const serverResponse = await connectAndSend({
            type: 'list_tunnels'
        });

        let serverStats = {};
        if (serverResponse.type === 'tunnels_list') {
            serverResponse.tunnels.forEach(tunnel => {
                serverStats[tunnel.name] = {
                    bytesSent: tunnel.bytes_sent || 0,
                    bytesReceived: tunnel.bytes_received || 0,
                    lastActiveAt: tunnel.lastActiveAt,
                    clientCount: tunnel.clientCount || 0
                };
            });
        }

        // Prepare statistics for all tunnels
        const stats = {};

        // Process each tunnel
        for (const tunnel of tunnelsData.tunnels) {
            const tunnelName = tunnel.name;
            const tunnelStats = statsData.tunnels[tunnelName] || {
                connections: 0,
                bytesSent: 0,
                bytesReceived: 0,
                totalUptime: 0,
                lastStarted: null,
                lastStopped: null,
                history: []
            };

            // Check if tunnel is currently running
            const activeTunnel = tunnelsData.active ? tunnelsData.active.find(t => t.name === tunnelName) : null;
            const isRunning = activeTunnel ? await isProcessRunning(activeTunnel.pid) : false;

            // Calculate current uptime if running
            let currentUptime = 0;
            if (isRunning && tunnelStats.lastStarted) {
                const startTime = new Date(tunnelStats.lastStarted).getTime();
                const currentTime = new Date().getTime();
                currentUptime = (currentTime - startTime) / 1000; // in seconds
            }

            stats[tunnelName] = {
                isActive: isRunning,
                stats: {
                    ...tunnelStats,
                    currentUptime: isRunning ? currentUptime : 0,
                    totalUptimeFormatted: formatUptime(tunnelStats.totalUptime + (isRunning ? currentUptime : 0)),
                    currentUptimeFormatted: formatUptime(currentUptime),
                    activeConnections: isRunning ? (serverStats[tunnelName]?.clientCount || 0) : 0,
                    server: serverStats[tunnelName] || {}
                }
            };
        }

        // Calculate global statistics
        let totalConnections = 0;
        let totalBytesSent = 0;
        let totalBytesReceived = 0;
        let totalUptime = 0;
        let activeTunnels = 0;

        Object.values(stats).forEach(tunnelStat => {
            totalConnections += tunnelStat.stats.connections || 0;

            // Include both local and server-side bytes
            const localBytesSent = tunnelStat.stats.bytesSent || 0;
            const localBytesReceived = tunnelStat.stats.bytesReceived || 0;
            const serverBytesSent = tunnelStat.stats.server?.bytesSent || 0;
            const serverBytesReceived = tunnelStat.stats.server?.bytesReceived || 0;

            // Use server-side bytes if available, fall back to local bytes
            totalBytesSent += serverBytesSent > 0 ? serverBytesSent : localBytesSent;
            totalBytesReceived += serverBytesReceived > 0 ? serverBytesReceived : localBytesReceived;

            // Include both stored uptime and current uptime
            totalUptime += (tunnelStat.stats.totalUptime || 0) + (tunnelStat.stats.currentUptime || 0);

            if (tunnelStat.isActive) activeTunnels++;
        });

        res.json({
            success: true,
            summary: {
                tunnelCount: tunnelsData.tunnels.length,
                activeTunnels,
                totalConnections,
                totalBytesSent,
                totalBytesReceived,
                totalUptime,
                totalUptimeFormatted: formatUptime(totalUptime),
                totalBytesSentFormatted: formatBytes(totalBytesSent),
                totalBytesReceivedFormatted: formatBytes(totalBytesReceived)
            },
            tunnels: stats
        });
    } catch (err) {
        logger.error(`Error retrieving global statistics: ${err.message}`);
        res.status(500).json({ error: 'Failed to retrieve global statistics' });
    }
});

// Uygulama root endpoint - Web UI için
app.get('*', (req, res, next) => {
    // API rotaları için bir sonraki middleware'e geç
    if (req.path.startsWith('/api/')) {
        return next();
    }

    // Web UI directory var mı kontrol et
    if (fs.existsSync(WEB_UI_DIR)) {
        // index.html dosyasını gönder (Single Page Application için)
        res.sendFile(path.join(WEB_UI_DIR, 'index.html'));
    } else {
        // Web UI yok, basit bir bilgi sayfası göster
        res.send(`
            <html>
            <head>
                <title>V-Tunnel API</title>
                <style>
                    body { font-family: sans-serif; line-height: 1.5; max-width: 800px; margin: 0 auto; padding: 20px; }
                    h1 { color: #333; }
                    .status { background: #f0f0f0; padding: 15px; border-radius: 5px; }
                    .success { color: green; }
                    .details { margin-top: 20px; }
                    code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
                </style>
            </head>
            <body>
                <h1>V-Tunnel API Servisi</h1>
                <div class="status">
                    <p>Durum: <span class="success">✅ Çalışıyor</span></p>
                    <p>Versiyon: ${packageVersion}</p>
                    <p>Zaman: ${new Date().toLocaleString()}</p>
                </div>
                <div class="details">
                    <p>API erişim noktaları:</p>
                    <ul>
                        <li><code>GET /api/status</code> - API durumu</li>
                        <li><code>POST /api/auth/login</code> - Giriş yapma</li>
                        <li><code>GET /api/tunnels</code> - Tünel listesi</li>
                        <li><code>GET /api/stats</code> - İstatistikler</li>
                    </ul>
                    <p>Web arayüzü için <code>web-ui</code> dizinine React uygulamanızı yerleştirebilirsiniz.</p>
                </div>
            </body>
            </html>
        `);
    }
});

// Port kullanılabilirliğini kontrol et
function checkPort(port) {
    return new Promise((resolve) => {
        const tester = net.createServer()
            .once('error', err => {
                if (err.code === 'EADDRINUSE') {
                    resolve(false); // Port kullanımda
                } else {
                    resolve(false); // Başka hata durumu
                }
                tester.close();
            })
            .once('listening', () => {
                tester.close();
                resolve(true); // Port kullanılabilir
            })
            .listen(port);
    });
}

// Start API server
async function startApiServer() {
    return new Promise(async (resolve, reject) => {
        try {
            // Önce portu kontrol et
            const isPortAvailable = await checkPort(API_PORT);

            if (!isPortAvailable) {
                logger.warning(`Port ${API_PORT} zaten kullanımda. Muhtemelen API sunucusu zaten çalışıyor.`);

                // PID'imizi yine de kaydet (eğer bu işlem gerçekten API sunucusuysa)
                savePid();

                // Yine de resolve ile dönelim, çünkü bu durumda çalışıyor olarak varsayabiliriz
                resolve({ alreadyRunning: true, port: API_PORT });
                return;
            }

            // PID'i kaydet
            savePid();

            // Sunucuyu başlat
            const server = app.listen(API_PORT, () => {
                logger.success(`V-Tunnel API server listening on port ${API_PORT}`);

                if (fs.existsSync(WEB_UI_DIR)) {
                    logger.info(`Web UI: http://localhost:${API_PORT}/`);
                }

                logger.info(`API endpoint: http://localhost:${API_PORT}/api`);
                resolve(server);
            });

            server.on('error', (err) => {
                logger.error(`Failed to start API server: ${err.message}`);
                reject(err);
            });
        } catch (err) {
            logger.error(`Error starting API server: ${err.message}`);
            reject(err);
        }
    });
}

// Stop the API server
async function stopApiServer(server) {
    return new Promise((resolve, reject) => {
        if (!server) {
            logger.warning('No server instance to stop');
            resolve(true);
            return;
        }

        server.close(err => {
            if (err) {
                logger.error(`Error stopping server: ${err.message}`);
                reject(err);
                return;
            }

            logger.success('API server stopped successfully');

            // Remove PID file
            try {
                if (fs.existsSync(API_PID_FILE)) {
                    fs.unlinkSync(API_PID_FILE);
                }
            } catch (err) {
                logger.warning(`Could not remove PID file: ${err.message}`);
            }

            resolve(true);
        });
    });
}

// Export the API server methods
module.exports = {
    startApiServer,
    stopApiServer
};

// If this file is run directly, start the API server
if (require.main === module) {
    console.log('API sunucusu doğrudan başlatılıyor...');
    savePid();

    startApiServer().catch(err => {
        logger.error(`Failed to start API server: ${err.message}`);
        process.exit(1);
    });
}
