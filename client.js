#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const inquirer = require('inquirer');
const axios = require('axios');
const WebSocket = require('ws');
const net = require('net');
const express = require('express');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const Table = require('cli-table3');
const colors = require('colors/safe');
const ip = require('ip');
const { spawn } = require('child_process');

// Sabitler
const CONFIG_DIR = path.join(os.homedir(), '.vtunnel-client');
const AUTH_FILE = path.join(CONFIG_DIR, 'auth.json');
const ACTIVE_TUNNELS_FILE = path.join(CONFIG_DIR, 'active.json');
const DEFAULT_SERVER = 'http://localhost';
const LOCAL_API_PORT = 9015; // 9012'den 9015'e değiştirildi

// Yapılandırma dizininin varlığını kontrol et
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// AES Şifreleme/Şifre Çözme
const AES_KEY = crypto.randomBytes(32);
const AES_IV = crypto.randomBytes(16);

function encryptData(data) {
    const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, AES_IV);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        encrypted,
        iv: AES_IV.toString('hex'),
        key: AES_KEY.toString('hex')
    };
}

function decryptData(encryptedData) {
    const decipher = crypto.createDecipheriv(
        'aes-256-cbc',
        Buffer.from(encryptedData.key, 'hex'),
        Buffer.from(encryptedData.iv, 'hex')
    );
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

// Kimlik doğrulama token'ını al
function getAuthToken() {
    if (fs.existsSync(AUTH_FILE)) {
        try {
            const encryptedData = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
            const authData = decryptData(encryptedData);
            return authData.token;
        } catch (err) {
            console.error('Kimlik doğrulama token\'ını okurken hata:', err.message);
            return null;
        }
    }
    return null;
}

// Kimlik doğrulama token'ını kaydet
function saveAuthToken(token, server) {
    const authData = {
        token,
        server: server || DEFAULT_SERVER
    };

    const encryptedData = encryptData(authData);
    fs.writeFileSync(AUTH_FILE, JSON.stringify(encryptedData));
}

// Sunucu URL'sini al
function getServerUrl() {
    if (fs.existsSync(AUTH_FILE)) {
        try {
            const encryptedData = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
            const authData = decryptData(encryptedData);
            return authData.server || DEFAULT_SERVER;
        } catch (err) {
            console.error('Sunucu URL\'sini okurken hata:', err.message);
            return DEFAULT_SERVER;
        }
    }
    return DEFAULT_SERVER;
}

// Kullanıcının giriş yapıp yapmadığını kontrol et
function isLoggedIn() {
    return getAuthToken() !== null;
}

// Kimlik doğrulamalı API istemcisi oluştur
function createApiClient() {
    const token = getAuthToken();
    const server = getServerUrl();

    return axios.create({
        baseURL: server,
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
}

// Aktif tüneller deposu
const activeTunnels = new Map();
let webSocketClient = null;

// Yardımcı fonksiyonlar
function colorizeStatus(status) {
    switch (status) {
        case 'active':
            return colors.green(status);
        case 'inactive':
            return colors.yellow(status);
        case 'error':
            return colors.red(status);
        default:
            return status;
    }
}

function formatBytes(bytes) {
    // Eğer bytes null, undefined veya NaN ise "0 B" döndür
    if (bytes === null || bytes === undefined || isNaN(bytes) || bytes === 0) {
        return '0 B';
    }

    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Aktif tünelleri dosyaya kaydet
function saveActiveTunnels() {
    try {
        const tunnelData = {};

        for (const [tunnelId, tunnel] of activeTunnels.entries()) {
            tunnelData[tunnelId] = {
                name: tunnel.name,
                host: tunnel.host,
                port: tunnel.port,
                serverPort: tunnel.serverPort,
                localPort: tunnel.localPort
            };
        }

        const encryptedData = encryptData(tunnelData);
        fs.writeFileSync(ACTIVE_TUNNELS_FILE, JSON.stringify(encryptedData));

        console.log(`Aktif tüneller ${ACTIVE_TUNNELS_FILE} dosyasına kaydedildi.`);
    } catch (err) {
        console.error(`Aktif tünelleri kaydederken hata: ${err.message}`);
    }
}

// Aktif tünelleri dosyadan yükle
function loadActiveTunnels() {
    if (!fs.existsSync(ACTIVE_TUNNELS_FILE)) {
        return {};
    }

    try {
        const encryptedData = JSON.parse(fs.readFileSync(ACTIVE_TUNNELS_FILE, 'utf8'));
        return decryptData(encryptedData);
    } catch (err) {
        console.error(`Aktif tünelleri yüklerken hata: ${err.message}`);
        return {};
    }
}

// Tünelleri otomatik olarak yeniden başlat
async function restoreActiveTunnels() {
    if (!isLoggedIn()) {
        return;
    }

    try {
        const savedTunnels = loadActiveTunnels();

        if (Object.keys(savedTunnels).length === 0) {
            return;
        }

        console.log('Önceki aktif tüneller yükleniyor...');

        // WebSocket bağlantısını sağla
        await ensureWebSocketConnection();

        const api = createApiClient();

        // Tünel listesini al
        const tunnelsResponse = await api.get('/api/tunnels');
        const tunnels = tunnelsResponse.data;

        for (const [tunnelId, tunnelInfo] of Object.entries(savedTunnels)) {
            // Tünel hala var mı kontrol et
            const tunnel = tunnels.find(t => t.id.toString() === tunnelId);

            if (tunnel) {
                console.log(`"${tunnelInfo.name}" tüneli yeniden başlatılıyor...`);

                try {
                    // Tüneli başlat
                    await api.post(`/api/tunnels/${tunnelId}/start`);
                } catch (err) {
                    console.error(`"${tunnelInfo.name}" tünelini yeniden başlatırken hata: ${err.message}`);
                }
            }
        }
    } catch (err) {
        console.error(`Tünelleri yeniden başlatırken hata: ${err.message}`);
    }
}

// WebSocket bağlantısı
async function ensureWebSocketConnection() {
    if (webSocketClient && webSocketClient.readyState === WebSocket.OPEN) {
        console.log('WebSocket bağlantısı zaten açık.');
        return;
    }

    const token = getAuthToken();
    if (!token) {
        throw new Error('Giriş yapılmamış');
    }

    const serverUrl = getServerUrl();
    const wsUrl = serverUrl.replace(/^http/, 'ws') + '/ws';

    console.log(`WebSocket sunucusuna bağlanılıyor: ${wsUrl}`);

    return new Promise((resolve, reject) => {
        webSocketClient = new WebSocket(wsUrl);

        webSocketClient.on('open', () => {
            console.log('Sunucuya WebSocket bağlantısı kuruldu');

            // Kimlik doğrulama gönder
            const authMessage = {
                type: 'auth',
                token,
                clientName: os.hostname(),
                clientIp: ip.address(),
                clientOs: `${os.platform()} ${os.release()}`
            };

            console.log('Kimlik doğrulama gönderiliyor...');
            webSocketClient.send(JSON.stringify(authMessage));

            // Heartbeat kur
            const heartbeatInterval = setInterval(() => {
                if (webSocketClient.readyState === WebSocket.OPEN) {
                    webSocketClient.send(JSON.stringify({ type: 'heartbeat' }));
                } else {
                    clearInterval(heartbeatInterval);
                }
            }, 30000);

            resolve();
        });

        webSocketClient.on('message', (data) => {
            const message = JSON.parse(data);
            console.log('WebSocket mesajı alındı:', message.type);

            if (message.type === 'authResult') {
                if (message.success) {
                    console.log('WebSocket kimlik doğrulama başarılı');
                } else {
                    console.error(`Kimlik doğrulama başarısız: ${message.error}`);
                    webSocketClient.close();
                    reject(new Error(message.error));
                }
            }
            else if (message.type === 'startTunnel') {
                console.log(`Sunucudan tünel başlatma talebi alındı: ${message.name} (ID: ${message.tunnelId})`);
                handleStartTunnel(message);
            }
            else if (message.type === 'stopTunnel') {
                console.log(`Sunucudan tünel durdurma talebi alındı: ${message.tunnelId}`);
                handleStopTunnel(message);
            }
            else if (message.type === 'heartbeatAck') {
                // Heartbeat onayı, hiçbir şey yapma
                console.log('Heartbeat onayı alındı');
            }
            else if (message.type === 'tunnelStartConfirmed') {
                console.log(`"${message.name}" tüneli (port: ${message.serverPort}) başarıyla aktifleştirildi.`);
                console.log('Tünel aktif ve çalışıyor. Ctrl+C ile çıkabilirsiniz.');
            }
            else if (message.type === 'tunnelStartFailed') {
                console.error(`Tünel başlatma başarısız oldu: ${message.error}`);
            }
            else {
                console.log(`Bilinmeyen WebSocket mesaj türü: ${message.type}`);
            }
        });

        webSocketClient.on('close', () => {
            console.log('Sunucu WebSocket bağlantısı kesildi');
        });

        webSocketClient.on('error', (err) => {
            console.error(`WebSocket hatası: ${err.message}`);
            reject(err);
        });
    });
}

// Sunucudan tünel başlatma komutunu işle
function handleStartTunnel(message) {
    const { tunnelId, name, host, port, serverPort } = message;

    // Tünelin zaten aktif olup olmadığını kontrol et
    if (activeTunnels.has(tunnelId)) {
        console.log(`"${name}" tüneli zaten aktif. Yoksayılıyor.`);
        return;
    }

    console.log(`"${name}" tüneli ${host}:${port} hedefine başlatılıyor (Sunucu portu: ${serverPort})`);

    try {
        // Önce hedef servisin erişilebilir olup olmadığını kontrol et
        const testSocket = net.createConnection({
            host,
            port,
            timeout: 3000 // 3 saniye timeout
        });

        testSocket.on('connect', () => {
            console.log(`Hedef servis ${host}:${port} erişilebilir, tünel kuruluyor...`);
            testSocket.end();

            // Hedef erişilebilir, tünel proxy'sini oluştur
            createTunnelProxy(tunnelId, name, host, port, serverPort);
        });

        testSocket.on('timeout', () => {
            console.error(`Hedef servis ${host}:${port} zaman aşımına uğradı. Tünel oluşturulamadı.`);
            testSocket.destroy();

            // Sunucuya hata gönder
            if (webSocketClient && webSocketClient.readyState === WebSocket.OPEN) {
                webSocketClient.send(JSON.stringify({
                    type: 'tunnelStarted',
                    tunnelId,
                    success: false,
                    error: `Hedef servis ${host}:${port} zaman aşımına uğradı.`
                }));
            }
        });

        testSocket.on('error', (err) => {
            console.error(`Hedef servis ${host}:${port} bağlantı hatası: ${err.message}`);

            // Sunucuya hata gönder
            if (webSocketClient && webSocketClient.readyState === WebSocket.OPEN) {
                webSocketClient.send(JSON.stringify({
                    type: 'tunnelStarted',
                    tunnelId,
                    success: false,
                    error: `Hedef servis ${host}:${port} bağlantı hatası: ${err.message}`
                }));
            }
        });
    } catch (err) {
        console.error(`"${name}" tünelini başlatırken hata: ${err.message}`);

        // Sunucuya hata gönder
        if (webSocketClient && webSocketClient.readyState === WebSocket.OPEN) {
            webSocketClient.send(JSON.stringify({
                type: 'tunnelStarted',
                tunnelId,
                success: false,
                error: err.message
            }));
        }
    }
}

// Tünel proxy'si oluştur
function createTunnelProxy(tunnelId, name, host, port, serverPort) {
    // Yerel-uzak proxy oluştur
    const proxy = net.createServer((socket) => {
        console.log(`Tünel #${tunnelId} için yeni bağlantı: ${socket.remoteAddress}:${socket.remotePort}`);

        // Hedefe bağlan
        const targetSocket = net.createConnection({
            host,
            port
        });

        targetSocket.on('connect', () => {
            console.log(`"${name}" tüneli hedef bağlantısı kuruldu: ${host}:${port}`);
        });

        // İstemciden hedefe veri akışını işle
        socket.on('data', (data) => {
            try {
                targetSocket.write(data);
            } catch (err) {
                console.error(`Veri gönderirken hata: ${err.message}`);
            }
        });

        // Hedeften istemciye veri akışını işle
        targetSocket.on('data', (data) => {
            try {
                socket.write(data);
            } catch (err) {
                console.error(`Veri alırken hata: ${err.message}`);
            }
        });

        // Bağlantı kapanmasını işle
        socket.on('close', () => {
            console.log(`Tünel #${tunnelId} istemci bağlantısı kapandı`);
            try {
                targetSocket.end();
            } catch (err) {
                // Zaten kapanmış olabilir
            }
        });

        // Hedef bağlantı kapanmasını işle
        targetSocket.on('close', () => {
            console.log(`Tünel #${tunnelId} hedef bağlantısı kapandı`);
            try {
                socket.end();
            } catch (err) {
                // Zaten kapanmış olabilir
            }
        });

        // Hataları işle
        socket.on('error', (err) => {
            console.error(`Tünel #${tunnelId} istemci soketi hatası: ${err.message}`);
            try {
                targetSocket.end();
            } catch (err) {
                // Yoksay
            }
        });

        targetSocket.on('error', (err) => {
            console.error(`Tünel #${tunnelId} hedef soketi hatası: ${err.message}`);
            try {
                socket.end();
            } catch (err) {
                // Yoksay
            }
        });
    });

    // Tüm arayüzlerde rastgele bir portta dinle
    proxy.listen(0, '0.0.0.0', () => {
        const localPort = proxy.address().port;

        // Aktif tüneli kaydet
        activeTunnels.set(tunnelId, {
            name,
            host,
            port,
            serverPort,
            localPort,
            proxy
        });

        console.log(`"${name}" tüneli başarıyla başlatıldı. Yerel port: ${localPort}`);

        // Sunucuya onay gönder
        if (webSocketClient && webSocketClient.readyState === WebSocket.OPEN) {
            const confirmMessage = {
                type: 'tunnelStarted',
                tunnelId,
                success: true
            };
            console.log('Sunucuya tünel başlatma onayı gönderiliyor:', confirmMessage);
            webSocketClient.send(JSON.stringify(confirmMessage));
        } else {
            console.error('WebSocket bağlantısı yok veya kapalı. Tünel başlatma onayı gönderilemedi.');
        }

        // Aktif tünelleri kaydet
        saveActiveTunnels();
    });

    // Hataları işle
    proxy.on('error', (err) => {
        console.error(`"${name}" tünelini başlatırken hata: ${err.message}`);

        // Sunucuya hata gönder
        if (webSocketClient && webSocketClient.readyState === WebSocket.OPEN) {
            webSocketClient.send(JSON.stringify({
                type: 'tunnelStarted',
                tunnelId,
                success: false,
                error: err.message
            }));
        }
    });
}

// Sunucudan tünel durdurma komutunu işle
function handleStopTunnel(message) {
    const { tunnelId } = message;

    // Tünelin aktif olup olmadığını kontrol et
    if (activeTunnels.has(tunnelId)) {
        const tunnel = activeTunnels.get(tunnelId);

        console.log(`"${tunnel.name}" tüneli durduruluyor`);

        // Proxy'yi kapat
        tunnel.proxy.close();

        // Aktif tünellerden kaldır
        activeTunnels.delete(tunnelId);

        // Aktif tünelleri güncelle
        saveActiveTunnels();

        console.log(`"${tunnel.name}" tüneli durduruldu`);

        // Sunucuya onay gönder
        if (webSocketClient && webSocketClient.readyState === WebSocket.OPEN) {
            webSocketClient.send(JSON.stringify({
                type: 'tunnelStopped',
                tunnelId
            }));
        }
    }
}

// PID kaydet
function savePid(pid) {
    const pidFile = path.join(CONFIG_DIR, 'api.pid');
    fs.writeFileSync(pidFile, pid.toString());
}

// PID dosyasını temizle
function clearPid() {
    const pidFile = path.join(CONFIG_DIR, 'api.pid');
    if (fs.existsSync(pidFile)) {
        fs.unlinkSync(pidFile);
    }
}

// İşlem çalışıyor mu kontrol et
function checkApiProcess() {
    return new Promise((resolve) => {
        // PID dosyasının varlığını kontrol et
        const pidFile = path.join(CONFIG_DIR, 'api.pid');

        if (!fs.existsSync(pidFile)) {
            resolve(false);
            return;
        }

        try {
            // PID'yi oku
            const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());

            // İşlem çalışıyor mu kontrol et (platform bağımsız)
            if (process.platform === 'win32') {
                // Windows için tasklist
                const tasklist = spawn('tasklist', ['/fi', `PID eq ${pid}`, '/fo', 'csv', '/nh']);
                let output = '';

                tasklist.stdout.on('data', (data) => {
                    output += data.toString();
                });

                tasklist.on('close', () => {
                    resolve(output.includes(`"${pid}"`));
                });
            } else {
                // Unix/Linux/macOS için kill -0
                try {
                    process.kill(pid, 0);
                    resolve(true);
                } catch (e) {
                    resolve(false);
                }
            }
        } catch (err) {
            console.error('PID dosyası okunurken hata:', err.message);
            resolve(false);
        }
    });
}

// Arka planda API başlatma fonksiyonu
function startApiInBackground() {
    // Mevcut işlemi kontrol et
    checkApiProcess()
        .then(isRunning => {
            if (isRunning) {
                console.log('Yerel API zaten çalışıyor');
                return;
            }

            // Node.js'i ayrı bir işlem olarak başlat
            const child = spawn(process.execPath, [process.argv[1], 'api', '--start'], {
                detached: true,
                stdio: 'ignore'
            });

            // Ana işlemden ayır
            child.unref();

            console.log(`Yerel API ${LOCAL_API_PORT} portunda arka planda başlatıldı (PID: ${child.pid})`);

            // PID'yi kaydet
            savePid(child.pid);
        })
        .catch(err => {
            console.error('API işlemi kontrol edilirken hata:', err.message);
        });
}

// Yerel API sunucusu
let localApiServer = null;

// API komutunu düzenleyin
function apiCommand(argv) {
    if (argv.start) {
        if (argv.background || argv.daemon) {
            // Arka planda başlat
            startApiInBackground();
        } else {
            // Normal şekilde başlat
            startLocalApi();
        }
    } else if (argv.stop) {
        stopLocalApi();
    } else if (argv.status) {
        checkLocalApiStatus();
    } else {
        console.log('Lütfen --start, --stop, veya --status belirtin');
        console.log('Arka planda başlatmak için: --start --background');
    }
}

function startLocalApi() {
    if (localApiServer) {
        console.log('Yerel API zaten çalışıyor');
        return;
    }

    if (!isLoggedIn()) {
        console.log('Giriş yapmamışsınız. Önce "vtunnel login" kullanın.');
        return;
    }

    const app = express();
    app.use(express.json());

    // API başladığında PID'yi kaydet
    savePid(process.pid);

    // Kapatıldığında PID dosyasını temizle
    process.on('exit', () => {
        clearPid();
    });

    // Kimlik doğrulamayı kontrol etmek için middleware
    app.use((req, res, next) => {
        if (!isLoggedIn()) {
            return res.status(401).json({ error: 'Giriş yapılmamış' });
        }
        next();
    });

    // API rotaları
    app.get('/tunnels', async (req, res) => {
        try {
            const api = createApiClient();
            const response = await api.get('/api/tunnels');
            res.json(response.data);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    app.post('/tunnels/start', async (req, res) => {
        try {
            const { id, name } = req.body;

            if (!id && !name) {
                return res.status(400).json({ error: 'Tünel ID veya adı gerekli' });
            }

            const api = createApiClient();

            // Tünel listesini al
            const tunnelsResponse = await api.get('/api/tunnels');
            const tunnels = tunnelsResponse.data.filter(t => t.status !== 'active');

            let tunnelId;

            if (id) {
                tunnelId = id;
            } else if (name) {
                const tunnel = tunnels.find(t => t.name === name);
                if (!tunnel) {
                    return res.status(404).json({ error: `"${name}" adında tünel bulunamadı` });
                }
                tunnelId = tunnel.id;
            }

            // WebSocket bağlantısını sağla
            await ensureWebSocketConnection();

            // Tüneli başlat
            await api.post(`/api/tunnels/${tunnelId}/start`);

            res.json({ message: 'Tünel başlatma komutu gönderildi' });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    app.post('/tunnels/stop', async (req, res) => {
        try {
            const { id, name } = req.body;

            if (!id && !name) {
                return res.status(400).json({ error: 'Tünel ID veya adı gerekli' });
            }

            const api = createApiClient();

            // Tünel listesini al
            const tunnelsResponse = await api.get('/api/tunnels');
            const tunnels = tunnelsResponse.data.filter(t => t.status === 'active');

            let tunnelId;

            if (id) {
                tunnelId = id;
            } else if (name) {
                const tunnel = tunnels.find(t => t.name === name);
                if (!tunnel) {
                    return res.status(404).json({ error: `"${name}" adında aktif tünel bulunamadı` });
                }
                tunnelId = tunnel.id;
            }

            // Tüneli durdur
            await api.post(`/api/tunnels/${tunnelId}/stop`);

            // Ayrıca aktifse yerel tüneli de durdur
            if (activeTunnels.has(tunnelId)) {
                const tunnel = activeTunnels.get(tunnelId);
                tunnel.proxy.close();
                activeTunnels.delete(tunnelId);
            }

            res.json({ message: 'Tünel durduruldu' });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    app.post('/tunnels/stopall', async (req, res) => {
        try {
            const api = createApiClient();

            // Tünel listesini al
            const tunnelsResponse = await api.get('/api/tunnels');
            const activeTunnelIds = tunnelsResponse.data
                .filter(t => t.status === 'active')
                .map(t => t.id);

            if (activeTunnelIds.length === 0) {
                return res.json({ message: 'Aktif tünel bulunamadı' });
            }

            // Her tüneli durdur
            for (const tunnelId of activeTunnelIds) {
                await api.post(`/api/tunnels/${tunnelId}/stop`);

                // Ayrıca aktifse yerel tüneli de durdur
                if (activeTunnels.has(tunnelId)) {
                    const tunnel = activeTunnels.get(tunnelId);
                    tunnel.proxy.close();
                    activeTunnels.delete(tunnelId);
                }
            }

            res.json({ message: `${activeTunnelIds.length} tünel durduruldu` });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    app.post('/tunnels/create', async (req, res) => {
        try {
            const { name, host, port } = req.body;

            if (!name || !host || !port) {
                return res.status(400).json({ error: 'İsim, host ve port gerekli' });
            }

            const api = createApiClient();
            const response = await api.post('/api/tunnels', {
                name,
                host,
                port
            });

            res.status(201).json(response.data);
        } catch (err) {
            res.status(500).json({ error: err.response?.data?.error || err.message });
        }
    });

    // Sunucuyu başlat
    localApiServer = app.listen(LOCAL_API_PORT, () => {
        console.log(`Yerel API sunucusu ${LOCAL_API_PORT} portunda başlatıldı (PID: ${process.pid})`);
    });
}

function stopLocalApi() {
    // PID dosyasını kontrol et
    const pidFile = path.join(CONFIG_DIR, 'api.pid');

    if (fs.existsSync(pidFile)) {
        try {
            const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());

            // Çalışan bir işlem var mı kontrol et
            try {
                // İşlemi sonlandır
                if (process.platform === 'win32') {
                    spawn('taskkill', ['/pid', pid, '/f', '/t']);
                } else {
                    process.kill(pid, 'SIGTERM');
                }
                console.log(`API işlemi (PID: ${pid}) sonlandırıldı.`);
            } catch (e) {
                console.log('API işlemi zaten sonlandırılmış.');
            }

            // PID dosyasını temizle
            clearPid();
        } catch (err) {
            console.error('API işlemi sonlandırılırken hata:', err.message);
        }
    }

    // Mevcut oturumda çalışan bir sunucu varsa kapat
    if (localApiServer) {
        localApiServer.close();
        localApiServer = null;
        console.log('Yerel API sunucusu durduruldu');
    } else {
        console.log('Bu oturumda çalışan API sunucusu yok.');
    }
}

function checkLocalApiStatus() {
    checkApiProcess().then(isRunning => {
        if (isRunning) {
            const pidFile = path.join(CONFIG_DIR, 'api.pid');
            const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());
            console.log(`Yerel API sunucusu ${LOCAL_API_PORT} portunda çalışıyor (PID: ${pid})`);
        } else {
            console.log('Yerel API sunucusu çalışmıyor');
        }
    }).catch(err => {
        console.error('API durumu kontrol edilirken hata:', err.message);
    });
}

// Komutlar
const commands = {
    login: async function(argv) {
        // Zaten giriş yapılıp yapılmadığını kontrol et
        if (isLoggedIn() && !argv.force) {
            console.log('Zaten giriş yapmışsınız. Tekrar giriş yapmak için --force kullanın.');
            return;
        }

        try {
            // Sunucu URL'sini al
            const { server } = await inquirer.prompt([
                {
                    type: 'input',
                    name: 'server',
                    message: 'Sunucu URL:',
                    default: getServerUrl()
                }
            ]);

            // Kimlik bilgilerini al
            const { username, password } = await inquirer.prompt([
                {
                    type: 'input',
                    name: 'username',
                    message: 'Kullanıcı adı:'
                },
                {
                    type: 'password',
                    name: 'password',
                    message: 'Şifre:',
                    mask: '*'
                }
            ]);

            // Giriş dene
            const response = await axios.post(`${server}/api/login`, {
                username,
                password
            });

            // Token'ı kaydet
            saveAuthToken(response.data.token, server);

            console.log('Giriş başarılı.');
        } catch (err) {
            console.error('Giriş başarısız:', err.response?.data?.error || err.message);
        }
    },

    logout: async function() {
        if (fs.existsSync(AUTH_FILE)) {
            fs.unlinkSync(AUTH_FILE);
            console.log('Çıkış başarılı.');
        } else {
            console.log('Giriş yapmamışsınız.');
        }
    },

    whoami: async function() {
        if (!isLoggedIn()) {
            console.log('Giriş yapmamışsınız. Önce "vtunnel login" kullanın.');
            return;
        }

        try {
            const api = createApiClient();
            const userResponse = await api.get('/api/user');
            const tunnelsResponse = await api.get('/api/tunnels');

            console.log(`Sunucu: ${getServerUrl()}`);
            console.log(`Kullanıcı adı: ${userResponse.data.username}`);
            console.log(`Admin: ${userResponse.data.is_admin ? 'Evet' : 'Hayır'}`);
            console.log(`Toplam tünel: ${tunnelsResponse.data.length}`);
            console.log(`Aktif tünel: ${tunnelsResponse.data.filter(t => t.status === 'active').length}`);
        } catch (err) {
            console.error('Kullanıcı bilgilerini alırken hata:', err.response?.data?.error || err.message);
        }
    },

    passwd: async function() {
        if (!isLoggedIn()) {
            console.log('Giriş yapmamışsınız. Önce "vtunnel login" kullanın.');
            return;
        }

        try {
            const { currentPassword, newPassword, confirmPassword } = await inquirer.prompt([
                {
                    type: 'password',
                    name: 'currentPassword',
                    message: 'Mevcut şifre:',
                    mask: '*'
                },
                {
                    type: 'password',
                    name: 'newPassword',
                    message: 'Yeni şifre:',
                    mask: '*',
                    validate: (input) => input.length >= 8 ? true : 'Şifre en az 8 karakter olmalı'
                },
                {
                    type: 'password',
                    name: 'confirmPassword',
                    message: 'Yeni şifreyi onaylayın:',
                    mask: '*',
                    validate: (input, answers) => input === answers.newPassword ? true : 'Şifreler eşleşmiyor'
                }
            ]);

            const api = createApiClient();
            await api.post('/api/change-password', {
                currentPassword,
                newPassword
            });

            console.log('Şifre başarıyla değiştirildi. Lütfen tekrar giriş yapın.');

            // Çıkışı zorla
            if (fs.existsSync(AUTH_FILE)) {
                fs.unlinkSync(AUTH_FILE);
            }
        } catch (err) {
            console.error('Şifre değiştirirken hata:', err.response?.data?.error || err.message);
        }
    },

    create: async function(argv) {
        if (!isLoggedIn()) {
            console.log('Giriş yapmamışsınız. Önce "vtunnel login" kullanın.');
            return;
        }

        try {
            let name, host, port;

            if (argv.name && argv.host && argv.port) {
                name = argv.name;
                host = argv.host;
                port = argv.port;
            } else {
                const answers = await inquirer.prompt([
                    {
                        type: 'input',
                        name: 'name',
                        message: 'Tünel adı:',
                        validate: (input) => input.length > 0 ? true : 'İsim gerekli'
                    },
                    {
                        type: 'input',
                        name: 'host',
                        message: 'Hedef host:',
                        default: 'localhost'
                    },
                    {
                        type: 'input',
                        name: 'port',
                        message: 'Hedef port:',
                        validate: (input) => {
                            const port = parseInt(input);
                            return !isNaN(port) && port > 0 && port < 65536 ? true : 'Geçersiz port numarası';
                        },
                        filter: (input) => parseInt(input)
                    }
                ]);

                name = answers.name;
                host = answers.host;
                port = answers.port;
            }

            const api = createApiClient();
            const response = await api.post('/api/tunnels', {
                name,
                host,
                port
            });

            console.log(`Tünel başarıyla oluşturuldu:`);
            console.log(`  İsim: ${response.data.name}`);
            console.log(`  Yerel: ${response.data.host}:${response.data.port}`);
            console.log(`  Sunucu Portu: ${response.data.server_port}`);
            console.log(`  Durum: ${response.data.status}`);
            console.log(`Bu tüneli başlatmak için "vtunnel start" kullanın`);
        } catch (err) {
            console.error('Tünel oluştururken hata:', err.response?.data?.error || err.message);
        }
    },

    start: async function(argv) {
        if (!isLoggedIn()) {
            console.log('Giriş yapmamışsınız. Önce "vtunnel login" kullanın.');
            return;
        }

        try {
            const api = createApiClient();

            // Tünel listesini al
            const tunnelsResponse = await api.get('/api/tunnels');

            // Tüm tüneller (aktif veya değil)
            const allTunnels = tunnelsResponse.data;

            // Yalnızca aktif olmayan tüneller
            const inactiveTunnels = tunnelsResponse.data.filter(t => t.status !== 'active');

            // Hem aktif hem de inaktif tünellerin sayılarını göster
            console.log(`Toplam tünel sayısı: ${allTunnels.length}`);
            console.log(`Aktif tünel sayısı: ${allTunnels.length - inactiveTunnels.length}`);
            console.log(`İnaktif tünel sayısı: ${inactiveTunnels.length}`);

            if (inactiveTunnels.length === 0) {
                console.log('İnaktif tünel bulunamadı. Önce bir tünel oluşturun veya aktif tünelleri durdurun.');
                return;
            }

            let tunnelId;
            let selectedTunnel;

            if (argv.id) {
                tunnelId = argv.id;
                selectedTunnel = allTunnels.find(t => t.id == argv.id);

                if (!selectedTunnel) {
                    console.log(`ID #${argv.id} olan tünel bulunamadı.`);
                    return;
                }

                if (selectedTunnel.status === 'active') {
                    console.log(`ID #${argv.id} olan tünel zaten aktif.`);
                    console.log(`  Tünel: ${selectedTunnel.name}`);
                    console.log(`  Hedef: ${selectedTunnel.host}:${selectedTunnel.port}`);
                    console.log(`  Sunucu portu: ${selectedTunnel.server_port}`);
                    console.log(`  Durum: ${colorizeStatus(selectedTunnel.status)}`);
                    return;
                }
            } else if (argv.name) {
                selectedTunnel = allTunnels.find(t => t.name === argv.name);
                if (!selectedTunnel) {
                    console.log(`"${argv.name}" adında tünel bulunamadı.`);
                    return;
                }

                if (selectedTunnel.status === 'active') {
                    console.log(`"${argv.name}" tüneli zaten aktif.`);
                    console.log(`  Tünel: ${selectedTunnel.name}`);
                    console.log(`  Hedef: ${selectedTunnel.host}:${selectedTunnel.port}`);
                    console.log(`  Sunucu portu: ${selectedTunnel.server_port}`);
                    console.log(`  Durum: ${colorizeStatus(selectedTunnel.status)}`);
                    return;
                }

                tunnelId = selectedTunnel.id;
            } else {
                // Tüm tünelleri görüntülemek için bir tablo oluştur
                const table = new Table({
                    head: ['ID', 'İsim', 'Hedef', 'Sunucu Portu', 'Durum'],
                    style: { head: ['cyan', 'bold'] }
                });

                // Önce aktif tünelleri göster
                const activeTunnelsTable = allTunnels
                    .filter(t => t.status === 'active')
                    .map(t => [
                        t.id,
                        t.name,
                        `${t.host}:${t.port}`,
                        t.server_port,
                        colorizeStatus(t.status)
                    ]);

                // Sonra inaktif tünelleri göster
                const inactiveTunnelsTable = inactiveTunnels.map(t => [
                    t.id,
                    t.name,
                    `${t.host}:${t.port}`,
                    t.server_port,
                    colorizeStatus(t.status)
                ]);

                // Tüm tünelleri tabloya ekle
                [...activeTunnelsTable, ...inactiveTunnelsTable].forEach(row => {
                    table.push(row);
                });

                console.log(table.toString());

                const { tunnelChoice } = await inquirer.prompt([
                    {
                        type: 'list',
                        name: 'tunnelChoice',
                        message: 'Başlatmak için bir tünel seçin:',
                        choices: inactiveTunnels.map(t => ({
                            name: `${t.name} (${t.host}:${t.port}) - Sunucu Portu: ${t.server_port}`,
                            value: t.id
                        }))
                    }
                ]);

                tunnelId = tunnelChoice;
                selectedTunnel = allTunnels.find(t => t.id === tunnelId);
            }

            console.log(`"${selectedTunnel.name}" tüneli başlatılıyor... (Sunucu Portu: ${selectedTunnel.server_port})`);

            // WebSocket bağlantısını sağla
            await ensureWebSocketConnection();

            // Tüneli başlat
            await api.post(`/api/tunnels/${tunnelId}/start`);

            console.log('Tünel başlatma komutu gönderildi. Onay bekleniyor...');

            // Onay bekle ancak 5 saniye sonra devam et
            setTimeout(() => {
                console.log('Tünel aktif oldu. Ctrl+C ile çıkabilirsiniz.');
            }, 5000);
        } catch (err) {
            console.error('Tünel başlatırken hata:', err.response?.data?.error || err.message);
        }
    },

    stop: async function(argv) {
        if (!isLoggedIn()) {
            console.log('Giriş yapmamışsınız. Önce "vtunnel login" kullanın.');
            return;
        }

        try {
            const api = createApiClient();

            // Tünel listesini al
            const tunnelsResponse = await api.get('/api/tunnels');
            const tunnels = tunnelsResponse.data.filter(t => t.status === 'active');

            if (tunnels.length === 0) {
                console.log('Aktif tünel bulunamadı.');
                return;
            }

            let tunnelId;

            if (argv.id) {
                tunnelId = argv.id;
            } else if (argv.name) {
                const tunnel = tunnels.find(t => t.name === argv.name);
                if (!tunnel) {
                    console.log(`"${argv.name}" adında aktif tünel bulunamadı`);
                    return;
                }
                tunnelId = tunnel.id;
            } else {
                // Tünelleri görüntülemek için bir tablo oluştur
                const table = new Table({
                    head: ['ID', 'İsim', 'Hedef', 'Sunucu Portu', 'Durum'],
                    style: { head: ['cyan', 'bold'] }
                });

                tunnels.forEach(t => {
                    table.push([
                        t.id,
                        t.name,
                        `${t.host}:${t.port}`,
                        t.server_port,
                        colorizeStatus(t.status)
                    ]);
                });

                console.log(table.toString());

                const { tunnelChoice } = await inquirer.prompt([
                    {
                        type: 'list',
                        name: 'tunnelChoice',
                        message: 'Durdurmak için bir tünel seçin:',
                        choices: tunnels.map(t => ({
                            name: `${t.name} (${t.host}:${t.port})`,
                            value: t.id
                        }))
                    }
                ]);

                tunnelId = tunnelChoice;
            }

            // Tüneli durdur
            await api.post(`/api/tunnels/${tunnelId}/stop`);

            console.log('Tünel durdurma komutu gönderildi.');

            // Ayrıca aktifse yerel tüneli de durdur
            if (activeTunnels.has(tunnelId)) {
                const tunnel = activeTunnels.get(tunnelId);
                tunnel.proxy.close();
                activeTunnels.delete(tunnelId);
            }
        } catch (err) {
            console.error('Tünel durdururken hata:', err.response?.data?.error || err.message);
        }
    },

    stopall: async function() {
        if (!isLoggedIn()) {
            console.log('Giriş yapmamışsınız. Önce "vtunnel login" kullanın.');
            return;
        }

        try {
            const api = createApiClient();

            // Tünel listesini al
            const tunnelsResponse = await api.get('/api/tunnels');
            const activeTunnelIds = tunnelsResponse.data
                .filter(t => t.status === 'active')
                .map(t => t.id);

            if (activeTunnelIds.length === 0) {
                console.log('Aktif tünel bulunamadı.');
                return;
            }

            // Her tüneli durdur
            for (const tunnelId of activeTunnelIds) {
                await api.post(`/api/tunnels/${tunnelId}/stop`);

                // Ayrıca aktifse yerel tüneli de durdur
                if (activeTunnels.has(tunnelId)) {
                    const tunnel = activeTunnels.get(tunnelId);
                    tunnel.proxy.close();
                    activeTunnels.delete(tunnelId);
                }
            }

            console.log(`${activeTunnelIds.length} tünel durduruldu.`);
        } catch (err) {
            console.error('Tünelleri durdururken hata:', err.response?.data?.error || err.message);
        }
    },

    monitor: async function() {
        if (!isLoggedIn()) {
            console.log('Giriş yapmamışsınız. Önce "vtunnel login" kullanın.');
            return;
        }

        try {
            const api = createApiClient();

            // Tünel listesini al
            const tunnelsResponse = await api.get('/api/tunnels');
            const tunnels = tunnelsResponse.data;

            if (tunnels.length === 0) {
                console.log('Tünel bulunamadı.');
                return;
            }

            // Tünelleri görüntülemek için bir tablo oluştur
            const table = new Table({
                head: ['ID', 'İsim', 'Hedef', 'Sunucu Portu', 'Durum', 'Gelen Trafik', 'Giden Trafik', 'Erişim URL'],
                style: { head: ['cyan', 'bold'] }
            });

            const serverHost = getServerUrl().replace(/^https?:\/\//, '').split(':')[0] || 'localhost';

            tunnels.forEach(t => {
                // Trafik değerlerini kontrol edip güvenli bir şekilde formatlayalım
                const inTraffic = typeof t.traffic_in === 'number' ? formatBytes(t.traffic_in) : '0 B';
                const outTraffic = typeof t.traffic_out === 'number' ? formatBytes(t.traffic_out) : '0 B';

                // Aktif tüneller için erişim URL'i oluştur
                const accessUrl = t.status === 'active' ?
                    `${serverHost}:${t.server_port}` : '-';

                table.push([
                    t.id,
                    t.name,
                    `${t.host}:${t.port}`,
                    t.server_port,
                    colorizeStatus(t.status),
                    inTraffic,
                    outTraffic,
                    t.status === 'active' ? colors.green(accessUrl) : accessUrl
                ]);
            });

            console.log(table.toString());

            // Aktif tüneller için bilgi mesajı
            const activeTunnels = tunnels.filter(t => t.status === 'active');
            if (activeTunnels.length > 0) {
                console.log('\n📋 Aktif Tünel Erişim Bilgileri:');
                activeTunnels.forEach(t => {
                    console.log(`  🚀 ${t.name}: ${serverHost}:${t.server_port} -> ${t.host}:${t.port}`);
                });
                console.log('\n⚠️ Tünele erişemiyorsanız şunları kontrol edin:');
                console.log('  1. Sunucu güvenlik duvarı ayarları (iptables, ufw, firewalld)');
                console.log('  2. Hedef servisin çalıştığından emin olun');
                console.log('  3. Tüneli yeniden başlatmayı deneyin: "vtunnel stop --id ' + activeTunnels[0].id + '" ve sonra "vtunnel start --id ' + activeTunnels[0].id + '"');
            }
        } catch (err) {
            console.error('Tünelleri izlerken hata:', err.response?.data?.error || err.message);
        }
    },

    api: apiCommand
};

// Ana CLI
yargs(hideBin(process.argv))
    .command('login', 'vTunnel sunucusuna giriş yap', (yargs) => {
        return yargs.option('force', {
            describe: 'Zaten giriş yapmış olsan bile girişi zorla',
            type: 'boolean',
            default: false
        });
    }, (argv) => commands.login(argv))
    .command('logout', 'vTunnel sunucusundan çıkış yap', () => commands.logout())
    .command('whoami', 'Mevcut kullanıcı bilgilerini göster', () => commands.whoami())
    .command('passwd', 'Şifre değiştir', () => commands.passwd())
    .command('create', 'Yeni bir tünel oluştur', (yargs) => {
        return yargs
            .option('name', {
                describe: 'Tünel adı',
                type: 'string'
            })
            .option('host', {
                describe: 'Hedef host',
                type: 'string'
            })
            .option('port', {
                describe: 'Hedef port',
                type: 'number'
            });
    }, (argv) => commands.create(argv))
    .command('start', 'Bir tüneli başlat', (yargs) => {
        return yargs
            .option('id', {
                describe: 'Tünel ID',
                type: 'number'
            })
            .option('name', {
                describe: 'Tünel adı',
                type: 'string'
            });
    }, (argv) => commands.start(argv))
    .command('stop', 'Bir tüneli durdur', (yargs) => {
        return yargs
            .option('id', {
                describe: 'Tünel ID',
                type: 'number'
            })
            .option('name', {
                describe: 'Tünel adı',
                type: 'string'
            });
    }, (argv) => commands.stop(argv))
    .command('stopall', 'Tüm aktif tünelleri durdur', () => commands.stopall())
    .command('monitor', 'Tünelleri izle', () => commands.monitor())
    .command('list-active', 'Kayıtlı aktif tünelleri listele', () => {
        const savedTunnels = loadActiveTunnels();

        if (Object.keys(savedTunnels).length === 0) {
            console.log('Kayıtlı aktif tünel yok.');
            return;
        }

        const table = new Table({
            head: ['ID', 'İsim', 'Hedef', 'Sunucu Portu', 'Yerel Port'],
            style: { head: ['cyan', 'bold'] }
        });

        for (const [tunnelId, tunnel] of Object.entries(savedTunnels)) {
            table.push([
                tunnelId,
                tunnel.name,
                `${tunnel.host}:${tunnel.port}`,
                tunnel.serverPort,
                tunnel.localPort || 'N/A'
            ]);
        }

        console.log(table.toString());
    })
    .command('restore', 'Kayıtlı aktif tünelleri yeniden başlat', async () => {
        await restoreActiveTunnels();
    })
    .command('daemon', 'Tünel daemon\'unu başlat', () => {
        console.log('vTunnel daemon başlatılıyor...');
        restoreActiveTunnels();

        // Daemon modunda çalışırken
        const checkInterval = setInterval(async () => {
            if (!isLoggedIn()) {
                console.log('Oturum sonlandırılmış, daemon kapatılıyor.');
                clearInterval(checkInterval);
                process.exit(0);
            }

            // WebSocket bağlantısını kontrol et ve gerekirse yeniden bağlan
            if (!webSocketClient || webSocketClient.readyState !== WebSocket.OPEN) {
                try {
                    await ensureWebSocketConnection();
                    console.log('WebSocket bağlantısı yeniden kuruldu.');
                } catch (err) {
                    console.error('WebSocket bağlantısı kurulamadı:', err.message);
                }
            }
        }, 60000); // Her dakika kontrol et

        console.log('vTunnel daemon başlatıldı ve hazır. (Çıkmak için Ctrl+C)');
    })
    .command('api', 'Yerel API sunucusunu yönet', (yargs) => {
        return yargs
            .option('start', {
                describe: 'Yerel API sunucusunu başlat',
                type: 'boolean'
            })
            .option('stop', {
                describe: 'Yerel API sunucusunu durdur',
                type: 'boolean'
            })
            .option('status', {
                describe: 'Yerel API sunucusu durumunu kontrol et',
                type: 'boolean'
            })
            .option('background', {
                describe: 'API sunucusunu arka planda çalıştır',
                type: 'boolean',
                alias: 'b'
            })
            .option('daemon', {
                describe: 'API sunucusunu daemon olarak çalıştır (--background ile aynı)',
                type: 'boolean',
                alias: 'd'
            });
    }, (argv) => commands.api(argv))
    .demandCommand(1, 'Bir komut belirtmeniz gerekir')
    .help()
    .argv;

// Düzgün kapatmayı işle
process.on('SIGINT', async () => {
    console.log('Kapatılıyor...');

    // WebSocket bağlantısını kapat
    if (webSocketClient && webSocketClient.readyState === WebSocket.OPEN) {
        webSocketClient.close();
    }

    // Tüm aktif tünelleri kapat
    for (const tunnel of activeTunnels.values()) {
        tunnel.proxy.close();
    }

    // Yerel API sunucusunu kapat
    if (localApiServer) {
        localApiServer.close();
    }

    process.exit(0);
});
