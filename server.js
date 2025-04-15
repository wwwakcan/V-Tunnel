#!/usr/bin/env node
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const inquirer = require('inquirer');
const net = require('net');
const os = require('os');
const { v4: uuidv4 } = require('uuid');

// Sabitler
const API_PORT = 9013;
const TUNNEL_PORT_RANGE = { min: 5120, max: 5220 };
const CONFIG_DIR = path.join(os.homedir(), '.vtunnel');
const SERVER_CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const DB_CONFIG_FILE = path.join(CONFIG_DIR, 'database.json');

// Ana şifreleme anahtarı - bu sabit kalabilir, şifrelenmiş verileri korumak için kullanılacak
const MASTER_KEY = crypto.scryptSync(os.hostname() + os.userInfo().username, 'vtunnel-salt', 32);
const MASTER_IV = crypto.randomBytes(16);

// Bu değişkenler başlangıçta boş, initializeServerConfig fonksiyonunda doldurulacak
let JWT_SECRET;
let AES_KEY;
let AES_IV;

// Yapılandırma dizininin varlığını kontrol et
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

// Express ve WebSocket sunucusunu başlat
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());

// Aktif istemciler ve tüneller için depolama
const activeClients = new Map();
const activeTunnels = new Map();

// Veritabanı bağlantısı
let pool;


// Aktif tünellerin yönetimi için yardımcı fonksiyonlar

// Tünel proxy'si oluştur ve kaydet (düzeltilmiş versiyon)
async function createAndSaveTunnelProxy(tunnelId, serverPort, targetHost, targetPort) {
    console.log(`[Proxy] Tünel #${tunnelId} için proxy oluşturuluyor: ${serverPort} => ${targetHost}:${targetPort}`);

    try {
        // Önce tüm proxy'leri kontrol et ve aynı tunnelId veya port varsa temizle
        cleanupOldProxies(tunnelId, serverPort);

        // Yeni proxy oluştur
        const proxy = await createTunnelProxy(tunnelId, serverPort, targetHost, targetPort);

        if (proxy) {
            const proxyKey = `${tunnelId}:${serverPort}`;
            activeTunnels.set(proxyKey, proxy);
            console.log(`[Proxy] Tünel proxy'si başarıyla oluşturuldu ve kaydedildi: ${proxyKey}`);
            console.log(`[Proxy] Aktif tüneller: ${Array.from(activeTunnels.keys()).join(', ')}`);
            return true;
        } else {
            console.error(`[Proxy] Tünel #${tunnelId} için proxy oluşturulamadı`);
            return false;
        }
    } catch (err) {
        console.error(`[Proxy] Proxy oluşturma ve kaydetme hatası: ${err.message}`);
        return false;
    }
}

// Varolan eski proxy'leri temizleme fonksiyonu
function cleanupOldProxies(tunnelId, serverPort) {
    const tunnelProxyKey = `${tunnelId}:${serverPort}`;

    // Tüm proxy'leri kontrol et
    for (const [key, proxy] of activeTunnels.entries()) {
        // Aynı tünel ID'si veya aynı portu kullanan proxy varsa temizle
        if (key.startsWith(`${tunnelId}:`) || key.endsWith(`:${serverPort}`)) {
            console.log(`[Proxy] Eski proxy temizleniyor: ${key}`);
            try {
                proxy.close();
            } catch (e) {
                console.error(`[Proxy] Eski proxy kapatılırken hata: ${e.message}`);
            }
            activeTunnels.delete(key);
        }
    }
}

// Tünel proxy'sini kapat ve sil
function closeTunnelProxy(tunnelId, serverPort) {
    const proxyKey = `${tunnelId}:${serverPort}`;

    if (activeTunnels.has(proxyKey)) {
        try {
            const proxy = activeTunnels.get(proxyKey);
            proxy.close();
            activeTunnels.delete(proxyKey);
            console.log(`[Proxy] Tünel proxy'si kapatıldı: ${proxyKey}`);
            console.log(`[Proxy] Kalan aktif tüneller: ${Array.from(activeTunnels.keys()).join(', ') || 'Yok'}`);
            return true;
        } catch (err) {
            console.error(`[Proxy] Proxy kapatılırken hata: ${err.message}`);
            activeTunnels.delete(proxyKey); // Hata olsa bile kaydı temizle
            return false;
        }
    } else {
        // Alternatif proxyKey formatlarını kontrol et
        let found = false;
        for (const [key, proxy] of activeTunnels.entries()) {
            if (key.startsWith(`${tunnelId}:`) || key.endsWith(`:${serverPort}`)) {
                try {
                    proxy.close();
                    activeTunnels.delete(key);
                    console.log(`[Proxy] Alternatif eşleşme ile tünel proxy'si kapatıldı: ${key}`);
                    found = true;
                } catch (e) {
                    console.error(`[Proxy] Alternatif proxy kapatılırken hata: ${e.message}`);
                    activeTunnels.delete(key); // Hata olsa bile kaydı temizle
                }
            }
        }

        if (!found) {
            console.log(`[Proxy] Tünel #${tunnelId} için aktif proxy bulunamadı: ${proxyKey}`);
        }

        return found;
    }
}


// Sunucu yapılandırmasını oluştur veya oku
async function initializeServerConfig() {
    try {
        if (fs.existsSync(SERVER_CONFIG_FILE)) {
            // Mevcut yapılandırmayı oku
            const encryptedConfig = JSON.parse(fs.readFileSync(SERVER_CONFIG_FILE, 'utf8'));

            // Şifrelenmiş yapılandırmayı çöz
            const config = decryptWithMasterKey(encryptedConfig);

            // Değişkenleri ayarla
            JWT_SECRET = config.jwtSecret;
            AES_KEY = Buffer.from(config.aesKey, 'hex');
            AES_IV = Buffer.from(config.aesIv, 'hex');

            console.log('Sunucu yapılandırması başarıyla yüklendi.');
            return true;
        } else {
            // İlk kurulum - yeni yapılandırma oluştur
            console.log('Sunucu ilk kez başlatılıyor, yapılandırma oluşturuluyor...');

            // Yeni anahtarlar oluştur
            JWT_SECRET = crypto.randomBytes(64).toString('hex');
            AES_KEY = crypto.randomBytes(32);
            AES_IV = crypto.randomBytes(16);

            // Yapılandırmayı kaydet
            const config = {
                jwtSecret: JWT_SECRET,
                aesKey: AES_KEY.toString('hex'),
                aesIv: AES_IV.toString('hex'),
                createdAt: new Date().toISOString()
            };

            // Yapılandırmayı şifrele ve kaydet
            const encryptedConfig = encryptWithMasterKey(config);
            fs.writeFileSync(SERVER_CONFIG_FILE, JSON.stringify(encryptedConfig));

            console.log('Sunucu yapılandırması oluşturuldu ve kaydedildi.');
            return true;
        }
    } catch (err) {
        console.error('Sunucu yapılandırması oluşturulurken veya okunurken hata:', err);
        return false;
    }
}

// Ana şifreleme anahtarı ile veri şifrele
function encryptWithMasterKey(data) {
    const cipher = crypto.createCipheriv('aes-256-cbc', MASTER_KEY, MASTER_IV);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        encrypted,
        iv: MASTER_IV.toString('hex')
    };
}

// Ana şifreleme anahtarı ile şifrelenmiş veriyi çöz
function decryptWithMasterKey(encryptedData) {
    const decipher = crypto.createDecipheriv(
        'aes-256-cbc',
        MASTER_KEY,
        Buffer.from(encryptedData.iv, 'hex')
    );
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

// Verileri şifrelemek için fonksiyon
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

// Şifrelenmiş verileri çözmek için fonksiyon
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

// JWT Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ error: 'Kimlik doğrulama gerekli' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Geçersiz veya süresi dolmuş token' });
        req.user = user;
        next();
    });
}

// Veritabanı tablolarını kur
async function setupDatabase(pool) {
    try {
        // Kullanıcılar tablosunu oluştur
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(100) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Tüneller tablosunu oluştur
        await pool.query(`
            CREATE TABLE IF NOT EXISTS tunnels (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                name VARCHAR(50) NOT NULL,
                host VARCHAR(100) NOT NULL,
                port INTEGER NOT NULL,
                server_port INTEGER NOT NULL,
                client_name VARCHAR(100),
                client_ip VARCHAR(50),
                client_os VARCHAR(100),
                traffic_in BIGINT DEFAULT 0,
                traffic_out BIGINT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(20) DEFAULT 'inactive'
            )
        `);

        // İstatistikler tablosunu oluştur
        await pool.query(`
            CREATE TABLE IF NOT EXISTS statistics (
                id SERIAL PRIMARY KEY,
                tunnel_id INTEGER REFERENCES tunnels(id),
                visitor_ip VARCHAR(50),
                visitor_url VARCHAR(255),
                method VARCHAR(20),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Veritabanı kurulumu başarıyla tamamlandı.');
    } catch (err) {
        console.error('Veritabanı kurulumunda hata:', err);
        process.exit(1);
    }
}

// Veritabanı bağlantısını başlat
async function initializeDatabase() {
    // Veritabanı yapılandırmasının var olup olmadığını kontrol et
    if (fs.existsSync(DB_CONFIG_FILE)) {
        try {
            const encryptedData = JSON.parse(fs.readFileSync(DB_CONFIG_FILE, 'utf8'));
            const dbConfig = decryptData(encryptedData);
            pool = new Pool(dbConfig);

            // Bağlantıyı test et
            await pool.query('SELECT NOW()');
            console.log('Veritabanı bağlantısı başarılı.');

            // Tabloları kur
            await setupDatabase(pool);

            // Admin kullanıcısının var olup olmadığını kontrol et
            const adminResult = await pool.query('SELECT * FROM users WHERE is_admin = true LIMIT 1');
            if (adminResult.rows.length === 0) {
                await createAdminUser();
            }

            return true;
        } catch (err) {
            console.error('Veritabanına bağlanırken hata:', err);
            return false;
        }
    } else {
        // Veritabanı yapılandırması için istem göster
        console.log('İlk kez kurulum: Lütfen PostgreSQL veritabanı bağlantı bilgilerini sağlayın.');
        const dbConfig = await promptDatabaseConfig();

        try {
            pool = new Pool(dbConfig);

            // Bağlantıyı test et
            await pool.query('SELECT NOW()');
            console.log('Veritabanı bağlantısı başarılı.');

            // Şifrelenmiş yapılandırmayı kaydet
            const encryptedConfig = encryptData(dbConfig);
            fs.writeFileSync(DB_CONFIG_FILE, JSON.stringify(encryptedConfig));

            // Tabloları kur
            await setupDatabase(pool);

            // Admin kullanıcısı oluştur
            await createAdminUser();

            return true;
        } catch (err) {
            console.error('Veritabanına bağlanırken hata:', err);
            return false;
        }
    }
}

// Veritabanı yapılandırması için istem
async function promptDatabaseConfig() {
    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'host',
            message: 'Veritabanı sunucusu:',
            default: 'localhost'
        },
        {
            type: 'input',
            name: 'port',
            message: 'Veritabanı portu:',
            default: '5432'
        },
        {
            type: 'input',
            name: 'database',
            message: 'Veritabanı adı:',
            default: 'vtunnel'
        },
        {
            type: 'input',
            name: 'user',
            message: 'Veritabanı kullanıcısı:',
            default: 'postgres'
        },
        {
            type: 'password',
            name: 'password',
            message: 'Veritabanı şifresi:',
            mask: '*'
        }
    ]);

    return {
        host: answers.host,
        port: parseInt(answers.port),
        database: answers.database,
        user: answers.user,
        password: answers.password
    };
}

// Admin kullanıcısı oluştur
async function createAdminUser() {
    console.log('Admin kullanıcısı oluşturuluyor...');

    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'username',
            message: 'Admin kullanıcı adı:',
            validate: (input) => input.length >= 3 ? true : 'Kullanıcı adı en az 3 karakter olmalı'
        },
        {
            type: 'password',
            name: 'password',
            message: 'Admin şifresi:',
            mask: '*',
            validate: (input) => input.length >= 8 ? true : 'Şifre en az 8 karakter olmalı'
        },
        {
            type: 'password',
            name: 'confirmPassword',
            message: 'Şifreyi onaylayın:',
            mask: '*',
            validate: (input, answers) => input === answers.password ? true : 'Şifreler eşleşmiyor'
        }
    ]);

    const hashedPassword = await bcrypt.hash(answers.password, 10);

    await pool.query(
        'INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)',
        [answers.username, hashedPassword, true]
    );

    console.log(`Admin kullanıcısı '${answers.username}' başarıyla oluşturuldu.`);
}

// Aralıkta kullanılabilir port bul
async function findAvailablePort() {
    try {
        // Tüm tünellerin portlarını al (aktif veya değil)
        const result = await pool.query(
            'SELECT server_port FROM tunnels'
        );

        const usedPorts = result.rows.map(row => row.server_port);

        // Port aralığında kullanılmayan bir port bul
        for (let port = TUNNEL_PORT_RANGE.min; port <= TUNNEL_PORT_RANGE.max; port++) {
            if (!usedPorts.includes(port)) {
                // Ayrıca sistemde bu portun gerçekten kullanılmadığından emin ol
                try {
                    const testServer = net.createServer();

                    await new Promise((resolve, reject) => {
                        testServer.once('error', (err) => {
                            testServer.close();
                            if (err.code === 'EADDRINUSE') {
                                // Port zaten kullanımda, bir sonrakini dene
                                reject(new Error('Port zaten kullanımda'));
                            } else {
                                reject(err);
                            }
                        });

                        testServer.once('listening', () => {
                            testServer.close();
                            resolve();
                        });

                        testServer.listen(port);
                    });

                    console.log(`Kullanılabilir port bulundu: ${port}`);
                    return port;
                } catch (err) {
                    // Bu port kullanılamaz, sonraki porta geç
                    console.log(`Port ${port} kullanılamaz: ${err.message}`);
                    continue;
                }
            }
        }

        throw new Error('Aralıkta kullanılabilir port yok');
    } catch (err) {
        console.error(`Port bulunurken hata: ${err.message}`);
        throw err;
    }
}

// Tünel proxy'si oluştur
function createTunnelProxy(tunnelId, serverPort, targetHost, targetPort) {
    console.log(`[Proxy] Tünel #${tunnelId} için proxy oluşturuluyor: ${serverPort} => ${targetHost}:${targetPort}`);

    // Port kullanımda mı kontrol et
    try {
        const testServer = net.createServer();

        // Asenkron bir şekilde port kontrolü yap
        return new Promise((resolve, reject) => {
            testServer.once('error', (err) => {
                testServer.close();
                if (err.code === 'EADDRINUSE') {
                    console.error(`[Proxy] Port ${serverPort} zaten kullanımda!`);
                    // Port kullanımda hatası, null döndür
                    resolve(null);
                } else {
                    console.error(`[Proxy] Port kontrol hatası: ${err.message}`);
                    resolve(null);
                }
            });

            testServer.once('listening', () => {
                testServer.close(() => {
                    // Port kullanılabilir, proxy oluştur
                    const proxy = createProxyServer();
                    resolve(proxy);
                });
            });

            testServer.listen(serverPort);
        });
    } catch (err) {
        console.error(`[Proxy] Port kontrolü sırasında hata: ${err.message}`);
        return null;
    }

    // Asıl proxy sunucusunu oluştur
    function createProxyServer() {
        const proxy = net.createServer(async (socket) => {
            // Bağlantı istatistiklerini kaydet
            const clientIp = socket.remoteAddress ? socket.remoteAddress.replace(/^::ffff:/, '') : 'unknown';

            console.log(`[Proxy] Yeni bağlantı: ${clientIp} -> Tünel #${tunnelId} (${targetHost}:${targetPort})`);

            try {
                await pool.query(
                    'INSERT INTO statistics (tunnel_id, visitor_ip, visitor_url, method) VALUES ($1, $2, $3, $4)',
                    [tunnelId, clientIp, 'direct-tcp', 'CONNECT']
                );
            } catch (err) {
                console.error(`[Proxy] İstatistik kaydederken hata: ${err.message}`);
            }

            // Hedefe bağlan
            let targetSocket;
            try {
                targetSocket = net.createConnection({
                    host: targetHost,
                    port: targetPort
                });

                targetSocket.on('connect', () => {
                    console.log(`[Proxy] Hedef bağlantısı başarılı: ${targetHost}:${targetPort}`);
                });
            } catch (err) {
                console.error(`[Proxy] Hedef bağlantısı hatası: ${err.message}`);
                socket.end();
                return;
            }

            let inBytes = 0;
            let outBytes = 0;

            // İstemciden hedefe veri akışını işle
            socket.on('data', (data) => {
                try {
                    inBytes += data.length;
                    targetSocket.write(data);
                } catch (err) {
                    console.error(`[Proxy] Veri gönderirken hata: ${err.message}`);
                }
            });

            // Hedeften istemciye veri akışını işle
            targetSocket.on('data', (data) => {
                try {
                    outBytes += data.length;
                    socket.write(data);
                } catch (err) {
                    console.error(`[Proxy] Veri alırken hata: ${err.message}`);
                }
            });

            // Bağlantı kapanmasını işle
            socket.on('close', async () => {
                console.log(`[Proxy] İstemci bağlantısı kapandı, tünel #${tunnelId}, trafik: in=${inBytes}, out=${outBytes}`);

                try {
                    targetSocket.end();
                } catch (err) {
                    // Zaten kapanmış olabilir, yoksay
                }

                // Trafik sayaçlarını güncelle
                try {
                    await pool.query(
                        'UPDATE tunnels SET traffic_in = traffic_in + $1, traffic_out = traffic_out + $2 WHERE id = $3',
                        [inBytes, outBytes, tunnelId]
                    );
                    console.log(`[Proxy] Tünel #${tunnelId} trafik güncellendi`);
                } catch (err) {
                    console.error(`[Proxy] Trafik güncellenirken hata: ${err.message}`);
                }
            });

            // Hedef bağlantı kapanmasını işle
            targetSocket.on('close', () => {
                console.log(`[Proxy] Hedef bağlantısı kapandı: ${targetHost}:${targetPort}`);
                try {
                    socket.end();
                } catch (err) {
                    // Zaten kapanmış olabilir, yoksay
                }
            });

            // Hataları işle
            socket.on('error', (err) => {
                console.error(`[Proxy] İstemci soketi hatası: ${err.message}`);
                try {
                    targetSocket.end();
                } catch (e) {
                    // Yoksay
                }
            });

            targetSocket.on('error', (err) => {
                console.error(`[Proxy] Hedef soketi hatası: ${err.message}`);
                try {
                    socket.end();
                } catch (e) {
                    // Yoksay
                }
            });
        });

        proxy.on('listening', () => {
            console.log(`[Proxy] Tünel #${tunnelId} proxy'si dinlemeye başladı: ${serverPort}`);
        });

        proxy.on('error', (err) => {
            console.error(`[Proxy] Tünel #${tunnelId} proxy'sinde hata: ${err.message}`);

            // Port zaten kullanılıyor olabilir
            if (err.code === 'EADDRINUSE') {
                console.log(`[Proxy] Port ${serverPort} zaten kullanımda, proxy başlatılamadı`);

                // Tüneli error durumuna getir
                pool.query(
                    'UPDATE tunnels SET status = $1 WHERE id = $2',
                    ['error', tunnelId]
                ).catch(e => console.error(`Durum güncellenirken hata: ${e.message}`));
            }
        });

        try {
            proxy.listen(serverPort, () => {
                console.log(`[Proxy] Tünel proxy'si ${serverPort} portunda dinliyor`);
            });
        } catch (err) {
            console.error(`[Proxy] Proxy başlatılırken hata: ${err.message}`);
            return null;
        }

        return proxy;
    }
}

// API Rotaları
// Giriş rotası
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
        }

        const user = result.rows[0];

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, is_admin: user.is_admin },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// Şifre değiştirme rotası
app.post('/api/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id;

        const result = await pool.query(
            'SELECT password FROM users WHERE id = $1',
            [userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        }

        const validPassword = await bcrypt.compare(currentPassword, result.rows[0].password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Mevcut şifre yanlış' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query(
            'UPDATE users SET password = $1 WHERE id = $2',
            [hashedPassword, userId]
        );

        res.json({ message: 'Şifre başarıyla değiştirildi' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// Kullanıcı bilgisi rotası
app.get('/api/user', authenticateToken, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username,
        is_admin: req.user.is_admin
    });
});

// Tünel oluşturma rotası
app.post('/api/tunnels', authenticateToken, async (req, res) => {
    try {
        const { name, host, port } = req.body;
        const userId = req.user.id;

        // Bu kullanıcı için tünel adının zaten var olup olmadığını kontrol et
        const existingTunnel = await pool.query(
            'SELECT * FROM tunnels WHERE user_id = $1 AND name = $2',
            [userId, name]
        );

        if (existingTunnel.rows.length > 0) {
            return res.status(400).json({ error: 'Tünel adı zaten mevcut' });
        }

        // Kullanılabilir sunucu portu bul
        const serverPort = await findAvailablePort();

        console.log(`"${name}" tüneli için ${serverPort} portu atandı`);

        // Tünel oluştur
        const result = await pool.query(
            `INSERT INTO tunnels
                 (user_id, name, host, port, server_port, status)
             VALUES ($1, $2, $3, $4, $5, $6)
                 RETURNING id`,
            [userId, name, host, port, serverPort, 'inactive']
        );

        const tunnelId = result.rows[0].id;

        // Teyit amaçlı tünel bilgilerini tekrar çek
        const createdTunnel = await pool.query(
            'SELECT * FROM tunnels WHERE id = $1',
            [tunnelId]
        );

        if (createdTunnel.rows.length === 0) {
            return res.status(500).json({ error: 'Tünel oluşturuldu ancak bilgileri alınamadı' });
        }

        const tunnelInfo = createdTunnel.rows[0];

        res.status(201).json({
            id: tunnelInfo.id,
            name: tunnelInfo.name,
            host: tunnelInfo.host,
            port: tunnelInfo.port,
            server_port: tunnelInfo.server_port,
            status: tunnelInfo.status
        });
    } catch (err) {
        console.error('Tünel oluştururken hata:', err);
        res.status(500).json({ error: err.message });
    }
});

// Tünel listesi rotası
app.get('/api/tunnels', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // Admin ise tüm tünelleri görebilir
        let query;
        let params;

        if (req.user.is_admin && req.query.all === 'true') {
            query = `
                SELECT t.*, u.username
                FROM tunnels t
                         JOIN users u ON t.user_id = u.id
                ORDER BY t.created_at DESC
            `;
            params = [];
        } else {
            query = `
                SELECT * FROM tunnels
                WHERE user_id = $1
                ORDER BY created_at DESC
            `;
            params = [userId];
        }

        const result = await pool.query(query, params);

        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// Tünel detayları rotası
app.get('/api/tunnels/:id', authenticateToken, async (req, res) => {
    try {
        const tunnelId = req.params.id;
        const userId = req.user.id;

        let query;
        let params;

        if (req.user.is_admin) {
            query = `
                SELECT t.*, u.username
                FROM tunnels t
                         JOIN users u ON t.user_id = u.id
                WHERE t.id = $1
            `;
            params = [tunnelId];
        } else {
            query = `
                SELECT * FROM tunnels
                WHERE id = $1 AND user_id = $2
            `;
            params = [tunnelId, userId];
        }

        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Tünel bulunamadı' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// Tünel başlatma rotası
app.post('/api/tunnels/:id/start', authenticateToken, async (req, res) => {
    try {
        const tunnelId = req.params.id;
        const userId = req.user.id;

        // Tünelin var olup olmadığını ve kullanıcıya ait olup olmadığını kontrol et (veya kullanıcı admin mi)
        let query;
        let params;

        if (req.user.is_admin) {
            query = 'SELECT * FROM tunnels WHERE id = $1';
            params = [tunnelId];
        } else {
            query = 'SELECT * FROM tunnels WHERE id = $1 AND user_id = $2';
            params = [tunnelId, userId];
        }

        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Tünel bulunamadı' });
        }

        const tunnel = result.rows[0];

        // Tünelin durumunu kontrol et ve gerekirse temizle
        if (tunnel.status !== 'inactive') {
            console.log(`Tünel #${tunnelId} durumu '${tunnel.status}' - durumu sıfırlanıyor...`);

            // Proxy varsa durdur
            const proxyKey = `${tunnel.id}:${tunnel.server_port}`;
            if (activeTunnels.has(proxyKey)) {
                console.log(`Önceki proxy kapatılıyor: ${proxyKey}`);
                const proxy = activeTunnels.get(proxyKey);
                proxy.close();
                activeTunnels.delete(proxyKey);
            }

            // Durumu inactive olarak güncelle
            await pool.query(
                'UPDATE tunnels SET status = $1 WHERE id = $2',
                ['inactive', tunnelId]
            );

            // Tünel durumunu yenile
            tunnel.status = 'inactive';
            console.log(`Tünel #${tunnelId} durumu 'inactive' olarak sıfırlandı`);
        }

        // Durumu güncelle - başlatılıyor olarak işaretle
        await pool.query(
            'UPDATE tunnels SET status = $1 WHERE id = $2',
            ['starting', tunnelId]
        );

        console.log(`Tünel #${tunnelId} başlatılıyor...`);

        // Bu kullanıcı için istemci bul
        const userClientId = Array.from(activeClients.keys()).find(clientId => {
            const client = activeClients.get(clientId);
            return client.userId === tunnel.user_id;
        });

        if (!userClientId) {
            console.log(`Tünel #${tunnelId} için aktif istemci bulunamadı`);

            // Durumu güncelleyerek hatayı işaretle
            await pool.query(
                'UPDATE tunnels SET status = $1 WHERE id = $2',
                ['error', tunnelId]
            );

            return res.status(400).json({ error: 'Bu tünel için aktif istemci bulunamadı' });
        }

        const clientWs = activeClients.get(userClientId).ws;

        // İstemciye başlatma komutu gönder
        const startMessage = {
            type: 'startTunnel',
            tunnelId: tunnel.id,
            name: tunnel.name,
            host: tunnel.host,
            port: tunnel.port,
            serverPort: tunnel.server_port
        };

        console.log(`Tünel #${tunnelId} başlatma komutu istemciye gönderiliyor:`, startMessage);

        try {
            clientWs.send(JSON.stringify(startMessage));

            // Timeout ekle - istemci yanıt vermezse
            setTimeout(async () => {
                // Mevcut durumu kontrol et
                const currentStatus = await pool.query(
                    'SELECT status FROM tunnels WHERE id = $1',
                    [tunnelId]
                );

                if (currentStatus.rows.length > 0 && currentStatus.rows[0].status === 'starting') {
                    console.log(`Tünel #${tunnelId} başlatma zaman aşımı, durumu 'error' olarak güncelleniyor`);

                    await pool.query(
                        'UPDATE tunnels SET status = $1 WHERE id = $2',
                        ['error', tunnelId]
                    );
                }
            }, 10000); // 10 saniye bekleme süresi

        } catch (err) {
            console.error(`İstemciye başlatma komutu gönderirken hata: ${err.message}`);

            // Hata durumunda durumu güncelle
            await pool.query(
                'UPDATE tunnels SET status = $1 WHERE id = $2',
                ['error', tunnelId]
            );

            return res.status(500).json({ error: 'İstemciye komut gönderirken hata: ' + err.message });
        }

        res.json({
            message: 'Tünel başlatma komutu gönderildi',
            tunnel: {
                id: tunnel.id,
                name: tunnel.name,
                host: tunnel.host,
                port: tunnel.port,
                server_port: tunnel.server_port,
                status: 'starting'
            }
        });
    } catch (err) {
        console.error('Tünel başlatırken hata:', err);
        res.status(500).json({ error: 'Sunucu hatası: ' + err.message });
    }
});

// Tünel durdurma rotası
// Tünel durdurma rotası - Düzeltilmiş versiyon
app.post('/api/tunnels/:id/stop', authenticateToken, async (req, res) => {
    try {
        const tunnelId = req.params.id;
        const userId = req.user.id;

        console.log(`Tünel durdurma isteği alındı: Tünel ID #${tunnelId}, Kullanıcı ID #${userId}`);

        // Tünelin var olup olmadığını ve kullanıcıya ait olup olmadığını kontrol et
        let query;
        let params;

        if (req.user.is_admin) {
            query = 'SELECT * FROM tunnels WHERE id = $1';
            params = [tunnelId];
        } else {
            query = 'SELECT * FROM tunnels WHERE id = $1 AND user_id = $2';
            params = [tunnelId, userId];
        }

        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            console.log(`Tünel #${tunnelId} bulunamadı veya kullanıcıya ait değil`);
            return res.status(404).json({ error: 'Tünel bulunamadı' });
        }

        const tunnel = result.rows[0];
        console.log(`Tünel bulundu: ID #${tunnelId}, ad: ${tunnel.name}, durum: ${tunnel.status}`);

        // Tünelin aktif olup olmadığını kontrol et
        if (tunnel.status !== 'active') {
            console.log(`Tünel #${tunnelId} aktif değil, durumu: ${tunnel.status}`);

            // Aktif değilse ve hatalı bir durumda ise, durumu düzelt
            if (tunnel.status === 'starting' || tunnel.status === 'error' || tunnel.status === 'stopping') {
                await pool.query(
                    'UPDATE tunnels SET status = $1 WHERE id = $2',
                    ['inactive', tunnelId]
                );
                console.log(`Tünel #${tunnelId} durumu inactive olarak düzeltildi`);
            }

            return res.status(200).json({
                message: 'Tünel zaten aktif değil, durum düzeltildi',
                tunnel: {...tunnel, status: 'inactive'}
            });
        }

        // Durumu güncelle - durdurma süreci başlıyor
        await pool.query(
            'UPDATE tunnels SET status = $1 WHERE id = $2',
            ['stopping', tunnelId]
        );

        console.log(`Tünel #${tunnelId} durduruluyor...`);

        // Doğru proxy anahtarını tanımla
        const proxyKey = `${tunnel.id}:${tunnel.server_port}`;
        console.log(`Aranacak proxy anahtarı: ${proxyKey}`);

        // Tüm aktif tünelleri liste olarak logla
        console.log(`Aktif tüneller: ${Array.from(activeTunnels.keys()).join(', ') || 'Yok'}`);

        // Proxy varsa durdur
        if (activeTunnels.has(proxyKey)) {
            const proxy = activeTunnels.get(proxyKey);
            try {
                proxy.close();
                console.log(`Tünel #${tunnelId} proxy'si kapatıldı: ${proxyKey}`);
            } catch (e) {
                console.error(`Proxy kapatılırken hata: ${e.message}`);
            }
            activeTunnels.delete(proxyKey);
        } else {
            console.log(`Tünel #${tunnelId} için aktif proxy bulunamadı: ${proxyKey}`);
        }

        // Bu kullanıcı için istemci bul
        const userClientId = Array.from(activeClients.keys()).find(clientId => {
            const client = activeClients.get(clientId);
            return client.userId === tunnel.user_id;
        });

        if (userClientId) {
            const clientWs = activeClients.get(userClientId).ws;
            console.log(`Tünel #${tunnelId} için istemci bulundu: ${userClientId}`);

            // İstemciye durdurma komutu gönder
            const stopMessage = {
                type: 'stopTunnel',
                tunnelId: parseInt(tunnelId)  // ID'nin sayı olarak gönderildiğinden emin ol
            };

            console.log(`Tünel #${tunnelId} durdurma komutu istemciye gönderiliyor:`, JSON.stringify(stopMessage));

            try {
                clientWs.send(JSON.stringify(stopMessage));

                // İstemci cevabı için bir süre bekle, sonra durumu güncelle
                setTimeout(async () => {
                    // Mevcut durumu kontrol et, hala stopping ise inactive yap
                    const currentStatus = await pool.query(
                        'SELECT status FROM tunnels WHERE id = $1',
                        [tunnelId]
                    );

                    if (currentStatus.rows.length > 0 && currentStatus.rows[0].status === 'stopping') {
                        await pool.query(
                            'UPDATE tunnels SET status = $1 WHERE id = $2',
                            ['inactive', tunnelId]
                        );
                        console.log(`Tünel #${tunnelId} durumu inactive olarak güncellendi (timeout)`);
                    }
                }, 5000); // 5 saniye bekle

            } catch (err) {
                console.error(`İstemciye mesaj gönderirken hata: ${err.message}`);
                // WebSocket hatası durumunda durumu inactive olarak ayarla
                await pool.query(
                    'UPDATE tunnels SET status = $1 WHERE id = $2',
                    ['inactive', tunnelId]
                );
            }
        } else {
            console.log(`Tünel #${tunnelId} için istemci bulunamadı, doğrudan durdurulacak`);

            // İstemci yoksa doğrudan inactive yap
            await pool.query(
                'UPDATE tunnels SET status = $1 WHERE id = $2',
                ['inactive', tunnelId]
            );

            console.log(`Tünel #${tunnelId} durumu inactive olarak güncellendi (istemci yok)`);
        }

        res.json({
            message: 'Tünel durdurma işlemi başlatıldı',
            tunnel: {
                id: tunnel.id,
                name: tunnel.name,
                host: tunnel.host,
                port: tunnel.port,
                server_port: tunnel.server_port,
                status: 'stopping'
            }
        });
    } catch (err) {
        console.error('Tünel durdururken hata:', err);
        res.status(500).json({ error: 'Sunucu hatası: ' + err.message });
    }
});


// Tünel silme rotası
app.delete('/api/tunnels/:id', authenticateToken, async (req, res) => {
    try {
        const tunnelId = req.params.id;
        const userId = req.user.id;

        // Tünelin var olup olmadığını ve kullanıcıya ait olup olmadığını kontrol et (veya kullanıcı admin mi)
        let query;
        let params;

        if (req.user.is_admin) {
            query = 'SELECT * FROM tunnels WHERE id = $1';
            params = [tunnelId];
        } else {
            query = 'SELECT * FROM tunnels WHERE id = $1 AND user_id = $2';
            params = [tunnelId, userId];
        }

        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Tünel bulunamadı' });
        }

        const tunnel = result.rows[0];

        // Tünel aktifse durdur
        if (tunnel.status === 'active') {
            // Bu kullanıcı için istemci bul
            const userClientId = Array.from(activeClients.keys()).find(clientId => {
                const client = activeClients.get(clientId);
                return client.userId === tunnel.user_id;
            });

            if (userClientId) {
                const clientWs = activeClients.get(userClientId).ws;

                // İstemciye durdurma komutu gönder
                clientWs.send(JSON.stringify({
                    type: 'stopTunnel',
                    tunnelId: tunnel.id
                }));
            }

            // Proxy varsa durdur
            const proxyKey = `${tunnel.id}:${tunnel.server_port}`;
            if (activeTunnels.has(proxyKey)) {
                const proxy = activeTunnels.get(proxyKey);
                proxy.close();
                activeTunnels.delete(proxyKey);
            }
        }

        // Bu tünel için istatistikleri sil
        await pool.query(
            'DELETE FROM statistics WHERE tunnel_id = $1',
            [tunnelId]
        );

        // Tüneli sil
        await pool.query(
            'DELETE FROM tunnels WHERE id = $1',
            [tunnelId]
        );

        res.json({ message: 'Tünel silindi' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// Tünel istatistikleri rotası
app.get('/api/tunnels/:id/stats', authenticateToken, async (req, res) => {
    try {
        const tunnelId = req.params.id;
        const userId = req.user.id;

        // Tünelin var olup olmadığını ve kullanıcıya ait olup olmadığını kontrol et (veya kullanıcı admin mi)
        let query;
        let params;

        if (req.user.is_admin) {
            query = 'SELECT * FROM tunnels WHERE id = $1';
            params = [tunnelId];
        } else {
            query = 'SELECT * FROM tunnels WHERE id = $1 AND user_id = $2';
            params = [tunnelId, userId];
        }

        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Tünel bulunamadı' });
        }

        // İstatistikleri al
        const statsResult = await pool.query(
            `SELECT * FROM statistics
             WHERE tunnel_id = $1
             ORDER BY timestamp DESC
                 LIMIT 100`,
            [tunnelId]
        );

        res.json({
            tunnel: result.rows[0],
            statistics: statsResult.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// WebSocket işleme
wss.on('connection', (ws, req) => {
    const clientId = uuidv4();
    let authenticatedUserId = null;
    const clientIp = req ? req.socket.remoteAddress.replace(/^::ffff:/, '') : 'Bilinmiyor';

    console.log(`WebSocket istemcisi bağlandı: ${clientId} (IP: ${clientIp})`);

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            console.log(`WebSocket mesajı alındı (${clientId}): ${data.type}`);

            // Kimlik doğrulamayı işle
            if (data.type === 'auth') {
                const token = data.token;

                try {
                    const user = jwt.verify(token, JWT_SECRET);
                    authenticatedUserId = user.id;

                    // İstemci bilgilerini kaydet
                    activeClients.set(clientId, {
                        userId: user.id,
                        ws,
                        clientName: data.clientName || 'Bilinmiyor',
                        clientIp: data.clientIp || clientIp,
                        clientOs: data.clientOs || 'Bilinmiyor'
                    });

                    // Onay gönder
                    ws.send(JSON.stringify({
                        type: 'authResult',
                        success: true
                    }));

                    console.log(`İstemci ${clientId}, ${user.id} kullanıcısı olarak kimlik doğruladı (${data.clientName})`);
                } catch (err) {
                    // Geçersiz token
                    ws.send(JSON.stringify({
                        type: 'authResult',
                        success: false,
                        error: 'Geçersiz token'
                    }));

                    console.error(`İstemci ${clientId} kimlik doğrulama hatası: ${err.message}`);
                }
            }
            // Tünel başlatma onayını işle
            // WebSocket Tünel başlatma onayını işleyen kodun düzeltilmiş versiyonu
            else if (data.type === 'tunnelStarted' && authenticatedUserId) {
                const tunnelId = parseInt(data.tunnelId); // ID'yi sayıya çevir
                console.log(`Tünel başlatma onayı alındı (İstemci: ${clientId}): Tünel #${tunnelId}, Başarılı: ${data.success}`);

                if (data.success) {
                    // Tünelin mevcut durumunu kontrol et
                    const statusResult = await pool.query(
                        'SELECT status, host, port, server_port FROM tunnels WHERE id = $1',
                        [tunnelId]
                    );

                    // Eğer tünel bulunamadıysa veya artık 'starting' durumunda değilse, işlemi iptal et
                    if (statusResult.rows.length === 0 || statusResult.rows[0].status !== 'starting') {
                        console.log(`Tünel #${tunnelId} başlatma onayı alındı, ancak durum artık 'starting' değil: ${statusResult.rows[0]?.status || 'bulunamadı'}`);

                        ws.send(JSON.stringify({
                            type: 'tunnelStartFailed',
                            tunnelId,
                            error: 'Tünel durumu değiştirildi, başlatma iptal edildi'
                        }));

                        return;
                    }

                    const tunnel = statusResult.rows[0];

                    // Tüneldeki istemci bilgilerini güncelle
                    const clientInfo = activeClients.get(clientId);

                    await pool.query(
                        `UPDATE tunnels
                         SET client_name = $1, client_ip = $2, client_os = $3, status = $4
                         WHERE id = $5`,
                        [clientInfo.clientName, clientInfo.clientIp, clientInfo.clientOs, 'active', tunnelId]
                    );

                    console.log(`Tünel #${tunnelId} durumu "active" olarak güncellendi`);

                    // Tünel proxy'si oluştur ve kaydet
                    const success = await createAndSaveTunnelProxy(
                        tunnelId,
                        tunnel.server_port,
                        tunnel.host,
                        tunnel.port
                    );

                    if (success) {
                        // İstemciye tünel başlatıldı onayı gönder
                        ws.send(JSON.stringify({
                            type: 'tunnelStartConfirmed',
                            tunnelId: tunnelId,
                            name: tunnel.name || `Tünel #${tunnelId}`,
                            serverPort: tunnel.server_port
                        }));

                        console.log(`Tünel #${tunnelId} başlatma onayı istemciye gönderildi`);
                    } else {
                        console.error(`Tünel #${tunnelId} için proxy oluşturulamadı`);

                        // Proxy oluşturulamadıysa hata durumuna getir
                        await pool.query(
                            'UPDATE tunnels SET status = $1 WHERE id = $2',
                            ['error', tunnelId]
                        );

                        // Hata mesajını istemciye ilet
                        ws.send(JSON.stringify({
                            type: 'tunnelStartFailed',
                            tunnelId,
                            error: 'Proxy sunucusu oluşturulamadı'
                        }));
                    }
                } else {
                    // Tünel durumunu hata olarak güncelle
                    await pool.query(
                        'UPDATE tunnels SET status = $1 WHERE id = $2',
                        ['error', tunnelId]
                    );

                    const error = data.error || 'Bilinmeyen hata';
                    console.error(`Tünel #${tunnelId} başlatma hatası: ${error}`);

                    // Hata mesajını istemciye ilet
                    ws.send(JSON.stringify({
                        type: 'tunnelStartFailed',
                        tunnelId,
                        error: error
                    }));
                }
            }
            // Tünel durdurma onayını işle
            // Tünel durdurma onayını işle - Düzeltilmiş versiyon
            else if (data.type === 'tunnelStopped' && authenticatedUserId) {
                const tunnelId = parseInt(data.tunnelId); // ID'yi sayıya çevir
                console.log(`Tünel #${tunnelId} durdurma onayı alındı (İstemci: ${clientId})`);

                // Önce tünelin mevcut durumunu kontrol et
                const statusResult = await pool.query(
                    'SELECT status, server_port FROM tunnels WHERE id = $1',
                    [tunnelId]
                );

                if (statusResult.rows.length > 0) {
                    const currentStatus = statusResult.rows[0].status;
                    const serverPort = statusResult.rows[0].server_port;
                    console.log(`Tünel #${tunnelId} mevcut durumu: ${currentStatus}, port: ${serverPort}`);

                    // Eğer tünel hala active veya stopping durumundaysa inactive yap
                    if (currentStatus === 'active' || currentStatus === 'stopping') {
                        // Tünel durumunu güncelle
                        await pool.query(
                            'UPDATE tunnels SET status = $1 WHERE id = $2',
                            ['inactive', tunnelId]
                        );

                        console.log(`Tünel #${tunnelId} durumu "inactive" olarak güncellendi (istemci onayıyla)`);
                    } else {
                        console.log(`Tünel #${tunnelId} zaten inactive veya başka bir durumda (${currentStatus}), güncelleme yapılmadı`);
                    }

                    // Tüm aktif proxy'leri kontrol et
                    console.log(`Aktif tüneller: ${Array.from(activeTunnels.keys()).join(', ') || 'Yok'}`);

                    // Proxy'yi bul ve kapat
                    const proxyKey = `${tunnelId}:${serverPort}`;
                    console.log(`Aranacak proxy anahtarı: ${proxyKey}`);

                    if (activeTunnels.has(proxyKey)) {
                        try {
                            const proxy = activeTunnels.get(proxyKey);
                            proxy.close();
                            activeTunnels.delete(proxyKey);
                            console.log(`Tünel proxy'si kapatıldı: ${proxyKey}`);
                        } catch (e) {
                            console.error(`Proxy kapatılırken hata: ${e.message}`);
                        }
                    } else {
                        console.log(`Tünel #${tunnelId} için aktif proxy bulunamadı: ${proxyKey}`);
                    }
                } else {
                    console.log(`Tünel #${tunnelId} veritabanında bulunamadı`);
                }

                // Tünel bilgilerini al
                const result = await pool.query(
                    'SELECT * FROM tunnels WHERE id = $1',
                    [tunnelId]
                );

                if (result.rows.length > 0) {
                    const tunnel = result.rows[0];

                    // İstemciye onay gönder
                    ws.send(JSON.stringify({
                        type: 'tunnelStopConfirmed',
                        tunnelId: tunnel.id,
                        name: tunnel.name
                    }));

                    console.log(`Tünel #${tunnelId} durdurma onayı istemciye gönderildi`);
                } else {
                    console.log(`Tünel #${tunnelId} bulunamadı, istemciye yanıt gönderilemiyor`);
                }
            }
            // Heartbeat'i işle
            else if (data.type === 'heartbeat') {
                ws.send(JSON.stringify({ type: 'heartbeatAck' }));
            }
            else {
                console.log(`Bilinmeyen mesaj türü: ${data.type}`);
            }
        } catch (err) {
            console.error(`WebSocket mesajını işlerken hata (${clientId}): ${err.message}`);
        }
    });

    ws.on('close', () => {
        console.log(`WebSocket istemcisi bağlantısı kesildi: ${clientId}`);

        // Bu istemci için aktif proxy'leri temizle
        if (activeClients.has(clientId)) {
            const userId = activeClients.get(clientId).userId;

            console.log(`İstemci ${clientId} (Kullanıcı ID: ${userId}) bağlantısı kesildi. Tünel durumları korunuyor.`);

            // NOT: Artık tünel durumlarını 'inactive' olarak güncellemiyoruz.
            // Böylece kullanıcı yeniden bağlandığında tüneller hala aktif olarak görünecek.

            // Yalnızca proxy'leri kapat (çünkü WebSocket bağlantısı koptuğunda
            // proxy'lerin açık kalmasının bir anlamı yok)
            pool.query(
                'SELECT id, server_port FROM tunnels WHERE user_id = $1 AND status = $2',
                [userId, 'active']
            ).then(result => {
                for (const tunnel of result.rows) {
                    const proxyKey = `${tunnel.id}:${tunnel.server_port}`;
                    if (activeTunnels.has(proxyKey)) {
                        const proxy = activeTunnels.get(proxyKey);
                        proxy.close();
                        activeTunnels.delete(proxyKey);
                        console.log(`İstemci ayrıldı: Proxy kapatıldı: ${proxyKey} (Tünel ID: ${tunnel.id})`);
                    }
                }
            }).catch(err => {
                console.error(`Bağlantısı kesilen istemci için proxy'leri durdururken hata: ${err.message}`);
            });
        }

        // İstemciyi aktif istemcilerden kaldır
        activeClients.delete(clientId);
    });
});

// Sunucuyu başlat
async function startServer() {
    console.log('vTunnel sunucusu başlatılıyor...');

    // Önce sunucu yapılandırmasını yükle/oluştur
    const serverConfigInitialized = await initializeServerConfig();
    if (!serverConfigInitialized) {
        console.error('Sunucu yapılandırması başlatılamadı. Çıkılıyor...');
        process.exit(1);
    }

    // Ardından veritabanını başlat
    const dbInitialized = await initializeDatabase();
    if (!dbInitialized) {
        console.error('Veritabanı başlatılamadı. Çıkılıyor...');
        process.exit(1);
    }

    server.listen(API_PORT, () => {
        console.log(`vTunnel sunucusu ${API_PORT} portunda dinliyor`);
    });
}

// Düzgün kapatmayı işle
process.on('SIGINT', async () => {
    console.log('Sunucu kapatılıyor...');

    // Tüm tünel proxy'lerini kapat
    for (const proxy of activeTunnels.values()) {
        proxy.close();
    }

    // WebSocket sunucusunu kapat
    wss.close();

    // HTTP sunucusunu kapat
    server.close();

    // Veritabanı havuzunu kapat
    if (pool) {
        await pool.end();
    }

    process.exit(0);
});

// Sunucuyu başlat
startServer();
