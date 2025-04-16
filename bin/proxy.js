#!/usr/bin/env node

/**
 * V-Tunnel - Lightweight Tunnel Routing Solution
 *
 * A 100% free and open-source alternative to commercial tunneling solutions
 * like Ngrok, Cloudflare Tunnel, and others.
 *
 * @file        proxy.js
 * @description Enhanced Tunnel Routing Proxy for wildcard host
 * @author      Cengiz AKCAN <me@cengizakcan.com>
 * @copyright   Copyright (c) 2025, Cengiz AKCAN
 * @license     MIT
 * @version     1.1.0
 * @link        https://github.com/wwwakcan/V-Tunnel
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const inquirer = require('inquirer');
const colors = require('colors/safe');
const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { createProxyServer } = require('http-proxy');
const net = require('net');
const cluster = require('cluster');

// Sabitler
const PROXY_DIR = path.join(process.cwd(), '.vtunnel-proxy');
const SSL_DIR = path.join(PROXY_DIR, 'ssl');
const BACKGROUND_FILE = path.join(PROXY_DIR, 'background.json');
const CERTBOT_DIR = path.join(PROXY_DIR, 'certbot');
const CONFIG_FILE = path.join(PROXY_DIR, 'config.json');
const LOG_FILE = path.join(PROXY_DIR, 'proxy.log');
const ERROR_LOG_FILE = path.join(PROXY_DIR, 'error.log');

// CPU sayısı (performans için)
const NUM_CPUS = require('os').cpus().length;

// Subdomain cache (performans optimizasyonu)
const domainCache = new Map();
const HOST_CACHE_TTL = 60 * 1000; // 1 dakika cache süresi

// CLI renkli loglar için yardımcı fonksiyonlar
const log = {
    info: (text) => console.log(colors.blue(text)),
    success: (text) => console.log(colors.green('✓ ' + text)),
    warning: (text) => console.log(colors.yellow('⚠ ' + text)),
    error: (text) => console.log(colors.red('✗ ' + text)),
    title: (text) => console.log(colors.bold.cyan('\n' + text + '\n' + '='.repeat(text.length) + '\n'))
};

// Log fonksiyonu - dosyaya yazma kontrolü ile
function writeLog(message, isError = false) {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${message}\n`;

    // Worker process değilse veya master ise, konsola da yaz
    if (!cluster.isWorker || cluster.isMaster) {
        console.log(isError ? colors.red(message) : message);
    }

    // Asenkron dosya yazma işlemi (performans için)
    fs.appendFile(
        isError ? ERROR_LOG_FILE : LOG_FILE,
        logEntry,
        { flag: 'a' },
        (err) => {
            if (err && !isError) {
                console.error(`Log yazma hatası: ${err.message}`);
            }
        }
    );
}

// Dizin yapısını oluştur
async function setupDirectories() {
    // mkdirp API değişmiş olabilir, fs.mkdir kullanarak oluştur
    fs.mkdirSync(SSL_DIR, { recursive: true });
    fs.mkdirSync(CERTBOT_DIR, { recursive: true });

    // Log dosyaları için dizin kontrolü
    try {
        fs.accessSync(path.dirname(LOG_FILE), fs.constants.W_OK);
    } catch (err) {
        fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
    }
}

// Port erişilebilirliğini kontrol et (timeout ile optimize edildi)
function isPortAccessible(port, timeout = 500) {
    return new Promise((resolve) => {
        const testSocket = new net.Socket();

        testSocket.setTimeout(timeout);

        testSocket.on('error', () => {
            testSocket.destroy();
            resolve(false);
        });

        testSocket.on('timeout', () => {
            testSocket.destroy();
            resolve(false);
        });

        testSocket.connect(port, '127.0.0.1', () => {
            testSocket.destroy();
            resolve(true);
        });
    });
}

// Let's Encrypt için gerekli dosyaları oluştur
async function createCertbotCommand(domain, wildcardDomain) {
    log.title('Let\'s Encrypt Wildcard SSL Sertifikası Oluşturma');
    log.info('DNS-01 doğrulaması için TXT kaydı oluşturmanız gerekecek.');

    // Certbot komutu oluştur
    const certbotCommand = `certbot certonly --manual --preferred-challenges dns --server https://acme-v02.api.letsencrypt.org/directory -d "${wildcardDomain}" -d "${domain}" --cert-name "${domain}" --config-dir "${CERTBOT_DIR}" --work-dir "${CERTBOT_DIR}" --logs-dir "${CERTBOT_DIR}/logs"`;

    return certbotCommand;
}

// SSL sertifikalarını kopyala
function copySSLFiles(domain) {
    const srcDir = path.join(CERTBOT_DIR, 'live', domain);
    const destDir = path.join(SSL_DIR, domain);

    // Certbot dizini kontrol et
    if (!fs.existsSync(srcDir)) {
        throw new Error(`Certbot sertifika dizini bulunamadı: ${srcDir}`);
    }

    // Gerekli sertifika dosyalarının varlığını kontrol et
    const fullchainPath = path.join(srcDir, 'fullchain.pem');
    const privkeyPath = path.join(srcDir, 'privkey.pem');

    if (!fs.existsSync(fullchainPath)) {
        throw new Error(`SSL sertifikası bulunamadı: ${fullchainPath}`);
    }

    if (!fs.existsSync(privkeyPath)) {
        throw new Error(`SSL özel anahtarı bulunamadı: ${privkeyPath}`);
    }

    // Hedef dizini oluştur
    if (!fs.existsSync(destDir)) {
        fs.mkdirSync(destDir, { recursive: true });
    }

    // Sertifika dosyalarını kopyala
    fs.copyFileSync(fullchainPath, path.join(destDir, 'fullchain.pem'));
    fs.copyFileSync(privkeyPath, path.join(destDir, 'privkey.pem'));

    log.success(`SSL sertifikaları ${colors.cyan(destDir)} dizinine kopyalandı.`);
    return {
        cert: path.join(destDir, 'fullchain.pem'),
        key: path.join(destDir, 'privkey.pem')
    };
}

// Arkaplanda çalıştırılan proxy'nin durumunu kontrol et
function checkProxyStatus() {
    if (!fs.existsSync(BACKGROUND_FILE)) {
        return { running: false };
    }

    try {
        const status = JSON.parse(fs.readFileSync(BACKGROUND_FILE, 'utf8'));

        // PID hala aktif mi kontrol et
        if (status.pid) {
            try {
                // PID var mı diye kontrol et (UNIX/Linux)
                process.kill(status.pid, 0);
                return { ...status, running: true };
            } catch (err) {
                // PID geçersiz veya process ölmüş
                return { ...status, running: false };
            }
        }

        return { ...status, running: false };
    } catch (err) {
        return { running: false };
    }
}

// Proxy durumunu kaydet
function saveProxyStatus(status) {
    fs.writeFileSync(BACKGROUND_FILE, JSON.stringify(status, null, 2), 'utf8');
}

// Konfigürasyon kaydet
function saveConfig(config) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
}

// Konfigürasyon yükle
function loadConfig() {
    if (!fs.existsSync(CONFIG_FILE)) {
        return null;
    }

    try {
        return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    } catch (err) {
        return null;
    }
}

// Setup komutu - Kurulum işlemi
async function setupCommand(argv) {
    try {
        log.title('Wildcard SSL Proxy Kurulumu');

        // Dizin yapısını oluştur
        await setupDirectories();

        // Gerekli paketlerin kurulu olup olmadığını kontrol et
        log.info('Gerekli bağımlılıkları kontrol ediyorum...');

        try {
            execSync('certbot --version', { stdio: 'ignore' });
            log.success('Certbot kurulu.');
        } catch (err) {
            log.error('Certbot kurulu değil! Lütfen yükleyin:');
            log.info('Ubuntu/Debian: sudo apt-get install certbot');
            log.info('CentOS/RHEL: sudo yum install certbot');
            log.info('macOS: brew install certbot');
            return;
        }

        // Ana domain bilgisini al
        let domain = argv.domain;

        if (!domain) {
            const answer = await inquirer.prompt([{
                type: 'input',
                name: 'domain',
                message: 'Ana domain adını girin:',
                default: 'connect.vobo.cloud',
                validate: input => input.length > 0 ? true : 'Domain adı boş olamaz'
            }]);
            domain = answer.domain;
        }

        // Wildcard subdomain bilgisini oluştur
        const wildcardDomain = `*.${domain}`;
        log.info(`Wildcard domain: ${wildcardDomain}`);

        // Konfigürasyon kaydet
        const config = {
            domain,
            wildcardDomain,
            usePortBasedSubdomains: true, // Port temelli subdomain kullanımını belirt
            defaultPort: 0, // Spesifik bir default port yoksa 0
            maxWorkers: Math.max(1, NUM_CPUS - 1), // İşlemci sayısı - 1 (en az 1)
            proxyOptions: {
                xfwd: true, // X-Forwarded-For başlıklarını geçir
                secure: false, // SSL sertifikası doğrulamasını atla (iç ağda)
                changeOrigin: true, // Origin başlığını değiştir
                autoRewrite: true, // URL'leri otomatik yeniden yaz
                followRedirects: true, // Yönlendirmeleri takip et
                proxyTimeout: 30000, // 30 saniye zaman aşımı
                timeout: 30000
            }
        };

        // Default port belirleme seçeneği ekle
        const defaultPortAnswer = await inquirer.prompt([{
            type: 'confirm',
            name: 'useDefaultPort',
            message: 'Ana domain için özel bir port yönlendirmesi kullanmak istiyor musunuz?',
            default: false
        }]);

        if (defaultPortAnswer.useDefaultPort) {
            const portAnswer = await inquirer.prompt([{
                type: 'input',
                name: 'defaultPort',
                message: 'Ana domain için hedef portu girin:',
                validate: input => {
                    const port = parseInt(input, 10);
                    if (isNaN(port) || port < 1 || port > 65535) {
                        return 'Geçerli bir port numarası girin (1-65535)';
                    }
                    return true;
                },
                filter: input => parseInt(input, 10)
            }]);

            // Port erişilebilir mi kontrol et
            const isAccessible = await isPortAccessible(portAnswer.defaultPort);
            if (!isAccessible) {
                log.warning(`Port ${portAnswer.defaultPort} erişilebilir değil. Yine de devam edilecek.`);
            }

            config.defaultPort = portAnswer.defaultPort;
        }

        // Performans yapılandırma seçenekleri
        const performanceAnswer = await inquirer.prompt([{
            type: 'confirm',
            name: 'configurePerformance',
            message: 'Performans ayarlarını yapılandırmak ister misiniz?',
            default: true
        }]);

        if (performanceAnswer.configurePerformance) {
            const workerAnswer = await inquirer.prompt([{
                type: 'input',
                name: 'maxWorkers',
                message: `Maksimum worker sayısı (çekirdek sayısı: ${NUM_CPUS}):`,
                default: config.maxWorkers,
                validate: input => {
                    const workers = parseInt(input, 10);
                    if (isNaN(workers) || workers < 1) {
                        return 'En az 1 worker gereklidir';
                    }
                    return true;
                },
                filter: input => parseInt(input, 10)
            }]);

            config.maxWorkers = workerAnswer.maxWorkers;

            // Proxy zaman aşımı
            const timeoutAnswer = await inquirer.prompt([{
                type: 'input',
                name: 'proxyTimeout',
                message: 'Proxy zaman aşımı (milisaniye):',
                default: config.proxyOptions.proxyTimeout,
                validate: input => {
                    const timeout = parseInt(input, 10);
                    if (isNaN(timeout) || timeout < 1000) {
                        return 'En az 1000 ms (1 saniye) olmalıdır';
                    }
                    return true;
                },
                filter: input => parseInt(input, 10)
            }]);

            config.proxyOptions.proxyTimeout = timeoutAnswer.proxyTimeout;
            config.proxyOptions.timeout = timeoutAnswer.proxyTimeout;
        }

        saveConfig(config);
        log.success('Konfigürasyon kaydedildi.');

        // Certbot komutunu oluştur
        const certbotCommand = await createCertbotCommand(domain, wildcardDomain);

        log.title('Let\'s Encrypt Sertifikası Yapılandırma');
        log.info('DNS TXT kayıtları eklemeniz istenecek, lütfen bekleyin...');
        log.info(`Çalıştırılacak komut: ${certbotCommand}`);

        // Certbot komutunu çalıştır (interaktif)
        const certbotProcess = spawn(certbotCommand.split(' ')[0], certbotCommand.split(' ').slice(1), {
            stdio: 'inherit', // Doğrudan terminale bağla
            shell: true
        });

        // Certbot işleminin tamamlanmasını bekle
        await new Promise((resolve, reject) => {
            certbotProcess.on('close', (code) => {
                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(`Certbot işlemi ${code} hata koduyla çıktı.`));
                }
            });
        }).catch(error => {
            log.error(error.message);
            return;
        });

        // TXT kaydı eklendi mi onayı al
        const txtConfirm = await inquirer.prompt([{
            type: 'confirm',
            name: 'confirmed',
            message: 'DNS TXT kaydını eklediniz mi?',
            default: false
        }]);

        if (txtConfirm.confirmed) {
            try {
                // Certbot çıktı dizinini kontrol et
                const certbotLiveDir = path.join(CERTBOT_DIR, 'live');
                if (!fs.existsSync(certbotLiveDir)) {
                    log.error(`Certbot dizini bulunamadı: ${certbotLiveDir}`);
                    log.info('Olası nedenler:');
                    log.info('1. Certbot sertifika oluşturma işlemi başarısız olmuş olabilir');
                    log.info('2. Certbot farklı bir dizine sertifikaları kaydetmiş olabilir');

                    // Kullanıcıdan certbot dizinini manuel olarak belirtmesini iste
                    const manualPathConfirm = await inquirer.prompt([{
                        type: 'confirm',
                        name: 'useManualPath',
                        message: 'Sertifika dosyalarının yolunu manuel olarak belirtmek ister misiniz?',
                        default: true
                    }]);

                    if (manualPathConfirm.useManualPath) {
                        const manualPath = await inquirer.prompt([{
                            type: 'input',
                            name: 'certPath',
                            message: 'Lütfen fullchain.pem dosyasının tam yolunu girin:',
                            validate: input => fs.existsSync(input) ? true : 'Dosya bulunamadı'
                        }, {
                            type: 'input',
                            name: 'keyPath',
                            message: 'Lütfen privkey.pem dosyasının tam yolunu girin:',
                            validate: input => fs.existsSync(input) ? true : 'Dosya bulunamadı'
                        }]);

                        // Manuel belirtilen dosyaları kopyala
                        const destDir = path.join(SSL_DIR, domain);
                        if (!fs.existsSync(destDir)) {
                            fs.mkdirSync(destDir, { recursive: true });
                        }

                        fs.copyFileSync(manualPath.certPath, path.join(destDir, 'fullchain.pem'));
                        fs.copyFileSync(manualPath.keyPath, path.join(destDir, 'privkey.pem'));

                        // SSL bilgilerini konfigürasyona ekle
                        config.ssl = {
                            cert: path.join(destDir, 'fullchain.pem'),
                            key: path.join(destDir, 'privkey.pem')
                        };

                        saveConfig(config);
                        log.success('SSL sertifikaları konfigürasyona eklendi.');
                        log.success('Kurulum tamamlandı!');
                        log.info('Proxy\'i başlatmak için şu komutu çalıştırın: node proxy.js start');
                        return;
                    } else {
                        log.warning('İşlem iptal edildi.');
                        return;
                    }
                }

                // SSL dosyalarını kopyala
                const sslOptions = copySSLFiles(domain);

                // SSL bilgilerini konfigürasyona ekle
                config.ssl = {
                    cert: sslOptions.cert,
                    key: sslOptions.key
                };

                saveConfig(config);
                log.success('SSL sertifikaları konfigürasyona eklendi.');
                log.success('Kurulum tamamlandı!');
                log.info('Proxy\'i başlatmak için şu komutu çalıştırın: node proxy.js start');
            } catch (error) {
                log.error('SSL işlemi hatası: ' + error.message);

                // Hata durumunda kullanıcıya yardımcı bilgiler göster
                log.info('\nSorunun çözümü için şunları deneyebilirsiniz:');
                log.info('1. Certbot\'u manuel olarak çalıştırın:');
                log.info(`   certbot certonly --manual --preferred-challenges dns -d "*.${domain}" -d "${domain}"`);
                log.info('2. Oluşturulan sertifikaları kontrol edin:');
                log.info('   ls -la /etc/letsencrypt/live/');
                log.info('3. Kurulumu tekrar çalıştırın ve sertifika yollarını manuel olarak belirtin.');
            }
        } else {
            log.warning('İşlem iptal edildi.');
        }
    } catch (error) {
        log.error('Kurulum hatası: ' + error.message);
    }
}

// Proxy sunucusunu başlat - Optimize edilmiş
function startProxyServer(config) {
    // Ana domain kısmını al (örn: *.example.com -> example.com)
    const baseDomain = config.domain;
    const wildcardDomain = config.wildcardDomain;
    const usePortBasedSubdomains = config.usePortBasedSubdomains || false;
    const defaultPort = config.defaultPort || 0;
    const proxyOptions = config.proxyOptions || {};

    // SSL seçeneklerini yükle
    const sslOptions = {
        cert: fs.readFileSync(config.ssl.cert),
        key: fs.readFileSync(config.ssl.key)
    };

    // Ana sayfa HTML'i (hafızada tutarak performans artışı)
    const indexHtml = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Port-Based Proxy Server</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                line-height: 1.6;
            }
            h1 {
                color: #333;
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
            }
            code {
                background: #f4f4f4;
                padding: 2px 5px;
                border-radius: 3px;
            }
            .example {
                background: #f8f8f8;
                padding: 15px;
                border-left: 4px solid #4CAF50;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <h1>Port-Based Subdomain Proxy</h1>
        <p>Bu sunucu port tabanlı subdomain yönlendirme için yapılandırılmıştır.</p>
        <p>Kullanım şekli:</p>
        <div class="example">
            <code>PORT.${baseDomain}</code> → <code>127.0.0.1:PORT</code>
        </div>
        <p>Örnek:</p>
        <div class="example">
            <code>8080.${baseDomain}</code> → <code>127.0.0.1:8080</code>
        </div>
        <p>Subdomain kısmına doğrudan bağlanmak istediğiniz port numarasını yazın.</p>
    </body>
    </html>
    `;

    // Worker process içinde çalışıyorsa
    if (cluster.isWorker) {
        // HTTP proxy oluştur
        const proxy = createProxyServer({
            ...proxyOptions,
            ws: true // WebSocket desteği
        });

        // Hata yönetimi
        proxy.on('error', (err, req, res) => {
            const logMessage = `Proxy hatası: ${err.message}, Hedef: ${req.headers.host}`;
            writeLog(logMessage, true);

            if (res.writeHead) {
                res.writeHead(502, { 'Content-Type': 'text/plain' });
                res.end('Proxy hatası oluştu. Hedef sunucuya erişilemiyor.');
            }
        });

        // WebSocket proxy hataları
        proxy.on('proxyReqWs', (proxyReq, req, socket, options, head) => {
            socket.on('error', (err) => {
                writeLog(`WebSocket hatası: ${err.message}`, true);
            });
        });

        // HTTPS sunucusu oluştur
        const httpsServer = https.createServer(sslOptions, (req, res) => {
            // Host başlığından subdomain al
            const host = req.headers.host?.toLowerCase();
            if (!host) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Host başlığı gerekli');
                return;
            }

            // Cache'den hedef bilgisini al
            const cacheKey = host;
            const cachedTarget = domainCache.get(cacheKey);

            if (cachedTarget) {
                // Cache'den hedef bilgisini kullan
                proxy.web(req, res, { target: cachedTarget });
                return;
            }

            let targetPort;

            // Ana domain için kontrol
            if (host === baseDomain) {
                // Ana domain için varsayılan port kullan
                if (defaultPort > 0) {
                    targetPort = defaultPort;
                } else {
                    // Ana sayfayı göster
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(indexHtml);
                    return;
                }
            }
            // Subdomain kontrolü
            else if (usePortBasedSubdomains) {
                // Port tabanlı subdomain kullanılıyorsa
                // Regex ile daha verimli subdomain parsing
                const subdomainMatch = host.match(/^(\d+)\.(.+)$/);

                if (subdomainMatch && subdomainMatch[2] === baseDomain) {
                    targetPort = parseInt(subdomainMatch[1], 10);

                    // Geçerli port aralığında mı kontrol et
                    if (targetPort < 1 || targetPort > 65535) {
                        res.writeHead(400, { 'Content-Type': 'text/plain' });
                        res.end(`Geçersiz port numarası: ${targetPort}. Port aralığı 1-65535 olmalıdır.`);
                        return;
                    }
                } else {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.end(`Geçersiz subdomain formatı. Subdomain bir port numarası olmalıdır (örn: 8080.${baseDomain})`);
                    return;
                }
            } else {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end(`Bilinmeyen subdomain: ${host}`);
                return;
            }

            // İlgili porta yönlendir
            const target = `http://127.0.0.1:${targetPort}`;

            // Hedefi cache'e ekle
            domainCache.set(cacheKey, target);

            // Cache TTL için zamanlayıcı
            setTimeout(() => {
                domainCache.delete(cacheKey);
            }, HOST_CACHE_TTL);

            writeLog(`Yönlendiriliyor: ${host} -> ${target}`);
            proxy.web(req, res, { target });
        });

        // WebSocket desteği
        httpsServer.on('upgrade', (req, socket, head) => {
            const host = req.headers.host?.toLowerCase();
            if (!host) {
                socket.destroy();
                return;
            }

            // Cache'den WebSocket hedefini al
            const cacheKey = `ws:${host}`;
            const cachedTarget = domainCache.get(cacheKey);

            if (cachedTarget) {
                proxy.ws(req, socket, head, { target: cachedTarget });
                return;
            }

            let targetPort;

            // Ana domain için kontrol
            if (host === baseDomain) {
                if (defaultPort > 0) {
                    targetPort = defaultPort;
                } else {
                    socket.destroy();
                    return;
                }
            }
            // Subdomain kontrolü
            else if (usePortBasedSubdomains) {
                const subdomainMatch = host.match(/^(\d+)\.(.+)$/);

                if (subdomainMatch && subdomainMatch[2] === baseDomain) {
                    targetPort = parseInt(subdomainMatch[1], 10);

                    if (targetPort < 1 || targetPort > 65535) {
                        socket.destroy();
                        return;
                    }
                } else {
                    socket.destroy();
                    return;
                }
            } else {
                socket.destroy();
                return;
            }

            const target = `http://127.0.0.1:${targetPort}`;

            // WebSocket hedefini cache'e ekle
            domainCache.set(cacheKey, target);

            // Cache TTL için zamanlayıcı
            setTimeout(() => {
                domainCache.delete(cacheKey);
            }, HOST_CACHE_TTL);

            writeLog(`WebSocket yönlendiriliyor: ${host} -> ${target}`);
            proxy.ws(req, socket, head, { target });
        });

        // HTTP -> HTTPS yönlendirme sunucusu
        const httpServer = http.createServer((req, res) => {
            const host = req.headers.host;
            if (!host) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end('Host başlığı gerekli');
                return;
            }

            const redirectUrl = `https://${host}${req.url}`;
            res.writeHead(301, { 'Location': redirectUrl });
            res.end();
        });

        // Sunucuları belirtilen portlarda başlat
        const HTTPS_PORT = 443;
        const HTTP_PORT = 80;

        // Daha iyi hata yönetimi
        function startServers() {
            try {
                // HTTPS sunucusu başlat
                httpsServer.listen(HTTPS_PORT, () => {
                    writeLog(`HTTPS proxy sunucusu port ${HTTPS_PORT} üzerinde çalışıyor (Worker ${cluster.worker.id}).`);
                });

                // HTTPS hata dinleyicisi
                httpsServer.on('error', (err) => {
                    if (err.code === 'EADDRINUSE') {
                        writeLog(`Port ${HTTPS_PORT} zaten kullanımda. Proxy başlatılamadı.`, true);
                    } else {
                        writeLog(`HTTPS sunucusu hatası: ${err.message}`, true);
                    }
                    process.exit(1);
                });

                // HTTP sunucusu başlat
                httpServer.listen(HTTP_PORT, () => {
                    writeLog(`HTTP -> HTTPS yönlendirme sunucusu port ${HTTP_PORT} üzerinde çalışıyor (Worker ${cluster.worker.id}).`);
                });

                // HTTP hata dinleyicisi
                httpServer.on('error', (err) => {
                    if (err.code === 'EADDRINUSE') {
                        writeLog(`Port ${HTTP_PORT} zaten kullanımda. Yönlendirme sunucusu başlatılamadı.`, true);
                        // HTTP olmadan devam et, kritik değil
                    } else {
                        writeLog(`HTTP sunucusu hatası: ${err.message}`, true);
                    }
                });

                // Worker durumunu bildir
                process.send({ status: 'ready', id: cluster.worker.id });
            } catch (err) {
                writeLog(`Sunucu başlatma hatası: ${err.message}`, true);
                process.exit(1);
            }
        }

        // Sunucuları başlat
        startServers();
    }
    // Master süreç ise, worker'ları yönet
    else if (cluster.isMaster) {
        const maxWorkers = config.maxWorkers || 1;
        let readyWorkers = 0;

        writeLog(`Wildcard domain: ${wildcardDomain}`);
        writeLog(`Port tabanlı subdomain yönlendirme aktif:`);
        writeLog(`- [PORT].${baseDomain} -> 127.0.0.1:[PORT]`);

        if (defaultPort > 0) {
            writeLog(`Ana domain yönlendirmesi: ${baseDomain} -> 127.0.0.1:${defaultPort}`);
        }

        writeLog(`Cluster modu aktif: ${maxWorkers} worker başlatılıyor...`);

        // Worker süreçleri başlat
        for (let i = 0; i < maxWorkers; i++) {
            cluster.fork();
        }

        // Worker süreçlerini dinle
        cluster.on('message', (worker, message) => {
            if (message.status === 'ready') {
                readyWorkers++;
                if (readyWorkers === maxWorkers) {
                    writeLog(`Tüm worker'lar hazır. Proxy tam kapasitede çalışıyor.`);
                }
            }
        });

        // Worker çökmelerini yönet
        cluster.on('exit', (worker, code, signal) => {
            if (code !== 0) {
                writeLog(`Worker ${worker.id} çöktü! Yeniden başlatılıyor...`, true);
                cluster.fork();
            }
        });
    }
}

// Proxy'yi başlat komutu
async function startCommand() {
    try {
        log.title('Wildcard SSL Proxy Başlatılıyor');

        // Mevcut durumu kontrol et
        const status = checkProxyStatus();

        if (status.running) {
            log.warning(`Proxy zaten çalışıyor! PID: ${status.pid}`);
            return;
        }

        // Konfigürasyon yükle
        const config = loadConfig();

        if (!config) {
            log.error('Konfigürasyon bulunamadı! Önce kurulum yapın: node proxy.js setup');
            return;
        }

        if (!config.ssl || !config.ssl.cert || !config.ssl.key) {
            log.error('SSL sertifikaları bulunamadı! Kurulumu tamamlayın: node proxy.js setup');
            return;
        }

        // Port yönlendirme bilgisini göster
        log.info('Port tabanlı subdomain yönlendirme kullanılıyor:');
        log.info(`[PORT].${config.domain} -> 127.0.0.1:[PORT]`);

        if (config.defaultPort > 0) {
            log.info(`Ana domain yönlendirmesi: ${config.domain} -> 127.0.0.1:${config.defaultPort}`);
        }

        // Arkaplanda çalıştır
        const out = fs.openSync(LOG_FILE, 'a');
        const err = fs.openSync(ERROR_LOG_FILE, 'a');

        log.info('Proxy arkaplanda başlatılıyor...');

        const child = spawn(process.execPath, [__filename, 'run'], {
            detached: true,
            stdio: ['ignore', out, err]
        });

        // Çocuk işlemin bağımsız çalışmasını sağla
        child.unref();

        // Durum bilgisini kaydet
        const newStatus = {
            pid: child.pid,
            startTime: new Date().toISOString(),
            domain: config.domain,
            wildcardDomain: config.wildcardDomain,
            workers: config.maxWorkers || 1
        };

        saveProxyStatus(newStatus);

        log.success(`Proxy başarıyla arkaplanda başlatıldı. PID: ${child.pid}`);
        log.info(`Log dosyaları: ${LOG_FILE} ve ${ERROR_LOG_FILE}`);
    } catch (error) {
        log.error('Başlatma hatası: ' + error.message);
    }
}

// Proxy'yi durdur komutu
function stopCommand() {
    try {
        log.title('Wildcard SSL Proxy Durduruluyor');

        // Mevcut durumu kontrol et
        const status = checkProxyStatus();

        if (!status.running) {
            log.warning('Proxy zaten çalışmıyor!');
            return;
        }

        // Prosesi sonlandır
        try {
            process.kill(status.pid, 'SIGTERM');
            log.success(`Proxy durduruldu. PID: ${status.pid}`);

            // Durum bilgisini güncelle
            status.running = false;
            status.stopTime = new Date().toISOString();
            saveProxyStatus(status);
        } catch (err) {
            log.error(`Prosesi durdururken hata oluştu: ${err.message}`);
        }
    } catch (error) {
        log.error('Durdurma hatası: ' + error.message);
    }
}

// Durum komutu
function statusCommand() {
    try {
        log.title('Wildcard SSL Proxy Durumu');

        // Mevcut durumu kontrol et
        const status = checkProxyStatus();

        if (status.running) {
            log.success(`Proxy çalışıyor. PID: ${status.pid}`);
            log.info(`Başlatma zamanı: ${status.startTime}`);
            log.info(`Domain: ${status.domain}`);
            log.info(`Wildcard domain: ${status.wildcardDomain}`);

            if (status.workers) {
                log.info(`Çalışan worker sayısı: ${status.workers}`);
            }

            // Konfigürasyon yükle
            const config = loadConfig();

            if (config) {
                log.info('Aktif port tabanlı subdomain yönlendirme:');
                log.info(`[PORT].${config.domain} -> 127.0.0.1:[PORT]`);

                if (config.defaultPort > 0) {
                    log.info(`Ana domain yönlendirmesi: ${config.domain} -> 127.0.0.1:${config.defaultPort}`);
                }
            }
        } else {
            log.warning('Proxy çalışmıyor.');

            if (status.stopTime) {
                log.info(`Son durdurma zamanı: ${status.stopTime}`);
            }
        }
    } catch (error) {
        log.error('Durum hatası: ' + error.message);
    }
}

// Çalıştırma komutu - doğrudan işlem çalıştırması
function runCommand() {
    try {
        // Konfigürasyon yükle
        const config = loadConfig();

        if (!config) {
            console.error('Konfigürasyon bulunamadı!');
            process.exit(1);
        }

        // Proxy sunucusunu başlat
        startProxyServer(config);
    } catch (error) {
        console.error('Çalıştırma hatası: ' + error.message);
        process.exit(1);
    }
}

// Ana uygulama
async function main() {
    // Dizin yapısını kontrol et
    if (!fs.existsSync(PROXY_DIR)) {
        await setupDirectories();
    }

    // Komut satırı argümanlarını yapılandır
    const argv = yargs(hideBin(process.argv))
        .usage('Usage: $0 <command> [options]')
        .command('setup', 'SSL oluşturma ve proxy için kurulum yap', (yargs) => {
            return yargs
                .option('domain', {
                    alias: 'd',
                    describe: 'Ana domain adı',
                    type: 'string'
                });
        })
        .command('start', 'Proxy sunucusunu başlat')
        .command('stop', 'Çalışan proxy sunucusunu durdur')
        .command('status', 'Proxy sunucusunun durumunu kontrol et')
        .command('run', 'Proxy sunucusunu doğrudan çalıştır (genelde dahili kullanım)')
        .demandCommand(1, 'Bir komut belirtmelisiniz: setup, start, stop veya status')
        .help()
        .alias('help', 'h')
        .version()
        .alias('version', 'v')
        .argv;

    // Komutu çalıştır
    const command = argv._[0];

    switch (command) {
        case 'setup':
            await setupCommand(argv);
            break;
        case 'start':
            await startCommand();
            break;
        case 'stop':
            stopCommand();
            break;
        case 'status':
            statusCommand();
            break;
        case 'run':
            runCommand();
            break;
        default:
            log.error(`Bilinmeyen komut: ${command}`);
            break;
    }
}

// Programı başlat
main();
