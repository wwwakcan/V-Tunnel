# V-Tunnel

[![npm version](https://badge.fury.io/js/v-tunnel.svg)](https://www.npmjs.com/package/v-tunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)
![NodeJS](https://img.shields.io/badge/node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white)
![NPM](https://img.shields.io/badge/NPM-%23CB3837.svg?style=for-the-badge&logo=npm&logoColor=white)
![GitHub](https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white)


A lightweight (99Kb), 100% free and open-source alternative to commercial tunneling solutions like Ngrok, Cloudflare Tunnel, and others.

[English](#english) | [Türkçe](#turkish)

<a name="english"></a>

V-Tunnel allows you to expose local services to the internet through secure tunnels. Perfect for development, demos, webhooks, IoT devices, and remote access scenarios.

## Features

- **Lightweight**: Only 99Kb, minimal dependencies
- **Secure**: JWT authentication and AES-256-CBC encryption
- **Easy to use**: Simple CLI interface
- **Self-hostable**: Run your own tunnel server
- **Multi-user**: Support for multiple users and tunnels
- **Traffic monitoring**: Track data transferred through tunnels
- **No rate limits**: Unlike most commercial solutions
- **Persistent tunnels**: Run as background services
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Background mode**: Run server as a daemon process
- **SSL Proxy**: Automatically manage SSL certificates for custom domains

## Installation

```bash
npm install -g v-tunnel
```

## Quick Start

### Server Setup

Set up your tunnel server:

```bash
vtunnel server
```

Follow the interactive setup to:
1. Create an admin user
2. Configure server port (default: 9012)
3. Set tunnel port range (default: 51200-52200)

### Client Usage

#### Login to server

```bash
vtunnel client login
```

#### Create a tunnel

```bash
vtunnel client create
```

Follow the prompts to create a tunnel with:
- Tunnel name
- Description (optional)
- Local service address (default: localhost)
- Local service port

#### Start a tunnel

```bash
vtunnel client start
```

Your local service is now accessible through the tunnel!

## Client Commands

| Command                | Description |
|------------------------|-------------|
| `vtunnel client login` | Log in to the tunnel server |
| `vtunnel client logout`       | Log out from the tunnel server |
| `vtunnel client create`       | Define a new tunnel |
| `vtunnel client list`         | List all tunnels |
| `vtunnel client start`        | Start a tunnel |
| `vtunnel client stop`         | Stop a running tunnel |
| `vtunnel client status`       | Show status of tunnels |
| `vtunnel client details`      | Show details of a tunnel |
| `vtunnel client delete`       | Delete a tunnel |
| `vtunnel client password`     | Change your password |
| `vtunnel client --help`       | Show help information |

## Server Commands

| Command                              | Description |
|--------------------------------------|-------------|
| `vtunnel server`                     | Start the tunnel server |
| `vtunnel server background start`    | Start the tunnel server in background mode |
| `vtunnel server background stop`     | Stop the background tunnel server |
| `vtunnel server background status`   | Check status of the background server process |
| `vtunnel server --port=9012`         | Specify control server port |
| `vtunnel server --range-start=51200` | Set tunnel port range start |
| `vtunnel server --range-end=52200`   | Set tunnel port range end |
| `vtunnel server --stats`             | Display server stats periodically |
| `vtunnel server --help`              | Show help information |

## Proxy Commands

| Command                              | Description |
|--------------------------------------|-------------|
| `vtunnel proxy`                      | Start the SSL proxy server |
| `vtunnel proxy setup`                | Configure proxy settings interactively |
| `vtunnel proxy show`                 | Show current proxy configuration |
| `vtunnel proxy background start`     | Start proxy in background mode |
| `vtunnel proxy background stop`      | Stop background proxy server |
| `vtunnel proxy background status`    | Check status of background proxy |

## How It Works

V-Tunnel uses a client-server architecture:

1. **Server Component**: Hosts the tunnel endpoints and routes traffic
2. **Client Component**: Connects to the server and forwards traffic to local services
3. **Proxy Component**: Routes traffic based on domain names and manages SSL certificates

When a tunnel is established:
- The server allocates a port for the tunnel
- The client connects to the server and registers the tunnel
- External traffic to the server's allocated port is forwarded to the client
- The client forwards traffic to the local service

## SSL Proxy Feature

V-Tunnel includes a powerful SSL proxy that allows you to:

- Use custom domain names for your tunnels
- Automatically manage SSL certificates
- Route traffic based on subdomain patterns

For example, running a local service on port 3000 can be accessed through `3000.yourdomain.com` with full SSL support.

The proxy configuration is stored in `.vtunnel-proxy/config.json` and includes:
- Main domain configuration
- Subdomain pattern matching
- SSL certificate management (using Let's Encrypt)
- Port configurations

## Running as a Background Service

You can run both V-Tunnel server and proxy as background services:

```bash
# Start the server in background mode
vtunnel server background start

# Start the proxy in background mode
vtunnel proxy background start

# Check status
vtunnel server background status
vtunnel proxy background status

# Stop services
vtunnel server background stop
vtunnel proxy background stop
```

When running in background mode:
- Server logs are saved to `.vtunnel-server/vtunnel.log`
- Proxy logs are saved to `.vtunnel-proxy/proxy-output.log`
- Error logs are saved to `.vtunnel-server/vtunnel-error.log` and `.vtunnel-proxy/proxy-error.log`
- Process information is stored in the respective configuration directories

## Advanced Configuration

### Client Configuration

Client configuration is stored in `.vtunnel-client/` directory:
- `auth.json`: Stores authentication information
- `tunnels.json`: Stores tunnel configurations

### Server Configuration

Server configuration is stored in `.vtunnel-server/` directory:
- `config.json`: Stores server configuration
- `vtunnel.db`: SQLite database for users and tunnels
- `bg.json`: Background process information (PID and status)
- `vtunnel.log`: Server logs when running in background mode
- `vtunnel-error.log`: Error logs when running in background mode

### Proxy Configuration

Proxy configuration is stored in `.vtunnel-proxy/` directory:
- `config.json`: Stores domain and SSL settings
- `greenlock/`: Contains SSL certificate information
- `background.json`: Background process information
- `proxy-output.log`: Proxy logs when running in background
- `proxy-error.log`: Error logs for proxy in background

## Comparison with Alternatives

| Feature | V-Tunnel | Ngrok | Cloudflare Tunnel | LocalTunnel |
|---------|----------|-------|-------------------|-------------|
| Price | Free | Freemium | Freemium | Free |
| Open Source | ✅ | ❌ | ❌ | ✅ |
| Self-hosted | ✅ | ❌ | ❌ | ✅ |
| Custom domains | ✅ | ⚠️ (paid) | ✅ | ❌ |
| Multiple tunnels | ✅ | ⚠️ (limited) | ✅ | ⚠️ (limited) |
| Persistent tunnels | ✅ | ⚠️ (paid) | ✅ | ❌ |
| Background mode | ✅ | ✅ | ✅ | ❌ |
| Traffic metrics | ✅ | ✅ | ✅ | ❌ |
| SSL certificates | ✅ | ✅ | ✅ | ❌ |
| Size | 99Kb | ~15MB | ~10MB | ~5MB |

## Security Considerations

- Always use strong passwords
- Restrict access to your tunnel server
- Consider running behind a reverse proxy for TLS termination
- Set up firewall rules to restrict access to the tunnel server

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Cengiz AKCAN - me@cengizakcan.com

---

*V-Tunnel is not affiliated with any of the commercial tunnel providers mentioned.*

---

<a name="turkish"></a>

# V-Tunnel

[![npm version](https://badge.fury.io/js/v-tunnel.svg)](https://www.npmjs.com/package/v-tunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Ngrok, Cloudflare Tunnel ve diğer ticari tünel çözümlerine alternatif olarak hafif (99Kb), %100 ücretsiz ve açık kaynaklı bir çözüm.

## Özellikler

- **Hafif**: Sadece 99Kb, minimum bağımlılıklar
- **Güvenli**: JWT kimlik doğrulama ve AES-256-CBC şifreleme
- **Kullanımı kolay**: Basit komut satırı arayüzü
- **Kendi sunucunuzda çalıştırabilme**: Kendi tünel sunucunuzu işletin
- **Çoklu kullanıcı**: Birden fazla kullanıcı ve tünel desteği
- **Trafik izleme**: Tünellerden aktarılan verileri takip etme
- **Limit yok**: Çoğu ticari çözümün aksine
- **Kalıcı tüneller**: Arka plan hizmetleri olarak çalıştırma
- **Çapraz platform**: Windows, macOS ve Linux'ta çalışır
- **Arkaplan modu**: Sunucuyu daemon süreci olarak çalıştırma
- **SSL Proxy**: Özel domainler için SSL sertifikalarını otomatik yönetme

## Kurulum

```bash
npm install -g v-tunnel
```

## Hızlı Başlangıç

### Sunucu Kurulumu

Tünel sunucunuzu kurun:

```bash
vtunnel server
```

Etkileşimli kurulumu takip ederek:
1. Bir yönetici kullanıcısı oluşturun
2. Sunucu portunu yapılandırın (varsayılan: 9012)
3. Tünel port aralığını ayarlayın (varsayılan: 51200-52200)

### İstemci Kullanımı

#### Sunucuya giriş yapma

```bash
vtunnel client login
```

#### Tünel oluşturma

```bash
vtunnel client create
```

Aşağıdaki bilgileri girerek bir tünel oluşturun:
- Tünel adı
- Açıklama (isteğe bağlı)
- Yerel servis adresi (varsayılan: localhost)
- Yerel servis portu

#### Tünel başlatma

```bash
vtunnel client start
```

Yerel servisiniz artık tünel üzerinden erişilebilir!

## İstemci Komutları

| Komut | Açıklama |
|---------|-------------|
| `vtunnel client login` | Tünel sunucusuna giriş yap |
| `vtunnel client logout` | Tünel sunucusundan çıkış yap |
| `vtunnel client create` | Yeni bir tünel tanımla |
| `vtunnel client list` | Tüm tünelleri listele |
| `vtunnel client start` | Bir tünel başlat |
| `vtunnel client stop` | Çalışan bir tüneli durdur |
| `vtunnel client status` | Tünellerin durumunu göster |
| `vtunnel client details` | Bir tünelin detaylarını göster |
| `vtunnel client delete` | Bir tüneli sil |
| `vtunnel client password` | Şifrenizi değiştirin |
| `vtunnel client --help` | Yardım bilgisini göster |

## Sunucu Komutları

| Komut                                | Açıklama |
|--------------------------------------|-------------|
| `vtunnel server`                     | Tünel sunucusunu başlat |
| `vtunnel server background start`    | Tünel sunucusunu arkaplanda başlat |
| `vtunnel server background stop`     | Arkaplanda çalışan tünel sunucusunu durdur |
| `vtunnel server background status`   | Arkaplanda çalışan sunucu sürecinin durumunu kontrol et |
| `vtunnel server --port=9012`         | Kontrol sunucusu portunu belirt |
| `vtunnel server --range-start=51200` | Tünel port aralığı başlangıcını ayarla |
| `vtunnel server --range-end=52200`   | Tünel port aralığı sonunu ayarla |
| `vtunnel server --stats`             | Sunucu istatistiklerini periyodik olarak göster |
| `vtunnel server --help`              | Yardım bilgisini göster |

## Proxy Komutları

| Komut                                | Açıklama |
|--------------------------------------|-------------|
| `vtunnel proxy`                      | SSL proxy sunucusunu başlat |
| `vtunnel proxy setup`                | Proxy ayarlarını interaktif olarak yapılandır |
| `vtunnel proxy show`                 | Mevcut proxy yapılandırmasını göster |
| `vtunnel proxy background start`     | Proxy'yi arkaplanda başlat |
| `vtunnel proxy background stop`      | Arkaplanda çalışan proxy'yi durdur |
| `vtunnel proxy background status`    | Arkaplanda çalışan proxy durumunu kontrol et |

## Nasıl Çalışır

V-Tunnel istemci-sunucu mimarisi kullanır:

1. **Sunucu Bileşeni**: Tünel uç noktalarını barındırır ve trafiği yönlendirir
2. **İstemci Bileşeni**: Sunucuya bağlanır ve trafiği yerel servislere yönlendirir
3. **Proxy Bileşeni**: Domain adlarına göre trafiği yönlendirir ve SSL sertifikalarını yönetir

Bir tünel kurulduğunda:
- Sunucu tünel için bir port tahsis eder
- İstemci sunucuya bağlanır ve tüneli kaydeder
- Sunucunun tahsis edilen portuna gelen dış trafik istemciye yönlendirilir
- İstemci trafiği yerel servise yönlendirir

## SSL Proxy Özelliği

V-Tunnel, güçlü bir SSL proxy içerir:

- Tünelleriniz için özel domain adları kullanabilirsiniz
- SSL sertifikaları otomatik olarak yönetilir
- Trafik subdomain desenlerine göre yönlendirilir

Örneğin, 3000 portunda çalışan yerel bir servise tam SSL desteğiyle `3000.yourdomain.com` üzerinden erişilebilir.

Proxy yapılandırması `.vtunnel-proxy/config.json` dosyasında saklanır ve şunları içerir:
- Ana domain yapılandırması
- Subdomain eşleştirme desenleri
- SSL sertifika yönetimi (Let's Encrypt kullanarak)
- Port yapılandırmaları

## Arkaplan Servisi Olarak Çalıştırma

V-Tunnel sunucusunu ve proxy'yi arkaplan servisi olarak çalıştırabilirsiniz:

```bash
# Sunucuyu arkaplanda başlat
vtunnel server background start

# Proxy'yi arkaplanda başlat
vtunnel proxy background start

# Durumu kontrol et
vtunnel server background status
vtunnel proxy background status

# Servisleri durdur
vtunnel server background stop
vtunnel proxy background stop
```

Arkaplan modunda çalışırken:
- Sunucu logları `.vtunnel-server/vtunnel.log` dosyasına kaydedilir
- Proxy logları `.vtunnel-proxy/proxy-output.log` dosyasına kaydedilir
- Hata logları `.vtunnel-server/vtunnel-error.log` ve `.vtunnel-proxy/proxy-error.log` dosyalarına kaydedilir
- İşlem bilgileri ilgili yapılandırma dizinlerinde saklanır

## Gelişmiş Yapılandırma

### İstemci Yapılandırması

İstemci yapılandırması `.vtunnel-client/` dizininde saklanır:
- `auth.json`: Kimlik doğrulama bilgilerini saklar
- `tunnels.json`: Tünel yapılandırmalarını saklar

### Sunucu Yapılandırması

Sunucu yapılandırması `.vtunnel-server/` dizininde saklanır:
- `config.json`: Sunucu yapılandırmasını saklar
- `vtunnel.db`: Kullanıcılar ve tüneller için SQLite veritabanı
- `bg.json`: Arkaplan işlem bilgisi (PID ve durum)
- `vtunnel.log`: Arkaplanda çalışırken sunucu logları
- `vtunnel-error.log`: Arkaplanda çalışırken hata logları

### Proxy Yapılandırması

Proxy yapılandırması `.vtunnel-proxy/` dizininde saklanır:
- `config.json`: Domain ve SSL ayarlarını saklar
- `greenlock/`: SSL sertifika bilgilerini içerir
- `background.json`: Arkaplan işlem bilgisi
- `proxy-output.log`: Arkaplanda çalışırken proxy logları
- `proxy-error.log`: Arkaplanda çalışırken proxy hata logları

## Alternatiflerle Karşılaştırma

| Özellik | V-Tunnel | Ngrok | Cloudflare Tunnel | LocalTunnel |
|---------|----------|-------|-------------------|-------------|
| Fiyat | Ücretsiz | Freemium | Freemium | Ücretsiz |
| Açık Kaynak | ✅ | ❌ | ❌ | ✅ |
| Kendi sunucunuzda | ✅ | ❌ | ❌ | ✅ |
| Özel alan adları | ✅ | ⚠️ (ücretli) | ✅ | ❌ |
| Çoklu tüneller | ✅ | ⚠️ (sınırlı) | ✅ | ⚠️ (sınırlı) |
| Kalıcı tüneller | ✅ | ⚠️ (ücretli) | ✅ | ❌ |
| Arkaplan modu | ✅ | ✅ | ✅ | ❌ |
| Trafik metrikleri | ✅ | ✅ | ✅ | ❌ |
| SSL sertifikaları | ✅ | ✅ | ✅ | ❌ |
| Boyut | 99Kb | ~15MB | ~10MB | ~5MB |

## Güvenlik Hususları

- Her zaman güçlü şifreler kullanın
- Tünel sunucunuza erişimi kısıtlayın
- TLS sonlandırma için bir ters proxy arkasında çalıştırmayı düşünün
- Tünel sunucusuna erişimi kısıtlamak için güvenlik duvarı kuralları ayarlayın

## Lisans

MIT

## Katkıda Bulunma

Katkılar memnuniyetle karşılanır! Lütfen bir Pull Request göndermeye çekinmeyin.

## Yazar

Cengiz AKCAN - me@cengizakcan.com

---

*V-Tunnel, bahsedilen ticari tünel sağlayıcılarından herhangi biriyle ilişkili değildir.*
