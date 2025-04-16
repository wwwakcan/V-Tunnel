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
- **Web Management Panel**: Control your tunnels through a web interface
- **Self-hostable**: Run your own tunnel server
- **Multi-user**: Support for multiple users and tunnels
- **Traffic monitoring**: Track data transferred through tunnels
- **No rate limits**: Unlike most commercial solutions
- **Persistent tunnels**: Run as background services
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Background mode**: Run server as a daemon process
- **API Mode**: Run an API server for management

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

After logging in, the management panel is automatically activated at http://localhost:9011.

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

## Web Management Panel

After logging in, a web management panel is automatically activated at:
```
http://localhost:9011
```

The management panel provides advanced features:
- Adding new tunnels
- Examining tunnel details
- Starting and stopping tunnels
- Deleting tunnels
- Viewing detailed statistics

## Client Commands

| Command                | Description |
|------------------------|-------------|
| `vtunnel client login` | Log in to the tunnel server (automatically activates web panel) |
| `vtunnel client logout`       | Log out from the tunnel server |
| `vtunnel client create`       | Define a new tunnel |
| `vtunnel client list`         | List all tunnels |
| `vtunnel client start`        | Start a tunnel |
| `vtunnel client stop`         | Stop a running tunnel |
| `vtunnel client status`       | Show status of tunnels |
| `vtunnel client details`      | Show details of a tunnel |
| `vtunnel client delete`       | Delete a tunnel |
| `vtunnel client password`     | Change your password |
| `vtunnel client api start`    | Start the API server for management |
| `vtunnel client api stop`     | Stop the API server |
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

## How It Works

V-Tunnel uses a client-server architecture:

1. **Server Component**: Hosts the tunnel endpoints and routes traffic
2. **Client Component**: Connects to the server and forwards traffic to local services
3. **Management Panel**: Web interface for controlling tunnels (automatically activated after login)
4. **API Server**: Provides programmatic access to tunnel management

When a tunnel is established:
- The server allocates a port for the tunnel
- The client connects to the server and registers the tunnel
- External traffic to the server's allocated port is forwarded to the client
- The client forwards traffic to the local service

## Running as a Background Service

You can run V-Tunnel server as a background service:

```bash
# Start the server in background mode
vtunnel server background start

# Check if the server is running
vtunnel server background status

# Stop the background server
vtunnel server background stop
```

When running in background mode:
- Server logs are saved to `.vtunnel-server/vtunnel.log`
- Error logs are saved to `.vtunnel-server/vtunnel-error.log`
- Process information is stored in `.vtunnel-server/bg.json`

## API Mode

You can start and stop the API server for programmatic management:

```bash
# Start the API server
vtunnel client api start

# Stop the API server
vtunnel client api stop
```

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

## Comparison with Alternatives

| Feature | V-Tunnel | Ngrok | Cloudflare Tunnel | LocalTunnel |
|---------|----------|-------|-------------------|-------------|
| Price | Free | Freemium | Freemium | Free |
| Open Source | ✅ | ❌ | ❌ | ✅ |
| Self-hosted | ✅ | ❌ | ❌ | ✅ |
| Web UI | ✅ | ✅ | ✅ | ❌ |
| API Access | ✅ | ✅ | ✅ | ❌ |
| Custom domains | ✅ | ⚠️ (paid) | ✅ | ❌ |
| Multiple tunnels | ✅ | ⚠️ (limited) | ✅ | ⚠️ (limited) |
| Persistent tunnels | ✅ | ⚠️ (paid) | ✅ | ❌ |
| Background mode | ✅ | ✅ | ✅ | ❌ |
| Traffic metrics | ✅ | ✅ | ✅ | ❌ |
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
- **Web Yönetim Paneli**: Tünellerinizi web arayüzü üzerinden kontrol edin
- **Kendi sunucunuzda çalıştırabilme**: Kendi tünel sunucunuzu işletin
- **Çoklu kullanıcı**: Birden fazla kullanıcı ve tünel desteği
- **Trafik izleme**: Tünellerden aktarılan verileri takip etme
- **Limit yok**: Çoğu ticari çözümün aksine
- **Kalıcı tüneller**: Arka plan hizmetleri olarak çalıştırma
- **Çapraz platform**: Windows, macOS ve Linux'ta çalışır
- **Arkaplan modu**: Sunucuyu daemon süreci olarak çalıştırma
- **API Modu**: Yönetim için API sunucusu çalıştırma

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

Giriş yaptıktan sonra, yönetim paneli otomatik olarak http://localhost:9011 adresinde aktif olur.

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

## Web Yönetim Paneli

Giriş yaptıktan sonra, web yönetim paneli otomatik olarak şu adreste aktif olur:
```
http://localhost:9011
```

Yönetim paneli gelişmiş özellikler sunar:
- Yeni tüneller ekleme
- Tünel detaylarını inceleme
- Tünelleri başlatma ve durdurma
- Tünelleri silme
- Detaylı istatistikleri görüntüleme

## İstemci Komutları

| Komut | Açıklama |
|---------|-------------|
| `vtunnel client login` | Tünel sunucusuna giriş yap (otomatik olarak web panelini aktifleştirir) |
| `vtunnel client logout` | Tünel sunucusundan çıkış yap |
| `vtunnel client create` | Yeni bir tünel tanımla |
| `vtunnel client list` | Tüm tünelleri listele |
| `vtunnel client start` | Bir tünel başlat |
| `vtunnel client stop` | Çalışan bir tüneli durdur |
| `vtunnel client status` | Tünellerin durumunu göster |
| `vtunnel client details` | Bir tünelin detaylarını göster |
| `vtunnel client delete` | Bir tüneli sil |
| `vtunnel client password` | Şifrenizi değiştirin |
| `vtunnel client api start` | Yönetim için API sunucusunu başlat |
| `vtunnel client api stop` | API sunucusunu durdur |
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

## Nasıl Çalışır

V-Tunnel istemci-sunucu mimarisi kullanır:

1. **Sunucu Bileşeni**: Tünel uç noktalarını barındırır ve trafiği yönlendirir
2. **İstemci Bileşeni**: Sunucuya bağlanır ve trafiği yerel servislere yönlendirir
3. **Yönetim Paneli**: Tünelleri kontrol etmek için web arayüzü (giriş yapıldıktan sonra otomatik aktif olur)
4. **API Sunucusu**: Tünel yönetimi için programatik erişim sağlar

Bir tünel kurulduğunda:
- Sunucu tünel için bir port tahsis eder
- İstemci sunucuya bağlanır ve tüneli kaydeder
- Sunucunun tahsis edilen portuna gelen dış trafik istemciye yönlendirilir
- İstemci trafiği yerel servise yönlendirir

## Arkaplan Servisi Olarak Çalıştırma

V-Tunnel sunucusunu bir arkaplan servisi olarak çalıştırabilirsiniz:

```bash
# Sunucuyu arkaplanda başlat
vtunnel server background start

# Sunucunun çalışıp çalışmadığını kontrol et
vtunnel server background status

# Arkaplan sunucusunu durdur
vtunnel server background stop
```

Arkaplan modunda çalışırken:
- Sunucu logları `.vtunnel-server/vtunnel.log` dosyasına kaydedilir
- Hata logları `.vtunnel-server/vtunnel-error.log` dosyasına kaydedilir
- İşlem bilgileri `.vtunnel-server/bg.json` dosyasında saklanır

## API Modu

Programatik yönetim için API sunucusunu başlatabilir ve durdurabilirsiniz:

```bash
# API sunucusunu başlat
vtunnel client api start

# API sunucusunu durdur
vtunnel client api stop
```

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

## Alternatiflerle Karşılaştırma

| Özellik | V-Tunnel | Ngrok | Cloudflare Tunnel | LocalTunnel |
|---------|----------|-------|-------------------|-------------|
| Fiyat | Ücretsiz | Freemium | Freemium | Ücretsiz |
| Açık Kaynak | ✅ | ❌ | ❌ | ✅ |
| Kendi sunucunuzda | ✅ | ❌ | ❌ | ✅ |
| Web Arayüzü | ✅ | ✅ | ✅ | ❌ |
| API Erişimi | ✅ | ✅ | ✅ | ❌ |
| Özel alan adları | ✅ | ⚠️ (ücretli) | ✅ | ❌ |
| Çoklu tüneller | ✅ | ⚠️ (sınırlı) | ✅ | ⚠️ (sınırlı) |
| Kalıcı tüneller | ✅ | ⚠️ (ücretli) | ✅ | ❌ |
| Arkaplan modu | ✅ | ✅ | ✅ | ❌ |
| Trafik metrikleri | ✅ | ✅ | ✅ | ❌ |
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
