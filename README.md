# V-Tunnel

[![npm version](https://badge.fury.io/js/vtunnel.svg)](https://www.npmjs.com/package/vtunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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

## Installation

```bash
npm install -g vtunnel
```

## Quick Start

### Server Setup

Set up your tunnel server:

```bash
vtunnel-server
```

Follow the interactive setup to:
1. Create an admin user
2. Configure server port (default: 9012)
3. Set tunnel port range (default: 51200-52200)

### Client Usage

#### Login to server

```bash
vtunnel login
```

#### Create a tunnel

```bash
vtunnel create
```

Follow the prompts to create a tunnel with:
- Tunnel name
- Description (optional)
- Local service address (default: localhost)
- Local service port

#### Start a tunnel

```bash
vtunnel start
```

Your local service is now accessible through the tunnel!

## Client Commands

| Command | Description |
|---------|-------------|
| `vtunnel login` | Log in to the tunnel server |
| `vtunnel logout` | Log out from the tunnel server |
| `vtunnel create` | Define a new tunnel |
| `vtunnel list` | List all tunnels |
| `vtunnel start` | Start a tunnel |
| `vtunnel stop` | Stop a running tunnel |
| `vtunnel status` | Show status of tunnels |
| `vtunnel details` | Show details of a tunnel |
| `vtunnel delete` | Delete a tunnel |
| `vtunnel password` | Change your password |
| `vtunnel --help` | Show help information |

## Server Commands

| Command | Description |
|---------|-------------|
| `vtunnel-server` | Start the tunnel server |
| `vtunnel-server --port=9012` | Specify control server port |
| `vtunnel-server --range-start=51200` | Set tunnel port range start |
| `vtunnel-server --range-end=52200` | Set tunnel port range end |
| `vtunnel-server --stats` | Display server stats periodically |
| `vtunnel-server --help` | Show help information |

## How It Works

V-Tunnel uses a client-server architecture:

1. **Server Component**: Hosts the tunnel endpoints and routes traffic
2. **Client Component**: Connects to the server and forwards traffic to local services

When a tunnel is established:
- The server allocates a port for the tunnel
- The client connects to the server and registers the tunnel
- External traffic to the server's allocated port is forwarded to the client
- The client forwards traffic to the local service

## Advanced Configuration

### Client Configuration

Client configuration is stored in `.vtunnel-client/` directory:
- `auth.json`: Stores authentication information
- `tunnels.json`: Stores tunnel configurations

### Server Configuration

Server configuration is stored in `.vtunnel-server/` directory:
- `config.json`: Stores server configuration
- `vtunnel.db`: SQLite database for users and tunnels

## Comparison with Alternatives

| Feature | V-Tunnel | Ngrok | Cloudflare Tunnel | LocalTunnel |
|---------|----------|-------|-------------------|-------------|
| Price | Free | Freemium | Freemium | Free |
| Open Source | ✅ | ❌ | ❌ | ✅ |
| Self-hosted | ✅ | ❌ | ❌ | ✅ |
| Custom domains | ✅ | ⚠️ (paid) | ✅ | ❌ |
| Multiple tunnels | ✅ | ⚠️ (limited) | ✅ | ⚠️ (limited) |
| Persistent tunnels | ✅ | ⚠️ (paid) | ✅ | ❌ |
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

[![npm version](https://badge.fury.io/js/vtunnel.svg)](https://www.npmjs.com/package/vtunnel)
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

## Kurulum

```bash
npm install -g vtunnel
```

## Hızlı Başlangıç

### Sunucu Kurulumu

Tünel sunucunuzu kurun:

```bash
vtunnel-server
```

Etkileşimli kurulumu takip ederek:
1. Bir yönetici kullanıcısı oluşturun
2. Sunucu portunu yapılandırın (varsayılan: 9012)
3. Tünel port aralığını ayarlayın (varsayılan: 51200-52200)

### İstemci Kullanımı

#### Sunucuya giriş yapma

```bash
vtunnel login
```

#### Tünel oluşturma

```bash
vtunnel create
```

Aşağıdaki bilgileri girerek bir tünel oluşturun:
- Tünel adı
- Açıklama (isteğe bağlı)
- Yerel servis adresi (varsayılan: localhost)
- Yerel servis portu

#### Tünel başlatma

```bash
vtunnel start
```

Yerel servisiniz artık tünel üzerinden erişilebilir!

## İstemci Komutları

| Komut | Açıklama |
|---------|-------------|
| `vtunnel login` | Tünel sunucusuna giriş yap |
| `vtunnel logout` | Tünel sunucusundan çıkış yap |
| `vtunnel create` | Yeni bir tünel tanımla |
| `vtunnel list` | Tüm tünelleri listele |
| `vtunnel start` | Bir tünel başlat |
| `vtunnel stop` | Çalışan bir tüneli durdur |
| `vtunnel status` | Tünellerin durumunu göster |
| `vtunnel details` | Bir tünelin detaylarını göster |
| `vtunnel delete` | Bir tüneli sil |
| `vtunnel password` | Şifrenizi değiştirin |
| `vtunnel --help` | Yardım bilgisini göster |

## Sunucu Komutları

| Komut | Açıklama |
|---------|-------------|
| `vtunnel-server` | Tünel sunucusunu başlat |
| `vtunnel-server --port=9012` | Kontrol sunucusu portunu belirt |
| `vtunnel-server --range-start=51200` | Tünel port aralığı başlangıcını ayarla |
| `vtunnel-server --range-end=52200` | Tünel port aralığı sonunu ayarla |
| `vtunnel-server --stats` | Sunucu istatistiklerini periyodik olarak göster |
| `vtunnel-server --help` | Yardım bilgisini göster |

## Nasıl Çalışır

V-Tunnel istemci-sunucu mimarisi kullanır:

1. **Sunucu Bileşeni**: Tünel uç noktalarını barındırır ve trafiği yönlendirir
2. **İstemci Bileşeni**: Sunucuya bağlanır ve trafiği yerel servislere yönlendirir

Bir tünel kurulduğunda:
- Sunucu tünel için bir port tahsis eder
- İstemci sunucuya bağlanır ve tüneli kaydeder
- Sunucunun tahsis edilen portuna gelen dış trafik istemciye yönlendirilir
- İstemci trafiği yerel servise yönlendirir

## Gelişmiş Yapılandırma

### İstemci Yapılandırması

İstemci yapılandırması `.vtunnel-client/` dizininde saklanır:
- `auth.json`: Kimlik doğrulama bilgilerini saklar
- `tunnels.json`: Tünel yapılandırmalarını saklar

### Sunucu Yapılandırması

Sunucu yapılandırması `.vtunnel-server/` dizininde saklanır:
- `config.json`: Sunucu yapılandırmasını saklar
- `vtunnel.db`: Kullanıcılar ve tüneller için SQLite veritabanı

## Alternatiflerle Karşılaştırma

| Özellik | V-Tunnel | Ngrok | Cloudflare Tunnel | LocalTunnel |
|---------|----------|-------|-------------------|-------------|
| Fiyat | Ücretsiz | Freemium | Freemium | Ücretsiz |
| Açık Kaynak | ✅ | ❌ | ❌ | ✅ |
| Kendi sunucunuzda | ✅ | ❌ | ❌ | ✅ |
| Özel alan adları | ✅ | ⚠️ (ücretli) | ✅ | ❌ |
| Çoklu tüneller | ✅ | ⚠️ (sınırlı) | ✅ | ⚠️ (sınırlı) |
| Kalıcı tüneller | ✅ | ⚠️ (ücretli) | ✅ | ❌ |
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
