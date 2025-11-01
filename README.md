# CLI-H4X v1.0.0 🔐

**Secure TLS relay server with Signal double-ratchet E2EE, riddle-based registration, IP ban system, and admin monitoring.**

## 🚀 Quick Download

**[📦 Download Latest Release](https://github.com/Moon9t/CLI-H4X/releases/latest)** - Available for Linux, Windows, and macOS

**Public Server**: `cli-h4x.eclipse-softworks.com:443`

👉 **[Quick Start Guide for Users](QUICKSTART.md)**

---

## 💻 Platform-Specific Instructions

### 🪟 Windows

#### Client Usage
```cmd
REM Download cli-h4x-client-windows-amd64.exe from releases
cli-h4x-client-windows-amd64.exe -server cli-h4x.eclipse-softworks.com:443

REM Commands work the same as Linux/macOS
> keygen
> register
> login
> upload_prekeys
> send username message
`````

## 🎯 Features

### Security

- **Signal Protocol**: End-to-end encryption using double-ratchet algorithm
- **TLS 1.3 Only**: Hardened TLS configuration with strong cipher suites
- **Pre-key Bundles**: X25519 key exchange with one-time pre-keys
- **Ed25519 Authentication**: Challenge-response authentication
- **Rate Limiting**: Per-IP rate limiting to prevent abuse
- **IP Banning**: Automatic banning after failed registration attempts
- **Admin Whitelist**: IP-based access control for admin endpoints

### Features

- **Riddle Registration Gate**: Human verification during registration
- **Message Queuing**: Offline message delivery
- **Session Persistence**: SQLite-backed session storage
- **Admin Notifications**: Email and Discord webhook alerts
- **Pre-key Management**: Automated one-time pre-key rotation

## 📋 Prerequisites

- Go 1.20+
- Docker & Docker Compose (optional)
- TLS certificates (self-signed or from CA)
- SMTP server (for email notifications)
- Discord webhook (optional, for Discord notifications)

## 🚀 Quick Start

### 1. Generate TLS Certificates

```bash
# Self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Run with Docker Compose

```bash
docker-compose up -d
```

### 4. Or Run Manually

```bash
# Install dependencies
go mod download

# Run server
go run server.go -addr 0.0.0.0:5555 -cert certs/server.crt -key certs/server.key

# Run webhook receiver (separate terminal)
go run webhook_receiver.go -port 8080

# Run client
go run client.go -server localhost:5555 -insecure
```

## 📖 Usage Guide

### Client Commands

```
keygen           - Generate new cryptographic keypair
load             - Load existing keys from encrypted file
register         - Register username on server (includes riddle)
login            - Authenticate with server
upload_prekeys   - Upload 100 one-time pre-keys
send <user> <msg>- Send encrypted message to user
recv             - Receive and decrypt incoming messages
quit             - Logout and exit
```

### Example Session

```bash
# Terminal 1: Client A
$ go run client.go -server localhost:5555 -insecure
> keygen
Username: alice
Passphrase: ********
✓ Keys generated and saved

> register
Riddle: I speak without a mouth...
Answer: echo
✓ OK registered

> login
✓ OK logged-in

> upload_prekeys
Generating 100 one-time pre-keys... done
OK prekeys uploaded

> send bob Hello Bob!
✓ Message sent

# Terminal 2: Client B
$ go run client.go -server localhost:5555 -insecure
> load
Passphrase: ********
✓ Keys loaded for bob

> login
✓ OK logged-in

> recv
✉ From: alice
   Message: Hello Bob!
```

## 🏗️ Architecture

### Protocol Flow

```
1. Registration:
   Client → START_REGISTER → Server
   Server → RIDDLE → Client
   Client → ANSWER → Server
   Server → OK registered

2. Authentication:
   Client → LOGIN → Server
   Server → CHALLENGE → Client
   Client → AUTH(signature) → Server
   Server → OK logged-in

3. Message Sending:
   Client A → GETBUNDLE(B) → Server
   Server → BUNDLE → Client A
   [Client A initializes Signal session]
   Client A → SEND(encrypted) → Server
   Server → [Queue or deliver] → Client B
```

### Encryption Layers

1. **Transport**: TLS 1.3 (server to client)
2. **End-to-End**: Signal double-ratchet (client to client)
3. **Storage**: ChaCha20-Poly1305 (local key storage)

### Database Schema

**Server (cli_h4x.db):**

- `users`: User accounts with identity keys
- `prekey_bundles`: Signed pre-keys per user
- `onetime_prekeys`: One-time pre-keys pool
- `queued`: Offline message queue
- `bans`: IP ban list with expiration
- `attempts`: Failed authentication attempts
- `pending_riddle`: Pending registration challenges
- `rate_limits`: Rate limiting state

**Client (sessions.db):**

- `sessions`: Active Signal sessions with peers
- `onetime_prekeys`: Local pre-key storage

## 🛡️ Security Features

### Rate Limiting

- 10 requests per minute per IP
- Applies to registration, login, and message sending
- Automatic cleanup of old rate limit entries

### IP Banning

- 2 failed riddle attempts → 60-minute ban (configurable)
- Ban persistence across restarts
- Admin notification on ban events

### TLS Hardening

```go
MinVersion: TLS 1.3
CipherSuites:
  - TLS_AES_256_GCM_SHA384
  - TLS_AES_128_GCM_SHA256
  - TLS_CHACHA20_POLY1305_SHA256
```

### Webhook Security

- Bearer token authentication
- Constant-time comparison to prevent timing attacks
- Request size limits (1MB max)
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Method and Content-Type validation

## 📊 Admin Endpoints

### Server Stats (IP-whitelisted)

```bash
# Connect and authenticate
> STATS
{
  "users_registered": 42,
  "queued_messages": 5,
  "active_bans": 3,
  "online_users": 12,
  "timestamp": 1730477934
}
```

Configure admin IPs via environment:

```bash
export ADMIN_IPS="192.168.1.100,10.0.0.5"
```

## 🔔 Notifications

### Email Notifications

Requires SMTP configuration in `.env`:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
EMAIL_TO=admin@yourdomain.com
```

### Discord Notifications

Create a Discord webhook and add to `.env`:

```
DISCORD_WEBHOOK=https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
```

Notifications include:

- Failed riddle attempts
- IP bans
- Rate limit violations
- Authentication failures

## 🐳 Docker Deployment

### Production Setup

1. **Generate production certificates:**

```bash
# Using Let's Encrypt
certbot certonly --standalone -d your-domain.com
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem certs/server.crt
cp /etc/letsencrypt/live/your-domain.com/privkey.pem certs/server.key
```

2. **Configure firewall:**

```bash
ufw allow 5555/tcp comment 'CLI-H4X server'
ufw allow 8080/tcp comment 'CLI-H4X webhook'
```

3. **Set environment variables:**

```bash
cp .env.example .env
nano .env  # Fill in your values
```

4. **Deploy:**

```bash
docker-compose up -d
docker-compose logs -f  # Monitor logs
```

### Backup

```bash
# Backup server database
docker cp cli_h4x_server:/data/cli_h4x.db ./backups/cli_h4x_$(date +%Y%m%d).db

# Restore
docker cp ./backups/cli_h4x_20241101.db cli_h4x_server:/data/cli_h4x.db
docker-compose restart server
```

## 🔧 Configuration

### Server Flags

```
-addr string          Listen address (default "0.0.0.0:5555")
-db string            SQLite database file (default "cli_h4x.db")
-cert string          TLS certificate file (default "server.crt")
-key string           TLS private key file (default "server.key")
-admin_webhook string Admin webhook URL
-ban_min int          Ban duration in minutes (default 60)
```

### Environment Variables

```
ADMIN_WEBHOOK    - Webhook receiver URL
ADMIN_IPS        - Comma-separated admin IPs
WEBHOOK_SECRET   - Authentication token for webhook
```

## 🧪 Testing

### Unit Tests

```bash
go test ./...
```

### Integration Test

```bash
# Terminal 1: Start server
go run server.go -insecure

# Terminal 2: Run test client
./test_client.sh
```

### Load Testing

```bash
# Install hey (HTTP load testing tool)
go install github.com/rakyll/hey@latest

# Test webhook receiver
hey -n 1000 -c 10 \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -m POST \
  -d '{"ip":"test","username":"test","attempts":1,"timestamp":1234,"reason":"load test"}' \
  http://localhost:8080/webhook
```

## 🐛 Troubleshooting

### Connection refused

```bash
# Check if server is running
netstat -tlnp | grep 5555

# Check TLS certificate
openssl s_client -connect localhost:5555 -showcerts
```

### Authentication failed

```bash
# Verify keys match
> keygen
> register
# Ensure you use 'load' with same passphrase later
```

### Rate limit exceeded

```bash
# Wait 1 minute or restart server to clear
docker-compose restart server
```

### Webhook not receiving notifications

```bash
# Check webhook logs
docker logs cli_h4x_webhook

# Test webhook manually
curl -X POST http://localhost:8080/webhook \
  -H "Authorization: Bearer your-secret" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","username":"test","attempts":1,"timestamp":1234,"reason":"test"}'
```

## 📚 Protocol Specification

### Wire Protocol

All messages are line-delimited text over TLS.

#### Registration

```
C: START_REGISTER <username> <identity_key> <pub_sign> <signed_prekey> <prekey_sig>
S: RIDDLE <id> <question>
C: ANSWER <id> <answer>
S: OK registered | ERR <reason>
```

#### Authentication

```
C: LOGIN <username>
S: CHALLENGE <nonce> <pub_sign>
C: AUTH <ed25519_signature>
S: OK logged-in | ERR <reason>
```

#### Messaging

```
C: GETBUNDLE <username>
S: BUNDLE <json>
C: SEND <json_payload>
S: OK sent | ERR <reason>
```

### Message Format

```json
{
  "to": "bob",
  "type": "prekey_message",
  "identity_key": "...",
  "ephemeral_key": "...",
  "ciphertext": "...",
  "onetime_prekey": "...",
  "counter": 0
}
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -am 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📜 License

MIT License - see LICENSE file for details

## ⚠️ Security Notice

This is a reference implementation. For production use:

1. Conduct security audit
2. Use proper key management (HSM, KMS)
3. Implement certificate pinning
4. Add rate limiting at network level
5. Enable comprehensive logging
6. Set up monitoring and alerting
7. Follow OWASP best practices

## 📞 Support

- Issues: GitHub Issues
- Discussions: GitHub Discussions
- Security: <security@yourdomain.com>

---

**Built with ❤️ for secure communications**
