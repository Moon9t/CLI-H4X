# CLI-H4X v2.0 - Secure Messaging System

**🌙 Moon9t Edition - Signal Protocol • Real-time Messaging**

CLI-H4X is a secure, end-to-end encrypted messaging system using the Signal Protocol with real-time delivery.

## 🚀 Quick Start

### For Users (Connecting to Server)

1. **Download the client** for your platform:
   - **Linux (x64)**: `cli-h4x-client-linux-amd64`
   - **Linux (ARM64)**: `cli-h4x-client-linux-arm64`
   - **Windows**: `cli-h4x-client-windows-amd64.exe`
   - **macOS (Intel)**: `cli-h4x-client-macos-amd64`
   - **macOS (Apple Silicon)**: `cli-h4x-client-macos-arm64`

2. **Make executable** (Linux/macOS):
   ```bash
   chmod +x cli-h4x-client-*
   ```

3. **Connect to the server**:
   ```bash
   # Linux/macOS
   ./cli-h4x-client-linux-amd64 -server cli-h4x.eclipse-softworks.com:443
   
   # Windows (PowerShell)
   .\cli-h4x-client-windows-amd64.exe -server cli-h4x.eclipse-softworks.com:443
   ```

4. **First-time setup**:
   ```
   guest@h4x> keygen          # Generate encryption keys
   guest@h4x> register        # Solve riddle to create account
   guest@h4x> login           # Login to enable real-time messaging
   guest@h4x> upload_prekeys  # Upload pre-keys for Signal protocol
   ```

5. **Send encrypted messages**:
   ```
   username@h4x> send friend_username Hello, this is encrypted!
   ```

## 🔒 Security Features

- ✅ **Signal Protocol**: X25519 ECDH key exchange, Ed25519 signatures
- ✅ **Perfect Forward Secrecy**: Double-ratchet algorithm
- ✅ **End-to-End Encryption**: ChaCha20-Poly1305 AEAD
- ✅ **TLS 1.3**: Secure transport layer
- ✅ **Riddle Registration**: Human verification system
- ✅ **IP Banning**: Protection against brute force attacks
- ✅ **Rate Limiting**: 10 commands/second with burst of 5

## 📋 Available Commands

| Command | Description |
|---------|-------------|
| `keygen` | Generate new Signal protocol keypair |
| `load` | Load existing keypair from storage |
| `register` | Register account with server (requires riddle) |
| `login` | Login to the server (enables real-time messages) |
| `upload_prekeys` | Upload 100 one-time pre-keys to server |
| `send <user> <msg>` | Send encrypted message using Signal protocol |
| `recv` | Manually check for queued messages |
| `sessions` | List active Signal sessions |
| `help` | Show help message |
| `quit` | Exit the client |

## 🌐 Server Information

**Public Server**: `cli-h4x.eclipse-softworks.com:443`

- Hosted via Cloudflare Tunnel
- TLS certificate validated by Cloudflare
- Real-time message delivery
- Discord webhook notifications for admins

## 🛠️ For Server Operators

Download `cli-h4x-server-linux-amd64` and run:

```bash
./cli-h4x-server-linux-amd64 -addr 0.0.0.0:8443 -db messages.db
```

**Server Options**:
- `-addr`: Listen address (default: 0.0.0.0:5555)
- `-db`: SQLite database file (default: cli_h4x.db)
- `-cert`: TLS certificate (default: certs/server.crt)
- `-key`: TLS private key (default: certs/server.key)
- `-admin_webhook`: Discord webhook URL for notifications
- `-admin_ips`: Comma-separated admin IPs
- `-ban_min`: Ban duration in minutes (default: 60)

## 🔐 Riddles

New users must solve one of three riddles during registration:
1. **Echo Riddle**: "I speak without a mouth and hear without ears..."
2. **Candle Riddle**: "The more you take, the more you leave behind..."
3. **Keyboard Riddle**: "What has keys but no locks..."

Users get 2 attempts before their IP is banned for 60 minutes.

## 📦 Building from Source

```bash
# Install dependencies
go mod download

# Build client
go build -tags client_v2 -o cli-h4x-client client_v2.go client_v2_commands.go client_v2_sessions.go animations.go

# Build server
go build -tags server -o cli-h4x-server server.go

# Build all platforms
./build-release.sh v1.0.0
```

## 📄 License

© 2025 Moon9t - Secure • Private • Encrypted

## 🐛 Issues & Support

Report issues or request features via GitHub Issues.

---

**Note**: This is cryptographic software. Use at your own risk. Review the code before trusting it with sensitive communications.
