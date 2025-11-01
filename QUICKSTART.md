# 🚀 How to Join CLI-H4X

## Quick Start Guide for Your Friends

### Step 1: Download the Client

Go to: **<https://github.com/Moon9t/CLI-H4X/releases/latest>**

Download the file for your system:

- **Windows**: `cli-h4x-client-windows-amd64.exe`
- **Mac (Intel)**: `cli-h4x-client-macos-amd64`
- **Mac (Apple Silicon)**: `cli-h4x-client-macos-arm64`
- **Linux**: `cli-h4x-client-linux-amd64`

### Step 2: Make it Executable (Mac/Linux only)

```bash
chmod +x cli-h4x-client-*
```

### Step 3: Connect to the Server

**Windows (PowerShell or CMD):**

```
.\cli-h4x-client-windows-amd64.exe -server cli-h4x.eclipse-softworks.com:443
```

**Mac/Linux:**

```bash
./cli-h4x-client-linux-amd64 -server cli-h4x.eclipse-softworks.com:443
```

### Step 4: Create Your Account

Once connected, type these commands:

```
guest@h4x> keygen
# Enter a strong passphrase (you'll need this every time you login!)

guest@h4x> register
# Solve the riddle to create your account

guest@h4x> login
# Login to activate real-time messaging

guest@h4x> upload_prekeys
# Upload encryption keys
```

### Step 5: Start Chatting

```
username@h4x> send friendname Hello! This message is encrypted!
```

---

## 🔑 Important Notes

1. **Your passphrase**: Don't forget it! You'll need it every time you connect.
2. **Riddles**: You get 2 attempts. After that, your IP is banned for 60 minutes.
3. **Security**: All messages are end-to-end encrypted using the Signal Protocol.
4. **Real-time**: Messages arrive instantly when you're logged in.

## 📋 Useful Commands

- `help` - Show all available commands
- `send <username> <message>` - Send encrypted message
- `sessions` - Show your active encrypted sessions
- `quit` - Exit the client

---

**Server**: cli-h4x.eclipse-softworks.com:443
**Project**: <https://github.com/Moon9t/CLI-H4X>
