// client.go
//go:build client
// +build client

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/scrypt"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"

	// Background colors
	bgRed     = "\033[41m"
	bgGreen   = "\033[42m"
	bgYellow  = "\033[43m"
	bgBlue    = "\033[44m"
	bgMagenta = "\033[45m"
	bgCyan    = "\033[46m"
)

// UI helper functions
func printBanner() {
	fmt.Printf("%s%s", colorCyan, colorBold)
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                    CLI-H4X CLIENT                         ║")
	fmt.Println("║              Encrypted Messaging System                   ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Printf("%s\n", colorReset)
}

func printSuccess(msg string) {
	fmt.Printf("%s✓ %s%s\n", colorGreen, msg, colorReset)
}

func printError(msg string) {
	fmt.Printf("%s✗ %s%s\n", colorRed, msg, colorReset)
}

func printWarning(msg string) {
	fmt.Printf("%s⚠ %s%s\n", colorYellow, msg, colorReset)
}

func printInfo(msg string) {
	fmt.Printf("%sℹ %s%s\n", colorCyan, msg, colorReset)
}

func printMessage(from, msg string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s%s%s: %s%s%s\n",
		colorDim, timestamp, colorReset,
		colorMagenta, from, colorReset,
		colorWhite, msg, colorReset)
}

func printPrompt(user string) {
	if user != "" {
		fmt.Printf("%s%s%s%s@h4x%s> %s", colorBold, colorGreen, user, colorCyan, colorReset, colorWhite)
	} else {
		fmt.Printf("%s%sguest%s@h4x%s> %s", colorBold, colorYellow, colorCyan, colorReset, colorWhite)
	}
}

func printHelp() {
	fmt.Printf("\n%s%sAvailable Commands:%s\n\n", colorBold, colorCyan, colorReset)

	cmds := []struct {
		cmd  string
		desc string
	}{
		{"keygen", "Generate a new keypair"},
		{"load", "Load existing keypair from storage"},
		{"register", "Register account with server (requires riddle)"},
		{"login", "Login to the server"},
		{"getpub <user>", "Get public key for a user"},
		{"send <user> <msg>", "Send encrypted message to user"},
		{"recv", "Receive pending messages"},
		{"help", "Show this help message"},
		{"quit", "Exit the client"},
	}

	for _, c := range cmds {
		fmt.Printf("  %s%-20s%s %s%s%s\n", colorYellow, c.cmd, colorReset, colorDim, c.desc, colorReset)
	}
	fmt.Println()
}

type LocalKeys struct {
	Username    string `json:"username"`
	PrivEncB64  string `json:"priv_enc"`
	PrivSignB64 string `json:"priv_sign"`
	PubEncB64   string `json:"pub_enc"`
	PubSignB64  string `json:"pub_sign"`
}

const (
	keydirName = ".cli_h4x"
	keyfile    = "keys.json.enc"
	scryptN    = 1 << 15
	scryptR    = 8
	scryptP    = 1
	aesKeyLen  = 32
)

func main() {
	server := flag.String("server", "your.server.example:5555", "server:port (TLS)")
	insecureSkipVerify := flag.Bool("insecure", false, "skip TLS verification (not recommended)")
	flag.Parse()

	printBanner()

	// prepare tls config
	tlsCfg := &tls.Config{InsecureSkipVerify: *insecureSkipVerify}

	printInfo(fmt.Sprintf("Connecting to %s...", *server))
	conn, err := tls.Dial("tcp", *server, tlsCfg)
	if err != nil {
		printError(fmt.Sprintf("Connection failed: %v", err))
		return
	}
	defer conn.Close()
	printSuccess(fmt.Sprintf("Connected to %s", *server))

	reader := bufio.NewReader(conn)

	// greet
	if ln, _ := reader.ReadString('\n'); ln != "" {
		greeting := strings.TrimSpace(ln)
		fmt.Printf("%s%s%s\n\n", colorCyan, greeting, colorReset)
	}

	if *insecureSkipVerify {
		printWarning("TLS certificate verification is disabled!")
	}

	printHelp()

	var local LocalKeys
	var haveLocal bool

	in := bufio.NewReader(os.Stdin)
	for {
		username := ""
		if haveLocal {
			username = local.Username
		}
		printPrompt(username)

		line, _ := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		cmd := parts[0]

		switch cmd {
		case "help":
			printHelp()

		case "keygen":
			fmt.Printf("%sEnter username: %s", colorCyan, colorReset)
			u, _ := in.ReadString('\n')
			u = strings.TrimSpace(u)
			if u == "" {
				printError("Username cannot be empty")
				continue
			}
			fmt.Printf("%sEnter passphrase: %s", colorCyan, colorReset)
			pass, _ := in.ReadString('\n')
			pass = strings.TrimSpace(pass)
			if len(pass) < 8 {
				printWarning("Weak passphrase! Consider using at least 8 characters")
			}

			printInfo("Generating keypair...")
			localK, err := keygenAndSave(u, pass)
			if err != nil {
				printError(fmt.Sprintf("Key generation failed: %v", err))
				continue
			}
			local = *localK
			haveLocal = true
			printSuccess(fmt.Sprintf("Keys generated and saved for user '%s'", u))
		case "load":
			fmt.Printf("%sEnter passphrase: %s", colorCyan, colorReset)
			pass, _ := in.ReadString('\n')
			pass = strings.TrimSpace(pass)

			printInfo("Loading keys...")
			k, err := loadLocalKeys(pass)
			if err != nil {
				printError(fmt.Sprintf("Failed to load keys: %v", err))
				continue
			}
			local = *k
			haveLocal = true
			printSuccess(fmt.Sprintf("Keys loaded for user '%s'", local.Username))
		case "register":
			if !haveLocal {
				printError("No local keys loaded. Run 'keygen' or 'load' first")
				continue
			}

			printInfo(fmt.Sprintf("Registering user '%s'...", local.Username))
			fmt.Fprintf(conn, "START_REGISTER %s %s %s\n", local.Username, local.PubEncB64, local.PubSignB64)
			ln, _ := reader.ReadString('\n')
			ln = strings.TrimSpace(ln)

			if strings.HasPrefix(ln, "RIDDLE ") {
				rest := strings.TrimPrefix(ln, "RIDDLE ")
				parts := strings.SplitN(rest, " ", 2)
				id := parts[0]
				question := parts[1]

				fmt.Printf("\n%s%s╔═══════════════════════════════════════════════════════╗%s\n", colorBold, colorYellow, colorReset)
				fmt.Printf("%s%s║  REGISTRATION RIDDLE                                  ║%s\n", colorBold, colorYellow, colorReset)
				fmt.Printf("%s%s╚═══════════════════════════════════════════════════════╝%s\n", colorBold, colorYellow, colorReset)
				fmt.Printf("\n%s%s%s\n\n", colorWhite, question, colorReset)
				printWarning("You have 2 attempts to answer correctly")

				attempts := 0
				for attempts < 2 {
					fmt.Printf("%sYour answer: %s", colorCyan, colorReset)
					ans, _ := in.ReadString('\n')
					ans = strings.TrimSpace(ans)

					fmt.Fprintf(conn, "ANSWER %s %s\n", id, ans)
					resp, _ := reader.ReadString('\n')
					resp = strings.TrimSpace(resp)

					if strings.HasPrefix(resp, "OK") {
						printSuccess("Registration successful! You can now login.")
						break
					}
					if strings.Contains(resp, "banned") || strings.Contains(resp, "ERR banned") {
						printError("Too many failed attempts. You are temporarily banned.")
						break
					}

					attempts++
					if attempts >= 2 {
						printError("Two failed attempts. Registration blocked.")
					} else {
						printWarning(fmt.Sprintf("Wrong answer! %d attempt remaining", 2-attempts))
					}
				}
			} else {
				printError(fmt.Sprintf("Unexpected response: %s", ln))
			}
		case "login":
			if !haveLocal {
				printError("No local keys loaded. Run 'keygen' or 'load' first")
				continue
			}

			printInfo(fmt.Sprintf("Logging in as '%s'...", local.Username))
			fmt.Fprintln(conn, "LOGIN "+local.Username)
			ln, _ := reader.ReadString('\n')
			ln = strings.TrimSpace(ln)

			if strings.HasPrefix(ln, "CHALLENGE ") {
				rest := strings.TrimPrefix(ln, "CHALLENGE ")
				fields := strings.SplitN(rest, " ", 2)
				ch := fields[0]

				printInfo("Signing authentication challenge...")
				privSignBytes, _ := base64.RawStdEncoding.DecodeString(local.PrivSignB64)
				sig := ed25519.Sign(privSignBytes, []byte(ch))
				sigB64 := base64.RawStdEncoding.EncodeToString(sig)

				fmt.Fprintln(conn, "AUTH "+sigB64)
				r2, _ := reader.ReadString('\n')
				r2 = strings.TrimSpace(r2)

				if strings.HasPrefix(r2, "OK") {
					printSuccess(fmt.Sprintf("Login successful! Welcome, %s", local.Username))
				} else {
					printError(fmt.Sprintf("Login failed: %s", r2))
				}
			} else {
				printError(fmt.Sprintf("Unexpected response: %s", ln))
			}
		case "getpub":
			if len(parts) < 2 {
				printError("Usage: getpub <username>")
				continue
			}
			target := parts[1]

			printInfo(fmt.Sprintf("Fetching public key for '%s'...", target))
			fmt.Fprintln(conn, "GETPUB "+target)
			ln, _ := reader.ReadString('\n')
			ln = strings.TrimSpace(ln)

			if strings.HasPrefix(ln, "PUB ") {
				printSuccess(fmt.Sprintf("Public key retrieved for '%s'", target))
				fmt.Printf("%s%s%s\n", colorDim, ln, colorReset)
			} else {
				printError(fmt.Sprintf("Failed: %s", ln))
			}
		case "send":
			if len(parts) < 3 {
				printError("Usage: send <username> <message>")
				continue
			}
			if !haveLocal {
				printError("No local keys loaded. Run 'keygen' or 'load' first")
				continue
			}

			to := parts[1]
			msg := parts[2]

			// Fetch recipient public key
			printInfo(fmt.Sprintf("Fetching public key for '%s'...", to))
			fmt.Fprintln(conn, "GETPUB "+to)
			ln, _ := reader.ReadString('\n')
			ln = strings.TrimSpace(ln)

			if !strings.HasPrefix(ln, "PUB ") {
				printError(fmt.Sprintf("Failed to get public key: %s", ln))
				continue
			}

			body := strings.TrimPrefix(ln, "PUB ")
			f := strings.SplitN(body, " ", 2)
			pubEncB64 := f[0]

			printInfo("Encrypting message...")
			payload, err := boxEncryptMessage(pubEncB64, local.PrivEncB64, msg)
			if err != nil {
				printError(fmt.Sprintf("Encryption failed: %v", err))
				continue
			}

			payload["to"] = to
			payload["from"] = local.Username
			js, _ := json.Marshal(payload)

			fmt.Fprintln(conn, "SEND "+string(js))
			resp, _ := reader.ReadString('\n')
			resp = strings.TrimSpace(resp)

			if strings.HasPrefix(resp, "OK") {
				printSuccess(fmt.Sprintf("Message sent to '%s'", to))
			} else {
				printError(fmt.Sprintf("Send failed: %s", resp))
			}
		case "recv":
			if !haveLocal {
				printError("No local keys loaded. Run 'keygen' or 'load' first")
				continue
			}

			printInfo("Checking for messages...")
			fmt.Fprintln(conn, "RECV")
			ln, _ := reader.ReadString('\n')
			ln = strings.TrimSpace(ln)

			if strings.HasPrefix(ln, "OK no messages") {
				printInfo("No new messages")
				continue
			}

			if strings.HasPrefix(ln, "ERR") {
				printError(ln)
				continue
			}

			// Try to parse as JSON message
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(ln), &m); err == nil {
				if _, ok := m["ciphertext"]; ok {
					printInfo("Encrypted message received, decrypting...")
					pt, err := boxDecryptIncoming(m, local)
					if err != nil {
						printError(fmt.Sprintf("Decryption failed: %v", err))
					} else {
						from, _ := m["from"].(string)
						if from == "" {
							from = "unknown"
						}
						printMessage(from, string(pt))
					}
				} else {
					// Non-encrypted message or other JSON
					fmt.Printf("%s%s%s\n", colorDim, ln, colorReset)
				}
			} else {
				// Plain text response
				fmt.Printf("%s%s%s\n", colorDim, ln, colorReset)
			}

		case "quit", "exit":
			printInfo("Logging out...")
			fmt.Fprintln(conn, "LOGOUT")
			ln, _ := reader.ReadString('\n')
			fmt.Printf("%s%s%s\n", colorCyan, strings.TrimSpace(ln), colorReset)
			printSuccess("Goodbye!")
			return

		default:
			printError(fmt.Sprintf("Unknown command: '%s'. Type 'help' for available commands", cmd))
		}
	}
}

/* --- key storage helpers --- */

func keydir() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "."
	}
	dir := filepath.Join(home, keydirName)
	_ = os.MkdirAll(dir, 0700)
	return dir
}

func keypath() string {
	return filepath.Join(keydir(), keyfile)
}

func keygenAndSave(username, pass string) (*LocalKeys, error) {
	pubEnc, privEnc, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pubSign, privSign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	l := &LocalKeys{
		Username:    username,
		PrivEncB64:  base64.RawStdEncoding.EncodeToString((*privEnc)[:]),
		PrivSignB64: base64.RawStdEncoding.EncodeToString(privSign),
		PubEncB64:   base64.RawStdEncoding.EncodeToString((*pubEnc)[:]),
		PubSignB64:  base64.RawStdEncoding.EncodeToString(pubSign),
	}
	js, _ := json.Marshal(l)
	cipher, err := encryptWithPass([]byte(pass), js)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keypath(), cipher, 0600); err != nil {
		return nil, err
	}
	return l, nil
}

func encryptWithPass(pass, plain []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key(pass, salt, scryptN, scryptR, scryptP, aesKeyLen)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, nil)
	out := append(salt, nonce...)
	out = append(out, ct...)
	return out, nil
}

func loadLocalKeys(pass string) (*LocalKeys, error) {
	b, err := os.ReadFile(keypath())
	if err != nil {
		return nil, err
	}
	if len(b) < 16+chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("bad keyfile")
	}
	salt := b[:16]
	nonce := b[16 : 16+chacha20poly1305.NonceSizeX]
	ct := b[16+chacha20poly1305.NonceSizeX:]
	key, err := scrypt.Key([]byte(pass), salt, scryptN, scryptR, scryptP, aesKeyLen)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	var l LocalKeys
	if err := json.Unmarshal(plain, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

/* --- box encrypt helpers (ephemeral per message) --- */

func boxEncryptMessage(recipientPubEncB64, senderPrivEncB64, msg string) (map[string]string, error) {
	rPub, err := base64.RawStdEncoding.DecodeString(recipientPubEncB64)
	if err != nil {
		return nil, err
	}
	sPriv, err := base64.RawStdEncoding.DecodeString(senderPrivEncB64)
	if err != nil {
		return nil, err
	}
	var rPubArr [32]byte
	var sPrivArr [32]byte
	copy(rPubArr[:], rPub)
	copy(sPrivArr[:], sPriv)
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := box.Seal(nil, []byte(msg), (*[24]byte)(nonce), &rPubArr, ephPriv)
	out := map[string]string{
		"eph_pub":    base64.RawStdEncoding.EncodeToString((*ephPub)[:]),
		"nonce":      base64.RawStdEncoding.EncodeToString(nonce),
		"ciphertext": base64.RawStdEncoding.EncodeToString(ct),
	}
	return out, nil
}

func boxDecryptIncoming(m map[string]interface{}, local LocalKeys) ([]byte, error) {
	ephB64, _ := m["eph_pub"].(string)
	nonceB64, _ := m["nonce"].(string)
	ctB64, _ := m["ciphertext"].(string)
	if ephB64 == "" || nonceB64 == "" || ctB64 == "" {
		return nil, fmt.Errorf("missing fields")
	}
	eph, _ := base64.RawStdEncoding.DecodeString(ephB64)
	nonce, _ := base64.RawStdEncoding.DecodeString(nonceB64)
	ct, _ := base64.RawStdEncoding.DecodeString(ctB64)
	privEnc, _ := base64.RawStdEncoding.DecodeString(local.PrivEncB64)
	var ephArr [32]byte
	var privArr [32]byte
	copy(ephArr[:], eph)
	copy(privArr[:], privEnc)
	var nonceArr [24]byte
	copy(nonceArr[:], nonce)
	plain, ok := box.Open(nil, ct, &nonceArr, &ephArr, &privArr)
	if !ok {
		return nil, fmt.Errorf("decrypt failed")
	}
	return plain, nil
}
