// client_v2.go - Signal protocol enabled client with real-time messaging
//go:build !server
// +build !server

package main

import (
	"bufio"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/time/rate"

	_ "cli-h4x/signal" // Used in client_v2_sessions.go
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
)

type LocalKeys struct {
	Username      string `json:"username"`
	IdentityPriv  string `json:"identity_priv"`   // X25519 private key
	IdentityPub   string `json:"identity_pub"`    // X25519 public key
	SignedPrePriv string `json:"signed_pre_priv"` // Signed pre-key private
	SignedPrePub  string `json:"signed_pre_pub"`  // Signed pre-key public
	SignedPreSig  string `json:"signed_pre_sig"`  // Ed25519 signature
	PrivSignB64   string `json:"priv_sign"`       // Ed25519 signing key
	PubSignB64    string `json:"pub_sign"`        // Ed25519 verify key
}

type Client struct {
	conn     *tls.Conn
	reader   *bufio.Reader
	local    LocalKeys
	db       *sql.DB
	mu       sync.Mutex
	loggedIn bool
	limiter  *rate.Limiter // Rate limiter for commands
}

const (
	keydirName = ".cli_h4x"
	keyfile    = "keys.json.enc"
	dbfile     = "sessions.db"
	scryptN    = 1 << 15
	scryptR    = 8
	scryptP    = 1
	aesKeyLen  = 32
)

// UI helper functions
func printBanner() {
	fmt.Printf("%s%s", colorCyan, colorBold)
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                CLI-H4X CLIENT v2.0                        ║")
	fmt.Println("║         Signal Protocol • Real-time Messaging            ║")
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
	fmt.Printf("%sℹ %s%s\n", colorBlue, msg, colorReset)
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
	printBanner()
	fmt.Printf("\n%s%sAvailable Commands:%s\n\n", colorBold, colorCyan, colorReset)

	cmds := []struct {
		cmd  string
		desc string
	}{
		{"keygen", "Generate new Signal protocol keypair"},
		{"load", "Load existing keypair from storage"},
		{"register", "Register account with server (requires riddle)"},
		{"login", "Login to the server (enables real-time messages)"},
		{"upload_prekeys", "Upload 100 one-time pre-keys to server"},
		{"send <user> <msg>", "Send encrypted message using Signal protocol"},
		{"recv", "Manually check for queued messages"},
		{"sessions", "List active Signal sessions"},
		{"help", "Show this help message"},
		{"quit", "Exit the client"},
	}

	for _, c := range cmds {
		fmt.Printf("  %s%-20s%s %s%s%s\n", colorYellow, c.cmd, colorReset, colorDim, c.desc, colorReset)
	}
	fmt.Println()
}

func main() {
	server := flag.String("server", "localhost:5555", "server:port (TLS)")
	insecureSkipVerify := flag.Bool("insecure", false, "skip TLS verification")
	flag.Parse()

	// Show animated banner with Moon9t branding
	printAnimatedBanner()

	// Initialize session database
	db, err := initDB()
	if err != nil {
		printError(fmt.Sprintf("Database initialization failed: %v", err))
		return
	}
	defer db.Close()

	// Connect to server
	tlsCfg := &tls.Config{InsecureSkipVerify: *insecureSkipVerify}

	animateConnection(*server)
	conn, err := tls.Dial("tcp", *server, tlsCfg)
	if err != nil {
		printError(fmt.Sprintf("Connection failed: %v", err))
		return
	}
	defer conn.Close()
	animateSuccess(fmt.Sprintf("Connected to %s", *server))
	showHeartbeat()

	reader := bufio.NewReader(conn)

	// Read greeting
	if ln, _ := reader.ReadString('\n'); ln != "" {
		greeting := strings.TrimSpace(ln)
		fmt.Printf("%s%s%s\n\n", colorCyan, greeting, colorReset)
	}

	if *insecureSkipVerify {
		printWarning("TLS certificate verification is disabled!")
	}

	printHelp()

	client := &Client{
		conn:    conn,
		reader:  reader,
		db:      db,
		limiter: rate.NewLimiter(rate.Every(100*time.Millisecond), 5), // 5 commands per 500ms burst
	}

	printInfo("Rate limiter active: max 10 commands/second with burst of 5")

	// Start background message listener
	stopChan := make(chan bool)
	go client.messageListener(stopChan)

	// Command loop
	in := bufio.NewReader(os.Stdin)
	for {
		username := ""
		if client.local.Username != "" {
			username = client.local.Username
		}
		printPrompt(username)

		line, _ := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		cmd := parts[0]

		// Rate limit commands (except help and quit)
		if cmd != "help" && cmd != "quit" && cmd != "exit" {
			if !client.limiter.Allow() {
				printWarning("Rate limit exceeded. Please slow down.")
				continue
			}
		}

		switch cmd {
		case "help":
			printHelp()

		case "keygen":
			client.cmdKeygen(in)

		case "load":
			client.cmdLoad(in)

		case "register":
			client.cmdRegister(in)

		case "login":
			client.cmdLogin()

		case "upload_prekeys":
			client.cmdUploadPreKeys()

		case "send":
			if len(parts) < 3 {
				printError("Usage: send <username> <message>")
				continue
			}
			client.cmdSend(parts[1], parts[2])

		case "recv":
			client.cmdRecv()

		case "sessions":
			client.cmdSessions()

		case "quit", "exit":
			printInfo("Logging out...")
			fmt.Fprintln(conn, "LOGOUT")
			ln, _ := reader.ReadString('\n')
			fmt.Printf("%s%s%s\n", colorCyan, strings.TrimSpace(ln), colorReset)
			stopChan <- true
			printSuccess("Goodbye!")
			return

		default:
			printError(fmt.Sprintf("Unknown command: '%s'. Type 'help' for available commands", cmd))
		}
	}
}

// Initialize session database
func initDB() (*sql.DB, error) {
	dbPath := filepath.Join(keydir(), dbfile)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS sessions (
		peer TEXT PRIMARY KEY,
		state TEXT NOT NULL,
		remote_identity TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS onetime_prekeys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		prekey TEXT NOT NULL,
		used INTEGER DEFAULT 0
	);
	`
	_, err = db.Exec(schema)
	return db, err
}

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

// Message listener goroutine - listens for incoming messages in real-time
// NOTE: This is disabled during synchronous command execution to avoid race conditions
func (c *Client) messageListener(stop chan bool) {
	for {
		select {
		case <-stop:
			return
		default:
			// Only run listener when logged in (after interactive commands complete)
			c.mu.Lock()
			if !c.loggedIn {
				c.mu.Unlock()
				time.Sleep(100 * time.Millisecond)
				continue
			}
			c.mu.Unlock()

			// Set a short read deadline to avoid blocking
			c.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

			line, err := c.reader.ReadString('\n')
			if err != nil {
				// Timeout or error - continue
				c.conn.SetReadDeadline(time.Time{}) // Clear deadline
				continue
			}

			c.conn.SetReadDeadline(time.Time{}) // Clear deadline after successful read

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Handle incoming message
			c.handleIncomingMessage(line)
		}
	}
}

func (c *Client) handleIncomingMessage(line string) {
	// Only handle MSG commands in background listener
	// Skip all other server responses (OK, ERR, RIDDLE, CHALLENGE, etc.)
	if !strings.HasPrefix(line, "MSG ") {
		return
	}

	// Parse MSG payload
	msgJSON := strings.TrimPrefix(line, "MSG ")
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(msgJSON), &m); err != nil {
		return
	}

	// Check if it's an encrypted message
	if header, ok := m["header"].(string); ok {
		// Signal protocol message
		c.handleSignalMessage(m, header)
	} else if _, ok := m["ciphertext"]; ok {
		// Legacy NaCl box message (for compatibility)
		from, _ := m["from"].(string)
		printMessage(from, "[legacy encrypted message - upgrade sender to v2.0]")
	}
}

func (c *Client) handleSignalMessage(m map[string]interface{}, headerB64 string) {
	from, _ := m["from"].(string)
	if from == "" {
		return
	}

	ciphertextB64, _ := m["ciphertext"].(string)
	if ciphertextB64 == "" {
		return
	}

	// Show typing indicator while processing
	go showTypingIndicator(from)

	// Get session
	session, err := c.getSession(from)
	if err != nil {
		printError(fmt.Sprintf("No session with %s", from))
		return
	}

	// Decrypt
	header, _ := base64.RawStdEncoding.DecodeString(headerB64)
	ciphertext, _ := base64.RawStdEncoding.DecodeString(ciphertextB64)

	plaintext, err := session.Decrypt(header, ciphertext)
	if err != nil {
		printError(fmt.Sprintf("Failed to decrypt message from %s: %v", from, err))
		return
	}

	// Save updated session
	c.saveSession(from, session)

	// Display message
	fmt.Print("\r") // Clear current line
	printMessage(from, string(plaintext))
	printPrompt(c.local.Username)
}

// Continue in next message...
