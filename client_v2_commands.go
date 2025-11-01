// client_v2_commands.go - Command implementations for Signal client
//go:build client_v2
// +build client_v2

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/scrypt"

	_ "cli-h4x/signal" // Used in client_v2_sessions.go
)

func (c *Client) cmdKeygen(in *bufio.Reader) {
	fmt.Printf("%sEnter username: %s", colorCyan, colorReset)
	u, _ := in.ReadString('\n')
	u = strings.TrimSpace(u)
	if u == "" {
		printError("Username cannot be empty")
		return
	}

	fmt.Printf("%sEnter passphrase: %s", colorCyan, colorReset)
	pass, _ := in.ReadString('\n')
	pass = strings.TrimSpace(pass)
	if len(pass) < 8 {
		printWarning("Weak passphrase! Consider using at least 8 characters")
	}

	animateKeyGen()

	// Generate X25519 identity key
	var identityPriv, identityPub [32]byte
	if _, err := rand.Read(identityPriv[:]); err != nil {
		printError(fmt.Sprintf("Failed to generate identity key: %v", err))
		return
	}
	curve25519.ScalarBaseMult(&identityPub, &identityPriv)

	// Generate signed pre-key
	var signedPrePriv, signedPrePub [32]byte
	if _, err := rand.Read(signedPrePriv[:]); err != nil {
		printError(fmt.Sprintf("Failed to generate pre-key: %v", err))
		return
	}
	curve25519.ScalarBaseMult(&signedPrePub, &signedPrePriv)

	// Generate Ed25519 signing key
	pubSign, privSign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		printError(fmt.Sprintf("Failed to generate signing key: %v", err))
		return
	}

	// Sign the pre-key with Ed25519
	preKeySig := ed25519.Sign(privSign, signedPrePub[:])

	local := LocalKeys{
		Username:      u,
		IdentityPriv:  base64.RawStdEncoding.EncodeToString(identityPriv[:]),
		IdentityPub:   base64.RawStdEncoding.EncodeToString(identityPub[:]),
		SignedPrePriv: base64.RawStdEncoding.EncodeToString(signedPrePriv[:]),
		SignedPrePub:  base64.RawStdEncoding.EncodeToString(signedPrePub[:]),
		SignedPreSig:  base64.RawStdEncoding.EncodeToString(preKeySig),
		PrivSignB64:   base64.RawStdEncoding.EncodeToString(privSign),
		PubSignB64:    base64.RawStdEncoding.EncodeToString(pubSign),
	}

	// Save encrypted keys
	js, _ := json.Marshal(local)
	cipher, err := encryptWithPass([]byte(pass), js)
	if err != nil {
		printError(fmt.Sprintf("Failed to encrypt keys: %v", err))
		return
	}

	if err := os.WriteFile(keypath(), cipher, 0600); err != nil {
		printError(fmt.Sprintf("Failed to save keys: %v", err))
		return
	}

	c.local = local
	printSuccess(fmt.Sprintf("Signal protocol keys generated for user '%s'", u))
	printInfo("Remember to run 'upload_prekeys' after registration")
}

func (c *Client) cmdLoad(in *bufio.Reader) {
	fmt.Printf("%sEnter passphrase: %s", colorCyan, colorReset)
	pass, _ := in.ReadString('\n')
	pass = strings.TrimSpace(pass)

	showSpinner("Loading keys", 800*time.Millisecond)
	b, err := os.ReadFile(keypath())
	if err != nil {
		printError(fmt.Sprintf("Failed to read keys: %v", err))
		return
	}

	if len(b) < 16+chacha20poly1305.NonceSizeX {
		printError("Invalid keyfile")
		return
	}

	salt := b[:16]
	nonce := b[16 : 16+chacha20poly1305.NonceSizeX]
	ct := b[16+chacha20poly1305.NonceSizeX:]

	key, err := scrypt.Key([]byte(pass), salt, scryptN, scryptR, scryptP, aesKeyLen)
	if err != nil {
		printError(fmt.Sprintf("Key derivation failed: %v", err))
		return
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		printError(fmt.Sprintf("Cipher initialization failed: %v", err))
		return
	}

	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		printError("Decryption failed (wrong passphrase?)")
		return
	}

	var local LocalKeys
	if err := json.Unmarshal(plain, &local); err != nil {
		printError(fmt.Sprintf("Invalid key format: %v", err))
		return
	}

	c.local = local
	printSuccess(fmt.Sprintf("Keys loaded for user '%s'", local.Username))
}

func (c *Client) cmdRegister(in *bufio.Reader) {
	if c.local.Username == "" {
		printError("No local keys loaded. Run 'keygen' or 'load' first")
		return
	}

	printInfo(fmt.Sprintf("Registering user '%s'...", c.local.Username))
	fmt.Fprintf(c.conn, "START_REGISTER %s %s %s %s %s\n",
		c.local.Username,
		c.local.IdentityPub,
		c.local.PubSignB64,
		c.local.SignedPrePub,
		c.local.SignedPreSig)

	ln, _ := c.reader.ReadString('\n')
	ln = strings.TrimSpace(ln)
	for ln == "" {
		ln, _ = c.reader.ReadString('\n')
		ln = strings.TrimSpace(ln)
	}

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

		autoAnswer := strings.TrimSpace(os.Getenv("CLI_H4X_AUTO_RIDDLE"))
		if autoAnswer != "" {
			fmt.Fprintf(c.conn, "ANSWER %s %s\n", id, autoAnswer)
			resp, _ := c.reader.ReadString('\n')
			resp = strings.TrimSpace(resp)
			if strings.HasPrefix(resp, "OK") {
				printSuccess("Registration successful! You can now login.")
			} else if strings.Contains(resp, "banned") || strings.Contains(resp, "ERR banned") {
				printError("Too many failed attempts. You are temporarily banned.")
			} else {
				printError(fmt.Sprintf("Registration failed: %s", resp))
			}
			return
		}

		attempts := 0
		for attempts < 2 {
			fmt.Printf("%sYour answer: %s", colorCyan, colorReset)
			ans, _ := in.ReadString('\n')
			ans = strings.TrimSpace(ans)

			fmt.Fprintf(c.conn, "ANSWER %s %s\n", id, ans)
			resp, _ := c.reader.ReadString('\n')
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
}

func (c *Client) cmdLogin() {
	if c.local.Username == "" {
		printError("No local keys loaded. Run 'keygen' or 'load' first")
		return
	}

	printInfo(fmt.Sprintf("Logging in as '%s'...", c.local.Username))
	fmt.Fprintln(c.conn, "LOGIN "+c.local.Username)
	ln, _ := c.reader.ReadString('\n')
	ln = strings.TrimSpace(ln)

	if strings.HasPrefix(ln, "CHALLENGE ") {
		rest := strings.TrimPrefix(ln, "CHALLENGE ")
		fields := strings.SplitN(rest, " ", 2)
		ch := fields[0]

		printInfo("Signing authentication challenge...")
		privSignBytes, _ := base64.RawStdEncoding.DecodeString(c.local.PrivSignB64)
		sig := ed25519.Sign(privSignBytes, []byte(ch))
		sigB64 := base64.RawStdEncoding.EncodeToString(sig)

		fmt.Fprintln(c.conn, "AUTH "+sigB64)
		r2, _ := c.reader.ReadString('\n')
		r2 = strings.TrimSpace(r2)

		if strings.HasPrefix(r2, "OK") {
			c.loggedIn = true
			animateLoginSuccess(c.local.Username)
			printInfo("Real-time messaging is now active. You'll receive messages automatically.")
		} else {
			printError(fmt.Sprintf("Login failed: %s", r2))
		}
	} else {
		printError(fmt.Sprintf("Unexpected response: %s", ln))
	}
}

func (c *Client) cmdUploadPreKeys() {
	if !c.loggedIn {
		printError("Login required")
		return
	}

	// Temporarily disable background listener during command
	c.mu.Lock()
	wasLoggedIn := c.loggedIn
	c.loggedIn = false
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.loggedIn = wasLoggedIn
		c.mu.Unlock()
	}()

	showProgressBar("Generating pre-keys", 2*time.Second)

	prekeys := make([]string, 100)
	for i := 0; i < 100; i++ {
		var priv, pub [32]byte
		rand.Read(priv[:])
		curve25519.ScalarBaseMult(&pub, &priv)
		prekeys[i] = base64.RawStdEncoding.EncodeToString(pub[:])

		// Store private key locally for later use
		_, err := c.db.Exec("INSERT INTO onetime_prekeys(prekey) VALUES(?)",
			base64.RawStdEncoding.EncodeToString(priv[:]))
		if err != nil {
			printWarning(fmt.Sprintf("Failed to store pre-key %d", i))
		}
	}

	// Build payload with required fields
	payload := map[string]interface{}{
		"identity_key":    c.local.IdentityPub,
		"signed_prekey":   c.local.SignedPrePub,
		"signature":       c.local.SignedPreSig,
		"onetime_prekeys": prekeys,
	}

	js, _ := json.Marshal(payload)
	fmt.Fprintf(c.conn, "UPLOAD_PREKEYS %s\n", string(js))

	resp, _ := c.reader.ReadString('\n')
	resp = strings.TrimSpace(resp)

	if strings.HasPrefix(resp, "OK") {
		printSuccess("100 one-time pre-keys uploaded successfully")
	} else {
		printError(fmt.Sprintf("Upload failed: %s", resp))
	}
}

func (c *Client) cmdSend(to, msg string) {
	if !c.loggedIn {
		printError("Login required")
		return
	}

	// Check if we have a session with this user
	session, err := c.getSession(to)
	if err != nil {
		// No session - need to fetch bundle and initialize
		printInfo(fmt.Sprintf("Initializing Signal session with '%s'...", to))
		session, err = c.initializeSession(to)
		if err != nil {
			printError(fmt.Sprintf("Failed to initialize session: %v", err))
			return
		}
	}

	animateEncryption()

	// Encrypt with Signal ratchet
	header, ciphertext, err := session.Encrypt([]byte(msg))
	if err != nil {
		printError(fmt.Sprintf("Encryption failed: %v", err))
		return
	}

	// Save updated session state
	c.saveSession(to, session)

	// Send message
	payload := map[string]string{
		"to":         to,
		"from":       c.local.Username,
		"header":     base64.RawStdEncoding.EncodeToString(header),
		"ciphertext": base64.RawStdEncoding.EncodeToString(ciphertext),
	}

	js, _ := json.Marshal(payload)
	fmt.Fprintln(c.conn, "SEND "+string(js))

	resp, _ := c.reader.ReadString('\n')
	resp = strings.TrimSpace(resp)

	if strings.HasPrefix(resp, "OK") {
		animateMessageSent(to)
		printSuccess(fmt.Sprintf("Message delivered to '%s'", to))
	} else {
		printError(fmt.Sprintf("Send failed: %s", resp))
	}
}

func (c *Client) cmdRecv() {
	if !c.loggedIn {
		printError("Login required")
		return
	}

	printInfo("Checking for messages...")
	fmt.Fprintln(c.conn, "RECV")

	ln, _ := c.reader.ReadString('\n')
	ln = strings.TrimSpace(ln)

	if strings.HasPrefix(ln, "OK no messages") {
		printInfo("No new messages")
		return
	}

	if strings.HasPrefix(ln, "ERR") {
		printError(ln)
		return
	}

	// Handle message
	c.handleIncomingMessage(ln)
}

func (c *Client) cmdSessions() {
	rows, err := c.db.Query("SELECT peer, updated_at FROM sessions ORDER BY updated_at DESC")
	if err != nil {
		printError(fmt.Sprintf("Database error: %v", err))
		return
	}
	defer rows.Close()

	fmt.Printf("\n%s%sActive Signal Sessions:%s\n\n", colorBold, colorCyan, colorReset)
	count := 0
	for rows.Next() {
		var peer string
		var updated int64
		rows.Scan(&peer, &updated)
		updatedTime := time.Unix(updated, 0).Format("2006-01-02 15:04:05")
		fmt.Printf("  %s%-20s%s Last updated: %s%s%s\n",
			colorYellow, peer, colorReset,
			colorDim, updatedTime, colorReset)
		count++
	}

	if count == 0 {
		printInfo("No active sessions")
	} else {
		fmt.Printf("\n%sTotal: %d session(s)%s\n\n", colorDim, count, colorReset)
	}
}

// Helper functions
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
