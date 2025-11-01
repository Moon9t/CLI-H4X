// client_v2_sessions.go - Signal session management
//go:build client_v2
// +build client_v2

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cli-h4x/signal"
)

func (c *Client) getSession(peer string) (*signal.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var stateJSON, remoteIdentityB64 string
	err := c.db.QueryRow("SELECT state, remote_identity FROM sessions WHERE peer = ?", peer).
		Scan(&stateJSON, &remoteIdentityB64)
	if err != nil {
		return nil, fmt.Errorf("no session found")
	}

	// Decode remote identity
	var remoteIdentity [32]byte
	remoteIDBytes, _ := base64.RawStdEncoding.DecodeString(remoteIdentityB64)
	copy(remoteIdentity[:], remoteIDBytes)

	// Deserialize session
	session, err := signal.DeserializeState(stateJSON, remoteIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize session: %v", err)
	}

	return session, nil
}

func (c *Client) saveSession(peer string, session *signal.Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	stateJSON, err := session.SerializeState()
	if err != nil {
		return fmt.Errorf("failed to serialize session: %v", err)
	}

	// Get remote identity from session
	remoteIdentityB64 := base64.RawStdEncoding.EncodeToString(session.RemoteIdentity[:])

	_, err = c.db.Exec(
		"INSERT OR REPLACE INTO sessions(peer, state, remote_identity, updated_at) VALUES(?,?,?,?)",
		peer, stateJSON, remoteIdentityB64, time.Now().Unix())

	return err
}

func (c *Client) initializeSession(peer string) (*signal.Session, error) {
	// Fetch pre-key bundle from server
	printInfo(fmt.Sprintf("Fetching pre-key bundle for '%s'...", peer))
	fmt.Fprintf(c.conn, "GETBUNDLE %s\n", peer)

	ln, _ := c.reader.ReadString('\n')
	ln = strings.TrimSpace(ln)

	if !strings.HasPrefix(ln, "BUNDLE ") {
		return nil, fmt.Errorf("failed to get bundle: %s", ln)
	}

	bundleJSON := strings.TrimPrefix(ln, "BUNDLE ")
	var bundleData map[string]string
	if err := json.Unmarshal([]byte(bundleJSON), &bundleData); err != nil {
		return nil, fmt.Errorf("invalid bundle format: %v", err)
	}

	// Parse bundle - PreKeyBundle fields are strings
	bundle := signal.PreKeyBundle{
		IdentityKey:     bundleData["identity_key"],
		SignedPreKey:    bundleData["signed_prekey"],
		PreKeySignature: bundleData["prekey_sig"],
		OneTimePreKey:   bundleData["onetime_prekey"],
	}

	// Get our identity keys
	var identityPriv, identityPub [32]byte
	identityPrivBytes, _ := base64.RawStdEncoding.DecodeString(c.local.IdentityPriv)
	copy(identityPriv[:], identityPrivBytes)
	identityPubBytes, _ := base64.RawStdEncoding.DecodeString(c.local.IdentityPub)
	copy(identityPub[:], identityPubBytes)

	// Generate shared secret (X3DH key agreement)
	sharedSecret := [32]byte{} // Simplified - in real X3DH this is more complex

	// Initialize Alice (initiator) session
	session, err := signal.InitializeAlice(identityPriv, identityPub, bundle, sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize session: %v", err)
	}

	// Save session
	if err := c.saveSession(peer, session); err != nil {
		return nil, fmt.Errorf("failed to save session: %v", err)
	}
	printSuccess("Signal session initialized successfully")
	return session, nil
}
