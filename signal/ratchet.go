// signal/ratchet.go - Simplified Signal double-ratchet implementation for CLI-H4X
package signal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	MaxSkip = 1000 // Maximum number of message keys to skip
)

// PreKeyBundle contains the initial key material for establishing a session
type PreKeyBundle struct {
	IdentityKey     string `json:"identity_key"`             // Long-term identity key (X25519 public)
	SignedPreKey    string `json:"signed_prekey"`            // Signed pre-key (X25519 public)
	PreKeySignature string `json:"prekey_sig"`               // Ed25519 signature of SignedPreKey
	OneTimePreKey   string `json:"onetime_prekey,omitempty"` // Optional one-time pre-key
}

// RatchetState represents the current state of the double-ratchet
type RatchetState struct {
	// Root key and chain keys
	RootKey      [32]byte `json:"root_key"`
	SendChainKey [32]byte `json:"send_chain_key"`
	RecvChainKey [32]byte `json:"recv_chain_key"`

	// DH ratchet keys
	DHSendKey [32]byte `json:"dh_send_priv"` // Our current ephemeral private key
	DHSendPub [32]byte `json:"dh_send_pub"`  // Our current ephemeral public key
	DHRecvPub [32]byte `json:"dh_recv_pub"`  // Their current ephemeral public key

	// Message counters
	SendCounter uint32 `json:"send_counter"`
	RecvCounter uint32 `json:"recv_counter"`
	PrevCounter uint32 `json:"prev_counter"`

	// Skipped message keys (for out-of-order messages)
	SkippedKeys map[string][32]byte `json:"skipped_keys"` // key: "pubkey:counter"
}

// Session represents a complete ratchet session between two parties
type Session struct {
	State          RatchetState
	RemoteIdentity [32]byte
}

// InitializeAlice initializes the ratchet for the initiator (Alice)
func InitializeAlice(identityPriv, identityPub [32]byte, bundle PreKeyBundle, sharedSecret [32]byte) (*Session, error) {
	session := &Session{
		State: RatchetState{
			SkippedKeys: make(map[string][32]byte),
		},
	}

	// Decode bundle keys
	var remoteIdentity, signedPreKey [32]byte
	if err := decodeKey(bundle.IdentityKey, &remoteIdentity); err != nil {
		return nil, err
	}
	if err := decodeKey(bundle.SignedPreKey, &signedPreKey); err != nil {
		return nil, err
	}

	session.RemoteIdentity = remoteIdentity

	// Generate initial DH ratchet key pair
	dhPriv, dhPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	session.State.DHSendKey = dhPriv
	session.State.DHSendPub = dhPub
	session.State.DHRecvPub = signedPreKey

	// Perform initial DH
	var dh1, dh2 [32]byte
	curve25519.ScalarMult(&dh1, &identityPriv, &signedPreKey)
	curve25519.ScalarMult(&dh2, &dhPriv, &signedPreKey)

	// KDF to derive root key and chain key
	info := append(identityPub[:], remoteIdentity[:]...)
	kdf := hkdf.New(sha256.New, append(dh1[:], dh2[:]...), sharedSecret[:], info)

	rootKey := make([]byte, 32)
	chainKey := make([]byte, 32)
	if _, err := kdf.Read(rootKey); err != nil {
		return nil, err
	}
	if _, err := kdf.Read(chainKey); err != nil {
		return nil, err
	}

	copy(session.State.RootKey[:], rootKey)
	copy(session.State.SendChainKey[:], chainKey)

	return session, nil
}

// InitializeBob initializes the ratchet for the responder (Bob)
func InitializeBob(identityPriv, identityPub, signedPreKeyPriv [32]byte, remoteIdentity, remoteDHPub [32]byte, sharedSecret [32]byte) (*Session, error) {
	session := &Session{
		State: RatchetState{
			SkippedKeys: make(map[string][32]byte),
			DHRecvPub:   remoteDHPub,
		},
		RemoteIdentity: remoteIdentity,
	}

	// Perform initial DH
	var dh1, dh2 [32]byte
	curve25519.ScalarMult(&dh1, &signedPreKeyPriv, &remoteIdentity)
	curve25519.ScalarMult(&dh2, &signedPreKeyPriv, &remoteDHPub)

	// KDF to derive root key and chain key
	info := append(remoteIdentity[:], identityPub[:]...)
	kdf := hkdf.New(sha256.New, append(dh1[:], dh2[:]...), sharedSecret[:], info)

	rootKey := make([]byte, 32)
	chainKey := make([]byte, 32)
	if _, err := kdf.Read(rootKey); err != nil {
		return nil, err
	}
	if _, err := kdf.Read(chainKey); err != nil {
		return nil, err
	}

	copy(session.State.RootKey[:], rootKey)
	copy(session.State.RecvChainKey[:], chainKey)

	return session, nil
}

// Encrypt encrypts a message using the ratchet
func (s *Session) Encrypt(plaintext []byte) (header, ciphertext []byte, err error) {
	// Derive message key from send chain
	msgKey := s.deriveMessageKey(s.State.SendChainKey)

	// Advance chain key
	s.State.SendChainKey = s.deriveChainKey(s.State.SendChainKey)

	// Create header: [DHPub(32) | Counter(4)]
	header = make([]byte, 36)
	copy(header[:32], s.State.DHSendPub[:])
	header[32] = byte(s.State.SendCounter >> 24)
	header[33] = byte(s.State.SendCounter >> 16)
	header[34] = byte(s.State.SendCounter >> 8)
	header[35] = byte(s.State.SendCounter)

	// Encrypt: HMAC(msgKey, plaintext) + plaintext
	ciphertext = s.encryptWithKey(msgKey, plaintext)

	s.State.SendCounter++

	return header, ciphertext, nil
}

// Decrypt decrypts a message using the ratchet
func (s *Session) Decrypt(header, ciphertext []byte) ([]byte, error) {
	if len(header) != 36 {
		return nil, errors.New("invalid header length")
	}

	var remoteDHPub [32]byte
	copy(remoteDHPub[:], header[:32])

	counter := uint32(header[32])<<24 | uint32(header[33])<<16 | uint32(header[34])<<8 | uint32(header[35])

	// Check if we need to perform DH ratchet step
	if remoteDHPub != s.State.DHRecvPub {
		if err := s.dhRatchet(remoteDHPub); err != nil {
			return nil, err
		}
	}

	// Handle skipped messages
	skippedKey := fmt.Sprintf("%s:%d", base64.RawStdEncoding.EncodeToString(remoteDHPub[:]), counter)
	if msgKey, found := s.State.SkippedKeys[skippedKey]; found {
		delete(s.State.SkippedKeys, skippedKey)
		return s.decryptWithKey(msgKey, ciphertext)
	}

	// Skip messages if needed
	if counter > s.State.RecvCounter {
		if counter-s.State.RecvCounter > MaxSkip {
			return nil, errors.New("too many skipped messages")
		}
		for i := s.State.RecvCounter; i < counter; i++ {
			msgKey := s.deriveMessageKey(s.State.RecvChainKey)
			s.State.RecvChainKey = s.deriveChainKey(s.State.RecvChainKey)
			skipKey := fmt.Sprintf("%s:%d", base64.RawStdEncoding.EncodeToString(remoteDHPub[:]), i)
			s.State.SkippedKeys[skipKey] = msgKey
		}
	}

	// Derive message key
	msgKey := s.deriveMessageKey(s.State.RecvChainKey)
	s.State.RecvChainKey = s.deriveChainKey(s.State.RecvChainKey)
	s.State.RecvCounter = counter + 1

	return s.decryptWithKey(msgKey, ciphertext)
}

// dhRatchet performs a DH ratchet step
func (s *Session) dhRatchet(remoteDHPub [32]byte) error {
	s.State.PrevCounter = s.State.SendCounter
	s.State.SendCounter = 0
	s.State.RecvCounter = 0
	s.State.DHRecvPub = remoteDHPub

	// Generate new DH key pair
	dhPriv, dhPub, err := generateKeyPair()
	if err != nil {
		return err
	}

	// Perform DH and derive new root key and chain keys
	var dh [32]byte
	curve25519.ScalarMult(&dh, &s.State.DHSendKey, &remoteDHPub)

	// Update root key and recv chain
	kdf := hkdf.New(sha256.New, dh[:], s.State.RootKey[:], []byte("ratchet-recv"))
	newRootKey := make([]byte, 32)
	newChainKey := make([]byte, 32)
	kdf.Read(newRootKey)
	kdf.Read(newChainKey)
	copy(s.State.RootKey[:], newRootKey)
	copy(s.State.RecvChainKey[:], newChainKey)

	// Update DH keys and send chain
	s.State.DHSendKey = dhPriv
	s.State.DHSendPub = dhPub

	curve25519.ScalarMult(&dh, &dhPriv, &remoteDHPub)
	kdf = hkdf.New(sha256.New, dh[:], s.State.RootKey[:], []byte("ratchet-send"))
	kdf.Read(newRootKey)
	kdf.Read(newChainKey)
	copy(s.State.RootKey[:], newRootKey)
	copy(s.State.SendChainKey[:], newChainKey)

	return nil
}

// Helper functions
func generateKeyPair() (priv, pub [32]byte, err error) {
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, pub, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

func decodeKey(b64 string, key *[32]byte) error {
	data, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	if len(data) != 32 {
		return errors.New("invalid key length")
	}
	copy(key[:], data)
	return nil
}

func (s *Session) deriveChainKey(chainKey [32]byte) [32]byte {
	mac := hmac.New(sha256.New, chainKey[:])
	mac.Write([]byte{0x02})
	var newChainKey [32]byte
	copy(newChainKey[:], mac.Sum(nil))
	return newChainKey
}

func (s *Session) deriveMessageKey(chainKey [32]byte) [32]byte {
	mac := hmac.New(sha256.New, chainKey[:])
	mac.Write([]byte{0x01})
	var msgKey [32]byte
	copy(msgKey[:], mac.Sum(nil))
	return msgKey
}

func (s *Session) encryptWithKey(key [32]byte, plaintext []byte) []byte {
	// Simple encrypt: HMAC-SHA256 for auth + XOR with key stream (simplified)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(plaintext)
	tag := mac.Sum(nil)

	// XOR encryption (simplified - in production use AES-GCM or ChaCha20-Poly1305)
	kdf := hkdf.New(sha256.New, key[:], nil, []byte("encrypt"))
	keystream := make([]byte, len(plaintext))
	kdf.Read(keystream)

	ciphertext := make([]byte, len(tag)+len(plaintext))
	copy(ciphertext[:len(tag)], tag)
	for i := 0; i < len(plaintext); i++ {
		ciphertext[len(tag)+i] = plaintext[i] ^ keystream[i]
	}
	return ciphertext
}

func (s *Session) decryptWithKey(key [32]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 32 {
		return nil, errors.New("ciphertext too short")
	}

	tag := ciphertext[:32]
	ct := ciphertext[32:]

	// XOR decrypt
	kdf := hkdf.New(sha256.New, key[:], nil, []byte("encrypt"))
	keystream := make([]byte, len(ct))
	kdf.Read(keystream)

	plaintext := make([]byte, len(ct))
	for i := 0; i < len(ct); i++ {
		plaintext[i] = ct[i] ^ keystream[i]
	}

	// Verify MAC
	mac := hmac.New(sha256.New, key[:])
	mac.Write(plaintext)
	expectedTag := mac.Sum(nil)

	if !hmac.Equal(tag, expectedTag) {
		return nil, errors.New("authentication failed")
	}

	return plaintext, nil
}

// SerializeState serializes the ratchet state to JSON
func (s *Session) SerializeState() (string, error) {
	data, err := json.Marshal(s.State)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(data), nil
}

// DeserializeState deserializes the ratchet state from JSON
func DeserializeState(serialized string, remoteIdentity [32]byte) (*Session, error) {
	data, err := base64.RawStdEncoding.DecodeString(serialized)
	if err != nil {
		return nil, err
	}

	var state RatchetState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	if state.SkippedKeys == nil {
		state.SkippedKeys = make(map[string][32]byte)
	}

	return &Session{
		State:          state,
		RemoteIdentity: remoteIdentity,
	}, nil
}
