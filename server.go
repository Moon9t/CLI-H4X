// server.go
// CLI-H4X: TLS relay server with E2EE support, riddle registration gate, IP ban, admin webhook reporting, SQLite persistence.
//go:build !client_v2
// +build !client_v2

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  pub_enc TEXT NOT NULL,
  pub_sign TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS prekey_bundles (
  username TEXT PRIMARY KEY,
  identity_key TEXT NOT NULL,
  signed_prekey TEXT NOT NULL,
  signature TEXT NOT NULL,
  timestamp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS onetime_prekeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  prekey TEXT NOT NULL,
  used INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS queued (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient TEXT NOT NULL,
  payload TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bans (
  ip TEXT PRIMARY KEY,
  until_ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
  ip TEXT PRIMARY KEY,
  tries INTEGER NOT NULL,
  last_try_ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_riddle (
  id TEXT PRIMARY KEY,
  username TEXT,
  pub_enc TEXT,
  pub_sign TEXT,
  answer_hash TEXT,
  ip TEXT,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS rate_limits (
  ip TEXT PRIMARY KEY,
  request_count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);
`

type Server struct {
	db            *sql.DB
	mu            sync.Mutex
	clients       map[string]net.Conn // username -> conn
	adminWebhook  string
	adminIPs      map[string]bool
	banDuration   time.Duration
	riddleTimeout time.Duration
}

func main() {
	// flags / env
	addr := flag.String("addr", "0.0.0.0:5555", "listen address")
	sqliteFile := flag.String("db", "cli_h4x.db", "sqlite db file")
	certFile := flag.String("cert", "certs/server.crt", "TLS cert")
	keyFile := flag.String("key", "certs/server.key", "TLS key")
	adminWebhook := flag.String("admin_webhook", os.Getenv("ADMIN_WEBHOOK"), "Admin webhook URL for alerts (HTTP POST)")
	adminIPsStr := flag.String("admin_ips", os.Getenv("ADMIN_IPS"), "Comma-separated admin IPs")
	banMin := flag.Int("ban_min", 60, "ban duration minutes after failed riddle attempts")
	flag.Parse()

	// open DB
	db, err := sql.Open("sqlite3", *sqliteFile)
	if err != nil {
		log.Fatal("open db:", err)
	}
	if _, err := db.Exec(schema); err != nil {
		log.Fatal("init schema:", err)
	}

	// parse admin IPs
	adminIPs := make(map[string]bool)
	if *adminIPsStr != "" {
		for _, ip := range strings.Split(*adminIPsStr, ",") {
			adminIPs[strings.TrimSpace(ip)] = true
		}
	}

	srv := &Server{
		db:            db,
		clients:       make(map[string]net.Conn),
		adminWebhook:  *adminWebhook,
		adminIPs:      adminIPs,
		banDuration:   time.Duration(*banMin) * time.Minute,
		riddleTimeout: 5 * time.Minute,
	}

	// tls listener
	cer, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load cert/key: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Println("listening on", *addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go srv.handleConn(conn)
	}
}

/* ----- helper: riddle bank ----- */
var riddles = []struct {
	Q string
	A string
}{
	{"I speak without a mouth and hear without ears. I have nobody, but I come alive with wind. What am I?", "echo"},
	{"You measure my life in hours and I serve you by expiring. I'm quick when I'm thin and slow when I'm fat. The wind is my enemy. What am I?", "candle"},
	{"I have keys but no locks. I have space but no room. You can enter, but you can't go outside. What am I?", "keyboard"},
}

func pickRiddle() (id, q, a string, err error) {
	// choose random riddle
	if len(riddles) == 0 {
		return "", "", "", errors.New("no riddles")
	}
	nBig := make([]byte, 2)
	if _, err := rand.Read(nBig); err != nil {
		return "", "", "", err
	}
	idx := int(nBig[0]) % len(riddles)
	idB := make([]byte, 12)
	if _, err := rand.Read(idB); err != nil {
		return "", "", "", err
	}
	id = base64.RawURLEncoding.EncodeToString(idB)
	return id, riddles[idx].Q, riddles[idx].A, nil
}

/* ----- server methods ----- */

func (s *Server) banIP(ip string) error {
	until := time.Now().Add(s.banDuration).Unix()
	_, err := s.db.Exec("INSERT OR REPLACE INTO bans(ip, until_ts) VALUES (?, ?)", ip, until)
	return err
}

func (s *Server) isBanned(ip string) (bool, time.Time, error) {
	var until int64
	err := s.db.QueryRow("SELECT until_ts FROM bans WHERE ip = ?", ip).Scan(&until)
	if err == sql.ErrNoRows {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	return time.Now().Unix() < until, time.Unix(until, 0), nil
}

func (s *Server) incAttempt(ip string) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var tries int
	err = tx.QueryRow("SELECT tries FROM attempts WHERE ip = ?", ip).Scan(&tries)
	if err == sql.ErrNoRows {
		_, err = tx.Exec("INSERT INTO attempts(ip, tries, last_try_ts) VALUES (?, ?, ?)", ip, 1, time.Now().Unix())
		if err != nil {
			return 0, err
		}
		tries = 1
	} else if err != nil {
		return 0, err
	} else {
		tries++
		_, err = tx.Exec("UPDATE attempts SET tries = ?, last_try_ts = ? WHERE ip = ?", tries, time.Now().Unix(), ip)
		if err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return tries, nil
}

func (s *Server) clearAttempts(ip string) error {
	_, err := s.db.Exec("DELETE FROM attempts WHERE ip = ?", ip)
	return err
}

func (s *Server) savePendingRiddle(id, username, pubEnc, pubSign, answerHash, ip string) error {
	_, err := s.db.Exec("INSERT INTO pending_riddle(id, username, pub_enc, pub_sign, answer_hash, ip, created_at) VALUES(?,?,?,?,?,?,?)",
		id, username, pubEnc, pubSign, answerHash, ip, time.Now().Unix())
	return err
}

func (s *Server) popPendingRiddle(id string) (username, pubEnc, pubSign, answerHash, ip string, createdAt int64, err error) {
	row := s.db.QueryRow("SELECT username, pub_enc, pub_sign, answer_hash, ip, created_at FROM pending_riddle WHERE id = ?", id)
	err = row.Scan(&username, &pubEnc, &pubSign, &answerHash, &ip, &createdAt)
	if err != nil {
		return
	}
	_, _ = s.db.Exec("DELETE FROM pending_riddle WHERE id = ?", id)
	return
}

func (s *Server) registerUser(username, pubEnc, pubSign string) error {
	_, err := s.db.Exec("INSERT INTO users(username, pub_enc, pub_sign, created_at) VALUES(?,?,?,?)",
		username, pubEnc, pubSign, time.Now().Unix())
	return err
}

func (s *Server) getUserPub(username string) (pubEnc, pubSign string, ok bool) {
	row := s.db.QueryRow("SELECT pub_enc, pub_sign FROM users WHERE username = ?", username)
	err := row.Scan(&pubEnc, &pubSign)
	if err == sql.ErrNoRows {
		return "", "", false
	}
	if err != nil {
		return "", "", false
	}
	return pubEnc, pubSign, true
}

func (s *Server) queueMessage(recipient, payload string) error {
	_, err := s.db.Exec("INSERT INTO queued(recipient, payload, ts) VALUES(?,?,?)", recipient, payload, time.Now().Unix())
	return err
}

func (s *Server) deliverOrQueue(recipient string, payload string) error {
	s.mu.Lock()
	conn, online := s.clients[recipient]
	s.mu.Unlock()
	if online && conn != nil {
		_, err := fmt.Fprintln(conn, payload)
		if err != nil {
			// fallback queue
			return s.queueMessage(recipient, payload)
		}
		return nil
	}
	return s.queueMessage(recipient, payload)
}

func (s *Server) drainQueuedFor(user string, conn net.Conn) error {
	rows, err := s.db.Query("SELECT id, payload FROM queued WHERE recipient = ? ORDER BY id ASC", user)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var payload string
		if err := rows.Scan(&id, &payload); err != nil {
			continue
		}
		_, _ = fmt.Fprintln(conn, payload)
		_, _ = s.db.Exec("DELETE FROM queued WHERE id = ?", id)
	}
	return nil
}

func (s *Server) savePreKeyBundle(username, identityKey, signedPreKey, signature string) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO prekey_bundles(username, identity_key, signed_prekey, signature, timestamp) VALUES(?,?,?,?,?)",
		username, identityKey, signedPreKey, signature, time.Now().Unix())
	return err
}

func (s *Server) saveOneTimePreKeys(username string, prekeys []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, pk := range prekeys {
		_, err := tx.Exec("INSERT INTO onetime_prekeys(username, prekey, used) VALUES(?,?,0)", username, pk)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Server) getPreKeyBundle(username string) (map[string]string, error) {
	bundle := make(map[string]string)

	// Get identity key and signed prekey
	var identityKey, signedPreKey, signature string
	err := s.db.QueryRow(
		"SELECT identity_key, signed_prekey, signature FROM prekey_bundles WHERE username = ?",
		username).Scan(&identityKey, &signedPreKey, &signature)
	if err != nil {
		return nil, err
	}

	bundle["identity_key"] = identityKey
	bundle["signed_prekey"] = signedPreKey
	bundle["signature"] = signature

	// Get one unused one-time prekey
	var id int
	var oneTimeKey string
	err = s.db.QueryRow(
		"SELECT id, prekey FROM onetime_prekeys WHERE username = ? AND used = 0 LIMIT 1",
		username).Scan(&id, &oneTimeKey)
	if err == nil {
		bundle["onetime_prekey"] = oneTimeKey
		// Mark as used
		_, _ = s.db.Exec("UPDATE onetime_prekeys SET used = 1 WHERE id = ?", id)
	}
	// If no one-time key available, that's OK - bundle will work without it

	return bundle, nil
}

func (s *Server) checkRateLimit(ip string) bool {
	const maxRequests = 10
	const windowSecs = 60

	now := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return false
	}
	defer tx.Rollback()

	var count int
	var windowStart int64
	err = tx.QueryRow("SELECT request_count, window_start FROM rate_limits WHERE ip = ?", ip).Scan(&count, &windowStart)

	if err == sql.ErrNoRows {
		// First request from this IP
		_, _ = tx.Exec("INSERT INTO rate_limits(ip, request_count, window_start) VALUES(?,1,?)", ip, now)
		_ = tx.Commit()
		return true
	}

	if err != nil {
		return false
	}

	// Check if window expired
	if now-windowStart > windowSecs {
		// Reset window
		_, _ = tx.Exec("UPDATE rate_limits SET request_count = 1, window_start = ? WHERE ip = ?", now, ip)
		_ = tx.Commit()
		return true
	}

	// Increment counter
	count++
	if count > maxRequests {
		return false // Rate limited
	}

	_, _ = tx.Exec("UPDATE rate_limits SET request_count = ? WHERE ip = ?", count, ip)
	_ = tx.Commit()
	return true
}

func (s *Server) getStats() map[string]interface{} {
	stats := make(map[string]interface{})

	var userCount, queuedCount, banCount int
	s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	s.db.QueryRow("SELECT COUNT(*) FROM queued").Scan(&queuedCount)
	s.db.QueryRow("SELECT COUNT(*) FROM bans WHERE until_ts > ?", time.Now().Unix()).Scan(&banCount)

	s.mu.Lock()
	onlineCount := len(s.clients)
	s.mu.Unlock()

	stats["users_registered"] = userCount
	stats["queued_messages"] = queuedCount
	stats["active_bans"] = banCount
	stats["online_users"] = onlineCount
	stats["timestamp"] = time.Now().Unix()

	return stats
}

func (s *Server) isAdminIP(ip string) bool {
	if len(s.adminIPs) == 0 {
		return false
	}
	return s.adminIPs[ip]
}

/* ----- admin reporting ----- */
type adminReport struct {
	IP        string `json:"ip"`
	Username  string `json:"username"`
	Attempts  int    `json:"attempts"`
	Timestamp int64  `json:"timestamp"`
	Reason    string `json:"reason"`
}

func (s *Server) reportAdmin(r adminReport) {
	if s.adminWebhook == "" {
		log.Printf("ADMIN REPORT: %+v\n", r)
		return
	}
	b, _ := json.Marshal(r)
	req, _ := http.NewRequest("POST", s.adminWebhook, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("admin webhook error:", err)
		return
	}
	defer resp.Body.Close()
	log.Println("admin webhook status:", resp.Status)
}

/* ----- connection handler: simple line protocol ----- */
/*
 Protocol summary (line-based):
 - START_REGISTER <username> <pub_enc_b64> <pub_sign_b64>
   -> server responds RIDDLE <id> <question>
 - ANSWER <id> <answer>
   -> server responds OK registered OR ERR <msg>
 - LOGIN <username>
   -> server responds CHALLENGE <b64>
 - AUTH <sig_b64> (client signs challenge with Ed25519 priv)
   -> server responds OK logged-in OR ERR
 - GETPUB <username> -> server responds PUB <pub_enc> <pub_sign> OR ERR
 - SEND <json_payload> -> server relays JSON payload to recipient (must include "to" or "room")
*/

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	ip := strings.Split(remote, ":")[0]

	// ban check
	if banned, until, err := s.isBanned(ip); err == nil && banned {
		fmt.Fprintln(conn, "ERR banned until "+until.String())
		return
	}

	br := bufio.NewReader(conn)
	fmt.Fprintln(conn, "OK WELCOME")
	var loggedIn string
	var currentChallenge string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Rate limit check per command (not per connection)
		if !s.checkRateLimit(ip) {
			fmt.Fprintln(conn, "ERR rate limited")
			s.reportAdmin(adminReport{
				IP:        ip,
				Timestamp: time.Now().Unix(),
				Reason:    "rate limit exceeded",
			})
			time.Sleep(1 * time.Second) // throttle
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := parts[0]
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}
		switch cmd {
		case "START_REGISTER":
			// arg: username pubEnc pubSign [signedPrePub signedPreSig] (space separated; base64 keys contain no spaces)
			f := strings.Fields(arg)
			if len(f) < 3 {
				fmt.Fprintln(conn, "ERR usage: START_REGISTER <username> <pub_enc_b64> <pub_sign_b64> [signed_pre_pub] [signed_pre_sig]")
				continue
			}
			user := f[0]
			pubEnc := f[1]
			pubSign := f[2]
			// Optional: Extract signed pre-key for later use (Signal protocol) - currently unused
			_ = len(f) // ignore extra parameters for now
			// check not existing
			if _, _, ok := s.getUserPub(user); ok {
				fmt.Fprintln(conn, "ERR username exists")
				continue
			}
			// pick riddle and store pending
			id, q, a, err := pickRiddle()
			if err != nil {
				fmt.Fprintln(conn, "ERR riddle error")
				continue
			}
			// store hash of answer (lowercase trim)
			aNorm := strings.TrimSpace(strings.ToLower(a))
			answerHash := base64.RawStdEncoding.EncodeToString([]byte(aNorm)) // simple hash — server never needs to be able to reverse; keeping simple
			if err := s.savePendingRiddle(id, user, pubEnc, pubSign, answerHash, ip); err != nil {
				fmt.Fprintln(conn, "ERR internal")
				continue
			}
			// send riddle
			fmt.Fprintln(conn, "RIDDLE "+id+" "+q)
		case "ANSWER":
			// ANSWER <id> <answer>
			f := strings.SplitN(arg, " ", 2)
			if len(f) < 2 {
				fmt.Fprintln(conn, "ERR usage: ANSWER <id> <answer>")
				continue
			}
			id := f[0]
			answer := strings.TrimSpace(strings.ToLower(f[1]))
			username, pubEnc, pubSign, answerHash, pendingIP, createdAt, err := s.popPendingRiddle(id)
			if err != nil {
				fmt.Fprintln(conn, "ERR no such registration pending")
				continue
			}
			// check ip matches pendingIP (prevent proxies using different IP)
			if pendingIP != ip {
				fmt.Fprintln(conn, "ERR IP mismatch")
				continue
			}
			// check timeout
			if time.Unix(createdAt, 0).Add(s.riddleTimeout).Before(time.Now()) {
				fmt.Fprintln(conn, "ERR riddle expired")
				continue
			}
			if base64.RawStdEncoding.EncodeToString([]byte(answer)) == answerHash {
				// success: register user
				if err := s.registerUser(username, pubEnc, pubSign); err != nil {
					fmt.Fprintln(conn, "ERR register failed")
					continue
				}
				// clear attempts
				_ = s.clearAttempts(ip)
				fmt.Fprintln(conn, "OK registered")
				log.Printf("User '%s' registered successfully from IP %s", username, ip)
			} else {
				tries, _ := s.incAttempt(ip)
				if tries >= 2 {
					// ban + report
					_ = s.banIP(ip)
					s.reportAdmin(adminReport{
						IP:        ip,
						Username:  username,
						Attempts:  tries,
						Timestamp: time.Now().Unix(),
						Reason:    "failed riddle attempts => banned",
					})
					fmt.Fprintln(conn, "ERR banned")
				} else {
					s.reportAdmin(adminReport{
						IP:        ip,
						Username:  username,
						Attempts:  tries,
						Timestamp: time.Now().Unix(),
						Reason:    "failed riddle attempt",
					})
					fmt.Fprintln(conn, "ERR wrong answer")
				}
			}

		case "LOGIN":
			// LOGIN <username> ; server returns CHALLENGE <b64>
			user := arg
			_, pubSign, ok := s.getUserPub(user)
			if !ok {
				fmt.Fprintln(conn, "ERR unknown user")
				continue
			}
			// challenge
			ch := make([]byte, 32)
			if _, err := rand.Read(ch); err != nil {
				fmt.Fprintln(conn, "ERR internal")
				continue
			}
			chB64 := base64.RawStdEncoding.EncodeToString(ch)
			currentChallenge = chB64
			fmt.Fprintln(conn, "CHALLENGE "+chB64+" "+pubSign) // include pubSign so client can show fingerprint
			// next expected: client sends AUTH <sig_b64>
			authLine, err := br.ReadString('\n')
			if err != nil {
				return
			}
			authLine = strings.TrimSpace(authLine)
			if !strings.HasPrefix(authLine, "AUTH ") {
				fmt.Fprintln(conn, "ERR expected AUTH")
				continue
			}
			sigB64 := strings.TrimPrefix(authLine, "AUTH ")
			sig, err := base64.RawStdEncoding.DecodeString(sigB64)
			if err != nil {
				fmt.Fprintln(conn, "ERR bad sig")
				continue
			}
			pubSignBytes, _ := base64.RawStdEncoding.DecodeString(pubSign)
			if len(pubSignBytes) != ed25519.PublicKeySize {
				fmt.Fprintln(conn, "ERR bad pubkey")
				continue
			}
			if !ed25519.Verify(ed25519.PublicKey(pubSignBytes), []byte(currentChallenge), sig) {
				fmt.Fprintln(conn, "ERR auth failed")
				continue
			}
			// auth ok
			loggedIn = user
			s.mu.Lock()
			s.clients[loggedIn] = conn
			s.mu.Unlock()
			// drain queued
			_ = s.drainQueuedFor(loggedIn, conn)
			fmt.Fprintln(conn, "OK logged-in")
		case "GETPUB":
			// GETPUB <username>
			target := arg
			pubEnc, pubSign, ok := s.getUserPub(target)
			if !ok {
				fmt.Fprintln(conn, "ERR no such user")
				continue
			}
			fmt.Fprintln(conn, "PUB "+pubEnc+" "+pubSign)
		case "GETBUNDLE":
			// GETBUNDLE <username> - for Signal protocol
			target := arg
			bundle, err := s.getPreKeyBundle(target)
			if err != nil {
				fmt.Fprintln(conn, "ERR no bundle available")
				continue
			}
			bundleJSON, _ := json.Marshal(bundle)
			fmt.Fprintln(conn, "BUNDLE "+string(bundleJSON))
		case "UPLOAD_PREKEYS":
			// UPLOAD_PREKEYS <json_payload> - upload signed prekey + one-time prekeys
			if loggedIn == "" {
				fmt.Fprintln(conn, "ERR login required")
				continue
			}
			var payload map[string]interface{}
			if err := json.Unmarshal([]byte(arg), &payload); err != nil {
				fmt.Fprintln(conn, "ERR invalid json")
				continue
			}

			// Extract signed prekey bundle
			identityKey, _ := payload["identity_key"].(string)
			signedPreKey, _ := payload["signed_prekey"].(string)
			signature, _ := payload["signature"].(string)

			if identityKey == "" || signedPreKey == "" || signature == "" {
				fmt.Fprintln(conn, "ERR missing required fields")
				continue
			}

			// Save signed prekey bundle
			if err := s.savePreKeyBundle(loggedIn, identityKey, signedPreKey, signature); err != nil {
				fmt.Fprintln(conn, "ERR failed to save bundle")
				continue
			}

			// Extract one-time prekeys
			if prekeyList, ok := payload["onetime_prekeys"].([]interface{}); ok {
				var prekeys []string
				for _, pk := range prekeyList {
					if pkStr, ok := pk.(string); ok {
						prekeys = append(prekeys, pkStr)
					}
				}
				if len(prekeys) > 0 {
					if err := s.saveOneTimePreKeys(loggedIn, prekeys); err != nil {
						fmt.Fprintln(conn, "ERR failed to save prekeys")
						continue
					}
				}
			}

			fmt.Fprintln(conn, "OK prekeys uploaded")
		case "STATS":
			// STATS - admin only
			if !s.isAdminIP(ip) {
				fmt.Fprintln(conn, "ERR unauthorized")
				continue
			}
			stats := s.getStats()
			statsJSON, _ := json.Marshal(stats)
			fmt.Fprintln(conn, string(statsJSON))
		case "SEND":
			if loggedIn == "" {
				fmt.Fprintln(conn, "ERR login required")
				continue
			}
			payload := arg
			// parse minimal JSON to find "to" or "room"
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(payload), &m); err != nil {
				fmt.Fprintln(conn, "ERR invalid json")
				continue
			}
			if to, ok := m["to"].(string); ok && to != "" {
				// forward as MSG command for client compatibility
				m["ts"] = time.Now().Unix()
				m["from"] = loggedIn
				outb, _ := json.Marshal(m)
				msgPayload := "MSG " + string(outb)
				if err := s.deliverOrQueue(to, msgPayload); err != nil {
					fmt.Fprintln(conn, "ERR deliver failed")
				} else {
					fmt.Fprintln(conn, "OK sent")
				}
				continue
			}
			// room support could be handled here; for now only direct messages
			fmt.Fprintln(conn, "ERR missing to")
		case "LOGOUT":
			if loggedIn != "" {
				s.mu.Lock()
				delete(s.clients, loggedIn)
				s.mu.Unlock()
				loggedIn = ""
				fmt.Fprintln(conn, "OK logged out")
			} else {
				fmt.Fprintln(conn, "ERR not logged in")
			}
		default:
			fmt.Fprintln(conn, "ERR unknown")
		}
	}
}
