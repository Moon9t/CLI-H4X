// webhook_receiver.go - Admin webhook receiver with email and Discord notifications
package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type AdminReport struct {
	IP        string `json:"ip"`
	Username  string `json:"username"`
	Attempts  int    `json:"attempts"`
	Timestamp int64  `json:"timestamp"`
	Reason    string `json:"reason"`
}

type Config struct {
	Port           string
	SecretToken    string
	SMTPHost       string
	SMTPPort       string
	SMTPUser       string
	SMTPPass       string
	EmailFrom      string
	EmailTo        string
	DiscordWebhook string
}

func main() {
	port := flag.String("port", "8080", "HTTP port to listen on")
	flag.Parse()

	config := Config{
		Port:           *port,
		SecretToken:    os.Getenv("WEBHOOK_SECRET"),
		SMTPHost:       os.Getenv("SMTP_HOST"),
		SMTPPort:       os.Getenv("SMTP_PORT"),
		SMTPUser:       os.Getenv("SMTP_USER"),
		SMTPPass:       os.Getenv("SMTP_PASS"),
		EmailFrom:      os.Getenv("EMAIL_FROM"),
		EmailTo:        os.Getenv("EMAIL_TO"),
		DiscordWebhook: os.Getenv("DISCORD_WEBHOOK"),
	}

	// Guard against placeholder Discord URLs so we don't attempt to post to an invalid endpoint
	if strings.Contains(strings.ToUpper(config.DiscordWebhook), "YOUR_WEBHOOK_ID") ||
		strings.Contains(strings.ToUpper(config.DiscordWebhook), "YOUR_WEBHOOK_TOKEN") {
		log.Printf("Discord webhook looks like a placeholder; disabling Discord notifications until a real URL is set.")
		config.DiscordWebhook = ""
	}

	if config.SecretToken == "" {
		log.Fatal("WEBHOOK_SECRET environment variable is required")
	}

	http.HandleFunc("/webhook", securityMiddleware(config, handleWebhook(config)))
	http.HandleFunc("/health", handleHealth)

	log.Printf("Webhook receiver starting on port %s", config.Port)
	log.Printf("Email notifications: %v", config.EmailTo != "")
	log.Printf("Discord notifications: %v", config.DiscordWebhook != "")

	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		log.Fatal(err)
	}
}

// Security middleware with hardening
func securityMiddleware(config Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Method check
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Token authentication (constant-time comparison)
		authHeader := r.Header.Get("Authorization")
		expectedToken := "Bearer " + config.SecretToken
		if subtle.ConstantTimeCompare([]byte(authHeader), []byte(expectedToken)) != 1 {
			log.Printf("Unauthorized access attempt from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Content-Type check
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
			return
		}

		// Size limit (1MB)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		next(w, r)
	}
}

func handleWebhook(config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var report AdminReport

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if err := json.Unmarshal(body, &report); err != nil {
			log.Printf("Error parsing JSON: %v", err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Log the report
		log.Printf("Report received: IP=%s, User=%s, Attempts=%d, Reason=%s",
			report.IP, report.Username, report.Attempts, report.Reason)

		// Send notifications
		var emailErr, discordErr error

		if config.EmailTo != "" {
			emailErr = sendEmailNotification(config, report)
			if emailErr != nil {
				log.Printf("Email notification failed: %v", emailErr)
			}
		}

		if config.DiscordWebhook != "" {
			discordErr = sendDiscordNotification(config, report)
			if discordErr != nil {
				log.Printf("Discord notification failed: %v", discordErr)
			}
		}

		// Respond with status
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "received",
			"email_sent":   emailErr == nil && config.EmailTo != "",
			"discord_sent": discordErr == nil && config.DiscordWebhook != "",
			"timestamp":    time.Now().Unix(),
		})
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func sendEmailNotification(config Config, report AdminReport) error {
	if config.SMTPHost == "" || config.EmailTo == "" {
		return nil
	}

	timestamp := time.Unix(report.Timestamp, 0).Format(time.RFC1123)
	subject := fmt.Sprintf("CLI-H4X Security Alert: %s", report.Reason)

	body := fmt.Sprintf(`CLI-H4X Security Alert

Reason: %s
IP Address: %s
Username: %s
Attempts: %d
Timestamp: %s

This is an automated notification from CLI-H4X server.
Please review and take appropriate action if needed.

---
CLI-H4X Admin System
`, report.Reason, report.IP, report.Username, report.Attempts, timestamp)

	// Format email
	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n",
		config.EmailFrom, config.EmailTo, subject, body)

	// Send via SMTP
	auth := smtp.PlainAuth("", config.SMTPUser, config.SMTPPass, config.SMTPHost)
	addr := config.SMTPHost + ":" + config.SMTPPort

	return smtp.SendMail(addr, auth, config.EmailFrom, []string{config.EmailTo}, []byte(msg))
}

func sendDiscordNotification(config Config, report AdminReport) error {
	if config.DiscordWebhook == "" {
		return nil
	}

	timestamp := time.Unix(report.Timestamp, 0).Format(time.RFC1123)

	// Discord webhook embed format
	payload := map[string]interface{}{
		"username":   "CLI-H4X Security",
		"avatar_url": "https://cdn-icons-png.flaticon.com/512/2913/2913133.png",
		"embeds": []map[string]interface{}{
			{
				"title":       "🚨 Security Alert",
				"description": report.Reason,
				"color":       0xFF0000, // Red
				"fields": []map[string]interface{}{
					{
						"name":   "IP Address",
						"value":  report.IP,
						"inline": true,
					},
					{
						"name":   "Username",
						"value":  report.Username,
						"inline": true,
					},
					{
						"name":   "Attempts",
						"value":  fmt.Sprintf("%d", report.Attempts),
						"inline": true,
					},
					{
						"name":   "Timestamp",
						"value":  timestamp,
						"inline": false,
					},
				},
				"footer": map[string]string{
					"text": "CLI-H4X Admin System",
				},
				"timestamp": time.Unix(report.Timestamp, 0).Format(time.RFC3339),
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(config.DiscordWebhook, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}

	return nil
}
