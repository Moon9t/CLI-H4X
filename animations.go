// animations.go - ASCII animations and branding
//go:build client_v2
// +build client_v2

package main

import (
	"fmt"
	"time"
)

// Animated loading spinner
func showSpinner(message string, duration time.Duration) {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	end := time.Now().Add(duration)
	i := 0

	for time.Now().Before(end) {
		fmt.Printf("\r%s%s %s%s", colorCyan, frames[i%len(frames)], message, colorReset)
		time.Sleep(100 * time.Millisecond)
		i++
	}
	fmt.Print("\r")
}

// Animated banner with Moon9t branding
func printAnimatedBanner() {
	// Clear screen
	fmt.Print("\033[2J\033[H")

	banner := []string{
		"",
		"    ╔═══════════════════════════════════════════════════════════╗",
		"    ║                                                           ║",
		"    ║     ██████╗██╗     ██╗      ██╗  ██╗██╗  ██╗██╗  ██╗    	 ║",
		"    ║    ██╔════╝██║     ██║      ██║  ██║██║  ██║╚██╗██╔╝      ║",
		"    ║    ██║     ██║     ██║█████╗███████║███████║ ╚███╔╝     	 ║",
		"    ║    ██║     ██║     ██║╚════╝██╔══██║╚════██║ ██╔██╗     	 ║",
		"    ║    ╚██████╗███████╗██║      ██║  ██║     ██║██╔╝ ██╗    	 ║",
		"    ║     ╚═════╝╚══════╝╚═╝      ╚═╝  ╚═╝     ╚═╝╚═╝  ╚═╝    	 ║",
		"    ║                                                           ║",
		"    ║              🌙 Moon9t Edition v2.0 🌙                    ║",
		"    ║                                                           ║",
		"    ║          Signal Protocol • Real-time Messaging            ║",
		"    ║                                                           ║",
		"    ╚═══════════════════════════════════════════════════════════╝",
		"",
	}

	// Animate banner lines
	for _, line := range banner {
		fmt.Printf("%s%s%s\n", colorCyan, line, colorReset)
		time.Sleep(30 * time.Millisecond)
	}

	// Show branding
	time.Sleep(200 * time.Millisecond)
	printBranding()
	time.Sleep(300 * time.Millisecond)

	// Moon phase animation (Moon9t themed)
	animateMoonPhase()
	time.Sleep(200 * time.Millisecond)
}

// Branding
func printBranding() {
	branding := []string{
		"",
		"                    ╭───────────────────────────╮",
		"                    │   © 2025 Moon9t           │",
		"                    ╰───────────────────────────╯",
		"",
	}

	for _, line := range branding {
		fmt.Printf("%s%s%s\n", colorDim, line, colorReset)
		time.Sleep(40 * time.Millisecond)
	}
}

// Loading animation for key generation
func animateKeyGen() {
	frames := []string{
		"[    ] Generating identity keys...",
		"[=   ] Generating identity keys...",
		"[==  ] Generating identity keys...",
		"[=== ] Generating identity keys...",
		"[====] Identity keys ready!",
		"[    ] Generating pre-keys...",
		"[=   ] Generating pre-keys...",
		"[==  ] Generating pre-keys...",
		"[=== ] Generating pre-keys...",
		"[====] Pre-keys ready!",
		"[    ] Generating signing keys...",
		"[=   ] Generating signing keys...",
		"[==  ] Generating signing keys...",
		"[=== ] Generating signing keys...",
		"[====] Signing keys ready!",
	}

	for _, frame := range frames {
		fmt.Printf("\r%s%s%s", colorCyan, frame, colorReset)
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println()
}

// Matrix-style connection animation
func animateConnection(server string) {
	chars := "⣾⣽⣻⢿⡿⣟⣯⣷"

	for i := 0; i < 10; i++ {
		fmt.Printf("\r%s%c Establishing secure connection to %s...%s",
			colorGreen, chars[i%8], server, colorReset)
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Println()
}

// Success checkmark animation
func animateSuccess(message string) {
	frames := []string{
		"○",
		"◔",
		"◑",
		"◕",
		"●",
		"✓",
	}

	for _, frame := range frames {
		fmt.Printf("\r%s%s %s%s", colorGreen, frame, message, colorReset)
		time.Sleep(80 * time.Millisecond)
	}
	fmt.Println()
}

// Typing indicator for real-time messages
func showTypingIndicator(user string) {
	dots := []string{"   ", ".  ", ".. ", "..."}
	for i := 0; i < 12; i++ {
		fmt.Printf("\r%s%s is typing%s%s", colorDim, user, dots[i%4], colorReset)
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Print("\r                              \r")
}

// Encryption animation
func animateEncryption() {
	frames := []string{
		"🔓 Preparing message...",
		"🔒 Encrypting with Signal protocol...",
		"🔐 Double-ratchet active...",
		"✓ Message secured!",
	}

	for _, frame := range frames {
		fmt.Printf("\r%s%s%s", colorYellow, frame, colorReset)
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Println()
}

// Message delivery animation
func animateMessageSent(recipient string) {
	frames := []string{
		"📤 Sending to " + recipient,
		"📨 In transit...",
		"📬 Delivered!",
	}

	for _, frame := range frames {
		fmt.Printf("\r%s%s%s", colorCyan, frame, colorReset)
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Print("\r                              \r")
}

// Login celebration animation
func animateLoginSuccess(username string) {
	fmt.Printf("%s\nWelcome back, %s\n\n%s", colorGreen, username, colorReset)
}

// Moon phase animation (Moon9t themed)
func animateMoonPhase() {
	phases := []string{"🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘"}

	for i := 0; i < 16; i++ {
		fmt.Printf("\r%s%s Moon9t Secure Messaging %s%s",
			colorCyan, phases[i%8], phases[(i+4)%8], colorReset)
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println()
}

// Logo
func showEclipseLogo() {
	// Removed - keeping it minimal
}

// Progress bar animation
func showProgressBar(label string, duration time.Duration) {
	width := 40
	steps := 20

	for i := 0; i <= steps; i++ {
		filled := (i * width) / steps
		bar := ""
		for j := 0; j < width; j++ {
			if j < filled {
				bar += "█"
			} else {
				bar += "░"
			}
		}

		percent := (i * 100) / steps
		fmt.Printf("\r%s%s [%s] %d%%%s", colorCyan, label, bar, percent, colorReset)
		time.Sleep(duration / time.Duration(steps))
	}
	fmt.Println()
}

// Heartbeat animation (for connection status)
func showHeartbeat() {
	beats := []string{"💙", "💚", "💙", "💚"}

	for _, beat := range beats {
		fmt.Printf("\r%s %s Connected %s", beat, colorGreen, colorReset)
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Print("\r                    \r")
}

// ASCII art signature
func showSignature() {
	// Signature removed
}
