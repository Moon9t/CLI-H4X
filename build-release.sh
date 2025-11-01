#!/bin/bash
# Build script for CLI-H4X cross-platform releases

VERSION=${1:-v1.0.0}
OUTPUT_DIR="releases/$VERSION"

mkdir -p "$OUTPUT_DIR"

echo "Building CLI-H4X $VERSION for multiple platforms..."

# Build client for different platforms
echo "Building client binaries..."

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -tags client_v2 -ldflags "-s -w" -o "$OUTPUT_DIR/cli-h4x-client-linux-amd64" client_v2.go client_v2_commands.go client_v2_sessions.go animations.go
echo "✓ Linux AMD64 client built"

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -tags client_v2 -ldflags "-s -w" -o "$OUTPUT_DIR/cli-h4x-client-linux-arm64" client_v2.go client_v2_commands.go client_v2_sessions.go animations.go
echo "✓ Linux ARM64 client built"

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -tags client_v2 -ldflags "-s -w" -o "$OUTPUT_DIR/cli-h4x-client-windows-amd64.exe" client_v2.go client_v2_commands.go client_v2_sessions.go animations.go
echo "✓ Windows AMD64 client built"

# macOS AMD64 (Intel)
GOOS=darwin GOARCH=amd64 go build -tags client_v2 -ldflags "-s -w" -o "$OUTPUT_DIR/cli-h4x-client-macos-amd64" client_v2.go client_v2_commands.go client_v2_sessions.go animations.go
echo "✓ macOS AMD64 (Intel) client built"

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -tags client_v2 -ldflags "-s -w" -o "$OUTPUT_DIR/cli-h4x-client-macos-arm64" client_v2.go client_v2_commands.go client_v2_sessions.go animations.go
echo "✓ macOS ARM64 (Apple Silicon) client built"

# Build server (Linux only)
echo "Building server binary..."
GOOS=linux GOARCH=amd64 go build -tags server -ldflags "-s -w" -o "$OUTPUT_DIR/cli-h4x-server-linux-amd64" server.go
echo "✓ Server built"

# Create checksums
echo "Generating checksums..."
cd "$OUTPUT_DIR"
sha256sum * > SHA256SUMS
cd - > /dev/null

echo ""
echo "✓ All binaries built successfully in $OUTPUT_DIR/"
echo ""
echo "Files created:"
ls -lh "$OUTPUT_DIR/"
