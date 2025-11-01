.PHONY: all build clean test run docker-build docker-up docker-down install help \
	server client client_v2 webhook run-server run-webhook run-webhook-env webhook-test \
	run-client run-client-v2 docker-logs setup cert backup format lint

# Variables
BINARY_SERVER=bin/server
BINARY_CLIENT=bin/client
BINARY_CLIENT_V2=bin/client_v2
BINARY_WEBHOOK=bin/webhook
GO=go
DOCKER_COMPOSE=docker-compose

all: build

## build: Build all binaries
build: server client client_v2 webhook

## server: Build server
server:
	@echo "Building server..."
	@mkdir -p bin
	$(GO) build -o $(BINARY_SERVER) server.go
	@echo "✓ Server built"

## client: Build legacy client
client:
	@echo "Building legacy client..."
	@mkdir -p bin
	$(GO) build -o $(BINARY_CLIENT) client.go
	@echo "✓ Client built"

## client_v2: Build client v2.0 with Signal protocol
client_v2:
	@echo "Building client v2.0 (Signal Protocol)..."
	@mkdir -p bin
	$(GO) build -tags client_v2 -o $(BINARY_CLIENT_V2) client_v2.go client_v2_commands.go client_v2_sessions.go animations.go
	@echo "✓ Client v2.0 built"

## webhook: Build webhook receiver
webhook:
	@echo "Building webhook receiver..."
	@mkdir -p bin
	$(GO) build -o $(BINARY_WEBHOOK) webhook/webhook_receiver.go
	@echo "✓ Webhook receiver built"

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f *.db *.db-journal
	@echo "✓ Clean complete"

## install: Install dependencies
install:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	@echo "✓ Dependencies installed"

## test: Run tests
test:
	@echo "Running tests..."
	$(GO) test -v -race -coverprofile=coverage.out ./...
	@echo "✓ Tests complete"

## run-server: Run server locally
run-server: build
	@echo "Starting server..."
	./$(BINARY_SERVER) -addr 0.0.0.0:5555 -cert certs/server.crt -key certs/server.key -insecure

## run-webhook: Run webhook receiver (env already exported)
run-webhook: webhook
	@echo "Starting webhook receiver..."
	./$(BINARY_WEBHOOK) -port 8080

## run-webhook-env: Run webhook receiver with .env loaded
run-webhook-env: webhook
	@echo "Starting webhook receiver with .env..."
	bash scripts/run_webhook.sh 8080

## webhook-test: Send a test report to webhook
webhook-test:
	@echo "Sending test webhook payload to http://localhost:8080/webhook ..."
	bash scripts/send_webhook_test.sh 8080

## run-client: Run legacy client
run-client: client
	@echo "Starting legacy client..."
	./$(BINARY_CLIENT) -server localhost:5555 -insecure

## run-client-v2: Run client v2.0 (Signal protocol)
run-client-v2: client_v2
	@echo "Starting client v2.0 (Moon9t Edition)..."
	./$(BINARY_CLIENT_V2) -server localhost:5555 -insecure

## docker-build: Build Docker images
docker-build:
	@echo "Building Docker images..."
	$(DOCKER_COMPOSE) build
	@echo "✓ Docker build complete"

## docker-up: Start Docker containers
docker-up:
	@echo "Starting containers..."
	$(DOCKER_COMPOSE) up -d
	@echo "✓ Containers started"
	@echo "Server: localhost:5555"
	@echo "Webhook: localhost:8080"

## docker-down: Stop Docker containers
docker-down:
	@echo "Stopping containers..."
	$(DOCKER_COMPOSE) down
	@echo "✓ Containers stopped"

## docker-logs: View Docker logs
docker-logs:
	$(DOCKER_COMPOSE) logs -f

## setup: Initial setup
setup:
	@echo "Running setup..."
	@chmod +x setup.sh
	@./setup.sh

## cert: Generate self-signed certificates
cert:
	@echo "Generating certificates..."
	@mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
	@echo "✓ Certificates generated"

## backup: Backup database
backup:
	@echo "Creating backup..."
	@mkdir -p backups
	@if [ -f data/cli_h4x.db ]; then \
		cp data/cli_h4x.db backups/cli_h4x_$(shell date +%Y%m%d_%H%M%S).db; \
		echo "✓ Backup created in backups/"; \
	else \
		echo "✗ No database found"; \
	fi

## format: Format Go code
format:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@echo "✓ Format complete"

## lint: Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run; \
	else \
		echo "⚠ golangci-lint not installed, skipping"; \
	fi

## help: Display this help message
help:
	@echo "CLI-H4X Makefile Commands:"
	@echo ""
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
