# Use bash on every OS, so the same Makefile works on Windows (Git Bash),
# in GitHub Actions and on the Linux VPS.
SHELL := bash

# Load variables from .env (the leading '-' ignores a missing file, e.g. in CI).
-include .env
# Export only DATABASE_URL, so goose can read it. A bare 'export' would export everything.
export DATABASE_URL


APP_NAME := aktenlens-api
# go.mod lives in backend/, so every Go command runs from there.
BACKEND_DIR := backend
# Paths below are relative to backend/ (backend/bin is in .gitignore).
BUILD_DIR := bin
MAIN_PATH := ./cmd/api

.PHONY: all build run dev test test-race fmt vet lint clean help db db-stop db-logs db-psql db-reset migrate migrate-down migrate-status

# Default target when running only 'make'
all: help

build: ## Compile the API binary
	@echo "==> Compiling the project..."
	cd $(BACKEND_DIR) && go build -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)

run: ## Run the API (go run, no binary left behind)
	@echo "==> Running the API..."
	cd $(BACKEND_DIR) && go run $(MAIN_PATH)

dev: ## Start everything in Docker (PostgreSQL + API)
	@echo "==> Starting the full stack in Docker..."
	docker compose up --build

test: ## Run all backend tests
	@echo "==> Running tests..."
	cd $(BACKEND_DIR) && go test ./...

# -race needs a 64-bit C compiler (cgo). The old 32-bit MinGW fails, so the
# race detector is a separate target; CI runs it on Linux.
test-race: ## Run all backend tests with the race detector
	@echo "==> Running tests with the race detector..."
	cd $(BACKEND_DIR) && go test -race ./...

fmt: ## Format the Go code (gofmt)
	@echo "==> Formatting the code..."
	cd $(BACKEND_DIR) && go fmt ./...

vet: ## Look for suspicious code (go vet)
	@echo "==> Running vet..."
	cd $(BACKEND_DIR) && go vet ./...

lint: ## Run golangci-lint (includes gosec)
	@echo "==> Running golangci-lint..."
	cd $(BACKEND_DIR) && golangci-lint run

clean: ## Remove build artifacts
	@echo "==> Cleaning artifacts..."
	rm -rf $(BACKEND_DIR)/$(BUILD_DIR)

# Lists every target that has a "## description" comment.
help: ## Show the available commands
	@echo "Available commands for $(APP_NAME):"
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(firstword $(MAKEFILE_LIST)) | awk 'BEGIN {FS = ":.*## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

db: ## Start PostgreSQL in Docker
	@echo "==> Starting PostgreSQL..."
	docker compose up -d postgres

db-stop: ## Stop PostgreSQL, keeping the data
	@echo "==> Stopping PostgreSQL..."
	docker compose stop postgres

db-logs: ## Follow the PostgreSQL logs (Ctrl+C to leave)
	docker compose logs -f postgres

# $$ keeps the variables for the container's shell, so the Makefile does not
# need to read .env. If the terminal complains about a TTY, try "winpty make db-psql".
db-psql: ## Open psql inside the container
	docker compose exec postgres sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

db-reset: ## DELETE all database data and start a fresh database
	@echo "==> Deleting the database data and recreating it..."
	docker compose down -v
	$(MAKE) db

migrate: ## Apply all pending database migrations
	@echo "==> Applying migrations..."
	cd $(BACKEND_DIR) && go tool goose -dir db/migrations postgres "$$DATABASE_URL" up

migrate-down: ## Roll back the last migration
	@echo "==> Rolling back the last migration..."
	cd $(BACKEND_DIR) && go tool goose -dir db/migrations postgres "$$DATABASE_URL" down

migrate-status: ## Show which migrations were applied
	cd $(BACKEND_DIR) && go tool goose -dir db/migrations postgres "$$DATABASE_URL" status