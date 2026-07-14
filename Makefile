.PHONY: help dev build test lint clean docker-up docker-down

BINARY     := rayyan-asm
GO_VERSION := 1.22.4
NODE_VER   := 20
VERSION    := $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS    := -ldflags="-w -s -X main.Version=$(VERSION)"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dev-backend: ## Run backend in development mode (SQLite)
	RAYYAN_DATABASE_DRIVER=sqlite \
	RAYYAN_DATABASE_FILEPATH=./rayyan-dev.db \
	RAYYAN_AUTH_JWTSECRET=dev-secret-change-in-production-32chars \
	RAYYAN_LOG_FORMAT=console \
	RAYYAN_LOG_LEVEL=debug \
	go run ./cmd/server

dev-frontend: ## Run Vite dev server
	cd frontend && npm run dev

dev: ## Run backend + frontend concurrently (requires tmux or run separately)
	@echo "Run 'make dev-backend' and 'make dev-frontend' in separate terminals"

build-backend: ## Build backend binary
	CGO_ENABLED=1 go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/server

build-frontend: ## Build frontend
	cd frontend && npm run build

build: build-backend build-frontend ## Build everything

test: ## Run all Go tests
	go test ./... -v -race -timeout 120s

test-short: ## Run tests without network calls
	go test ./... -short -race -timeout 30s

test-coverage: ## Run tests with HTML coverage report
	go test ./... -coverprofile=coverage.out -timeout 120s
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration: ## Run integration tests only
	go test ./tests/integration/... -v -timeout 60s

lint: ## Run golangci-lint
	golangci-lint run ./...

lint-frontend: ## Lint and type-check frontend
	cd frontend && npm run lint && npx tsc --noEmit

docker-up: ## Start all services with Docker Compose
	docker compose up -d

docker-down: ## Stop all Docker services
	docker compose down

docker-logs: ## Follow Docker logs
	docker compose logs -f

docker-build: ## Rebuild Docker images
	docker compose build --no-cache

db-reset: ## Delete dev SQLite database
	rm -f rayyan-dev.db
	@echo "Database reset. Run 'make dev-backend' to recreate."

k8s-apply: ## Apply Kubernetes manifests
	kubectl apply -f deployments/kubernetes/manifests.yaml

k8s-delete: ## Delete Kubernetes resources
	kubectl delete namespace rayyan-asm

helm-install: ## Install Helm chart (set values first)
	helm upgrade --install rayyan-asm deployments/helm/ \
		--namespace rayyan-asm --create-namespace \
		--set env.jwtSecret=$$(openssl rand -hex 32)

generate-secret: ## Generate a secure JWT secret
	@openssl rand -hex 32

clean: ## Remove build artifacts
	rm -rf bin/ dist/ coverage.out coverage.html
	cd frontend && rm -rf dist/ node_modules/.vite

install-tools: ## Install development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	cd frontend && npm install
