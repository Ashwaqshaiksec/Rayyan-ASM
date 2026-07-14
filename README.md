# Rayyan ASM — Attack Surface Management Platform

> Production-grade, self-hosted Attack Surface Management platform for authorized asset discovery, inventory management, exposure analysis, and continuous security monitoring.

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat&logo=typescript)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat&logo=postgresql)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Quick Start

**Production** (all 66 scanning tools installed — nmap, subfinder, nuclei, httpx, ffuf, ...):

```bash
docker compose -f docker-compose.yml up --build -d
```

**Dev** (hot reload via `air`, frontend served separately by Vite — **no scanning tools baked in**, this is expected, not a bug):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

`docker-compose.dev.yml` is opt-in only — Compose never merges it automatically, so a plain `docker compose up` always gives you the production build.

### How it's deployed

In production, the Go binary itself serves both the REST API and the built React frontend from a single origin on port 8080 — there is no separate frontend container, and no nginx layer is required to reach the app. CORS only becomes relevant in dev mode, where the frontend runs on its own Vite dev server (port 5173) and talks to the backend (port 8080) across origins.

---

## Overview

Rayyan ASM is a comprehensive, open-source Attack Surface Management platform designed for security teams performing **authorized** asset discovery and monitoring. It provides:

- **Asset Discovery** — Network scanning, DNS intelligence, web crawling, cloud inventory
- **Continuous Monitoring** — Scheduled scans, change detection, certificate expiry alerts
- **Asset Inventory** — Centralized database of domains, hosts, services, certificates, and technologies
- **Multi-tenant** — Organization isolation with RBAC (admin / analyst / viewer)
- **Real-time** — WebSocket live updates during scans
- **API-first** — Full REST API with API key support

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Nginx (Reverse Proxy)                 │
│              Port 80/443 → Frontend + API + WS              │
└─────────────────┬───────────────────────┬───────────────────┘
                  │                       │
         ┌────────▼───────┐     ┌─────────▼────────┐
         │  React Frontend│     │  Go Backend (Gin) │
         │  (TypeScript)  │     │  Port 8080        │
         │  Tailwind CSS  │     │  REST API         │
         └────────────────┘     │  WebSocket Hub    │
                                │  Job Queue        │
                                │  Scheduler        │
                                └────┬────────┬─────┘
                                     │        │
                            ┌────────▼──┐  ┌──▼──────┐
                            │ PostgreSQL│  │  Redis  │
                            │  (main)   │  │ (queue) │
                            └───────────┘  └─────────┘
```

### Discovery Engine

```
Scan Job Created
      │
      ▼
Job Queue (Redis / in-memory)
      │
      ▼
Worker Pool (goroutines)
      │
   ┌──┴──────────────────────────────┐
   │  Dispatch by scan type          │
   ├─ network  → ICMP/TCP probing    │
   ├─ port     → TCP/UDP port scan   │
   ├─ dns      → DNS record harvest  │
   ├─ web      → HTTP/TLS analysis   │
   └─ full     → All of the above    │
                                     │
      ┌──────────────────────────────┘
      │
      ▼
Results saved to PostgreSQL
      │
      ▼
WebSocket broadcast → Frontend live update
      │
      ▼
Alert generation (cert expiry, new assets, changes)
```

---

## Technology Stack

| Layer        | Technology                              |
|--------------|-----------------------------------------|
| Backend      | Go 1.22+, Gin, GORM                     |
| Database     | PostgreSQL 16 (production), SQLite (dev)|
| Cache/Queue  | Redis 7                                 |
| Frontend     | React 18, TypeScript, Vite, Tailwind    |
| Auth         | JWT (HS256), bcrypt, API Keys           |
| Realtime     | WebSocket (gorilla/websocket)           |
| Scheduler    | robfig/cron v3                          |
| Container    | Docker, Docker Compose                  |
| Orchestration| Kubernetes, Helm                        |
| CI/CD        | GitHub Actions                          |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Git

### 1. Clone the repository

```bash
git clone https://github.com/ShadooowX/rayyan-asm.git
cd rayyan-asm
```

### 2. Configure environment

```bash
cp .env.docker.example .env
# Edit .env with your values:
#   DB_PASSWORD, REDIS_PASSWORD, JWT_SECRET
#   Optional: SHODAN_API_KEY, CENSYS_API_ID, etc.
```

`.env.docker.example` uses the short variable names (`DB_PASSWORD`,
`JWT_SECRET`, ...) that `docker-compose.yml` itself substitutes and then
translates into the app's real `RAYYAN_*` config vars — don't use
`.env.example` here, that one's for running the Go server natively without
Docker Compose (see [Development Setup](#development-setup) below), and its
`RAYYAN_*` names won't match anything `docker-compose.yml` looks for.

### 3. Start with Docker Compose

```bash
docker compose up -d --build
```

This starts three containers:
- PostgreSQL on :5432
- Redis on :6379 (password-protected — see `REDIS_PASSWORD` in `.env`)
- The Go backend on :8080, which also serves the built React frontend
  directly (no separate Nginx/frontend container — the frontend is a static
  bundle compiled into the same image at build time)

### 4. Open the platform

Navigate to **http://localhost:8080** and register your organization.

---

## Development Setup

### Backend (Go)

```bash
# Install dependencies
go mod download

# Run with SQLite (no external deps needed)
RAYYAN_DATABASE_DRIVER=sqlite \
RAYYAN_DATABASE_FILEPATH=./rayyan-dev.db \
RAYYAN_AUTH_JWTSECRET=dev-secret-change-in-production \
go run ./cmd/server

# Server listens on :8080
```

### Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
# Dev server on :5173, proxies /api → :8080
```

### Run all tests

```bash
# Backend tests (unit + integration)
go test ./... -v -race

# Short mode (skip network-dependent tests)
go test ./... -short

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Frontend type check
cd frontend && npx tsc --noEmit
```

---

## Configuration

Configuration is loaded from (in order of precedence):

1. Environment variables (prefix: `RAYYAN_`)
2. `./config/config.yaml`
3. `/etc/rayyan-asm/config.yaml`
4. Built-in defaults

### Key configuration options

| Variable | Default | Description |
|----------|---------|-------------|
| `RAYYAN_DATABASE_DRIVER` | `sqlite` | `postgres` or `sqlite` |
| `RAYYAN_DATABASE_HOST` | `localhost` | PostgreSQL host |
| `RAYYAN_DATABASE_PASSWORD` | — | PostgreSQL password |
| `RAYYAN_REDIS_ENABLED` | `false` | Enable Redis for queue |
| `RAYYAN_AUTH_JWTSECRET` | — | **Required** — JWT signing secret |
| `RAYYAN_QUEUE_WORKERS` | `10` | Number of scan worker goroutines |
| `RAYYAN_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `RAYYAN_EXTERNAL_SHODANAPIKEY` | — | Shodan API key |
| `RAYYAN_EXTERNAL_CENSYSAPIID` | — | Censys API ID |
| `RAYYAN_EXTERNAL_VIRUSTOTALKEY` | — | VirusTotal API key |

---

## API Reference

Base URL: `http://localhost:8080/api/v1`

### Authentication

```bash
# Login
POST /auth/login
{"email": "admin@example.com", "password": "password"}
→ {"access_token": "...", "refresh_token": "...", "user": {...}}

# Use token
Authorization: Bearer <access_token>

# API Key
X-API-Key: rayyan_<key>
```

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard` | Summary statistics |
| GET | `/domains` | List domains |
| POST | `/domains` | Add domain |
| GET | `/domains/:id` | Get domain detail |
| GET | `/domains/:id/subdomains` | Domain subdomains |
| GET | `/hosts` | List hosts / IPs |
| GET | `/hosts/:id/services` | Host services |
| GET | `/services` | List all services |
| GET | `/certificates` | List certificates |
| GET | `/certificates/expiring` | Expiring certs (30d) |
| GET | `/dns` | List DNS records |
| POST | `/scans` | Create scan job |
| GET | `/scans/:id` | Scan status |
| GET | `/alerts` | List alerts |
| PUT | `/alerts/:id/acknowledge` | Acknowledge alert |
| POST | `/reports` | Generate report |
| GET | `/search?q=<query>` | Global asset search |
| GET | `/cloud` | Cloud assets |
| GET | `/technologies` | Detected technologies |

### Scan Payload Example

```json
POST /api/v1/scans
{
  "name": "Production Network Scan",
  "type": "full",
  "targets": {
    "hosts": ["10.0.0.0/24", "192.168.1.0/24"],
    "domains": ["example.com"]
  },
  "options": {
    "resolve_dns": true,
    "banner_grab": true,
    "full_port_range": false,
    "parse_tls": true
  }
}
```

### WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8080/ws')
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data)
  // msg.type: scan_created | scan_updated | scan_completed | alert_created
  // msg.data: payload
}
```

---

## Roles & Permissions

| Action | admin | analyst | viewer |
|--------|:-----:|:-------:|:------:|
| View all assets | ✅ | ✅ | ✅ |
| Create scans | ✅ | ✅ | ❌ |
| Add/edit domains & hosts | ✅ | ✅ | ❌ |
| Manage users | ✅ | ❌ | ❌ |
| View audit log | ✅ | ❌ | ❌ |
| Manage API keys | ✅ | ✅ | ✅ (own only) |
| Delete assets | ✅ | ❌ | ❌ |

---

## Discovery Modules

### Network Discovery
- TCP connect probing across worker pool
- CIDR expansion (IPv4 + IPv6)
- Reverse DNS resolution
- Configurable concurrency and rate limiting

### Port Scanner
- TCP SYN / connect scanning
- Banner grabbing
- Service fingerprinting (80+ services)
- Common ports mode or full range (1–65535)

### DNS Intelligence
- A, AAAA, MX, TXT, NS, SOA, PTR records
- Custom resolver support (1.1.1.1, 8.8.8.8, etc.)
- Subdomain enumeration (wordlist-based)
- Concurrent multi-domain scanning

### Web Asset Discovery
- HTTP and HTTPS probing
- Redirect chain following
- TLS certificate parsing
- Security header analysis
- Technology fingerprinting (20+ patterns)

### External Integrations
| Provider | Capabilities |
|----------|-------------|
| **Shodan** | Host lookup, search query |
| **Censys** | Host services, certificates |
| **SecurityTrails** | Subdomain enumeration, DNS history |
| **VirusTotal** | Domain reputation, passive DNS |

---

## Kubernetes Deployment

```bash
# Apply manifests
kubectl apply -f deployments/kubernetes/manifests.yaml

# Edit the Secret before applying
kubectl -n rayyan-asm edit secret rayyan-secrets

# Or with Helm
helm repo add bitnami https://charts.bitnami.com/bitnami
helm dependency update deployments/helm/
helm upgrade --install rayyan-asm deployments/helm/ \
  --namespace rayyan-asm --create-namespace \
  --set env.jwtSecret=<your-32-char-secret> \
  --set env.postgresPassword=<password> \
  --set env.redisPassword=<password>
```

---

## Project Structure

```
rayyan-asm/
├── cmd/
│   └── server/main.go          # Entry point
├── internal/
│   ├── api/
│   │   ├── router.go           # Gin router + route registration
│   │   ├── handlers/           # HTTP handler functions
│   │   ├── middleware/         # Auth, RBAC, rate limit, audit
│   │   └── websocket/          # WebSocket hub
│   ├── auth/                   # JWT, bcrypt, API keys
│   ├── config/                 # Viper-based config loading
│   ├── database/               # GORM init + AutoMigrate
│   ├── models/                 # GORM models (all tables)
│   ├── modules/
│   │   ├── network/            # ICMP/TCP host discovery
│   │   ├── port/               # Port scanner
│   │   ├── dns/                # DNS intelligence
│   │   ├── web/                # HTTP/TLS asset scanner
│   │   └── cloud/              # External API integrations
│   ├── queue/                  # Worker pool + Redis queue
│   └── scheduler/              # Cron-based job scheduler
├── pkg/
│   └── logger/                 # Zap logger wrapper
├── tests/
│   └── integration/            # API integration tests
├── frontend/
│   ├── src/
│   │   ├── components/         # Reusable React components
│   │   ├── pages/              # Page components (one per route)
│   │   ├── store/              # Zustand state management
│   │   ├── types/              # TypeScript type definitions
│   │   └── utils/api.ts        # Axios client + all API helpers
│   ├── index.html
│   └── vite.config.ts
├── deployments/
│   ├── docker/                 # Dockerfiles + Nginx config
│   ├── helm/                   # Helm chart
│   └── kubernetes/             # K8s manifests
├── .github/workflows/ci.yml    # GitHub Actions CI/CD
├── docker-compose.yml
└── go.mod
```

---

## Security Considerations

- All passwords hashed with bcrypt (cost 12 in production)
- JWT tokens signed with HS256; short expiry (24h) + refresh tokens
- API keys hashed before storage; shown only once at creation
- Account lockout after 5 failed login attempts (15-minute lockout)
- RBAC enforced at every protected route
- Full audit log of all mutating API calls
- Rate limiting on all endpoints (strict on /auth/login)
- SQL injection protection via GORM parameterized queries
- CORS configured to allowed origins only

> **Important**: This platform is designed for **authorized** security assessments only. Only scan assets you own or have explicit written permission to scan.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit with conventional commits (`feat:`, `fix:`, `docs:`)
4. Open a Pull Request against `develop`

---

## License

MIT © ShadooowX — See [LICENSE](LICENSE) for details.
