# Contributing to Rayyan ASM

## Getting Started

### Prerequisites
- Go 1.22+
- Node.js 20+
- Docker & Docker Compose (for local DB/Redis)
- External tools: `nmap`, `subfinder`, `gowitness`, `nuclei` (see `scripts/install-tools.sh`)

### Local Setup

```bash
# 1. Start dependencies
docker-compose up -d postgres redis

# 2. Copy config
cp config/config.yaml.example config/config.yaml

# 3. Run backend
go run cmd/server/main.go

# 4. Run frontend
cd frontend && npm install && npm run dev
```

### Running Tests

```bash
# Backend unit tests
go test ./...

# Backend with coverage
go test -cover ./...

# Frontend
cd frontend && npm test
```

## Code Standards

### Backend (Go)
- Run `gofmt` and `go vet` before committing
- Handler functions must: validate input, enforce org isolation, write audit logs for mutations
- No raw SQL strings with user input — use GORM parameterized queries
- New scan types must register a cancel-aware context handler in `dispatcher.go`
- All new packages need at least one `_test.go` file

### Frontend (TypeScript/React)
- Strict TypeScript — no `any` unless justified with a comment
- New pages need a corresponding `*.test.tsx`
- Use the shared `api.ts` utility for all API calls

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
feat(scanner): add UDP port scan support
fix(auth): enforce bcrypt minimum cost
docs(api): add OpenAPI spec for findings endpoints
```

## Pull Request Process

1. Fork the repo and create a feature branch from `main`
2. Ensure all tests pass and no new lint warnings
3. Update `CHANGES-*.md` or `CHANGELOG.md` with a description
4. Open a PR with a clear description of the change and why
5. PRs require one approval from a maintainer before merging

## Security Issues

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree your contributions will be licensed under the same license as this project.
