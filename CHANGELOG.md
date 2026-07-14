# Changelog

All notable changes to Rayyan ASM are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Fixed
- **Cross-org WebSocket leak**: `BroadcastRaw` (global fanout) replaced with `BroadcastToOrg` in `workflow_dispatcher.go` and `discovery/engine.go`. Scan progress and discovery events are now scoped to the requesting tenant. `BroadcastRaw` retained only for admin tool-installer events which are legitimately global. All three `WSHub` interfaces updated to require `BroadcastToOrg`.
- **Silent DB errors** across handlers: ~40 `.Find()`/`.First()`/`.Updates()` calls in `handlers.go`, `assets.go`, `findings.go`, and `projects_notes_todos.go` now propagate errors to the caller with appropriate HTTP 500 responses and structured log entries.
- **Request context propagation**: Key list endpoints (`DomainHandler`, `HostHandler`, `ServiceHandler`, `DNSHandler`, `AlertHandler`, `ScanHandler.List`, `FindingsHandler`, `AuditHandler`) now pass `c.Request.Context()` to GORM via `db.WithContext(ctx)` through the new `dbCtx(db, c)` helper. Client disconnects now cancel in-flight queries, preventing goroutine and DB connection leaks under load.
- **Inconsistent pagination caps**: Centralised in `internal/api/handlers/pagination.go`. Constants `MaxPageLimit` (500), `MaxPageLimitLarge` (1000), `MaxPageLimitSmall` (200), and `DefaultPageLimit` (20) replace ad-hoc inline values. Helper functions `clampPage` and `clampLimit` added.

### Added
- `internal/api/handlers/pagination.go`: central pagination constants and `dbCtx` helper.
- `tests/integration/pagination_ws_test.go`: integration tests covering pagination cap enforcement, negative page handling, WS ticket endpoint, and request context propagation across list endpoints.

- Migrations 001–009 reconstructed as canonical SQL files for full schema replay
- GitHub Actions CI pipeline: lint → vet → unit test → build → docker push
- Frontend test infrastructure: Vitest + @testing-library/react, auth store tests, LoginPage tests
- Email verification flow on registration (token, resend endpoint, middleware gate)
- Route-based code splitting via `React.lazy` + `Suspense` across all 30+ routes
- `ErrorBoundary` component with per-route and root-level recovery
- Cloud module unit tests (Shodan, Censys, SecurityTrails, VirusTotal) via `httptest`
- `CHANGELOG.md`

### Changed
- `App.tsx` refactored from eager static imports to lazy-loaded routes

### Fixed
- Dockerfile frontend copy path confirmed correct (was a false alarm)

---

## [1.0.0] — 2025-06

### Added
- Module 1: Asset discovery — domains, subdomains, hosts, services, certificates, DNS, technologies
- Module 2: Risk scoring engine with weighted CVSS/exposure/staleness factors
- Module 3: Attack path analysis (Dijkstra-based graph engine over asset relationships)
- Module 4: Advanced alerting, change detection, exposure centre, executive KPI dashboard
- Continuous external discovery (Shodan, Censys, SecurityTrails, VirusTotal, CT logs)
- Tool runner — 30+ offensive tools orchestrated as async jobs with streaming results
- WebSocket hub for real-time scan progress and alert feed
- TOTP MFA, JWT revocation via Redis, AES-256-GCM credential encryption
- Password reset with SMTP delivery and token hashing
- Role-based access control (admin / analyst / viewer)
- Multi-stage Dockerfile + docker-compose with PostgreSQL, Redis, and Nginx
- Kubernetes manifests and Helm chart skeleton
- Integration test suite and per-module unit tests
- Migrations 010–026 covering all module additions

### Security
- WebSocket orgID no longer trusted from query param (JWT-derived)
- MFA verify endpoint rate-limited (5 req/min)
- WebSocket `writePump` exits cleanly on send error
- SMTP password reset now delivered (was silently dropped)
- JWT refresh tokens rotated on use
- Rate limiting on login and MFA endpoints
