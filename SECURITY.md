# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

Rayyan ASM is an attack surface management platform. We take security seriously.

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

Email: **security@rayyan-asm.example.com**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Affected component(s)
- Potential impact
- Any suggested mitigations (optional)

### What to Expect

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 5 business days
- **Status updates**: every 7 days while under investigation
- **Credit**: reporters will be credited in release notes unless anonymity is requested

### Scope

In scope:
- API endpoints (`/api/v1/*`)
- Authentication and authorization logic
- Scan execution and result handling
- Data isolation between organizations
- WebSocket communication

Out of scope:
- Rate limiting bypass via distributed IPs
- Social engineering
- Physical access attacks
- Vulnerabilities in dependencies not yet assigned a CVE

### Disclosure Policy

We follow coordinated disclosure. We ask that you:
- Give us reasonable time to patch before public disclosure (90 days)
- Not exploit vulnerabilities beyond what is needed to demonstrate impact
- Not access or modify other users' data

## Security Controls

- JWT-based authentication with token revocation (Redis)
- Per-organization data isolation enforced at the DB query layer
- bcrypt password hashing (minimum cost 10)
- Rate limiting on all authentication endpoints
- Audit logging for all mutating operations
- Role-based access control (admin / analyst / viewer)
- WebSocket authentication via single-use short-lived tickets
