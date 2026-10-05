# Security

QuantZen™ SolveGio Gateway is an MVP security gateway PoC.

## Current controls

- Hybrid Ed25519 + ML-DSA-65 request signatures.
- RFC 8785 JSON canonicalization and SHA-256 content binding.
- Protocol versioning with tenant-bound signature targets.
- Timestamp tolerance and nonce replay protection.
- Distributed replay protection fails closed when Redis is configured but unavailable.
- Administrative dashboard APIs require signed, HttpOnly cookie sessions with CSRF protection.
- Repeated administrator login failures are throttled.
- Dashboard responses use security headers and API responses are not cached.
- Request and signature inputs are size-bounded.
- Local Compose database and Redis ports are bound to loopback.
- Go unit tests, vetting, and govulncheck run in CI.

## Required deployment secrets

Set a strong DASHBOARD_PASSWORD and a random DASHBOARD_SESSION_SECRET of at least 32 bytes. Never commit SolveGio API keys, webhook secrets, database passwords, Redis passwords, or dashboard credentials.

For production, use managed secret storage and hardware-backed key custody where appropriate. The current demo identity and in-memory trust registry are not a production key-management system.

## Disclosure

Do not publish exploit details in public issues. Contact the project maintainers privately with reproduction steps and affected commit/version.

The current build has not undergone independent cryptographic review, penetration testing, formal conformance validation, or production security certification.
