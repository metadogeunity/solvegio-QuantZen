# QuantZen™ × SolveGio

A strong, intentionally small MVP security gateway around the SolveGio MVNE/MVNO API.

Architecture: Partner or simulator → QuantZen™ Gateway → SolveGio API → SolveGio webhook → verification → audit/control panel.

Included:
- Ed25519 + ML-DSA-65 hybrid request authentication
- RFC 8785 JSON canonicalization
- SHA-256 payload binding
- timestamp and nonce replay protection
- trust registry and key status
- SolveGio server-side API connector
- SolveGio webhook HMAC verification and event deduplication
- hash-linked audit events
- operator dashboard and simulator
- Docker Compose and Helm deployment

Representative SolveGio paths:
GET /v1/destinations
GET /v1/products
GET /v1/products/{id}
POST /v1/payments
GET /v1/subscriptions
GET /v1/subscriptions/{id}

Run locally:
1. cp .env.example .env
2. docker compose up --build
3. open http://localhost:8080

PoC only. No claim of production certification, formal cryptographic audit, HSM-backed keys or full MVNE functionality.


CI runs module tidy, formatting, tests, and vet checks.
