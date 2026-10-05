# QuantZen™ × SolveGio Security Architecture

QuantZen™ is an external security boundary around the existing SolveGio business platform. The PoC does not rebuild SolveGio.

Request verification order:
1. Parse QuantZen headers.
2. Canonicalize JSON with RFC 8785 JCS.
3. Calculate SHA-256 digest.
4. Resolve kid in the Trust Registry.
5. Require active key and accepted validity window.
6. Validate timestamp tolerance.
7. Verify Ed25519 and ML-DSA-65 signatures.
8. Atomically claim nonce in Redis or the in-memory fallback.
9. Forward only an allowlisted /v1/ path to SolveGio using a server-side API key.
10. Append a hash-linked audit event.

Webhook boundary:
SolveGio webhook timestamp/HMAC is verified first. Event IDs are deduplicated for 24 hours. Accepted events become QuantZen audit entries.

Production hardening backlog:
- KMS/HSM private-key custody
- durable trust registry with RBAC and approvals
- workload identity or mTLS
- per-tenant rate limits and circuit breakers
- OpenTelemetry
- full endpoint schema validation
- independent crypto review and conformance vectors
