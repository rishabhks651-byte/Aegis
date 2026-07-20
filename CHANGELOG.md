# Changelog

All notable changes to this project will be documented here.

## [Unreleased]

### Added

- Authentication with bcrypt password hashing and session tokens
- Role-based access control (USER, PAYMENT_VERIFIER, ADMIN)
- Agent registry with ownership isolation and revocation
- Deterministic policy engine with priority-ordered rule matching
- Default-deny authorization with fail-closed behavior
- Tamper-evident audit logging with SHA-256 hash chain
- Controlled filesystem access (read-only, scope-constrained)
- Process execution allowlists with symlink protection
- Network destination allowlists with SSRF validation
- AI Copilot with local template-based provider and remote OpenAI-compatible
  provider
- Subscription and entitlement management with built-in Free, Pro, and
  Enterprise plans
- UPI payment submission and manual verification workflow
- FastAPI HTTP API with versioned endpoints, Bearer token authentication,
  rate limiting, CORS, and OpenAPI documentation
- NDJSON-based local storage
- SQLAlchemy persistence layer and NDJSON-to-SQL migration
- Comprehensive test suite

### Changed

- Initial project structure and packaging

### Fixed

- (None yet — initial release)
