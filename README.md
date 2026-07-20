# Aegis

A security gateway for AI and software agents.

Aegis provides a unified authorization, policy enforcement, and audit layer for
autonomous agents. It operates as a CLI tool and HTTP API, sitting between
agents and the resources they access — filesystem, network, process execution,
and AI services.

## The problem

Autonomous agents make decisions that affect real systems. Without a
centralized enforcement layer, each agent must independently implement its own
security controls — a pattern that leads to inconsistent enforcement,
incomplete audit trails, and unintended access.

## What Aegis does

Aegis provides a policy evaluation engine, role-based access control,
tamper-evident audit logging, entitlement management, and a payment/subscription
system — all accessible through a CLI and an HTTP API. Agents do not decide what
they are allowed to do; Aegis enforces it.

## Who it is for

- **Developers** building autonomous agent systems that need a security layer
- **Platform teams** providing agent infrastructure within an organization
- **Security engineers** who need audit trails and policy enforcement for agent
  actions

## Architecture

```
User
 │
 ├── CLI
 └── API (FastAPI)
        │
        ▼
  Authentication (bcrypt, sessions)
        │
        ▼
  Role-Based Access Control (USER / PAYMENT_VERIFIER / ADMIN)
        │
        ▼
  Gateway — precondition validation, policy lookup, audit orchestration
        │
        ▼
  Policy Engine — deterministic, priority-ordered rule matching
        │
        ▼
  Controlled Capability (filesystem / process / network / AI)
        │
        ▼
  Audit Log — tamper-evident SHA-256 hash chain
```

Each request passes through every layer. The system fails closed: any error at
any layer produces a DENY decision.

## Core capabilities

- **Authentication** — bcrypt password hashing, session tokens (SHA-256 hashed
  in storage), login/logout, session revocation
- **Role-Based Access Control** — three roles (USER, PAYMENT_VERIFIER, ADMIN)
  with granular permissions, fail-closed for unknown roles
- **Agent Registry** — per-user agent registration, ownership isolation,
  revocation
- **Policy Engine** — deterministic, priority-ordered rule matching; supports
  exact, wildcard (`*`), and prefix (`abc*`) matching; defaults to DENY when
  no rule matches
- **Default-Deny Authorization** — every decision starts as DENY; only explicit
  ALLOW rules in an applicable policy can change it
- **Fail-Closed Behavior** — any precondition failure (unknown agent, revoked
  agent, policy evaluation error, audit persistence failure) produces a DENY
  decision
- **Audit Logging** — tamper-evident hash chain using SHA-256; each event links
  to the previous event via `previous_hash`; `verify()` detects inserted,
  deleted, reordered, or modified events
- **Controlled Filesystem Access** — read-only, scope-constrained to a
  designated directory; path canonicalization prevents traversal escapes;
  no write or delete operations
- **Process Execution Allowlists** — name-to-path mapping with canonical path
  resolution and symlink substitution detection; no shell execution
- **Network Destination Allowlists** — scheme, hostname, port, and path-prefix
  matching; SSRF protection blocks private/loopback/link-local/multicast IPs
- **AI Copilot** — explains security decisions, summarizes audit logs, reviews
  and drafts policies; local template-based provider or remote OpenAI-compatible
  provider
- **Entitlements and Subscriptions** — Free, Pro, and Enterprise plans with
  configurable entitlements (agent limits, policy limits, feature flags);
  most-recent-wins state machine
- **UPI Payment Submission and Verification** — UTR-based payment submissions
  with duplicate detection; explicit verification workflow requiring authorized
  verifier; never auto-verifies
- **HTTP API** — FastAPI with versioned endpoints (`/api/v1/`), Bearer token
  authentication, structured request/response schemas, centralized exception
  handling, rate limiting, CORS configuration, OpenAPI documentation

## Quick Start

```bash
git clone https://github.com/rishabhks651-byte/Aegis
cd Aegis
python -m venv .venv
```

**Windows:**
```powershell
.venv\Scripts\activate
```

**Linux / macOS:**
```bash
source .venv/bin/activate
```

```bash
python -m pip install --upgrade pip
pip install -e .
```

Verify the installation:

```bash
aegis --help
aegis --version
```

## CLI Examples

```bash
# Create a user
aegis user create alice

# Login
aegis auth login

# Create an agent
aegis agent create my-bot

# Apply a policy
aegis policy apply policy.yaml

# Evaluate an action
aegis action evaluate <agent-id> <policy-id> fs_read path=/safe/file.txt

# Verify the audit chain integrity
aegis audit verify

# List registered agents
aegis agent list

# List applied policies
aegis policy list
```

## API

Start the API server:

```bash
aegis api
```

The API serves at `http://127.0.0.1:8000` with OpenAPI documentation at
`/api/v1/docs`.

Endpoints are organized under `/api/v1/`:

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET  /api/v1/auth/me`
- `GET  /api/v1/auth/permissions`
- `POST /api/v1/agents`
- `GET  /api/v1/agents`
- `GET  /api/v1/agents/{agent_id}`
- `POST /api/v1/agents/{agent_id}/revoke`
- `POST /api/v1/policies`
- `GET  /api/v1/policies`
- `GET  /api/v1/policies/{policy_id}`
- `POST /api/v1/actions/evaluate`
- `POST /api/v1/filesystem/read`
- `POST /api/v1/execution/execute`
- `POST /api/v1/network/request`
- `POST /api/v1/copilot/explain`
- `POST /api/v1/copilot/audit-summary`
- `POST /api/v1/copilot/policy-review`
- `POST /api/v1/copilot/policy-draft`
- `POST /api/v1/payments/submit`
- `GET  /api/v1/payments`
- `GET  /api/v1/payments/{payment_id}`
- `POST /api/v1/payments/verify`
- `POST /api/v1/payments/reject`
- `GET  /api/v1/subscriptions/me`
- `GET  /api/v1/subscriptions/me/entitlements`
- `GET  /api/v1/subscriptions/plans`

## Security model

### Default-deny and fail-closed

Every evaluation starts as DENY. Only an explicit ALLOW rule in a matching
policy can produce an ALLOW decision. If any component fails — agent lookup,
policy evaluation, or audit persistence — the result is DENY. The system
cannot be tricked into ALLOW by causing an error.

### Authentication vs authorization

Authentication (bcrypt password verification + session tokens) verifies *who
you are*. Authorization (RBAC permissions) determines *what you can do*. A
valid session does not grant any permissions by itself; role-based permissions
are checked independently.

### Policy evaluation vs sandboxing

Policy evaluation (`engine.py`) is a pure, stateless function that returns a
decision based on the action and the applicable policies. It does not execute
anything. Sandboxing (scope-constrained filesystem, process allowlists, network
allowlists, SSRF validation) is a separate layer that restricts what the
underlying capability can access, regardless of the policy decision.

### Tamper-evident, not tamper-proof

The audit log uses a SHA-256 hash chain that makes tampering detectable
(`aegis audit verify`). It does not prevent tampering at the storage layer.
Severity: tampering is detected, not prevented. Operational controls
(filesystem permissions, backups, append-only storage) are the responsibility
of the deployer.

### Secret handling

- Passwords are hashed with bcrypt (12 rounds); never stored in plaintext
- Session tokens are stored as SHA-256 hashes; the raw token is shown only at
  creation time
- API tokens (when used) follow the same hash-and-reveal-once pattern
- Sensitive parameters (passwords, tokens, secrets) are redacted from logs
- UPI destination ID is configurable via `AEGIS_UPI_ID` environment variable

## Testing

The project uses pytest:

```bash
pip install -e ".[dev]"
pytest
```

The test suite covers:

- Authentication (registration, login, logout, session expiry, revocation)
- RBAC (permissions, role assignment, ownership isolation)
- Policy engine (matching, wildcards, priority, default-deny)
- Gateway (full evaluation lifecycle, preconditions, audit)
- Audit log (append, query, hash-chain integrity, tamper detection)
- Filesystem (authorized access, path traversal prevention)
- Process execution (allowlist enforcement, timeout, output limits)
- Network (allowlist matching, SSRF validation, HTTP client)
- AI Copilot (decision explanation, audit summary, policy review/draft)
- Payments (UTR validation, submission, verification, rejection, RBAC
  enforcement)
- Entitlements (plan limits, subscription state machine, expiry)
- API (all endpoints, authentication, authorization, validation, error
  handling, rate limiting, CORS, security headers)
- Persistence (NDJSON storage, SQLAlchemy ORM, migration)
- Models (frozen dataclass invariants, serialization, determinism)

## Production status

Aegis is under active development. Core security controls are implemented and
tested, but production deployment should follow the documented hardening and
operational requirements.

## Project status

### Implemented

- Core security controls (authentication, RBAC, policy engine, gateway)
- Tamper-evident audit logging
- Controlled filesystem, process, and network access with allowlists
- SSRF protection
- AI Copilot (local and remote providers)
- Entitlement and subscription management
- UPI payment submission and manual verification workflow
- FastAPI HTTP API with rate limiting and CORS
- NDJSON-based local storage
- SQLAlchemy persistence layer and NDJSON-to-SQL migration
- Comprehensive test suite

### In progress

- Production database backend hardening
- Deployment documentation and operational runbooks
- Additional audit and monitoring integrations

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE)
file for details.
