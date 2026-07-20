# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Aegis, please report it by
emailing **rishabhks651@gmail.com**.

**Do not** open a public GitHub issue for security vulnerabilities.

### What to include

- A clear description of the issue
- Steps to reproduce (proof of concept is helpful)
- The affected version(s)
- Any suggested fix, if known
- Your contact information for follow-up

### What to expect

- We will acknowledge receipt within 48 hours
- We will investigate and provide an estimated timeline for a fix
- We will notify you when the issue is resolved
- We will credit you in the release notes (unless you prefer to remain
  anonymous)

## Responsible disclosure

Please allow us reasonable time to investigate and fix the issue before
disclosing it publicly. We aim to release a fix within 90 days of
notification for confirmed vulnerabilities.

## Supported versions

Only the latest release receives security patches. Users are encouraged
to update to the most recent version.

## Scope

The following are considered in scope for security reports:

- Authentication and session handling
- Authorization and RBAC enforcement
- Policy engine decision logic
- Audit log integrity
- Input validation and sanitisation
- Secret and credential handling
- API authentication and rate limiting
- Dependencies with known vulnerabilities

The following are considered out of scope:

- Theoretical attacks requiring physical access to the server
- Attacks requiring the attacker to already have valid credentials
- Voluntary denial of service by authenticated users within their
  entitlement limits
