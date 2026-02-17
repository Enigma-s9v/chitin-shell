# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Chitin Shell, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

Email: **security@chitin.id**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity (Critical: 7 days, High: 14 days, Medium: 30 days)

### What Qualifies

- Bypassing process isolation (accessing credentials from the LLM container)
- Policy engine bypass (executing actions without proper verification)
- Output sanitization bypass (secrets leaking through to the LLM)
- Signature forgery or verification bypass
- Rate limiter bypass
- Audit log tampering

### What Does NOT Qualify

- The LLM producing malicious Intents (this is expected — the Policy Engine catches them)
- Denial of service on the Policy Engine (availability, not security)
- Issues in dependencies (report to the dependency maintainer)
- Social engineering attacks on human approval flow

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (alpha) | Best effort |
| < 0.1 | Not supported |

## Security Design

Chitin Shell's security model is documented in [ARCHITECTURE.md](./docs/ARCHITECTURE.md). Key principles:

1. **Zero-Knowledge Agent**: The LLM never has access to credentials
2. **Intent, Not Action**: The LLM produces structured requests, not raw API calls
3. **Defense in Depth**: Multiple independent security layers
4. **Fail-Closed**: Unknown actions default to Tier 3 (human approval required)

## Acknowledgments

We thank the following researchers for responsibly disclosing vulnerabilities:

*(None yet — be the first!)*
