# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.1.x | Yes |
| < 1.1 | No |

## Reporting a Vulnerability

If you discover a security vulnerability in Dojigiri, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **tattoo.laforge@gmail.com** (or open a private security advisory on GitHub via the "Security" tab).

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (what an attacker could achieve)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Assessment:** Within 7 days
- **Fix or mitigation:** Depends on severity, targeting within 30 days for critical/high issues

## Scope

The following are in scope for security reports:

- Path traversal or file access outside intended boundaries
- Prompt injection that suppresses legitimate security findings
- API key exfiltration or credential exposure
- Code execution via auto-fix (malicious fix injection)
- MCP server boundary bypasses
- Denial of service via crafted input (e.g., ReDoS in custom rules)
- Supply chain issues (dependency vulnerabilities, build process)

The following are generally out of scope:

- False positives/negatives in static analysis rules (use regular issues)
- LLM hallucinations or incorrect findings (expected limitation, documented)
- Issues requiring physical access to the machine running Dojigiri

## Security Design

Dojigiri's security architecture is documented across:

- [PRIVACY.md](PRIVACY.md) — Data handling and transmission
- [TERMS.md](TERMS.md) — Disclaimers and liability
- [ARCHITECTURE.md](ARCHITECTURE.md) — System design

Key security boundaries:
- Static scan mode makes zero network requests
- Deep scan requires explicit consent (`--accept-remote`)
- MCP server restricts file access to cwd and validated subdirectories
- Auto-fix requires `--accept-llm-fixes` for LLM-generated changes
- API keys are only read from environment variables (never from config files)
- Scanned code is wrapped in XML boundary tags to mitigate prompt injection
