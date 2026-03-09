# Case 14: SSRF in Next.js API Route via Middleware Transform

**CWE:** CWE-918 (Server-Side Request Forgery)

## Vulnerability

User-controlled `req.query.url` flows through `buildProxyUrl()` in a middleware module, then into `fetch()`. The `buildProxyUrl` function parses and reconstructs the URL but performs no validation of the host — an attacker can request `?url=http://169.254.169.254/latest/meta-data/` to access AWS instance metadata or internal services.

The `new URL()` constructor looks like validation but only ensures the string is a well-formed URL, not that it points to an allowed host.

## Why Semgrep Misses It

Semgrep's SSRF rules match patterns like `fetch(req.query.url)` in a single file. Here the taint flows cross-file: `req.query.url` → `buildProxyUrl()` (in `middleware.js`) → return value → `fetch()` (in `api/proxy.js`). Semgrep's intra-file analysis loses track of the taint when it crosses the module boundary.

Additionally, `new URL()` inside `buildProxyUrl` may be treated as a sanitizer by some rules (URL parsing = validation assumption), even though it doesn't restrict the target host.

## Detection Requirements

- Cross-file taint tracking through imported function calls
- Understanding that `new URL()` is not an SSRF sanitizer (it validates format, not destination)
- Modeling `fetch()` as an SSRF sink when its argument derives from user input
