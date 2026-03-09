# SSRF Through Wrapper Function

**CWE-918** | Server-Side Request Forgery

## Vulnerability

User input (`request.args["url"]`) flows into `fetch_json()`, a wrapper in `utils.py` that calls `httpx.get()`. No URL validation, no allowlist, `follow_redirects=True` makes bypass trivial.

## Why Semgrep Misses It

Semgrep's taint tracking doesn't follow data flow across function calls into separate files by default. The sink (`httpx.get`) is behind a wrapper (`fetch_json` -> `fetch_url` -> `httpx.get`), which is two levels of indirection in a different module. Semgrep's inter-file analysis (DeepSemgrep/Pro) handles simple cases but struggles with multi-hop wrapper chains where the tainted argument is passed positionally through helper functions.

## Attack

```
GET /preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
