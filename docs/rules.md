# Rule Catalog

Dojigiri ships 2,179 rules across three tiers.

## Rules by tier

| Tier | Source | Rules | Description |
|------|--------|------:|-------------|
| Tier 1 | Regex patterns | 778 | Fast pattern matching, all 18 languages |
| Tier 1 | YAML rules | 797 | Extended patterns for security, language-specific, and universal checks |
| Tier 3 | LLM rules | 604 | AI security rules (OWASP LLM Top 10, prompt injection, agent safety) |
| **Total** | | **2,179** | |

## Rules by category

| Category | Coverage |
|----------|----------|
| Security | SQL injection, XSS, path traversal, command injection, hardcoded secrets, unsafe deserialization, weak crypto, SSRF, open redirect, and more |
| LLM / AI Security | Prompt injection, system prompt leakage, excessive agency, training data poisoning, multimodal injection, unbounded consumption (OWASP LLM Top 10: 10/10) |
| Bugs | Null dereference (branch-aware), mutable defaults, type confusion, resource leaks, unused variables, unreachable code |
| Quality | Cyclomatic complexity, semantic clones, dead code, too many parameters |

## Rules by language

| Language | Tier 1 (regex + YAML) | Tier 2 (semantic) |
|----------|:---------------------:|:-----------------:|
| Python | 319 + 155 | Scope, taint, null, types, CFG, resources, smells |
| JavaScript | 336 + 126 | Scope, taint, null, types, CFG |
| TypeScript | 336 + 28 | Scope, taint, null, types, CFG |
| Java | 278 + 123 | Scope, taint, null, types, CFG |
| Go | 267 + 68 | Scope, taint, null, types, CFG |
| C# | 216 + 50 | Scope, taint, null, types, CFG |
| PHP | 218 + 52 | Regex rules only |
| Rust | 206 + 40 | Scope, taint, null, types, CFG |
| C/C++, Ruby, Swift, Kotlin, Pine Script, Bash, SQL, HTML, CSS | Regex | -- |

Rule counts are live via `doji rules` (shows regex rules) and the `/v1/languages` API endpoint (shows all tiers).

## Listing rules via CLI

```bash
doji rules                    # List all regex rules
doji rules --language python  # Python rules only
doji rules --category security # Security rules only
```
