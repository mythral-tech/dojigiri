# Rule Catalog

!!! note "Full catalog coming soon"
    A complete, searchable rule catalog is in progress. Below is a summary of coverage.

## Rule count by category

| Category | Rules |
|----------|------:|
| Security | 50+ |
| Bug | 30+ |
| Style | 25+ |
| Performance | 10+ |
| Dead Code | 15+ |
| **Total** | **130+** |

## Rules by language

| Language | Tier 1 (regex) | Tier 2 (semantic) |
|----------|:-:|:-:|
| Python | 40+ | Scope, taint, null, types, CFG, resources, smells |
| JavaScript/TypeScript | 30+ | Scope, taint, null, types, CFG |
| Java | 25+ | Scope, taint, null, types, CFG |
| Go | 15+ | Scope, taint, null, types, CFG |
| Rust | 10+ | Scope, taint, null, types, CFG |
| C/C++ | 15+ | Scope, taint, null, types, CFG |
| Other (Ruby, PHP, C#, Swift, Kotlin, Pine, Bash, SQL, HTML, CSS) | 5-10 each | -- |

## Key security rules

- `sql-injection` -- string concatenation in SQL queries (CWE-89)
- `command-injection` -- unsanitized input in shell commands (CWE-78)
- `xss` -- unescaped user input in HTML output (CWE-79)
- `path-traversal` -- directory traversal via user input (CWE-22)
- `hardcoded-secret` -- passwords, API keys, tokens in source (CWE-798)
- `weak-crypto` -- deprecated algorithms (MD5, SHA1, DES) (CWE-327)
- `unsafe-deserialization` -- pickle, yaml.load, eval on untrusted data (CWE-502)
- `insecure-cookie` -- cookies without Secure/HttpOnly flags (CWE-614)

## Key bug detection rules

- `null-dereference` -- branch-aware null pointer analysis (CWE-476)
- `resource-leak` -- unclosed files, connections, cursors (CWE-772)
- `mutable-default` -- mutable default arguments in Python
- `type-confusion` -- incompatible type operations
- `unused-variable` -- declared but never referenced
- `unreachable-code` -- code after return/break/continue

## Listing rules via CLI

```bash
doji rules                    # List all rules
doji rules --language python  # Python rules only
doji rules --category security # Security rules only
```
