# Static Analysis

Dojigiri's static engine runs in two tiers: regex pattern matching (Tier 1) and tree-sitter AST/semantic analysis (Tier 2). Both run on every scan.

## Language support

| Language | Tier 1 (regex) | Tier 2 (AST) |
|----------|:-:|:-:|
| Python | ✓ | ✓ |
| JavaScript | ✓ | ✓ |
| TypeScript | ✓ | ✓ |
| Java | ✓ | ✓ |
| Go | ✓ | ✓ |
| Rust | ✓ | ✓ |
| C | ✓ | ✓ |
| C++ | ✓ | ✓ |
| Ruby | ✓ | |
| PHP | ✓ | |
| C# | ✓ | |
| Swift | ✓ | |
| Kotlin | ✓ | |
| Pine Script | ✓ | |
| Bash | ✓ | |
| SQL | ✓ | |
| HTML | ✓ | |
| CSS | ✓ | |

## Severity levels

- **CRITICAL** -- exploitable security issues, hardcoded secrets, dangerous function calls
- **WARNING** -- bugs, potential vulnerabilities, resource leaks, null dereferences
- **INFO** -- code smells, style issues, unused code

## Categories

| Category | What it covers |
|----------|---------------|
| SECURITY | Injection, XSS, secrets, crypto, traversal |
| BUG | Null deref, type confusion, mutable defaults, resource leaks |
| PERFORMANCE | Unnecessary allocations, inefficient patterns |
| STYLE | Complexity, naming, dead code |
| DEAD_CODE | Unreachable code, unused variables/imports |

## Tier 2: Semantic analysis

When tree-sitter is available (installed by default), Dojigiri builds a full semantic model of each file:

- **Scope analysis** -- unused variables, shadowed names, uninitialized references
- **Taint tracking** -- source-to-sink flow analysis (SQL injection, command injection, XSS), path-sensitive with CFG
- **Control flow graphs** -- unreachable code, dead branches
- **Type inference** -- type confusion, incompatible operations
- **Null safety** -- branch-aware null dereference detection
- **Resource tracking** -- unclosed files, connections, cursors
- **Code smells** -- god classes, feature envy, semantic clones

## CWE and NIST mapping

Every finding maps to:

- **CWE ID** -- Common Weakness Enumeration (e.g., CWE-89 for SQL injection)
- **NIST SP 800-53 controls** -- federal security control families

This enables compliance reporting via SARIF output.

## Inline suppression

Suppress specific rules per-line:

```python
x = eval(user_input)  # doji:ignore(dangerous-eval)
```
