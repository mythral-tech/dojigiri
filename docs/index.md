# Dojigiri

**Static analysis + SCA with a three-tier engine: regex, AST/semantic, and LLM.**

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](https://github.com/mythral-tech/dojigiri/blob/main/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-1426-brightgreen.svg)]()
[![OWASP Benchmark](https://img.shields.io/badge/OWASP%20Benchmark%20v1.2-100%25-brightgreen.svg)]()
[![Languages](https://img.shields.io/badge/languages-18-blue.svg)]()

```bash
pip install dojigiri
doji scan .
```

## Why Dojigiri

- **Three analysis tiers.** Regex patterns (fast, 18 languages) &rarr; tree-sitter AST/semantic analysis (CFG, taint, null safety, type inference) &rarr; optional LLM deep scan for what rules can't reach.
- **Zero config.** Works out of the box. No database, no Docker, no JVM.
- **Built-in SCA.** Dependency vulnerability scanning via Google OSV across 10 lockfile formats.
- **SARIF, JSON, HTML output.** Plugs into GitHub Code Scanning, GitLab SAST, or any SARIF-compatible tool.
- **MCP server mode.** AI agents and IDEs can invoke scans programmatically.
- **CWE + NIST SP 800-53 mappings.** Every finding links to a CWE ID and NIST control.
- **Auto-fix.** Deterministic fixers + LLM-assisted fixes with syntax validation.

## Quick Links

- [Installation](getting-started/installation.md) -- get running in 30 seconds
- [Quick Start](getting-started/quickstart.md) -- scan, fix, explain
- [CI/CD Integration](getting-started/ci-cd.md) -- GitHub Actions, GitLab CI
- [Configuration](configuration.md) -- `.doji.toml` reference
- [Benchmarks](benchmarks.md) -- OWASP Benchmark v1.2 results
