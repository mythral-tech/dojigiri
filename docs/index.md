# Dojigiri Documentation

**Open-source static analysis + SCA with a three-tier engine: regex, AST/semantic, and LLM.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://github.com/mythral-tech/dojigiri/blob/main/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

```bash
pip install dojigiri
doji scan .
```

## Documentation

- [Architecture](architecture.md) -- system design, module map, data flow
- [Configuration](configuration.md) -- `.doji.toml` reference, ignore files, inline suppression
- [CI/CD Integration](ci-integration.md) -- GitHub Actions, GitLab CI, Docker
- [Rules](rules.md) -- rule catalog by category and language
- [Benchmarks](benchmark-comparison.md) -- OWASP Benchmark v1.2 results, competitive comparison
- [Contributing](../CONTRIBUTING.md) -- setup, code style, PR process
- [Security Policy](../SECURITY.md) -- vulnerability reporting
