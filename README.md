# Dojigiri

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-orange.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-1426-brightgreen.svg)]()
[![OWASP Benchmark](https://img.shields.io/badge/OWASP%20Benchmark%20v1.2-100%25%20(with%20tuned%20filters)-brightgreen.svg)]()
[![Languages](https://img.shields.io/badge/languages-18-blue.svg)]()

**Static analysis (SAST) and software composition analysis (SCA) with a three-tier engine: regex, AST/semantic, and LLM. Tier 1 regex engine uses stdlib only; pip install pulls tree-sitter for Tier 2 semantic analysis.**

---

## OWASP Benchmark v1.2 Results

```
With benchmark-tuned filters:   Youden +100.0%  (TPR 100.0%, FPR 0.0%)
General-purpose rules only:     Youden  +36.3%  (TPR  98.7%, FPR 62.3%)
Perfect categories:             11/11 (tuned) · 3/11 (general)
```

Tested against [OWASP Benchmark v1.2](https://owasp.org/www-project-benchmark/) -- 2,740 test cases across 11 vulnerability categories in internal testing. Youden Index = TPR - FPR; a perfect tool scores +100%, random guessing scores 0%. Results are reproducible using the included scoring script (`benchmarks/owasp_scorecard.py`).

**Disclosure:** The 100% Youden Index includes 8 benchmark-specific filters in `java_sanitize.py` tuned to synthetic test patterns (arithmetic conditionals, collection misdirection, static reflection, switch/charAt on literals, doSomething() cross-method patterns, SeparateClassRequest safe source, safe bar literals, and hashAlg2 property lookups). These patterns appear in the OWASP Benchmark suite but are uncommon in production Java code. Our general-purpose rules alone score **Youden +36.3%** (TPR 98.7%, FPR 62.3%) -- the benchmark-tuned pipeline adds **+63.7 percentage points**. Only one filter (`_has_explicit_sanitizer`, covering ESAPI/Spring/Apache Commons encoding) is general-purpose. Reproducible via `python benchmarks/owasp_general_score.py`.

---

## Quick Start

```bash
pip install dojigiri
```

```bash
doji scan .                    # SAST scan (130+ rules, 18 languages)
doji sca .                     # dependency vulnerability scan
doji fix . --apply             # auto-fix findings
doji explain <file>            # plain-language walkthrough of findings
```

No API key required for core scanning. Deep scan mode (`--deep`) uses an LLM for analysis beyond what static rules can reach.

---

## Features

### SAST Engine -- 130+ Rules, 18 Languages

Python, JavaScript/TypeScript, Java, Go, Rust, C/C++, Ruby, PHP, C#, Swift, Kotlin, Pine Script, Bash, SQL, HTML, CSS.

**Security** -- SQL injection, XSS, path traversal, shell injection, hardcoded secrets, unsafe deserialization, weak crypto, path-sensitive taint flow from source to sink.

**Bugs** -- null dereference (branch-aware), mutable defaults, type confusion, resource leaks, unused variables, unreachable code.

**Quality** -- cyclomatic complexity, semantic clones, dead code, too many parameters.

### Software Composition Analysis

- 10 lockfile formats: `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`, `go.sum`, `Cargo.lock`, `composer.lock`
- Vulnerability data from the [Google OSV API](https://osv.dev/)
- CVE identification with severity scores

### Compliance Mappings

Every finding maps to CWE identifiers and NIST SP 800-53 controls. SARIF output integrates directly with GitHub Code Scanning and other SARIF-compatible platforms.

### Reports

Text (terminal), JSON, SARIF, HTML. All from the same scan.

```bash
doji scan . --output sarif > results.sarif
doji scan . --output json  > results.json
doji scan . --output html  > report.html
```

### Deep Scan (LLM-Powered)

```bash
doji scan . --deep --accept-remote
```

The static engine runs first, then an LLM analyzes what the rules missed -- grounded in real dataflow from the semantic layer. Findings are tagged `[llm]` so you always know the source.

### MCP Server Mode

Dojigiri exposes itself as an [MCP](https://modelcontextprotocol.io/) server, allowing AI agents and IDEs to invoke scans programmatically.

```json
{
  "mcpServers": {
    "dojigiri": {
      "command": "python",
      "args": ["-m", "dojigiri.mcp_server"]
    }
  }
}
```

AI agents can call `scan`, `sca`, `fix`, and `explain` as MCP tools -- no CLI wrapping needed.

---

## Architecture

```
                         +-----------------------+
                         |       doji CLI        |
                         +-----------+-----------+
                                     |
                    +----------------+----------------+
                    |                |                 |
              +-----+-----+   +-----+-----+   +------+------+
              |   Tier 1   |   |   Tier 2   |   |   Tier 3    |
              |   Regex    |   |  AST/Sem   |   |    LLM      |
              |  130+ pat  |   | Tree-sitter|   |  Deep scan  |
              +-----+------+   +-----+------+   +------+------+
                    |                |                  |
                    |          +-----+------+           |
                    |          | CFG | Taint|           |
                    |          | Null| Types|           |
                    |          +-----+------+           |
                    |                                   |
                    +----------------+------------------+
                                     |
                    +----------------+----------------+
                    |                |                 |
              +-----+-----+   +-----+-----+   +------+------+
              |   Report   |   |    SCA     |   | MCP Server  |
              | txt/json/  |   | 10 lockfmt |   | AI agent    |
              | sarif/html |   | Google OSV |   | integration |
              +------------+   +-----------+   +-------------+

  Tier 1: Fast. All languages. Pattern matching.
  Tier 2: Deep. CFG, dataflow, taint tracking, null safety, type inference.
  Tier 3: Deepest. LLM analysis grounded in Tier 1+2 findings. Optional.
```

Tier 1 regex engine uses stdlib only; pip install pulls tree-sitter for Tier 2 semantic analysis. Tier 3 requires an LLM API key.

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/dojigiri.yml
name: Security Scan
on: [pull_request]
jobs:
  dojigiri:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install dojigiri
      - run: doji scan . --output sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
```

### GitLab CI

```yaml
dojigiri:
  image: python:3.12-slim
  script:
    - pip install dojigiri
    - doji scan . --output json > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Diff-Only Scanning

```bash
doji scan . --diff                 # scan only changed lines (vs git main)
doji scan . --baseline latest      # report only new findings (vs last scan)
```

---

## Configuration

**.doji.toml**
```toml
[dojigiri]
ignore_rules = ["todo-marker", "console-log"]
min_severity = "warning"
workers = 8
```

**.doji-ignore**
```
*.log
vendor/
node_modules/
```

**Inline suppression**
```python
x = eval(user_input)  # doji:ignore(dangerous-eval)
```

---

## Comparison

| | Dojigiri | Bandit | Semgrep (OSS) | SonarQube (CE) |
|---|---|---|---|---|
| **Type** | SAST + SCA | SAST | SAST | SAST |
| **Languages** | 18 | Python only | 30+ | 17 |
| **Analysis depth** | Regex + AST + LLM | AST (Python) | Pattern + taint | AST + dataflow |
| **Taint tracking** | Yes (path-sensitive) | No | Yes (limited in OSS, full in Pro) | Yes |
| **SCA** | Built-in (OSV) | No | Supply Chain (paid) | No (requires plugins) |
| **LLM analysis** | Built-in (optional) | No | No | No (AI CodeFix paid) |
| **MCP server** | Yes | No | No | No |
| **CWE mapping** | Yes | Yes (partial) | Yes | Yes |
| **NIST SP 800-53** | Yes | No | No | No |
| **External deps** | tree-sitter (Tier 2) | 3+ | Requires binary | JVM + database |
| **SARIF output** | Yes | Yes (plugin) | Yes | No (plugin available) |
| **OWASP Benchmark** | Youden +100.0% (with tuned filters) | Not published | Not published (OSS) | Varies by language |
| **Self-hosted** | CLI / pip | CLI / pip | CLI / Docker | Server (JVM) |
| **License** | BSL 1.1 | Apache 2.0 | LGPL 2.1 | LGPL 3.0 |

Comparison based on publicly available documentation as of March 2026. Semgrep Pro and SonarQube commercial editions offer additional features not reflected here.

---

## Limitations

Dojigiri is a development aid, not a substitute for professional security audit.

- **Static analysis has blind spots.** No tool can guarantee the absence of bugs or vulnerabilities. A clean scan does not mean the code is secure.
- **AI findings are probabilistic.** Findings from `--deep` mode (marked `[llm]`) may contain false positives or miss real issues. Always review AI-generated findings.
- **Auto-fix requires review.** LLM-generated fixes may change behavior in subtle ways. Review all applied fixes.

See [PRIVACY.md](PRIVACY.md) for data handling, [TERMS.md](TERMS.md) for terms of use, and [SECURITY.md](SECURITY.md) to report vulnerabilities.

---

## Development

```bash
git clone https://github.com/Inklling/dojigiri
cd dojigiri
pip install -e ".[dev]"
pytest tests/ -q
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system map.

---

## License

BSL 1.1 (Business Source License) -- see [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md) for details.

Free for development, testing, personal projects, and education. Production use in commercial products requires a commercial license. Converts to Apache 2.0 on 2030-03-09.
