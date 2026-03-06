<p align="center">
  <h1 align="center">童子切 Dojigiri</h1>
  <p align="center"><em>Static analysis that cuts deep.</em></p>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License"></a>
  <a href="#"><img src="https://img.shields.io/badge/tests-1122%20passed-brightgreen.svg" alt="Tests"></a>
  <a href="#"><img src="https://img.shields.io/badge/rules-50%2B-orange.svg" alt="Rules"></a>
  <a href="#"><img src="https://img.shields.io/badge/languages-17-blueviolet.svg" alt="Languages"></a>
</p>

---

Dojigiri is a static analysis and code audit tool that combines regex pattern matching, Python AST checks, and **tree-sitter semantic analysis** with optional **Claude AI deep scans**. It catches bugs, security vulnerabilities, performance issues, and code smells across 17 languages — then optionally fixes them.

Named after [童子切安綱](https://en.wikipedia.org/wiki/D%C5%8Djigiri) (Dōjigiri Yasutsuna), one of Japan's legendary Five Great Swords — a blade known for cutting through what others couldn't.

## Install

```bash
pip install dojigiri
```

## Quick Start

```bash
# Scan a project
doji scan .

# Scan with auto-fix (dry run by default)
doji fix .

# Deep scan with Claude AI (requires API key)
export ANTHROPIC_API_KEY="sk-..."
doji scan . --deep --accept-remote
```

## Why Dojigiri

| Capability | ruff | semgrep | **dojigiri** |
|---|---|---|---|
| Regex pattern rules | — | Yes | **Yes (40+)** |
| AST-based checks | Yes | Yes | **Yes** |
| Cross-file taint flow | — | Yes | **Yes (path-sensitive)** |
| Null dereference tracking | — | — | **Yes** |
| Type inference | — | — | **Yes** |
| Resource leak detection | — | — | **Yes** |
| Dependency graph analysis | — | — | **Yes** |
| LLM-powered deep analysis | — | — | **Yes** |
| Auto-fix (deterministic + LLM) | Yes | Yes | **Yes** |
| SARIF output for GitHub | — | Yes | **Yes** |
| Inline suppression | Yes | Yes | **Yes** |

Dojigiri's tree-sitter engine builds control flow graphs, runs fixed-point dataflow analysis, and tracks taint through branches and sanitizers. The optional LLM layer adds context-aware analysis that static tools can't replicate.

## Supported Languages

**Full semantic analysis** (taint flow, null safety, type inference, CFG):
Python · JavaScript · TypeScript · Go · Rust · Java · C#

**Pattern-based analysis:**
C/C++ · Ruby · PHP · Swift · Kotlin · SQL · HTML · CSS · Bash · Pine Script

## Commands

```bash
# Scanning
doji scan <path>                    # Quick scan (static only, free)
doji scan <path> --deep             # Deep scan (static + Claude AI)
doji scan <path> --diff             # Only scan changed lines vs git main
doji scan <path> --lang python      # Filter by language
doji scan <path> --no-cache         # Skip file hash cache

# Filtering
doji scan . --ignore todo-marker,console-log
doji scan . --min-severity warning
doji scan . --min-confidence medium
doji scan . --baseline latest       # Only NEW findings vs last scan

# Output formats
doji scan . --output json           # JSON for CI/CD
doji scan . --output sarif          # SARIF for GitHub Code Scanning

# Auto-fix
doji fix <path>                     # Dry run — show proposed changes
doji fix <path> --apply             # Apply fixes
doji fix <path> --apply --llm       # Include LLM-generated fixes
doji fix <path> --rules bare-except,unused-import

# Project analysis (cross-file)
doji analyze <dir>                  # Dependency graph + cross-file issues
doji analyze <dir> --no-llm         # Graph only (free, no API key)

# Single-file deep dive
doji debug <file>                   # Bug hunting with Claude
doji debug <file> --context auto    # Include related files automatically
doji optimize <file>                # Performance suggestions
doji explain <file>                 # Beginner-friendly walkthrough

# Utilities
doji rules                          # List all available rules
doji rules --lang python            # Rules for a specific language
doji report                         # Show latest scan results
doji cost <path>                    # Estimate deep scan cost
doji hook install                   # Add pre-commit hook
doji setup                          # Check environment
```

## What It Detects

### Security
- Hardcoded secrets and API keys (redacted in reports)
- SQL injection (string formatting, f-strings, `.format()`)
- XSS (`innerHTML`, `eval`, `document.write`)
- Path traversal, shell injection
- Unsafe deserialization (`pickle`, `yaml.load`)
- Weak cryptography (MD5, SHA1, DES, ECB)
- AWS credential patterns
- Taint flow from user input to dangerous sinks (path-sensitive)

### Bugs
- Null/None dereference with branch-aware narrowing
- Mutable default arguments
- Bare except clauses
- Type confusion (`type()` vs `isinstance`)
- Shadowed builtins
- Resource leaks (files, connections, sockets)
- Unused variables and imports
- Unreachable code

### Performance & Quality
- High cyclomatic complexity
- Too many function parameters
- Semantic code clones (similarity > 0.85)
- Dead code detection
- TODO/FIXME tracking

### Inline Suppression

```python
x = eval(user_input)  # doji:ignore(dangerous-eval)
password = "hunter2"   # doji:ignore
```

## Configuration

### .doji.toml

```toml
[dojigiri]
ignore_rules = ["todo-marker", "console-log"]
min_severity = "warning"
workers = 8

[[dojigiri.rules]]
pattern = "<<<<<<< "
name = "merge-conflict"
message = "Unresolved merge conflict marker"
severity = "critical"
category = "bug"
```

### .doji-ignore

```
*.log
test_*.py
vendor/
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Code Scan
on: [pull_request]

jobs:
  dojigiri:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install dojigiri

      - name: Scan for issues
        run: doji scan . --output sarif --accept-remote > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Baseline Mode

```bash
# On main — establish baseline
doji scan .

# On feature branch — show only new issues
doji scan . --baseline latest
```

### Pre-commit Hook

```bash
doji hook install     # Adds doji to .git/hooks/pre-commit
doji hook uninstall   # Removes it
```

## Architecture

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full system map — call flow
diagrams, module tables, data flow through the semantic engine, and a
"start here" guide for navigating the codebase.

```
dojigiri/
├── __main__.py          CLI entry point (6 subcommands)
├── analyzer.py          Scan orchestration, file collection, caching
├── detector.py          Static analysis engine (regex + AST + semantic)
├── languages.py         50+ pattern rules across 17 languages
├── fixer.py             Deterministic fixers + LLM fix orchestration
├── llm.py               Claude API wrapper with cost tracking
├── llm_backend.py       Backend abstraction (Anthropic/OpenAI/Ollama)
├── llm_focus.py         Targeted LLM prompts from static findings
├── chunker.py           File splitting for LLM context windows
├── config.py            Data structures, enums, constants
├── compliance.py        CWE and NIST SP 800-53 mappings
├── storage.py           JSON reports, file hash cache
├── report.py            Console output (ANSI, JSON, SARIF)
├── report_html.py       Self-contained HTML reports
├── mcp_server.py        FastMCP server for AI agent integration
├── hooks.py             Pre-commit hook management
├── semantic/            Tree-sitter semantic analysis engine
│   ├── core.py          Single-pass AST extraction
│   ├── cfg.py           Control flow graph construction
│   ├── taint.py         Path-sensitive taint analysis
│   ├── types.py         Type inference + contracts
│   ├── nullsafety.py    Null dereference detection
│   ├── resource.py      Resource leak detection
│   ├── scope.py         Unused vars, shadowing, uninitialized
│   ├── smells.py        God class, feature envy, semantic clones
│   ├── checks.py        Cross-language AST checks
│   ├── explain.py       Tutorial-mode file explanation
│   └── lang_config.py   Language configs for 7 grammars
└── graph/               Cross-file analysis
    ├── depgraph.py      Dependency graph + call graph engine
    ├── callgraph.py     Dead functions, arg mismatches
    └── project.py       Cross-file analysis orchestrator
```

**35 modules · ~17,000 lines · 1,122 tests**

## Development

```bash
git clone https://github.com/Inklling/dojigiri
cd dojigiri
pip install -e ".[dev]"
pytest tests/ -q         # 1035 tests, ~40s
```

## License

MIT
