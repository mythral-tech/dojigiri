# dojigiri

Static analysis + LLM-powered code audit tool. 820+ tests, 12,500 lines, 28 modules.

Dojigiri combines regex pattern matching, Python AST checks, and tree-sitter semantic analysis with optional Claude AI deep scans. It catches bugs, security issues, performance problems, and code smells across 7 languages — then optionally fixes them.

## Quick Start

```bash
pip install dojigiri

# Scan a project (free, instant)
doji scan .

# Scan with auto-fix (dry run by default)
doji fix .

# Deep scan with Claude AI (requires API key)
export ANTHROPIC_API_KEY="sk-..."
doji scan . --deep --accept-remote
```

## What Dojigiri Catches That Others Don't

| Capability | ruff | semgrep | dojigiri |
|---|---|---|---|
| Regex pattern rules | - | Yes | Yes (40+) |
| AST-based checks | Yes | Yes | Yes |
| Cross-file taint flow | - | Yes | Yes (path-sensitive) |
| Null dereference tracking | - | - | Yes |
| Type inference | - | - | Yes |
| Resource leak detection | - | - | Yes |
| Dependency graph analysis | - | - | Yes |
| LLM-powered deep analysis | - | - | Yes |
| Auto-fix (deterministic + LLM) | Yes | Yes | Yes |
| SARIF output for GitHub | - | Yes | Yes |

Dojigiri's tree-sitter engine builds control flow graphs, runs fixed-point dataflow analysis, and tracks taint through branches and sanitizers. The LLM layer adds context-aware analysis that static tools can't do.

## Languages

Python, JavaScript, TypeScript, Go, Rust, Java, C/C++, Ruby, PHP, C#, Swift, Kotlin, SQL, HTML, CSS, Bash, Pine Script.

Tree-sitter semantic analysis (taint flow, null safety, type inference, CFG) is available for Python, JavaScript, TypeScript, Go, Rust, Java, and C#.

## Commands

```bash
# Scanning
doji scan <path>                    # Quick scan (static only, free)
doji scan <path> --deep             # Deep scan (static + Claude AI)
doji scan <path> --diff             # Only scan lines changed vs git main/master
doji scan <path> --lang python      # Filter by language
doji scan <path> --no-cache         # Skip file hash cache

# Filtering
doji scan . --ignore todo-marker,console-log
doji scan . --min-severity warning
doji scan . --min-confidence medium
doji scan . --baseline latest       # Show only NEW findings vs last scan

# Output formats
doji scan . --output json           # JSON for CI/CD
doji scan . --output sarif          # SARIF for GitHub Code Scanning

# Auto-fix
doji fix <path>                     # Dry run — show what would change
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
doji explain <file>                 # Beginner-friendly code walkthrough

# Utilities
doji report                         # Show latest scan results
doji cost <path>                    # Estimate deep scan cost
doji hook install                   # Add pre-commit hook
doji setup                          # Check environment
```

## What It Detects

### Security
- Hardcoded secrets and API keys (redacted in reports)
- SQL injection (string formatting, f-strings, .format())
- XSS (innerHTML, eval, document.write)
- Path traversal, shell injection
- Unsafe deserialization (pickle, yaml.load)
- Weak cryptography (MD5, SHA1, DES, ECB)
- AWS credential patterns
- Taint flow from user input to dangerous sinks (path-sensitive)

### Bugs
- Null/None dereference with branch-aware narrowing
- Mutable default arguments
- Bare except clauses
- Type confusion (type() vs isinstance)
- Shadowed builtins
- Resource leaks (files, connections, sockets)
- Unused variables and imports
- Unreachable code

### Performance & Style
- High cyclomatic complexity
- Too many function parameters
- Semantic code clones (similarity > 0.85)
- Dead code detection
- TODO/FIXME tracking

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

### GitHub Actions with SARIF

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

### Baseline mode (only new findings)

```bash
# On main branch — establish baseline
doji scan .

# On feature branch — show only new issues
doji scan . --baseline latest
```

### Pre-commit hook

```bash
doji hook install    # Adds doji to .git/hooks/pre-commit
doji hook uninstall  # Removes it
```

## Architecture

```
dojigiri/
├── __main__.py          CLI: scan, debug, optimize, analyze, fix, explain
├── analyzer.py          Scan orchestration, file collection, caching
├── detector.py          Static analysis engine (regex + AST + tree-sitter)
├── languages.py         40+ regex pattern rules
├── fixer.py             9 deterministic fixers + LLM fix orchestration
├── depgraph.py          Dependency graph (import resolution, cycles, metrics)
├── project.py           Cross-file analysis orchestration
├── ts_semantic.py       Tree-sitter: function/class/variable extraction
├── ts_cfg.py            Control flow graph construction
├── ts_taint.py          Taint analysis (flow-insensitive + path-sensitive)
├── ts_types.py          Type inference + contract checking
├── ts_nullsafety.py     Null dereference + narrowing
├── ts_resource.py       Resource leak detection
├── ts_scope.py          Unused vars, shadowing, undefined references
├── ts_smells.py         Dead code, complexity, semantic clones
├── ts_checks.py         AST pattern checks
├── ts_callgraph.py      Call graph construction
├── ts_explain.py        Beginner-friendly code explanation
├── ts_lang_config.py    Language configs for 7 tree-sitter grammars
├── llm.py               Claude API: scan, debug, optimize, analyze, explain
├── llm_focus.py         Micro-queries for targeted LLM analysis
├── chunker.py           File splitting for LLM context windows
├── config.py            Data structures, enums, constants
├── storage.py           JSON reports, file hash cache
├── report.py            Output formatting (ANSI, JSON, SARIF)
└── hooks.py             Pre-commit hook management
```

## Development

```bash
git clone https://github.com/Inklling/Genesis
cd Genesis
pip install -e ".[dev]"
pytest tests/ -q         # 820 tests, ~8s
```

## License

MIT
