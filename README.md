# 童子切 Dojigiri

Static analysis. Security, correctness, quality — across 17 languages.

Named after [童子切安綱](https://en.wikipedia.org/wiki/D%C5%8Djigiri), one of Japan's Five Great Swords.

```bash
pip install dojigiri
```

---

## Usage

```bash
doji scan .                          # static scan
doji scan . --deep --accept-remote   # + Claude AI analysis
doji fix .                           # dry run
doji fix . --apply                   # apply fixes
doji analyze <dir>                   # cross-file dependency graph
```

```bash
doji scan . --diff                   # changed lines only (vs git main)
doji scan . --baseline latest        # new findings only (vs last scan)
doji scan . --output sarif           # SARIF for GitHub Code Scanning
doji scan . --output json            # JSON for CI/CD
```

```bash
doji debug <file>                    # bug hunting with Claude
doji optimize <file>                 # performance suggestions
doji explain <file>                  # beginner-friendly walkthrough
doji rules                           # list all rules
doji cost <path>                     # estimate deep scan cost
```

## What it finds

**Security** — hardcoded secrets, SQL injection, XSS, path traversal, shell injection, unsafe deserialization, weak crypto, taint flow from source to sink (path-sensitive)

**Bugs** — null dereference (branch-aware), mutable defaults, bare except, type confusion, shadowed builtins, resource leaks, unused variables, unreachable code

**Quality** — cyclomatic complexity, semantic clones, dead code, too many parameters

## How it works

Three analysis layers, each deeper than the last:

| Layer | Method | Scope |
|---|---|---|
| Pattern | Regex rules (50+) | All 17 languages |
| Semantic | Tree-sitter AST, CFG, dataflow | Python, JS, TS, Go, Rust, Java, C# |
| Deep | Claude AI context-aware analysis | Any (requires API key) |

The semantic engine builds control flow graphs, runs fixed-point dataflow, and tracks taint through branches and sanitizers. Auto-fix is available for both deterministic patterns and LLM-suggested changes.

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
```

**Inline suppression**
```python
x = eval(user_input)  # doji:ignore(dangerous-eval)
```

## CI/CD

```yaml
# .github/workflows/scan.yml
name: Code Scan
on: [pull_request]
jobs:
  dojigiri:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install dojigiri
      - run: doji scan . --output sarif --accept-remote > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system map.

```
dojigiri/
  __main__.py       CLI (6 subcommands)
  analyzer.py       Scan orchestration, caching
  discovery.py      File collection, language detection
  detector.py       Static analysis engine
  languages.py      Pattern rules (17 languages)
  fixer/            Auto-fix (deterministic + LLM)
  llm.py            Claude API, cost tracking
  llm_backend.py    Backend abstraction
  llm_focus.py      Targeted prompts from static findings
  config.py         Data structures, constants
  metrics.py        Session metrics, history
  report.py         Console output (ANSI, JSON, SARIF)
  report_html.py    HTML reports
  mcp_server.py     MCP server for AI agents
  semantic/         Tree-sitter analysis engine
    core.py         AST extraction
    cfg.py          Control flow graphs
    taint.py        Path-sensitive taint analysis
    types.py        Type inference
    nullsafety.py   Null dereference detection
    resource.py     Resource leak detection
    scope.py        Unused vars, shadowing
    smells.py       Code smells, semantic clones
  graph/            Cross-file analysis
    depgraph.py     Dependency + call graphs
    project.py      Cross-file orchestrator
```

## Development

```bash
git clone https://github.com/Inklling/dojigiri
cd dojigiri
pip install -e ".[dev]"
pytest tests/ -q
```

## License

MIT
