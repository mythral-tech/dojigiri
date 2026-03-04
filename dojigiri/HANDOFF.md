# Dojigiri — Handoff Notes

## What This Is

Python static analysis + LLM-powered code audit tool. 28 modules across 3 packages, ~4000 lines.
Run with: `python -m dojigiri scan <path> [--no-cache] [--deep] [--output json] [--ignore rules] [--min-severity level]`

## Architecture

```
dojigiri/
  __init__.py      Public API exports (Finding, ScanReport, Severity, etc.)
  __main__.py      CLI (argparse, 6 subcommands: scan, debug, optimize, report, cost, setup)
  config.py        Enums (Severity, Source, Category), dataclasses (Finding, FileAnalysis, ScanReport), constants
  languages.py     50+ regex rules across 5 language groups (universal, python, js/ts, go, rust, security)
  detector.py      Regex engine + Python AST checks + semantic analysis integration
  analyzer.py      Orchestrator: collect files -> static analysis -> LLM chunks -> merge -> save report
  chunker.py       Split large files into overlapping chunks for LLM context limits
  llm.py           Anthropic SDK wrapper, system prompts, cost tracking, JSON recovery
  llm_focus.py     Smart LLM: build focused prompts from static findings (v0.8.0)
  fixer.py         Auto-fix engine: deterministic fixers + LLM orchestration
  report.py        ANSI console formatting, JSON/SARIF output
  storage.py       SHA256 file hash cache, JSON report persistence, auto-prune
  hooks.py         Pre-commit hook install/uninstall

  semantic/        Tree-sitter semantic analysis subsystem (12 modules)
    _utils.py        Shared helpers (_get_text, _line, _end_line)
    lang_config.py   Per-language tree-sitter node type mappings (7 languages)
    core.py          Single-pass AST extraction: assignments, calls, scopes, classes
    checks.py        Cross-language AST checks (unused imports, unreachable code, etc.)
    cfg.py           Control flow graph construction + reverse postorder
    types.py         Type inference + function contracts
    taint.py         Intra-procedural taint analysis: source → sink tracking
    scope.py         Scope analysis: unused vars, shadowing, uninitialized
    smells.py        Architectural smells: god class, feature envy, duplicates
    nullsafety.py    Null dereference detection + type narrowing
    resource.py      Resource leak detection (file handles, connections)
    explain.py       Tutorial-mode file explanation (doji explain)

  graph/           Dependency + project analysis (3 modules)
    depgraph.py      Dependency graph + call graph engine
    project.py       Project analysis orchestrator with cross-file checks
    callgraph.py     Call graph checks: dead functions, arg mismatches
```

## Version History

### v1.0.0 — Renamed to Dojigiri (formerly Wiz)
- Full rename: package, CLI (`doji`), config files (`.doji.toml`, `.doji-ignore`), MCP tools
- Cyberpunk forge themed launcher

### v0.8.0 — Semantic Analysis Engine (Claude)
Turns the tool from a linter into a real static analyzer with 5 analysis systems:

1. **Shared extraction layer** (`semantic/core.py`) — single-pass AST walk extracts assignments, references, calls, scopes, classes.
2. **Scope analysis** (`semantic/scope.py`) — unused variables, variable shadowing, possibly-uninitialized detection.
3. **Call graph** (`graph/callgraph.py` + `graph/depgraph.py`) — function-level dependency tracking, dead function detection.
4. **Taint analysis** (`semantic/taint.py`) — intra-procedural source→sink tracking.
5. **Architectural smells** (`semantic/smells.py`) — god class, feature envy, long method, near-duplicate functions.
6. **Smart LLM** (`llm_focus.py`) — uses static findings to build targeted prompts.

### v0.2.0 — Initial release
Regex patterns, Python AST checks, LLM integration, CLI UX.

### v0.2.1 — Bug fixes + tests
Parallel scanning, 120 tests, pyproject.toml.

## Type Safety

- **mypy**: Configured in `pyproject.toml` under `[tool.mypy]`. Passes clean.
- **Return types**: All public functions have return type annotations.
- **Protocol**: `FixerFn` in `fixer.py` types the deterministic fixer functions.
- **Type aliases**: `Findings` (`list[Finding]`) and `SourceBytes` (`bytes`) in `config.py`.
- **`__all__`**: Defined in `dojigiri/__init__.py`, `dojigiri/semantic/__init__.py`, `dojigiri/graph/__init__.py`.
- **`py.typed`**: PEP 561 marker present.

## Known Issues

1. **Block comments** — only line comments (`#`, `//`) handled. No `/* */`, `""" """`, `<!-- -->`
2. **Deep scan ignores cache** — rescans everything, doesn't benefit from file hash cache
