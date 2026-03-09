# Dojigiri Architecture

## Overview

Dojigiri is a static analysis + LLM-powered code audit tool. It scans source files
for bugs, security issues, and code smells using three analysis layers: regex patterns,
tree-sitter AST analysis, and optional LLM enrichment.

This document maps the entire system so you can navigate the codebase without
reading every file first.

---

## High-Level Pipeline

```
User runs: doji scan .
            |
            v
    __main__.py (CLI)
    Parses args, loads config (.doji.toml)
            |
            v
    analyzer.py (Orchestrator)
    Collects files, dispatches to analysis, merges results
            |
            +---> detector.py (Static Analysis Engine)
            |         |
            |         +---> languages.py ........... 130+ regex rules by language
            |         +---> semantic/checks.py ..... tree-sitter AST checks
            |         +---> Python ast module ....... Python-specific AST checks
            |         +---> semantic/core.py ....... single-pass AST extraction
            |         |         |
            |         |         +---> semantic/scope.py ...... unused vars, shadowing
            |         |         +---> semantic/taint.py ...... source-to-sink tracking
            |         |         +---> semantic/cfg.py ........ control flow graphs
            |         |         +---> semantic/types.py ...... type inference
            |         |         +---> semantic/nullsafety.py . null deref detection
            |         |         +---> semantic/resource.py ... resource leak detection
            |         |         +---> semantic/smells.py ..... god class, clones, etc.
            |         |
            |         v
            |     list[Finding]  (static results)
            |
            +---> chunker.py (splits large files for LLM)
            |         |
            |         v
            +---> llm.py (Anthropic SDK wrapper)
            |         |
            |         +---> llm_backend.py ... backend abstraction (Anthropic/OpenAI/Ollama)
            |         +---> llm_focus.py ..... builds targeted prompts from static findings
            |         |
            |         v
            |     list[Finding]  (LLM results)
            |
            +---> _merge_findings() combines static + LLM results
            |
            v
    ScanReport
            |
            +---> report.py ........... ANSI console output
            +---> report_html.py ...... self-contained HTML report
            +---> mcp_format.py ....... AI-friendly plain text
            +---> storage.py .......... JSON persistence + SHA256 file cache
```

---

## Module Map

### Core Pipeline (what runs on every scan)

| Module | Role | Reads From | Writes To |
|--------|------|-----------|-----------|
| `__main__.py` | CLI entry point, arg parsing, subcommand dispatch | config.py, analyzer.py | report.py, storage.py |
| `config.py` | Enums, dataclasses, constants, project config loader | .doji.toml files | (imported everywhere) |
| `analyzer.py` | Orchestrator: collect files, run analysis, merge, save | detector.py, chunker.py, llm.py, storage.py | ScanReport |
| `detector.py` | Static analysis engine: regex + AST + semantic | languages.py, semantic/* | list[Finding] |
| `languages.py` | 130+ regex rules organized by language group | config.py (enums only) | Rule tuples |
| `storage.py` | SHA256 file cache, JSON report persistence | config.py (paths) | ~/.dojigiri/ |

### Semantic Analysis (tree-sitter powered)

All modules in `semantic/` operate on `FileSemantics` — a struct extracted in one
pass over the tree-sitter AST. If tree-sitter is not available, every module
gracefully returns `[]`.

| Module | Role | Input | Output |
|--------|------|-------|--------|
| `semantic/core.py` | Single-pass AST extraction | source bytes + language | `FileSemantics` (assignments, references, scopes, functions, classes) |
| `semantic/lang_config.py` | Per-language node type mappings | language string | `LanguageConfig` (7 languages supported) |
| `semantic/checks.py` | Cross-language AST checks | source bytes + language | list[Finding] (unused imports, empty catch, complexity) |
| `semantic/scope.py` | Scope analysis | FileSemantics | list[Finding] (unused vars, shadowing, uninitialized) |
| `semantic/taint.py` | Taint tracking: source to sink | FileSemantics + CFG (optional) | list[Finding] (SQL injection, command injection, etc.) |
| `semantic/cfg.py` | Control flow graph construction | FileSemantics | dict[scope_id, FunctionCFG] |
| `semantic/types.py` | Type inference from literals/annotations | FileSemantics + CFG | FileTypeMap |
| `semantic/nullsafety.py` | Null dereference detection | FileSemantics + FileTypeMap | list[Finding] |
| `semantic/resource.py` | Resource leak detection | FileSemantics + CFG | list[Finding] (unclosed files, connections) |
| `semantic/smells.py` | Architectural smells | FileSemantics | list[Finding] (god class, feature envy, clones) |
| `semantic/explain.py` | Tutorial-mode file explanation | FileSemantics + FileTypeMap | FileExplanation |
| `semantic/_utils.py` | Shared tree-sitter node helpers | tree-sitter nodes | text, line numbers |

**Data flow through semantic analysis:**

```
source bytes
    |
    v
core.extract_semantics()  -->  FileSemantics
    |                               |
    |    +--------------------------+-------------------+
    |    |              |           |          |        |
    v    v              v           v          v        v
  scope.py         taint.py     smells.py   types.py  cfg.py
  (unused vars)    (injection)  (god class)  (types)  (control flow)
                       |                       |        |
                       |            +----------+--------+
                       |            |
                       v            v
                  taint.py      nullsafety.py    resource.py
                  (path-       (null deref)      (leaks)
                   sensitive)
```

### Graph Analysis (cross-file)

| Module | Role | Input | Output |
|--------|------|-------|--------|
| `graph/depgraph.py` | Dependency graph + call graph construction | source files | DepGraph, CallGraph, GraphMetrics |
| `graph/callgraph.py` | Dead function + arg mismatch detection | CallGraph, DepGraph | list[Finding] |
| `graph/project.py` | Cross-file analysis orchestrator | directory path | ProjectAnalysis |

### LLM Integration (optional, costs money)

| Module | Role | Input | Output |
|--------|------|-------|--------|
| `llm.py` | Anthropic SDK wrapper, cost tracking | Chunk + system prompt | list[Finding] + cost |
| `llm_backend.py` | Backend abstraction (Anthropic/OpenAI/Ollama) | messages + model config | LLMResponse |
| `llm_focus.py` | Builds targeted prompts from static findings | list[Finding] | focused prompt string |
| `chunker.py` | Splits large files for LLM context windows | file content | list[Chunk] |

### Output & Integration

| Module | Role | Input | Output |
|--------|------|-------|--------|
| `report.py` | ANSI console output with colors | ScanReport | stdout |
| `report_html.py` | Self-contained HTML report | ScanReport | HTML string |
| `mcp_format.py` | AI-friendly plain text (no ANSI) | ScanReport | text string |
| `mcp_server.py` | FastMCP server (5 tools for AI agents) | scan requests | mcp_format output |
| `compliance.py` | CWE and NIST SP 800-53 rule mappings | rule name | CWE ID, NIST controls |
| `metrics.py` | Session observability (scan stats, costs) | scan events | SessionMetrics |

### Other

| Module | Role |
|--------|------|
| `fixer/` | Auto-fix engine: deterministic fixers + LLM-assisted fixes (package: engine, deterministic, cascade, llm_fixes, helpers) |
| `java_sanitize.py` | OWASP Benchmark Java sanitizer detection |
| `pr_review.py` | Pull request review integration |
| `hooks.py` | Git pre-commit hook install/uninstall |

---

## Key Data Types

All defined in `types.py`:

- **`Finding`** — a single issue found in code (file, line, severity, category, rule, message)
- **`FileAnalysis`** — all findings for one file, plus metadata (language, line count, hash)
- **`ScanReport`** — complete scan result (list of FileAnalysis + cross-file findings + costs)
- **`Severity`** — CRITICAL / WARNING / INFO
- **`Category`** — BUG / SECURITY / PERFORMANCE / STYLE / DEAD_CODE
- **`Source`** — STATIC (regex) / AST (tree-sitter or Python ast) / LLM
- **`Fix`** — a proposed code change (original lines, replacement, explanation)
- **`CrossFileFinding`** — an issue spanning two files (e.g., semantic clones)

---

## "I want to understand X" — where to start

| Goal | Start here |
|------|-----------|
| How a scan works end-to-end | `analyzer.py` → `scan_quick()` or `scan_deep()` |
| How regex rules are defined | `languages.py` → `_UNIVERSAL_RULES`, `_PYTHON_RULES`, etc. |
| How tree-sitter checks work | `semantic/checks.py` → `run_tree_sitter_checks()` |
| How taint analysis works | `semantic/taint.py` → `analyze_taint()` and `analyze_taint_pathsensitive()` |
| How the LLM is called | `llm.py` → follow `analyze_chunk()` |
| How findings merge (static + LLM) | `analyzer.py` → `_merge_findings()` |
| How cross-file analysis works | `graph/project.py` → `analyze_project()` |
| How fixes are generated | `fixer.py` |
| How the CLI is structured | `__main__.py` → argparse setup at top, subcommand handlers below |
| How results are displayed | `report.py` (console), `report_html.py` (HTML), `mcp_format.py` (AI) |
| How caching works | `storage.py` → `file_hash()`, `load_cache()`, `save_cache()` |
| How inline suppression works | `detector.py` → `_parse_line_suppression()`, `doji:ignore` |
| How config files work | `config.py` → `load_project_config()`, `compile_custom_rules()` |
| How it runs as an MCP server | `mcp_server.py` → `@mcp.tool()` decorated functions |

---

## File Count & Size

- **42 Python modules** across 4 packages (`dojigiri/`, `semantic/`, `graph/`, `fixer/`)
- **~15,000 lines** production code + **~17,000 lines** tests (39 test files)
- Largest files: `__main__.py` (~1300 lines, CLI), `languages.py` (regex rules), `detector.py` (analysis engine)
- Compiled to standalone `.exe` via Nuitka (Python → C → native binary)
