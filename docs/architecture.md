# Architecture

## High-level pipeline

```
doji scan .
    |
    v
CLI (__main__.py)
    |
    v
Orchestrator (analyzer.py)
    |
    +---> Tier 1: Regex Engine (detector.py + languages.py)
    |         130+ patterns across 18 languages
    |         |
    |         v
    |     list[Finding]
    |
    +---> Tier 2: Semantic Engine (semantic/*)
    |         Tree-sitter AST analysis
    |         |
    |         +---> scope.py ........ unused vars, shadowing
    |         +---> taint.py ........ source-to-sink tracking
    |         +---> cfg.py .......... control flow graphs
    |         +---> types.py ........ type inference
    |         +---> nullsafety.py ... null dereference detection
    |         +---> resource.py ..... resource leak detection
    |         +---> smells.py ....... god class, clones, etc.
    |         |
    |         v
    |     list[Finding]
    |
    +---> Tier 3: LLM Engine (llm.py, optional)
    |         Focused prompts from Tier 1+2 findings
    |         Chunked file analysis
    |         Structured response parsing
    |         |
    |         v
    |     list[Finding]
    |
    +---> Merge (static + semantic + LLM)
    |
    v
ScanReport
    |
    +---> report.py ......... Terminal output
    +---> report_html.py .... HTML report
    +---> sarif.py .......... SARIF for GitHub/GitLab
    +---> mcp_format.py ..... AI-friendly plain text
    +---> storage.py ........ JSON persistence + SHA256 cache
```

## Module groups

### Core pipeline

| Module | Role |
|--------|------|
| `__main__.py` | CLI entry point, arg parsing |
| `config.py` | Enums, constants, `.doji.toml` loader |
| `analyzer.py` | Orchestrator: collect files, run analysis, merge |
| `detector.py` | Static analysis engine: regex + AST |
| `languages.py` | 130+ regex rules by language |
| `storage.py` | SHA256 file cache, JSON persistence |

### Semantic analysis

All modules operate on `FileSemantics` -- a struct extracted in one pass over the tree-sitter AST. If tree-sitter is unavailable, every module returns `[]`.

| Module | Role |
|--------|------|
| `semantic/core.py` | Single-pass AST extraction |
| `semantic/scope.py` | Unused vars, shadowing, uninitialized |
| `semantic/taint.py` | Source-to-sink taint tracking (path-sensitive) |
| `semantic/cfg.py` | Control flow graph construction |
| `semantic/types.py` | Type inference from literals/annotations |
| `semantic/nullsafety.py` | Null dereference detection |
| `semantic/resource.py` | Resource leak detection |
| `semantic/smells.py` | God class, feature envy, clones |

### Cross-file analysis

| Module | Role |
|--------|------|
| `graph/depgraph.py` | Dependency graph + call graph |
| `graph/callgraph.py` | Dead function + arg mismatch detection |
| `graph/project.py` | Cross-file analysis orchestrator |

### LLM integration

| Module | Role |
|--------|------|
| `llm.py` | Anthropic SDK wrapper, cost tracking |
| `llm_backend.py` | Backend abstraction (Anthropic/OpenAI/Ollama) |
| `llm_focus.py` | Builds targeted prompts from static findings |
| `llm_parsers.py` | JSON response parsing + 4-layer recovery |
| `chunker.py` | Splits large files for context windows |

### SCA

| Module | Role |
|--------|------|
| `sca/scanner.py` | SCA orchestrator |
| `sca/parsers.py` | 10 lockfile format parsers |
| `sca/osv.py` | Google OSV API client |

### Output and integration

| Module | Role |
|--------|------|
| `report.py` | ANSI terminal output |
| `report_html.py` | Self-contained HTML report |
| `sarif.py` | SARIF generation (GitHub Code Scanning) |
| `mcp_server.py` | MCP server (6 tools, 4 resources, 2 prompts) |
| `compliance.py` | CWE + NIST SP 800-53 mappings |
| `fixer/` | Auto-fix engine (deterministic + LLM cascade) |

## Key data types

Defined in `types.py`:

- **Finding** -- single issue (file, line, severity, category, rule, message)
- **FileAnalysis** -- all findings for one file + metadata
- **ScanReport** -- complete scan result (files + cross-file + costs)
- **Severity** -- CRITICAL / WARNING / INFO
- **Category** -- BUG / SECURITY / PERFORMANCE / STYLE / DEAD_CODE
- **Source** -- STATIC / AST / LLM

## Scale

- 72 Python modules across 7 packages
- ~26,500 lines production code
- ~33,000 lines tests (1,426 tests)
- Compiled to standalone binary via Nuitka (Python &rarr; C &rarr; native)
