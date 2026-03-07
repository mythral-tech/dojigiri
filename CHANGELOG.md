# Changelog

All notable changes to Dojigiri will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.1.0] - 2026-03-07

### Added
- LLM backend abstraction supporting Anthropic, OpenAI-compatible, and Ollama backends
- CWE and NIST SP 800-53 compliance mappings for all rules (`compliance.py`)
- Self-contained HTML report output (`--output html`), optional PDF via weasyprint
- Classification levels for report banners (`--classification`)
- Scan profiles for preset configurations (`--profile`)
- Offline mode (`--offline`) for environments without LLM access
- CLI flags: `--backend`, `--model`, `--base-url`, `--output-file`, `--project-name`
- Inline suppression comments (`doji:ignore(rule-name)`)
- `doji rules` command listing all available rules with CWE/NIST mappings
- MCP server with 5 tools for AI agent integration (`doji mcp`)
- `doji setup-claude` command for Claude Code MCP configuration
- `doji explain` tutorial-mode file walkthrough with semantic analysis
- `doji analyze` cross-file dependency and call graph analysis
- `doji init` command for scaffolding `.doji-ignore` with smart defaults
- Path-sensitive taint analysis with fixed-point dataflow iteration
- Control flow graph construction for 7 languages
- Type inference engine with function contracts
- Null dereference detection with type narrowing
- Resource leak detection (unclosed files, connections, sockets)
- Architectural smell detection (god class, feature envy, semantic clones)
- Scope analysis (unused variables, shadowing, possibly-uninitialized)
- Cross-file dependency graphs, dead function detection, argument mismatch checks
- Smart LLM prompts built from static findings (`llm_focus.py`)
- Custom rule definitions via `.doji.toml`
- Pre-commit hook install/uninstall (`doji hook`)
- Fix verification with automatic re-scan after applying fixes
- Baseline/diff mode (`--baseline`) for tracking new findings only
- Diff scanning (`--diff`) for changed lines vs git branch
- SARIF 2.1.0 output for GitHub Code Scanning integration
- Deep scan file hash caching (unchanged files skip LLM re-analysis)
- Parallel deep scanning with configurable worker count (`--workers`)
- Confidence filtering (`--min-confidence`)
- Standalone `.exe` build via Nuitka with selective tree-sitter binding inclusion
- VS Code extension with diagnostics and code actions
- 1088 tests across 39 test files
- `doji clean` command for removing backup/temp files
- `doji privacy` command for viewing data handling policy
- Source attribution in reports (static vs LLM findings)
- AI disclaimer in CLI and HTML reports when LLM analysis is used
- Context file discovery extracted to reusable `context.py` module

### Changed
- Renamed from Wiz to Dojigiri (package, CLI `doji`, config files `.doji.toml`/`.doji-ignore`)
- LLM integration refactored from direct Anthropic SDK to pluggable backend protocol
- Package restructured into `dojigiri/semantic/` (12 modules) and `dojigiri/graph/` (3 modules)
- CWE IDs included in SARIF tags and text output
- Findings serialization now includes CWE and NIST control references
- Static analysis runs before LLM (partial results survive LLM failures)
- LLM retry with exponential backoff for rate limits and timeouts
- AST-aware Python chunking respects function/class boundaries
- Improved JSON recovery from malformed LLM responses
- Fixer engine hardened with post-fix syntax validation and automatic rollback
- Console output uses ANSI formatting; MCP output uses plain text

### Fixed
- SARIF version corrected from 1.0.0 to 1.1.0
- `build_exe.py` version no longer hardcoded (reads from package)
- ARCHITECTURE.md stats updated (35 to 42 modules, 3 to 4 packages)
- Taint propagation now processes assignments in source order (fixed edge case)
- CFG multi-statement line indexing handles multiple assignments/calls per line
- `SEVERITY_ORDER` deduplicated from 4 locations to single canonical definition
- `_SHADOW_BUILTINS` deduplicated (unified 28-builtin set at module level)
- False positives: threading primitives no longer flagged as resource leaks
- False positives: `dict.get(key, default)` with non-None default no longer triggers null-dereference
- False positives: for-loop variables no longer flagged as possibly-uninitialized
- False positives: `var-usage` rule removed from JS defaults (style opinion, not a bug)
- False positives: `require()` calls no longer flagged as path traversal
- False positives: test files excluded from `insecure-http` and `console-log` rules
- False positives: TypeVar/NewType/NamedTuple definitions no longer flagged as unused variables
- False positives: early-exit guard patterns now require actual raise/return in body
- Auto-fix: multi-line assignment removal (triple-quoted strings) now uses AST for full span
- Auto-fix: regex literal stripping prevents false brace-count failures in JS validation
- Auto-fix: removing sole catch-block statement no longer creates empty-exception-handler
- Auto-fix: `_fix_unused_import` skips multiline import blocks
- Auto-fix: string-context guards prevent fixes inside docstrings and multiline strings
- SARIF `properties` field uses `setdefault` merge instead of overwrite
- Fixer blank-line removal off-by-one with `deleted_indices` tracking
- Malformed `.doji.toml` no longer crashes (warns to stderr, continues)
- Cache enum serialization uses `.value` for Severity/Confidence
- `diff_reports` path mismatch resolved with `os.path.normpath`
- Triple-quote block comment detection limited to line-start (docstrings only)
- `scan_diff` file count no longer includes non-existent files from git output
- Deep scan caching bug in MCP server (cached results returning zero findings)
- Invalid `min_severity` values in MCP now return proper error instead of silently passing

### Security
- Symlink and path traversal protection in file collection (`resolve().relative_to()`)
- Sensitive file patterns blocked from scanning (`.env`, `*.pem`, `*.key`, credentials)
- Finding snippets redacted for `hardcoded-secret` and `aws-credentials` rules in serialized output
- Storage directory permissions set to `0o700` on Unix
- Custom rule regex validated against nested quantifier ReDoS patterns with 2s timeout
- LLM usage requires explicit consent (`--accept-remote`) in non-interactive environments
- SARIF output uses redacted snippets (secrets no longer leak to GitHub Code Scanning)
- MCP server path boundary hardened — `mcp_allowed_roots` restricted to cwd subdirectories
- Prompt injection mitigation — scanned code wrapped in XML boundary tags
- HTML report CSP meta tag (`default-src 'none'; style-src 'unsafe-inline'`)
- `--accept-llm-fixes` consent flag required for applying LLM-generated auto-fixes
- Runtime warning when API keys detected in `.doji.toml`
- Git ref validation in diff scanning to prevent command injection
- `--max-cost` flag with `CostLimitExceeded` enforcement for deep scan budget control
- Non-HTTPS URL warning for OpenAI-compatible backend
- Prompt caching on Anthropic backend reduces repeated analysis costs ~90%
- PRIVACY.md and TERMS.md added for public distribution
