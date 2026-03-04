# Collaboration Board

## Status
**Last agent**: Claude
**Date**: 2026-03-04
**What they did**: Fixer system audit — fixed all 3 root causes of 43/47 failed fixes in `doji fix --apply`. 5 phases, ~15 edits in `dojigiri/fixer.py` + test cleanup. 942 tests pass (3 removed with dead `_fix_var_usage`).

**Previous**: Claude — Full rename Wiz → Dojigiri (945 tests pass)

## Review
**Fixer system audit** (Claude → Oz for review). Fixed 3 root causes killing 43/47 fixes + 12 medium-severity bugs in `dojigiri/fixer.py`. Key areas to verify:

1. **RC1 — `_fix_open_without_with` body collection** (lines ~254-280): Rewrote loop to collect blank lines as body, stop on shallower indent/def/class, strip trailing blanks. Empty body → `pass` instead of bare `with:`. Verify on demo's `analytics.py` and `database.py`.
2. **RC2 — `_fix_os_system`** (line ~497): Now emits `shlex.split(cmd)` instead of `shell=True`. Added `shlex` to modules_needed. Verify no `shell-true` finding on re-scan.
3. **RC3 — `_strip_template_literals`** (new function, ~60 lines before `_validate_syntax`): Stack-based state machine for nested `${}` in template literals. Replaces simple regex that couldn't handle nesting. Test with demo's `dashboard.js` and `utils.ts`.
4. **`_sub_outside_strings` helper** (new, after line ~27): Used by `_fix_loose_equality` and `_fix_none_comparison` to avoid corrupting string literals. Verify `==`/`!=` inside strings are preserved.
5. **`apply_fixes` equality check** (lines ~873, 888): Changed `strip() not in actual` (substring) to `strip() != actual.strip()` (exact equality). This is a behavior change — verify no regressions.
6. **Dead code removal**: `_fix_var_usage` deleted (rule removed from detector). 3 tests removed from `test_fixer.py`.
7. **Conflict resolution**: New `open-without-with` vs `resource-leak` dedup (lines ~1210-1220). If both target same file+variable, resource-leak is dropped.
8. **`_fix_sql_injection` Pattern 2** now returns `None` (was incomplete — added `?` but didn't modify `execute()` call).
9. **`_fix_hardcoded_secret`** emits `process.env.VAR` for JS/TS files.
10. **`_fix_resource_leak`** uses return line's indentation for `.close()`, not creation indent.
11. **`_fix_fstring_no_expr`** regex handles escaped quotes.
12. **`fail_reason`** now set in OSError write handler (was missing).

**Ideal test**: Restore demo backups, run `doji fix "...\webapp" --apply`, target 0 failed fixes.

**Previous: Rename Wiz → Dojigiri** (Claude → Oz for review). Full rename completed. Key areas to verify:

1. **Syntax validation + rollback** — `_validate_syntax()` runs after `apply_fixes`. Python: `ast.parse()`. JS/TS: balanced braces/parens/brackets. Failure → `_rollback_from_backup()` restores `.wiz.bak`, marks all fixes FAILED.
2. **New-issues rollback** — If `verify_fixes` reports `new_issues > 0`, same rollback logic fires. Previously new issues were reported but broken file stayed.
3. **`_fix_loose_equality`** — Skips `== null` / `!= null` (intentional JS idiom for null+undefined check). Uses `_STRING_LITERAL_RE` to check code portions only.
4. **`_fix_insecure_http`** — Negative lookahead skips `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`.
5. **`_fix_console_log`** — Regex requires standalone `console.log(...)` as sole statement. Multi-statement lines (semicolons, chaining) are skipped.
6. **`_fix_eval_usage`** — Appends `# NOTE: only works for literal expressions` if no existing comment.
7. **`_fix_unused_variable`** — Added `re.search(r'\.\w+\s*\(', rhs)` to catch method calls like `foo.bar()` as side effects.
8. **`_fix_var_usage`** — Walks backwards to check if var is inside `if`/`for`/`while`/`switch` block. If so, skips (let has block scoping, would break outer references).
9. **`_fix_hardcoded_secret`** — Checks basename against test patterns (`test_*`, `*_test.py`, `*.test.js`, `*.spec.js`) and `__tests__` in path.
10. **`_fix_mutable_default`** — After finding signature end, scans forward for docstring (single-line or multi-line). If found, includes docstring in `new_sig` so guards go after it.

**Key areas to verify**: (a) The JS/TS balanced-delimiter check in `_validate_syntax` — does it handle template literals with `${}`? (b) `_fix_var_usage` backward walk — does it handle nested blocks correctly? (c) `_fix_mutable_default` docstring detection — does it handle edge cases like `r"""` or triple-single-quotes? (d) The rollback in `fix_file` recomputes `applied`/`failed` counts — verify the FixReport reflects the rollback correctly.

**Previous: Exe build review complete** (Oz). All 5 areas verified:

1. **`patch_tree_sitter_for_bundled()`** — Safe. Verified `spec_from_file_location` loads .pyd files correctly — module name `tree_sitter_language_pack.bindings.python` matches `PyInit_python` export (Python uses only the last component). Error handling is correct: failed loads are cleaned from `sys.modules`. No initialization order issues — patch runs at `wiz/__init__.py` import time, before any tree-sitter code executes.
2. **`is_bundled()` detection** — Sufficient. `__compiled__` is Nuitka-specific, `sys.frozen` covers PyInstaller/cx_Freeze. Both are standard detection patterns.
3. **`build_exe.py`** — Correct. 6 binding .pyd files (~4MB) vs 170 full set (170MB). `tree_sitter_c_sharp` included as separate package (it's a top-level import, not a binding .pyd). `tree_sitter_yaml` and `tree_sitter_embedded_template` included as packages (imported at module level by tslp). LLM deps correctly excluded.
4. **`wiz init`** — Clean. Idempotent (second run says "already exists"), good defaults (node_modules, venv, __pycache__, .git, IDE dirs, binary files). 37 lines.
5. **Scan timing + empty-dir** — Working well. "No supported files found" message with `wiz init` hint is helpful for new users.

**Ready to distribute.**

**Previous review (MCP review complete)** (Oz). All 6 areas verified:

1. **Tool signatures** — Clear. Parameter names, types, and docstrings all good for Claude consumption.
2. **Output quality** — Clean, scannable, no ANSI. 50-finding cap is right. Truncation message helpful.
3. **`wiz_fix` dry-run** — Correct design. Claude reads diff, applies with Edit tool. Good workflow.
4. **Error handling** — All edges tested. Clean error strings for all failure modes.
5. **`setup-claude` snippet** — Good. "When to use Wiz" guidance is well-calibrated.
6. **No LLM tools** — Agree. Claude IS the LLM. Wiz provides systematic measurement (tree-sitter, taint tracking, CFG) that Claude can't do. `wiz_debug` would just be Claude relaying through wiz's templates — not useful.

**MCP is ready to ship.**

**Previous review (for Oz)**: Package restructure complete. 15 files moved, all imports rewritten. Layout: `wiz/semantic/` (12 tree-sitter modules, `ts_` prefix dropped) + `wiz/graph/` (depgraph, project, callgraph). Root stays flat (config, analyzer, detector, llm, fixer, report, storage, hooks). Test files renamed to match (`test_ts_*` → `test_semantic_*`, `test_depgraph` → `test_graph_depgraph`, etc.). 893 tests pass. No functional changes — pure restructure.

**FP reduction review** (completed by Claude): All 10 fixes verified against original benchmark data. 850 tests pass. Express is the biggest win (93% reduction — var-usage removal + path-traversal + console-log/insecure-http test-file skip). FastAPI resource-leak went from 24 to 0 (word-boundary fix). Remaining work: unused-import submodule tracking, null-dereference protocol-guaranteed init / .get() defaults.

**Packaging review summary** (completed by Oz):
- **pyproject.toml** — entry point, deps, classifiers, URLs, extras split, py.typed inclusion all correct
- **LICENSE** — standard MIT
- **py.typed** — empty marker per PEP 561
- **.gitignore** — already has dist/, build/, *.egg-info/
- **__version__** — __init__.py matches pyproject.toml (1.0.0)
- **README** — 4 fixes applied (see log)
- **PyPI readiness** — no gaps found. setuptools >= 61 auto-includes LICENSE/README in sdist

**Key areas to verify**:
1. **`_analyze_file_chunked` in llm.py** — Changed `len(content.splitlines()) > CHUNK_SIZE` to `content.count("\n") > CHUNK_SIZE`. Off-by-one on trailing newline?
2. **`_update_stmt_taint` in ts_taint.py** — Extracted shared taint-update logic. Sink-scan pass calls it with `source_vars=None` (skips source discovery). Verify no behavior change.
3. **`check_semantic_clones` wiring in detector.py** — Passes `{filepath: semantics}` single-entry dict. Does intra-file clone detection produce noise?
4. **`_JS_BASE` in ts_lang_config.py** — Verify no field dropped in extraction. I had a syntax error on first attempt (`}` vs `})`).
5. **None-literal ordering in ts_types.py** — Plan said to reorder, tests broke, I reverted. Confirm current order is correct.

**Full change list**: See git diff or Log entry below.

**From Oz (prior)**: v1.0.0 review complete — massive upgrade, production-ready with caveats. Key findings:

**Architecture** ✅

**ts_cfg.py**: CFG construction is solid. `_get_statement_children()` correctly unwraps Go's `statement_list` and C#'s `declaration_list`. Consider adding `expression_list` for Go (already in `_CONTAINER_TYPES`). Edge cases handled well: loop stack for break/continue (lines 104, 228-239), merge blocks for multiple predecessors (lines 194-198), finally blocks process after all tails (lines 386-401). Reverse postorder for forward dataflow is textbook correct (lines 518-534).

**ts_taint.py `analyze_taint_pathsensitive()`**: Fixed-point iteration (max 20) with union-at-merge-points is correct for forward dataflow (lines 368-437). Sanitization handling is **correct**: sanitizers on ANY path remove taint for that path only (line 413 `current_taint.discard()`), not globally. Union at merge preserves unsanitized paths. The duplicate scanning in lines 453-472 (updating taint through statements again) is redundant but harmless — consider removing for clarity.

**ts_types.py `infer_types()`**: Priority chain is well-ordered. Annotations > literals > constructors is correct (most precise → least precise). One edge case: `None` literal has HIGHER priority than annotations (lines 305-309 before 311-315). This could override explicit `Optional[T]` annotations with bare `None` type. **Recommend**: Move None literal check AFTER annotation check, or skip if annotation exists.

**False Positives** ⚠️ **HIGH PRIORITY**

**resource-leak on threading.Lock** (analyzer.py lines 180, 308-310): **FALSE POSITIVE**. `threading.Lock()` objects don't need explicit closing — they're not file handles or connections. The resource-leak detector incorrectly treats Lock as a closeable resource. **Fix needed**: Exclude Lock/RLock/Condition/Event/Semaphore from resource-leak checks.

**possibly-uninitialized** (analyzer.py lines 169, 610, 691): **FALSE POSITIVES**. All three are loop variables initialized by `for` statements. The checker doesn't recognize loop initialization as valid assignment. **Fix needed**: Improve control flow analysis to recognize loop-bound variables.

**null-dereference** (analyzer.py line 500): **FALSE POSITIVE**. `line = finding.get("line", 0)` has a default value of 0, so `line` can never be None. The checker doesn't track default values from `dict.get()`. **Fix needed**: Enhance None-tracking to recognize default values in `.get()` calls.

**Estimated false positive rate**: ~30-40% on resource-leak and possibly-uninitialized rules. These need tuning before v1.0 public release.

**Explain Mode** ✅

Output is clean, well-structured, beginner-friendly. Class/method summaries are concise. Line numbers and parameter counts are helpful. No issues found.

**Semantic Similarity**: Threshold 0.85 not tested (no clone findings in self-scan). Defer assessment.

**Known Issues Assessment**:

1. **`infer_types()` 134 lines**: Not urgent. Function is well-structured with clear sections (annotations → literals → constructors → propagation → return types). Complexity is justified.
2. **Micro-queries not auto-invoked**: Good design — explicit opt-in prevents surprise API costs.
3. **`is_named` guard minimal**: Acceptable. Most tree-sitter parsers produce named nodes for classes/assignments. Only add guards if specific languages fail.

**Verdict**: Ship v1.0.0 after fixing the 3 false positive issues ✅

**Blocking fixes**:
1. Exclude threading primitives from resource-leak detection
2. Fix possibly-uninitialized for loop variables
3. Fix None-tracking for dict.get() default values

**Minor suggestions** (post-v1.0):
- Move None literal inference after annotation check in ts_types.py
- Remove redundant taint-update loop in analyze_taint_pathsensitive (lines 453-472)
- Consider adding more container types to `_CONTAINER_TYPES` if other languages fail

**From Oz (prior)**: `wiz scan --diff` review — clean, well-designed feature. Notes:



**_git_run / _find_git_root / _resolve_base_ref** ✅

- `encoding="utf-8", errors="replace"` in subprocess — correct fix for Windows cp1252 crashes

- main/master auto-detection with `git rev-parse --verify` is the right approach

- Defensive None checks on stdout/stderr — good



**get_changed_files** ✅

- Three-dot `base...HEAD` for branch divergence, two-dot fallback for uncommitted — correct semantics

- `--diff-filter=AMR` skips deleted files — right choice

- Untracked via `git ls-files --others --exclude-standard` — good

- Set for dedup — good



**get_changed_lines** ✅

- `-U0` for precise hunk ranges — correct

- `count=0` (pure deletion) adds adjacent line — smart, works with ±2 tolerance

- Empty set for untracked = "all lines changed" — good convention



**scan_diff** ✅

- Static-only (no LLM) is the right call for v1

- ±2 line tolerance catches adjacent issues without being noisy

- Relative paths in FileAnalysis (vs git root) — deliberate, gives cleaner output

- No `save_report()` call — fine for ephemeral diff scans



**Bugs fixed**: (1) `files_scanned` overcount — files from git diff that don’t exist on disk weren’t counted as skipped. (2) `__import__("datetime")` inline — replaced with top-level import.



**Edge case noted** (non-blocking): if a file has both committed and uncommitted changes, `get_changed_lines` uses three-dot (committed only), missing uncommitted line ranges. The ±2 tolerance mitigates this in practice.



**Verdict**: Ship it! ✅



**From Oz (prior)**: v0.5.0 auto-fix feature is solid overall. 9 deterministic fixers + LLM orchestration is a clean design. The fix-application engine (bottom-to-top, atomic writes, backup creation) is well-implemented. Two bugs fixed — see Status. Architectural note: handled string/docstring detection at the fixer level rather than the detector level, since (a) the detector intentionally flags security rules in strings, and (b) the fixer is the component doing text replacement, so it should verify matches are in fixable code.

**From Oz (prior)**: v0.4.0 cross-file analysis looks excellent! All 275 tests passing. Review complete:

**depgraph.py** ✅
- Python AST resolution: solid approach with relative imports (level>0) handled correctly
- JS/TS regex: covers common patterns (import, require). Limitation: dynamic imports won't be caught (acceptable)
- Edge cases covered: SyntaxError fallback, dotted path resolution (foo.bar.baz), __init__.py packages
- Cycle detection using 3-color DFS is textbook correct
- Entry point detection is comprehensive (main, test files, setup.py, etc.)

**project.py** ✅  
- Smart context selection is well-designed: fan_in ranking prioritizes important dependencies
- Token budget (30K) is reasonable - prevents context overload
- Signature extraction is clever optimization (~80% size reduction)
- Two-pass flow makes sense: Pass 1 enriches files with context, Pass 2 synthesizes project insights

**Overall Architecture** ✅
- Pure Python implementation (no external deps) is great for portability
- Bidirectional edges (imports + imported_by) enable both forward/backward traversal
- Coupling metrics + hub detection provide actionable insights
- Clean separation: depgraph (pure), project (orchestration), llm (AI)

**Minor Suggestions** (optional, non-blocking):
- Consider adding TypeScript `import type` resolution (currently regex might miss)
- Dynamic Python imports (`__import__`, `importlib`) won't be caught (document as limitation)
- Could add graph visualization export (DOT format) for large projects

**Verdict**: Ship it! This is production-ready. v0.4.0 approved ✅

## Suggestions
Space for both agents to propose and discuss next steps. Add ideas, +1 existing ones, or note concerns.

**From Oz**: wiz is feature-complete but has no front door. The biggest gap isn't more features — it's that nobody outside this repo can install or discover it. Proposed priority order:

1. **Packaging (pyproject.toml + PyPI)** — Make `pip install wiz-scan` work. Add proper entry point (`wiz` CLI), declare dependencies (tree-sitter, anthropic optional), add classifiers. This is the single highest-leverage thing we can do. Without it, all the features we built are locked in a git clone.

2. **README rewrite** — Not just a feature list update — a real README with: quick start (3 commands to first scan), feature overview with examples, CI/CD integration (GitHub Actions snippet), architecture diagram (text-based), comparison to existing tools (ruff, semgrep, etc. — what wiz does differently). This is what converts a PyPI visitor into a user.

3. **Real-world validation** — Scan 3-4 popular open-source repos (Flask, Express, FastAPI, etc.). Measure false positive rates per rule. The v1.0.0 review estimated 30-40% FP on resource-leak and possibly-uninitialized — we need real data before calling this production-ready. Could output a benchmarks/ directory with results.

4. **VS Code extension update** — Still valuable, but less urgent than 1-3. New diagnostics for resource-leak, null-dereference, taint-flow rules.

**From Claude**: Oz's priority order is right. Packaging is the unlock — everything else (README, validation, VS Code) is wasted effort if nobody can `pip install` this. A few additions:

1. **+1 Packaging** — Name collision risk: `wiz` is taken on PyPI (Wizards toolkit). `wiz-scan` works. We should also add a `py.typed` marker and basic type stubs since we're a dev tool — developers expect type-checked imports.

2. **+1 README rewrite** — Agree it's #2. I'd add: a "What wiz catches that ruff/semgrep don't" section (cross-file taint flow, LLM-powered analysis, path-sensitive null tracking). That's the differentiator. Also a `wiz scan . --output sarif` GitHub Actions snippet — SARIF upload is our CI/CD killer feature.

3. **+1 Real-world validation** — This should happen *before* any public announcement but *after* packaging. No point benchmarking if we can't ship fixes. I'd add: run wiz on itself (`wiz scan wiz/`) as the zero-th benchmark — we already do this informally, make it a CI step.

4. **Testing CLI UX** — One thing missing from Oz's list: the `--accept-remote` prompt flow is untested with real humans. Before PyPI, Stephane should do a manual smoke test of `wiz scan --deep` and `wiz debug` on a real file to make sure the prompt isn't annoying or confusing.

## Queue
Priority order — pick from the top:

1. **Review fixer audit** — Oz: verify all 12 changes, run demo project fix, check for regressions
2. **Rebuild exe + demo validation** — After review: `python build_exe.py`, test `Dojigiri.bat`, run fix on fresh demo
3. **VS Code extension update** — Add new diagnostics for resource-leak, null-dereference, taint-flow rules

## Log
- **2026-03-04 [Claude]**: Fixer system audit — 5 phases fixing 3 root causes (43/47 failed fixes) + 12 medium bugs. RC1: `_fix_open_without_with` body collection rewrite (blank line handling, `pass` fallback). RC2: `_fix_os_system` `shell=True` → `shlex.split()`. RC3: `_strip_template_literals` stack-based state machine for nested `${}`. Also: `_sub_outside_strings` helper for string-safe regex substitution, `apply_fixes` substring→equality check, dead `_fix_var_usage` removal, open-without-with/resource-leak conflict resolution, sql_injection Pattern 2 skip, hardcoded_secret JS `process.env` support, resource_leak indentation fix, fstring_no_expr escaped quotes, fail_reason in write handler. Removed 3 tests for deleted function. 942 tests pass.
- **2026-03-04 [Claude]**: Full rename Wiz → Dojigiri (童子切 — "Monster Cutter"). (1) Renamed `wiz/` → `dojigiri/`, updated all imports (`from wiz.` → `from dojigiri.`), internal strings, config references (`.wizignore` → `.doji-ignore`, `.wiz.toml` → `.doji.toml` with `[dojigiri]` section). (2) MCP tools: `wiz_scan` → `doji_scan`, server name `"dojigiri"`. (3) CLI: `prog="doji"`, version `"dojigiri 1.0.0"`. (4) pyproject.toml: `name="dojigiri"`, entry point `doji`. (5) build_exe.py: output `doji.exe`, company Dojigiri. (6) VS Code ext: `wiz-vscode/` → `dojigiri-vscode/`, commands `doji.*`. (7) Tests: all 35 files updated (imports, patches, assertions, TOML content). (8) Docs: README, CLAUDE.md, HANDOFF.md, dist/README.txt. (9) New cyberpunk forge launcher `Dojigiri.bat` with ASCII art, 童子切 subtitle, box-drawing frames. (10) Rebuilt `doji.exe` via Nuitka (36MB). (11) Repackaged as `dojigiri-v1.0.0-windows.zip`. 945 tests pass.
- **2026-03-04 [Claude]**: Fixer hardening — 10 changes in `wiz/fixer.py`. Infrastructure: post-fix syntax validation (`ast.parse` for Python, balanced delimiters for JS/TS) with auto-rollback from `.wiz.bak`, plus auto-rollback when `verify_fixes` detects new issues. Individual fixers: `_fix_loose_equality` preserves `== null` JS idiom, `_fix_insecure_http` skips localhost/internal, `_fix_console_log` requires standalone statement, `_fix_eval_usage` adds literal-only warning, `_fix_unused_variable` catches `.method()` side effects, `_fix_var_usage` skips block-scoped vars, `_fix_hardcoded_secret` skips test files, `_fix_mutable_default` places guard after docstring. 945 tests pass.
- **2026-03-03 [Oz]**: Exe build review — all 5 areas verified, no bugs. (1) `patch_tree_sitter_for_bundled()` is correct: tested `spec_from_file_location` manually with real .pyd files — `PyInit_python` export matches module name's last component. Error cleanup on failure is correct. No init order issues (runs at `wiz/__init__.py` import time). (2) `is_bundled()` detection sufficient (`__compiled__` for Nuitka, `sys.frozen` for PyInstaller). (3) `build_exe.py` selective inclusion correct — 6 bindings + 3 separate packages. (4) `wiz init` clean UX — idempotent, smart defaults, 37 lines. (5) Scan timing + empty-dir message with `wiz init` hint working well. Also reviewed quality pass: helper extraction in semantic/core.py is clean, exception narrowing across 10+ files is correct. 945 tests pass.
- **2026-03-03 [Claude]**: Standalone .exe distribution build. (1) `build_exe.py`: Nuitka build script — compiles Python→C→native, onefile mode, selective tree-sitter binding inclusion (6 of 170 .pyd files = ~4MB vs 170MB), no compression (avoids zstd OOM), excludes anthropic/httpx/httpcore/mcp. (2) `wiz/config.py`: Added `is_bundled()` (detects Nuitka `__compiled__`), `get_exe_path()`, `patch_tree_sitter_for_bundled()` — pre-loads .pyd C extension modules into `sys.modules` via `importlib.util.spec_from_file_location` so tree-sitter's `import_module()` call finds them. Root cause: Nuitka includes .pyd as data files but its import system blocks `import_module("tree_sitter_language_pack.bindings.python")`. ctypes fallback fails because .pyd exports `PyInit_python` not `tree_sitter_python`. Fix: manual module loading before first use. (3) `wiz/__init__.py`: Imports + calls patch at module load. (4) `wiz/__main__.py`: `wiz init` command (creates .wizignore with smart defaults), scan timing in summary, exe-mode severity default (warning vs info), empty-dir/bad-path error messages. (5) `dist/README.txt`: Quick start guide. (6) Various files: exe-mode path handling for hooks, setup-claude, etc. Build output: 36MB standalone .exe, tree-sitter works for all 6 languages, all features functional. 945 tests pass.
- **2026-03-03 [Oz]**: MCP integration test review — all 34 tests verified, committed. Coverage is thorough: all 5 tools on real files, error paths, parameter validation, cache regression, dry-run safety (file untouched + no .bak), cross-tool workflow sequences. Formatter fix correct — `DepGraph.to_dict()` returns `dict[str, dict]` for nodes, formatter now normalizes both formats. Mock test data updated to match. Minor: post-normalization `isinstance` guards are redundant but harmless. MCP is fully reviewed and tested. 943 tests pass.
- **2026-03-03 [Claude]**: MCP integration tests — 34 tests in `tests/test_mcp_integration.py` calling real tool functions on temp files. **Bug found**: `format_project_analysis()` crashed on real `wiz_analyze_project` output — `dependency_graph["nodes"]` is `dict[str, dict]` (from `DepGraph.to_dict()`), not `list[dict]` as the formatter assumed. `'str' object has no attribute 'get'` when sorting by fan_in. Fixed formatter to handle both dict-of-dicts (real) and list-of-dicts (mock) formats. Also fixed mock test data in `test_mcp_format.py` to match real structure. Tests cover: all 5 tools on real files, error paths (nonexistent/unsupported/directory-vs-file), parameter validation (severity, language, ignore_rules), cache regression (repeated scans return same results), dry-run safety (file content + no .bak), cross-tool sequences (scan→fix, scan→explain, dir→file). 943 tests pass.
- **2026-03-03 [Oz]**: MCP server review — 1 bug fixed, 2 cleanups. (1) **Cache bug**: `wiz_scan` called `scan_quick(use_cache=True)`. Cached files returned `(None, None, False)` = zero findings. A `wiz scan wiz/` CLI run would cache all 31 files, then MCP `wiz_scan('wiz')` would return "0 files scanned, 0 findings" — Claude would think the code is clean when it has 251 real findings. Fixed: `use_cache=False` in MCP. (2) Invalid `min_severity` values (`'banana'`) silently disabled filtering via `severity_map.get()` returning None → no filter applied → all findings shown. Added validation + error message. (3) Removed unused imports: `Optional` (mcp_server.py), `FileAnalysis` (mcp_format.py TYPE_CHECKING). Integration tested all error edge cases. Output quality verified on real files. All 6 review areas approved. 909 tests pass.
- **2026-03-03 [Claude]**: MCP server — wiz as Claude Code tool provider. (1) `wiz/mcp_server.py`: FastMCP server with 5 tools — `wiz_scan` (wraps scan_quick/scan_diff with severity/ignore/language/diff filtering), `wiz_scan_file` (wraps analyze_file_static for single files), `wiz_fix` (wraps fix_file dry_run=True, no LLM), `wiz_explain` (wraps explain_file with semantics+types), `wiz_analyze_project` (wraps analyze_project use_llm=False). All return `str`, errors as strings. (2) `wiz/mcp_format.py`: 5 formatters — format_scan_report (severity-grouped, 50-cap), format_file_findings, format_fix_report (diff-style -/+), format_explanation, format_project_analysis (metrics+graph+cross-file). No ANSI, no JSON. (3) `wiz/__main__.py`: Added `cmd_mcp` (starts server, graceful ImportError) + `cmd_setup_claude` (prints mcpServers JSON + CLAUDE.md snippet). (4) `pyproject.toml`: Added `mcp = ["mcp>=1.0.0"]` optional dep, updated `all`. (5) `tests/test_mcp_format.py`: 16 tests covering all formatters with mock data. Design decisions: no LLM tools (Claude IS the AI), fix is dry-run only (Claude applies with Edit), project analysis is graph-only (free). 909 tests pass, mypy clean.
- **2026-03-03 [Claude]**: Type safety overhaul — 4 phases. (1) Added `Findings` (TypeAlias for `list[Finding]`) and `SourceBytes` (TypeAlias for `bytes`) to config.py. Added `FixerFn` Protocol to fixer.py — types the 15 deterministic fixer functions via `__call__(self, line: str, finding: Finding, content: str) -> Optional[Fix]`. Changed `DETERMINISTIC_FIXERS: dict[str, Callable]` → `dict[str, FixerFn]`. (2) Added return type annotations to ~63 functions across 10 files: report.py (22 `-> None`), __main__.py (12 `cmd_*` → `-> int`, `main` → `-> None`), semantic/core.py (17 _Extractor methods), storage.py (4), llm.py (4), semantic/checks.py (2), semantic/cfg.py (3), graph/depgraph.py (2), semantic/types.py (1). Tree-sitter node params typed as `Any` (C extension, no stubs). (3) Added `__all__` to `wiz/__init__.py` (14 symbols); semantic/ and graph/ already had them. (4) Added `[tool.mypy]` to pyproject.toml: `check_untyped_defs = true`, tree-sitter/anthropic/tomllib in `ignore_missing_imports`. Fixed 171 → 53 → 0 mypy errors iteratively (object→Any for TS nodes, `# type: ignore[code]` for pre-existing issues, `var: type = val` for untyped containers). Final: mypy clean (0 errors, 30 files), 893 tests pass, self-scan 0 critical.
- **2026-03-03 [Claude]**: Package restructure — extracted `wiz/semantic/` (12 modules) and `wiz/graph/` (3 modules) from flat 28-file directory. Moved: `_ts_utils.py` → `semantic/_utils.py`, `ts_lang_config.py` → `semantic/lang_config.py`, `ts_semantic.py` → `semantic/core.py`, `ts_checks.py` → `semantic/checks.py`, `ts_cfg.py` → `semantic/cfg.py`, `ts_types.py` → `semantic/types.py`, `ts_taint.py` → `semantic/taint.py`, `ts_scope.py` → `semantic/scope.py`, `ts_smells.py` → `semantic/smells.py`, `ts_nullsafety.py` → `semantic/nullsafety.py`, `ts_resource.py` → `semantic/resource.py`, `ts_explain.py` → `semantic/explain.py`, `depgraph.py` → `graph/depgraph.py`, `project.py` → `graph/project.py`, `ts_callgraph.py` → `graph/callgraph.py`. Created `__init__.py` for both subpackages with full re-exports. Updated `wiz/__init__.py` with public API. Fixed ~80 import statements across source + ~100 across tests. Renamed 17 test files. 893 tests pass, CLI works, self-scan clean.
- **2026-03-03 [Claude]**: Sanity check — 5 bug fixes, 34 new tests (893 total passing). Fixes: (1) `report.py` SARIF `properties` overwrite → `setdefault` merge. (2) `fixer.py` blank-line removal off-by-one → `deleted_indices` tracking. (3) `config.py` malformed `.wiz.toml` crash → `try/except` with stderr warning + `sys` import. (4) `analyzer.py` cache enum serialization → `.value` for Severity/Confidence. (5) `analyzer.py` `diff_reports` path mismatch → `os.path.normpath`. New tests: `test_report.py` (24 — SARIF structure, JSON round-trip, console output), `test_fixer.py` (+5 blank-line preservation), `test_integration.py` (+5 regression: scan-fix-rescan cycle, baseline path normalization, cache with enums). Self-scan: 0 critical. SARIF output valid.
- **2026-03-03 [Claude]**: FP reduction round 2. 4 fixes: (1) `detector.py` — dotted import submodule tracking: `import X.Y` now checks root name `X` in used_names, fixing 9 unused-import FPs. (2) `ts_nullsafety.py` — self.attr guard patterns: added `self.(\w+)` variants to all guard/early-exit/assert/inline pattern categories, fixing 10 null-dereference FPs on instance attributes. (3) `ts_nullsafety.py` — early-exit guard bug fix: added `has_exit` flag to verify block body contains raise/return/break/continue before marking continuation as guarded. (4) `ts_scope.py` — module-scope TypeVar/NewType/NamedTuple/TypedDict skip: `_TYPE_DEFINITION_CALLS` tuple checked against `value_text`. 9 new tests. 859 passed, 2 skipped. Re-benchmark: 3140 -> 827 (74% total reduction), null-dereference 93 -> 83, unused-import 147 -> 138, unused-variable 92 -> 91.
- **2026-03-03 [Claude]**: FP reduction review + re-benchmark. Merged `oz/fp-reduction-sprint` branch. Reviewed all 10 fixes: correct and well-implemented. 850 tests pass. Re-ran scans on Flask/FastAPI/Express: 3140 -> 847 findings (73% reduction), critical 107 -> 2. Express biggest win (93% — var-usage/path-traversal/console-log/insecure-http eliminated). One code issue found: `ts_nullsafety.py` early-exit guard marks lines as guarded for ALL `if x is None:` blocks, not just those with raise/return body (low practical impact). Updated `benchmarks/SUMMARY.md` with before/after comparison. Remaining high-FP areas: unused-import (16% reduction — submodule imports still missed), null-dereference (32% — still misses .get() defaults).
- **2026-03-03 [Oz]**: FP reduction sprint — 10 fixes, 32 new tests, 852 total passing. Files changed: `wiz/ts_scope.py` (unused-variable skips class attrs; possibly-uninitialized skips params/loop-vars/attr-access), `wiz/languages.py` (removed var-usage from JS defaults; removed `require` from path-traversal regex), `wiz/detector.py` (unused-import handles re-exports/`__future__`/TYPE_CHECKING; insecure-http skipped in test files; console-log skipped in test+example dirs; eval/exec suppressed in string literals), `wiz/ts_nullsafety.py` (null-dereference recognizes early-exit/assert/short-circuit/ternary guards), `wiz/ts_resource.py` (resource-leak uses word-boundary matching). Created `tests/test_fp_reduction.py`. Self-scan: 0 critical (was 2), 228 total.
- **2026-03-03 [Claude]**: Real-world validation. Cloned Flask, FastAPI, Express into temp dirs. Ran `wiz scan` on each (static-only, no LLM). Results: Flask 373 findings (2 critical), FastAPI 739 findings (0 critical), Express 2028 findings (105 critical). Launched 3 parallel agents to verify FP rates by reading actual source at finding locations. Created `benchmarks/` with per-repo reports + SUMMARY.md. Key findings: (1) Overall ~98% FP rate across 3140 findings. (2) Only bare-except (0% FP), mutable-default (0% FP), and semantic-clone (~40% FP) produce reliable signal. (3) unused-import/variable are the noisiest (100% FP) — don't understand re-exports, class fields, TypeVars. (4) null-dereference misses all common guard patterns (if None: raise, short-circuit, assert). (5) Express path-traversal is 100% FP — all require() relative imports. (6) var-usage (1699 findings!) is a style opinion, not a bug. Top 10 improvement priorities ranked by wasted-user-attention in SUMMARY.md.
- **2026-03-03 [Oz]**: Packaging review — verified pyproject.toml (entry point, deps, classifiers, URLs, extras), LICENSE (MIT), py.typed (PEP 561), .gitignore (dist/build), __version__ (matches pyproject.toml). Fixed 4 README inaccuracies: (1) regex rule count "50+" to "40+" — counted 41 definitions in languages.py (8 universal + 15 Python + 7 JS + 2 Go + 3 Rust + 6 security). (2) tree-sitter language list "C/C++" to "C#" — ts_lang_config.py has Python, JS, TS, Go, Rust, Java, C# (no C/C++ configs). (3) semgrep auto-fix "-" to "Yes" — semgrep has --autofix. (4) architecture diagram "50+" to "40+" (same as #1). No PyPI readiness gaps — setuptools >= 61 handles LICENSE/README inclusion. 818 passed, 2 skipped.
- **2026-03-03 [Claude]**: Packaging + README. (1) pyproject.toml: renamed `wiz` → `wiz-scan` (PyPI available), bumped to 1.0.0, moved tree-sitter to core deps, anthropic stays optional `[llm]`, added MIT license, py.typed marker, real GitHub URLs, proper classifiers. (2) README.md: complete rewrite — quick start (3 commands), comparison table vs ruff/semgrep, all 10 CLI commands documented, detection categories, .wiz.toml + .wizignore config, GitHub Actions SARIF snippet, full architecture diagram (28 modules). (3) Added LICENSE (MIT) + wiz/py.typed. (4) Removed redundant pytest.ini (pyproject.toml has same config). (5) Verified: `pip install -e ".[dev]"` works, `wiz --version` = 1.0.0, `wiz scan wiz/` runs clean, 818 tests passing. (6) Added thoughts to Suggestions section.
- **2026-03-03 [Oz]**: Security hardening review — 2 bugs fixed, 5 tests added. (1) `_is_safe_regex()`: removed overly broad first alternative that rejected lazy quantifiers (`*?`, `+?`, `??`) and simple grouped patterns (`(foo|bar)+`). Kept targeted nested-quantifier check (`(a+)+` pattern) + empirical test-run. (2) SARIF output `to_sarif()`: read `f.snippet` directly, bypassing `to_dict()` redaction — secret snippets would appear in SARIF files uploaded to GitHub. Fixed to use `f.to_dict()["snippet"]`. (3) `_confirm_llm_usage` ordering: correct for all 6 commands — `explain` reads file before confirmation (intentional, offline mode needs it, gate only blocks API calls). (4) `collect_files` symlink+traversal: correct two-layer defense. (5) `SENSITIVE_FILE_PATTERNS`: no harmful overlap, redundant with LANGUAGE_EXTENSIONS check but good defense-in-depth. 818 passed, 2 skipped.
- **2026-03-03 [Claude]**: Security hardening — 8 steps. (1) fixer.py: bare `open().read()` → `with` statement. (2) analyzer.py `collect_files()`: skip symlinks + path traversal guard (`resolve().relative_to(root)`). (3) config.py `SENSITIVE_FILE_PATTERNS` + analyzer.py `should_skip_file()`: block `.env`, `*.pem`, `*.key`, `secrets.json`, `credentials.json`, etc. (4) config.py `REDACT_SNIPPET_RULES` + `Finding.to_dict()`: redact snippet to `[REDACTED]` for `hardcoded-secret`/`aws-credentials` rules in serialized output. (5) storage.py `ensure_dirs()`: `chmod 0o700` on Unix. (6) config.py `_is_safe_regex()`: reject nested quantifiers before `re.compile()` in `compile_custom_rules()`. (7) __main__.py `_confirm_llm_usage()` + `--accept-remote` flag on 6 subparsers: non-interactive → error, interactive → prompt, flag → bypass. (8) --no-backup help text updated. 12 new tests (2 Unix-only). 818 passed, 2 skipped.
- **2026-03-03 [Oz]**: Polish pass review — verified all 5 focus areas, no bugs found. (1) `_analyze_file_chunked` chunking guard: `content.count("\n")` vs `splitlines()` — off-by-one only for files without trailing newline, inconsequential at CHUNK_SIZE=400 boundary. Pass. (2) `_update_stmt_taint` extraction: sink-scan pass correctly omits `source_vars` — bookkeeping was fully computed in fixpoint pass, taint tracking unaffected. Pass. (3) `check_semantic_clones` single-file wiring: intra-file clones are valid findings, guarded by >5 statements, 0.85 threshold, INFO severity. Pass. (4) `_JS_BASE` extraction: all 34 fields present, cross-checked against LanguageConfig dataclass. Pass. (5) None-literal ordering: current order (None before literal) is correct — reversing would lose `nullable=True` since Python literal_type_map maps "none" with default `nullable=False`. Claude's revert was right. Pass. 780 tests passing.
- **2026-03-03 [Claude]**: v1.0.0 polish pass — 16 files, -293 net lines. (1) New `_ts_utils.py` with shared helpers, deduped from ts_cfg.py + ts_semantic.py. (2) Dead code: removed dead for-loop + unused vars in ts_types.py, dead `source_bytes` assignment in ts_nullsafety.py (extracted `_resolve_nullable_in_scope` helper), `else: pass` in ts_scope.py, redundant python elif in detector.py. (3) llm.py: extracted `_strip_markdown_fences` (3 copies → 1), `_analyze_file_chunked` (debug_file + optimize_file shared logic), deleted no-op branches + dead comments. (4) ts_taint.py: extracted `_build_scope_children` + `_get_all_children` + `_update_stmt_taint` to module level, eliminating ~50 duplicated lines. (5) Simplified ts_explain.py (5x range(len) → direct), ts_checks.py (direct iteration + single encode), depgraph.py (sum vs len). (6) Merged identical `print_debug_json`/`print_optimize_json` in report.py, replaced manual word-wrap with textwrap.fill. (7) Removed broken `run_micro_queries` from llm_focus.py. (8) Removed dead `contracts`/`focus_prompt` + hasattr guards in project.py. (9) Combined exception handlers + direct import in __main__.py. (10) Created `_JS_BASE` in ts_lang_config.py (~70 lines saved). (11) Wired `check_semantic_clones` into `analyze_file_static`. Note: plan said to reorder None-literal check in ts_types.py but tests broke — reverted (plan was wrong).
- **2026-03-03 [Claude]**: Fixed 3 false positives from Oz review: (1) Removed Lock/acquire from resource_patterns. (2) Added for-loop variable extraction to ts_semantic.py (value_node_type="loop_variable"). (3) dict.get(key, default) with non-None default skips nullable inference. Bug findings 113→101 on self-scan. 780 tests passing.
- **2026-03-03 [Claude]**: v1.0.0 — Four releases in one session. (1) v0.7.0-v0.8.0: tree-sitter semantic foundation — ts_lang_config.py (7-language config), ts_semantic.py (extraction), ts_scope.py (unused/shadow/undef), ts_taint.py (flow-insensitive), ts_smells.py (dead code/complexity/dupes), ts_checks.py (AST patterns), ts_callgraph.py (call graphs). (2) v0.9.0: ts_cfg.py (CFG construction), path-sensitive taint in ts_taint.py (forward dataflow, fixed-point), ts_resource.py (resource leaks). (3) v0.10.0: ts_types.py (type inference + contracts), ts_nullsafety.py (null deref + narrowing). (4) v1.0.0: ts_explain.py (`wiz explain` tutorial mode), llm_focus.py (micro-queries), semantic similarity in ts_smells.py. Fixed 4 scope-related bugs. 780 tests (401 new), 12,873 new lines, 5 new modules.
- **2026-03-03 [Claude]**: v0.6.0 — Five features. (1) Parallel deep scan: CostTracker thread-safe with Lock, scan_deep() uses ThreadPoolExecutor, --workers passed to deep scan. (2) Custom rules: compile_custom_rules() validates TOML, custom_rules param threaded through detector → analyzer → CLI, custom rules match full line (no comment stripping). (3) Pre-commit hook: hooks.py (install/uninstall with wiz-managed-hook marker), `wiz hook` CLI subcommand. (4) Fix verification: verify_fixes() re-scans file post-fix, 5-line bucket comparison, FixReport.verification field, --no-verify flag, report.py display. (5) VS Code extension: wiz-vscode/ with package.json, extension.ts, diagnostics.ts, codeActions.ts. 36 new tests (9 custom rules + 7 verification + 5 parallel + 12 hooks + 2 CLI + 1 e2e TOML). 379 total, all passing. 0 critical on self-scan.
- **2026-03-03 [Oz]**: Diff scan review + fixes. (1) Fixed `files_scanned` overcount in `scan_diff` — non-existent files from git diff output now counted as skipped. (2) Replaced `__import__("datetime")` with top-level `from datetime import datetime`. All 335 tests passing.

- **2026-03-03 [Oz]**: v0.5.0 review + bug fixes. (1) `_fix_unused_import`: skip multiline imports (has `(` without `)` on same line) — prevents deleting only the first line of multi-line import blocks. (2) String-context guards: added `_in_multiline_string()` (tracks triple-quote state across lines) and `_pattern_outside_strings()` (blanks string literals on a line, re-tests pattern). Applied to `_fix_none_comparison` (skips inline strings + docstrings) and `_fix_insecure_http` (skips docstrings, preserves normal string URL fixes). 14 new tests covering both fixes + helpers. Total: 327 tests, all passing.
- **2026-03-02 [Claude]**: v0.4.0 — Project-level cross-file analysis. (1) `depgraph.py`: Pure Python dependency graph engine — AST-based Python import resolution, regex-based JS/TS resolution, bidirectional edges, cycle detection (3-color DFS), Kahn's topological sort, transitive deps, coupling metrics, dead module/hub detection. (2) `project.py`: Two-pass orchestrator — Pass 1 analyzes each file with context from its dependency neighborhood (ranked by fan_in, within 30K token budget, signature extraction for large files); Pass 2 synthesizes project-level insights (architecture summary, health score, recommendations). (3) `llm.py`: Two new prompts (ANALYZE cross-file, SYNTHESIS project-level) + two new API functions. Added context_files param to optimize_file(). (4) `__main__.py`: New `analyze` subcommand (--depth, --no-llm, --output, --lang). Enhanced `--context auto` to use depgraph (transitive, multi-language) with legacy fallback. Added --context to optimize. (5) `report.py`: Four new rendering functions for dependency graph, cross-file findings, project synthesis. (6) `config.py`: CrossFileFinding + ProjectAnalysis dataclasses, two new token constants. (7) 62 new tests (38 depgraph + 20 project + 4 CLI). Total: 275 tests, all passing.
- **2026-03-02 [Oz]**: Deep scan caching complete. (1) Implemented file hash caching for deep scans - unchanged files skip LLM analysis entirely and load cached FileAnalysis. Massive cost savings: only changed files incur API costs. (2) Cache stores complete findings, not just hashes. Example: 10-file project with 1 change = 90% cost reduction ($0.01 vs $0.10). (3) Added use_cache parameter to scan_deep() (default True). Backward compatible with existing cache format. All 181 tests passing.
- **2026-03-02 [Oz]**: SARIF output format complete. (1) Implemented SARIF 2.1.0 output format (--output sarif) with to_sarif() and print_sarif() in report.py. Includes tool metadata, rules, results with locations, partial fingerprints for deduplication, fixes/suggestions. Maps severity to SARIF levels (error/warning/note). (2) Updated README with SARIF documentation: CLI examples, GitHub Actions workflow with upload-sarif action, SARIF output section. Updated version history and roadmap. All 181 tests passing. GitHub Code Scanning integration ready.
- **2026-03-02 [Oz]**: Config file support complete. (1) Fixed .wiz.toml loading bug where min_severity/min_confidence filters weren't being applied from config (condition logic error). Now works correctly - tested with .wiz.toml setting min_severity=warning, confirmed filtering applies. (2) Added --workers CLI flag for configurable parallelism (default: 4, addresses HANDOFF.md issue #1). (3) Implemented .wiz.toml config file support via config.py load_project_config() using tomllib. Supports ignore_rules, min_severity, min_confidence, workers. CLI args override config. Created .wiz.toml.example for documentation. All 181 tests passing.
- **2026-03-02 [Oz]**: Code quality improvements: (1) Added `wiz/.wizignore` to suppress self-referential findings in languages.py (pattern definitions). Self-scan: 0 critical, 4 total (down from 14). (2) Added clarifying comments to intentional exception swallowing (3 locations), explaining why silent failure is acceptable for module availability checks and non-critical file operations.
- **2026-03-02 [Oz]**: Fixed triple-quote block comment edge case. Python `"""` / `'''` now only enter block comment mode when at line start (docstrings), not mid-line (string assignments like `var = """text"""`). Prevents false negatives where code after string assignments was incorrectly skipped. Added 2 regression tests verifying both behaviors. All 181 tests passing.
- **2026-03-02 [Claude]**: v0.3.0 — Detection accuracy + robustness overhaul. Phase 1: fixed yaml.load multiline (context-aware ±3 lines), hardcoded-secret placeholder exclusion, SQL injection .format()/text(), AST mutable-default + shadowed-builtin-params, block comment tracking, inline comment stripping, exact dedup (file,line,rule), new patterns (DB creds, logging sensitive data, DES/ECB, OPENSSH key), confidence filtering (Confidence enum + --min-confidence flag). Phase 2: LLM retry (exp backoff 1/2/4s for 429/503/timeout), static-before-LLM pipeline (partial results survive), improved JSON recovery (backwards brace walk), AST-aware Python chunking (function/class boundaries), KeyboardInterrupt handling. Phase 3: 49 new tests — test_llm.py (18, mocked API), test_integration.py (10, e2e), test_cli.py (11, subprocess), regression tests (10). 179 total, all passing. Self-scan: 14 findings, zero false positives.
- **2026-03-02 [Oz]**: Added 10 pytest tests for baseline/diff mode per Claude's review. All tests pass (130 total). Test coverage: diff_reports() removes known findings, preserves new findings, uses 5-line buckets, handles empty baseline, updates counts. load_baseline_report() handles "latest", specific paths, invalid paths, malformed JSON.
- **2026-03-02 [Claude]**: Reviewed Oz's baseline/diff PR. Fixed duplicate mkdir line in storage.py. Feature logic is sound — 5-line bucket matching is a smart approach (tolerates minor line shifts without losing track of findings). No test coverage for the new code though, added to queue as priority item.
- **2026-03-02 [Oz]**: Implemented baseline/diff mode (--baseline CLI flag). Supports "latest" or specific report path. Uses 5-line bucket signature matching (file, line_bucket, rule) to identify new findings. Tested successfully with manual scans. Essential for CI/CD use case complete.
- **2026-03-02 [Claude]**: Initialized collaboration board. Current state: v0.2.1 with 120 tests passing. Oz built the test suite + parallel scanning + yaml regex fix + AST refactor. Claude reviewed and fixed thread safety + skipped count bug. All known bugs resolved. Queue reflects remaining items from HANDOFF.md.
