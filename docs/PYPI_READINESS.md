# PyPI Publish Readiness Report

**Date:** 2026-03-09
**Version:** 1.1.0
**Auditor:** Takumi (Code Craftsmanship)

---

## Checklist

| # | Item | Status | Notes |
|---|------|--------|-------|
| 1 | **pyproject.toml metadata** | PASS | Name, version, description, author, license, classifiers, keywords, python_requires all present and correct |
| 2 | **Project URLs** | PASS (fixed) | Added `Documentation` and `Changelog` URLs. Homepage, Repository, Issues already present |
| 3 | **README.md** | PASS | Comprehensive. Badges, quick start, feature list, architecture diagram, comparison table, CI examples, limitations. A developer lands on PyPI and knows what this is in 10 seconds |
| 4 | **LICENSE (BUSL-1.1)** | PASS (with caveat) | File present and correct. **Caveat:** Licensor field reads `-PENDING LLC-` -- update before publish if the LLC is formed |
| 5 | **CHANGELOG.md** | PASS | Thorough, follows Keep a Changelog format. Current for v1.1.0 |
| 6 | **`__init__.py` exports** | PASS | `__version__` = "1.1.0" matches pyproject.toml. Clean `__all__` with all public types |
| 7 | **`__version__` consistency** | PASS | pyproject.toml and `__init__.py` both read "1.1.0" |
| 8 | **YAML rules in package data** | PASS (fixed) | Was **BROKEN**: 10 YAML rule files (632 rules) were excluded from both wheel and sdist. Fixed `pyproject.toml` package-data and `MANIFEST.in` to include `*.yaml` |
| 9 | **`loader.py` in package** | PASS (fixed) | Was excluded from prior build. Now included via corrected MANIFEST.in |
| 10 | **PyYAML dependency** | PASS (fixed) | YAML loader imports `yaml` but PyYAML was not in dependencies. Added `pyyaml>=6.0` to core deps. Without this, installed users would silently fall back to the smaller Python rule set |
| 11 | **CLI entry point** | PASS | `doji = dojigiri.__main__:main` correctly configured as console_scripts |
| 12 | **Dependencies** | PASS | `tree-sitter>=0.24`, `tree-sitter-language-pack>=0.10`, `pyyaml>=6.0`, `tomli>=1.0` (3.10 only). Optional extras properly separated: llm, mcp, pdf, all, dev |
| 13 | **py.typed marker** | PASS | Present in package root and included in wheel |
| 14 | **MANIFEST.in** | PASS (fixed) | Added `*.yaml` to recursive-include. Prunes tests, benchmarks, .github, .claude, .internal |
| 15 | **Build test** | PASS | `python -m build --sdist --wheel` succeeds cleanly. Wheel: 365 KB, sdist: 329 KB |
| 16 | **twine check** | PASS | Both wheel and sdist pass twine validation |
| 17 | **Security - no secrets** | PASS | No `.env` files, no API keys, no credentials in any published file. `.gitignore` covers `.env*`, `*.pem`, `*.key`, `.credentials*`, `.doji.toml` |
| 18 | **Security - no internal files** | PASS | `.internal/`, `.claude/`, `INCIDENT.md`, `CLAUDE.md` all excluded via MANIFEST.in prune and .gitignore |
| 19 | **Sensitive file patterns in code** | PASS | References to `.env`, `secret`, `api_key` etc. exist only in detection rule patterns (the tool's job) -- not as actual secrets |
| 20 | **Wheel contents** | PASS | 91 files total. All expected packages present: cli, fixer, graph, rules (+ yaml/), sca, semantic. Zero suspicious files |

---

## Issues Fixed During Audit

### Critical (would have broken installs)

1. **YAML rules missing from package** -- `pyproject.toml` `[tool.setuptools.package-data]` only listed `py.typed`. Added `rules/yaml/*.yaml`. Without this fix, `pip install dojigiri` would ship without 632 of the tool's rules (the C#, PHP, TypeScript rule sets would be completely absent, and other languages would lose their expanded YAML rules).

2. **`loader.py` missing from prior wheel** -- The YAML rule loader module was not in the previously built wheel. The corrected MANIFEST.in now includes it.

3. **PyYAML not in dependencies** -- The YAML rule loader does `import yaml` with a silent fallback. Users would get a degraded rule set with no warning. Added `pyyaml>=6.0` to core dependencies.

### Minor (improved but not blocking)

4. **Missing Documentation and Changelog URLs** -- Added `Documentation = "https://dojigiri.dev"` and `Changelog` URL to `[project.urls]`. PyPI renders these as sidebar links.

---

## Items for Sol to Decide

1. **LICENSE: `-PENDING LLC-` placeholder** -- The Licensor field in LICENSE reads `-PENDING LLC-`. If the LLC is formed before publish, update it. If not, it still works legally (copyright line names Stephane Perez) but looks unfinished.

2. **Version 1.1.0 as first PyPI release** -- Technically fine, but some projects start at 0.x or 1.0.0 for first public release. 1.1.0 implies a prior 1.0.0 existed publicly. This is cosmetic and probably doesn't matter for the target audience.

3. **README badge URLs** -- The Tests and OWASP Benchmark badges are static (no linked CI). Consider linking to actual CI runs or removing the badge format in favor of plain text. Not blocking.

4. **`semgrep_benchmark.json` (1.2 MB)** -- This file sits in the repo root. It's excluded from the package (good) but will be in the GitHub repo. Consider moving to `.internal/` or `benchmarks/results/`.

---

## Verdict

**READY TO PUBLISH** -- after fixing the 3 critical issues above (all applied in this audit).

The package builds clean, twine validates, all rules are included, dependencies are correct, no secrets leak, the README is strong, and the entry point works. The only open item is the `-PENDING LLC-` placeholder in LICENSE, which Sol should update if the LLC exists.

### Files Modified

- `pyproject.toml` -- added `pyyaml>=6.0` dep, `rules/yaml/*.yaml` to package-data, Documentation + Changelog URLs
- `MANIFEST.in` -- added `*.yaml` to recursive-include pattern
