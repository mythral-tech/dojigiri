# Quick Start

## Scan a project

```bash
doji scan .
```

Scans the current directory with 130+ rules across 18 languages. No config needed.

Example output:

```
src/auth.py:42  CRITICAL  [security]  hardcoded-secret
  Hardcoded password detected: password = "admin123"

src/db.py:18   WARNING   [security]  sql-injection
  Possible SQL injection via string formatting

src/utils.py:7 INFO      [style]     unused-import
  Unused import: os

Found 3 issues (1 critical, 1 warning, 1 info) in 12 files
```

## Deep scan (LLM-powered)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
doji scan . --deep --accept-remote
```

Runs the static engine first, then sends targeted chunks to an LLM for analysis beyond what rules can catch. LLM findings are tagged `[llm]`.

## Dependency scan

```bash
doji sca .
```

Scans lockfiles for known vulnerabilities via the Google OSV database.

## Auto-fix

```bash
doji fix .              # Preview fixes
doji fix . --apply      # Apply fixes
```

Deterministic fixers handle common patterns. LLM-assisted fixes available with `--deep`.

## Explain a file

```bash
doji explain src/auth.py
```

Plain-language walkthrough of findings in a file -- useful for onboarding or code review.

## Output formats

```bash
doji scan . --output sarif > results.sarif
doji scan . --output json  > results.json
doji scan . --output html  > report.html
```

## Filter by severity

```bash
doji scan . --min-severity warning    # Skip INFO findings
doji scan . --min-severity critical   # Only critical issues
```

## Diff-only scanning

```bash
doji scan . --diff                    # Scan only git-changed lines
doji scan . --baseline latest         # Report only new findings
```
