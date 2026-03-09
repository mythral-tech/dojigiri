# Auto-Fix

Dojigiri can generate and apply fixes for detected issues.

## Usage

```bash
doji fix .              # Preview fixes (dry run)
doji fix . --apply      # Apply fixes to files
```

## How it works

Two fix engines run in cascade:

1. **Deterministic fixers** -- pattern-based transformations for well-defined issues (unused imports, bare excepts, mutable defaults, etc.). These are reliable and fast.
2. **LLM-assisted fixes** -- for complex issues that need context understanding. Requires `--deep` and an API key.

## Safety checks

Before applying any fix:

- **Syntax validation** -- the fixed code is parsed to confirm it's syntactically valid
- **Scope preservation** -- fixes don't introduce new names or remove used references
- **Rollback** -- if a fix breaks syntax, it's reverted and reported

## Example

```bash
$ doji fix src/auth.py

src/auth.py:3  unused-import
  - import os
  (remove unused import)

src/auth.py:15  mutable-default
  - def process(items=[]):
  + def process(items=None):
  +     if items is None:
  +         items = []

2 fixes available. Run with --apply to apply.
```

## Filtering

```bash
doji fix . --rules unused-import,mutable-default   # Only fix specific rules
doji fix . --min-severity warning                   # Skip INFO-level fixes
```

!!! note
    Always review LLM-generated fixes before committing. They may change behavior in subtle ways.
