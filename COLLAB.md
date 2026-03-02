# Collaboration Board

## Status
**Last agent**: Claude
**Date**: 2026-03-02
**What they did**: Fixed parallel scanning thread safety (added Lock for cache dict) and corrected skipped file count (cache hits were incorrectly counted as skipped). Added is_error flag to _analyze_single_file return tuple.

## Review
*Nothing pending.*

## Queue
Priority order — pick from the top:

1. **Baseline/diff mode** (`--baseline latest`) — only show NEW findings since last scan. Essential for CI use.
2. **Config file** (`.wiz.toml`) — project-level severity overrides, ignored rules. Currently `--ignore` is ephemeral.
3. **Deep scan cache** — deep scan rescans everything, should respect file hash cache.
4. **Block comments** — handle `/* */`, `""" """`, `<!-- -->` (currently only line comments).
5. **SARIF output** — GitHub Code Scanning integration standard.

## Log
- **2026-03-02 [Claude]**: Initialized collaboration board. Current state: v0.2.1 with 120 tests passing. Oz built the test suite + parallel scanning + yaml regex fix + AST refactor. Claude reviewed and fixed thread safety + skipped count bug. All known bugs resolved. Queue reflects remaining items from HANDOFF.md.
