# Case 18: Path Traversal via filepath.Join

**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

## Vulnerability

User-controlled `filename` from the query string is joined with a base directory using `filepath.Join(uploadsDir, filename)`. An attacker requests:

```
/download?name=../../../etc/passwd
```

`filepath.Join` resolves the path to `/etc/passwd` — it cleans the path components but does not enforce that the result stays within `uploadsDir`. The file is then opened and streamed to the attacker.

## Why Semgrep Misses It

Semgrep's Go path traversal rules treat `filepath.Join` as a **sanitizer**. The reasoning is that `filepath.Join` calls `filepath.Clean` internally, which resolves `.` and `..` components. But cleaning a path is not the same as constraining it — `filepath.Join("/var/app/uploads", "../../../etc/passwd")` produces a clean, absolute path that escapes the intended directory.

Rules that look for `os.Open(userInput)` will miss this because `safePath` (the variable passed to `os.Open`) was "sanitized" by `filepath.Join`. The variable name even reinforces the false assumption.

## Detection Requirements

- `filepath.Join` must NOT be treated as a path traversal sanitizer
- Taint tracking from query parameters through `filepath.Join` to filesystem sinks
- Detection that no directory boundary check (e.g., `strings.HasPrefix` after cleaning) exists between join and open
