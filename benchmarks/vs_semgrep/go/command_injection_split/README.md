# Case 17: Command Injection via strings.Split Container Tracking

**CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

## Vulnerability

User-controlled query parameters `opts` and `file` flow into `exec.Command`. The `opts` value is split into parts via `strings.Split`, then spread into the command arguments with `args...`. An attacker sends:

```
/convert?opts=-o+/tmp/out&file=;id
```

The `filename` parameter is appended to the split parts and passed to the command. On some systems with shell interpretation, or by injecting flags that control output paths, this enables arbitrary file write or command execution.

## Why Semgrep Misses It

Semgrep's taint tracking for Go loses track of tainted values when they pass through container operations. The flow is:

1. `input` (tainted) → `strings.Split(input, " ")` → `parts` (slice)
2. `parts` (tainted slice) → `append(parts, filename)` → `args` (slice)
3. `args...` spread into `exec.Command`

Semgrep cannot propagate taint through `strings.Split` return values into slice elements, then through `append`, then through variadic spread (`args...`). Each container transformation step is a potential taint-loss point. The tool sees `exec.Command("convert", args...)` but cannot connect `args` back to `r.URL.Query().Get()`.

## Detection Requirements

- Taint propagation through `strings.Split` (input tainted → all output elements tainted)
- Taint propagation through `append` (any tainted element → result tainted)
- Variadic spread (`...`) recognized as expanding tainted elements into sink arguments
