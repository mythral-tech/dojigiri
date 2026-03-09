# Case 16: SQL Injection via Struct Method

**CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

## Vulnerability

User-controlled `req.Query` from the HTTP request body flows into `repo.Search(req.Query)` in the handler, which calls `fmt.Sprintf` to build a raw SQL query in `repository.go`. An attacker sends:

```json
{"query": "' OR 1=1 --"}
```

This dumps all users from the database.

## Why Semgrep Misses It

This is **documented Semgrep bug #10358**. Semgrep's Go taint analysis loses track of tainted data when it flows through struct method calls. The taint enters at `json.NewDecoder(r.Body).Decode(&req)` in `handler.go`, passes through `repo.Search(req.Query)` — a method on `*UserRepository` — and reaches the `fmt.Sprintf` + `db.Query` sink in `repository.go`.

Semgrep's inter-procedural analysis for Go does not follow taint through method receivers. It tracks function calls but treats method calls on struct instances as opaque boundaries. The `Search` method's `term` parameter is never connected back to the tainted `req.Query` argument.

## Detection Requirements

- Cross-file taint tracking through struct method calls
- Connecting method parameters to call-site arguments across receiver boundaries
- `fmt.Sprintf` → `db.Query` recognized as SQL injection pattern
