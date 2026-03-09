# List Comprehension Breaks Taint Propagation

**CWE-89** | SQL Injection

## Vulnerability

User input from `request.args.getlist()` passes through a list comprehension (`[x.strip() for x in raw_ids]`). The resulting list is interpolated into a raw SQL query. Both endpoints are vulnerable to SQL injection despite the `.strip()` calls, which do nothing for sanitization.

## Why Semgrep Misses It

This is Semgrep bug [#10795](https://github.com/semgrep/semgrep/issues/10795). List comprehensions break Semgrep's taint propagation. When tainted data passes through `[expr for x in tainted_list]`, Semgrep loses track of the taint on the output list. The data flows `request.args` -> list comprehension -> string interpolation -> `execute()`, but Semgrep sees the comprehension output as clean.

Both `str.strip()` and `str.lower()` are not sanitizers, yet Semgrep never even reaches the sink analysis because taint is already lost at the comprehension boundary.

## Attack

```
GET /users?ids=1&ids=1) UNION SELECT password FROM credentials--
GET /tags?tag=x' OR '1'='1
```
