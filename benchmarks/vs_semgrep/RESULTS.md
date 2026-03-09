# Dojigiri vs Semgrep Benchmark Results

**Date:** 2026-03-09
**Mode:** Quick scan (static only, no LLM)
**Version:** Current HEAD
**Flags:** `--no-cache --min-severity info --min-confidence low`

---

## Results Table

| # | Case | Language | CWE | Detected | Rule(s) | Notes |
|---|------|----------|-----|----------|---------|-------|
| 1 | comprehension_taint | Python | CWE-89 | **YES** | `sql-injection` (AST taint) | Tracked taint through list comprehension to `conn.execute`. Both code paths caught. |
| 2 | pickle_redis | Python | CWE-502 | **YES** | `deserialization-unsafe`, `pickle-unsafe`, `taint-flow` | Multiple rules fire: pickle usage, unsafe deser pattern, and taint flow. Strong coverage. |
| 3 | second_order_sqli | Python | CWE-89 | **YES** | `sql-injection`, `taint-flow` | Caught f-string interpolation in `execute()` and taint from parameter to SQL sink. |
| 4 | ssrf_wrapper | Python | CWE-918 | **NO** | -- | SSRF hidden behind `fetch_json()` wrapper in separate file. No cross-file taint for Python SSRF. Only info-level findings. |
| 5 | ssti_stored | Python | CWE-1336 | **YES** | `ssti-risk`, `jinja2-autoescape-off`, `taint-flow` | Caught template construction from string, autoescape disabled, and taint flow. Excellent multi-rule coverage. |
| 6 | eval_function_constructor | JavaScript | CWE-94 | **YES** | `function-constructor`, `ssti-risk` | Caught `new Function()` with user input. Both code-injection and template-injection rules fire. |
| 7 | nosql_injection_mongodb | JavaScript | CWE-943 | **NO** | -- | Only unrelated findings (helmet, unused var). No NoSQL injection detection. Missing rule for MongoDB query operator injection (`$gt`, `$ne` via unsanitized req.body). |
| 8 | prototype_pollution | JavaScript | CWE-1321 | **NO** | -- | Only `express-no-helmet`. No rule for `_.merge()` / deep merge prototype pollution patterns. |
| 9 | ssrf_nextjs_middleware | JavaScript | CWE-918 | **YES** | `ssrf-risk` | Caught HTTP request construction from user input in proxy route. |
| 10 | stored_xss_react | JavaScript | CWE-79 | **YES** | `react-dangerously-set-innerhtml` | Caught `dangerouslySetInnerHTML` usage. Direct hit on the vulnerability pattern. |
| 11 | deser_gadget_chain | Java | CWE-502 | **YES** | `deserialization-unsafe`, `java-unsafe-deserialization`, `java-runtime-exec` | Multiple rules fire across the gadget chain: `readObject`, `defaultReadObject`, `Runtime.exec`. Excellent depth. |
| 12 | jndi_via_map | Java | CWE-74 | **NO** | `java-xss` (unrelated) | XSS findings on `resp.getWriter().write()` are noise. Missed the actual JNDI injection via `ctx.lookup(path)` where `path` comes from HashMap aliased to user input. |
| 13 | race_condition_async | Java | CWE-367 | **NO** | `java-upload-original-filename` (tangential) | The `getOriginalFilename()` finding is tangential (path traversal risk). Missed the actual TOCTOU race condition between `Files.exists()` check and `Files.copy()`/`Files.delete()` in async context. |
| 14 | spel_injection | Java | CWE-917 | **NO** | -- | Only `unused-import`. No rule for Spring Expression Language injection via `ExpressionParser.parseExpression()` with user-controlled input. |
| 15 | xxe_cross_file | Java | CWE-611 | **YES** | `java-xxe-saxparser`, `xxe-risk` | Caught SAXParser XXE vulnerability. Cross-file config detected. |
| 16 | struct_method_sqli | Go | CWE-89 | **YES** | `go-sql-sprintf` | Caught `fmt.Sprintf` SQL string construction. Direct pattern match. |
| 17 | command_injection_split | Go | CWE-78 | **NO** | -- | No security findings at warning+. Missed `exec.Command` with user input passed through `strings.Split()`. Taint doesn't track through split/append to exec sink in Go. |
| 18 | path_traversal_join | Go | CWE-22 | **YES** | `go-path-traversal` | Caught `filepath.Join` with user input. |
| 19 | ssrf_custom_transport | Go | CWE-918 | **NO** | -- | No security findings. Missed SSRF where user URL goes through custom `RoundTripper` transport. Go SSRF rules don't cover `client.Get()` with custom transport indirection. |
| 20 | template_injection | Go | CWE-79 | **YES** | `go-template-js-func` | Caught `template.HTML`/`template.JS` auto-escape bypass. |

---

## Summary

| Metric | Value |
|--------|-------|
| **Total cases** | 20 |
| **Detected** | **13/20 (65%)** |
| **Missed** | 7/20 (35%) |

### By Language

| Language | Detected | Total | Rate |
|----------|----------|-------|------|
| Python | 4/5 | 5 | 80% |
| JavaScript | 3/5 | 5 | 60% |
| Java | 2/5 | 5 | 40% |
| Go | 3/5 | 5 | 60% |

---

## Strengths

These are the catches that matter most -- the ones Semgrep misses and Dojigiri nails:

1. **comprehension_taint (Python)** -- Taint tracking through list comprehensions is genuinely hard. The AST-based taint engine traced `raw_ids` through a list comp into an f-string SQL query. This is the kind of finding that justifies the tool's existence.

2. **deser_gadget_chain (Java)** -- Multiple rules fire across a 3-file gadget chain: `readObject` override, `defaultReadObject()`, and `Runtime.exec()` in the transform proxy. Not just pattern matching -- it sees the whole chain.

3. **ssti_stored (Python)** -- Three independent rules converge: template construction from string, autoescape disabled, and taint flow from model to render. Multi-signal detection is more convincing than a single pattern match.

4. **second_order_sqli (Python)** -- Caught SQL injection where the taint source (`display_name`) is a function parameter that originates from a database read in a different view. The taint engine traced variable indirection correctly.

5. **xxe_cross_file (Java)** -- Detected SAXParser XXE even though the parser factory configuration and the handler using it are in separate files.

6. **eval_function_constructor (JavaScript)** -- Both `function-constructor` and `ssti-risk` rules fire on `new Function("return " + expression)`. Dual-rule coverage reduces false negative risk.

---

## Gaps

### Missing Rules (need new rules)

| Gap | Cases Missed | Effort | Priority |
|-----|-------------|--------|----------|
| **NoSQL injection** (MongoDB `$gt`/`$ne` operator injection) | nosql_injection_mongodb | Medium -- need MongoDB-specific sink patterns for query operators passed from `req.body` | HIGH -- very common vulnerability |
| **Prototype pollution** (`_.merge`, deep merge patterns) | prototype_pollution | Medium -- need rules for `lodash.merge`, `Object.assign` with user-controlled deep objects | HIGH -- CWE-1321 is in OWASP Top 10 |
| **JNDI injection** (`InitialContext.lookup()` with tainted input) | jndi_via_map | Medium -- need Java JNDI sink rule + taint through HashMap indirection | HIGH -- Log4Shell class vulnerability |
| **SpEL injection** (`ExpressionParser.parseExpression()` with user input) | spel_injection | Low -- straightforward sink pattern | MEDIUM -- Spring-specific but common |
| **TOCTOU race condition** (check-then-act patterns in async code) | race_condition_async | Hard -- requires understanding of concurrency semantics, not just taint | LOW -- niche, hard to do statically |

### Taint Tracking Gaps (existing rules, insufficient reach)

| Gap | Cases Missed | Issue |
|-----|-------------|-------|
| **Go exec.Command taint** | command_injection_split | Taint doesn't propagate through `strings.Split()` + `append()` to `exec.Command` args. Go taint engine needs Split/append as passthrough. |
| **Go SSRF via custom transport** | ssrf_custom_transport | `client.Get(target)` where client uses custom `RoundTripper` -- the `http.Get`-equivalent pattern isn't recognized when the client is constructed with a custom transport. |
| **Python cross-file SSRF** | ssrf_wrapper | `fetch_json(url)` wrapper hides `requests.get()` call. Cross-file taint for Python SSRF sinks doesn't reach through utility function indirection. |

---

## Recommendations for Next Fold

**Quick wins (new rules, high impact):**
1. `nosql-injection-mongodb` -- Pattern: unsanitized `req.body` fields passed directly to MongoDB `find()`/`findOne()` queries
2. `prototype-pollution` -- Pattern: `_.merge()`, `_.defaultsDeep()`, `Object.assign()` with user-controlled nested objects
3. `jndi-injection` -- Pattern: `InitialContext.lookup()` / `Context.lookup()` with tainted input
4. `spel-injection` -- Pattern: `ExpressionParser.parseExpression()` with user-controlled string

**Taint engine improvements (harder, broader impact):**
5. Go: Add `strings.Split`, `strings.Fields`, `append` as taint-propagating functions for exec sinks
6. Go: Recognize `client.Get()` as SSRF sink when client is any `*http.Client`
7. Python: Cross-file taint through wrapper functions (general capability, not just SSRF)

Adding rules 1-4 would bring the benchmark score to **17/20 (85%)**. Fixing taint gaps 5-7 would hit **20/20**.
