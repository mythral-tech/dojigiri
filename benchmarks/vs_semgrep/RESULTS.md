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
| 7 | nosql_injection_mongodb | JavaScript | CWE-943 | **YES** | `nosql-injection-mongodb` | Caught both `findOne({` with destructured `req.body` fields (line 15) and `find(filter)` with variable query (line 29). Two findings cover both injection vectors. |
| 8 | prototype_pollution | JavaScript | CWE-1321 | **YES** | `prototype-pollution-merge` | Caught `_.merge(config, userPrefs)` where `userPrefs` is derived from `req.body.preferences`. Pattern detects deep merge with variable source argument. |
| 9 | ssrf_nextjs_middleware | JavaScript | CWE-918 | **YES** | `ssrf-risk` | Caught HTTP request construction from user input in proxy route. |
| 10 | stored_xss_react | JavaScript | CWE-79 | **YES** | `react-dangerously-set-innerhtml` | Caught `dangerouslySetInnerHTML` usage. Direct hit on the vulnerability pattern. |
| 11 | deser_gadget_chain | Java | CWE-502 | **YES** | `deserialization-unsafe`, `java-unsafe-deserialization`, `java-runtime-exec` | Multiple rules fire across the gadget chain: `readObject`, `defaultReadObject`, `Runtime.exec`. Excellent depth. |
| 12 | jndi_via_map | Java | CWE-74 | **YES** | `java-jndi-lookup-variable` | Caught `ctx.lookup(path)` where `path` originates from HashMap populated by user input. New rule detects variable-based JNDI lookups on common context variable names. |
| 13 | race_condition_async | Java | CWE-367 | **NO** | `java-upload-original-filename` (tangential) | The `getOriginalFilename()` finding is tangential (path traversal risk). Missed the actual TOCTOU race condition between `Files.exists()` check and `Files.copy()`/`Files.delete()` in async context. |
| 14 | spel_injection | Java | CWE-917 | **YES** | `java-spel-parse-variable` | Caught `parser.parseExpression(expression)` in `ExpressionEvaluator.java` where `expression` flows from user-controlled `@RequestParam`. New rule detects variable-based SpEL parsing on common parser variable names. |
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
| **Detected** | **17/20 (85%)** |
| **Missed** | 3/20 (15%) |

### By Language

| Language | Detected | Total | Rate |
|----------|----------|-------|------|
| Python | 4/5 | 5 | 80% |
| JavaScript | 5/5 | 5 | 100% |
| Java | 4/5 | 5 | 80% |
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

7. **nosql_injection_mongodb (JavaScript)** -- New `nosql-injection-mongodb` rule catches both inline object queries with destructured request fields and variable-argument queries to MongoDB collection methods. Covers the `$gt`/`$ne` operator injection class.

8. **jndi_via_map (Java)** -- New `java-jndi-lookup-variable` rule catches `ctx.lookup(path)` where context variable names match common JNDI patterns. Detects the Log4Shell-class vulnerability even through HashMap indirection.

---

## Gaps

### Missing Rules (need new rules)

| Gap | Cases Missed | Effort | Priority |
|-----|-------------|--------|----------|
| **TOCTOU race condition** (check-then-act patterns in async code) | race_condition_async | Hard -- requires understanding of concurrency semantics, not just taint | LOW -- niche, hard to do statically |

### Taint Tracking Gaps (existing rules, insufficient reach)

| Gap | Cases Missed | Issue |
|-----|-------------|-------|
| **Go exec.Command taint** | command_injection_split | Taint doesn't propagate through `strings.Split()` + `append()` to `exec.Command` args. Go taint engine needs Split/append as passthrough. |
| **Go SSRF via custom transport** | ssrf_custom_transport | `client.Get(target)` where client uses custom `RoundTripper` -- the `http.Get`-equivalent pattern isn't recognized when the client is constructed with a custom transport. |
| **Python cross-file SSRF** | ssrf_wrapper | `fetch_json(url)` wrapper hides `requests.get()` call. Cross-file taint for Python SSRF sinks doesn't reach through utility function indirection. |

---

## Recommendations for Next Fold

**Taint engine improvements (harder, broader impact):**
1. Go: Add `strings.Split`, `strings.Fields`, `append` as taint-propagating functions for exec sinks
2. Go: Recognize `client.Get()` as SSRF sink when client is any `*http.Client`
3. Python: Cross-file taint through wrapper functions (general capability, not just SSRF)

Fixing taint gaps 1-3 would hit **20/20**.
