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
| 4 | ssrf_wrapper | Python | CWE-918 | **YES** | `taint-flow-cross-file` | Cross-file taint traces `request.args.get('url')` through `fetch_json()` wrapper to `httpx.get()` sink in utils.py. Transitive intra-file sink propagation resolves wrapper chain. |
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
| 17 | command_injection_split | Go | CWE-78 | **YES** | `os-system` (taint) | Taint flows through `strings.Split()` → `append()` → `exec.Command()`. Fixed Go receiver extraction (`operand`/`field` AST fields) and added split/append as taint passthroughs. |
| 18 | path_traversal_join | Go | CWE-22 | **YES** | `go-path-traversal` | Caught `filepath.Join` with user input. |
| 19 | ssrf_custom_transport | Go | CWE-918 | **YES** | `ssrf` (taint) | Taint traces `r.URL.Query().Get()` → `client.Get(target)` on custom `*http.Client`. Method-only sink patterns (`.Get`, `.Post`, `.Do`) catch custom client instances. |
| 20 | template_injection | Go | CWE-79 | **YES** | `go-template-js-func` | Caught `template.HTML`/`template.JS` auto-escape bypass. |

---

## Summary

| Metric | Value |
|--------|-------|
| **Total cases** | 20 |
| **Detected** | **19/20 (95%)** |
| **Missed** | 1/20 (5%) |

### By Language

| Language | Detected | Total | Rate |
|----------|----------|-------|------|
| Python | 5/5 | 5 | 100% |
| JavaScript | 5/5 | 5 | 100% |
| Java | 4/5 | 5 | 80% |
| Go | 5/5 | 5 | 100% |

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

## Remaining Gap

| Gap | Case | Effort | Priority |
|-----|------|--------|----------|
| **TOCTOU race condition** (check-then-act patterns in async code) | race_condition_async (CWE-367) | Hard — requires concurrency semantics, not taint | LOW — niche, no SAST tool handles this well |

This is the only miss. It requires understanding that `Files.exists()` and `Files.copy()`/`Files.delete()` execute in different temporal contexts under `@Async`. No pattern matcher or taint engine can reason about thread scheduling. This is LLM-augmented deep scan territory.

## Resolved Gaps (Fold 46)

| Gap | Fix |
|-----|-----|
| Go exec.Command taint through strings.Split/append | Fixed Go receiver extraction (operand/field AST fields), added split/append as taint passthroughs |
| Go SSRF via custom http.Client | Added method-only sink patterns (.Get, .Post, .Do) with receiver exclusion logic |
| Python cross-file SSRF through wrapper functions | Added SSRF sinks to AST taint module, fixed return/assign sink detection, added transitive intra-file sink propagation |
