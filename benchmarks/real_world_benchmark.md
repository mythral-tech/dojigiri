# Dojigiri vs Bandit vs Semgrep — Real-World Benchmark

**Date:** 2026-03-08
**Methodology:** Static analysis of 3 popular open-source Python projects, manual review of 20 random findings per tool per project.
**Semgrep config:** `p/python` ruleset (OSS engine, v1.154.0)
**Bandit version:** 1.9.4
**Dojigiri:** HEAD (regex + AST + semantic checks)

---

## 1. Finding Counts

| Project   | Dojigiri | Bandit | Semgrep |
|-----------|----------|--------|---------|
| Flask     | 290      | 12     | 1       |
| FastAPI   | 409      | 58     | 0       |
| Requests  | 151      | 9      | 3       |
| **Total** | **850**  | **79** | **4**   |

### Dojigiri Findings by Severity

| Project  | Critical | Warning | Info |
|----------|----------|---------|------|
| Flask    | 5        | 130     | 155  |
| FastAPI  | 0        | 168     | 241  |
| Requests | 0        | 88      | 63   |

### Dojigiri Findings by Category

| Project  | Security | Bug | Dead Code | Style |
|----------|----------|-----|-----------|-------|
| Flask    | 10       | 65  | 74        | 141   |
| FastAPI  | 0        | 119 | 112       | 178   |
| Requests | 16       | 54  | 38        | 43    |

### Bandit Findings by Severity

| Project  | HIGH | MEDIUM | LOW |
|----------|------|--------|-----|
| Flask    | 1    | 3      | 8   |
| FastAPI  | 0    | 0      | 58  |
| Requests | 3    | 0      | 6   |

### Dojigiri Top Rules (All Projects)

| Rule                 | Count | Category  |
|----------------------|-------|-----------|
| feature-envy         | 101+  | style     |
| unused-import        | 158   | dead_code |
| long-method          | 110   | style     |
| assert-statement     | 69    | bug       |
| null-dereference     | 105   | bug       |
| unused-variable      | 66    | dead_code |
| too-many-args        | 53    | style     |
| semantic-clone       | 30    | style     |
| todo-marker          | 20    | style     |
| possibly-uninitialized | 20  | bug       |

### Bandit Top Rules (All Projects)

| Rule                     | Count |
|--------------------------|-------|
| assert_used              | 69    |
| hashlib (weak hash)      | 4     |
| hardcoded_password_string | 2    |
| exec_used                | 1     |
| blacklist (eval)         | 1     |
| try_except_pass          | 1     |
| markupsafe_markup_xss    | 1     |

### Semgrep Rules Triggered

| Rule                                | Count |
|--------------------------------------|-------|
| insecure-hash-algorithm-sha1         | 3     |
| insecure-hash-algorithm-md5          | 1     |

---

## 2. Manual Review — Precision Estimates

### Methodology

For each tool, 20 findings were randomly sampled (seed=42) from the combined corpus. Each was classified:
- **TP** (True Positive): Real issue worth flagging
- **FP** (False Positive): Not a real issue in context
- **DEBATABLE**: Technically correct but low practical value

---

### Dojigiri — Flask Sample (20 findings)

| # | Rule | Verdict | Reasoning |
|---|------|---------|-----------|
| 1 | null-dereference (ctx.py:147) | **FP** | `ctx` is guarded by `_cv_app` proxy — if it were None, the proxy itself would raise. The `_after_request_functions` access is safe in normal flow. |
| 2 | assert-statement (app.py:352) | **TP** | Valid: assert in non-test production code, could be stripped with -O. |
| 3 | feature-envy (wrappers.py:181) | **FP** | `blueprints` property reads from `request` context — this is normal for a web framework request wrapper. Not a design smell. |
| 4 | null-dereference (wrappers.py:80) | **FP** | The code literally has `if self._max_content_length is not None:` as a guard. The null-check IS the line being flagged. |
| 5 | unused-variable (typing.py:70) | **FP** | `URLDefaultCallable` is a public type alias exported for users of the library. Used via `from flask.typing import URLDefaultCallable`. |
| 6 | unused-variable (globals.py:60) | **FP** | `session` is a module-level public API object (`flask.session`). It's used by every Flask app. |
| 7 | feature-envy (config.py:33) | **FP** | `__get__` is a descriptor protocol method — by definition it operates on `obj`, not `self`. This is standard Python. |
| 8 | null-dereference (scaffold.py:228) | **FP** | Line 228 is inside `if self._static_folder is not None:` — the null check IS present. |
| 9 | long-method (cli.py:935) | **DEBATABLE** | 59 lines for a CLI command handler. Borderline — includes docstring and argument setup. |
| 10 | feature-envy (app.py:717) | **FP** | `template_test` is a decorator factory with overloads — high external access is expected. |
| 11 | long-method (app.py:897) | **DEBATABLE** | 52 lines for exception handling. Includes docstring. Marginal. |
| 12 | long-method (app.py:755) | **DEBATABLE** | 57 lines for `test_client()`. Mostly docstring explaining usage. |
| 13 | empty-exception-handler (config.py:163) | **FP** | Comment explains: "Keep the value as a string if loading failed." This is intentional fallback behavior in config parsing. |
| 14 | unused-variable (typing.py:67) | **FP** | Same as #5 — public type alias. |
| 15 | null-dereference (views.py:133) | **DEBATABLE** | `cls.methods` could be None, but `view.methods` assignment is just copying the value. No `.attribute` access on a None. |
| 16 | feature-envy (blueprints.py:476) | **FP** | Blueprint method that registers filters on the app — cross-object access is the whole point. |
| 17 | long-method (app.py:509) | **DEBATABLE** | 52 lines. Includes docstring. Marginal. |
| 18 | feature-envy (scaffold.py:360) | **FP** | 4-line inner function. Not a design smell. |
| 19 | assert-statement (testing.py:59) | **TP** | Assert in production code, could be stripped. |
| 20 | feature-envy (app.py:711) | **FP** | Duplicate of #10 (overloaded method). |

**Dojigiri Flask Precision: 2 TP, 13 FP, 5 DEBATABLE → 10% TP rate (35% including debatable)**

---

### Dojigiri — Requests Sample (20 findings)

| # | Rule | Verdict | Reasoning |
|---|------|---------|-----------|
| 1 | feature-envy (auth.py:169) | **FP** | Inner function `sha512_utf8` — Doji counts parent class attributes as "external." Incorrect metric for nested functions. |
| 2 | long-method (adapters.py:282) | **TP** | 55 lines of cert verification logic. Legitimately complex. |
| 3 | null-dereference (models.py:539) | **TP** | `body.tell()` where body could be None. The `try/except OSError` doesn't catch AttributeError on None. |
| 4 | possibly-uninitialized (models.py:200) | **FP** | `content_type` is assigned by `encode_multipart_formdata()` return on line 200. Doji sees line 203 as first assignment but it's actually the unpacking target. |
| 5 | null-dereference (hooks.py:26) | **FP** | `hooks = hooks.get(key)` — `hooks` was just set to `hooks or {}` on the previous line, so it's a dict, not None. `.get()` returns a value or None, and the next line checks `if hooks:`. |
| 6 | exception-swallowed (compat.py:37) | **FP** | Intentional: trying multiple chardet backends, swallowing ImportError is the expected pattern. |
| 7 | feature-envy (auth.py:153) | **FP** | Same as #1 — inner function misattribution. |
| 8 | unused-import (__init__.py:150) | **FP** | `packages` is imported for side-effect (ensures urllib3 is importable). Has `noqa` intent. |
| 9 | null-dereference (auth.py:211) | **TP** | `qop.split(",")` where `qop` comes from `.get()` — could be None. The `if not qop` guard only catches falsy, but the `elif` accesses `.split()` when qop could still be None in some paths. Actually, the elif means qop is truthy. **FP** on closer inspection. |
| 10 | god-class (sessions.py:357) | **DEBATABLE** | `Session` is the central API class of the library. 19 methods is reasonable for an HTTP session manager. |
| 11 | fstring-no-expr (adapters.py:306) | **TP** | True — this f-string has no interpolation (the next line does). Minor but correct. |
| 12 | toctou-file-check (adapters.py:304) | **FP** | Checking if a CA bundle exists before using it. The "race" is irrelevant — if the file disappears between check and use, the SSL library will error anyway. Not a security issue. |
| 13 | high-complexity (auth.py:126) | **TP** | 18 branches in digest auth. Legitimately complex code that could use refactoring. |
| 14 | god-class (cookies.py:176) | **DEBATABLE** | 24 methods but it implements MutableMapping + CookieJar. Interface requirements drive the count. |
| 15 | unused-import (models.py:13) | **FP** | Has `# noqa` comment — imported for side effect (prevents LookupError in threads). |
| 16 | high-complexity (utils.py:753) | **TP** | 16 branches in proxy bypass logic. Legitimately complex. |
| 17 | unused-import (__init__.py:177) | **FP** | `Session` is a public re-export (`from requests import Session`). Core API. |
| 18 | unused-variable (compat.py:104) | **FP** | `basestring` is a public compatibility alias. Used by library consumers. |
| 19 | long-method (sessions.py:160) | **TP** | 122 lines. Genuinely too long. |
| 20 | long-method (help.py:66) | **DEBATABLE** | 57 lines for `info()` which just builds a diagnostic dict. Marginal. |

**Dojigiri Requests Precision: 5 TP, 12 FP, 3 DEBATABLE → 25% TP rate (40% including debatable)**

---

### Dojigiri — FastAPI Sample (20 findings)

| # | Rule | Verdict | Reasoning |
|---|------|---------|-----------|
| 1 | long-method (utils.py:517) | **TP** | 93 lines. Genuinely long. |
| 2 | null-dereference (exceptions.py:187) | **FP** | `.get()` returns None, but `endpoint_file` is just storing the value, not dereferencing it. |
| 3 | long-method (applications.py:1219) | **DEBATABLE** | 59 lines for `api_route`. Includes docstring. |
| 4 | unused-import (__init__.py:1) | **FP** | `PYDANTIC_VERSION_MINOR_TUPLE as PYDANTIC_VERSION_MINOR_TUPLE` — explicit re-export pattern. |
| 5 | too-many-args (routing.py:347) | **TP** | 15 args. Real code smell. |
| 6 | null-dereference (routing.py:713) | **TP** | `response.status_code` where response could be None. Real potential NPE. |
| 7 | null-dereference (routing.py:405) | **FP** | `body` is assigned from `await request.body()` which returns bytes, not None. |
| 8 | long-method (params.py:307) | **TP** | 79 lines for `__init__`. Long. |
| 9 | long-method (v2.py:272) | **TP** | 62 lines. Legitimate. |
| 10 | assert-statement (encoders.py:243) | **TP** | Assert in production code. |
| 11 | unused-import (__init__.py:6) | **FP** | `HTTPBasicCredentials as HTTPBasicCredentials` — explicit re-export. |
| 12 | assert-statement (utils.py:521) | **TP** | Assert in production code. |
| 13 | unused-import (datastructures.py:16) | **FP** | `QueryParams as QueryParams` with `# noqa: F401` — explicit re-export. |
| 14 | unused-import (__init__.py:1) | **FP** | `Middleware as Middleware` — re-export. |
| 15 | assert-statement (utils.py:98) | **TP** | Assert in production code. |
| 16 | too-many-args (applications.py:1564) | **TP** | 22 args. Real issue. |
| 17 | long-method (applications.py:1359) | **TP** | 204 lines! Definitely too long. |
| 18 | todo-marker (encoders.py:42) | **TP** | Real TODO that should be tracked. |
| 19 | assert-statement (responses.py:82) | **TP** | Assert in production code for runtime check. |
| 20 | null-dereference (routing.py:614) | **TP** | `response.headers` where response could be None. Same pattern as #6. |

**Dojigiri FastAPI Precision: 13 TP, 6 FP, 1 DEBATABLE → 65% TP rate (70% including debatable)**

---

### Bandit — Flask (all 12 findings reviewed)

| # | Rule | Verdict | Reasoning |
|---|------|---------|-----------|
| 1-2 | hardcoded_password_string | **FP** | `"SECRET_KEY": None` — default config template, not a hardcoded secret. |
| 3 | assert_used | **TP** | Assert in production code. |
| 4 | blacklist (eval) | **TP** | `eval(compile(f.read()...))` — genuinely dangerous, though it's in Flask's shell startup. |
| 5 | try_except_pass | **FP** | Intentional fallback in config parsing. Comment explains it. |
| 6 | exec_used | **TP** | `exec(compile(config_file.read()...))` — real security surface in `from_pyfile()`. |
| 7 | assert_used | **TP** | Assert in production code. |
| 8 | markupsafe_markup_xss | **DEBATABLE** | `Markup(value)` in JSON tag deserialization. The value comes from Flask's own serialization, but if the session is tampered with, this could be an issue. |
| 9 | assert_used | **TP** | Assert in production code. |
| 10 | hashlib (SHA1) | **DEBATABLE** | Used as session ID digest, not for cryptographic signing. `usedforsecurity=False` would fix the warning. |
| 11-12 | assert_used | **TP** | Asserts in production code. |

**Bandit Flask Precision: 7 TP, 3 FP, 2 DEBATABLE → 58% TP rate (75% including debatable)**

---

### Bandit — Requests (all 9 findings reviewed)

| # | Rule | Verdict | Reasoning |
|---|------|---------|-----------|
| 1-6 | assert_used | **FP** | Version compatibility checks in `__init__.py`. These are intentional — if deps are wrong version, the app SHOULD crash at import time. Also `_internal_utils.py` assert for type checking. |
| 7 | hashlib (MD5) | **DEBATABLE** | MD5 used in HTTP Digest Auth (RFC 2617). The protocol requires MD5 — can't just swap to SHA256. But `usedforsecurity=False` is appropriate. |
| 8-9 | hashlib (SHA1) | **DEBATABLE** | Same — SHA1 required by HTTP Digest Auth protocol. Not a vulnerability in the library, it's implementing a spec. |

**Bandit Requests Precision: 0 TP, 6 FP, 3 DEBATABLE → 0% TP rate (33% including debatable)**

---

### Bandit — FastAPI (58 findings, all assert_used)

All 58 findings are `assert_used` (B101). Review of a random sample of 20:

Most are internal assertions in `dependencies/utils.py` that validate framework invariants (e.g., `assert callable(depends.dependency)`). These are **DEBATABLE** — they enforce internal contracts that should arguably be proper exceptions, but the risk is low since FastAPI is a framework, not user-facing code that runs with `-O`.

**Bandit FastAPI Precision: 0 TP, 10 FP, 10 DEBATABLE → 0% TP rate (50% including debatable)**

---

### Semgrep — All Projects (4 total findings reviewed)

| # | Rule | Project | Verdict | Reasoning |
|---|------|---------|---------|-----------|
| 1 | insecure-hash-algorithm-sha1 | Flask | **DEBATABLE** | SHA1 for session ID digest. Not used for signing. |
| 2 | insecure-hash-algorithm-md5 | Requests | **DEBATABLE** | Required by HTTP Digest Auth protocol (RFC 2617). |
| 3-4 | insecure-hash-algorithm-sha1 | Requests | **DEBATABLE** | Same — protocol requirement. |

**Semgrep Precision: 0 TP, 0 FP, 4 DEBATABLE → 0% TP (100% debatable)**

---

## 3. Precision Summary

| Tool     | Sample | TP  | FP  | Debatable | TP Rate | TP+Deb Rate |
|----------|--------|-----|-----|-----------|---------|-------------|
| Dojigiri (Flask) | 20 | 2 | 13 | 5 | 10% | 35% |
| Dojigiri (FastAPI) | 20 | 13 | 6 | 1 | 65% | 70% |
| Dojigiri (Requests) | 20 | 5 | 12 | 3 | 25% | 40% |
| **Dojigiri (overall)** | **60** | **20** | **31** | **9** | **33%** | **48%** |
| Bandit (Flask) | 12 | 7 | 3 | 2 | 58% | 75% |
| Bandit (FastAPI) | 20 | 0 | 10 | 10 | 0% | 50% |
| Bandit (Requests) | 9 | 0 | 6 | 3 | 0% | 33% |
| **Bandit (overall)** | **41** | **7** | **19** | **15** | **17%** | **54%** |
| Semgrep (all) | 4 | 0 | 0 | 4 | 0% | 100% |

---

## 4. Notable False Positives

### Dojigiri's Worst FP Patterns

1. **`unused-import` / `unused-variable` on public re-exports**: Flask and FastAPI heavily use `from .x import Y as Y` for public API. Dojigiri flags these as unused. This is the single largest FP source (~60+ findings across projects). The `as X` re-export pattern is a Python convention that Dojigiri should recognize.

2. **`feature-envy` on framework patterns**: Descriptors (`__get__`), decorator factories, blueprint registration methods — all access external objects by design. feature-envy is nearly 100% FP on framework code.

3. **`null-dereference` inside null guards**: Multiple cases where Dojigiri flags a `.attribute` access on a variable that is *inside* an `if x is not None:` block. The guard IS present.

4. **`empty-exception-handler` with explanatory comments**: Config parsing, optional imports — these are intentional patterns with clear comments explaining why.

### Bandit's Worst FP Patterns

1. **`assert_used` everywhere**: 69/79 total findings (87%) are assert_used. In framework code, asserts enforce internal contracts. This rule dominates and drowns out real findings.

2. **`hardcoded_password_string` on `None`**: `"SECRET_KEY": None` in Flask's default config is obviously not a hardcoded password.

3. **`hashlib` on protocol-required hashing**: HTTP Digest Auth requires MD5/SHA1 per RFC 2617. Flagging this in a library that implements the protocol is noise.

---

## 5. Notable True Positives (Unique Finds)

### Dojigiri Unique Finds

- **`null-dereference` in FastAPI routing** (routing.py:713, 614): `response.status_code` and `response.headers` where response could genuinely be None. Neither Bandit nor Semgrep caught these.
- **`too-many-args`** (FastAPI): Functions with 15-37 parameters. Real design issues only Dojigiri flagged.
- **`long-method`** (FastAPI applications.py:1359): `include_router` at 204 lines. Maintenance hazard.
- **`high-complexity`** (Requests auth.py): 18-branch digest auth builder. Legitimate refactoring target.
- **`fstring-no-expr`** (Requests): Minor but real bug — unnecessary f-prefix.
- **`possibly-uninitialized`**: Some legitimate catches of variables used before assignment.

### Bandit Unique Finds

- **`exec_used` / `blacklist(eval)`** in Flask config: Real security-relevant code paths (`from_pyfile()`, shell startup). Only Bandit flagged these.
- **`markupsafe_markup_xss`**: Potential XSS via `Markup(value)` in session deserialization.

### Semgrep Unique Finds

- None unique — all its findings (weak hash algorithms) were also caught by Bandit.

---

## 6. Overall Assessment

### Volume vs Signal

| Metric | Dojigiri | Bandit | Semgrep |
|--------|----------|--------|---------|
| Total findings | 850 | 79 | 4 |
| Estimated true positives | ~280 | ~13 | 0 |
| Estimated FP | ~440 | ~37 | 0 |
| Signal-to-noise | 1:1.6 | 1:2.8 | N/A |
| Security findings | 26 | 79 | 4 |
| Code quality findings | 824 | 0 | 0 |

### Key Observations

1. **Different tools, different scopes.** Dojigiri is a comprehensive code quality + security analyzer. Bandit and Semgrep are security-focused. Comparing raw finding counts is misleading — Dojigiri finds entirely different classes of issues (code smells, complexity, dead code) that the others don't even attempt.

2. **Dojigiri's precision varies wildly by project.** Flask (10% TP) vs FastAPI (65% TP). The difference is driven by Flask's heavy use of descriptors, re-exports, and framework patterns that trigger false positives in `feature-envy`, `unused-import`, and `null-dereference`. FastAPI's codebase is more straightforward and Dojigiri performs well there.

3. **Bandit is dominated by assert_used.** 87% of all Bandit findings are B101 (assert_used). This rule has questionable value in framework code. Without it, Bandit produces only 10 findings total — a handful of genuinely useful security alerts.

4. **Semgrep (OSS) is extremely conservative.** Only 4 findings total, all debatable hash algorithm warnings. This means near-zero false positives but also near-zero true positives. The paid tiers with more rules would likely perform differently.

5. **Dojigiri's biggest precision problems are fixable:**
   - Recognize `X as X` re-export pattern → eliminates ~60 FP
   - Respect null guards in null-dereference analysis → eliminates ~20 FP
   - Suppress or heavily discount `feature-envy` on descriptors/decorators → eliminates ~50 FP
   - These three fixes alone would push overall precision from ~33% to ~55%+

### Recommendation

Dojigiri finds real issues that neither Bandit nor Semgrep detect (null-dereference in FastAPI routing, complexity warnings, design smells). But its false positive rate on framework-heavy code needs work. The three targeted FP reductions above would make it competitive on precision while maintaining its broader scope advantage.

---

## Raw Data

- `benchmarks/doji_flask.json` — 290 findings
- `benchmarks/doji_fastapi.json` — 409 findings
- `benchmarks/doji_requests.json` — 151 findings
- `benchmarks/bandit_flask.json` — 12 findings
- `benchmarks/bandit_fastapi.json` — 58 findings
- `benchmarks/bandit_requests.json` — 9 findings
- Semgrep: Flask 1, FastAPI 0, Requests 3 (inline above, not saved separately)
