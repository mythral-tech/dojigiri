# +44.2% Youden: How Taint Analysis and LLM Augmentation Beat Pattern Matching on the OWASP Benchmark

*March 2026 — Stephane Perez*

---

Most static analysis tools are pattern matchers. They look for known-bad code shapes — `eval(user_input)`, `"SELECT * FROM users WHERE id=" + id` — and flag them. This works surprisingly well for the easy cases, and completely falls apart for the hard ones.

Cross-file taint propagation. Container aliasing where tainted data enters a map, gets extracted three methods later under a different key, and hits a SQL sink. Second-order attacks where user input is stored in a database, retrieved by a different handler, and rendered unescaped. These aren't edge cases. They are the majority of real-world injection vulnerabilities, and pattern matching is structurally blind to them.

We built Dojigiri to address this gap. It combines tree-sitter-based semantic analysis, path-sensitive taint tracking with fixed-point dataflow iteration, and an optional LLM augmentation layer for context-aware deep scanning. We ran it against the OWASP Benchmark v1.2 — the standard test suite for SAST tool evaluation — and scored a **+44.2% Youden J-statistic** across all 11 vulnerability categories.

This post breaks down the methodology, the results, and how the architecture makes those results possible.

## What Is the OWASP Benchmark?

The [OWASP Benchmark](https://owasp.org/www-project-benchmark/) is a purpose-built Java web application containing 2,740 test cases across 11 CWE categories: SQL injection, command injection, cross-site scripting, path traversal, LDAP injection, XPath injection, weak cryptography, weak hashing, weak randomness, trust boundary violations, and insecure cookies.

Each test case is a self-contained Java servlet that either contains a real vulnerability (true positive) or is a safe implementation designed to look vulnerable (false positive trap). The ground truth is published alongside the code. There is no ambiguity — every test case has a known correct answer.

### Why Youden and Not Just Detection Rate

Raw detection rate (true positive rate, TPR) is meaningless without false positive rate (FPR). A tool that flags everything achieves 100% TPR and 100% FPR — it catches every vulnerability but also every non-vulnerability. It tells you nothing.

The **Youden J-statistic** (J = TPR - FPR) measures the distance above the random-guess diagonal. A score of 0% means the tool is no better than a coin flip. A score of +100% means perfect detection with zero false positives. Negative scores mean the tool is actively misleading — it is more likely to flag safe code than vulnerable code.

This is the metric the OWASP Benchmark project itself uses to rank tools. It penalizes both missed vulnerabilities and false alarms, which is exactly what matters in practice.

## Test Setup

- **Tool:** Dojigiri v1.1.0, quick-scan mode (regex + semantic analysis + taint analysis, no LLM layer)
- **Benchmark:** OWASP Benchmark v1.2 (2,740 test cases, 11 CWE categories)
- **Configuration:** Default rules, no benchmark-specific tuning. General-purpose sanitizer detection via ESAPI, Spring Security, and Apache Commons patterns.
- **Taint gating:** For injection categories (CWE-22, 78, 89, 90, 501, 643) where regex alone produces near-100% FPR, findings are only reported when taint analysis confirms a source-to-sink data flow.
- **Scoring:** OWASP standard macro-average (average of per-category Youden scores)

The "general-only" score is the important one. We also have a tuned configuration that scores higher, but the general score represents what you get out of the box with no benchmark-specific optimization. That is what matters for real-world use.

## Results

### Overall

| Metric | Score |
|--------|-------|
| **Youden J-statistic** | **+44.2%** |
| True Positive Rate (TPR) | 72.7% |
| False Positive Rate (FPR) | 28.5% |

### Per-Category Breakdown

| Category | CWE | TPR | FPR | Youden |
|----------|-----|-----|-----|--------|
| Weak Cryptography | 327 | 100.0% | 0.0% | **+100.0%** |
| Weak Randomness | 330 | 100.0% | 0.0% | **+100.0%** |
| Insecure Cookie | 614 | 100.0% | 0.0% | **+100.0%** |
| Weak Hashing | 328 | 100.0% | 30.8% | +69.2% |
| Cross-Site Scripting | 79 | 100.0% | 70.3% | +29.7% |
| XPath Injection | 643 | 93.3% | 65.0% | +28.3% |
| Path Traversal | 22 | 83.5% | 68.1% | +15.3% |
| Trust Boundary | 501 | 38.6% | 23.3% | +15.3% |
| LDAP Injection | 90 | 44.4% | 31.2% | +13.2% |
| SQL Injection | 89 | 33.5% | 24.6% | +8.9% |
| Command Injection | 78 | 6.3% | 0.0% | +6.3% |

Every category scores above the random-guess line (Youden > 0). No category drags the score negative.

### Comparison Context

The OWASP Benchmark project publishes [historical results](https://rawgit.com/nicerapp/OWASP-Benchmark-scorecard/master/index.html) for commercial and open-source tools. Most tools cluster between 0% and +30% Youden.

A 2024 academic study from Brunel University ([EASE 2024](https://dl.acm.org/doi/fullHtml/10.1145/3661167.3661262)) evaluated Semgrep Community Edition against the OWASP Benchmark and found an out-of-the-box Youden of **15.9%**. With extensive custom rule tuning ("Semgrep*"), they achieved 44.7% — but that required significant manual effort to build benchmark-aware rules.

Dojigiri's +44.2% is achieved with **default configuration** — no custom rules, no benchmark-specific tuning.

Doyensec's 2022 comparison found CodeQL completely missed 3 CWE categories and achieved roughly 20% detection on SQL injection in certain test configurations. Build-dependent tools like CodeQL also have a structural disadvantage: if the project doesn't compile, the tool can't run.

### Where We're Weak

Transparency matters more than flattering numbers.

**Command Injection (CWE-78): +6.3% Youden.** The OWASP Benchmark uses `Runtime.exec()` patterns that Dojigiri's current taint model doesn't fully trace through the Java runtime API chain. TPR is 6.3% with 0% FPR — almost no findings at all, but the ones it does report are correct.

**SQL Injection (CWE-89): +8.9% Youden.** Java SQL injection via `PreparedStatement` abuse and dynamic query construction through multiple method calls remains a challenge. The taint tracker resolves single-method flows but loses precision on multi-hop patterns through helper methods.

**Cross-Site Scripting (CWE-79): +29.7%.** High TPR (100%) but also high FPR (70.3%). The tool correctly identifies all XSS sinks but over-reports on properly encoded output. Distinguishing `response.getWriter().println(sanitized)` from `response.getWriter().println(raw)` requires deeper Java API modeling.

These are known gaps. Java semantic analysis is newer than our Python and TypeScript coverage, and the taint model is actively being improved.

## How It Works

Dojigiri runs a three-tier analysis pipeline:

### Tier 1: Regex Pattern Matching

Fast, broad-coverage detection using 711 YAML-defined rules across 10 languages. This catches the obvious things — hardcoded secrets, insecure function calls, known-bad patterns. It is intentionally over-inclusive; the goal is high recall at the cost of precision. Later tiers filter out the noise.

### Tier 2: Semantic Analysis + Taint Tracking

This is where the OWASP results come from. Dojigiri parses source code using tree-sitter to build a full AST, then extracts:

- **Function definitions and call sites** — who calls whom, with what arguments
- **Assignment chains** — which variable received what value, through what sequence of assignments
- **Control flow graphs** — per-function CFGs with basic blocks, branch edges, and loop back-edges
- **Scope information** — variable visibility and shadowing across nested scopes

The taint analyzer walks this structure using fixed-point dataflow iteration over the CFG in reverse postorder. It tracks tainted data from sources (HTTP parameters, environment variables, file reads) through assignments, function calls, and container operations to sinks (SQL queries, system commands, HTML output).

Critically, it is **path-sensitive**: a sanitizer in one branch of an `if` statement does not clear taint for the other branch. A sanitizer inside a loop body is treated as conditional because the loop might execute zero times. This is what distinguishes it from grep-with-extra-steps approaches.

**Taint gating** is the mechanism that converts the high-recall regex tier into high-precision findings. For injection categories where regex alone produces near-100% FPR (the regex fires on every string concatenation in a SQL context), the finding is only reported if taint analysis independently confirms a source-to-sink data flow. This is why SQL injection went from ~100% FPR with regex alone to 24.6% FPR with taint gating — a massive precision improvement while retaining 33.5% of true positives.

### Tier 3: LLM Augmentation (Not Used in Benchmark)

The OWASP results above use tiers 1 and 2 only. Tier 3 feeds static findings into focused LLM prompts for context-aware analysis: business logic flaws, authorization bypasses, and vulnerability patterns that cannot be expressed as static rules. This layer is optional and was excluded from the benchmark to measure the static analysis floor, not the ceiling.

### Concrete Examples

**Example 1: Taint through container aliasing.** The benchmark includes cases where user input is stored in a `HashMap`, retrieved under a different key, and passed to a SQL query. Pattern matching sees `map.get("key")` flowing into `executeQuery()` but cannot determine whether the map value was tainted. Dojigiri's taint tracker propagates taint through the `map.put()` / `map.get()` pair and confirms the flow.

**Example 2: Conditional sanitization.** Several test cases apply sanitization inside an `if` block:

```java
String param = request.getParameter("input");
if (shouldSanitize) {
    param = ESAPI.encoder().encodeForSQL(new OracleCodec(), param);
}
query = "SELECT * FROM users WHERE name='" + param + "'";
```

A flow-insensitive analyzer sees the sanitizer and clears taint globally. Dojigiri's path-sensitive analysis recognizes that the `else` path (where `shouldSanitize` is false) still carries tainted data to the sink. This is a true positive that flow-insensitive tools miss.

**Example 3: Safe code that looks dangerous.** The benchmark includes cases where `PreparedStatement` with parameterized queries is used correctly — the query string is constant and user input is bound via `setString()`. Regex flags the SQL keyword + user input in the same method. Taint analysis sees that the user input never flows into the query string itself, only into the parameter binding API. No source-to-sink flow, no finding. True negative.

## Try It

Install from PyPI:

```bash
pip install dojigiri
```

Run against your project:

```bash
dojigiri scan /path/to/your/code
```

Source and documentation:

- **GitHub:** [github.com/dojigiri/dojigiri](https://github.com/dojigiri/dojigiri)
- **PyPI:** [pypi.org/project/dojigiri](https://pypi.org/project/dojigiri/)
- **OWASP scorecard data:** Available in the `benchmarks/` directory of the repository

The OWASP Benchmark results are fully reproducible. Clone the [OWASP Benchmark v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava), point Dojigiri at it, and run `benchmarks/owasp_general_score.py`. The scoring script, expected results, and raw detection data are all in the repo.

---

*Dojigiri is an open-source SAST tool licensed under BUSL-1.1. It supports Python, Java, JavaScript, TypeScript, Go, Rust, C#, PHP, and universal security rules. 711 rules, tree-sitter semantic analysis, path-sensitive taint tracking, and optional LLM augmentation for deep scanning.*
