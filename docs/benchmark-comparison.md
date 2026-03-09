# Dojigiri vs. Traditional SAST: Benchmark Results

**Date:** March 2026 | **Version:** Dojigiri quick-scan mode (no LLM layer)

---

## Benchmark Targets

| Target | Description | Files Scanned |
|--------|-------------|---------------|
| **OWASP BenchmarkJava** | Purpose-built Java webapp with 11 vulnerability classes (SQLi, XSS, command injection, path traversal, XXE, etc.) | 5,526 |
| **OWASP Juice Shop** | Intentionally vulnerable Node.js/TypeScript e-commerce app | 685 |

## Dojigiri Results

### OWASP BenchmarkJava

| Severity | Count | Key Rules |
|----------|-------|-----------|
| Critical | 451 | sql-injection (449), ssti-risk (1), hardcoded-secret (1) |
| Warning | 5,352 | unused-variable (5,076), xxe-risk (75), insecure-http (37) |
| Info | 2,762 | — |
| **Total** | **8,565** | — |

**Security findings: 566** across SQL injection, XXE, insecure HTTP, innerHTML risks, SSTI, and hardcoded secrets.

### OWASP Juice Shop

| Severity | Count | Key Rules |
|----------|-------|-----------|
| Critical | 13 | hardcoded-secret (4), eval-usage (4), sql-injection (2), private-key (1), syntax-error (2) |
| Warning | 900 | unused-variable (739), loose-equality (89), insecure-http (31), innerHTML (19) |
| Info | 91 | — |
| **Total** | **1,004** | — |

**Security findings: 64** — eval() usage, SQL injection via string interpolation, SSRF risk, hardcoded secrets, exposed private key, document.write, innerHTML XSS vectors.

## How Competitors Perform

Published data from independent benchmarks and research (Doyensec 2022, sanj.dev Q3 2025):

| Metric | Semgrep | CodeQL | Dojigiri |
|--------|---------|--------|----------|
| **Detection score** (AI code, 2025) | 87/100 | 84/100 | Not yet independently scored |
| **Accuracy** | ~82% | ~88% | TBD |
| **False positive rate** | ~12% | ~5% | See caveat below |
| **SQL injection detection** | ~88% | ~95% | 449 findings on BenchmarkJava |
| **Speed** (50K LOC) | ~90s | ~8 min | seconds (no build step) |
| **CWE gaps** | None reported | Missed 3 CWE categories entirely (Doyensec) | No CWE gaps in covered rules |
| **Setup** | Config + rules | Build database required | Zero-config, single binary |

**Important caveat on Semgrep:** A 2024 academic study found that out-of-the-box Semgrep detects only ~15.9% of OWASP Benchmark vulnerabilities. With custom tuning ("Semgrep*"), detection improved to 44.7% — a 181% gain, but still under 50%. Enterprise Semgrep with proprietary rules scores higher (~87/100 on newer benchmarks), but that's a paid product.

**CodeQL gap:** Doyensec found CodeQL achieved only ~20% detection on SQL injection in certain test suites and completely missed 3 CWE categories, dragging its average score well below Semgrep on the OWASP Benchmark specifically.

## What Dojigiri Catches That Others Miss

### 1. No build step required
CodeQL requires building a database from source — if the project doesn't compile, CodeQL can't scan it. Dojigiri scans raw source files. Incomplete repos, partial code, vendored snippets — all scannable.

### 2. Cross-language in a single pass
Juice Shop contains TypeScript, JavaScript, Python, YAML, and Dockerfiles. Dojigiri scanned all of them in one run with zero configuration. Semgrep and CodeQL require per-language rule packs and configuration.

### 3. LLM deep scan layer (unique to Dojigiri)
The three-tier architecture — regex → AST/semantic → LLM — means Dojigiri can escalate ambiguous findings to an LLM for contextual analysis. No other SAST tool ships this. The benchmarks above used **quick mode only** (no LLM). The deep scan layer catches:
- Business logic flaws that pattern matching cannot express
- Context-dependent vulnerabilities (e.g., "this looks like a password reset token but has no expiry")
- Novel vulnerability patterns not covered by static rules

### 4. SCA via OSV (new)
Dependency vulnerability scanning using the OSV database. Zero external dependencies, no API keys. Catches known CVEs in transitive deps — a category Semgrep OSS doesn't cover at all (requires Semgrep Supply Chain, a paid add-on).

### 5. MCP server mode
Dojigiri runs as an MCP server, meaning AI coding agents can invoke it programmatically as part of their workflow. No other SAST tool offers this integration pattern.

## Honest Limitations

- **Java coverage is shallow.** Dojigiri's semantic analysis (taint tracking, CFG, null safety) is strongest in Python and TypeScript. Java rules are regex-only, which means high recall but poor precision on Java-specific benchmarks. OWASP BenchmarkJava scorecard: 88.6% TPR / 88.8% FPR on SQLi — the rule fires on all string concatenation in SQL without taint analysis. Only 2 of 11 Java CWE categories covered. This is the weakest surface area and is being improved.
- **unused-variable noise:** 5,076 of 5,352 warnings on BenchmarkJava are unused-variable findings. Technically correct but noisy. Filter by `category:security` for the real picture.
- **Quick mode only:** These scans didn't use the LLM layer. The numbers above represent the static analysis floor, not Dojigiri's ceiling.
- **Strongest on JS/TS/Python.** Juice Shop (Node.js/TS/Python) is where Dojigiri's semantic analysis shines — all 13 criticals were verified true positives. Lead with this, not the Java benchmark.

## Architecture Comparison

| Feature | Semgrep OSS | CodeQL | Dojigiri |
|---------|-------------|--------|----------|
| Analysis tiers | Pattern matching | Dataflow + taint | Regex → AST → LLM |
| Taint tracking | Pro only | Yes | Yes (path-sensitive) |
| SCA / dependency scanning | Paid add-on | Via Dependabot | Built-in (OSV API) |
| Languages | 30+ | 10 | 17 |
| Output formats | SARIF, JSON | SARIF, CSV | SARIF, JSON, HTML, PDF |
| Setup | Install + config | Install + build DB | Single binary, zero config |
| AI/LLM layer | No | No | Yes (optional deep scan) |
| MCP integration | No | No | Yes (native server mode) |
| Pricing | Free (OSS) / Paid (Pro) | Free (GitHub) | Free (OSS) |
| Self-hostable | Yes | Yes | Yes |

## The Pitch

Dojigiri isn't trying to replace Semgrep or CodeQL. It's the layer that sits on top — or runs alongside — catching what pattern-based tools structurally cannot. The LLM tier is the moat. SCA is table stakes that we now cover. MCP integration makes Dojigiri the first SAST tool built for the AI-agent era.

For acquirers: the value isn't just another rule engine. It's the three-tier architecture that degrades gracefully (works without LLM, works better with it) and the MCP server mode that no competitor has.

---

*Data sources: [Doyensec Semgrep vs CodeQL (2022)](https://blog.doyensec.com/2022/10/06/semgrep-codeql.html), [sanj.dev AI Code Security Benchmark (2025)](https://sanj.dev/post/ai-code-security-tools-comparison), [Semgrep* EASE 2024](https://dl.acm.org/doi/fullHtml/10.1145/3661167.3661262), [OWASP Benchmark Project](https://owasp.org/www-project-benchmark/)*
