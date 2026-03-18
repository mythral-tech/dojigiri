# Dojigiri vs. Competitors: Gap Analysis

**Date:** 2026-03-18
**Purpose:** Honest assessment of where Doji stands against established SAST tools.

---

## Competitive Landscape

| Tool | Approach | Languages | Rules | Taint | Cross-file | Price |
|------|----------|-----------|-------|-------|------------|-------|
| **Semgrep CE** | Pattern + taint | 30+ | 4,000+ | Intraprocedural only | No | Free |
| **Semgrep Pro** | + interprocedural | 30+ | 5,500+ | Cross-file (fails >1K files) | Yes (fragile) | $6-21/dev/mo |
| **CodeQL** | Query-based DF | 12+ | Large | Global (expensive) | Yes (config-heavy) | Free (GH Advanced Security) |
| **Snyk Code** | Hybrid ML + rules | ~15 | Opaque | ML-learned | Yes (opaque) | $25/dev/mo |
| **SonarQube** | Pattern + taint | 12+ | 10,000+ | 4 langs only | Yes (4 langs) | $20K+/yr |
| **Dojigiri** | Pattern + taint + LLM | 8 | ~804 | Path-sensitive (1 file) | Python only | $19-99/mo |

---

## Where Doji Stands (verified data)

### Real Strengths

**Taint Engine** — Path-sensitive within functions (CFG-based), inter-procedural within single files (method summaries). Object attribute taint tracking via `_extract_class_attr_taint()`. More sophisticated than Semgrep CE's single-function taint, comparable to Semgrep Pro minus cross-file.

**LLM Layer** — Unique. No competitor has this. Cost-tracked, multi-backend, prompt-injection hardened. Deep scan validates static findings with Claude reasoning. Genuinely novel.

**OWASP Benchmark** (verified scores):
- **Tuned mode:** Youden +91.9% (macro). 10/11 categories at 100% TPR/0% FPR. SQL injection at 11.4% TPR is the gap.
- **General mode:** Youden +45.3%, TPR 70.8%, FPR 25.5%. Competitive — Semgrep CE sits at ~74.8% FPR in independent studies.

**CI/SARIF** — Production-ready. GitHub Actions, SARIF 2.1.0, Code Scanning integration.

**SCA** — Functional. 10 lockfile formats, OSV API. Basic but real.

### Where Doji Falls Short

#### 1. Cross-File Taint (Critical)
- **Doji:** Python-only, naive import resolution, breaks on relative imports
- **Fix priority:** JS/Java cross-file would double credibility
- **Effort:** Large (multi-session)

#### 2. Language Depth (Significant)
- Python/Java/JS/Go: deep semantic analysis + CFG + taint
- Rust: stubbed (2 source patterns, 1 sink)
- C#: basic sources/sinks, no ORM patterns
- PHP: regex rules only, no semantic analysis
- **Reality:** Claims 8, delivers 4 at depth

#### 3. Rule Count (Moderate)
- ~804 rules vs Semgrep's 4,000+
- But rule count is misleading — quality > quantity

#### 4. Framework Taint Models (Addressed 2026-03-18)
- **Added:** Django (GET/POST/FILES/body/META/COOKIES/path), FastAPI, Flask extended, Express extended (file/files/hostname/ip/path/url), Koa/Fastify/Hapi/NestJS, Spring MVC, Gin/Echo/Fiber, GORM, Sequelize/Prisma/Knex, JPA/Hibernate, Spring JdbcTemplate/RestTemplate/WebClient
- **Still missing:** Rails, Laravel, ASP.NET deeper patterns

#### 5. Real-World Validation (Critical for credibility)
- Flask + Open-Interpreter have ground-truth annotations
- Need 3-5 more repos annotated for marketing data
- No head-to-head comparison with Semgrep CE yet

#### 6. Aliasing & Dynamic Dispatch (Moderate)
- Import aliases work. Module aliases, `getattr()`, decorators, metaclasses — invisible.

---

## Doji's Tier

**Mid-tier SAST with one unique advantage (LLM) and several critical gaps.**

- Better than: Bandit, basic regex scanners
- Comparable to: Semgrep CE for Python/Java/JS (single-file analysis)
- Behind: Semgrep Pro, CodeQL, Snyk Code (cross-file, language breadth, battle-testing)

---

## Priority Improvements (bang for effort)

1. **Annotate 3-5 more benchmark repos** — gives real FP/TP rates and marketing data
2. **Cross-file taint for JS/Java** — biggest credibility gap
3. **Head-to-head comparison** — run Doji + Semgrep CE on same 5 repos, publish delta
4. **OWASP SQL injection gap** — 11.4% TPR in tuned mode needs investigation

## What Not to Chase

- 30+ languages — 8 at depth beats 30 at surface
- 10,000+ rules — vanity metric
- Global call graph — even CodeQL admits it doesn't scale

## The LLM Moat

The acquisition story. Semgrep/Snyk would buy the taint-to-LLM pipeline, not 804 rules. Patent filing is the right move. But LLM can't compensate for cross-file gap — a buyer prices accordingly.
