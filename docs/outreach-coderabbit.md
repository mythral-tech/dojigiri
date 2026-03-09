# CodeRabbit Outreach — Cold Email + Follow-Up

**Target:** CEO/CTO at CodeRabbit (AI code review, $60M raised, no SAST engine)
**Angle:** Acquisition or licensing of Dojigiri as their SAST layer

---

## Email 1 — Cold Outreach

**Subject:** You're missing a SAST engine. I built one that speaks LLM.

---

Hey [Name],

CodeRabbit does AI code review better than anyone, but you don't have a static analysis engine underneath it — no taint tracking, no dataflow, no control flow graphs. That's a gap your competitors will fill before you do.

I built Dojigiri: a SAST tool covering 17 languages with three analysis tiers — regex, tree-sitter AST (taint tracking, CFG, dataflow), and an LLM deep scan layer on top. It also runs as an MCP server, so AI agents can invoke it natively — first SAST tool built for that. Against OWASP BenchmarkJava it pulled 449 SQL injection findings; against Juice Shop, 13 criticals, all legitimate.

15K LOC Python, 1,293 tests passing, ships as a single binary. SARIF output, GitHub Actions ready. It would plug into your stack, not fight it.

Worth 15 minutes to talk about licensing or acquisition?

— Stephane

---

## Email 2 — Follow-Up (if they respond with interest)

**Subject:** Re: [previous thread]

---

Hey [Name],

Glad this landed. Here's the technical breakdown.

**Three-tier analysis:**
1. **Regex layer** — fast pattern matching for known-bad patterns, low false positive rate. 50+ rules across 17 languages (Python, JS/TS, Go, Rust, Java, C#, PHP, Ruby, C/C++, Kotlin, Swift, Scala, Dart, Lua, Shell, SQL).
2. **Tree-sitter AST layer** — this is the core. Full semantic analysis: taint tracking (source-to-sink), control flow graphs, dataflow analysis, null safety checks. Not string matching pretending to be SAST.
3. **LLM deep scan** — sends suspicious code segments through an LLM for business logic analysis, complex injection chain detection, and context-dependent vulnerability assessment. This is the layer that catches what static rules can't, and it's the reason this would be native to CodeRabbit's architecture rather than bolted on.

**NEW: SCA dependency scanning** via the OSV API. Vulnerability lookup across all major ecosystems. This means Dojigiri covers both first-party code (SAST) and third-party dependencies (SCA) — two product lines from one engine.

**MCP server mode:** Dojigiri exposes its full analysis capability as an MCP server. Any AI agent or LLM-powered tool can invoke scans, query results, and act on findings programmatically. This isn't a CLI wrapper — it's a native protocol integration. For CodeRabbit, this means your AI review agents could call Dojigiri's analysis directly during review, combining your LLM review with grounded static analysis results.

**Benchmark results:**
- OWASP BenchmarkJava: 449 SQL injection findings (comprehensive coverage)
- OWASP Juice Shop: 13 critical findings, all verified legitimate (low false positive rate)

**Technical details:**
- ~15K LOC Python, single-file binary distribution
- 1,293 tests passing
- Output formats: SARIF, JSON, HTML, PDF
- GitHub Actions integration ready
- CI/CD pipeline friendly — runs anywhere Python runs

**What I'm looking for:** Either acquisition (you own the engine outright) or a licensing deal where CodeRabbit integrates Dojigiri as your SAST layer under your brand. I'm flexible on structure — the goal is getting this in front of real users at scale, and CodeRabbit is the right home for it.

Happy to do a live demo or give you a binary to throw at your own repos. What works best?

— Stephane
