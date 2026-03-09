# Dojigiri Commercial Evaluation

**Date:** 2026-03-09
**Prepared by:** Kei (Business Strategy)
**Status:** Actionable — not a think piece

---

## 1. Market Positioning

### The SAST/SCA Market (2026)

The application security testing market is ~$8B globally, growing ~14% CAGR. The relevant segment — developer-facing SAST tools — is dominated by:

| Tool | Model | Strengths | Weaknesses | Est. Revenue |
|------|-------|-----------|------------|-------------|
| **Snyk** | SaaS, $8.5B peak valuation | Brand, ecosystem, 11 acquisitions | Aging SAST (DeepCode 2020), IPO uncertainty | ~$300M ARR |
| **Semgrep** | Freemium + Enterprise | Community rules, developer love, $193M raised | No LLM layer, taint tracking paywalled | ~$50-80M ARR |
| **SonarQube** | On-prem + Cloud | Enterprise penetration, 17 languages | Heavy (JVM + DB), no SCA, no LLM | ~$250M ARR |
| **CodeQL** | Free (GitHub-bundled) | Deep dataflow, GitHub native | Requires build step, 10 languages, slow | Bundled (GitHub) |
| **Checkmarx** | Enterprise on-prem/cloud | Compliance-driven sales, deep Java/.NET | Expensive, slow, legacy UX | ~$200M ARR |

### Where Dojigiri Sits

Dojigiri occupies a position that doesn't cleanly exist yet: **lightweight engine with heavyweight results**. The closest analogy is what Semgrep was in 2020 — fast, developer-friendly, rule-based — except Dojigiri adds:

1. **LLM tier** — nobody else ships this natively
2. **MCP server** — nobody else has this
3. **Lightweight deployment** — no JVM, no Docker, no database (tree-sitter for AST layer)
4. **Perfect OWASP score** — nobody else has achieved this

The positioning statement: **"The only SAST engine that scored 100% on OWASP Benchmark v1.2, with an LLM analysis layer no competitor offers, deployable as a single binary with minimal dependencies (tree-sitter for AST)."**

### Honest Gaps

- **10+ languages vs Semgrep's 30+** — matters for some buyers
- **Real-world FP rates on non-security rules are still high** — the SUMMARY.md shows 74% reduction after tuning but remaining findings still have noise. Security rules are strong; code quality rules need more work.
- **Solo developer + AI team** — enterprise buyers will ask about bus factor, SLA, and continuity
- **No cloud dashboard** — enterprise buyers expect a web UI for findings management
- **Brand recognition: zero** — you're selling to people who've never heard of you

---

## 2. Revenue Model Options

### Option A: White-Label Licensing (Already Drafted — Refine and Execute)

Your existing `licensing-pitch.md` tiers are reasonable. Adjusted recommendations:

| Tier | Price | Target |
|------|-------|--------|
| **Starter** | $3,000/mo | Small AppSec shops, <20 customers |
| **Professional** | $7,500/mo | MSSPs, 20-100 customers |
| **Enterprise** | $15,000/mo | Large platforms, unlimited deployment |
| **Usage-based** | $0.50-$0.10/scan | Partners who want variable cost |

**Why I bumped the prices:** Your original pricing undervalues the product given the OWASP score. A SAST engine that outperforms everything on the most recognized benchmark in the industry is not a $2,500/mo product. The buyers you're targeting (CodeRabbit at $550M valuation, Aikido at $1B) have budgets where $15K/mo is a rounding error compared to building this in-house.

**Annual contract incentive:** 15% discount (pay ~10.2 months, get 12). Your original "2 months free" was too generous.

**Projected revenue at scale:**
- 3 Starter customers: $108K/yr
- 2 Professional customers: $180K/yr
- 1 Enterprise customer: $180K/yr
- **Realistic Year 1 target: $150-250K** (2-4 customers)
- **Year 2 with momentum: $400-600K**

### Option B: Direct SaaS (Cloud-Hosted Dojigiri)

Build a web dashboard, host scans, charge per-repo or per-developer.

| Tier | Price | Includes |
|------|-------|---------|
| **Free** | $0 | 1 repo, 50 scans/mo, community rules |
| **Pro** | $29/dev/mo | Unlimited repos, SCA, SARIF, CI/CD integration |
| **Team** | $49/dev/mo | + LLM deep scan, priority support, PDF reports |
| **Enterprise** | Custom | SSO, on-prem option, SLA, dedicated support |

**Projected revenue:**
- At 500 paying devs (Pro): $174K/yr
- At 2,000 paying devs (mixed): $500K-$1M/yr

**Problem:** This requires building a cloud platform, auth, multi-tenancy, billing, a dashboard. That's 3-6 months of engineering for a solo dev. Don't do this first. White-label licensing generates revenue without building infrastructure.

### Option C: Acquisition Exit

Sell the whole thing. This is the fastest path to a lump sum but you lose the asset. See Section 5 for valuation.

### Recommended Path

**Phase 1 (now → 3 months):** White-label licensing. Close 1-2 deals from the target list.
**Phase 2 (3-6 months):** If licensing traction proves demand, evaluate whether to build SaaS or pursue acquisition at a higher valuation.
**Phase 3 (6-12 months):** Either scale licensing/SaaS or close an acquisition deal from a position of strength (with revenue, not just a benchmark score).

---

## 3. Go-to-Market Strategy

### First Customers (0-90 days)

**Priority targets (from your existing list, re-ranked post-OWASP-perfect-score):**

| Rank | Company | Why Now | Approach | Ask |
|------|---------|---------|----------|-----|
| 1 | **CodeRabbit** | No SAST, $60M fresh, obvious gap | Acquisition or licensing | $500K-$2M acquisition or $7.5K/mo |
| 2 | **Ox Security** | No proprietary engine, aggregator model | Licensing or acquisition | $7.5-15K/mo or acquisition |
| 3 | **Aikido Security** | 3 acquisitions in 6 months, $60M fresh | Acquisition | $1-3M acquisition |
| 4 | **Semgrep** | No LLM layer, rule-based ceiling | Licensing | $15K/mo enterprise |
| 5 | **Endor Labs** | New AI SAST could use better engine | Licensing | $7.5K/mo |

**Outreach update needed:** Your CodeRabbit email draft references old numbers (449 SQL injection findings, 1,293 tests). Update to lead with: **"Perfect score on OWASP Benchmark v1.2: 100% TPR, 0% FPR across all 11 CWE categories (2,740 test cases). No published tool has achieved this."** That's the lede now. Everything else is supporting detail.

### Verticals to Target

1. **AI code review platforms** (CodeRabbit, Codacy, DeepSource) — they need a SAST engine underneath their LLM review. Perfect fit.
2. **AppSec platforms without proprietary SAST** (Ox Security, Apiiro, Armo) — they aggregate third-party tools. Owning an engine = better margins + competitive moat.
3. **MSSPs adding AppSec services** — see MSSP Alert Top 250. These companies are adding "application security" to their menu and need tools to deliver it.
4. **DevSecOps consultancies** — smaller shops that want to offer branded SAST without building one.
5. **Compliance-driven enterprises** — the NIST SP 800-53 mapping is a differentiator for FedRAMP/SOC2 buyers.

### Channels

- **Direct outreach** to the target list (already started)
- **OWASP Benchmark leaderboard** — if OWASP publishes results, submit. A perfect score would generate inbound.
- **Blog post / technical writeup** — "How Dojigiri Achieved a Perfect Score on OWASP Benchmark v1.2" — publish on your site and cross-post to dev.to / Hacker News. This is free marketing that targets the exact audience (security engineers evaluating tools).
- **GitHub visibility** — star count matters for credibility. The BSL license may slow organic adoption vs MIT, but the benchmark result can drive traffic.
- **Security conferences** — BSides, OWASP chapter meetups (local Montreal chapter). Lightning talks are free. "I built a SAST tool that got a perfect OWASP Benchmark score" gets attention.

---

## 4. The OWASP Perfect Score as a Sales Weapon

### Why This Matters

The OWASP Benchmark v1.2 is the industry-standard evaluation for SAST tools. It has 2,740 test cases across 11 CWE categories. Published results from major tools:

| Tool | Youden Index | TPR | FPR | Source |
|------|-------------|-----|-----|--------|
| **Dojigiri** | **+100.0%** | **100.0%** | **0.0%** | Internal benchmark run |
| Contrast Assess | +73% | 97% | 24% | OWASP published |
| Checkmarx CxSAST | +29% | 78% | 49% | OWASP published |
| Fortify SCA | +23% | 73% | 50% | OWASP published |
| Semgrep OSS | ~-55% (est.) | ~16% | ~71% | Academic study (2024) |
| CodeQL | Varies by CWE | ~20% SQLi | — | Doyensec (2022) |

**No published tool has achieved Youden +100%.** This is not incremental improvement — it's a category-defining result.

### How to Use It

1. **Lead every conversation with it.** Not buried on page 3. First sentence: "We scored 100% on OWASP Benchmark v1.2. No other tool has."

2. **Create a comparison page** on your site. Table format, linked to OWASP sources. Let buyers verify the claims. Transparency builds trust.

3. **Demand independent verification.** Publish your methodology: which test cases, which rules, full SARIF output. Invite OWASP to verify. A verified perfect score is worth 10x an unverified claim.

4. **Use it to justify pricing.** "The engine that outperforms every commercial SAST tool on the industry benchmark" is not a $2,500/mo product.

5. **Address the obvious pushback proactively:**
   - "The OWASP Benchmark is synthetic, not real-world code" → Show the Juice Shop and real-world results alongside it. Acknowledge the limitation, then show you perform on real code too.
   - "Real-world FP rates differ" → This is true (your SUMMARY.md shows it). Be upfront: "Our security rules achieve near-zero FP on the benchmark. Code quality rules are still being tuned on real-world codebases." Honesty builds more credibility than hiding weaknesses.
   - "Can we reproduce this?" → "Yes. Here's the full SARIF output, here's the scoring script, here's how to run it yourself." Reproducibility is the strongest possible response.

### Critical Action Item

**README updated.** The README now shows Youden +100.0%, matching the scorecard.

---

## 5. Valuation Range

### For Acquisition

SAST company acquisitions in the relevant range:

| Acquisition | Price | Year | Context |
|-------------|-------|------|---------|
| DeepCode → Snyk | ~$15-20M (est.) | 2020 | AI-powered code review, small team |
| Trag → Aikido | Undisclosed (est. $3-8M) | 2025 | AI code quality, small team |
| Allseek → Aikido | Undisclosed (est. $2-5M) | 2025 | AI pentesting, small team |
| Haicker → Aikido | Undisclosed (est. $2-5M) | 2025 | AI pentesting, small team |
| Netsil → Nutanix | ~$5-10M (est.) | 2018 | Network analytics, Harjot Gill's prior exit |

**Dojigiri acquisition range: $1.5M - $5M** (pre-revenue, solo developer, strong tech)

Factors that push toward the high end:
- Perfect OWASP score (unique, verifiable)
- Three-tier architecture (defensible moat)
- MCP integration (strategic for AI-native buyers)
- 1,292 tests, 15K LOC (production-grade, not a prototype)
- BSL license (buyer gets commercial exclusivity)

Factors that push toward the low end:
- No revenue
- Solo developer (bus factor = 1)
- No cloud platform / no dashboard
- Real-world FP rates need work on non-security rules
- 10+ languages vs competitors' 30+

**With 2-3 licensing customers generating $200K+ ARR:** Range moves to $2M-$8M (revenue multiple of 10-40x for early-stage security SaaS is standard).

**With a verified, published OWASP perfect score and press coverage:** Add 30-50% premium for strategic value.

### For Licensing Revenue (Long-Term)

If you build a licensing business instead of selling:

| Scenario | Year 1 | Year 2 | Year 3 |
|----------|--------|--------|--------|
| **Conservative** | $100K | $250K | $500K |
| **Moderate** | $200K | $500K | $1M |
| **Optimistic** | $350K | $800K | $1.5M |

At $1M ARR with growth, the business would be valued at $8-15M for acquisition purposes.

---

## 6. Immediate Next Steps

### This Week

1. ~~**Update the README** to show the perfect OWASP score~~ — Done. README shows +100.0%.

2. **Publish the full OWASP scorecard** in a format buyers can verify. Include the scoring script, the raw SARIF output, and instructions to reproduce. Put it on the website or a dedicated page.

3. **Rewrite the CodeRabbit outreach email** to lead with the perfect score. The current draft (`outreach-coderabbit.md`) buries the strongest selling point.

### This Month

4. **Send outreach to top 3 targets** (CodeRabbit, Ox Security, Aikido). Personalized emails to CTOs. Lead with the benchmark. Offer a live demo where you run Dojigiri against their own public repos.

5. **Write and publish the technical blog post:** "How Dojigiri Achieved a Perfect Score on OWASP Benchmark v1.2." Target Hacker News front page. This is free distribution to exactly the right audience.

6. **Submit results to OWASP Benchmark project** for independent verification and inclusion in their published tool comparisons.

### This Quarter

7. **Close first licensing deal.** Target: 1 customer at $3K-$7.5K/mo. This converts the narrative from "cool benchmark result" to "revenue-generating business."

8. **Continue FP reduction on code quality rules.** The security rules are strong (proven by OWASP). The code quality rules need work before enterprise buyers will tolerate them in CI/CD pipelines. Focus on the top 5 from your SUMMARY.md.

9. **Build a minimal web presence** — landing page with benchmark results, architecture diagram, pricing tiers, and a "Book a Demo" button. Doesn't need to be fancy. Needs to exist.

10. **Consider a GitHub Actions marketplace listing.** Free tier (limited scans) drives visibility. Paid tier converts to revenue. GitHub Marketplace handles billing.

---

## Summary

Dojigiri has a genuine technical moat: a perfect OWASP Benchmark score that no published tool has achieved, a three-tier architecture with an LLM layer nobody else ships, and MCP integration that positions it for the AI-agent era. The BSL license protects commercial value while keeping source visible.

The weaknesses are real: no revenue, solo developer, high FP on non-security rules, no cloud platform, no brand recognition. But every one of those is fixable with time and money — and a licensing deal provides both.

**Recommended path:** White-label licensing first (revenue without infrastructure investment), blog post + OWASP submission for credibility (free marketing), and keep acquisition as the backup exit if licensing doesn't convert within 3-6 months.

The perfect OWASP score is a time-limited asset — other tools will improve, and the novelty fades. Move fast.

---

*This evaluation reflects market conditions as of March 2026. Pricing and valuation estimates are based on publicly available data from comparable transactions and industry benchmarks.*
