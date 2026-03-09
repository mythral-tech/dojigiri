# Dojigiri White-Label Licensing Pitch

**Fallback plan if direct acquisition doesn't close within 2-3 months.**

---

## 1. White-Label Licensing One-Pager

### What They Get

**Core Engine**
- Production SAST engine: 50+ security rules across 17 languages
- Tree-sitter AST semantic analysis — not regex pattern matching
  - Taint tracking, control flow graphs, dataflow analysis, null safety
- 1,088 tests, ~15k LOC Python. This isn't a prototype.

**LLM Deep Scan Layer (the differentiator)**
- AI-powered analysis that catches what static rules miss
- Business logic flaws, complex injection chains, context-dependent vulnerabilities
- This is the feature no competitor at their price point has

**Output & Integration**
- SARIF, JSON, HTML, PDF reporting out of the box
- MCP server integration for AI-native workflows
- CLI-first design — drops into any CI/CD pipeline

**White-Label Terms**
- Full rebrand rights: their name, their logo, their docs
- Source code access (read-only or modifiable, tier-dependent)
- Private rule authoring — they can add proprietary rules on top
- No "powered by" attribution required

### Integration Options

| Option | Effort | Description |
|--------|--------|-------------|
| **CLI Drop-In** | Days | Ship the engine as-is behind their brand. Wrap the CLI. |
| **Library Embed** | 1-2 weeks | Import as a Python package into their existing platform. |
| **API Service** | 2-3 weeks | Run as a microservice behind their API gateway. |
| **Full Fork** | Negotiable | Source access, they maintain their own fork. Highest tier only. |

---

## 2. Pricing Tiers

### Tier 1 — Starter (Small AppSec shops, <20 customers)
**$2,500/month flat**
- CLI + library integration
- All 50+ rules, all 17 languages
- Standard LLM scan layer (BYO API key)
- SARIF/JSON/HTML output
- Email support, quarterly updates
- Up to 20 end-customer deployments

### Tier 2 — Professional (MSSPs, 20-100 customers)
**$6,000/month flat** or **$150/seat/month** (whichever is higher)
- Everything in Starter
- PDF reporting, full output suite
- MCP server integration
- Source code access (read-only)
- Custom rule development support (2hrs/month)
- Priority Slack channel
- Up to 100 end-customer deployments

### Tier 3 — Enterprise (Large MSSPs, unlimited)
**$12,000/month flat** or **$100/seat/month** (whichever is higher, floor scales)
- Everything in Professional
- Full source access with modification rights
- Private fork option
- Co-development on custom rules
- Dedicated support (8hrs/month)
- Unlimited end-customer deployments
- Early access to new rules and language support

### Per-Scan Alternative
For partners who prefer usage-based:
- **$0.50/scan** (first 10k scans/month)
- **$0.25/scan** (10k-50k)
- **$0.10/scan** (50k+)
- Minimum monthly commitment: $1,000

**Notes on pricing:**
- Annual contracts get 2 months free (pay 10, get 12)
- LLM inference costs are pass-through — they use their own API keys
- All prices USD, billed monthly or annually

---

## 3. License Change Strategy

### Current State
MIT licensed. Anyone can fork it, rebrand it, sell it. That's a problem for a licensing model.

### Recommended: Dual License (BSL + Commercial)

**Public license: Business Source License (BSL 1.1)**
- Source code stays visible (transparency, trust, community contributions)
- Free for non-commercial use, evaluation, personal projects
- Production commercial use requires a commercial license
- Optional: auto-converts to open source (e.g., Apache 2.0) after 3-4 years per version
- Used by MariaDB, CockroachDB, Sentry, HashiCorp. Proven model.

**Commercial license: Standard SaaS/OEM terms**
- Grants production use, white-label rights, redistribution
- This is what the paying partners get
- Terms defined per tier (see pricing above)

### Migration Path
1. Tag current MIT release as v1.x-final-mit
2. New development (v2.0+) ships under BSL 1.1
3. Existing MIT code stays MIT — can't revoke that
4. All new rules, the LLM layer improvements, new language support — BSL
5. Commercial license available from day one alongside BSL

### Alternative: AGPL + Commercial
- More restrictive than BSL (network use triggers copyleft)
- Stronger forcing function toward commercial license
- But AGPL scares some enterprises. BSL is friendlier.

**Recommendation: BSL 1.1 with 4-year conversion to Apache 2.0.** It's the cleanest play — visible source builds trust, the commercial license captures value, and the conversion clause signals you're not trying to trap anyone.

---

## 4. Outreach Email Template

**Subject:** White-label SAST engine — 17 languages, LLM-powered analysis, ready to ship under your brand

---

Hi [Name],

I built a SAST engine called Dojigiri that I think could save [Company] significant development time — or open up a new product line without the R&D cost.

**Quick specs:**
- 50+ security rules across 17 languages (Python, JS/TS, Go, Rust, Java, C#, etc.)
- Tree-sitter AST analysis: taint tracking, control flow, dataflow — not regex grep
- LLM-powered deep scan layer that catches business logic and complex injection chains
- SARIF, JSON, HTML, PDF output. Drops into any CI/CD pipeline.
- 1,088 tests. Production-grade.

**Why this might matter to you:**
Building a competitive SAST engine is 2-3 years and a full team. The LLM analysis layer is another 6-12 months on top of that. White-labeling Dojigiri lets you ship a branded SAST product to your customers in weeks, not years.

I'm offering white-label licensing with full rebrand rights. You'd ship it as your own product — your name, your packaging, your pricing to your customers. I handle engine updates and new rule development.

Pricing starts at $2,500/month for smaller shops. Happy to walk through the tiers and integration options if there's interest.

Worth a 20-minute call this week or next?

Best,
[Your name]
[Your site/LinkedIn]

---

**Alternate shorter version (for cold outreach where you have less credibility signal):**

Subject: Question about [Company]'s SAST capabilities

Hi [Name],

Quick question — does [Company] currently offer static analysis as part of your security services? If you're buying a third-party engine or building in-house, I might have a faster path.

I built a SAST engine (17 languages, tree-sitter AST analysis, LLM-powered deep scanning) that's available for white-label licensing. A few AppSec companies are evaluating it as a way to add branded SAST without the R&D cost.

Happy to share specs if it's relevant. If not, no worries.

[Your name]

---

## Appendix: Target Company Profile

**Ideal white-label partners:**
- Small-to-mid AppSec companies (5-50 employees) without their own SAST engine
- MSSPs adding "application security" to their service menu
- DevSecOps consultancies who want a product arm
- Regional security firms competing against Snyk/Checkmarx/Semgrep but can't match R&D spend

**Where to find them:**
- MSSP Alert Top 250 list
- Cybersecurity Ventures MSSP lists
- AppSec Village / DEF CON / BSides vendor halls (the small booths)
- LinkedIn search: "AppSec" + "startup" or "MSSP" + "application security"
- Crunchbase: security companies, Series A or below, <$10M raised

**Disqualifiers:**
- Companies that already have a mature SAST product (they're competitors, not customers)
- Companies too small to pay ($2,500/month is their entire tool budget)
- Companies that only do compliance checkbox security (they'll buy the cheapest option regardless)
