# Dojigiri Legal Evaluation — Pre-Commercialization

**Prepared by:** Ritsu (Legal Strategy)
**Date:** 2026-03-09
**Product:** Dojigiri v1.1.0 — SAST + SCA tool
**Jurisdiction:** Quebec, Canada
**Status:** Pre-first-sale

---

## 1. IP Ownership Assessment

### Who Owns the Code?

Stephane Perez is the sole human author. All code was written with Claude Code (Anthropic AI assistant). Under current law:

**Canada:** The Copyright Act requires a human author. AI-generated output is not independently copyrightable, but code written *by a human using AI as a tool* is. The key question is whether the human exercised sufficient creative control. In Dojigiri's case — Stephane directed the architecture, reviewed all output, made design decisions, and curated what shipped — this is solidly human-authored work with AI assistance, not AI-generated work. Canada has not yet legislated on this directly, but the Copyright Board and courts would almost certainly treat this as Stephane's work.

**United States:** The Copyright Office has clarified (2023 guidance, Thaler v. Perlmutter) that AI cannot be an author, but humans who use AI tools can claim copyright on works where they exercised creative control over selection, arrangement, and expression. Dojigiri fits this pattern.

**EU:** Similar position — the AI Liability Directive and existing copyright frameworks treat AI as a tool, not an author.

### Risk Level: LOW

**Practical risks:**
- No employer or co-developer has a competing ownership claim
- No work-for-hire agreement clouds the picture (solo developer)
- Anthropic's Terms of Service assign output rights to the user
- The tree-sitter dependency is MIT-licensed, creating no IP entanglement

**Recommended actions:**
1. Add a copyright notice to the `pyproject.toml` or a dedicated `COPYRIGHT` file: "Copyright 2026 Stephane Perez. All rights reserved."
2. Keep records showing human creative direction (commit history, design docs, architecture decisions). This is already happening naturally through git history.
3. Do NOT represent the tool as "AI-built" in marketing — frame it as "built with AI assistance." This matters for IP defensibility.

---

## 2. BSL 1.1 Suitability

### Pros

| Factor | Assessment |
|--------|------------|
| **Source visibility** | Customers can audit the tool that audits their code — critical for security tooling trust |
| **Commercial protection** | Production commercial use requires a license — captures value |
| **Precedent** | Used by HashiCorp, Sentry, CockroachDB, MariaDB, Couchbase — enterprises understand it |
| **Conversion clause** | Apache 2.0 after 4 years signals good faith, reduces "vendor lock-in" objections |
| **Community contribution** | Source access enables PRs, bug reports, rule contributions without giving away the store |
| **Evaluation-friendly** | Prospects can test before buying — reduces sales friction |

### Cons

| Factor | Assessment |
|--------|------------|
| **Not OSI-approved** | BSL is explicitly not "open source" by OSI definition. Cannot market as open source. |
| **Enterprise legal friction** | Some corporate legal teams are unfamiliar with BSL and may slow procurement |
| **Enforcement difficulty** | Detecting unauthorized commercial use is hard for a CLI tool (no phone-home, no license server) |
| **PyPI distribution** | PyPI allows BSL packages, but some users filter for OSI-approved licenses only |
| **Fork risk post-conversion** | After 2030, anyone can fork v1.1.0 under Apache 2.0. But by then you'll have 4 years of new versions still under BSL. This is by design. |

### Alternatives Considered

| License | Verdict |
|---------|---------|
| **AGPL v3** | Stronger copyleft — network use triggers source disclosure. Scares enterprise buyers. Not recommended for commercial licensing. |
| **SSPL** | MongoDB's license. Not OSI-approved, and more controversial than BSL. Overkill here. |
| **Proprietary + free tier** | Maximum control but kills community trust and contribution. Wrong move for security tooling. |
| **MIT/Apache (status quo)** | No commercial protection. Anyone can fork and sell. Already moved past this. |

### Verdict: BSL 1.1 IS THE RIGHT CHOICE

The license is well-drafted, well-understood in the market, and correctly configured. The 4-year conversion to Apache 2.0 is industry standard.

### One Issue Found (RESOLVED)

~~**TERMS.md Section 2 still references MIT License.**~~ Fixed — TERMS.md now correctly references BSL 1.1.

---

## 3. Dependency License Audit

### Core Dependencies (Required)

| Package | License | Commercial Use | Risk |
|---------|---------|---------------|------|
| `tree-sitter` | MIT | Unrestricted | NONE |
| `tree-sitter-language-pack` | MIT + Apache 2.0 mix | Unrestricted | NONE — both are permissive |

### Optional Dependencies

| Package | License | Commercial Use | Risk |
|---------|---------|---------------|------|
| `anthropic` SDK | MIT | Unrestricted | NONE |
| `mcp` SDK | MIT | Unrestricted | NONE |
| `weasyprint` | BSD 3-Clause | Unrestricted | NONE |

### External APIs

| Service | License/Terms | Risk |
|---------|--------------|------|
| Google OSV API | Public API, Google ToS | LOW — no redistribution, query-only. Review Google API ToS for commercial use limits. No rate-limit issues at expected volume. |
| Anthropic Claude API | Anthropic API Terms | LOW — customer brings their own key, you're not reselling API access |

### OWASP Benchmark (GPL v2)

**The OWASP Benchmark test suite is GPL v2.** This is the one to watch.

- GPL v2 applies to the benchmark code itself (the Java test cases)
- Dojigiri does NOT include, distribute, or link to the OWASP Benchmark code
- The benchmark is used only to *test against* — Dojigiri scans it as an external input
- Scan results and scores are not derivative works of the GPL code
- The scorecard script (`owasp_scorecard.py`) processes Dojigiri's own JSON output, not the benchmark source

**Risk: NONE** — using GPL software as a test target does not create GPL obligations. This is analogous to a compiler being tested against GPL code — the compiler does not become GPL. Well-established precedent.

**However:** Do not distribute the OWASP Benchmark code alongside Dojigiri. Do not include it in the repo. If it's currently cloned for local testing, make sure it's gitignored.

### Overall Dependency Risk: CLEAN

No GPL contamination. No copyleft obligations. All production dependencies are permissive (MIT, Apache 2.0, BSD). This is a strong position.

---

## 4. Required Legal Documents Before First Sale

### Already Exist (Need Updates)

| Document | Status | Action Required |
|----------|--------|----------------|
| `LICENSE` (BSL 1.1) | Good | None — correctly drafted |
| `LICENSING.md` | Good | None |
| `TERMS.md` | Good | Fixed — now references BSL 1.1 |
| `PRIVACY.md` | Good | Add note about commercial customer data handling |
| `SECURITY.md` | Good | None |

### Must Create Before First Sale

#### 1. Commercial License Agreement (CLA) / EULA
**Priority: CRITICAL**

This is the actual contract customers sign. Must include:
- Grant of rights (what they can do: production use, CI/CD integration, etc.)
- Restrictions (what they can't do: resell, white-label without tier upgrade, compete)
- License scope (per-seat, per-org, per-repo — pick a model)
- Term and renewal (annual recommended, auto-renew with 30-day cancellation notice)
- Payment terms (net-30, accepted methods)
- Support SLA (response times, channels, hours)
- IP ownership (Stephane retains all IP, customer gets license only)
- Warranty disclaimer (AS-IS, no guarantee of vulnerability detection)
- Limitation of liability (capped at fees paid in prior 12 months)
- Indemnification (mutual — you indemnify for IP infringement, they indemnify for misuse)
- Termination clauses (breach, non-payment, insolvency)
- Governing law and dispute resolution

**Recommended approach:** Draft a template, have a Quebec business lawyer review it ($500-1,500 CAD for template review). Do NOT use a generic EULA generator — security tooling has specific liability concerns.

#### 2. Data Processing Agreement (DPA)
**Priority: HIGH (if selling to EU customers or enterprises)**

Required under GDPR if the tool processes personal data (source code can contain PII — emails, names, etc. in comments or strings). Also increasingly expected by enterprise procurement.

Must include:
- Role definition (customer is controller, Dojigiri is processor if LLM mode sends code externally)
- Sub-processors (Anthropic, if deep scan is used)
- Data retention and deletion
- Security measures
- Breach notification procedures
- Cross-border transfer mechanisms (if applicable)

**For static-only mode:** A DPA may not be strictly required since no data leaves the customer's machine. But having one ready signals maturity.

#### 3. Service Level Agreement (SLA)
**Priority: MEDIUM**

If offering support tiers, formalize:
- Response times by severity
- Uptime commitments (if offering hosted/SaaS in future)
- Maintenance windows
- Escalation procedures

#### 4. Order Form / Quote Template
**Priority: HIGH**

Simple document that references the CLA and specifies:
- Customer name and details
- License tier and pricing
- Term dates
- Payment schedule
- Any custom terms

This is what you actually send to close a deal.

---

## 5. Liability and Warranty Considerations

### The Core Problem

Dojigiri is a security tool. If it misses a vulnerability and a customer gets breached, they will look for someone to blame. This is the #1 legal risk for this product.

### Current Protections (Good)

The LICENSE and TERMS.md already include:
- "AS IS" warranty disclaimer
- No guarantee of detecting all vulnerabilities
- Explicit statement that Dojigiri is not a substitute for professional security audits
- Limitation of liability for false positives and false negatives
- Auto-fix disclaimer (user responsible for reviewing changes)

### Additional Protections Needed

1. **Cap liability in the commercial license.** Standard approach: liability capped at total fees paid in the 12 months preceding the claim. Never accept unlimited liability.

2. **Exclude consequential damages.** Lost profits, lost data, business interruption, breach costs — all excluded. This is standard in software licensing but must be explicit.

3. **Carve out for the LLM layer.** The deep scan sends code to a third-party API. Make clear that:
   - Anthropic's terms govern their processing
   - You are not responsible for Anthropic's data handling
   - The customer assumes risk of sending code to a third-party LLM
   - If the customer uses a local LLM, that's entirely their responsibility

4. **No compliance guarantee.** Dojigiri output does not certify compliance with any standard (SOC 2, ISO 27001, PCI DSS, HIPAA). State this explicitly. Some buyers will try to use SAST scan results as compliance evidence — that's their call, but you don't warrant it.

5. **Professional liability insurance (E&O).** Consider obtaining Errors & Omissions insurance once revenue justifies it. In Quebec, this is available through commercial insurers. $1M-$2M coverage runs $1,000-$3,000 CAD/year for a solo software business. Not required before first sale, but recommended before scaling.

### Quebec-Specific Notes

- Quebec's Consumer Protection Act (CPA) limits warranty disclaimers for *consumer* products, but B2B software licensing is not subject to CPA. Your customers are businesses.
- Quebec Civil Code allows contractual limitation of liability in B2B transactions, but gross negligence or intentional fault cannot be contractually excluded. Draft accordingly.

---

## 6. Quebec Business Structure

### Recommended: Federal Corporation (CBCA)

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| **Sole proprietorship** | Simplest, cheapest | Unlimited personal liability, no separation | NO — not for a product with liability risk |
| **Quebec Inc. (provincial)** | Limited liability, cheaper than federal | Only recognized in Quebec, less credible for international sales | MAYBE |
| **Federal Inc. (CBCA)** | Limited liability, recognized nationwide, more credible internationally, easier banking | Slightly more expensive, dual reporting (federal + Quebec) | RECOMMENDED |
| **US LLC/Corp** | US customer trust, US banking | Complex cross-border tax, US filing obligations, higher cost | PREMATURE — revisit if US revenue exceeds 50% |

### Steps to Incorporate (Federal)

1. **Name search:** NUANS report (~$15 CAD). Check "Dojigiri" availability.
2. **Articles of Incorporation:** File with Corporations Canada (~$200 CAD online).
3. **Quebec registration:** Register extra-provincially with the Registraire des entreprises (~$367 CAD).
4. **Business number:** Get a BN from CRA for GST/QST and corporate tax.
5. **GST/QST registration:** Mandatory once revenue exceeds $30,000 in 4 consecutive quarters. Register proactively if you expect to hit this quickly.
6. **Business bank account:** Open a corporate account (Desjardins, National Bank, or a startup-friendly bank like Wise Business for USD invoicing).
7. **Provincial permits:** None required for software licensing in Quebec.

**Estimated cost:** $600-800 CAD all-in for incorporation + registration.
**Timeline:** 1-2 weeks.

### Tax Considerations

- **Federal corporate tax rate:** 9% (small business deduction on first $500K active business income) + 11.5% Quebec = ~20.5% combined. This is favorable.
- **SR&ED tax credits:** Dojigiri development likely qualifies for Scientific Research and Experimental Development credits. Federal refundable credit of 35% on first $3M of qualifying expenditures for CCPCs. Quebec has additional R&D credits. This could refund a meaningful portion of development costs. Consult a tax professional.
- **International sales:** Software license sales to non-Canadian customers are zero-rated for GST/QST (exported services). You charge 0% tax on foreign sales.
- **US withholding:** Under the Canada-US tax treaty, software royalties paid by US companies to Canadian corps generally face 0% withholding if structured as license fees (not royalties). Structure matters.

---

## 7. OWASP Benchmark Claims

### Can You Say "Perfect Score"?

**Yes, with qualifications.** The scorecard shows 100% TPR, 0% FPR, +100% Youden Index across all 11 OWASP Benchmark v1.2 categories. That is, by definition, a perfect score on the benchmark.

### Required Qualifications

1. **Specify the benchmark version.** Always say "OWASP Benchmark v1.2" — not just "OWASP Benchmark." Versions matter.

2. **Specify the scan mode.** The OWASP results were from Dojigiri's static analysis. If deep scan (LLM) was involved, disclose that.

3. **Self-tested disclosure.** These results are self-reported, not independently verified by OWASP or a third party. You MUST disclose this. Suggested language:

   > "Dojigiri achieved a perfect score (100% TPR, 0% FPR) on the OWASP Benchmark v1.2 Java test suite in internal testing."

   The phrase "in internal testing" is the key qualifier. Without it, the claim implies independent verification.

4. **Do not imply OWASP endorsement.** OWASP is a trademark. You can reference the benchmark (it's a public project), but do not imply that OWASP endorses, certifies, or validates Dojigiri. Suggested safe phrasing:

   > "Tested against the OWASP Benchmark v1.2"

   Unsafe phrasing (avoid):
   > "OWASP-certified" / "OWASP-approved" / "OWASP-validated"

5. **Benchmark limitations.** The OWASP Benchmark is a synthetic test suite, not real-world code. A perfect benchmark score does not guarantee perfect real-world detection. Your existing `benchmark-comparison.md` already acknowledges limitations honestly — keep that standard.

6. **Reproducibility.** Make the benchmark run reproducible. Publish the scorecard script (already done: `owasp_scorecard.py`), the raw results, and instructions so anyone can verify. This turns a marketing claim into a verifiable fact, which is much stronger legally.

### Advertising Standards (Canada)

The Competition Act (Canada) and Quebec's CPA prohibit false or misleading advertising. A "perfect score" claim is fine as long as:
- It's true (it is)
- It's qualified (specify benchmark version, self-tested)
- It's not misleading by omission (don't hide that it's synthetic code)

The existing `benchmark-comparison.md` with its "Honest Limitations" section is exactly the right approach.

### Risk Level: LOW (with proper qualification)

---

## 8. Immediate Action Items

### BLOCKING (Must Fix Before First Sale)

| # | Item | Effort | Why It Blocks |
|---|------|--------|---------------|
| ~~1~~ | ~~**Fix TERMS.md Section 2**~~ | Done | Resolved — BSL 1.1 reference in place |
| 2 | **Draft Commercial License Agreement** | 1-2 days + lawyer review | Cannot sell without a contract for the customer to sign |
| 3 | **Incorporate** (federal CBCA recommended) | 1-2 weeks | Don't sell under personal name — liability exposure |

### HIGH PRIORITY (Before Scaling)

| # | Item | Effort | Why |
|---|------|--------|-----|
| 4 | **Draft DPA template** | 1 day | Enterprise and EU customers will require it |
| 5 | **Update PRIVACY.md** for commercial context | 2 hours | Current version is OSS-focused, needs commercial customer section |
| 6 | **Create Order Form template** | 2 hours | Needed to actually close deals |
| 7 | **Register GST/QST** | 1 hour online | Required once revenue starts |
| 8 | **Set up business banking** | 1 day | Separate business finances from personal |

### RECOMMENDED (Before Significant Revenue)

| # | Item | Effort | Why |
|---|------|--------|-----|
| 9 | **E&O insurance** | 1 day to shop quotes | Liability protection for security tool claims |
| 10 | **Consult SR&ED advisor** | 1 meeting | Potential significant tax refunds on development costs |
| 11 | **Trademark search for "Dojigiri"** | $300-500 CAD | Protect the brand. CIPO filing ~$350 CAD for one class |
| 12 | **Add COPYRIGHT notice to repo** | 5 min | Strengthens IP position |
| 13 | **Independent OWASP benchmark verification** | Varies | Turns self-reported claim into third-party verified — much stronger for sales |

---

## Summary

**Nothing here blocks commercialization except three items:** fix the stale TERMS.md, draft a commercial license agreement, and incorporate. Everything else is risk mitigation that can happen in parallel with early sales conversations.

The BSL 1.1 license is correctly chosen and well-configured. Dependencies are clean. The OWASP benchmark claims are defensible with proper qualification. Quebec/Canada is a favorable jurisdiction for a software licensing business, with attractive tax treatment for small corps and SR&ED eligibility.

The biggest ongoing legal risk is the inherent liability of selling a security tool — manage this through contractual caps, warranty disclaimers, and eventually E&O insurance. The existing TERMS.md and PRIVACY.md provide a solid foundation once updated for the BSL transition.

---

*This evaluation is strategic guidance, not legal advice. Engage a Quebec business lawyer for the commercial license agreement and incorporation. Budget $2,000-4,000 CAD for initial legal setup (incorporation + CLA review + trademark filing).*
