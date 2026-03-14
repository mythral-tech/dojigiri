# The Forging of Dōjigiri

*Software as bladesmithing. A living record of how a SAST scanner was forged through disciplined, creative craft.*

---

## The Method

Traditional Japanese swordsmiths fold steel to drive out impurities and create layered strength. Each fold doubles the layers — 15 folds produce 32,768 layers of interlocking grain. The blade doesn't become sharp through a single act. It becomes sharp through the accumulation of disciplined passes, each one measured, each one building on the last.

We write software the same way.

**A fold is a meaningful unit of work — one commit, one push, one measurable improvement.** Not a typo fix. A real strike on the steel. The fold count tracks the real craft invested. A 50-fold blade is not the same as a 5-fold blade — you can feel the difference when it cuts.

### Fold Categories

| Type | Japanese | Purpose | Example |
|------|----------|---------|---------|
| **Capability** | 能力 | New features, new detection | Adding 89 LLM injection rules |
| **Precision** | 精度 | Fewer false positives, fewer misses | OWASP Youden +36% → +91.9% |
| **Hardening** | 鍛造 | Security, licensing, infrastructure | BSL-1.1 licensing, CI/CD pipeline |
| **Polish** | 研磨 | Documentation, packaging, outreach | README overhaul, PyPI packaging |
| **Repair** | 修繕 | Fixing cracks found in the steel | Broken chmod regex, timing attacks |

### The Rules

1. **Measure the blade.** Every fold has a number. Benchmark scores, rule counts, test counts. If you can't measure the improvement, the fold didn't happen.
2. **Never break the blade.** Tests pass after every fold. A broken fold weakens everything before it.
3. **Parallel hammering.** Multiple agents work different parts of the blade simultaneously. One sharpens the edge, another tempers the spine.
4. **Gates before advancing.** Pass/fail checkpoints at boundaries. Security review before push. Quality check before ship. Catch problems at the gate, not at the end.
5. **The fold count is sacred.** It represents cumulative craft. Don't inflate it. Don't skip it.

---

## The Forge Log

*Each entry records: the fold number, what was done, what was measured, and what changed.*

### Phase I — Raw Ore to First Edge (Folds 1–10)

The scanner started as a basic Python linter — pattern matching with regex. These folds established the foundation: rule definitions, severity levels, the finding data model, and the first CLI.

| Fold | Type | Work | Measurement |
|------|------|------|-------------|
| 1–8 | Capability | Core scanner, rule system, SCA module, Java OWASP benchmark | 1,932 findings, bandit superset, zero regressions |
| 9 | Precision | Zero false positive rate, GitHub Action, README | FPR: 0% |
| 10 | Hardening | BSL-1.1 license, 21 Python security rules | Legal protection established |

### Phase II — Folding the Layers (Folds 10–36)

The semantic analysis layer was built here — tree-sitter AST parsing, scope analysis, the taint engine. The scanner evolved from regex matching to understanding code flow.

| Fold | Type | Work | Measurement |
|------|------|------|-------------|
| 36 | Precision | Full review — benchmark gating, doc accuracy, test coverage | Quality gates established |
| 37 | Precision | Full team review → 10/10 implementation | All review items addressed |
| 38 | Precision | Scope-aware taint, OWASP general score | Taint + scope integrated |
| 39 | Precision | Loop/nested-branch taint, OWASP category analysis | Complex flow coverage |
| 40 | Hardening | CLI/rules split, taint completeness, security hardening | Architecture clean |

### Phase III — The Edge (Folds 40–50)

The blade took its final shape. LLM-specific security rules, TypeScript support, OWASP benchmark dominance. Each fold was grinding the edge finer.

| Fold | Type | Work | Measurement |
|------|------|------|-------------|
| 41 | Hardening | Product launch infrastructure | Deploy pipeline live |
| 42 | Precision | Java taint breakthrough | OWASP Youden +36.3% → +44.2% |
| 43 | Capability | Rule expansion: 196 → 632 rules with CWE/NIST | 632 rules, full compliance mapping |
| 44 | Capability | TypeScript first-class support | 35 TS-specific security rules |
| 45 | Precision | Close 4 benchmark gaps | OWASP 13/20 → 17/20 (85%) |
| 46 | Precision | Taint engine breakthroughs | OWASP 17/20 → 19/20 |
| 47 | Precision | TOCTOU detection | OWASP 20/20 (100%) |
| 48 | Capability | LLM prompt injection detection, DOTALL fix | 89 LLM rules, 2,220 tests |
| 49 | Capability | SDK coverage, multimodal injection, OWASP LLM02 | Full LLM Top 10 coverage |
| 50 | Polish | Deduplicate rule IDs | Clean rule namespace |

**Steel-folding declared complete at fold 50.**

### Phase IV — Fitting the Tachi (Post-50)

The blade was forged. Now it needed a handle (landing page), a guard (API), and a scabbard (deployment). The scanner became a product.

| Fold | Type | Work | Measurement |
|------|------|------|-------------|
| 51+ | Hardening | FAANG-level API review, PostgreSQL migration, Stripe billing | 3 critical security fixes, 183 API tests |
| — | Hardening | Landing page overhaul, XSS fixes, CSP headers | Mag7-standard frontend |
| — | Hardening | GTM council, OG tags, rate limiting, ToS | Launch checklist complete |
| — | Polish | dojigiri.com live, api.dojigiri.com live | Product shipped |

### Phase V — Reforging (Current)

A master smith returns to the blade. Audit found 16 cracks in the steel — broken regex, timing attacks, race conditions. Each crack becomes a fold. The blade doesn't weaken from finding flaws — it strengthens from fixing them.

| Fold | Type | Work | Measurement |
|------|------|------|-------------|
| 51 | Repair | 9 blade cracks: chmod regex (missed 0o644), rule dedup (pickle×3, yaml×2, ssl×3, tls×3, cors×2 → unique IDs), requests-no-timeout DOTALL, false sanitizers removed (str.isdigit/isalnum), Exception→specific catches in analyzer, O(n²)→O(n) taint regex | 2,059 rules (deduped from 2,068), 2,392 tests passing, Ctrl+C works |

---

## Why This Works

Software has a craft problem. The industry optimizes for speed — ship fast, break things, patch later. The result is brittle code that dulls on first contact with reality.

Steel-folding optimizes for **edge retention**. Each fold is:
- **Intentional** — you choose what to improve, not what's easiest
- **Measured** — the number proves the fold happened
- **Irreversible** — the improvement is committed, pushed, permanent
- **Cumulative** — fold 50 contains the strength of all 49 before it

The creative insight is that software and metalwork share the same physics: **layered compression creates strength that monolithic construction cannot.** A sword forged in one pour shatters. A sword folded fifty times cuts through armor.

The same code, written in one pass, is fragile. The same code, refined through fifty measured passes, handles edge cases the author never imagined — because each fold was a chance to find and fix what the previous fold missed.

### The Gate System

Between phases, gates. A gate is a pass/fail checkpoint — the blade either meets the standard or it goes back to the anvil.

- **Pre-push gate** — security review before code leaves the forge
- **Pre-ship gate** — safety review before the product reaches users
- **Benchmark gate** — OWASP scores must not regress
- **Test gate** — all tests pass, no regressions

Gates are not bureaucracy. They're the discipline that makes the pause productive. You catch the crack at the boundary, not after the blade is mounted.

---

## The Blade Today

```
Run: python scripts/repo-stats.py tools/dojigiri
```

*Live metrics from the source. Never trust stale numbers — measure the blade.*

---

*Dōjigiri Yasutsuna — the Demon-Cutter. Forged by Yasutsuna of Hōki. Used by Minamoto no Yorimitsu to slay Shuten-dōji. One of the five Tenka-Goken, the legendary swords under heaven. It survived a thousand years because every layer of the steel was folded with intention.*

*This scanner carries that name. It earns it fold by fold.*
