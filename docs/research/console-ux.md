# VectaSec Console — UI/UX Research

**Status:** v1 (research) · **Date:** 2026-07-17 · **Scope:** `apps/web` (Next.js console)

This document is the design research behind the VectaSec console. It covers information architecture, findings-as-workflow interaction design, evidence/citation UX, accessible severity color, data-dense table design, concrete design tokens, and the current Next.js + Supabase auth conventions.

Every contrast ratio in §7 was **computed**, not estimated (WCAG relative-luminance formula, script in §7.7). Every spec/doc claim is cited to a URL that was actually fetched. Claims I could not verify are marked.

**Confidence legend:** 🟢 verified against a primary source (spec/vendor docs) · 🟡 secondary source or synthesis · 🔴 low — treat as hypothesis, verify before relying on it.

---

## Contents

1. [Design thesis — what makes a console feel like a security product](#1-design-thesis)
2. [Information architecture](#2-information-architecture)
3. [Findings as workflow](#3-findings-as-workflow)
4. [Evidence & citation UX](#4-evidence--citation-ux)
5. [Severity color & accessibility](#5-severity-color--accessibility)
6. [Data-dense table design](#6-data-dense-table-design)
7. [Design tokens](#7-design-tokens)
8. [Next.js 16 + Supabase auth](#8-nextjs-16--supabase-auth)
9. [Open questions & low-confidence items](#9-open-questions--low-confidence-items)
10. [Sources](#10-sources)

---

## 1. Design thesis

A security console earns credibility through **provenance and restraint**, not chrome. Three principles fall out of the research and out of VectaSec's own architecture (grounded AI, citation gate, deterministic detection):

**1. Every claim is traceable to an observation.** VectaSec's data model already enforces this at the DB layer (`observations`, `ai_output_evidence`). The console's job is to make that *visible*. This is the single biggest differentiator available to us: most security tools assert; we can cite. Research on attributed AI answers is explicit that citations are the trust surface — the model can be perfectly grounded and none of it transfers to the reader unless they can click through and confirm ([7wData](https://7wdata.be/uncategorized/citations-grounding-proof/), 🟡).

**2. Density is a feature, not a compromise.** Security analysts scan. A console that hides data behind cards and modals is a console that gets abandoned for a CSV export. Table interfaces are by nature very dense, so the goal is not to strip the UI but to reveal interactions opportunistically, only when and where needed ([Pencil & Paper](https://www.pencilandpaper.io/articles/ux-pattern-analysis-enterprise-data-tables), 🟡).

**3. The enemy is alert fatigue, and it is a design problem.** This is well-documented, not folklore. A 2026 survey synthesizing 119 records reports that a typical enterprise SIEM ingests **50–500 billion events per day**, producing hundreds to thousands of alerts per shift; one SOC measurement found only **~0.01% of daily alerts linked to true attacks**, and analyst accuracy **dropped by 40% over a 12-hour shift** when the false-positive rate exceeded 80% ([Ndichu et al., arXiv 2605.08316](https://arxiv.org/html/2605.08316v1), 🟢).

> The consequence for us: **a finding that is not actionable is a bug.** Grouping, dedup, and suppression are not features bolted on later — they are the primary IA.

---

## 2. Information architecture

### 2.1 What best-in-class consoles put on the landing view

Synthesis across Wiz, Orca, Snyk, Aikido, Vanta, and Datadog. The pattern is consistent:

| Zone | Content | Why |
|---|---|---|
| **Posture headline** | One number + trend (score, or "N critical open") | Executive glance value in <2s |
| **Prioritized queue** | Top ~5–10 findings by *contextual* risk, not raw severity | The landing page must answer "what do I do now" |
| **Coverage/health** | Connections + Collectors: connected, stale, erroring | A posture number is a lie if collection is broken |
| **Delta since last scan** | New / resolved / regressed | Security is a rate, not a level |
| **Compliance strip** | Framework pass rates | The budget-holder's view |

**The anti-pattern to avoid:** a wall of donut charts. Snyk's consolidated dashboard is explicitly framed as helping professionals sort and prioritize *instead of becoming overwhelmed by too many alerts* ([Snyk](https://snyk.io/comparison/snyk-vs-aikido/), 🟡 — vendor marketing, directional only).

**VectaSec-specific landing view.** Our differentiator is the layer nobody else sees, so the landing view should lead with it:

```
┌─ Posture ────────────┐ ┌─ Coverage ───────────────────────┐
│  72 / 100   ▲ +4     │ │ 6 connections · 1 Collector stale│
│  8 critical open     │ │ ⚠ kafka-prod last seen 3h ago    │
└──────────────────────┘ └──────────────────────────────────┘
┌─ Do this now (ranked, grouped) ─────────────────────────────┐
│ ●CRIT  Kafka accepts all clients when no ACL matches   ×3   │
│        kafka-prod, kafka-eu, msk-payments      [Triage ▸]   │
│ ●CRIT  Kong Admin API exposed without auth             ×1   │
│ ●HIGH  Istio PERMISSIVE mTLS                           ×7   │
└─────────────────────────────────────────────────────────────┘
┌─ Since last scan ────┐ ┌─ Compliance ─────────────────────┐
│ +3 new  -5 resolved  │ │ PCI 4.0.1 78% · DORA 64% · …     │
└──────────────────────┘ └──────────────────────────────────┘
```

Note the `×3` — occurrences are **collapsed by rule** on the landing view. See §3.4.

### 2.2 Findings list layout

The dominant model is **explorer + facets + group-by**, borrowed from log tooling. Datadog is the clearest documented example: misconfigurations can be grouped *"by any facet, custom property, or tag (or None to view misconfigurations individually)"*, with a query search bar and filters like `evaluation:fail` ([Datadog docs](https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/findings/), 🟢).

Recommended layout:

```
┌──────────┬──────────────────────────────────────────────────┐
│ FACETS   │  [query bar: severity:critical status:open    ]  │
│          │  Group by: [Rule ▾]   Density [≡]  Columns [⚙]   │
│ Severity │ ┌──────────────────────────────────────────────┐ │
│ ☑ Crit 8 │ │ ▸ ●CRIT KAFKA.ACL.ALLOW_EVERYONE        ×3   │ │
│ ☐ High 24│ │ ▸ ●CRIT KONG.ADMIN.NO_AUTH              ×1   │ │
│ Status   │ │ ▾ ●HIGH ISTIO.MTLS.PERMISSIVE           ×7   │ │
│ Rule     │ │     payments-svc   prod   2h ago   [unassigned]│
│ System   │ │     ledger-svc     prod   2h ago   @dishanth │ │
│ Asset    │ └──────────────────────────────────────────────┘ │
└──────────┴──────────────────────────────────────────────────┘
```

**Load-bearing choices:**

- **Facet counts are always visible.** A facet without a count forces a click to learn nothing.
- **The query bar is the URL.** Filter state must be shareable — analysts paste views into Slack. This maps cleanly onto Next.js `searchParams` (§8.4).
- **Group-by defaults to Rule**, not to flat. This is the single most effective anti-fatigue lever we have (§3.4).
- **Severity is never the only sort.** Default sort should be contextual risk. Snyk uses a Risk Score with 12+ contextual factors and reachability analysis ([Snyk](https://snyk.io/comparison/snyk-vs-aikido/), 🟡). Our equivalent inputs: severity × exposure (internet-reachable?) × blast radius (§2.4) × asset criticality tag.

### 2.3 Finding detail page

The structure that recurs across Wiz, Datadog, and Snyk — and the one our data model already implies:

| Section | Content | VectaSec source |
|---|---|---|
| **Header** | Title, severity, status, assignee, due, occurrence count | `findings` |
| **What we found** | One plain sentence. No jargon. | `findings.title` |
| **Evidence** | The literal config that triggered it, cited | `observations` (§4) |
| **Why it matters** | Impact, grounded and cited | `ai_outputs` + citation gate |
| **Blast radius** | Graph: what this reaches | `edges` recursive CTE |
| **Remediation** | Concrete, copy-pasteable fix | `findings.remediation` |
| **Compliance** | Controls this fails | `controls` |
| **History** | First seen, last seen, status changes | `findings` + `audit_log` |
| **Actions** | Assign · Suppress · Send to Jira/Slack | engine API |

Datadog's finding panel is documented as containing *"additional information about the misconfiguration and suggested remediation steps"* plus tags *"for more context about who owns the resource and where it resides"* ([Datadog](https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/findings/), 🟢).

**The evidence section is where we win.** Most tools describe the problem. We show the exact bytes:

```
┌─ Evidence ──────────────────────────────── observed 2026-07-17 04:12Z ─┐
│  broker/kafka-prod · server.properties                     [obs_8fa2c] │
│                                                                        │
│    allow.everyone.if.no.acl.found = true                               │
│    ─────────────────────────────────────                               │
│                                                                        │
│  ▸ Collected by collector-eu-1 · scan_31f9 · read-only AdminClient     │
└────────────────────────────────────────────────────────────────────────┘
```

Every element there is auditable: *what* was seen, *when*, *by which collector*, *in which scan*, and a stable observation ID a customer can quote back to us. This is what "detection is deterministic" looks like in pixels.

### 2.4 Asset graph visualization

Wiz's graph is the reference. The documented framing is that the graph answers three analyst questions: **how did the attacker get here** (path from internet to resource), **what can they do from here** (outbound edges — identities, data stores, lateral targets), and **what is the blast radius** (how many resources reachable in N hops) ([Wiz blog](https://www.wiz.io/blog/wiz-security-graph-enhances-cloud-incident-response), 🟡 vendor source). Wiz surfaces this from findings via a *"View in graph"* affordance rather than as a standalone destination ([Wiz](https://www.wiz.io/lp/wiz-security-graph), 🟡).

**Design rules for our graph — learned from what makes graphs useless:**

1. **The graph is a *lens on a finding*, not a homepage.** A full-estate graph is a hairball demo, not a tool. Entry point = "View blast radius" on a finding. This matches Wiz's "View in graph" pattern.
2. **Default to N=1 or 2 hops.** Let the user expand. Unbounded traversal = hairball.
3. **Node meaning must survive greyscale.** Shape + icon + label, never color alone (§5.2).
4. **The graph must have a table twin.** Every graph view needs "show as list" — it's more accessible, more scannable, and more exportable. The graph sells; the table works.
5. **Path narration in text.** Render the path as a sentence *above* the canvas: `internet → kong/route:/admin (no auth) → svc:ledger → kafka/topic:payments`. Screen-reader-usable, Slack-pasteable, and often the whole answer.

VectaSec's graph is Postgres recursive CTEs over `resources` + `edges` — so the natural rendering is server-computed paths, client-rendered canvas. Keep the traversal in SQL, ship a small path DTO to the client (§8.3).

---

## 3. Findings as workflow

The build plan already commits to this ("findings are a *workflow*, not a list"). Here is what that means concretely.

### 3.1 Status lifecycle

Datadog uses a deliberately minimal set — **Open** ("has not yet been resolved"), **Under Review** ("actively being investigated"), **Archived** ("the detection that caused the signal has been resolved") — with archived signals able to revert to Open within 30 days ([Datadog](https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/signals_explorer/), 🟢).

Our data model already declares: `open | triaged | in_progress | resolved | suppressed | accepted`.

**Recommendation (🟡 — my synthesis, not a vendor pattern):** six states is one or two too many for the UI. `triaged` and `in_progress` are hard to distinguish in practice, and `resolved` vs `accepted` vs `suppressed` blur. Keep all six in the DB, but **collapse to four in the UI**:

| UI state | DB states | Meaning |
|---|---|---|
| **Open** | `open` | Nobody has looked |
| **In progress** | `triaged`, `in_progress` | Owned, being worked |
| **Resolved** | `resolved` | Fixed — *and re-verified by a scan* |
| **Muted** | `suppressed`, `accepted` | Deliberately not fixing, with reason + expiry |

**Critical rule:** `resolved` must be **machine-confirmed, not human-asserted**. A finding goes resolved when a subsequent scan no longer produces its fingerprint. If a human marks it resolved and the next scan disagrees, it **reopens automatically and loudly**. This is the difference between a posture tool and a ticket tracker. Datadog's 30-day revert-to-open window is a weaker version of the same idea (🟢 for Datadog's behavior, 🟡 for my stronger recommendation).

### 3.2 Triage interaction patterns that work

From the SOC literature ([Ndichu et al.](https://arxiv.org/html/2605.08316v1), 🟢) and enterprise table practice:

- **Keyboard-first.** `j`/`k` move, `e` mute, `a` assign, `Enter` open. Analysts working a queue of 200 will not mouse. This is the highest-leverage, lowest-cost thing we can build.
- **Bulk action on a *group*, not on rows.** Muting 40 checkboxes is fatigue; muting one rule with a reason is a decision. The survey notes DeepCASE's key move is that **"analysts label clusters rather than individual events"** ([Ndichu et al.](https://arxiv.org/html/2605.08316v1), 🟢). Design the bulk action at the rule level.
- **Checkboxes on hover, bulk bar on selection.** Show bulk action buttons only after selection to reduce visual clutter ([Pencil & Paper](https://www.pencilandpaper.io/articles/ux-pattern-analysis-enterprise-data-tables), 🟡).
- **Never a blocking modal in a triage loop.** Assign/mute must be inline popovers. A modal costs ~1s of attention each; over 200 findings that's the whole afternoon.
- **Optimistic UI + undo, not confirm dialogs.** "Muted ×40 · Undo" beats "Are you sure?". Confirm dialogs train people to click through.

### 3.3 Severity vs. priority — keep them separate

Severity is a **property of the rule**. Priority is a **property of this occurrence in this estate**. Conflating them is why teams drown in "criticals".

Production practice combines *"alert severity with entity context, asset criticality, historical behavior, and threat-intelligence enrichment"* ([Ndichu et al.](https://arxiv.org/html/2605.08316v1), 🟢).

For VectaSec:

```
priority = severity_weight
         × exposure     (internet-reachable? 3× : 1×)
         × blast_radius (log-scaled reachable assets from `edges`)
         × asset_crit   (tenant tag: prod/payments → 2×)
         ÷ age_decay    (optional; keeps stale noise from dominating)
```

**Show the arithmetic.** A risk score the user cannot decompose is a black box, and in a security tool a black box gets distrusted and disabled. Render it as a breakdown popover on the score. This is the same trust principle as the citation gate — *show your work*.

### 3.4 Dedup and grouping — the core anti-fatigue lever

We already have the right primitive: `findings.fingerprint`. The UI must exploit it.

**Three distinct concepts — do not conflate:**

| Concept | Key | Meaning | UI |
|---|---|---|---|
| **Dedup** | `fingerprint` across scans | Same issue, same asset, seen again | One row; `last_seen` updates. Never a new row. |
| **Grouping** | `rule_id` across assets | Same rule, many assets | Collapsible group `×N` |
| **Correlation** | graph path | Different rules, one root cause | "Related findings" on detail |

Grouping is where the volume dies. "Istio PERMISSIVE mTLS ×7" is one decision. Seven rows is seven decisions with the same answer.

**Correlation is the aspirational one** and worth flagging as future work: the survey's Category III describes reconstructing multi-stage attacks by modeling *"alerts as nodes in a property graph connected by semantic, causal, and temporal relations"*, with graph summarization (DEPCOMM) achieving **−97.5% graph reduction** while maintaining detection rates ([Ndichu et al.](https://arxiv.org/html/2605.08316v1), 🟢). We have the property graph already (`resources` + `edges`). Root-cause grouping ("these 12 findings all stem from one unauthenticated Kong Admin API") is a credible v2 differentiator. 🔴 for feasibility on our timeline — do not promise it.

### 3.5 Suppression with expiry

Our schema has `suppressions(rule_id, scope, reason, expires_at, created_by)` — this is right. The UX rules:

- **Reason is required, free-text, and shown.** A mute without a reason is a landmine for the next analyst.
- **Expiry is required — offer 30/60/90 days, and make "never" hard.** Permanent mutes are how posture tools rot into theater. A defensible default: 90 days.
- **Muted is a *view*, not a void.** A "Muted (12)" facet, always visible with its count. Suppressed findings that vanish entirely destroy auditability — and we are the tool auditors point at.
- **Expiry warns before it fires.** "3 suppressions expire this week" belongs on the landing view. Silent un-muting produces a mystery critical on a Monday.
- **Every mute writes to `audit_log`.** Who muted what, when, why, until when. This is a compliance artifact, and it's already in our model.

---

## 4. Evidence & citation UX

This is VectaSec's signature surface. The `ai_output_evidence` citation gate is enforced in code; the console must make it legible.

### 4.1 What the research says

Recent HCI work is directly on point. **Attribution Gradients** (Kambhamettu, Hwang, Laban & Head — UIST '26, Nov 2026) argues that existing interfaces present citations all at once, which makes it hard to critically examine the claim↔source relationship, and proposes **progressive disclosure** — unfolding evidence incrementally as the user engages ([arXiv 2510.00361](https://arxiv.org/pdf/2510.00361), 🟢 for the paper's existence and thesis; 🟡 for details — the PDF's study specifics did not extract cleanly).

A 2026 pattern survey names seven citation patterns and, critically, the anti-patterns ([AYDesign](https://www.aydesign.ai/blog/ai-citation-source-ui-patterns-2026), 🟡 — industry blog, not peer-reviewed):

**Patterns:** inline numbered citations with hover preview · source card sidebar · **claim-level attribution** · deep-link to the source passage · **confidence/strength indicators** (strong/mixed/weak/unsupported) · source filtering controls · **missing-source disclosure** ("AI inference" / "no source" badges).

**Anti-patterns:** bibliography dumps at the end · paragraph-level citations that mask mixed sourced/unsourced content · equal visual weight for claims with unequal evidence · undisclosed inference blended with fact.

The survey is explicit that **high-stakes domains (legal, medical, finance) require claim-level attribution, deep-linking, and honest missing-source disclosure** as a trust necessity, not polish. **A security posture tool is unambiguously in that tier.**

### 4.2 The VectaSec citation pattern

Claim-level, deep-linked, progressive:

```
┌─ Why this matters ──────────────────────────── AI · grounded ─┐
│                                                                │
│  Any client that presents no ACL match is granted access [1],  │
│  and topic `payments` carries cardholder data [2] — so this    │
│  broker is effectively an open door to PCI-scoped data.        │
│                                                                │
│  ─────────────────────────────────────────────────────────     │
│  [1] obs_8fa2c · kafka-prod/server.properties · 04:12Z    ▸    │
│      allow.everyone.if.no.acl.found = true                     │
│  [2] obs_1c93d · topic:payments · tag pci=true            ▸    │
└────────────────────────────────────────────────────────────────┘
```

**Rules:**

1. **Every sentence carries ≥1 citation marker, or it does not ship.** This mirrors the DB gate. If the model emits an uncited sentence, we reject the output — and the UI should never be capable of rendering one.
2. **Markers are hoverable and expandable in place** (progressive disclosure, per Attribution Gradients) — hover = peek at the observation; click = expand inline; click-through = the full observation record.
3. **Deep-link to the exact line**, not to the file. We have `observations.source_ref jsonb` — populate it with enough to anchor precisely.
4. **AI content is visually fenced and labeled.** A subtle border + "AI · grounded" chip. The user must always know which pixels are deterministic (the finding, the evidence) and which are generated (the explanation). **This boundary is the product's integrity made visible.**
5. **Rule-based fallback is labeled too** — "Rule-based" chip when the LLM is off/unreachable. Never let the two be confused.
6. **No confidence percentages.** A "73% confident" number is unfalsifiable theater. Use the citation count and the evidence itself as the confidence signal — that's honest and checkable.

### 4.3 The observation record

Observations are immutable in our model. Lean into it — this is an *evidence ledger*, and it should read like one:

```
obs_8fa2c                                          [Copy ID] [Export]
─────────────────────────────────────────────────────────────────────
Claim        allow.everyone.if.no.acl.found = true
Resource     broker/kafka-prod
Observed     2026-07-17 04:12:33Z
Scan         scan_31f9
Collected by collector-eu-1 (v0.4.2) · read-only AdminClient
Source ref   server.properties:41
Cited by     finding_a91c · ai_output_77b2
Immutable    ✓ never modified since write
```

That "Immutable ✓" line is a small thing that does real work in a security review.

---

## 5. Severity color & accessibility

### 5.1 The actual WCAG 2.2 thresholds

Verified directly against the spec 🟢:

| Requirement | Ratio | Level | Source |
|---|---|---|---|
| **Normal text** | **4.5:1** | AA | [SC 1.4.3](https://www.w3.org/TR/WCAG22/) |
| **Large text** | **3:1** | AA | [SC 1.4.3](https://www.w3.org/TR/WCAG22/) |
| **UI components & graphical objects** | **3:1** | AA | [SC 1.4.11](https://www.w3.org/TR/WCAG22/) |
| **Use of color** | *not color alone* | **A** | [SC 1.4.1](https://www.w3.org/TR/WCAG22/) |

**"Large text" is defined as** at least **18pt**, or **14pt bold**. The Understanding doc gives the px conversion explicitly: *"The ratio between sizes in points and CSS pixels is 1pt = 1.333px, therefore 14pt and 18pt are equivalent to approximately **18.5px** and **24px**"* ([Understanding SC 1.4.3](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html), 🟢).

> **Practical rule for our type scale:** everything below **24px regular / 18.5px bold** must clear **4.5:1**. Since almost all console text is 12–14px, treat **4.5:1 as the floor for all text**, full stop. Only page titles get the 3:1 concession — and we won't take it.

**Exemptions** (🟢): incidental text in images, logotypes, and **inactive/disabled UI components** have no contrast requirement. Disabled controls are the only place we may go low-contrast — and even then, disabled state must not be the *only* indicator.

Note SC 1.4.1 is **Level A** — the *lowest* conformance bar. Encoding severity by color alone doesn't just fail AA, it fails the baseline.

### 5.2 Never encode by color alone

The intent of SC 1.4.1 is *"to ensure that all sighted users can access information that is conveyed by color differences, that is, by the use of color where each color has a meaning assigned to it"* ([Understanding SC 1.4.1](https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html), 🟢). Severity is *exactly* "color with a meaning assigned to it".

There is a partial escape hatch, and it's worth quoting precisely: *"If content is conveyed through the use of colors that differ not only in their hue, but that also have a significant difference in lightness, then this counts as an additional visual distinction, as long as the difference in relative luminance between the colors leads to a contrast ratio of 3:1 or greater."* **But** — *"if content relies on the user's ability to accurately perceive or differentiate a particular color an additional visual indicator will be required regardless of the contrast ratio."* (🟢)

Severity badges rely on differentiating red-from-orange-from-amber. Red/orange/amber are **precisely** the confusion axis for deuteranopia and protanopia (~8% of men). **So the lightness escape hatch does not save us. We need redundant encoding, always.**

**The VectaSec severity mark — four redundant channels:**

| Severity | Text | Icon | Shape | Color |
|---|---|---|---|---|
| Critical | `CRIT` | ⬤ filled octagon | filled | red |
| High | `HIGH` | ◆ filled diamond | filled | orange |
| Medium | `MED` | ▲ filled triangle | filled | amber |
| Low | `LOW` | ● filled circle | outline | blue |
| Info | `INFO` | ─ dash | outline | grey |

**The test:** screenshot the console, convert to greyscale, and confirm every severity is still readable. If it isn't, it's broken. Bake this into CI as a visual-regression check — it's cheap and it never regresses silently.

Additionally:
- **Order is a channel.** Sort by severity descending by default; position itself carries meaning.
- **Never rely on a bare colored dot.** The label ships with it. Always.

### 5.3 Dark-mode-safe severity

Two constraints fight each other in dark mode:

1. **Saturated colors vibrate on dark backgrounds**, causing eye strain, and struggle to pass contrast. Guidance is to desaturate accent colors by ~20–30% for dark mode ([atmos.style](https://atmos.style/blog/dark-mode-ui-best-practices), 🟡).
2. **Pure black is wrong.** White-on-black is *so* high-contrast it becomes uncomfortable; the standard advice is dark grey, with Material Design's `#121212` the canonical value ([atmos.style](https://atmos.style/blog/dark-mode-ui-best-practices), 🟡).

⚠️ **Confidence note:** I could **not** verify Material's `#121212`, the 15.8:1 figure, or the elevation-overlay percentages against Google's own docs — `design.google` and `m2.material.io` are JS-rendered and returned no specification text to either fetch. These values are **🟡 secondary-source only**. Our palette below does not depend on them; I cite them only as corroboration for the *direction* (dark grey over pure black).

**The resolution:** brand red `#E5484D` is a fine *badge fill* but a poor *text color* on dark. So we split the token:

- **`fg`** — a lightened, slightly desaturated tint, used for text/icons. Must clear 4.5:1.
- **`solid`** — the saturated hue, used only for fills, bars, and graph nodes (non-text → 3:1).
- **`bg`/`border`** — a dark tint for soft badges.

Verified numbers in §7.3. This split is exactly why the naive "one hex per severity" approach fails accessibility.

---

## 6. Data-dense table design

Concrete guidance from enterprise table practice ([Pencil & Paper](https://www.pencilandpaper.io/articles/ux-pattern-analysis-enterprise-data-tables), 🟡 — well-regarded practitioner source, not a spec):

### 6.1 Density and alignment

- **Row heights: condensed 40px / regular 48px / relaxed 56px**, user-switchable and persisted.
- **Left-align text; right-align numbers** (easier comparison, decimal alignment). Qualitative numbers — dates, postal codes, IDs — may be left-aligned.
- **Use monospace/tabular figures for numeric columns** so `$1,111.11` doesn't optically shrink next to `$999.99`. For us: counts, ports, CVSS, timestamps, fingerprints.
- **Headers match column alignment.**
- **Vertical align:** center when rows vary ≤3 lines; top-align beyond that.
- **Avoid zebra striping** — it collides with hover/selection/severity-tint states. Use 1px light dividers instead.

> ⚠️ For VectaSec, 40/48/56px is **too tall**. Those numbers come from general enterprise SaaS. A findings queue is closer to a log viewer, where analysts want 200 rows on screen. **My recommendation (🟡): 32 / 40 / 48px**, with 32px as a real "compact" mode. The principle to preserve — *"use a compact density mode with sane type instead of shrinking type to fit more rows"* — matters more than the exact values: **never drop below 12px type**; shrink padding, not text.

### 6.2 Columns

- **Sticky header** — non-negotiable at our row counts.
- **Pin the leftmost column** (severity + title) so identity survives horizontal scroll.
- **User-controlled show/hide/reorder**, with a reset-to-default.
- **Persist customization** (columns, density, sort) across sessions — with reset always available.

### 6.3 Sorting & filtering

- **Sort from the column header**, chevron indicator, toggling asc/desc/default.
- **Sensible default sort** — for us, contextual risk desc, then last_seen desc.
- **Faceted filters + a query bar.** Facets for exploration (severity, status, system, rule), query bar for precision. Datadog's `evaluation:fail` style query syntax is the model (🟢).
- **Highlight matched text** in results — strengthens the query↔result connection.
- **Filter state lives in the URL** (§8.4).

### 6.4 Row detail

Pencil & Paper offers five patterns — expandable rows, tooltips, modals, quick-view sidebars, full-screen — and calls the **quick-view sidebar the most scalable** (🟡).

**For VectaSec: sidebar as primary, full page as the shareable permalink.** A finding has evidence + graph + remediation + compliance — too much for a tooltip, too important to trap in a modal. The sidebar keeps queue context (the analyst can `j`/`k` through findings with the panel open — a huge triage accelerant), and `/findings/[id]` gives a linkable page for Slack/Jira. Build both over one component.

### 6.5 Empty states

*"Displaying a blank table when no data matches filters or searches leaves users confused about whether something is broken or if they need to take action."* Always include clear empty states with actionable next steps (🟡).

**Five distinct empty states — they are not the same and must not share a component:**

| State | Message | Action |
|---|---|---|
| **No connections** | "Connect your first system" | → onboarding |
| **Scan never run** | "Connected. First scan starts in ~2 min." | → Run now |
| **Scanning** | Skeleton + live progress (Realtime) | — |
| **Zero findings** | "No findings. 6 systems scanned 4m ago." | → view inventory |
| **Zero *matches*** | "No findings match these filters." | → **Clear filters** |

The last two are the ones everyone conflates, and it's a real bug: **"you are secure" and "your filter is too narrow" must never look alike** in a security tool. Always show *what was scanned and when* in the zero-findings state — an empty table with no provenance reads as broken, not as clean.

### 6.6 Loading states

- **Skeletons, not spinners**, for the table — preserves layout, communicates shape, no reflow.
- **Skeleton rows should match final row height exactly** or the page jumps (CLS).
- **Stream, don't block.** Findings arrive via Realtime; render rows as they land. React `<Suspense>` + streaming SSR maps onto this directly (§8.3).
- **Never let a scan block the console.** Scan progress is ambient (a strip), never a modal.
- **Stale-while-revalidate labeling:** "Updated 4m ago" beats a full-page spinner on refetch.

---

## 7. Design tokens

Dark-first, since security tooling is used in dark rooms for long shifts and every competitor is dark-first. Light mode is a first-class second.

**All ratios below were computed** with the WCAG relative-luminance formula (script in §7.7), not eyeballed. 🟢 for the math; 🟡 for the aesthetic choices.

### 7.1 Dark surfaces

Cool near-black with a blue cast (reads "technical"; avoids the muddy feel of neutral grey).

| Token | Hex | Use |
|---|---|---|
| `--bg` | `#0B0E14` | App background |
| `--surface` | `#12161F` | Cards, table |
| `--surface-raised` | `#1A1F2B` | Popovers, sidebar, hover |
| `--border` | `#262C3A` | Dividers (decorative) |
| `--border-strong` | `#3A4356` | Emphasis dividers |
| `--border-interactive` | `#616D85` | **Control outlines — 3.16:1 vs raised** ✓ |

> **Why `--border-interactive` exists.** `--border` (1.38:1) and `--border-strong` (1.95:1) **fail** SC 1.4.11's 3:1. That is *fine* for table dividers and card edges — decorative separators are not UI components. It is **not** fine for anything that is the sole visual indicator of a control (input outlines, unchecked checkboxes, secondary-button borders). Those must use `--border-interactive` (`#616D85`, computed **3.16:1** against the lightest surface). This distinction is the most commonly-missed accessibility bug in dark design systems — enforce it in review.

### 7.2 Dark text — computed

| Token | Hex | vs `--bg` | vs `--surface` | vs `--surface-raised` |
|---|---|---|---|---|
| `--text-primary` | `#E6EAF2` | **16.02:1** ✓ | 15.01:1 ✓ | 13.66:1 ✓ |
| `--text-secondary` | `#A3AEC2` | **8.64:1** ✓ | 8.09:1 ✓ | 7.37:1 ✓ |
| `--text-muted` | `#78849A` | **5.12:1** ✓ | 4.80:1 ✓ | 4.37:1 ⚠️ |

⚠️ `--text-muted` on `--surface-raised` computes **4.37:1** — **below 4.5**. Do not use muted text inside popovers/hover rows. Use `--text-secondary` there. (Kept in the table deliberately: this is a real trap, and silently deleting it would let someone rediscover it in production.)

### 7.3 Dark severity — computed

**Foreground** (text/icons — needs 4.5:1). All pass on all three surfaces:

| Severity | `fg` | vs `--bg` | vs `--surface` | vs `--surface-raised` |
|---|---|---|---|---|
| Critical | `#FF8A8A` | **8.51:1** ✓ | 7.98:1 ✓ | 7.26:1 ✓ |
| High | `#FFA766` | **10.09:1** ✓ | 9.46:1 ✓ | 8.61:1 ✓ |
| Medium | `#F2CC60` | **12.49:1** ✓ | 11.71:1 ✓ | 10.65:1 ✓ |
| Low | `#6FB6FF` | **9.02:1** ✓ | 8.46:1 ✓ | 7.70:1 ✓ |
| Info | `#A3AEC2` | **8.64:1** ✓ | 8.09:1 ✓ | 7.37:1 ✓ |

**Solid** (fills/bars/graph nodes — non-text, needs 3:1 vs background):

| Severity | `solid` | vs `--bg` | White text on it | Black text on it |
|---|---|---|---|---|
| Critical | `#E5484D` | **4.94:1** ✓ | 3.91:1 ✗ | 5.37:1 ✓ |
| High | `#F76B15` | **6.50:1** ✓ | 2.97:1 ✗ | 7.07:1 ✓ |
| Medium | `#FFC53D` | **12.24:1** ✓ | 1.58:1 ✗ | 13.31:1 ✓ |
| Low | `#3B9EFF` | **6.92:1** ✓ | 2.79:1 ✗ | 7.52:1 ✓ |

> **This table is why solid badges are a trap.** White text fails on *every* solid severity fill. Black text passes on all — but black-on-red badges look cheap and fight the dark theme. **Use soft badges instead** (below). If you ever need a solid fill with a label, the label must be black and ≥14px bold.

**Soft badges** (the recommended default — tinted bg + light fg):

| Severity | `bg` | `fg` | fg-on-badge |
|---|---|---|---|
| Critical | `#2E1116` | `#FF8A8A` | **7.66:1** ✓ |
| High | `#2B1808` | `#FFA766` | **8.87:1** ✓ |
| Medium | `#2A2208` | `#F2CC60` | **10.21:1** ✓ |
| Low | `#0E1F33` | `#6FB6FF` | **7.77:1** ✓ |
| Info | `#1C212B` | `#A3AEC2` | **7.21:1** ✓ |

Soft badge backgrounds sit at ~1.04–1.15:1 against `--surface` — intentionally subtle. They are **decorative tint only**; the text + icon + shape carry the meaning (§5.2), so SC 1.4.11 does not apply to the tint.

**Focus ring:** `#6FB6FF` — computed **9.02 / 8.46 / 7.70:1** across the three surfaces, comfortably over the 3:1 non-text bar. Use a 2px ring + 2px offset; never remove it.

### 7.4 Light mode — computed

| Token | Hex | vs `#FFFFFF` | vs `#F6F8FB` |
|---|---|---|---|
| `--text-primary` | `#0F1420` | **18.40:1** ✓ | 17.30:1 ✓ |
| `--text-secondary` | `#475069` | **8.02:1** ✓ | 7.54:1 ✓ |
| `--text-muted` | `#626C83` | **5.26:1** ✓ | 4.94:1 ✓ |

> Note: the obvious muted grey `#69738B` computes **4.46:1** on `#F6F8FB` — a hair under 4.5. Darkened to `#626C83` to pass. A 0.04 miss is invisible to the eye and fatal to an audit; this is why these get computed, not picked.

Light severity foregrounds:

| Severity | `fg` | vs white | badge `bg` | fg-on-badge |
|---|---|---|---|---|
| Critical | `#C3252A` | **5.80:1** ✓ | `#FDECEC` | 6.00:1 ✓ |
| High | `#A24A00` | **5.97:1** ✓ | `#FDF0E3` | 6.36:1 ✓ |
| Medium | `#7A5A00` | **6.38:1** ✓ | `#FBF3D9` | 6.97:1 ✓ |
| Low | `#0B5BB5` | **6.61:1** ✓ | `#E7F1FD` | 6.97:1 ✓ |
| Info | `#4A5568` | **7.53:1** ✓ | `#EFF1F5` | 7.63:1 ✓ |

Medium's `#7A5A00` is a dark olive, not a yellow — yellow simply cannot reach 4.5:1 on white. This is expected and correct; the icon and label carry severity, the hue only supports it.

### 7.5 Type scale

Console type is small and dense. **Every size here is below the 24px "large text" threshold, so all of it must clear 4.5:1** — which our text tokens do.

| Token | Size / line-height | Use |
|---|---|---|
| `--text-2xs` | 11px / 16px | Table meta, timestamps (uppercase, tracked) |
| `--text-xs` | 12px / 16px | **Table body — the workhorse** |
| `--text-sm` | 13px / 20px | Body, labels |
| `--text-base` | 14px / 20px | Default UI |
| `--text-lg` | 16px / 24px | Panel titles |
| `--text-xl` | 20px / 28px | Page titles |
| `--text-2xl` | 24px / 32px | Metrics |
| `--text-3xl` | 32px / 40px | Landing headline number |

**Fonts:**
- UI: `Inter` (or `system-ui`) with `font-variant-numeric: tabular-nums` on all numeric cells.
- Mono: `JetBrains Mono` / `ui-monospace` — **for all evidence, config, IDs, fingerprints.** Evidence in a proportional font doesn't read as evidence.

**11px floor.** Do not go below it, and use 11px only for de-emphasized meta — never for a value someone must act on.

### 7.6 Spacing & radii

**Spacing — 4px base.** Dense UI needs the 4/8/12 rungs to exist; general SaaS scales that start at 8 force either cramping or bloat.

| Token | px |
|---|---|
| `--space-1` | 4 |
| `--space-2` | 8 |
| `--space-3` | 12 |
| `--space-4` | 16 |
| `--space-5` | 24 |
| `--space-6` | 32 |
| `--space-7` | 48 |
| `--space-8` | 64 |

**Row heights** (see §6.1 — deliberately tighter than general-SaaS 40/48/56):

| Density | px |
|---|---|
| Compact | 32 |
| Default | 40 |
| Relaxed | 48 |

**Radii — small. Rounded corners read "consumer"; security tooling reads sharper.**

| Token | px | Use |
|---|---|---|
| `--radius-sm` | 3 | Badges, chips |
| `--radius-md` | 5 | Buttons, inputs, cards |
| `--radius-lg` | 8 | Panels, popovers |
| `--radius-full` | 9999 | Avatars, dots |

**Elevation.** In dark mode, elevation is communicated by **lighter surface**, not by shadow — shadows are nearly invisible on `#0B0E14`. Hence `--surface` → `--surface-raised`. (This is the same principle behind Material's elevation-overlay system; I could not verify their specific overlay percentages — see §5.3 — so we use explicit surface tokens rather than computed overlays. Simpler and more predictable anyway.)

### 7.7 Verification script

Ratios above were produced by `scripts/contrast-check.py` (drafted during this research at `/private/tmp/.../scratchpad/contrast.py`). **Port it into the repo and run it in CI.** It implements the WCAG relative-luminance formula:

```python
def srgb_to_lin(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

def luminance(hex_color):
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return 0.2126*srgb_to_lin(r) + 0.7152*srgb_to_lin(g) + 0.0722*srgb_to_lin(b)

def contrast(a, b):
    l1, l2 = luminance(a), luminance(b)
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)   # ≥4.5 text · ≥3.0 large text & non-text
```

**A palette that isn't tested is a palette that's wrong.** Two real failures were caught this way (`--text-muted` on raised; light muted at 4.46) — both invisible by eye.

---

## 8. Next.js 16 + Supabase auth

### 8.1 ⚠️ `middleware.ts` is deprecated — it's `proxy.ts` now

**This is a real, current change and it affects every Supabase SSR tutorial online.** Verified against Next.js docs **v16.2.10, last updated 2026-05-13** 🟢:

> *"The `middleware` file convention is deprecated and has been renamed to `proxy`."*

| Version | Change |
|---|---|
| **v16.0.0** | **Middleware deprecated → renamed to Proxy. Proxy defaults to the Node.js runtime.** |
| v15.5.0 | Middleware can use the Node.js runtime (stable) |
| v15.2.0 | Node.js runtime (experimental) |

Migration is a codemod:

```bash
npx @next/codemod@canary middleware-to-proxy .
```

It renames both the file and the exported function (`middleware` → `proxy`). Note the `runtime` config option is **not available** in Proxy files and setting it **throws** ([Next.js proxy docs](https://nextjs.org/docs/app/api-reference/file-conventions/proxy), 🟢).

**Why the rename:** the docs are candid — *"the term 'middleware' can often be confused with Express.js middleware"*, and *"this feature is recommended to be used as a last resort"*. The name "proxy" *"implies a network boundary in front of the app, which is how this feature behaves"* (🟢).

> **Read that as a design instruction:** Vercel is actively steering people *away* from putting logic here. Our Proxy should do exactly one thing — refresh the auth token and redirect unauthenticated users. Nothing else.

### 8.2 ⚠️ The auth footgun — and it has moved

The well-known advice is "never use `getSession()` on the server, use `getUser()`". **The Supabase docs have moved past that**, and the current text is 🟢:

> *"Never trust `supabase.auth.getSession()` inside server code such as Proxy. It isn't guaranteed to revalidate the Auth token."*

But the recommended replacement is now **`getClaims()`**, not `getUser()` ([Supabase Next.js SSR docs](https://supabase.com/docs/guides/auth/server-side/nextjs), 🟢). The reference docs are explicit ([getClaims](https://supabase.com/docs/reference/javascript/auth-getclaims), 🟢):

> *"Prefer this method over `GoTrueClient.getUser` which always sends a request to the Auth server"*

**How the three actually differ:**

| Method | Verification | Network | Use for |
|---|---|---|---|
| `getSession()` | **None on the server** — reads the cookie | No | ❌ **Never in server code** |
| `getClaims()` | Verifies JWT signature against JWKS (`/.well-known/jwks.json`); with **asymmetric** keys, verified **locally via WebCrypto**, usually no network call. With **symmetric** keys it calls the Auth server every time. | Usually no | ✅ Route protection, reading `sub`/`tenant_id` |
| `getUser()` | *"Performs a network request to the Auth server"* — authoritative | **Always** | ✅ When you need server-confirmed freshness/revocation |

Supabase's own framing: `getUser()` carries a network cost, so use it *"when fresh, server-confirmed information is essential — not for page protection alone"* (🟢).

**Context:** asymmetric JWT signing keys became opt-in during 2025, and *"starting October 1, 2025, all new projects will use asymmetric JWTs by default"* (🟡 — from search-result summaries of [Supabase's JWT signing keys blog](https://supabase.com/blog/jwt-signing-keys) and [signing keys docs](https://supabase.com/docs/guides/auth/signing-keys); I did not fetch these pages in full — **verify our project's key type before relying on the local-verification performance claim**).

> ⚠️ **The trade-off that matters specifically to us.** `getClaims()` verifies a *signature*; it does **not** check revocation. As long as the token is valid, it returns the data as it was when the token was granted. **For a security product, a revoked/demoted user continuing to hold access until token expiry is a real finding — against us.**
>
> **Recommendation:**
> - `getClaims()` for routine page/route protection (fast, correct, signature-verified).
> - `getUser()` on **privilege-sensitive operations** — role changes, suppression creation, connection/credential changes, API-key issuance, tenant admin.
> - **Set a short access-token TTL** so the `getClaims()` staleness window stays small. This is the mitigation that makes the fast path safe.
>
> (🟡 — this split is my synthesis for our threat model, not a Supabase recommendation. Supabase notes a GitHub issue exists that the SSR guides still use `getUser` — [supabase#39947](https://github.com/supabase/supabase/issues/39947) — so the ecosystem is mid-migration and guidance may shift again. Re-check at implementation time.)

### 8.3 Proxy is NOT an authorization boundary

The Next.js docs are unambiguous, and this is the highest-severity item in this section 🟢:

> *"Server Functions are not separate routes in this chain. They are handled as POST requests to the route where they are used, so a Proxy matcher that excludes a path will also skip Server Function calls on that path. A matcher change or a refactor that moves a Server Function to a different route can **silently remove Proxy coverage**. Always verify authentication and authorization inside each Server Function rather than relying on Proxy alone."*

And on Server Actions:

> *"when a Server Action is created and exported, it is reachable via a direct POST request, not just through your application's UI... you should still treat Server Actions as reachable via direct POST requests and verify authentication and authorization inside each one."*

> *"A page-level authentication check does not extend to the Server Actions defined within it. Always re-verify inside the action."*

([Next.js Data Security](https://nextjs.org/docs/app/guides/data-security), v16.2.10, updated 2026-06-23, 🟢)

**For VectaSec this is doubly true**: our real boundary is **Postgres RLS**, exactly as the build plan says. Proxy is a UX redirect. Server Actions re-verify. RLS is the guarantee. Three layers, and only the last one is load-bearing.

**Data Access Layer (recommended for new projects) 🟢.** A DAL should *"only run on the server, perform authorization checks, and return safe, minimal Data Transfer Objects (DTOs)"*. Also: *"Secret keys should be stored in environment variables, but only the Data Access Layer should access `process.env`."*

Maps onto our repo as:

```
apps/web/
  data/                 # DAL — 'server-only'
    findings.ts         # getFindingsDTO(), getFindingDTO(id)
    graph.ts            # getBlastRadiusDTO(id)  ← recursive CTE stays here
    auth.ts             # cache(getCurrentUser) / getClaims wrapper
  app/
    (console)/findings/page.tsx        # RSC — calls DAL
    (console)/findings/[id]/page.tsx   # RSC
  actions/
    triage.ts           # 'use server' — thin; re-verifies; delegates to DAL
```

Additional 🟢 practices worth adopting verbatim:
- `import 'server-only'` in the DAL — build error if it leaks clientward.
- **Wrap the auth read in React `cache()`** — the docs' own pattern; gives one auth read per request, and *"discourages passing it from Server Component to Server Component which minimizes risk of passing it to a Client Component."*
- **Return DTOs, not rows.** *"Only return what the UI needs, not raw database records."* Findings carry config snippets and `raw jsonb` — **`resources.raw` must never reach the client wholesale.** This is a genuine leak risk in our schema.
- **Check authorization, not just authentication** — *"does this user have permission to act on this specific resource?"* (IDOR prevention). For us RLS covers this, but the Server Action should still fail closed.
- **Consider `experimental.taint`** (`taintObjectReference` / `taintUniqueValue`) as defense-in-depth for `raw` blobs and collector credentials — the docs are clear it's *"an additional layer of protection"*, not a substitute for DAL filtering.

The docs' **audit checklist** is worth adopting as our PR review checklist verbatim (🟢): is there an isolated DAL? are DB packages and env vars imported outside it? do `"use client"` props expect private data? are `"use server"` args validated and the user re-authorized? are `[param]` folders validated? — *"`proxy.ts` and `route.ts`: Have a lot of power. Spend extra time auditing these."*

### 8.4 Server Components vs client interactivity

The split that fits the console:

| Concern | Where | Why |
|---|---|---|
| Findings list data | **RSC** | Filter state in `searchParams` → server query. Shareable URLs for free. |
| Facet counts | **RSC** | Aggregate in Postgres, not in JS |
| Finding detail | **RSC** | Evidence + citations are static per finding |
| Blast-radius traversal | **RSC** (DAL) | Recursive CTE server-side; ship a small path DTO |
| Graph canvas | **Client** | Pan/zoom/expand |
| Table interactions (sort/select/keyboard) | **Client** | Local state |
| Triage actions | **Server Actions** | Mutations; re-verify inside |
| Live scan progress | **Client** | Supabase Realtime subscription |
| Live findings stream | **Client** island in RSC shell | Realtime → prepend rows |

**Notes:**
- **Filters in `searchParams`, not `useState`.** Gives shareable URLs, server-side filtering, and no client-side re-fetch waterfall. It's also just the App Router grain.
- **Realtime is inherently client-side** (WebSocket). Keep it a small island: an RSC-rendered table with a thin client wrapper that prepends live rows. Don't make the whole page a client component to get live updates — that's the most common App Router regression.
- **Stream with `<Suspense>`** — the findings table streams in while the shell and facets render instantly.
- Mutations must never be render side-effects; the docs explicitly prevent setting cookies / revalidating in render (🟢).

### 8.5 Reference Proxy

Consolidating §8.1–8.3 (🟡 — my composition of two 🟢 sources; the Supabase docs' exact current snippet should be diffed at implementation time):

```ts
// proxy.ts  (was middleware.ts — renamed in Next.js 16)
import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

export async function proxy(request: NextRequest) {
  let response = NextResponse.next({ request })

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (cookiesToSet) => {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value))
          response = NextResponse.next({ request })
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options))
        },
      },
    }
  )

  // getClaims — verifies the JWT signature (locally, with asymmetric keys).
  // NOT getSession(): "isn't guaranteed to revalidate the Auth token".
  const { data } = await supabase.auth.getClaims()

  if (!data?.claims && !request.nextUrl.pathname.startsWith('/login')) {
    return NextResponse.redirect(new URL('/login', request.url))
  }

  // This redirect is UX only. RLS is the boundary. Server Actions re-verify.
  return response
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|login|auth).*)'],
}
```

⚠️ Two documented matcher gotchas 🟢:
1. **Without a matcher, Proxy runs on every request** including `_next/static` and `public/` — *"auth logic or redirects can unintentionally block CSS, JS, or images from loading."*
2. **`_next/data` routes run Proxy even when excluded** by a negative matcher — *"intentional behavior to prevent accidental security issues where you might protect a page but forget to protect the corresponding data route."*

Also note `setAll` in Supabase's own pattern applies cache headers (`Cache-Control`, `Expires`, `Pragma`) *"to prevent CDN caching that could leak sessions"* (🟢). Default cookie name is `sb-<project_ref>-auth-token`.

---

## 9. Open questions & low-confidence items

Flagged honestly rather than papered over:

| Item | Confidence | Action |
|---|---|---|
| Material Design `#121212`, 15.8:1, elevation-overlay percentages | 🔴 | **Unverifiable via fetch** — `design.google` and `m2.material.io` are JS-rendered and returned no spec text. Our palette does not depend on these. Do not cite them as fact. |
| Wiz / Orca / Snyk / Aikido IA specifics | 🟡 | All from vendor marketing or comparison blogs — inherently biased. **No public design-system docs exist for these consoles.** To do this properly: get trial accounts and screenshot the real IA. Recommended before locking the design. |
| Supabase asymmetric-JWT default from 2025-10-01 | 🟡 | From search summaries; the blog/docs were not fetched in full. Verify our project's key type directly. |
| `getClaims` vs `getUser` split for privileged ops | 🟡 | My synthesis for our threat model. Ecosystem is mid-migration ([supabase#39947](https://github.com/supabase/supabase/issues/39947)) — re-check at implementation. |
| Row heights 32/40/48 (vs the sourced 40/48/56) | 🟡 | My adaptation for log-viewer density. **Validate with a real analyst on real data.** |
| UI status collapse 6→4 | 🟡 | My recommendation. Needs a design-partner check — `triaged` vs `in_progress` may matter to some teams. |
| Root-cause correlation (graph-based finding clustering) | 🔴 | Research-grade (DEPCOMM/WATSON/KAIROS). Real differentiator, real scope. **Do not commit to a timeline.** |
| Attribution Gradients study specifics (N, metrics) | 🟡 | PDF didn't extract cleanly. Thesis and authorship confirmed; details not. |
| Alert-fatigue figures (50–500B events/day, ~0.01% true-positive, 40% accuracy drop) | 🟢 | From the arXiv survey. Note the survey itself attributes some figures to industry reports — solid for directional use, verify before customer-facing collateral. |

**The biggest gap:** everything in §2 about competitor IA rests on marketing pages. That's the weakest evidence in this document. Before committing to the IA, get hands on Wiz/Orca/Datadog trials — an hour each would upgrade §2 from 🟡 to 🟢.

---

## 10. Sources

All fetched 2026-07-17. Only URLs actually retrieved are listed.

**Specs (🟢)**
- [WCAG 2.2 Recommendation](https://www.w3.org/TR/WCAG22/) — SC 1.4.3 (4.5:1 / 3:1), SC 1.4.11 (3:1), SC 1.4.1 (Level A)
- [Understanding SC 1.4.3 Contrast (Minimum)](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html) — 1pt = 1.333px; 14pt≈18.5px, 18pt≈24px; exemptions
- [Understanding SC 1.4.1 Use of Color](https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html) — intent, 3:1 lightness caveat, "additional visual indicator required regardless of contrast ratio"

**Next.js (🟢 — v16.2.10)**
- [proxy.js file convention](https://nextjs.org/docs/app/api-reference/file-conventions/proxy) — middleware→proxy rename (v16.0.0), codemod, matcher gotchas, Server Function coverage warning
- [How to think about data security in Next.js](https://nextjs.org/docs/app/guides/data-security) — DAL, DTOs, `server-only`, taint, Server Action re-verification, audit checklist

**Supabase (🟢 unless noted)**
- [Server-Side Auth for Next.js](https://supabase.com/docs/guides/auth/server-side/nextjs) — "Never trust `getSession()` inside server code such as Proxy"; getAll/setAll; cache headers
- [JavaScript reference: getClaims](https://supabase.com/docs/reference/javascript/auth-getclaims) — JWKS verification, asymmetric/local vs symmetric/network, "prefer this method over getUser"
- [supabase#39947 — SSR auth guides use getUser instead of getClaims](https://github.com/supabase/supabase/issues/39947) — 🟡 surfaced via search, not fetched
- [JWT Signing Keys (blog)](https://supabase.com/blog/jwt-signing-keys) · [Signing Keys (docs)](https://supabase.com/docs/guides/auth/signing-keys) — 🟡 not fetched in full

**Research (🟢)**
- Ndichu, Yamada, Ban, Ozawa, Takahashi & Inoue, *AI-Driven Security Alert Screening and Alert Fatigue Mitigation in SOCs: A Comprehensive Survey*, [arXiv:2605.08316](https://arxiv.org/html/2605.08316v1) (May 2026) — four-stage taxonomy; alert volumes; 0.01% true-positive; 40% accuracy drop; DeepCASE cluster labeling; DEPCOMM −97.5%
- Kambhamettu, Hwang, Laban & Head, *Attribution Gradients: Incrementally Unfolding Citations for Critical Examination of Attributed AI Answers*, [arXiv:2510.00361](https://arxiv.org/pdf/2510.00361) (UIST '26, Nov 2026) — progressive disclosure of citations

**Practitioner / vendor (🟡)**
- [Pencil & Paper — Enterprise Data Tables](https://www.pencilandpaper.io/articles/ux-pattern-analysis-enterprise-data-tables) — 40/48/56px rows, alignment, sticky headers, pinning, empty states, sidebar pattern
- [Datadog — Explore Misconfigurations](https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/findings/) — group-by-any-facet, query bar
- [Datadog — Investigate Security Signals](https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/signals_explorer/) — Open / Under Review / Archived; assignment; side panel
- [Wiz Security Graph](https://www.wiz.io/lp/wiz-security-graph) · [Wiz — Graph for cloud IR](https://www.wiz.io/blog/wiz-security-graph-enhances-cloud-incident-response) — three graph questions; blast radius; "View in graph"
- [Snyk vs Aikido](https://snyk.io/comparison/snyk-vs-aikido/) — Risk Score, 12+ contextual factors, reachability
- [AYDesign — AI citation & source UI patterns 2026](https://www.aydesign.ai/blog/ai-citation-source-ui-patterns-2026) — seven patterns, anti-patterns, high-stakes requirements
- [7wData — Citations as user-visible proof of grounding](https://7wdata.be/uncategorized/citations-grounding-proof/) — citations as trust surface
- [atmos.style — Dark Mode UI Best Practices](https://atmos.style/blog/dark-mode-ui-best-practices) — avoid pure black, desaturate 20–30%, elevation via lighter surface
