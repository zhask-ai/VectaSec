# VectaSec Research Corpus

**Compiled:** 2026-07-17 · **Status:** research input, not shipped product spec

Nine documents that ground VectaSec's detection engine, compliance module, console, and positioning in verified, citable sources. This is the layer that exists so nobody has to reconstruct a config key, a requirement text, or an incident timeline from memory later.

**Read this first:** every document in this corpus tags its own claims by confidence, and several contain explicit *do-not-use* lists. Nothing here is safe to paste into a pitch deck, a customer email, or a detector without checking the tag on the specific claim. That discipline is the point — we are a security-posture vendor, and a vendor that launders unverified statistics into facts is the problem we sell against.

---

## The documents

### Detection — rulepacks

Per-rule implementation specs. Each rule states the exact config key or API field, the failing condition, the evidence string, severity, false-positive risk, remediation, and source.

| Doc | Rules | What it covers |
|---|---:|---|
| [`rulepack-kafka.md`](./rulepack-kafka.md) | 20 | Apache Kafka posture via read-only `AdminClient` — listeners/transport, authorizer + ACL breadth, SASL, TLS, topic governance, durability, legacy ZK. Includes the per-broker `describeConfigs` invariant that silently false-negatives every rule if you get it wrong. |
| [`rulepack-rabbitmq.md`](./rulepack-rabbitmq.md) | 16 | RabbitMQ via the Management HTTP API — `guest` remote login, default/EOL versions and CVEs, wildcard permissions, admin-tag sprawl, TLS peer verification, cluster port exposure. Turns on the `listeners`-vs-`contexts` schema distinction. |
| [`rulepack-kong.md`](./rulepack-kong.md) | 16 | Kong Gateway (OSS + Enterprise) via read-only Admin API `GET`s — Admin API exposure and auth, RBAC, per-route auth/rate-limit/size plugins, CORS, version CVEs. Includes the shared plugin-scope resolver that five rules depend on. |
| [`rulepack-mcp.md`](./rulepack-mcp.md) | 18 | MCP servers at spec revision 2025-11-25 — OAuth/PRM/PKCE/audience, transport and origin, session handling, tool-description poisoning, stdio command exposure, gateway lethal-trifecta composition. Every session/handshake rule is version-gated against the 2026-07-28 revision. |

Total: **70 rules** across four packs.

### Platform and control plane

| Doc | What it covers |
|---|---|
| [`platform-apis.md`](./platform-apis.md) | The exact read-only client APIs the connectors call — `confluent-kafka-python` 2.15.0, Kong Admin API 3.9.3 OSS, RabbitMQ Management API 4.3.2, MCP introspection over Streamable HTTP. Response shapes were **captured from live systems in Docker**, not copied from docs. Ends with version pins and eleven cross-cutting traps ranked by damage-if-missed. |
| [`supabase-hardening.md`](./supabase-hardening.md) | Multi-tenant Postgres/Supabase control-plane hardening — `FORCE ROW LEVEL SECURITY`, `USING` vs `WITH CHECK`, restrictive tenant guards, RLS performance, `SECURITY DEFINER` search-path pinning, the `tenant_members` recursion trap, pgmq, pg_cron, Vault, Realtime, the 2025 API-key migration, and a consolidated CI gate. |

### Product and positioning

| Doc | What it covers |
|---|---|
| [`threat-landscape.md`](./threat-landscape.md) | The evidence base for the narrative — Salesloft Drift, Gainsight, Klue, Snowflake, Cloudflare/Okta, MOVEit; NHI statistics with provenance tags; measured internet-exposure data; Kafka/RabbitMQ/Kong/Istio/MCP CVEs. Every claim carries a `[VERIFIED]` / `[REPORTED]` / `[VENDOR CLAIM]` / `[VENDOR TELEMETRY]` / `[UNVERIFIED]` / `[FABRICATED]` tag. **§8 is a hard do-not-use list** — including a CVE that does not exist and a statistic no vendor published. |
| [`compliance-mapping.md`](./compliance-mapping.md) | Rule IDs → PCI DSS 4.0.1, DORA, NIS2, HIPAA controls, plus OSCAL export design. Not a flat dict: the mapping is `(rule, asset_scope_tags, tenant_frameworks) → [(framework, control, relation, confidence)]`, and findings can only ever move a control to `fail`, never to `pass`. |
| [`console-ux.md`](./console-ux.md) | Console design research — information architecture, findings-as-workflow, evidence/citation UX, severity color with **computed** (not estimated) WCAG contrast ratios, data-dense table design, design tokens, and Next.js 16 + Supabase auth conventions. |

---

## Research method

Each document was produced by the same three-stage pipeline.

**1. Parallel research.** Independent passes per topic against primary sources — vendor documentation, project source code, specs, NVD, regulator publications, first-party incident disclosures. For `platform-apis.md`, "primary source" meant standing the real software up in Docker (Kafka 4.3.1, Kong 3.9.3, RabbitMQ 4.3.2, MCP SDK 1.28.1) and capturing actual responses.

**2. Adversarial verification.** Every rule was independently re-checked by a verifier whose job was to break it, against five questions:

| Check | The failure it catches |
|---|---|
| **Real config key** | The key/field exists, is spelled correctly, and is actually reachable on the surface the scanner reads. Kills rules keyed on a field that a documentation summary invented, or on an array that never carries the value (RabbitMQ `listeners` vs `contexts`). |
| **Read-only checkable** | The rule is evaluable from read-only calls with no side effects. Kills rules needing `tools/call`, a host shell, or a write. Anything requiring an active probe is marked ACTIVE and gated behind explicit consent. |
| **Source supports the claim** | The cited source actually says what the rule asserts — not a plausible neighbouring statement. Kills inferred defaults and fabricated CVEs. |
| **Severity** | The severity matches what the scanner can actually establish, capped where the vantage point cannot see exposure, reachability, or data sensitivity. |
| **False-positive risk** | The rule survives contact with normal deployments — service meshes, TLS-terminating proxies, CI brokers, provisioning accounts, managed providers. Rules that could not be scoped down were split or dropped. |

Verification outcome: **6 rules dropped, 70 corrected.** Corrections are applied inline; where a correction changed a rule materially, the reasoning is preserved in the doc rather than silently overwritten.

**3. Synthesis.** Corrected rules written up as implementation specs, with the collection sequence, three-state outcome model (`PASS` / `FAIL` / `NOT-ASSESSABLE` — never two-state), suppression toggles, dedup and correlation logic each pack needs.

### Two invariants the verification enforced everywhere

- **Absence of evidence is not evidence of absence.** A denied API call, a missing payload key, or an empty result set is `NOT-ASSESSABLE`, never `PASS`. Both the Kafka and RabbitMQ packs name fail-open coercion as their single largest correctness risk, and the compliance mapping applies the same rule at the control level: a finding can prove `fail`; a finding's absence can never prove `pass`.
- **Never assert what the vantage point cannot see.** "Internet-exposed", "requires no user consent", "spawned a subprocess", "the AS does not support PKCE" — each was struck from an evidence claim during verification because the scanner cannot establish it from the surface it reads.

---

## Confidence and gaps

Honest accounting. The corpus is strong on things we could execute or fetch, and materially weaker on regulatory text, competitor design, and internet-exposure counts.

### Strongest material

- **API shapes in `platform-apis.md`** — captured from live systems, not documentation. The highest-confidence content here.
- **Postgres/Supabase RLS semantics** — verified against PostgreSQL and Supabase official docs.
- **WCAG contrast ratios** — computed with a script that is included, not estimated.
- **Incident facts in `threat-landscape.md`** tagged `[VERIFIED]` — first-party disclosures from Google GTIG/Mandiant, Cloudflare, Okta, Codecov, Microsoft, CISA.
- **RabbitMQ and Kong rule mechanics** — read from project source, with the exact files and functions cited.

### Known weak points

| Area | Status |
|---|---|
| **PCI DSS requirement text** | Quoted from a **vendor reproduction** (a Genesys responsibility matrix), not the standard — the PCI SSC PDF sits behind a click-through and could not be fetched. **Diff every quoted string against the official PDF before any customer-facing use.** Which requirements sit in the 51 future-dated set is secondary-sourced beyond the two the PCI SSC blog names. |
| **DORA and NIS2 article text** | From third-party mirrors (`digital-operational-resilience-act.com`, `nis-2-directive.com`); the EUR-Lex fetch truncated before the operative articles. The NIS2 CJEU referral date is contested between two sources; the four countries and the fact of referral are confirmed. The "22 of 27 transposed" count is secondary-only — **do not put a live count in the product.** |
| **HIPAA NPRM contents** | Only the *status* is verified (still a Proposed Rule, RIN 0945-AA22). Contents, the July 2027 target, and the ~$9bn cost estimate are search-summary only. **Do not repeat to customers.** |
| **Internet-exposure counts for Kafka / RabbitMQ / Kong** | **We have none.** Shadowserver is JS-rendered and its API needs auth; Censys/Shodan need API keys we did not have. Kong Admin API exposure is a well-known misconfiguration we currently cannot quantify. First-party scan data would be more defensible than anyone's citation — and is a product asset, not just research. |
| **Competitor IA (Wiz / Orca / Snyk / Datadog)** | The weakest evidence in the corpus. All from vendor marketing and comparison blogs; no public design-system docs exist. `console-ux.md` names this as its biggest gap. **Get trial accounts before locking the IA.** |
| **Kafka version detection** | AdminClient exposes no broker version string, so *every* version-based Kafka CVE rule needs an out-of-band version source. The CVE table is real; the trigger for it is not yet built. |
| **Kong CVE coverage** | Genuinely thin — only four NVD records mention Kong Gateway, and Kong ships most fixes without CVE assignment. Version rules are a floor, not a picture. Kong being near-CVE-free is implausible; the NVD CPE-based search has not been run. |
| **RabbitMQ CVE version ranges** | `VERSION.UNPATCHED_CVE` and `CVE.OAUTH_SECRET_DISCLOSURE` currently rest on a **secondary source** (thehackernews.com) for ranges; cve.org returned an empty shell and GHSA pages render without CVE ids. **Confirm against the vendor advisory before shipping.** |
| **RabbitMQ field shapes** | Read from `main` (4.3-era). Shapes on 3.13 / 4.0–4.2 are assumed identical but unverified. Validate against a 3.13 broker before claiming support for that series. |
| **Kong field-level Admin API details** | The fullest retrievable field-level reference is an archived **2.0.x** page — five majors old, authoritative for response shape only. Verify against a live 3.x node before shipping detectors. |
| **MCP spec churn** | The pack targets 2025-11-25. The **2026-07-28 revision publishes in 11 days** and removes `initialize` and `MCP-Session-Id` — the surfaces several rules read. Isolation points are marked; the pack must be re-verified on publication. |
| **MCP exposure statistics** | Verified: Knostic's 1,862 Shodan-found servers with 119 manually confirmed. The Censys figures are cited as primary-fetched in `threat-landscape.md` but marked *not verified to primary* in `rulepack-mcp.md` — **the corpus contradicts itself here and the discrepancy is unresolved.** Resolve before either figure is used externally. |
| **Supabase specifics** | Ten open items listed in `supabase-hardening.md` §13, including `realtime.broadcast_changes()` parameter order, `pgmq.read_with_poll` signatures, partitioned-queue support, Supavisor + transaction-local `set_config` behaviour, and the legacy API-key removal date. |

### Counting caveat

The recorded RabbitMQ count of **16** does not match a naive heading count of 17. The extra section is `RABBITMQ.ERLANG.DEFAULT_COOKIE`, which the pack itself marks conditional: it is only a rule if the product ships an unknown/manual disposition that renders separately from actionable findings — otherwise the doc says to drop it and fold the guidance into `CLUSTER.DIST_PORT_EXPOSED`. That product decision has not been made. The `rulepack-mcp.md` header likewise says "18 primary + 6 split-out sub-rules" while four split-outs carry headings; the primary count of 18 is what the packs agree on. **Treat all four counts as post-verification and pre-implementation.**

### Not covered at all

- `*.SECRET.HARDCODED`, `KONG.WAF.MISSING`, and `*.ACCOUNT.STALE` — three rule families `compliance-mapping.md` §7 identifies as missing and mapping to *stronger, currently-audited* PCI requirements (8.6.2, 6.4.2, 7.2.5.1) than several rules already written. The first is called the highest-value missing rule in the corpus.
- MCP audit/telemetry (OWASP MCP08), shadow servers (MCP09), supply chain (MCP04), and output injection/ATPA — the last is undetectable at scan time by construction and needs a different collector.
- Istio bulletin → CVE mapping; the Klue incident (June 2026, four weeks old, most current proof the Drift playbook is live); Shai-Hulud 2.

---

## Conventions used across the corpus

- **Every doc names its own gaps.** `compliance-mapping.md` §8, `supabase-hardening.md` §13, `console-ux.md` §9, `threat-landscape.md` §8–9, and the "Implementation notes" tail of each rulepack. Read those sections before relying on the body.
- **Only fetched URLs are listed as sources.** Where a fetch failed or a page was JS-rendered, the doc says so rather than citing it anyway.
- **Third-party mirrors are labelled as mirrors.** Vendor reproductions of standards are labelled unofficial.
- **CVEs are verified against NVD before use.** A fabricated Kong CVE (CVE-2026-29413) passed every smell test except that one and is recorded in two docs specifically so it is not re-ingested. Pin CVE enrichment to the NVD API by CVE ID — never to keyword search, never to web search.
