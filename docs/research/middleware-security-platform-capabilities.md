# What a middleware-security platform must have — capability map & gap analysis

**As of 2026-07-17.** This is the answer to "what should our tool have that a mature middleware
security platform has, and where are we against it." It is grounded in a 12-agent research sweep
across the adjacent, more-established posture categories (CSPM / DSPM / CNAPP / ASPM / CIEM), the
API-security vendor landscape (Salt, Traceable, Cequence, Noname/Akamai, Wallarm, Wiz, 42Crunch,
StackHawk), the API gateways (Kong, Tyk, NGINX, Traefik, Apigee, AWS, Azure), message brokers,
service meshes, iPaaS platforms, and the MCP/agent-gateway frontier. Sources are listed at the end.

The honest framing up front, from the CNAPP research: analysts expect **one integrated platform on
a single data model (ideally a graph), not loosely-coupled modules** — and buyers are told to
"rank enterprise functionality into required / preferred / optional" and run functional pilots.
So this document mirrors exactly how a buyer will grade VectaSec: capability by capability, with a
**built / partial / not-built** status and file pointers. If a status isn't backed by a file, treat
it as aspirational.

Status legend: ✅ built & proven · 🟡 partial · ❌ not built.

---

## Part 1 — The capability taxonomy (the "table stakes" spine)

Every mature posture platform is built from the same five-layer spine. Here is each capability,
why buyers require it, and VectaSec's status.

### Sensing layer

**1. Asset discovery & inventory** — 🟡
Continuous, authoritative inventory of every in-scope asset. VectaSec discovers brokers, gateways,
queues, topics, routes, consumers, MCP tools via read-only connectors (`connect/*`), persists them
as `resources` with stable ext_ids, marks vanished assets `stale` rather than deleting. *Gap:* no
agentless cloud auto-discovery (a connector is pointed at a target, it does not enumerate an
estate); no shadow-asset discovery. **This is the single most-cited buyer capability — deepen it.**

**2. Connectors / collection (agent + agentless), broad coverage** — 🟡
5 read-only connectors: Kafka, RabbitMQ, Kong, Redis, MCP (`connect/{kafka,rabbitmq,kong,redis,mcp}`).
Add-a-file connector SDK (`@connector` + declared `ConnectorField` spec → auto-registers, appears in
the console form and CLI). A customer-side **Collector** exists for private networks (outbound-only,
credentials stay local). *Gap:* no cloud-provider agentless path (cross-account role), no
findings-import API for the long tail, no published coverage matrix. The research's "any platform"
bar (Wiz `/environments` pattern) wants a public, falsifiable support matrix — build one.

### Modeling layer

**3. Topology / dependency graph / blast-radius** — 🟡 (this is a natural VectaSec differentiator)
`graph.py` computes blast radius over `resources`+`edges` with per-path cycle guards and a depth
bound; the API exposes `/graph/blast-radius`. Kafka emits `broker→topic` edges; the NHI layer now
emits `credential→identity`, `grant→identity`, `grant→resource` edges. *Gap:* no **attack-path /
toxic-combination reasoning** as a first-class feature (though `DATA.EXPOSURE.SENSITIVE_PLAINTEXT` is
a hand-built instance of exactly this — see below); no choke-point identification. The graph is the
place VectaSec should win; attack-path analysis is the next investment.

### Analysis layer

**4. Misconfiguration / posture detection with a rule engine** — ✅ (the strong core)
85 deterministic detectors across 5 systems, auto-registered (`@detector`, drop-a-file). Per-detector
error isolation, suppression-with-expiry, and a **third honest outcome** (`not_assessable` — a
coverage gap, never a false pass) that most tools lack. Evidence ledger: every finding cites the
exact fact it read. *Gap:* no custom/policy-as-code rule authoring for customers yet; no IaC/shift-left
evaluation of the same rules.

**5. Vulnerability & CVE management** — 🟡
Version-based CVE checks exist where a version is readable (`REDIS.VERSION.RCE_CVE` for RediShell
CVE-2025-49844; RabbitMQ EOL/CVE rules; MCP SDK version notes). *Gap:* no CVE feed, no EPSS/KEV
enrichment, no SBOM. The research's RBVM bar (CVSS + EPSS + KEV + reachability) is unmet — but the
connectors that can't read a version record that honestly rather than passing.

**6. Data security & classification (DSPM)** — ✅ NEW
`classify.py` tags data-carrying resources (topics/queues/routes/MCP tools…) by inferred sensitivity
(PCI/PHI/PII/secrets/financial/auth) from naming signals, stored in `labels`, surfaced as chips and
an Overview lens. `DATA.SENSITIVE.INVENTORY` is the data-flow map. **The differentiator:**
`DATA.EXPOSURE.SENSITIVE_PLAINTEXT` is the "toxic combination" the Wiz/Noname research names as where
modern tools win — a PCI-named topic on a plaintext, no-authorizer broker fires **critical**, grounded
in both the naming signal and the broker config. Gateways and AWS punt data classification to the app
layer; the integration layer is exactly where regulated data flows, so this is whitespace VectaSec
owns. *Honest limit:* classification is inferred from naming (VectaSec reads config, not payloads) and
says "named like", never "contains".

**7. Identity & entitlement analysis — CIEM / NHI** — ✅ NEW (the positioning wedge)
`identity.py` derives a normalized Non-Human Identity model — `identity` / `credential` / `grant`
resources + edges — from what every connector already reads (Kafka ACL principals, Kong consumers +
credential counts, RabbitMQ users + permissions, Redis ACL users, MCP OAuth clients). A cross-system
NHI inventory (`/identities`) is what no single system's users screen shows. Detectors map to the
**OWASP Non-Human Identities Top 10**: `NHI.GRANT.WILDCARD` (NHI5 over-privilege), `NHI.IDENTITY.
SHARED_DEFAULT`, `NHI.CREDENTIAL.WEAK_HASH` (NHI4), `NHI.CREDENTIAL.STORAGE_UNVERIFIED` (honest
coverage gap). Credentials are **metadata only** — presence, type, hashing — never a secret value.
This is the category (Astrix/Entro/Oasis/GitGuardian) and the breach pattern (Salesloft Drift →
Gainsight OAuth) VectaSec leads with. *Gap:* no usage telemetry (stale/last-used), no rotation-age,
no third-party OAuth-grant blast radius across SaaS, no cross-connection identity correlation yet
(same principal in two systems — a query/console feature, not a detector).

**8. Risk prioritization / posture score & trend** — 🟡 NEW
`lib/posture.ts` + `vectasec posture`: one interpretable score from open findings, weighted by
severity, always shown beside the raw counts it came from (no magic number). Overview is now a real
dashboard: score, severity breakdown, coverage-gap honesty, NHI + sensitive-data lenses, "do this
now" worst-findings list, compliance strip. *Gap:* no trend-over-time (needs a `posture_snapshots`
table), no graph-context ranking (a finding on an attack path should outrank an isolated one), no
per-team/owner rollup, no CRQ.

### Action layer

**9. Remediation guidance, playbooks, ticketing, auto-remediation** — 🟡
Every finding carries structured `remediation` text; findings workflow (status/assign/suppress) via
the engine API with an audit row per mutation. Grounded AI triage (`ai.py`) with a citation gate.
*Gap:* no Jira/ServiceNow ticketing, no playbooks, no auto-remediation, no verification loop.

**10. Alerting / notification / routing + SIEM/SOAR** — ❌
`integrations` and `routing_rules` tables exist; no code. No Slack/email/webhook out, no SIEM export.
This is a hard enterprise procurement requirement — a near-term build (the tables are ready).

**11. Reporting & dashboards (exec + practitioner)** — 🟡
Practitioner views (findings queue, detail, evidence, assets, identities, scans) and an exec Overview
dashboard exist. *Gap:* no scheduled/exportable PDF/CSV reports, no saved views, no historical trend
reporting.

### Governance & platform layer

**12. Compliance & framework mapping, evidence/attestation** — ✅
`compliance/map.py` maps findings→controls for PCI DSS 4.0.1, DORA, HIPAA, NIS2, MCP-spec, evaluated
in the scan loop; a control can only reach `pass` via a human attestation (a clean scan never can),
and a live failing finding overrides it. The Overview compliance strip and `/compliance` render it.
The append-only evidence ledger + citation gate are enforced by Postgres, not app code. *Gap:* no
OSCAL export, no automated evidence bundles, no custom-framework builder, no SOC 2 window.

**13. Access control — SSO/SAML, RBAC/SCIM, multi-tenancy** — 🟡
Multi-tenancy is real and load-bearing: `FORCE RLS` on 18 tenant tables, tenant scoping enforced by
Postgres. Email+password sign-in works. *Gap:* no SSO/SAML, no SCIM, `tenant_members.role` is read by
nothing (no RBAC). Enterprise procurement gate — required before a second serious customer.

**14. Integrations & extensibility (API, connector SDK) + deployment models** — 🟡
Connector SDK is real (add-a-file). Dual delivery is a genuine moat: hosted multi-tenant SaaS AND
full on-prem self-host (self-hosted Supabase + services; `deploy/onprem/` Helm+Compose, lint-clean
but never booted). *Gap:* no public REST API for customers, no findings-import API, no webhook
ingestion, agentless cloud path unbuilt, on-prem unproven at runtime.

**15. Data lineage / provenance / evidence integrity** — 🟡 (a VectaSec-shaped differentiator)
The evidence ledger is append-only (UPDATE blocked by trigger) and every AI claim is citation-gated
in Postgres — stronger provenance than most tools ship. *Gap:* the ledger is tamper-evident against
UPDATE but not against DELETE+re-INSERT (STATUS.md gap 15); no hash-chaining/WORM mirror; no
cross-system data lineage (trace a data element across integrations — the natural integration-layer
play).

### Emerging

**16. AI-SPM / MCP & agent-gateway security** — 🟡 (early, and a land-grab)
The MCP connector + 19 detectors already cover tool-poisoning, auth-spec violations, transport, and
session handling, pinned to a spec revision. The research maps the frontier to the **OWASP MCP Top 10
(MCP01–MCP10)** and OWASP Agentic threats — VectaSec is unusually early here. *Gap:* no shadow-MCP-
server discovery across a fleet, no tool-definition pinning/rug-pull diffing, no runtime layer.

---

## Part 2 — Platform coverage (the "any platform" story)

"Any platform" is a claim buyers test against their own stack, so it must be falsifiable. Today:

| Category | Covered today | The reachable near-term set (research-scoped checks ready) |
|---|---|---|
| Message brokers / streaming | Kafka ✅, RabbitMQ ✅, Redis ✅ | NATS, Pulsar, ActiveMQ, IBM MQ, AWS SQS/SNS, Azure Service Bus, GCP Pub/Sub |
| API gateways | Kong ✅ | Tyk, NGINX/App Protect, Traefik, Apigee, AWS API Gateway, Azure APIM |
| Service mesh | — | Istio, Linkerd, Consul (checks fully scoped in research — mTLS-not-enforced, allow-all authz, wildcard rules) |
| iPaaS / integration | — | n8n (has a built-in audit API — easiest first), MuleSoft, Boomi, Workato, WSO2, Apache Camel, TIBCO |
| MCP / agent gateways | MCP ✅ | shadow-server discovery, gateway-policy posture, tool pinning |

The architecture makes each of these **one file** (a connector + a detector pack), and the research
docs (per category) contain the concrete, cited check-lists to implement them. There is **no CIS
Benchmark for any self-managed broker or service mesh** — which is itself the opportunity: VectaSec
should codify the vendor hardening guides + OWASP NHI/MCP Top 10s into its own benchmark.

---

## Part 3 — Where VectaSec wins vs. the market

The API-security incumbents (Salt, Traceable, Cequence, Noname, Wallarm) are **runtime, traffic-
analysis** tools for HTTP APIs; the gateways enforce inline but don't do posture; the CNAPPs
(Wiz/Orca) reach cloud-managed gateways but not self-hosted brokers/meshes/iPaaS. Three shared gaps
across all of them are VectaSec's whitespace:

1. **The integration layer itself** — brokers, queues, meshes, iPaaS flows — is unowned as a posture
   category. The API tools stop at HTTP; the CNAPPs stop at the cloud control plane.
2. **Non-human identity at the integration layer** — the actual attack surface of the 2023–2025
   OAuth-token breaches — has no dedicated posture home. VectaSec's NHI derivation now does.
3. **Object-level authorization + data classification** — every gateway and cloud provider explicitly
   punts these to the app layer. VectaSec's grant model + data classification + toxic-combination rule
   is exactly that layer.

Add the dual SaaS/on-prem delivery (a real requirement for this buyer that pure-SaaS API tools
can't meet), the deterministic-plus-grounded-AI evidence discipline, and the Postgres-enforced
integrity guarantees, and the position is defensible.

---

## Part 4 — Prioritized roadmap (cheapest-first among the highest-leverage)

Built this round: NHI/CIEM (#7), DSPM classification (#6), toxic-combination exposure, posture
score + dashboard (#8), Redis connector, `/identities`. The next moves, in order:

1. **Notifications / routing out (#10).** Tables exist; a webhook + Slack sender with severity/owner
   routing is a hard procurement gate and cheap. Add a findings-import API alongside (the long-tail
   coverage lever).
2. **Two or three more connectors (#2), testable first.** NATS + service mesh (Istio) have fully
   scoped check-lists and clear demo value; n8n's built-in audit API makes it the easiest iPaaS.
3. **Attack-path / toxic-combination as a first-class graph feature (#3).** Generalize
   `DATA.EXPOSURE.SENSITIVE_PLAINTEXT` into the graph: "internet-exposed + over-privileged NHI +
   sensitive data on one path" is the story that wins deals.
4. **Posture trend + owner rollups (#8).** A `posture_snapshots` table; show the score moving.
5. **SSO + RBAC (#13).** The `tenant_members.role` column is already there and read by nothing.
6. **Evidence integrity: hash-chained/mirrored ledger (#15).** Before anyone shows an auditor the
   word "tamper-evident."
7. **Cross-system NHI correlation + third-party OAuth blast radius (#7).** The Drift/Gainsight story,
   fully realized.

---

## Sources

Capability taxonomy (Gartner CNAPP/DSPM/CIEM/ASPM): wiz.io, orca.security, gartner.com market guides;
paloaltonetworks.com, securiti.ai, ibm.com (DSPM); microsoft.com/learn (CIEM).
NHI / OWASP: owasp.org/www-project-non-human-identities-top-10; astrix.security, entro.security,
oasis.security, gitguardian.com; cloud.google.com & unit42.paloaltonetworks.com (Salesloft Drift).
Brokers: kafka.apache.org, confluent.io, rabbitmq.com, docs.nats.io, pulsar.apache.org,
redis.io + wiz.io (RediShell CVE-2025-49844), activemq.apache.org (CVE-2023-46604), AWS/Azure/GCP docs.
API gateways & security: docs.konghq.com, tyk.io, docs.nginx.com/f5.com, doc.traefik.io,
docs.cloud.google.com (Apigee), AWS/Azure docs; salt.security, traceable.ai, cequence.ai,
akamai.com (Noname), wallarm.com, wiz.io; 42crunch.com, stackhawk.com.
Service mesh: istio.io, linkerd.io, developer.hashicorp.com (Consul).
iPaaS: docs.mulesoft.com, help.boomi.com, docs.workato.com, n8n.io docs, wso2 docs, camel.apache.org.
MCP / agent: modelcontextprotocol.io spec, owasp.org/www-project-mcp-top-10, genai.owasp.org,
invariantlabs.ai, trailofbits.com, cyberark.com.
Deployment/coverage patterns: wiz.io, orca.security, datadoghq.com, snyk.io (Broker), schema.ocsf.io.

(Full per-agent research with inline citations is preserved in the session transcript that produced
this document.)
