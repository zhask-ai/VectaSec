# VectaSec v4 — The Brutal Verdict and the Complete-Product Blueprint

**As of 2026-07-23.** Produced from a three-track sweep: a file-by-file due-diligence audit of this
repo, a map of the full 2026 middleware universe, and a refresh of the competitive bar (mid-2025 →
July 2026). Sources for the market claims are in the session that produced this doc; the code claims
point at files.

---

## Part 1 — The verdict: is this "the perfect middleware platform usable everywhere"?

**No. It is not close, and it is not even the right sentence.** Two separate failures:

### 1.0 Category honesty

VectaSec is not a *middleware platform* (it routes no traffic, brokers no messages, integrates
nothing). It is a **security posture product FOR the middleware layer**. That is the right product to
build — the research confirms the whitespace — but "perfect middleware platform" is a claim this
codebase cannot and should not make. The claim it should grow into is: **"the security posture,
identity, and governance layer for everything that connects systems together"** — brokers, gateways,
meshes, iPaaS, and AI/agent infrastructure.

### 1.1 What is genuinely good (do not throw away)

- **The detector core is real.** 85 deterministic detectors, real config evidence (not name-matching),
  per-detector error isolation, an honest `not_assessable` third outcome, and a refusal to guess
  (`connect/kafka.py` explicitly rejects the MSK "assume true" heuristic). Audited: zero stubs.
- **All 5 connectors are real** (AdminClient, mgmt APIs, redis-py, MCP handshake), credentials
  consistently reduced to metadata, never stored.
- **The integrity spine is rare in the market:** Postgres-enforced citation gate on AI output,
  append-only + hash-chained evidence ledger (migration 006 `verify_ledger`), FORCE-RLS
  multi-tenancy on 18 tables, audit row per mutation, in-transaction.
- **NHI derivation** (`identity.py`) — every connector yields identities/credentials/grants for free.
  This is the wedge the market validated (Cisco buying Astrix ~$400M; Oasis $120M; CyberArk $25B).
- JWT verification, compliance evaluation wiring, Kafka edges, realtime, and the repo push all
  landed after STATUS.md was written — the code is ahead of its own self-assessment.

### 1.2 Why "usable everywhere" is false today — the ten damning gaps

1. **Coverage: 5 systems.** Zero code for IBM MQ, ActiveMQ, NATS, Pulsar, SQS/SNS/EventBridge,
   Azure Service Bus, GCP Pub/Sub, any service mesh, any iPaaS (MuleSoft/Boomi/Workato/n8n), any
   cloud API gateway (Apigee/AWS/APIM), Tyk/Traefik/NGINX, Kubernetes. The credible "universal" bar
   is ~30–35 connectors, and Tier-1 alone (13 connectors, several fanning out to 5–10 services)
   covers ~80% of real 2026 enterprise middleware footprint. VectaSec covers a fraction of that.
2. **Point-in-time only.** `pg_cron` is installed and **zero jobs are scheduled**. Scans happen when
   a human clicks. Every 2026 buyer guide assumes continuous.
3. **The action layer is absent.** No Slack/webhook/email alerting, no SIEM export, no Jira/ServiceNow.
   `integrations` and `routing_rules` tables exist with no code. Unusable inside a real SOC.
4. **The agentless cloud path is vaporware.** README claims cross-account read-only role; there is no
   AWS SDK, no AssumeRole, no IAM code anywhere.
5. **No SSO/SAML/SCIM and no RBAC** (`tenant_members.role` read by nothing). Hard procurement gate.
6. **Credentials in plaintext JSONB** (`connections.config`); no Vault/`creds_ref`. Combined with the
   engine's BYPASSRLS credential: one leak reads every tenant's middleware secrets.
7. **A self-asserted-header auth bypass still ships** (`VECTASEC_DEV_TRUST_HEADERS`, default-on for
   localhost) — containerized on-prem exposes it cross-tenant.
8. **Collector round-trip and on-prem have never run.** MockTransport tests and lint-clean Helm only.
9. **No trend history, no report export, no public/read/import API, no CVE feed (version-string
   checks only), no attack-path reasoning as a feature.**
10. **MCP detectors are pinned to a spec that dies in 5 days.** The 2026-07-28 revision (RC final)
    removes `initialize` and protocol sessions (`server/discover` replaces it, `Mcp-Session-Id`
    gone), deprecates Roots/Sampling/Logging, adds RFC 9207 `iss` validation and Trace Context.
    Several `detect/mcp.py` rules read exactly the things being removed.

### 1.3 What the market did while this repo was being built (mid-2025 → 2026-07)

- **MCP-only posture is no longer whitespace.** Salt Security shipped "AG-SPM" (LLM+MCP+API posture,
  100 policies), Wiz AI-SPM discovers customer MCP servers agentlessly, and ~13 enterprise MCP
  gateways exist. Do not lead with MCP; make it one node class in the graph.
- **Still unowned as SaaS (the defensible core):** broker posture (Kafka/RabbitMQ/MQ), iPaaS tenant
  posture (MuleSoft/Boomi/Workato/n8n), gateway-fleet posture, and above all **the cross-layer
  graph** — brokers + gateways + iPaaS + MCP + NHIs in one topology/attack-path model. Nobody has
  the union.
- **NHI got white-hot:** Cisco/Astrix, Oasis $120M, GitGuardian $50M, Token RSAC sandbox, PAN/CyberArk
  $25B. NHI-**ITDR** (behavioral detection + revoke/rotate response) is a named product category now.
- **Buyer bar moved:** agentless-first + optional sensor; three-tier remediation (one-click, IaC/PR
  fix, playbook); SIEM set = Splunk/Sentinel/Google SecOps/CrowdStrike; Okta+Entra SSO with SCIM;
  policy-as-code (OPA) + a Terraform provider for the platform itself; OCSF export.
- **Ammunition:** n8n CVE-2025-68613 (9.9, ~103k exposed instances), RediShell (10.0, ~330k exposed
  Redis), Drift→Gainsight OAuth chain (700+ orgs), Postmark MCP backdoor, Shai-Hulud npm worm,
  93% of agent projects on unscoped API keys / 74% over-privileged.

**Verdict in one line:** a genuinely well-engineered 1-week-old kernel — detectors, evidence
integrity, NHI, multi-tenancy — wearing a "universal platform" label it earns on roughly none of the
axes a 2026 buyer scores: breadth, continuity, action, identity/access, runtime, or proof.

---

## Part 2 — What "complete" means (the v4 target spec)

Graded target: everything in **T** (table stakes) must exist before the word "platform" is used in
sales material; **D** items are how deals are won; **E** items are the 12–18-month bets.

**T — table stakes**
1. Continuous scheduled scanning (pg_cron → pgmq per-connection cadence) + drift-on-change.
2. Tier-1 connector set (§3 below) with a **public, falsifiable coverage matrix**.
3. Rules mapped to CIS/OWASP IDs — incl. OWASP MCP Top 10 (MCP01–10:2025) and OWASP NHI Top 10 —
   published as **the VectaSec Benchmark** (no CIS benchmark exists for any self-managed broker or
   mesh; codifying one is free authority).
4. Topology + attack-path graph with context-aware prioritization (exposed × over-privileged ×
   sensitive-data on one path outranks CVSS).
5. NHI inventory with ownership, staleness/last-used, rotation age.
6. Remediation: exact config/CLI fix per finding + IaC (Terraform) snippet + PR-based fix output.
7. Alerting/routing: Slack, email, generic webhook; severity/owner routing rules (tables exist).
8. SIEM export: OCSF-formatted events → Splunk HEC, Sentinel, Google SecOps; plus Jira and
   ServiceNow bidirectional ticketing.
9. SSO (Okta/Entra SAML+OIDC) + SCIM + RBAC (admin/editor/viewer read `tenant_members.role`).
10. Vault for connection credentials (`creds_ref`), engine JWT-only (kill header trust), collector
    round-trip proven in CI, on-prem stack booted and smoke-tested.
11. Compliance: PCI 4.0, DORA, NIS2, HIPAA, ISO 27001, SOC 2 — attestation flow (already built) +
    exportable evidence bundles (PDF/CSV/OSCAL), cross-framework control dedup.
12. Public REST read API + findings-import API (long-tail coverage lever) + posture trend
    (`posture_snapshots`) + exec reports.

**D — differentiators**
13. **The cross-layer graph as the headline**: one attack-path model spanning broker → gateway →
    iPaaS → MCP → NHI. Generalize `DATA.EXPOSURE.SENSITIVE_PLAINTEXT` into a graph rule engine
    ("toxic combinations"), with choke-point analysis.
14. **NHI-ITDR-lite**: baseline per-identity usage (where readable: Kafka ACL activity, Kong
    consumers, OAuth grants), flag anomalies, and wire revoke/rotate playbooks.
15. AI-SPM: shadow-MCP/agent discovery across a fleet (config-file discovery, registry diff,
    tool-definition pinning + rug-pull detection).
16. Policy-as-code: customer rules in OPA/Rego or Python against the resource model; Terraform
    provider for the platform itself.
17. Dual SaaS/on-prem, proven — the regulated-buyer moat pure-SaaS competitors can't match.
18. Evidence discipline as a feature: hash-chained ledger + citation-gated AI, shown to auditors.

**E — emerging bets**
19. MCP spec-lifecycle tracking (2026-07-28 statelessness migration = an immediate detector market:
    session-dependency, deprecated Roots/Sampling/Logging usage, missing RFC 8707/9207).
20. Agent-identity conformance (SPIFFE/WIMSE/AIMS draft; flag unscoped-API-key agents).
21. Trace-based runtime evidence (W3C Trace Context is now in the MCP spec; consume OTel).
22. Gateway-agnostic MCP-gateway posture scoring (assess Kong/ContextForge/MintMCP/Obot deployments
    rather than compete with them).
23. EU AI Act module (high-risk obligations deferred to Dec 2027/Aug 2028; Art. 50 lands Aug 2026).

---

## Part 3 — Connector roadmap (the "everywhere" math)

Each connector = one `connect/*.py` + one `detect/*.py` pack + NHI extractor (free) + docs row in
the coverage matrix. Force-multipliers first:

**Wave 1 — force multipliers (each unlocks many systems)**
- **Kubernetes API** → Istio, Linkerd, Cilium, Traefik, Envoy Gateway CRDs (mesh + ingress posture
  in one connector). Checks already scoped in `docs/research/`.
- **AWS** (one cross-account read-only role) → SQS, SNS, EventBridge, MSK, API Gateway, Step
  Functions. This makes the README's agentless claim true.
- **Azure** (ARM) → Service Bus, Event Hubs, APIM, Logic Apps.
- **GCP** → Pub/Sub, Apigee.
- **MCP spec-2026-07-28 migration** of the existing connector + new lifecycle detectors.

**Wave 2 — category completion**
- n8n (public API; CVE-2025-68613 story), MuleSoft Anypoint, NATS, IBM MQ (REST admin), Confluent
  Cloud, SaaS OAuth-grant posture (Salesforce connected apps — the Drift/Gainsight story).

**Wave 3 — long tail**
- Boomi, Workato, ActiveMQ/Artemis, Pulsar, Solace, Tyk/Traefik/NGINX config posture, Temporal,
  Airflow, Debezium/Kafka Connect, Apollo GraphOS, LiteLLM/AI-gateway posture.

End state: ~30 connectors ≈ 80%+ of real enterprise middleware footprint — the same arithmetic Salt
uses to say "universal" on ~20.

---

## Part 4 — v4 architecture deltas (evolve the kernel, rebuild the shell)

Keep: Supabase substrate, engine kernel (`contracts/registry/scan/identity/classify/graph`),
detector packs, ledger + citation gate, RLS schema, console.

Rebuild/add around it:
1. **Scheduler**: pg_cron → enqueue per-connection on cadence; scan-on-drift where APIs allow.
2. **Security hardening (before anything else ships)**: delete header-trust path, Vault/creds_ref,
   collector round-trip in CI, boot on-prem once for real.
3. **Action service**: router (severity/owner/system rules) → Slack/webhook/email/Jira/ServiceNow/
   SIEM(OCSF) senders; findings-import + public read API on the same service.
4. **Graph engine**: promote `graph.py` to a rule-driven attack-path evaluator (toxic-combination
   DSL over paths), feeding prioritization and the console.
5. **Identity plane**: SSO/SCIM via Supabase Auth SAML + RBAC middleware reading
   `tenant_members.role`; per-identity usage baseline tables for ITDR-lite.
6. **History**: `posture_snapshots` written per scan; trend on Overview; exec report generator.
7. **Coverage matrix**: generated from the registry into docs/site — falsifiable, Wiz-style.

## Part 5 — Execution order

0. **Stop-the-bleed (days):** MCP 2026-07-28 migration; kill header trust; Vault creds; prove
   collector loop; push → CI green.
1. **Continuous + action (the "product, not scanner" release):** scheduler, alerting/routing,
   Jira/Slack/webhook, SIEM export, trend snapshots.
2. **Breadth (the "everywhere" release):** K8s + AWS + Azure + GCP connectors (+ their rulepacks),
   coverage matrix, findings-import API.
3. **Enterprise (the "second customer" release):** SSO/SCIM/RBAC, report export, on-prem proven,
   public API, benchmark published.
4. **Moat (the "category" release):** attack-path graph engine, NHI usage/ITDR-lite, shadow-MCP
   fleet discovery, policy-as-code, n8n/MuleSoft/NATS/IBM MQ.
