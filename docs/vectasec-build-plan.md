# VectaSec — Build Plan & Architecture

**Status:** v3 (research-complete) · **Date:** 2026-07-16

VectaSec is a security posture platform for the **integration layer** — the message brokers, API gateways, service meshes, iPaaS/ESB platforms, and MCP / agent gateways that connect a company's systems together. It builds a live inventory of everything running and how it's wired, checks each asset against a security benchmark, maps results to compliance frameworks, and presents findings through an AI assistant that explains and prioritizes them.

It ships **two ways from one codebase**:

- **Hosted SaaS** — a multi-tenant control plane we run on Supabase; customers connect and get value in minutes.
- **On-prem / self-hosted** — a regulated customer runs the *entire* stack (self-hosted Supabase + our services) inside their own environment. Nothing leaves their network.

In both modes, the systems being scanned live in private networks with no cloud-API equivalent, so collection is done by a lightweight **customer-side Collector** that keeps credentials and raw data local and only sends findings out.

This document is the complete plan: a candid product critique, a market analysis, the full architecture end to end, the credential/trust model, data model, tech stack, onboarding, pricing, reliability, and the phased engineering plan. It is grounded in current (2025–26) market and architecture research; fast-moving figures are flagged for re-verification.

---

## Contents

1. [What the product does](#1-what-the-product-does)
2. [Hard truths — a critique of the product](#2-hard-truths--a-critique-of-the-product)
3. [Market analysis](#3-market-analysis)
4. [Positioning](#4-positioning)
5. [Architecture — the whole system](#5-architecture--the-whole-system)
6. [End-to-end: what happens in a scan](#6-end-to-end-what-happens-in-a-scan)
7. [Deployment modes: SaaS and on-prem](#7-deployment-modes-saas-and-on-prem)
8. [Credentials & data security](#8-credentials--data-security)
9. [Multi-tenancy](#9-multi-tenancy)
10. [Onboarding & time-to-value](#10-onboarding--time-to-value)
11. [Data model](#11-data-model)
12. [How the core pieces work](#12-how-the-core-pieces-work)
13. [SaaS essentials — launch vs defer](#13-saas-essentials--launch-vs-defer)
14. [Reliability & cost at scale](#14-reliability--cost-at-scale)
15. [Tech stack](#15-tech-stack)
16. [Repository layout](#16-repository-layout)
17. [Pricing & packaging](#17-pricing--packaging)
18. [Build plan (phased)](#18-build-plan-phased)

---

## 1. What the product does

A customer connects their integration systems to VectaSec. From there the platform delivers seven capabilities:

| Capability | What it does |
|---|---|
| **Discovery** | Inventories every broker, topic, gateway, route, mesh service, iPaaS recipe, credential, and MCP tool — and maps how they connect. |
| **Posture** | Scores each asset against a security benchmark (Kafka ACLs, Kong auth, Istio mTLS, …) into findings with severity and remediation. |
| **Identity** | Inventories non-human identities and OAuth grants; flags over-scoped, stale, or leaked credentials and their blast radius. |
| **Supply chain** | SBOM + CVE scan of connectors/images/deps; static analysis of integration-as-code (DataWeave, gateway policies, workflow JSON, MCP manifests). |
| **Compliance** | Maps findings to PCI DSS 4.0.1, DORA, HIPAA, NIS2; generates audit evidence and the DORA Article 28 register. |
| **MCP security** | Discovers MCP servers/tools and agent gateways; scans for tool-poisoning and auth-spec violations; ties each tool to the middleware it wraps. |
| **Runtime** *(optional)* | An in-cluster sensor for east-west traffic, egress anomalies, and attack paths. |

The founding principle: **detection is deterministic, and the AI is grounded.** Findings come from code, not a model. The AI may only state things it can cite back to a stored observation — it explains and prioritizes, it never invents facts.

---

## 2. Hard truths — a critique of the product

An honest read of the risks, which shape every decision that follows.

**"Middleware security" is not a budget line.** No CISO has one. Buyers expense this under API security, SSPM, CNAPP, or NHI. Selling a *new category* is slow and expensive. **Consequence:** attach the wedge to a funded adjacent line (NHI + API security) and let the category form on top — see [Positioning](#4-positioning).

**The primary data path is a customer-deployed Collector, and that's friction.** There is no `AssumeRole` that returns a Kafka topic ACL, an Istio `AuthorizationPolicy`, or a Kong plugin config — these are data-plane systems inside private networks, so we must speak their admin protocols from *inside*. That makes the Collector the default path, not an enterprise add-on, and a Collector is a deploy step, a security review, and a support surface. **Consequence:** engineer an instant "aha" that doesn't wait on the install (an agentless cloud-connector path for managed variants like MSK/API Gateway gives a first finding in minutes), make the Collector a one-command install, and turn its very existence into the trust story ("your credentials never leave your network").

**Breadth is the trap.** Seven capabilities across ~10 systems is enormous, and shallow coverage loses to a focused tool. **Consequence:** land one wedge with credible depth; expand only after it sticks.

**We become a high-value target.** VectaSec holds a map of a company's crown-jewel integrations and their weaknesses. **Consequence:** our own security is existential — never hold customer secrets in our cloud, get SOC 2 early, and make "your data stays in your environment" a literal architectural guarantee. This is also *why on-prem matters*: for the most sensitive buyers it's the only acceptable answer, and self-hosted demand in this layer is real (Conduktor, the deepest Kafka governance tool, is self-hosted).

**On-prem multiplies release/support burden.** Every self-hosted install is an operational surface. **Consequence:** gate on-prem to the enterprise tier, ship the *same artifacts* as SaaS, and automate install/upgrade.

**Incumbents are drifting toward us.** Runtime CNAPPs (Upwind, $250M raised; Wiz) already see broker/mesh traffic; NHI vendors (Oasis, Astrix) are closest to claiming OAuth/token posture; API players (Salt, Akamai) extend API→agents. We have no moat yet. **Consequence:** move fast on the confirmed whitespace (broker + iPaaS posture, which no one owns as SaaS) and own the open-source benchmark.

**The AI feature can quietly kill the margin.** LLM triage on every scan for every tenant is a recurring cost. **Consequence:** cache by finding fingerprint, batch, tier-gate deep triage, keep the rule-based fallback.

None of these are fatal. They are why the architecture below looks the way it does.

---

## 3. Market analysis

*Figures below vary widely across research firms because category definitions differ; treat all analyst TAMs as directional and re-verify against primary sources before customer-facing use. Low-confidence items are flagged.*

### The layer nobody owns

The integration layer is covered piecemeal; every horizontal player stops at cloud config, API traffic, and code:

- **API security** (Salt; Akamai/ex-Noname, acquired $450M) — HTTP/API traffic only. No broker, iPaaS, or mesh *config* posture.
- **CNAPP** (Wiz → Alphabet **$32B**, Mar 2026; Upwind, **$250M** raised) — sees the pod running Kafka/Kong and its CVEs, not topic ACLs, plugin chains, connector scopes, or dataflow blast radius. Upwind's runtime sensor is the *closest* to seeing broker/mesh flows but has no posture product for them.
- **NHI / machine identity** (CyberArk → Palo Alto ~$25B; Astrix → Cisco; Oasis, ~$195M total) — inventories the *identities* in middleware, not the middleware's own posture. Complementary — and the most natural budget home for us.
- **Compliance** (Vanta, **$2.45B** val, 8,000+ customers; Drata) — evidence automation, not runtime posture. The PLG-entry model to emulate.
- **Broker/iPaaS specialists** (Conduktor, Gravitee, Kroxylicious) — Kafka-specific, ops/governance-led, and **self-hosted**; none deliver multi-broker + iPaaS + mesh + MCP posture as SaaS.

### Adjacent market sizes (directional)

| Category | 2026 size (range) | CAGR | Note |
|---|---|---|---|
| API security | ~$1.2–1.8B pure-play (up to ~$9–12B incl. gateways) | 20–33% | Crowded |
| CNAPP | ~$11–13B | ~21% | Incumbent-heavy |
| SSPM | **$0.5–5.8B (10× spread)** | 5–49% | Category still being defined — red flag |
| **NHI security** | ~$8–12B | ~12–23% | Credible, large, fundable — our budget anchor |
| **Agentic AI / MCP security** | ~$1.65B → $13.5B by 2032 | **~42% (fastest)** | Tiny base, land-grab |
| ASPM | ~$0.5B → $2.3B by 2030 | ~27% | Adjacent |

Fastest-growing by CAGR is **agentic/MCP security (~42%)** off a tiny base; **NHI** is the most credible large-and-fast adjacent line to attach budget to.

### Competitor delivery & pricing (public/reported)

| Vendor | Delivery | Connector model | Pricing (public/reported) | Touches / misses our layer |
|---|---|---|---|---|
| Wiz | Agentless SaaS (+ Outpost) | Cross-account read-only role; **Outpost** keeps data in-VPC, sends metadata out | Asset-based; ~$24k/100 workloads *(3rd-party est.)* | Cloud config/API; **misses** broker/iPaaS/mesh/MCP posture |
| Orca | Agentless SaaS | Cloud API read-only | ~$30–200k/yr | Same gap |
| Upwind | Runtime-first (eBPF) | Cloud API + eBPF sensor | Quote-only | Closest to broker/mesh *traffic*; no posture product |
| Salt / Akamai | SaaS/hybrid | API traffic/gateway | Enterprise, non-public | API layer only |
| Vanta / Drata | Pure SaaS | Read-only OAuth connectors | Vanta ~$10k→$120k; Drata from ~$7.5k/yr | Compliance evidence; PLG entry model |
| Snyk | SaaS + IDE/CLI | Per-repo/SCM | **~$25/dev/mo**, modules separate; free tier | Code/deps; not integration runtime |
| Aikido | SaaS, PLG | SCM connect | **$0 / $300 / $600 per mo** (flat, users included) | AppSec; the transparent-PLG model to copy |
| **Conduktor** | **Self-hosted** + Kafka proxy | Kafka wire-level proxy | ~$80–150k/yr *(reported)*; free tier | Deepest **Kafka** governance — but self-hosted, Kafka-only, ops-led |
| Gravitee | Self-managed + SaaS CP | API + Kafka gateway | Enterprise | Gateway, not posture |

**Takeaway:** broker posture (Kafka/RabbitMQ/IBM MQ) and iPaaS posture (MuleSoft/Boomi/Workato/n8n) are **genuinely unowned as a dedicated SaaS posture product**. That is the confirmed whitespace.

### MCP / agent security — the fastest-moving, least-funded whitespace

Agentic AI security grows at ~42% CAGR, yet **total disclosed pure-play MCP-security funding is only ~$40M across ~4 startups** (Operant, Lasso, Runlayer $11M, Helmet $9M, Manufact) against **17,000+ deployed MCP servers**. This is the clearest land-grab in the space and our growth engine (module V6). Bigger AI-security players (Noma $132M; Zenity $71.5M) are AI-app/agent-governance-led, not middleware posture.

### Buyers, budgets, triggers

- **Buyer:** CISO holds final sign-off, but the integration layer suffers **fragmented ownership** across AppSec, DevSecOps, platform/data engineering, and compliance — which complicates budget capture. Platform/data eng is often the champion; the CISO signs.
- **Budget line:** API security, CNAPP, SSPM, or **NHI** (the most natural — brokers, iPaaS, and MCP are dense with non-human identities and OAuth tokens).
- **Triggers:** incidents (Salesloft Drift-class), compliance (**DORA** in force Jan 2025; **PCI DSS 4.0** mandatory Mar 2025; **NIS2**), and audits.
- **Motion:** hybrid — **PLG bottoms-up** (free single-connection Collector for platform eng) → **CISO expansion** on NHI/API-security budget.

### Proof points (usable sales narratives)

- **Salesloft Drift / Gainsight OAuth wave — the flagship.** Aug 2025: UNC6395 stole OAuth tokens from the Drift integration and exfiltrated Salesforce data from **700+ orgs** (Cloudflare, Google, Palo Alto, Proofpoint, Zscaler, Tanium, PagerDuty), hunting embedded AWS/Snowflake keys; recurred via **Gainsight (Nov 2025, 200+ orgs)**. The archetypal integration-layer / NHI / OAuth-token failure. *(Well-sourced: Google GTIG, Unit 42.)*
- **n8n (iPaaS) RCE wave.** CVE-2025-68613 (CVSS 9.9); **CVE-2026-21858 "Ni8mare" (CVSS 10.0, unauth)**; CVE-2026-21877 (9.9); **24,700+ unpatched instances; CISA-flagged actively exploited**. *(Well-sourced: The Hacker News, Rapid7.)*
- **Malicious MCP servers.** Tool poisoning (Invariant, Apr 2025); **Postmark-MCP** BCC-exfil (Sept 2025); **Smithery** compromise exposing keys for 3,000+ MCP apps (Oct 2025); Microsoft warning on poisoned tool descriptions (Jun 2026).
- **Broker/gateway CVEs (RabbitMQ / Kafka / Apigee):** earlier research surfaced specific CVEs (e.g. RabbitMQ CVE-2026-57219, Kafka CVE-2025-27817, Apigee CVE-2025-13292); a later pass could not independently re-confirm them. **Verify against NVD before using in any collateral.**

### Exit context

2025 saw ~$96B across ~400 cyber deals. Point/posture solutions in this orbit exit in a **~$450M–$1B tuck-in band** (Noname $450M, Protect AI ~$500M, Veza ~$1B) to a CNAPP, NHI, or API-security acquirer — the realistic outcome to build toward. *(Some 2025–26 M&A specifics are single-source; verify before citing.)*

---

## 4. Positioning

The product is integration-layer security posture. The **go-to-market wedge is not the category** — it's a funded, incident-backed entry:

> **"Non-Human Identity + integration posture — the OAuth tokens, service accounts, connectors, and MCP tools across your brokers, iPaaS, gateways, meshes, and agent gateways that Wiz, Salt, and CNAPP can't see."**

- **Cold-open:** the Salesloft Drift / Gainsight breach — the archetypal integration-layer OAuth failure.
- **Budget:** attach to **NHI / API-security** lines; ride **DORA / NIS2 / PCI 4.0** for compliance-driven urgency.
- **Growth engine:** ship the **MCP / agent-gateway posture** module early — 42% CAGR, ~$40M funded, 17,000+ ungoverned servers.
- **Motion:** free open-source single-connection Collector for platform/data engineering → CISO expansion.
- **Delivery:** multi-tenant SaaS **plus on-prem/BYOC** (self-hosted demand here is real — a differentiator, not a checkbox).
- **Do not** lead with "middleware/middleware security" as a category — it has no budget line and invites a long education slog.

---

## 5. Architecture — the whole system

VectaSec is a **modular backend** (an API service + background workers, one codebase) on a **Supabase substrate**, with a **customer-side Collector** as the primary way to reach systems inside private networks. The same components deploy as multi-tenant SaaS or single-tenant on-prem.

```
   ┌──────────────── customer estate ────────────────┐        ┌─────────── VectaSec control plane ───────────┐
   │                                                  │        │              (Supabase + services)            │
   │  ┌──────────────────────────────────────────┐    │        │   ┌────────────────────────────────────┐     │
   │  │  VectaSec Collector (customer-run)        │    │  out-  │   │  Supabase                          │     │
   │  │  — PRIMARY data path —                    │────┼──bound▶│   │  • Postgres (system of record +    │     │
   │  │  reads systems on the private network:    │    │  only  │   │     asset graph via CTEs)           │    │
   │  │   Kafka · RabbitMQ · IBM MQ · Kong ·       │    │  TLS   │   │  • Auth (RLS multi-tenancy, SSO)   │     │
   │  │   Apigee · Istio · Linkerd · MuleSoft ·    │◀───┼── jobs │   │  • Storage (evidence, SBOM, PDFs)  │     │
   │  │   Boomi · Workato · n8n · MCP servers      │    │(pull)  │   │  • Realtime (live console + jobs)  │     │
   │  │  • holds creds LOCALLY (never sent out)    │    │        │   │  • pgmq queue · pg_cron (jittered) │     │
   │  │  • sends normalized findings + metadata    │    │        │   │  • Vault (control-plane secrets)   │     │
   │  └──────────────────────────────────────────┘    │        │   └───────────────┬────────────────────┘     │
   │                                                   │        │                   │                          │
   │  managed / cloud middleware (optional path):      │        │   ┌───────────────▼────────────────────┐     │
   │   AWS MSK · API Gateway · hosted MCP              │◀──────▶│   │  engine (Python: api + workers)    │     │
   │     ▲ agentless: cross-account read-only role     │  API   │   │  connectors · detectors · AI · comp │    │
   │     │ (with External ID) — zero install           │        │   └───────────────┬────────────────────┘     │
   │  optional: runtime sensor (Tetragon/Pixie)        │        │   ┌───────────────▼────────────────────┐     │
   └───────────────────────────────────────────────────┘        │   │  web (Next.js)  ·  Edge Functions   │    │
   ┌──────────────── operator ─────────────────┐               │   │  (Slack/Jira/SIEM/webhook out)      │     │
   │  browser → console (findings, graph, AI)   │◀──────────────┤   └─────────────────────────────────────┘     │
   └────────────────────────────────────────────┘               └──────────────────────────────────────────────┘
```

**The pieces:**

- **Collector (customer-side — the primary path).** A single signed container / Helm chart the customer runs in their own network. On enrollment it authenticates (enrollment token) and receives a short-lived, tenant-scoped service token. It **pulls** scan jobs from the control plane over a single **outbound-only** TLS connection (no inbound ports opened), runs connectors locally against private systems, holds those systems' credentials **locally**, and pushes back only **normalized findings + metadata** — raw configs and message contents never leave the customer network. This is both the technical necessity (no cloud API exposes a Kafka ACL) and the headline trust story.

- **Cloud connectors (agentless, optional).** For *managed* middleware with a reachable API (AWS MSK, API Gateway, hosted MCP), the engine connects directly via **cross-account read-only role assumption with an External ID** (defeats the confused-deputy attack; no long-lived key stored) — zero install, for the fast first "aha."

- **Supabase (the substrate).** Managed Postgres is the system of record *and* asset graph (recursive CTEs) *and* job queue (`pgmq`) *and* scheduler (`pg_cron`). **Auth** provides users, SSO/SAML, and — via **Row-Level Security** — multi-tenancy enforcement. **Storage** holds evidence/SBOMs/audit PDFs. **Realtime** dispatches jobs to Collectors and streams live findings to the console. **Vault** encrypts the few control-plane secrets we hold. Supabase is fully self-hostable, which is what makes clean on-prem possible from the same artifacts.

- **engine (Python).** Run as an **API** (orchestration, onboarding, enqueue) and **workers** (claim jobs, run cloud-path connectors + all detectors, write findings + evidence, AI triage, compliance mapping). Console reads inventory/findings directly from Supabase (PostgREST + RLS); the engine handles actions.

- **web (Next.js console)** and **Edge Functions** (Deno) for inbound webhooks + outbound integrations (Slack/Jira/ServiceNow/SIEM/webhook), and to bridge Collector job-pull/result-push to the queue and Postgres under the tenant's RLS context.

- **Runtime sensor (optional).** Tetragon/Pixie in the customer cluster for east-west depth; opt-in, later phase.

**Why Supabase.** It gives a small team Postgres + auth + SSO + storage + realtime + queue + cron + secret-encryption as one managed platform for SaaS, and the *same* stack self-hosts for on-prem — no two worlds. The engine and console stay portable (plain Postgres + standard JWTs), so we're not locked in.

---

## 6. End-to-end: what happens in a scan

**Path A — Collector (primary; e.g. self-hosted Kafka):**

1. **Enroll the Collector.** One `helm install` / `docker run` with an enrollment token. It authenticates outbound and receives a short-lived tenant-scoped token.
2. **Configure locally.** The operator points it at the Kafka bootstrap servers with read-only creds. **Those creds stay in the Collector.**
3. **Job dispatch.** A scan is scheduled (`pg_cron`, jittered) and enqueued (`pgmq`). The Collector **pulls** the job outbound (or is signalled via Realtime) — no inbound port.
4. **Collect locally.** The Collector runs the Kafka connector inside the customer network, producing normalized resources + edges (and the minimal evidence snippets a finding needs), and pushes them outbound to an Edge Function that writes under the tenant's RLS context.

**Path B — agentless cloud connector (e.g. AWS MSK):** the engine assumes the customer's cross-account read-only role (External ID) and collects directly. No Collector needed.

**Both converge:**

5. **Detect.** A worker runs every detector registered for the collected resource kinds; each returns findings, and the exact triggering evidence is written to `observations` and linked.
6. **Map to compliance.** Each finding's `rule_id` updates the compliance controls it affects.
7. **Ground the AI (async, optional).** Triage ranks/clusters/drafts remediation using only the scan's observations; every statement links to the observations it cites, and uncited output is rejected. Explanations are cached by finding fingerprint.
8. **Done.** Via Realtime the console updates live: inventory, findings with evidence, moved compliance score, AI summary; findings route to Slack/Jira per the tenant's rules.

Adding a **new system** = one connector file + a few detector files; everything else is unchanged.

---

## 7. Deployment modes: SaaS and on-prem

One codebase, one set of images, two topologies.

**SaaS (default).** We host the control plane (Supabase — regional US/EU) + engine + console + Edge Functions. The customer runs only the **Collector** for private systems (or nothing, if all their middleware is managed and reachable agentlessly). Minutes to onboard; upgrades and billing are ours.

**On-prem / self-hosted (enterprise tier).** The customer runs everything — self-hosted Supabase + engine + console + Collector — in their own environment. Nothing leaves their network. Shipped as a **Docker Compose** bundle (single host) and a **Helm chart** (their K8s), same images as SaaS, offline-licensed, versioned migrations for upgrades. Gated to enterprise to control support cost. Because the substrate is identical, there is no separate on-prem build.

---

## 8. Credentials & data security

The trust model, made explicit — this is what wins or loses the security review. The objection ("I won't give a SaaS vendor admin creds to my Kafka/gateway") is **fatal if we hold the secret and evaporates if we architecturally cannot.** Best practice, strongest first:

1. **Never hold the secret — private-system creds live in the Collector.** Because the Collector runs in-VPC, the Kafka/Kong/MQ admin credential goes into the *Collector's* local secret store (K8s Secret / Vault / cloud secrets manager) and is **never transmitted to the control plane.** This is the headline differentiator; lead every security review with it.
2. **Cloud role assumption with External ID** (managed-service path only): read-only cross-account role, trust policy conditioned on `sts:ExternalId`, no long-lived key stored.
3. **Short-lived, minimally-scoped tokens** for everything else — the Vanta pattern: ~1-hour tokens, single active token per app, per-customer scoping, minimum-scope enforcement, encrypted at rest, server-side-only exchange, one-click revocation.
4. **BYO-KMS / customer-managed keys** for the small residue of secrets we must hold (e.g. a Slack webhook); envelope-encrypt under the customer's KMS key so they can revoke by disabling it.

Everything read-only; we never need write access to a customer's middleware. Only **normalized findings + metadata** cross the boundary — market this explicitly. Our own posture: **SOC 2 Type II observation window starts now** (a launch-critical sales gate), full audit logging, and on-prem for buyers who won't accept any external processing.

---

## 9. Multi-tenancy

- **Enforced at the database with Supabase Row-Level Security.** Every table carries `tenant_id`; RLS policies key off the tenant claim in the auth JWT, so a query *cannot* return another tenant's rows even if app code is wrong. For a security product this DB-level guarantee is the point — a cross-tenant leak here is an extinction event.
- **RLS hardening (non-negotiable):** `FORCE ROW LEVEL SECURITY`, a non-superuser app role, separate policies per `SELECT`/`INSERT`/`UPDATE`/`DELETE`, and **adversarial cross-tenant queries in CI**.
- **Pooled multi-tenant** by default (shared Postgres + RLS) — the correct Supabase-native model for ~80% of B2B SaaS and the right early-scale choice.
- **Per-tenant encryption keys** for sensitive columns (findings can embed config snippets); **BYO-KMS** at enterprise.
- **Data residency:** stand up **US + EU Supabase regions at/near launch** for regulated/EU buyers; route tenants by region at signup; keep findings in-region. The Collector model shrinks this problem — raw data stays in the customer VPC, so our cloud only holds normalized findings.
- **Dedicated single-tenant** (separate Supabase project) as a paid enterprise SKU when procurement demands physical separation; on-prem is the ultimate residency answer.

---

## 10. Onboarding & time-to-value

TTV is the #1 predictor of SaaS activation. Benchmarks: **<5 min excellent, 5–20 min acceptable, 20–60 min loses a meaningful fraction of signups.** The Collector install fights this, so:

- **Instant "aha" without waiting on the install:** at signup, offer the **agentless cloud-connector path** for any managed assets (MSK, API Gateway, hosted MCP) so the user sees a first finding **in minutes**.
- **One-command Collector:** `helm install` / `docker run` with the enrollment token pre-filled; auto-detect reachable systems and offer one-click "scan this."
- **Engineer the first finding to be undeniable:** end the guided flow on a specific, credible, high-signal result — "Kafka topic `payments` has a wildcard ACL allowing `*:read`," "Kong route `/admin` has no auth plugin," "Istio mesh has `PERMISSIVE` mTLS on 3 services," "this n8n webhook has no auth." The aha = *"you found a real exposure in my message bus/gateway I didn't know about, in minutes."*
- **Targets:** first cloud-connector finding **< 10 min**; first Collector finding **< 30 min** of the Collector going live.

---

## 11. Data model

Core tables, all tenant-scoped with RLS. Beyond the scan spine, this includes the SaaS operational layer.

```sql
-- Tenancy & identity ---------------------------------------------------------
tenants        (id, name, plan, region, created_at)
users          (id, tenant_id, email, role,        -- 'owner'|'admin'|'analyst'|'viewer' (Supabase Auth)
                sso_subject, created_at)
api_keys       (id, tenant_id, name, hash, scopes, last_used_at)
audit_log      (id, tenant_id, actor, action, target, at)   -- append-only, our own audit trail

-- Collectors & connections ---------------------------------------------------
collectors     (id, tenant_id, name, status, last_heartbeat, version, enroll_token_hash)
connections    (id, tenant_id, type, name, mode,   -- mode: 'collector' (default) | 'cloud' (agentless)
                collector_id, status, config jsonb,
                creds_ref,                          -- Vault ref (cloud) or NULL (collector holds them)
                rate_limit jsonb,                   -- per-target token-bucket settings
                created_at, last_scanned_at)

-- Inventory & graph ----------------------------------------------------------
resources      (id, tenant_id, connection_id, kind, name, namespace,
                labels jsonb, raw jsonb, first_seen, last_seen, stale bool)
edges          (id, tenant_id, src_resource_id, dst_resource_id, kind, labels jsonb)

-- Scans, findings, evidence --------------------------------------------------
scans          (id, tenant_id, connection_id, status, started_at, finished_at, stats jsonb)
findings       (id, tenant_id, scan_id, resource_id, rule_id, fingerprint,  -- fingerprint dedups across scans
                title, severity, status,            -- open|triaged|in_progress|resolved|suppressed|accepted
                assignee, due_at, first_seen, last_seen, remediation, detail)
suppressions   (id, tenant_id, rule_id, scope, reason, expires_at, created_by)  -- exceptions w/ expiry
observations   (id, tenant_id, finding_id, resource_id, observed_at, claim, source_ref jsonb)  -- immutable

-- Compliance -----------------------------------------------------------------
controls       (id, tenant_id, framework, control_id, title, requirement, status, failing_finding_ids jsonb)

-- Grounded AI ----------------------------------------------------------------
ai_outputs         (id, tenant_id, scan_id, kind, content, fingerprint, created_at)  -- cache key = fingerprint
ai_output_evidence (ai_output_id, observation_id)   -- citation gate: no output without ≥1 linked observation

-- Integrations & billing -----------------------------------------------------
integrations   (id, tenant_id, type, config jsonb)          -- slack|jira|servicenow|webhook|siem
routing_rules  (id, tenant_id, match jsonb, integration_id) -- which findings go where
usage          (id, tenant_id, metric, value, period)       -- connectors/assets/scans/LLM-tokens metering
```

Load-bearing rules: the **citation gate** (`ai_output_evidence`, enforced in code) makes the AI trustworthy; the **finding fingerprint + lifecycle** (`fingerprint`, `status`, `assignee`, `due_at`, `suppressions`) makes findings a *workflow*, not a list — which is what makes security teams adopt it; the **fingerprint cache key on `ai_outputs`** is what keeps LLM cost flat.

---

## 12. How the core pieces work

### Connectors — read-only, auto-registered
One file per system type; drop-in registration (no central list). Runs in the engine (cloud path) or inside the Collector (private path) — same code, same interface:

```python
class Connector(Protocol):
    type: str
    def ping(self, creds) -> PingResult: ...
    def collect(self, creds, config) -> Collected:   # → resources[], edges[]
        ...
```

Kafka via AdminClient, Kong via Admin API, RabbitMQ via management API, Istio via K8s API, iPaaS via platform APIs, MCP via server introspection — all read-only. The Collector applies a **per-target token bucket** so a scan never DoSes the customer's production broker (itself a selling point).

### Detectors — deterministic, auto-registered
One file per rule; declares resource kinds; returns findings with the triggering evidence:

```python
@detector(kinds=["broker"], rule_id="KAFKA.ACL.ALLOW_EVERYONE")
def allow_everyone(resource, ctx) -> list[Finding]:
    if resource.raw["config"].get("allow.everyone.if.no.acl.found") == "true":
        return [Finding(severity="high",
                        title="Kafka accepts all clients when no ACL matches",
                        remediation="Set allow.everyone.if.no.acl.found=false and define ACLs",
                        observation="config allow.everyone.if.no.acl.found = true")]
    return []
```

Initial rulepacks (our IP — there's no CIS Benchmark for these systems, so we author and open-source the benchmark): Kafka (allow-everyone incl. MSK default, PLAINTEXT listeners, no authorizer, wildcard ACLs, weak SASL), RabbitMQ (guest/guest, unTLS'd mgmt UI, missing vhost least-privilege), Kong (unauth Admin API, routes with no auth plugin, RBAC off), Istio (PERMISSIVE mTLS, AuthorizationPolicy bypass patterns, wildcard hosts), iPaaS + MCP (policy misconfig, weak-crypto secrets, MCP auth-spec + tool-poisoning). Config-heavy rules use OPA/Rego with a Python fallback. Per-tenant tuning (suppressions with expiry, severity overrides, baselining) is first-class in the data model.

### The Collector
A minimal, sandboxed image: enrolls outbound with a token, pulls jobs (no inbound ports), runs connectors locally, pushes normalized results over mTLS, heartbeats for liveness, self-updates to a pinned channel. Small attack surface, trivial cluster footprint. The single-connection version is **free/open-source** — both the PLG funnel and the trust proof ("the scanner in your VPC is inspectable").

### Grounded AI
A thin layer over Claude — **triage** (rank/cluster), **remediate** (draft the fix), **answer** (query your own inventory). Each call gets only the relevant observations and must return citations; uncited claims are rejected. Cost control: cache by finding fingerprint (one "wildcard ACL" explanation serves thousands of occurrences), batch per scan, tier-gate deep triage, meter tokens per tenant. Disabled/unreachable, a rule-based fallback still ranks findings.

### Integrations out
Findings route to Slack/Jira/ServiceNow/SIEM/webhooks via Edge Functions, driven by per-tenant `routing_rules`. A retention feature: findings that reach the team's existing tools get fixed.

---

## 13. SaaS essentials — launch vs defer

| Capability | Verdict | Notes |
|---|---|---|
| **Our own SOC 2 Type II** (ISO 27001 for EU) | **Launch-critical** | ~78% of enterprise buyers require SOC 2 before signing *(single-source stat; directional)*. Start the observation window now — Type II takes months. |
| **SSO (SAML/OIDC)** | **Launch** | Non-negotiable for any security buyer. |
| **RBAC** | **Launch** | Enforce at API/RLS, not just UI. |
| **Immutable audit log** | **Launch** | We're a security tool; be exemplary. |
| **Slack + Jira out** | **Launch** | Findings must flow into the SOC's workflow. |
| **Generic signed webhook** | **Launch** | Covers most SIEM needs initially. |
| **Read API** | **Launch** | Security teams automate. |
| **SCIM** | **Fast-follow** | Larger buyers demand automated deprovisioning. |
| **Native Splunk/Sentinel, write API** | **Fast-follow** | With first enterprise deals. |
| **ISO 27001, customer-managed KMS, dedicated tenant** | **Fast-follow** | Enterprise SKU. |
| **Terraform provider** | **Fast-follow** | Valued, not a first-deal blocker. |
| **ServiceNow** | **Defer** | Add when up-market. |

---

## 14. Reliability & cost at scale

- **Fair scan scheduling:** enqueue jobs on `pgmq` tagged with `tenant_id`; enforce a **per-tenant in-flight concurrency cap** (a worker won't pull a tenant's job past N running). Schedule recurring scans with `pg_cron` **plus jitter** so tenants don't stampede at :00.
- **Per-connection rate-limiting:** the Collector rate-limits calls to the customer's *own* broker/gateway (token bucket per target) — we must never overload their production systems. This protects the customer, which sells.
- **Isolate a slow/broken tenant:** concurrency quotas per tenant and a **circuit-breaker** on a tenant whose Collector errors or whose jobs time out; page only when the *platform* (not one tenant) is unhealthy.
- **LLM cost:** cache explanations by **finding fingerprint** (not per-tenant), batch per scan, **tier-gate deep triage** (free/low tiers get rule-based severity + cached explanations; premium gets on-demand deep-dives), and meter tokens per tenant so a heavy tenant is visible and upsell-able.

---

## 15. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Platform substrate | **Supabase** — Postgres, Auth (SSO), Storage, Realtime, `pgmq`, `pg_cron`, Vault | One managed platform for SaaS; self-hostable for on-prem — no two worlds. |
| Database / graph / queue | **Postgres 16** (via Supabase) | System of record + graph (CTEs) + queue in one store. |
| Multi-tenancy | **Row-Level Security** (`FORCE RLS`, non-superuser role, CI cross-tenant tests) | DB-enforced isolation — the right guarantee for a security product. |
| Backend engine | **Python 3.13 · FastAPI** (api + workers) | Rich clients for Kafka/K8s/cloud; worker is the same code. |
| Collector | **Small signed container** (Helm + Docker), outbound-only | Reaches private systems; keeps creds local; free single-connection edition. |
| Console | **Next.js + React**, Supabase client | Live console via Realtime. |
| Integrations | **Supabase Edge Functions (Deno)** | Webhooks + outbound integrations + Collector bridge. |
| Policy | **OPA/Rego + Python fallback** | Declarative config checks; resilient offline. |
| AI | **Claude, grounded + rule fallback**, fingerprint-cached | Triage/remediation/Q&A; citations enforced; cost-controlled. |
| Ingress / on-prem | **Caddy + Docker Compose + Helm** | One-command SaaS-parity install for on-prem. |
| Billing | **Stripe** | Metering + subscriptions. |

Deliberate non-choices for v1: no eBPF agent to build (optional runtime sensor embeds Tetragon/Pixie later), no SPIRE to operate (audit workload identity, don't issue it), no separate Kafka/Redis (Postgres via Supabase is the queue).

---

## 16. Repository layout

```
vectasec/
├── apps/
│   └── web/                      # Next.js console (Supabase client + engine API)
├── services/
│   ├── engine/                   # the `vectasec` Python package (api + workers share it)
│   │   └── src/vectasec/
│   │       ├── connect/          # connectors: one file per system (kafka.py, kong.py, ...)
│   │       ├── detect/           # detectors: one file per rule, auto-registered
│   │       ├── graph/            # resources + edges, CTE queries, blast-radius
│   │       ├── identity/         # NHI / OAuth-grant collectors + detectors
│   │       ├── supplychain/      # SBOM/CVE + iac-scan engine
│   │       ├── compliance/       # rule→control mapping, OSCAL, DORA register, GRC push
│   │       ├── mcp/              # MCP discovery + posture
│   │       ├── ai/               # grounded triage / remediate / answer (fingerprint cache)
│   │       ├── evidence/         # observation ledger + citation gate
│   │       ├── scan/             # scan loop, pgmq, per-tenant caps, worker entrypoint
│   │       └── api/              # FastAPI routers
│   └── collector/                # customer-side Collector (its own small signed image)
├── packages/
│   ├── contracts/                # shared schema (Pydantic + generated TS types)
│   ├── iac-scan/                 # static analysis engine + GitHub Action
│   ├── benchmark/                # open-source posture rulepacks (PLG + credibility)
│   └── ui/                       # React component library
├── supabase/
│   ├── migrations/               # SQL (tables, RLS policies, pgmq, pg_cron)
│   └── functions/                # Edge Functions (Collector bridge + Slack/Jira/SIEM)
├── deploy/
│   ├── saas/                     # hosted config (US + EU projects)
│   └── onprem/                   # docker-compose.yml + helm (self-hosted Supabase + services)
└── docs/
```

---

## 17. Pricing & packaging

- **Axis = per connected integration** (per broker/gateway/mesh/iPaaS/MCP instance). Maps to our cost (each connection = scan load + Collector overhead) and to customer value far better than per-seat (wrong buyer) or per-asset (bill-shock).
- **Free / open-source** — the single-connection Collector + the benchmark scanner + a GitHub Action. Both the PLG top-of-funnel *and* the trust proof (inspectable scanner running in your VPC). Model: Aikido (transparent, <10-min value) + Snyk (free tier + funnel).
- **Team** — a handful of connections, integrations out, SSO, core posture + discovery + compliance evidence.
- **Enterprise** — unlimited connections, SSO+SCIM, all frameworks + DORA register + OSCAL, SIEM/API/Terraform, dedicated tenant or **on-prem**, BYO-KMS, SLA. Gate deep-AI, runtime, and on-prem here to protect margin and support cost.

Reference points *(mostly third-party estimates — verify)*: Wiz ~$24k/100 workloads; Snyk ~$25/dev/mo; Aikido $0 / $300 / $600 per month; Vanta ~$10k→$120k; Conduktor ~$80–150k/yr.

---

## 18. Build plan (phased)

Each phase ends **provable** against a real system. Small team (2–4 engineers).

### Phase 0 — Foundation (weeks 0–3)
Supabase project + schema + **hardened RLS** (`FORCE RLS`, non-superuser role, CI cross-tenant tests) + `pgmq` + `pg_cron`; engine skeleton; evidence ledger + citation gate; Next.js console with Supabase Auth; Docker Compose + Helm on-prem path from day one; CI. **One real connector end to end:** Kafka via the agentless cloud path → resources/edges → one detector → finding + observation → live in the console via Realtime.
**Done when:** connect a real (managed) Kafka, scan, see a cited finding update live; the same stack runs against self-hosted Supabase (on-prem parity proven early).

### Phase 1 — Core product + first sale (weeks 3–10)
The **Collector** (private-system path end to end; creds stay local; outbound-only). Connectors + rulepacks for **Kafka, Kong, one iPaaS**; asset graph; findings workflow (assignee, suppression-with-expiry, dedup). Compliance: PCI 6.4.2 + DORA + OSCAL export. Grounded-AI triage v1 (fingerprint-cached); **Slack + Jira** out; SSO + RBAC + audit log; **SOC 2 observation window started**. Publish the **open-source benchmark + free single-connection Collector** (PLG). Onboarding engineered to a **<10-min cloud / <30-min Collector** first finding.
**Done when:** a design partner connects real Kafka + Kong + one iPaaS (cloud or Collector), works findings in Slack/Jira, exports compliance evidence — every claim cited. On-prem install validated with one partner.

### Phase 2 — Breadth + identity (weeks 10–22)
Connectors/rulepacks for **RabbitMQ, Istio, Apigee, Boomi/Workato/n8n**. **Identity:** NHI inventory + OAuth-grant blast-radius (the Drift-anchored demo) + workload-identity audit. **Supply chain:** `iac-scan` library + GitHub Action; SBOM/CVE for deployed runtime. **Compliance:** DORA Article 28 register generator; push evidence to Vanta/Drata. SaaS ops: per-connection billing/metering, SCIM, SIEM/webhook, read API; **US + EU regions**.
**Done when:** the OAuth-grant blast-radius view runs on a real estate; `iac-scan` gates a PR; billing is live.

### Phase 3 — MCP growth engine + runtime + enterprise (months 5–9)
**MCP security (the growth engine):** discovery, registry/allowlist with rug-pull detection, tool-poisoning + auth-spec scanning, joined to the underlying middleware. **Runtime (optional):** Tetragon/Pixie sensor; egress anomalies; cross-layer attack paths. **Enterprise:** dedicated tenant + hardened on-prem (air-gapped, offline licensing), BYO-KMS, Terraform provider, **SOC 2 Type II report in hand**.
**Done when:** an MCP tool's blast radius traces through the middleware it wraps; one enterprise runs fully on-prem; SOC 2 Type II achieved.

---

## Immediate next steps

1. Stand up the Supabase project (schema, hardened RLS, `pgmq`, `pg_cron`) + engine skeleton, with the Docker Compose / Helm on-prem path wired from the start.
2. Build the Kafka connector + one detector end to end via the agentless cloud path (fast first "aha").
3. Build the **Collector's** private-system path with self-hosted Kafka — the primary path and the trust story.
4. Ship the **free open-source single-connection Collector + benchmark** to open the PLG funnel.
5. Start the **SOC 2 Type II** observation window now — it gates every enterprise deal.
