# VectaSec — Anchor, Consolidate, Win SMB POCs

**As of 2026-10-17.** Produced from a code audit of this tree (39 connectors, ~440 detectors,
15 console surfaces, last commit 2026-08-07) plus two market sweeps (competitor landscape; SMB
anchor-feature research). Market claims carry a source; code claims point at files. Where a
figure comes from a vendor or aggregator it is marked so. This document replaces the sequencing
in `vectasec-capability-atlas.md` for the next 8 weeks; the atlas remains the long-term target.

---

## 1. Why prospects say "mid" and "mature products exist"

The feedback is accurate about **labels** and wrong about **data sources**. Prospects hear
"non-human identity", "posture", "MCP security" and pattern-match to vendors that are
genuinely mature in those labels:

- **NHI** consolidated in 2026: Astrix → Cisco (~$400M), Entro → SailPoint, Oasis → Cyera ($1B),
  Natoma → Snowflake. All enterprise-quoted, all derive identities from cloud IAM, IdP, SaaS
  OAuth, vaults and repos. **None reads Kafka ACLs, RabbitMQ vhost permissions, NATS accounts,
  Istio AuthorizationPolicy, Kong consumers or iPaaS connections.** There is now no SMB-priced
  NHI product at all.
- **CSPM** (Wiz from ~$24k/yr, Orca, Prowler $79–99/account/mo, Aikido $350–1,050/mo flat) sees
  "Redis port open" from the cloud control plane. It never logs into the broker and never sees
  `guest/guest`, a wildcard ACL, an unauthenticated Kong admin API, or an EOL broker branch.
- **MCP security** is crowded by late 2026 (Wiz catalog, Noma, Zenity, Akto, Snyk Agent Scan,
  Cisco DefenseClaw). Standalone MCP posture is no longer a differentiator.
- **In our exact lane** there is one product: KafkaGuard, Kafka-only, $79–239/cluster/month,
  looks like a one-person vendor. Nothing covers brokers + gateways + mesh + cloud messaging +
  automations together.

So the real problem is not that the market is full. It is that **VectaSec presents itself as a
smaller Wiz**: fifteen navigation items, a catalogue of 39 connectors, "448 detectors", a VEX
export, a licensing panel, a hash-chained ledger. A buyer with no security team cannot find the
one thing only we can show them. Every PLG security winner of 2023–26 (Aikido, Snyk, Semgrep,
Tailscale, Infisical, Prowler) led with one concrete first-ten-minute result and a price in a
unit the buyer already counts. None led with detector counts.

## 2. The anchor: "Who can touch your data"

**One sentence:** *Connect your AWS account and your brokers read-only; in ten minutes see every
API key, service account, OAuth client and AI automation that can read or write your queues,
topics, routes and clusters — who owns it, when it was last used, whether it is reachable from
the internet, whether it is also sitting in a git repo — and export the register your SOC 2 or
PCI auditor asks for.*

Internally this is the NHI graph we already derive from all 39 connectors (`identity.py`,
`detect/credential_lifecycle.py`, `graph_engine.py`). Externally we never say "NHI". SMBs search
for "API key leaked", "service account", "SOC 2 evidence", "is my Redis exposed".

Why this anchor and not the alternatives:

| Candidate | For | Against | Role |
|---|---|---|---|
| **Access map** (API keys / service accounts / agent credentials your middleware accepts) | Every 2025–26 headline incident is a machine-credential story (Salesloft Drift 700+ orgs, Shai-Hulud, Snowflake, Vercel/Context.ai, Nx). Enterprise NHI vendors all got acquired and left the SMB tier empty. GitGuardian's own report concedes "where is it used" is the missing context. SOC 2 CC6.1–6.3's most common exception is "no register of service accounts"; PCI 4.0.1 req 8.6 has been mandatory since March 2025. Uses the asset nobody else has: read access to the **acceptance** side of a credential. | Needs last-used telemetry we do not collect yet for most connectors. Needs broker credentials, a bigger ask than a GitHub app. | **Anchor** |
| **Internet-exposed integration layer in five minutes** (the `discovery` connector run from outside, no credentials) | Cheapest to try, one real finding with the n8n CVSS-10 or RabbitMQ OAuth-secret CVE attached, perfect free tier. | Thin moat (Shodan, Censys, Intruder adjacent). One-time value. | **Free entry** |
| **SOC 2 / PCI evidence pushed to Vanta/Drata** | Compliance is the only approved security budget line at most 50–500 person companies. Neither Vanta (400 integrations) nor Drata lists Kafka/RabbitMQ/Redis/Kong/Istio. | Add-on to a $10k platform they already pay; annual not continuous trigger; Vanta is moving toward agents fast. | **Expansion SKU + channel** |

The three stack: free exposure scan → paid access map → compliance expansion.

### What the access map must show per credential

| Column | Source today | Gap to close |
|---|---|---|
| Identity, type, system | `identity.py` across all connectors | none |
| Grants / scope (what it can read or write) | `grant` resources, wildcard rules | none |
| **Owner** | nothing | owner label, inferred from tag/annotation/name prefix, confirmable in UI |
| **Last used** | RabbitMQ connections, Redis ACL LOG, NATS connz, PgBouncer, Kafka consumer groups (`runtime_evidence.py`) | AWS IAM Access Advisor + CloudTrail LookupEvents for SQS/SNS/MSK/APIGW principals; Confluent API-key usage; Kong via access logs (mark unknown if none); K8s SA token (unknown without audit log — say so) |
| **Internet-reachable** | `ATTACKPATH.*`, exposure labels | join with discovery/public-scan results |
| **Also in git** | `connect/iac.py` fingerprints secrets but never values | match principal **names** (SASL user, Kong key-auth consumer, AWS access key ID) against repo manifests; integrate TruffleHog/GitGuardian findings rather than build a source scanner |
| **Stale / default / shared / never-rotated verdict** | 7 `CREDENTIAL.LIFECYCLE.*` rules, mostly `not_assessable` today | fires for real once last-used lands |
| **Belongs to an automation or agent** | n8n, Workato, MCP connectors | add Zapier; label identities used by n8n/Workato/Zapier/MCP as "automation"; this is how MCP stays in the product without being the headline |

## 3. Feature scoring: keep, merge, cut

Scored on four questions: does an SMB with no security team understand it in the first session,
does a CSPM or Vanta already show it, does it feed the anchor, and is it proven in the tree.

### Console: 15 surfaces → 6

| Today (nav) | Decision | Where it goes |
|---|---|---|
| Overview | **Keep** | Lead with access-map summary + "what changed this week", then posture score |
| Findings + detail | **Keep** | Absorbs Attack paths as a "Priority paths" tab and supply-chain CVE/EOL findings as a facet |
| Attack paths | **Merge** | Into Findings. It is the best finding we produce, not a separate product |
| Identities | **Keep, becomes the anchor** | Renamed **Access**. Absorbs Runtime (last-seen column) and the Data lens (sensitive-data column per grant) |
| Runtime | **Merge** | Into Access as "last used" and "connected now" |
| Data | **Merge** | Naming-based classification becomes a column and a filter, not a page. Thin on its own (inference only) |
| Assets | **Merge** | Into Estate as the inventory tab |
| Systems (catalogue) + Connections | **Merge** | One **Estate** page: connected, discovered-but-unmonitored, and "what we can assess" as a collapsed section |
| Discovery | **Merge** | Into Estate as the "shadow / unmonitored" tab; also becomes the free external scan |
| Scans | **Merge** | A history drawer on each connection; not a nav item |
| Supply chain | **Split** | CVE/EOL findings → Findings facet. SBOM/VEX/licensing → Compliance "Reports & exports". Licensing panel hidden by default |
| Compliance | **Keep, fix the catalogue** | Add SOC 2 TSC and ISO 27001:2022 (currently PCI, DORA, NIS2, HIPAA, MCP only — `compliance/map.py:68`). Add register export and Vanta/Drata push |
| Settings: integrations, members | **Keep** | Add weekly Slack digest |
| Admin | **Keep (internal)** | unchanged |

Final nav: **Overview · Findings · Access · Estate · Compliance · Settings.**

### Connectors: 39 in code → 12 on the shelf

Keep every connector in the code. Change what the catalogue shows by default.

- **Shelf (SMB, cloud-new):** AWS, GCP, Azure, Kubernetes/Istio, Kafka (incl. MSK/Confluent/Redpanda as one card), RabbitMQ, Redis, Kong + API Gateway, n8n, MCP, OpenAPI/GraphQL (one card), IaC/repo. Twelve cards, each with a one-click or copy-paste setup (CloudFormation for the AWS role, a read-only user script for each broker).
- **"Enterprise, on request":** IBM MQ, Solace, ActiveMQ, Pulsar, MFT, MuleSoft, Boomi, Workato, Flink, Airflow, Kafka Connect, Schema Registry, Solr, Elasticsearch, Memcached, PgBouncer, NATS, MQTT, gRPC, Vault, Keycloak, VectorDB, coordination (etcd/ZooKeeper/Nacos/Consul). Hidden behind a toggle; still scanned if a prospect asks.
- **Add one:** Zapier (the automation SMBs actually run), so the "automation holds credential X" story covers n8n + Zapier + Workato + MCP.

### Engine capabilities

| Capability | Decision |
|---|---|
| Deterministic detectors, `not_assessable` third state, citation-gated AI triage | **Keep.** This is the trust story for a buyer with no one to second-guess the tool. Stop marketing the ledger and "448 detectors"; let the finding page show the citation |
| NHI derivation + credential lifecycle + graph engine | **Keep, invest.** Everything in §2 builds here |
| Discovery / shadow middleware | **Keep, productise** as the free external scan with domain/IP ownership verification |
| SBOM + OSV + NVD + EOL | **Keep as findings**, hide the SBOM/licensing UI. EOL of a running broker is a finding Wiz does not file |
| VEX, OSCAL exports | **Park.** Keep endpoints, remove from UI. Regulated upsell later |
| Licensing inventory | **Park.** Not a security outcome |
| Collector + on-prem | **Park** for enterprise deals. Do not mention in SMB material. On-prem has never been booted |
| Compliance catalogue | **Fix.** SOC 2 and ISO 27001 missing is the single largest mismatch with the target buyer |
| Notify (Slack/Teams/webhook/email/Jira/SIEM) + routing | **Keep.** Add weekly digest |
| Remediation | **Upgrade.** Today it is a free-text string on each rule (615 strings, `contracts.py:40`). Needs an exact copy-paste fix per system (CLI / Terraform / Helm / console steps) and a **Verify** button that rescans and auto-closes |
| Atlas items 27, 28, 39, 49, 50, 58 (ITDR, SPIFFE, signed bundles, OPA, Terraform provider, MSSP mode) | **Defer** past this horizon |

## 4. New features, ranked

| # | Feature | Why | Effort | Depends on |
|---|---|---|---|---|
| 1 | **Last-used telemetry** for AWS (IAM Access Advisor, CloudTrail lookup), Confluent (API-key metrics), plus owner attribution; make `CREDENTIAL.LIFECYCLE.*` fire for real | Turns the inventory into verdicts. The anchor is hollow without it | 2 wk | AWS connector adds `iam:GenerateServiceLastAccessedDetails`, `cloudtrail:LookupEvents` (still read-only) |
| 2 | **Access page** (identity × grant × last-used × exposed × in-git × owner) + **auditor register export** (CSV/PDF mapped to SOC 2 CC6.1–6.3, PCI 8.6.1–8.6.3) | The anchor surface and the compliance hook in one | 2 wk | 1 |
| 3 | **Guided fix + Verify** on every finding: exact per-system fix snippet, rescan, auto-close, "fixed by / verified at" in the ledger | SMBs buy fixes. Read-only stays intact; the loop closes | 2 wk | none |
| 4 | **SOC 2 + ISO 27001 + CIS mapping** in `compliance/map.py`; **Vanta/Drata custom-evidence push** as an integration type | The budget line that exists | 1.5 wk | 2 |
| 5 | **Free external exposure scan**: enter a domain or IP range, verify ownership (DNS TXT or cloud-account match), get a public-safe report with CVE/EOL attached, no credentials | Top of funnel; the Wiz/Aikido "real finding in minutes" pattern | 1.5 wk | discovery connector + ownership gate |
| 6 | **Ten-minute onboarding**: CloudFormation one-click role, per-broker read-only user scripts, progress checklist, first-finding celebration | STATUS.md admits nothing measures or guides onboarding | 1 wk | none |
| 7 | **Automation and agent inventory**: Zapier connector; label identities held by n8n/Zapier/Workato/MCP; "this automation can write to `payments.*`" | SMB AI adoption barrier #1 is data security (Upwork Q1 2026, 27%); MCP becomes a node, not a headline | 1.5 wk | 2 |
| 8 | **Pricing, billing, marketplace**: free tier (external scan + 1 system), Team ~$299/mo up to 5 systems, Business ~$799/mo up to 20, Enterprise quote (SSO, collector, on-prem). AWS Marketplace listing | Per-system is legible (Prowler per account, KafkaGuard per cluster); per-identity feels punitive | 1.5 wk | Stripe + `usage` table (written by nothing today) |
| 9 | **Weekly Slack digest**: new credentials, newly exposed, newly unused, fixed | Keeps a no-security-team buyer engaged between scans | 0.5 wk | notify.py |
| 10 | **Git correlation**: principal names found in repo manifests; ingest TruffleHog/GitGuardian findings via webhook | "Also in git" column | 1 wk | iac connector |

Engineering hygiene that gates every POC, from STATUS.md: CI green on GitHub (never observed),
the duplicated posture formula and scheduler payload lockstep tests, `verify_ledger()` wired to
`vectasec doctor`, per-user JWTs on console calls. Budget one week across the plan.

## 5. Eight-week plan

| Sprint | Ships | Demo at end |
|---|---|---|
| **1 (wk 1–2)** | Nav consolidation to six pages; connector shelf tiering; SOC 2 + ISO 27001 catalogue; AWS last-used + owner attribution; CI green | Connect AWS + one broker, see Access page with real "unused 90 days" rows |
| **2 (wk 3–4)** | Access page complete (exposed, in-git, automation labels); auditor register export; Guided fix + Verify | Fix a wildcard ACL from the finding page, press Verify, control flips, register PDF downloads |
| **3 (wk 5–6)** | Free external exposure scan with ownership gate; ten-minute onboarding; pricing + billing + free tier; Slack digest | A stranger signs up, scans their domain, sees an exposed RabbitMQ with the OAuth-secret CVE, upgrades |
| **4 (wk 7–8)** | Vanta/Drata push; Zapier connector + automation inventory; POC kit; AWS Marketplace submission | Evidence lands in a Vanta sandbox; "this Zapier automation can write to orders topic" |

## 6. POC playbook for the next 30 days

Target: 5 paid-or-free POCs with 50–500 person companies new to cloud, 0–2 security people.
Run each in 45 minutes:

1. **Before the call** (free scan): their domain through the external exposure scan. Arrive with one
   real finding.
2. **Minute 0–10**: CloudFormation read-only role + one broker read-only user. Scan.
3. **Minute 10–30**: show three things their CSPM and Vanta cannot show. Pick from: `guest/guest`
   or default account in active use; wildcard ACL on a topic named like payments or PII; broker
   on an end-of-support branch; credential unused for 90 days with write grants; automation
   holding a production credential.
4. **Minute 30–45**: Guided fix + Verify on one of them. Download the register. Offer Slack digest.
5. **Ask**: a 60-day POC with a named success criterion (register accepted by their auditor,
   or N findings fixed and verified), a logo, and a reference call for Alex's network.

Channel to add in parallel: two or three vCISO / MSSP firms who run SOC 2 for SMBs and cannot
assess brokers manually; they bring the client list.

Citable incidents for the deck (sourced in the research notes; verify dates before use):
Salesloft Drift OAuth (Aug 2025, 700+ orgs), Shai-Hulud npm worms (Sep/Nov 2025), Snowflake
(unrotated credentials, 165 customers), Vercel / Context.ai OAuth (Apr 2026), n8n
CVE-2026-21858 (CVSS 10, unauthenticated RCE), RabbitMQ CVE-2026-57219 (management endpoint
returns the OAuth client secret), RediShell CVE-2025-49844 (~60k unauthenticated exposed
Redis), LiteLLM MCP auth bypass CVE-2026-59822 (CISA KEV), Unimed (14M patient chats via an
unsecured Kafka).

## 7. What we stop saying

- "448 detectors across 39 connectors" → "the fifteen things your cloud scanner and your
  compliance tool cannot see inside your brokers and gateways."
- "Non-human identity posture" → "every API key and service account that can touch your data."
- "MCP security" → "which automations and AI agents hold which credentials."
- "Hash-chained evidence ledger" → "every finding shows you the config line it came from."
- "Middleware security platform" → nothing; there is no budget line with that name.

## 8. Risks stated plainly

- **Vendor staying power** is the top SMB buying criterion. Counter: exportable data, open
  detector definitions, and public pricing.
- **Last-used for Kong and Kubernetes** is not available agentlessly. The Access page must say
  "unknown" rather than "unused", as `runtime_evidence.py` already does for Kafka.
- **Broker credentials are a bigger ask** than a cloud role. The free external scan and the AWS
  role exist to earn that trust first.
- **Vanta and Drata could absorb this.** They have no broker integrations today; move first and
  become their evidence source rather than their competitor.
- **No customer, no SOC 2, CI never green.** POCs are the fix for the first; the second starts
  after the first paying logo; the third is a one-week task and must happen in sprint 1.
