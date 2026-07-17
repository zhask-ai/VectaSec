# VectaSec

**A security posture platform for the integration layer** — the message brokers, API gateways, service meshes, iPaaS/ESB platforms, and MCP / agent gateways that connect a company's systems together.

VectaSec builds a live inventory of everything running and how it's wired, checks each asset against a security benchmark, maps the results to compliance frameworks, and presents findings through an AI assistant that explains and prioritizes them. Detection is deterministic; the AI is grounded — every claim it makes cites a stored observation.

It ships **two ways from one codebase**:

- **Hosted SaaS** — a multi-tenant control plane we run on Supabase; customers connect in minutes.
- **On-prem / self-hosted** — a regulated customer runs the *entire* stack (self-hosted Supabase + our services) in their own environment; nothing leaves their network.

Because the systems being scanned live in private networks with no cloud-API equivalent (there's no `AssumeRole` that returns a Kafka ACL), the **primary** collection path is a lightweight **customer-side Collector** that reads systems locally, keeps their credentials and raw data in the customer's network, and sends only findings outward over an outbound-only channel. Managed middleware (MSK, API Gateway, hosted MCP) can optionally be reached agentlessly via a cross-account read-only role — no install — for a first finding in minutes.

**Positioning:** we don't sell "middleware security" as a category (no budget line yet). The wedge is **Non-Human Identity + integration posture** — the OAuth tokens, service accounts, connectors, and MCP tools across your brokers, iPaaS, gateways, meshes, and agent gateways that Wiz/Salt/CNAPP can't see — with **MCP/agent-gateway security as the fast-growing land-grab** and the Salesloft Drift breach as the cold-open.

## What it does

| Capability | What it does |
|---|---|
| **Discovery** | Inventories every broker, topic, gateway, route, mesh service, iPaaS recipe, credential, and MCP tool, and maps how they connect. |
| **Posture** | Scores each asset against a security benchmark (Kafka ACLs, Kong auth, Istio mTLS, …) into findings with severity and remediation. |
| **Identity** | Inventories non-human identities and OAuth grants; flags over-scoped, stale, or leaked credentials and their blast radius. |
| **Supply chain** | SBOM + CVE scan of connectors/images/deps; static analysis of integration-as-code (DataWeave, gateway policies, workflow JSON, MCP manifests). |
| **Compliance** | Maps findings to PCI DSS 4.0.1, DORA, HIPAA, NIS2; generates audit evidence and the DORA Article 28 register. |
| **MCP security** | Discovers MCP servers/tools and agent gateways; scans for tool-poisoning and auth-spec violations; ties each tool to the middleware it wraps. |
| **Runtime** *(optional)* | In-cluster sensor for east-west traffic, egress anomalies, and attack paths. |

## Architecture (one line)

A Supabase-backed control plane (Postgres + RLS multi-tenancy, Auth/SSO, Storage, Realtime, `pgmq` queue, Vault) + a Python **engine** (connectors, deterministic detectors, grounded AI, compliance) + a customer-side **Collector** for private systems. Runs as multi-tenant SaaS or fully on-prem from the same artifacts. Credentials for private systems never leave the customer's environment.

## Full plan

See **[docs/vectasec-build-plan.md](docs/vectasec-build-plan.md)** for the product critique, market analysis, complete architecture (control plane, Collector, both deployment modes), credential/trust model, data model, tech stack, pricing hypothesis, and the phased build plan.

## Status

Founding plan (v2) complete; Phase 0 (foundation) next.
