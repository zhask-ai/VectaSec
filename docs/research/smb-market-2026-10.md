# SMB market and competitor research — October 2026

Sources behind `docs/vectasec-smb-strategy-2026-10.md`. Two web sweeps (~55 searches) on
2026-10-17. Tags: [V] primary/press-verified, [T] third-party aggregator, [I] inference.

## Competitors

**NHI (consolidated 2026, all enterprise-quoted, none read broker/mesh/gateway principals)**
- Astrix → Cisco, announced 2026-05-04, ~$400M [T]. https://convergedigest.com/cisco-to-acquire-astrix-security-to-address-ai-agent-identity-risks/
- Entro → SailPoint, closed 2026-06-29, ~$200M [T].
- Oasis → Cyera, $1B, closed Sept 2026 [V]. https://itbrief.news/story/cyera-completes-usd-1-billion-oasis-security-deal
- Natoma → Snowflake, intent 2026-05-27 [V]. https://www.snowflake.com/en/news/press-releases/snowflake-announces-intent-to-acquire-natoma-providing-secure-connectivity-for-the-agentic-enterprise
- Tracker: https://nhigovernance.com/market/nhi-consolidation-tracker.html ; CSA note: https://labs.cloudsecurityalliance.org/research/csa-research-note-cisco-astrix-ai-agent-identity-market-cons/
- Silverfort (Fabrix, AWS/Azure NHI), Aembit (workload IAM, needs agent), Clutch, Token Security remain independent. "Custom enterprise pricing, challenging for mid-market" https://hackread.com/astrix-aembit-alternatives-ai-agent-identity-security/
- Wiz NHI dashboard + Service Catalog of agents/MCP servers https://www.wiz.io/blog/non-human-identities-dashboard ; Orca cloud-IAM NHIs; Okta for AI Agents GA 2026-04-30; Entra Agent ID via Agent 365 $15/user/mo [T].

**API security (traffic/schema, not gateway control-plane posture)**
- Salt, Noname/Akamai, Traceable/Harness, Cequence, 42Crunch, StackHawk: custom pricing, ~$200–600/API/mo [T] https://www.getastra.com/blog/api-security/api-security-pricing/
- SMB-priced: Akto Free (25 endpoints) / Pro $490/mo, has MCP module https://akto.io/pricing ; Beagle $359/mo; Astra from $199/mo.

**CNAPP/CSPM for SMB (the budget competitor)**
- Wiz Marketplace Essential $24k / Advanced $38k per 100 workloads/yr [T]; Orca $7–30k/mo packs [T]; Prowler Cloud $79–99/cloud-account/mo https://prowler.com/pricing ; Aikido $350/$700/$1,050 flat, free tier https://www.codeant.ai/blogs/aikido-security-pricing ; Aikido $60M Series B at $1B Jan 2026 https://fintech.global/2026/01/15/aikido-security-secures-60m-to-advance-autonomous-security/
- CSPMs see exposed ports (Wiz: 330k exposed Redis, 60k no-auth https://www.securityweek.com/critical-vulnerability-puts-60000-redis-servers-at-risk-of-exploitation/) but never log into the broker.

**AI agent / MCP security (crowded)**
- Protect AI → Palo Alto; Prompt Security → SentinelOne ~$180M; Invariant → Snyk (Agent Scan) https://labs.snyk.io/resources/snyk-labs-invariant-labs/
- Zenity $125M Series C 2026-08-03 https://siliconangle.com/2026/08/03/israeli-startup-zenity-bags-125m-funding-build-security-layer-ai-agents/ ; Noma $132M; Lasso; Varonis Atlas; Runlayer $11M https://fintech.global/2025/11/24/runlayer-raises-11m-to-secure-enterprise-mcp-tools/
- MCP gateways: Docker MCP Gateway, Bifrost, Lunar MCPX, MintMCP, Obot, Zuplo (free tier) https://obot.ai/blog/the-13-best-mcp-gateways-for-enterprise-teams/
- Vanta shipped a remote MCP server and Claude plugin Apr 2026 https://www.vanta.com/resources/new-in-vanta-april-2026

**Direct lane (broker/gateway/mesh posture)**
- KafkaGuard: Kafka-only, 45–55 controls, $79–239/cluster/mo, free 1 cluster https://www.kafkaguard.com/pricing/
- Istio: `istioctl analyze`, OpenMeshGuard (early) https://github.com/openmeshguard/openmeshguard , Snowcat (stale)
- Conduktor/Gravitee/Confluent Gateway are enforcement proxies, not posture; Kong has a 24-point Konnect hardening checklist, no dashboard https://konghq.com/events/webinars/hardening-konnect
- "No single tool is dedicated solely to Kafka audits" https://tuxcare.com/blog/apache-kafka-security/

## Differentiator verdicts
| Claim | Verdict |
|---|---|
| NHI graph from brokers/meshes/gateways/iPaaS | Unique in sourcing; graph concept is commodity |
| Running-estate SBOM + EOL | Rare; Kafka has no official EOL dates, label inferred |
| Citation-gated AI | Differentiated UX, not a moat |
| MCP server posture | Commodity by late 2026 |
| Shadow-middleware discovery | Partly unique |
| VEX export | Low value to SMB; regulated upsell |
| Evidence ledger | Commodity in compliance tools; position as feeding Vanta/Drata |

## SMB buyer facts
- >50% of companies have ≤1 full-time security person [T] https://www.strongestlayer.com/blog/security-buyer-priorities-2026
- Upwork Q1 2026 (10–99 employees): data security/compliance is #1 agent-adoption barrier, 27% https://www.upwork.com/resources/state-of-ai-in-smbs ; Techaisle: shadow-AI governance #4 SMB issue https://www.techaisle.com/blog/668-2026-smb-top-10-business-issues-tech-priorities-agentic-ai-shift
- Compliance pricing [T, conflicting]: Vanta ~$10–23k/yr, Drata ~$7.5k+, Secureframe ~$7k, Sprinto ~$4–10k https://cavanex.com/blog/soc-2-compliance-platforms-compared-2026
- Vanta/Drata have no native Kafka/RabbitMQ/Redis/Kong/Istio integrations; custom evidence API https://www.vanta.com/products/vanta-api
- SOC 2 CC6 auditors want an NHI register (owner, purpose, scope, created); common exception "no register / MFA not for service accounts" https://www.idenhq.com/playbooks/soc-2-cc6-evidence-checklist
- PCI DSS 4.0.1 req 8.6.1–8.6.3 mandatory since 2025-03-31 https://oneuptime.com/blog/post/2026-09-24-pci-dss-application-system-account-credentials/view
- PLG pricing anchors: Snyk $25/dev, Semgrep ~$30/contributor, GitGuardian $18/dev, Infisical $18–20/identity, Doppler $21/user, Tailscale $6/user, Cloudflare Access $7/user.
- Remediation norm: PR/IaC patch, direct write gated (DoIT 2026-10-08 Terraform PRs https://www.doit.com/changelog/new-in-insights-remediate-infrastructure-issues-with-terraform-github-prs-early- ; Aikido AutoFix https://help.aikido.dev/autofix-and-remediation/faq/why-does-autofix-close-prs)
- Channels: AWS Marketplace (all CSPMs list), MSP/MSSP (2,698 US MSPs https://mspfinders.com/blog/us-msp-market-report-2026), vCISO firms [I].
- Vendor staying power ranks above price for 73% of security buyers (physical-security sample, analogy only) https://www.marketscale.com/industries/business-services/73-of-security-buyers-put-vendor-staying-power-ahead-of-price-and-performance

## Incidents for the deck (verify dates before use)
- Salesloft Drift OAuth, Aug 2025, 700+ orgs https://www.upguard.com/blog/salesloft-drift-breach
- Shai-Hulud npm worms Sep/Nov 2025, 800+ packages https://krebsonsecurity.com/2025/09/self-replicating-worm-hits-180-software-packages/
- Snowflake 2024: 165 customers, unrotated creds, no MFA https://darkreading.com/threat-intelligence/snowflake-account-attacks-driven-by-exposed-legitimate-credentials
- Vercel / Context.ai Apr 2026 https://www.trendmicro.com/en_us/research/26/d/vercel-breach-oauth-supply-chain.html
- Nx s1ngularity Aug 2025 https://www.wiz.io/blog/s1ngularity-supply-chain-attack
- n8n CVE-2026-21858 CVSS 10 https://censys.com/advisory/cve-2026-21858
- RabbitMQ CVE-2026-57219 OAuth secret via unauthenticated management endpoint https://thehackernews.com/2026/07/rabbitmq-flaws-could-leak-oauth-secrets.html
- RediShell CVE-2025-49844 https://www.darkreading.com/cloud-security/patch-now-redishell-redis-rce
- LiteLLM MCP auth bypass CVE-2026-59822, CISA KEV 2026-09-02 https://www.wiz.io/vulnerability-database/cve/cve-2026-59822
- Unimed 14M patient chats via unsecured Kafka https://www.scworld.com/brief/unimed-platform-misconfiguration-exposes-14m-patient-doctor-communications
- GitGuardian 2026: 28.65M new secrets in public GitHub in 2025, 64% of 2022 leaks still valid https://www.ciodive.com/press-release/20260317-ai-is-fueling-secrets-sprawl-gitguardian-reports-an-81-surge-of-ai-servic/
- MCP: 8.5% of registry servers use OAuth; 492 unauth internet-facing servers [T] https://nimblebrain.ai/blog/state-of-mcp-security-2026/
