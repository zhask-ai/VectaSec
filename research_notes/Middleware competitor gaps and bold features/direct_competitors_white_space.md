# Direct competitors and white space for "security of the middleware / integration layer" (state as of 23 November 2026)

Evidence labels used throughout:
- **[V]** = I read the primary doc, changelog or repository myself in this session.
- **[VC]** = vendor-claimed (vendor page, press release or vendor-authored comparison).
- **[3P]** = third-party report, index or trade press.
- **[S]** = taken from a search-result summary only; I did not open the underlying page. Treat as a lead, not a fact.

Method note: open-source check counts were produced by downloading the full git trees of Prowler (`master`), Checkov (`main`) and trivy-checks (`main`) on 2026-11-23 and counting check files per service directory. Prowler and Trivy counts are exact directory counts. Checkov counts are filename-pattern matches and are approximate.

Vendors named in the brief that I did NOT get to (no docs read, no claim made): Tyk, 42Crunch, Wallarm, Cequence, Levo, Escape, StackHawk, Pynt, Traceable/Harness, Tetrate, Solo/kgateway, Buoyant, Isovalent, Aiven, StreamNative, Zilla, Steampipe, Wiz, Orca (config rule counts), Grip, Wing, DoControl, Adaptive Shield/CrowdStrike, Obsidian, Reco, AppOmni, Trail of Bits MCP tools, Cloudflare MCP, Lasso (beyond index row), Operant, Noma, Pillar, Prompt Security, Censys, runZero, watchTowr, Shadowserver. These are listed again under the relevant Gaps.

---

## 1. Kafka / streaming security and governance: what the incumbents offer, what needs a proxy, what they do not cover

### Takeaway
Every Kafka-side rival found is either (a) a per-cluster management console with RBAC/masking/audit, or (b) a proxy/gateway that must sit in the data path to enforce encryption, masking and ACLs. None of the pages I read describes an agentless, cross-vendor posture assessment, credential last-used inventory, posture score or compliance-framework evidence for brokers.

### Cited Findings

**Conduktor (Console + Gateway; Shield, Trust)**
- [VC] Conduktor Gateway is described as a transparent Kafka proxy enforcing encryption, governance policies, traffic control, data masking and multi-tenancy. Shield is described as a SaaS platform centralising encryption, access control and compliance for sensitive data in Kafka. Trust (launched August 2025) is in-stream data quality enforcement, not a security product. [S] — [Conduktor Gateway docs](https://docs.conduktor.io/gateway.md); [Conduktor data protection](https://www.conduktor.io/solutions/use-case/data-protection); [Conduktor product releases](https://conduktor.io/product-releases)
- [V] Releases August-November 2026: Console 1.47.1 (2026-09-03), 1.47.2 (2026-09-22), 1.48.0 (2026-10-15, Gateway fleet view, Kafka SQL deprecated), 1.48.1 (2026-10-22), 1.48.2 and 1.49.0 (2026-11-19, agents, stricter permission checks, MCP server stops accepting admin API keys, application-instance API key advisory); Gateway 3.22.0 (2026-10-07, Azure/GCP/Fortanix KMS external connections, crypto shredding, client addresses in audit events), 3.22.1 (2026-10-16, fixed OAUTHBEARER identity spoofing in Kafka-managed mode), 3.22.2/3.22.3 (2026-10-22/23, eMudhra CA compromise fix), 3.23.0 (2026-11-19, Thales CipherTrust KMS, field-level encryption performance, ACL and service-account storage changes), 3.22.4 (2026-11-19). — [Conduktor release notes](https://docs.conduktor.io/guide/release-notes.md)
- [V] The release notes for this window (first 100k characters read) contain no mention of Shield, Trust, posture scoring or compliance mapping. — [Conduktor release notes](https://docs.conduktor.io/guide/release-notes.md)
- [VC, competitor-authored] Pricing: Team Edition $1,200 per seat per year; Community tier 50 users / 3 clusters; Gateway and Enterprise are sales-only. Console needs PostgreSQL 13+; "Gateway adds infrastructure in the data path". SOC 2 Type II. — [Factor House comparison, published 2026-06-17, updated 2026-10-05](https://factorhouse.io/articles/best-kafka-management-tools/)
- What a buyer still cannot get: masking/encryption/ACL enforcement without putting Gateway in the data path; anything for non-Kafka brokers.

**Kpow / Factor House**
- [VC] RBAC, multi-tenancy, SAML/OIDC/LDAP SSO, server-side masking, streamed audit log to SIEM. Single stateless JVM container, self-run only (no managed SaaS). From $4,500 per cluster per year with 100 users; free Community Edition up to 3 clusters without RBAC, masking or audit. — [Factor House comparison](https://factorhouse.io/articles/best-kafka-management-tools/)
- What a buyer still cannot get: a hosted option; security features in the free tier; any posture/misconfiguration assessment (none described on the page read).

**Lenses (owned by Celonis)**
- [VC, competitor-authored] Access control, data policies for masking (global by field, not role-aware), security groups; PostgreSQL plus an agent per cluster; production requires Kubernetes; Community free (2 clusters, 5 users), Team from $4,000/year for 15 users on one cluster. — [Factor House comparison](https://factorhouse.io/articles/best-kafka-management-tools/)
- [3P] Celonis announced the acquisition of Lenses.io in October 2021. — [SiliconANGLE, 2021-10-05](https://siliconangle.com/?p=560071)

**Open-source consoles (Kafbat UI, AKHQ, Redpanda Console community, Kafdrop, CMAK)**
- [VC, competitor-authored] Kafbat: YAML RBAC, non-role-aware masking, audit to a Kafka topic, community-maintained, last release v1.5.0 (April 2026). AKHQ: basic RBAC, global masking, opt-in audit. Redpanda Console: SSO/RBAC/masking/audit need an enterprise licence, one broker cluster per deployment. Kafdrop: no RBAC, audit or masking. CMAK: last release April 2022, ZooKeeper-dependent, does not work with Kafka 4.x KRaft. — [Factor House comparison](https://factorhouse.io/articles/best-kafka-management-tools/)
- Caution: the same page lists several 2026 CVE IDs for bundled libraries; I did not verify any of them against NVD.

**Confluent (an IBM company)**
- [VC] IBM completed the acquisition of Confluent on 17 March 2026 for $31 per share in cash, about $11B enterprise value. — [IBM newsroom, 2026-03-17](https://newsroom.ibm.com/2026-03-17-ibm-completes-acquisition-of-confluent,-making-real-time-data-the-engine-of-enterprise-ai-and-agents)
- [S] Confluent Cloud audit logs are retained on an independent cluster for a default of seven days and need a key scoped to that cluster; up to two active audit-log cluster API keys. — [Confluent audit log docs](https://docs.confluent.io/cloud/current/monitoring/audit-logging/configure.html)
- [S] The docs results surfaced no "last used" field for API keys; the documented approach is to filter `kafka.Authentication` audit events with a shell/jq pipeline. — [Confluent audit logging best practices](https://docs.confluent.io/cloud/current/monitoring/audit-logging/best-practices.html); [Best practices for API keys](https://docs.confluent.io/cloud/current/security/authenticate/workload-identities/service-accounts/api-keys/best-practices-api-keys.html)
- [VC] May 2026 launch: ML function for PII detection/redaction in Flink SQL (early access), Azure Private Link GA, Real-Time Context Engine GA, managed MCP server and Agent Skills. — [Confluent press release, 2026-05-19](https://www.confluent.io/press-release/build-and-secure-real-time-ai/)
- [S] Confluent Platform 8.4 docs include a "gateway" section (a Confluent-side gateway product exists). Not read. — [Confluent Platform gateway docs](https://docs.confluent.io/platform/8.4/gateway/index.html)

**Kong Event Gateway**
- [V] Changelog: 1.1.0 (2026-03-25: mTLS to backend clusters, mTLS client auth, JWT claims in ACL expressions); 1.2.0 (2026-06-29: Encrypt/Decrypt Fields policies AES-256-GCM, topic aliases, Kong Identity principal metadata); 1.2.1 (2026-08-04: CVE-2026-17578 AES-GCM key-usage-limit fix); 1.3.0 (2026-10-26: Request Rule Validator, Mask Fields policies, Record Transcode, AWS IAM auth to MSK, ACL support for IncrementalAlterConfigs, pprof endpoints off by default); 1.2.2 (2026-10-29) and 1.1.3 (2026-10-30) security dependency and trust-store bumps. — [Kong Event Gateway changelog](https://developer.konghq.com/event-gateway/changelog/)
- [S] Data planes are self-managed with the control plane in Konnect; docs state Event Gateway is only available through Konnect. — [Kong Event Gateway docs](https://developer.konghq.com/event-gateway/)
- [V] Every security feature in the changelog is a policy applied to Kafka traffic passing through the gateway; nothing in the changelog assesses the configuration of the backend brokers themselves. — [Kong Event Gateway changelog](https://developer.konghq.com/event-gateway/changelog/)
- What a buyer still cannot get: anything unless Kafka clients are re-pointed at the gateway; non-Kafka protocols (none appear in the changelog).

**Gravitee Kafka Gateway**
- [VC, S] Plans require OAuth/JWT/API key at the gateway; virtual clusters with their own auth chains including mTLS; authorization in GAPL (a Cedar subset) evaluated inline in each gateway; version 4.11 (April 2026) added multiple backend endpoints per Kafka API. — [Gravitee blog: operational control for Kafka](https://www.gravitee.io/blog/operational-control-for-kafka-rules-policies-multi-endpoints-tenant-support); [Gravitee Kafka proxy page](https://www.gravitee.io/kafka-proxy.html)
- [VC, S] Gravitee's own framing: the gateway is "a governed exposure layer" placed before the broker, "not by replacing the broker". — [Gravitee: securing event streams beyond broker ACLs](https://gravitee.io/kafka-governance-gate-gate-gate.html)

**Redpanda (Agentic Data Plane)**
- [3P/VC, S] ADP launched October 2025 (MCP and A2A connectivity); 18-19 February 2026 release added an AI gateway, OIDC identity, fine-grained authorization, OpenTelemetry-based observability; Redpanda's own post called it limited availability. I found no GA date. — [Help Net Security, 2026-02-19](https://www.helpnetsecurity.com/2026/02/19/redpanda-brings-identity-policy-control-and-data-governance-to-ai-agents/); [Redpanda blog: ADP limited availability](https://www.redpanda.com/blog/redpanda-agentic-data-plane-adp-is-now-available)

**Open-source Kafka ACL tooling**
- [S] Conduktor kafka-security-manager treats an external source as the source of truth for ACLs and reverts out-of-band changes; it manages ACLs but does not analyse them. Aiven Klaw is a self-service governance portal with request audit logging. `kafka-acl-report` parses `kafka-acls` output. None of the results is a tool that detects unused or wildcard ACLs. — [conduktor/kafka-security-manager](https://github.com/conduktor/kafka-security-manager); [aiven/klaw](https://github.com/aiven/klaw); [gnlabrie/kafka-acl-report](https://github.com/gnlabrie/kafka-acl-report/blob/main)

### Inferences
- "Mature products exist" is true for Kafka *governance and data-plane enforcement* (Conduktor, Confluent, Kong, Gravitee, Kpow). It is not shown to be true for *assessment*: none of the pages read describes scoring a cluster's configuration, ranking findings or mapping them to a framework.
- The proxy requirement is the structural weakness of the gateway vendors for a 0-3 person security team: Conduktor Gateway, Kong Event Gateway and Gravitee all need client traffic re-routed, and October 2026 shows the cost (Conduktor shipped four Gateway security releases in four weeks, including an identity-spoofing fix; Kong shipped trust-store and crypto fixes).
- All of these are Kafka-protocol only in the material read. A buyer running Kafka plus RabbitMQ plus Redis plus SQS gets coverage of one of four.

### Gaps
- Not read: Aiven, StreamNative, Zilla, Solo/kgateway Kafka features; Confluent Stream Governance pricing tiers and CSFLE requirements; Conduktor Shield docs (only marketing summary seen). No claim is made about them.
- I could not find any "Current 2026" announcement coverage; whether the event produced security launches in September-October 2026 is unconfirmed.
- The absence of an API-key "last used" field in Confluent Cloud is based on search summaries of the docs, not a full read of the API reference. Verify before using in sales material.

---

## 2. RabbitMQ, NATS, Redis, cloud queues: dedicated posture tooling versus generic CSPM checks

### Takeaway
No dedicated security-posture product for RabbitMQ, NATS or Redis turned up; what exists is pentest tooling and thin CSPM coverage of the AWS-managed variants. Open-source CSPM coverage is shallow on AWS (2-8 checks per service) and zero for Azure Service Bus, Event Hubs and GCP Pub/Sub in Prowler and Trivy.

### Cited Findings

**Prowler (exact counts from repo tree, 2026-11-23)** — [prowler-cloud/prowler services tree](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services)
- [V] Totals: AWS 683 checks, Azure 207, GCP 118, Kubernetes 88.
- [V] AWS `kafka` (MSK): 8 — encryption at rest with CMK, enhanced monitoring, in-transit encryption, is-public, mTLS auth, unrestricted access, latest version, connector in-transit encryption.
- [V] AWS `sqs`: 2 (not public, SSE). `sns`: 3 (no HTTP subscriptions, KMS, not public). `eventbridge`: 4 (cross-account bus, exposed bus, global endpoint replication, schema registry cross-account). `mq`: 5 (active/cluster deployment mode, auto minor upgrade, logging, not public). `elasticache`: 8 (public subnet, auto upgrade, failover, backup, in-transit, multi-AZ, at-rest, replication-group auth). `kinesis`: 2. `stepfunctions`: 3. `transfer` (AWS Transfer Family): 3.
- [V] AWS `apigateway`: 10; `apigatewayv2`: 2; `appsync`: 2. Azure `apim`: 1 (`apim_threat_detection_llm_jacking`). GCP `apikeys`: 4.
- [V] Azure provider has no `servicebus`, `eventhub` or `eventgrid` service directory. GCP provider has no `pubsub` or `memorystore` directory. There is no Prowler provider for Confluent, Kafka, RabbitMQ, NATS, Redis, Kong, n8n or any iPaaS (provider list: alibabacloud, aws, azure, cloudflare, e2enetworks, gcp, github, googleworkspace, huaweicloud, kubernetes, linode, m365, mongodbatlas, nhn, okta, openstack, oraclecloud, scaleway, stackit, vercel).
- [V] The only self-managed broker coverage is network-level: `ec2_instance_port_kafka_exposed_to_internet`, `ec2_instance_port_redis_exposed_to_internet`, and the matching security-group checks for 9092 and 6379.
- [V] For comparison, AWS `bedrock` has 23 checks, which shows where maintainer effort is going.

**Trivy (trivy-checks, exact counts)** — [aquasecurity/trivy-checks cloud checks](https://github.com/aquasecurity/trivy-checks/tree/main/checks/cloud)
- [V] 366 cloud rego checks in total. AWS: `msk` 3, `sqs` 3, `sns` 2, `mq` 3, `elasticache` 4, `kinesis` 1, `apigateway` 6. Azure service list has no Service Bus, Event Hubs or APIM; Google list has no Pub/Sub.

**Checkov (Terraform checks, approximate filename match)** — [bridgecrewio/checkov terraform checks](https://github.com/bridgecrewio/checkov/tree/main/checkov/terraform/checks)
- [V, approximate] About 1,146 Terraform check files in total. By filename: MSK ~12, MQ ~6, SQS ~5, SNS ~4, ElastiCache ~7, Kinesis ~6, API Gateway ~17, AppSync ~6, Azure APIM ~4, Event Grid ~6, Event Hub ~2, Pub/Sub ~4, Redis (Azure/GCP) ~4-6. These are IaC-time checks, not checks of running brokers.

**Datadog**
- [S] Out-of-the-box misconfiguration rules exist for MSK (encryption at rest and in transit, CMK, public accessibility, IAM client auth, ZooKeeper TLS), SNS (four rules) and SQS (two rules: SSE, public access). — [Datadog OOTB rules](https://docs.datadoghq.com/security/default_rules/); [SQS public rule](https://docs.datadoghq.com/security/default_rules/dsk-1y0-pv3/); [MSK in-transit rule](https://docs.datadoghq.com/security/default_rules/aws-msk-cluster-msk-clusters-should-be-encrypted-in-transit-among-broker-nodes/)

**Benchmarks**
- [V] The CIS Benchmarks catalogue has no benchmark for Apache Kafka, Confluent, RabbitMQ, Redis, NATS, Pulsar, ActiveMQ, IBM MQ, Kong, Istio, Airflow, MuleSoft or Apigee. It does list NGINX, MongoDB, Cassandra, Snowflake, Kubernetes, "Microsoft Dynamics 365 Power Platform" and "AI (MCP Server)". (Page was truncated when read; absence is for the portion returned.) — [CIS Benchmarks list](https://www.cisecurity.org/cis-benchmarks)
- [S] Azure Cache for Redis appears only inside the CIS Azure Database Services Benchmark (July 2024 update). — [CIS July 2024 update](https://www.cisecurity.org/blog/cis-benchmarks-july-2024-update)

**Dedicated tools found**
- [S] Darkmoon (GPL-3.0, self-hosted) has a messaging agent that targets Redis, RabbitMQ and NATS for unauthenticated access and default credentials; it is offensive pentest tooling, not a posture product. — [dark-moon.org](https://www.dark-moon.org/blog/rabbitmq-kafka-mqtt-penetration-testing-ai/)
- [S] Other hits were Redis exploit modules and generic network scanners; no RabbitMQ or NATS configuration auditor was found. — [Database-Security-Audit Redis notes](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/Redis%20database%20penetration%20testing); [nsasoft/nsauditor-ai](https://github.com/nsasoft/nsauditor-ai/)

### Inferences
- Against the free baseline, a 440-detector/39-connector product is not "mid" on depth: the entire Prowler AWS messaging surface (MSK+SQS+SNS+EventBridge+MQ+ElastiCache+Kinesis) is 32 checks, all control-plane attributes (encryption flags, public flags, logging). None looks inside the broker (ACLs, users, vhosts, default accounts, topic-level authz).
- The Azure and GCP messaging gap in open source is total in Prowler and Trivy. A buyer on Azure Service Bus/Event Hubs or GCP Pub/Sub cannot assemble a free equivalent at runtime; only Checkov IaC checks exist.
- With no CIS benchmark for any broker, auditors have no canonical control list, which cuts both ways: no one can say VectaSec is "non-standard", but there is also no external standard to claim conformance to.

### Gaps
- Wiz, Orca and Steampipe rule counts for messaging services were not obtained (one search returned nothing useful; I did not read their catalogues). The brief's question "how many checks do Wiz/Orca actually have" is unanswered.
- Datadog counts come from a search summary of the docs, not a full enumeration.
- I did not check Microsoft Defender for Cloud or AWS Security Hub native controls for Service Bus/Event Hubs/MSK; those exist and should be counted before claiming a gap against the hyperscalers' own tools.
- I did not verify whether RabbitMQ (Broadcom/VMware Tanzu), Synadia (NATS) or Redis Inc. ship their own security-advisor features in 2026.

---

## 3. API gateway and service mesh posture: configuration level versus traffic level

### Takeaway
Gateway-configuration posture exists only as single-vendor features (Apigee Risk Assessment for Apigee, Defender for APIs for Azure APIM) or as bring-your-own-rules linting (decK). The API security vendors I could check describe posture in terms of APIs and traffic, not gateway configuration. Kiali validates mesh config correctness but does not judge permissiveness, score posture or map to compliance.

### Cited Findings

**Google Apigee Advanced API Security: Risk Assessment**
- [V] Applies to Apigee and Apigee hybrid; requires the Advanced API Security add-on. — [Apigee risk assessment docs](https://docs.cloud.google.com/apigee/docs/api-security/security-scores)
- [V] Risk Assessment v2 has 33 checks across AI (3), Auth (11), CORS (3), Mediation (3), Target (3), Threat (5), Traffic (5). All are "is policy X present on the proxy / is TLS or mTLS set on the target" checks, each weighted minor/moderate/major. — [Apigee risk assessment docs](https://docs.cloud.google.com/apigee/docs/api-security/security-scores)
- [V] Stated limits: only deployed proxies scored; max 100 custom profiles; no notification of new scores; scores retained in Cloud Monitoring up to 6 weeks; custom profile checks are AND-only; v2 has no abuse-traffic source assessment; shared-flow chaining not assessed in v1. — [Apigee risk assessment docs](https://docs.cloud.google.com/apigee/docs/api-security/security-scores)
- [V] "Multi-gateway" security profiles in API hub cover only Apigee X, hybrid and Edge. No AWS API Gateway, Kong or Azure APIM is mentioned. — [Apigee API hub multi-gateway security profiles](https://docs.cloud.google.com/apigee/docs/apihub/manage-security-profiles-multi-gateway)
- What a buyer still cannot get: any non-Apigee gateway; credential/key hygiene; compliance mapping (none on the pages read).

**Microsoft Defender for APIs / API security posture**
- [S] Covers APIs published in Azure API Management; Consumption tier not available; self-hosted gateways and workspace-managed APIs are not onboarded; only REST APIs analysed; posture findings (external, unused, unauthenticated) need the Defender CSPM plan; cannot offboard individual APIs; onboarding consumes APIM compute and memory. — [Defender for APIs FAQ](https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-apis); [API security posture overview](https://learn.microsoft.com/en-us/azure/defender-for-cloud/api-security-posture-overview); [Support and prerequisites](https://learn.microsoft.com/sl-si/azure/defender-for-cloud/defender-for-apis-prepare)
- [S] Microsoft pages conflict on multi-region APIM support (FAQ says fully supported; prerequisites page says limited). — same sources.

**Kong (decK, Konnect)**
- [V] `deck file lint` is a generic JSON/YAML linter: rules are user-written (JSONPath selector + function + severity). The docs page describes no built-in security ruleset; the examples are user rules such as "service protocol must be https". — [decK file lint docs](https://developer.konghq.com/deck/file/lint/)
- [3P, S] Trend Micro's Kong case study names exposed admin API and missing cloud firewall rules as the leading Kong misconfigurations. (Older research; date not checked.) — [Trend Micro: Kong API gateway misconfigurations](https://www.trendmicro.com/vinfo/it/security/news/virtualization-and-cloud/kong-api-gateway-misconfigurations-an-api-gateway-security-case-study)

**Salt Security**
- [VC] Posture governance: "nearly 100 pre-loaded posture rules", templates and custom policies; maps to PCI DSS, PSD2, HIPAA, CCPA, GDPR, LGPD, NIST, FFIEC with exportable audit reports; extends to MCP servers and AI agents. Modules: Salt Code, Salt Connect (configuration), Salt Collect (runtime). The page names no gateway, describes no gateway-plugin/admin-API/credential checks, and does not mention Kafka, brokers or iPaaS. — [Salt API posture management](https://salt.security/use-cases/api-posture-management)
- [VC, S] Policy Hub reached 100 pre-built policies (61 auto-activating) covering data security, access control, OAuth, API architecture, MCP configuration, third-party risk, agent issues; Salt Code launched June 2026. — [Salt press release: 100 policies](https://salt.security/press-releases/salt-security-reaches-100-pre-built-policies-in-policy-hub-setting-new-standard-for-agentic-ai-governance); [IT Brief on Salt Code](https://itbrief.com.au/story/salt-code-enforces-security-policies-in-ai-coding-tools)

**Akto**
- [VC/3P, S] Ingests traffic via eBPF, Kubernetes, API gateways (Envoy, NGINX, Istio, Kong, Apigee, MuleSoft), cloud mirroring; 80+ connectors including MCP and AI-gateway connectors (Bedrock, AgentCore, Azure AI Foundry, Vertex, LiteLLM, Portkey). — [Akto connectors](https://www.akto.io/connectors); [apis.io Akto profile](https://apis.io/providers/akto/)
- [3P, S] Pricing is inconsistent across listings: Software Advice shows a starting price of $1,890/month; GetApp shows a free plan (25 endpoints); Capterra says contact vendor. No official figure obtained. — [Software Advice](https://www.softwareadvice.com/product/423223-Akto/); [GetApp](https://www.getapp.com/all-software/a/akto/); [Capterra](https://www.capterra.com/p/10012820/Akto/)

**Open-source gateway checks** (see section 2 for method)
- [V] Prowler: AWS API Gateway 12 checks in total (REST 10, v2 2); Azure APIM 1; nothing for Kong, Apigee, Tyk or Gravitee. Trivy: AWS API Gateway 6. — [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services); [trivy-checks](https://github.com/aquasecurity/trivy-checks/tree/main/checks/cloud)

**Service mesh: Kiali**
- [V] Kiali lists 72 coded validations (first 100k characters read; later sections counted from the index): AuthorizationPolicy 9, DestinationRule 12, PeerAuthentication 3, RequestAuthentication 2, VirtualService 10, Ambient workloads 7, K8s Gateway 4, and others. Security-relevant ones include KIA1301 (workload not covered by any authorization policy) and mTLS-mismatch checks. — [Kiali validations](https://kiali.io/docs/features/validations)
- [V] The validations page mentions no compliance mapping, no posture score, and no check that assesses whether a policy is too broad. — [Kiali validations](https://kiali.io/docs/features/validations)
- [3P, S] A third-party guide states Kiali does not flag policies as too permissive by default and does not flag an AuthorizationPolicy with empty rules that allows all traffic. — [OneUptime: Kiali for security policy visualisation, 2026-02-24](https://oneuptime.com/blog/post/2026-02-24-how-to-use-kiali-for-security-policy-visualization/view)

### Inferences
- The traffic-level API security vendors (Salt, Akto) are moving toward agents/MCP, not toward gateway configuration. Their 2026 launches in the material found are all agentic (Salt Policy Hub, Salt Code, Akto Argus/MCP connectors). That leaves gateway-config posture across Kong + AWS + Apigee + APIM unclaimed by a multi-vendor product in what I read.
- The first-party tools are strict silos: Apigee's "multi-gateway" means multi-Apigee; Defender for APIs means cloud-hosted APIM only (not even self-hosted APIM gateways).
- Apigee's 33-check v2 list is a useful public yardstick: it is the most detailed first-party gateway-config rule list found and it is entirely "policy present/absent".

### Gaps
- Not read: Tyk, 42Crunch, Wallarm, Cequence, Levo, Escape, StackHawk, Pynt, Traceable/Harness, Kong Konnect security features, Insomnia, AWS-native API Gateway controls in Security Hub. No claim is made about their gateway-config coverage.
- Not read: Tetrate, Solo, Buoyant, Isovalent mesh policy tooling, and `istioctl analyze` rule counts. The mesh conclusion rests on Kiali only.
- Salt's actual connector list (Salt Connect) and rule list are not public on the page read; the "no gateway config checks" statement means "not described on the use-case page", not "confirmed absent".

---

## 4. iPaaS and automation security: who does posture for n8n, Zapier, Make, Workato, MuleSoft, Boomi, Power Automate, Airflow

### Takeaway
The low-code/agent security vendors document connectors for Power Platform, Salesforce, ServiceNow and Workato; in the docs and press I read, none documents a connector for n8n, Zapier, Make, Boomi, MuleSoft or Airflow. n8n has a built-in single-instance audit plus hobby-grade community scanners; no funded n8n/iPaaS posture company surfaced.

### Cited Findings

**Zenity**
- [V] Zenity docs navigation lists integrations for Microsoft (incl. Fabric, Power Platform), OpenAI, Google, AWS, Salesforce, Anthropic, Cursor, GitHub, MCP Gateway, LiteLLM, custom agents, Cribl Stream, Okta, CrowdStrike, Palo Alto Networks, Workato, Airtable, Budibase, ServiceNow. Zapier, n8n, Make, MuleSoft, Boomi, Airflow, Kafka and general API gateways do not appear. — [Zenity documentation](https://docs.zenity.io/)
- [VC, S] Zenity marketing names UiPath, Workato, MuleSoft, OutSystems, Appian among platforms it "can secure", and lists n8n in a "homegrown AI" category; no connector setup for those is documented in the results. — [Zenity blog](https://zenity.io/blog/security/how-zenity-unifies-security-platform-and-citizen-developer-teams-to-enable-ai-agents); [Zenity academy: homegrown AI security](https://zenity.io/academy/homegrown-ai-security)
- [VC, S] Zenity was named an AI Security Platform Leader in Latio's 2026 AI Security Market Report and appears in SACR's agent security report. — [Zenity blog on Latio and SACR](https://zenity.io/blog/latio-SACR-ai-agent-security-reports)
- What a buyer still cannot get: n8n/Zapier/Make/Boomi/Airflow posture; anything for brokers or API gateways.

**Nokod Security**
- [VC/3P, S] Platforms named: Microsoft Power Platform (plus a free open-source Power Platform attack-surface assessment tool), ServiceNow (added August 2024), UiPath, Salesforce; a later profile adds Copilot Studio. No result mentions n8n, Zapier or Workato. Coverage found is 2024-2025 press; nothing confirmed for 2026. — [Business Wire launch, 2024-05-02](https://www.businesswire.com/news/home/20240502429235/en); [ServiceNow support press release](https://www.sdxcentral.com/press-releases/nokod-security-expands-lcnc-multi-platform-support-to-servicenow-and-joins-servicenow-partner-program/)

**SSPM / SaaS-to-SaaS**
- [VC, S] Valence has a Workato page ("Workato Security"). — [Valence: Workato](https://www.valencesecurity.com/saas-applications/workato)
- [3P, S] Astrix discovers OAuth tokens, API keys, service accounts and webhooks across SaaS apps via each platform's API; one source says Astrix ended standalone sales of new licences on 30 June 2026 (single source, unverified). — [guptadeepak.com NHI tools 2026](https://guptadeepak.com/tools/top-10-non-human-identity-security-2026/); [startwithidentity.com rankings](https://startwithidentity.com/rankings/best-non-human-identity-security-platforms/)
- [VC/3P] Cisco announced intent to acquire Astrix on 4 May 2026 and its blog was updated 29 June 2026 to say the deal completed; Calcalist reported about $400M. — [Cisco blog](https://blogs.cisco.com/news/cisco-announces-intent-to-acquire-astrix-security); [SiliconANGLE, 2026-05-04](https://siliconangle.com/2026/05/04/cisco-buys-astrix-security-strengthen-ai-agent-discovery-governance/); [Calcalist](https://www.calcalistech.com/ctechnews/article/dy5obf581)
- [3P] Cyera signed to acquire Oasis Security for about $1B (announced 28 July 2026); completion reported 8 September 2026 by trade press. — [TechCrunch, 2026-07-28](https://techcrunch.com/2026/07/28/cyera-agrees-to-acquire-Oasis-Security-for-1B-to-safeguard-proliferating-ai-agents/); [SecurityBrief](https://securitybrief.co.uk/story/cyera-completes-usd-1-billion-oasis-security-deal)

**n8n specifically**
- [V] n8n's built-in audit (`POST /api/v1/audit`) returns five risk reports: credentials, database, nodes, filesystem, instance. Options are limited to `daysAbandonedWorkflow` and a category filter. It is per-instance; the page describes no network exposure checks, fleet view or compliance mapping. — [n8n audit API docs](https://docs.n8n.io/connect/n8n-api/instance-operations/audit)
- [3P, S] GitGuardian research reported in August 2026: 321 live n8n instances accepted API tokens leaked in public GitHub commits. — [The Hacker News, August 2026](https://thehackernews.com/2026/08/leaked-n8n-api-tokens-exposed-live.html)
- [S] Community tools: `Perufitlife/n8n-security` (MIT, keyless active probe: unauthenticated `/rest/settings` leak, open owner setup, version vs CVEs); a "Legion n8n shield" CLI on the n8n forum; an Apify "n8n hygiene auditor"; a logicworkflow.com credential scanner that fronts a consulting funnel. — [Perufitlife/n8n-security](https://github.com/Perufitlife/n8n-security); [n8n community post](https://community.n8n.io/t/free-cli-tool-to-audit-common-self-hosting-risks-on-n8n/297669); [Apify auditor](https://apify.com/fractionalhqforyou/n8n-instance-hygiene-auditor); [logicworkflow scanner](https://logicworkflow.com/tools/free-n8n-credential-scanner/)
- [S] One source cites Censys counting 26,512 exposed n8n hosts (secondary citation; not verified at Censys). — [nhimg.org n8n security guide](https://nhimg.org/n8n-security-guide)

**Benchmarks / analyst maps**
- [V] CIS publishes a "Microsoft Dynamics 365 Power Platform" benchmark; nothing for n8n, Zapier, Workato, MuleSoft, Boomi or Airflow. — [CIS Benchmarks list](https://www.cisecurity.org/cis-benchmarks)
- [3P, S] Latio's 2026 AI Security Market Report (September 2026) covers roughly 400 AI security vendors mapped by use case; no iPaaS or integration-security category surfaced in the summaries seen. — [Backslash on the Latio report](https://www.backslash.security/resources/2026-ai-security-market-latio-report); [hackerspot.net commentary](https://www.hackerspot.net/p/what-the-2026-ai-security-market)

### Inferences
- The low-code security vendors have re-badged as AI-agent security and follow enterprise platforms (Microsoft, Salesforce, ServiceNow). The tools SMBs actually run (n8n self-hosted, Zapier, Make) are documented by none of them. This is VectaSec's clearest buyer-fit white space.
- Demand evidence for n8n is real and recent (August 2026 token-leak research; a visible cottage industry of free scanners), but every tool found is single-instance, single-product and unsupported.
- The NHI consolidation (Astrix into Cisco, Oasis into Cyera) removes two independent vendors that an SMB might have bought for integration-credential visibility and moves them up-market.

### Gaps
- Not read: AppOmni, Obsidian, Reco, Grip, Wing, DoControl, Adaptive Shield/CrowdStrike supported-app lists. Whether any of them lists Zapier/Make/n8n/Workato as a monitored app is unknown.
- Zenity's and Nokod's absence of n8n/Zapier connectors is based on Zenity's docs navigation and Nokod press coverage; neither vendor was asked and Nokod's 2026 docs were not found.
- No research done on Airflow, MuleSoft or Boomi native security-advisor features. Boomi's July 2026 MCPX acquisition (section 6) suggests Boomi is investing in governance itself.
- Power Automate is covered by Zenity, Nokod and Microsoft's own tooling; I did not quantify that coverage.

---

## 5. Managed file transfer: posture tooling beyond advisories and attack-surface scanners

### Takeaway
Nothing found beyond CVE advisories, vendor-authored breach commentary and internet-footprint counts. No product or open-source project was found that audits MFT configuration (MOVEit, GoAnywhere, Cleo, CrushFTP, SFTPGo, AWS Transfer Family) as posture.

### Cited Findings
- [VC, S] Kiteworks (a competitor) counts four critical MFT flaws in about 18 months: Cleo (December 2024), CrushFTP (March 2025), Wing FTP (July 2025), MOVEit (April 2026); and says Progress disclosed two MOVEit Automation flaws on 30 April 2026. — [Kiteworks: MFT breaches architecture pattern](https://www.kiteworks.com/cybersecurity-risk-management/mft-breaches-architecture-pattern/); [Kiteworks: MOVEit 2026](https://www.kiteworks.com/cybersecurity-risk-management/moveit-vulnerability-2026-cve-4670/)
- [3P, S] Petri reports a survey finding that 59% of organisations had an MFT security incident in the past year, mostly from basic preventable gaps (survey sponsor not checked). — [Petri](https://petri.com/mft-breaches-weak-security-controls/)
- [3P, S] Bitsight publishes an internet footprint page for Fortra GoAnywhere MFT (roughly 2,000 observed instances per the summary). — [Bitsight Groma Explorer: GoAnywhere](https://www.bitsight.com/groma-explorer/fortra/goanywheremanagedfiletransfer)
- [V] Prowler has 3 checks for AWS Transfer Family (FIPS security policy, in-transit encryption, PQC SSH key exchange) and no MFT-product provider. — [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services)

### Inferences
- MFT is the family where the breach record is strongest and posture tooling is weakest in what I found. The buyer conversation is still "patch faster" and "replace the product", not "audit the configuration".

### Gaps
- Not checked: Censys, runZero, watchTowr, Shadowserver MFT coverage; vendor-side hardening checkers (Progress, Fortra, Cleo, IBM Sterling); Tenable/Qualys compliance audit files for MFT products. A Tenable or Qualys audit policy for MOVEit or GoAnywhere may exist and would be the nearest substitute.
- The single search run was dominated by Kiteworks content; the "nothing found" conclusion is weak and should be re-tested before it is used publicly.

---

## 6. MCP and AI gateway security posture: what is commodity, what is missing

### Takeaway
MCP scanning and MCP gateways are crowded and commoditising fast: an independent index tracks 17 tools including free ones from Snyk, Cisco, Docker, Microsoft, IBM, Red Hat, Google Cloud and the Linux Foundation, and CIS published an MCP Server Benchmark in September 2026. What is not visible is MCP posture joined to the rest of the integration estate (brokers, gateways, iPaaS, credentials).

### Cited Findings
- [3P] Agent Security Index "MCP gateways & scanners: 17 tools compared" (updated November 2026) lists: agentgateway (Linux Foundation Agentic AI Foundation project since 2026-06-04; v1.7.0 on 2026-10-27), Cisco MCP Scanner (open source), IBM ContextForge MCP Gateway (v1.1.0 on 2026-10-20), Docker MCP Gateway (open source; a high-severity CVE fixed in 0.42.2), Google Cloud Agent Gateway (GA 2026-06-18), Kong AI Gateway, Lasso MCP Gateway (open source, v1.2.0 2026-01-21), Lunar.dev MCPX (acquired by Boomi, announced 2026-07-27), MCP-Shield (last push April 2025, stale), Microsoft MCP Gateway (open source), Mintive (formerly MintMCP; $11M raised in total incl. a $7M round led by Cowboy Ventures, announced 2026-10-29), NVIDIA SkillSpector, Obot MCP Gateway, PointGuard AI Gateway (launched 2026-10-29), Red Hat MCP Gateway (GA 2026-10-16), Runlayer, Snyk Agent Scan (formerly Invariant mcp-scan). — [Agent Security Index](https://agentsecurityindex.com/category/mcp-security/)
- [VC, S] Snyk Agent Scan detects prompt injection, tool poisoning, tool shadowing, toxic flows and rug pulls (tool-description hashing); it starts stdio MCP servers by executing their configured commands to read tool descriptions, and shares tool names/descriptions with Snyk for analysis. — [snyk/agent-scan](https://github.com/snyk/agent-scan)
- [VC] CIS released the CIS MCP Server Benchmark v1.0.0 on 16 September 2026. — [CIS press release](https://www.cisecurity.org/about-us/media/press-release/cis-releases-cis-mcp-server-benchmark-v1-0-0)
- [3P, S] Syndicated coverage says the benchmark has 55 recommendations across 10 domains; I did not see that count on a CIS page. — [EIN Presswire](https://www.einpresswire.com/article/942834622/cis-launches-ai-mcp-benchmark)
- [3P] Runlayer: $11M seed out of stealth (November 2025); $30M Series A led by Felicis with Khosla (announced 24-25 June 2026), $42M total. — [SecurityWeek seed](https://www.securityweek.com/runlayer-emerges-from-stealth-mode-with-11-million-in-funding/); [SecurityWeek Series A](https://www.securityweek.com/runlayer-raises-30-million-in-series-a-funding/); [Fortune, 2026-06-24](https://fortune.com/2026/06/24/exclusive-vinod-khosla-felicis-runlayer-nanit-30-million-enterprise-ai/)
- [VC] Obot AI raised a $35M seed for an enterprise MCP gateway (September 2025). — [Obot blog](https://obot.ai/blog/obot-ai-secures-35m-seed-to-build-enterprise-mcp-gateway/)
- [VC, S] Salt: MCP server discovery (September 2025), Agentic Security Posture Management covering LLM connectivity, agents, MCP servers and APIs. — [Salt press release](https://salt.security/press-releases/salt-security-launches-industrys-first-agentic-security-platform-for-the-ai-stack-across-llms-mcp-servers-and-apis)
- [V] Zenity documents an "MCP Gateway" and "LiteLLM" integration. — [Zenity documentation](https://docs.zenity.io/)
- [V] Conduktor Console 1.49.0 (2026-11-19) changed its own MCP server to stop accepting admin API keys; Confluent shipped a managed MCP server in May 2026. Streaming vendors are now MCP surface themselves. — [Conduktor release notes](https://docs.conduktor.io/guide/release-notes.md); [Confluent press release](https://www.confluent.io/press-release/build-and-secure-real-time-ai/)
- [V] Prowler has 23 AWS Bedrock checks, 9 Azure AI services checks, 5 Vertex AI checks; no provider for standalone vector databases. — [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers)
- [VC, S] Vector databases: Orca describes agentless detection of exposed vector databases; Qdrant's docs say self-deployed instances "are not secure" by default; a Milvus CVE published 2026-02-13 concerns port 9091 exposed by default enabling auth bypass (fixed in 2.5.27/2.6.10). — [Orca blog](https://orca.security/resources/blog/vector-database-security-risks/); [Tenable CVE-2026-26190](https://www.tenable.com/cve/CVE-2026-26190); [BeyondScale](https://beyondscale.tech/blog/vector-database-security-enterprise-ai)

### Inferences
- Already commodity (free, multi-vendor, benchmarked): MCP tool-description scanning, tool-poisoning/rug-pull detection, MCP gateway with auth and allow-listing, MCP server discovery on endpoints. VectaSec should not lead with these; a CIS MCP benchmark mapping is table stakes from September 2026.
- Hyperscalers and platform vendors (Google, Microsoft, Red Hat, IBM, Docker, Kong) shipped first-party MCP gateways between June and October 2026. A standalone MCP gateway is a poor place for a small vendor to compete.
- Not visible in what I read: an MCP inventory that links each server's backing credentials to the brokers, gateways and iPaaS flows they can reach. The scanners look at tool descriptions; the gateways look at traffic.

### Gaps
- Not read: Cloudflare MCP, Trail of Bits tools, Operant, Noma, Pillar, Prompt Security, Akto MCP details, MCP registries with trust scoring. The index page gave no limitations for most tools.
- Vector-database posture beyond exposure (RBAC, namespace isolation, key scope) was not investigated in vendor docs; Wiz/Orca AI-SPM coverage lists were not read.
- AI gateway (LiteLLM, Portkey, Kong AI Gateway) configuration-posture tooling was not researched beyond noting Akto and Zenity list connectors for them.

---

## 7. Is anyone explicitly positioning as "middleware security", "integration security posture", "messaging security posture" or "event-driven security"? New startups and acquisitions

### Takeaway
I found no company using any of those category names, no 2026 seed or stealth launch aimed at broker/integration posture, and no analyst category for it. The 2026 M&A in adjacent spaces validates the components (streaming, NHI, MCP governance) as valuable but shows them being absorbed into large platforms, not assembled into an integration-layer security product.

### Cited Findings
- [S] An extended search for "middleware security" / "messaging security posture" / "event-driven security" plus Kafka posture management in 2026 returned only Kafka management tools, vendor guidance and unrelated companies; no startup. The nearest hit was a Slashdot directory listing BigID as "DSPM for Apache Kafka", a data-governance platform. — [Slashdot DSPM for Kafka listing](https://slashdot.org/software/data-security-posture-management-dspm/for-apache-kafka/)
- [S] An extended search for 2026 seed/stealth funding combining Kafka/streaming/integration with security posture and machine identity returned identity startups (Oak, $60M seed out of stealth, July 2026) and streaming infrastructure (AlgoX2, $3.5M seed, October 2025), none focused on broker or integration security. — [SecurityWeek: Oak](https://www.securityweek.com/oak-emerges-from-stealth-mode-with-60-million-in-funding/); [SiliconANGLE: AlgoX2](https://siliconangle.com/2025/10/08/algox2-raises-3-5m-modernize-data-streaming-infrastructure/)
- [3P, S] One identity funding report puts the 2026 median identity-security seed at $9.5M across 26 priced seed rounds. — [startwithidentity.com funding report](https://startwithidentity.com/reports/identity-funding-report-2026/)
- Acquisitions touching the layer: IBM-Confluent (closed 2026-03-17, ~$11B) [VC]; Cisco-Astrix (announced 2026-05-04, completed per Cisco blog update 2026-06-29) [VC/3P]; Cyera-Oasis (~$1B, announced 2026-07-28, completion reported 2026-09-08) [3P]; Boomi-Lunar.dev MCPX (announced 2026-07-27) [3P, via index only]; Snyk took over Invariant's mcp-scan [3P]. — [IBM newsroom](https://newsroom.ibm.com/2026-03-17-ibm-completes-acquisition-of-confluent,-making-real-time-data-the-engine-of-enterprise-ai-and-agents); [Cisco blog](https://blogs.cisco.com/news/cisco-announces-intent-to-acquire-astrix-security); [SecurityWeek: Cyera-Oasis](https://www.securityweek.com/cyera-acquiring-oasis-security-in-1-billion-deal/); [Agent Security Index](https://agentsecurityindex.com/category/mcp-security/)
- [VC] IBM's Confluent close announcement lists day-one integrations with IBM MQ, webMethods Hybrid Integration, watsonx.data and IBM Z. — [Barchart syndication of IBM release](https://www.barchart.com/story/news/794568/ibm-completes-acquisition-of-confluent-making-real-time-data-the-engine-of-enterprise-ai-and-agents)
- [VC, S] Workato publishes "Top 10 MCP security gaps CISOs need to know"; iPaaS vendors are producing their own security narrative. — [Workato product hub](https://www.workato.com/product-hub/ten-mcp-security-gaps-cisos-should-know/)

### Inferences
- The absence of a named category is double-edged. No direct competitor was found, but there is also no budget line, no analyst quadrant and no RFP template; "mid" feedback may partly reflect that buyers compare each family slice to the family specialist (Conduktor for Kafka, Salt for APIs, Zenity for automation, Snyk for MCP).
- IBM now owns Confluent, IBM MQ and webMethods. IBM is the party best placed to ship a first-party "integration security posture" view for large enterprises. That is a threat up-market and irrelevant to 0-3 person security teams.
- Money in 2026 is flowing to agent/MCP/NHI security. An integration-layer product is most fundable and most legible when framed as "the systems agents and automations run through", but the MCP slice itself is commodity (section 6).

### Gaps
- Not checked: YC company directory (W26/S26/F26), Crunchbase, KubeCon NA 2026, Black Hat 2026 and Current 2026 sponsor/talk lists. "No startup found" rests on two extended web searches and should be treated as provisional.
- Gartner market guides and the SACR report were not read; Latio was seen only through vendor summaries.
- Boomi-Lunar.dev was seen only on a third-party index; no primary press release was opened.

---

## 8. What a buyer could assemble from open source, and where it falls short

### Takeaway
A buyer can assemble thin cloud-control-plane coverage (Prowler/Trivy/Checkov), mesh correctness checks (Kiali), a BYO-rules Kong linter (decK), n8n's built-in audit and MCP scanners. The assembly has no broker-internal checks, no Azure/GCP messaging coverage at runtime, no credential usage data, no cross-system attack paths and no compliance evidence for this layer.

### Cited Findings
- [V] Prowler: 32 checks across AWS MSK, SQS, SNS, EventBridge, MQ, ElastiCache and Kinesis combined; 12 for AWS API Gateway; 1 for Azure APIM; 0 for Azure Service Bus/Event Hubs and GCP Pub/Sub; 3 for AWS Transfer Family; no broker-protocol, Kong, iPaaS or MFT-product providers. — [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers)
- [V] Trivy cloud checks: 16 across AWS MSK/SQS/SNS/MQ/ElastiCache/Kinesis; 6 for API Gateway; none for Azure or GCP messaging. — [trivy-checks](https://github.com/aquasecurity/trivy-checks/tree/main/checks/cloud)
- [V, approximate] Checkov: on the order of 40-50 Terraform checks across AWS messaging services and a handful for Event Grid, Event Hub and Pub/Sub; IaC-time only. — [Checkov terraform checks](https://github.com/bridgecrewio/checkov/tree/main/checkov/terraform/checks)
- [V] decK `file lint`: no built-in security ruleset documented; user writes rules. — [decK file lint docs](https://developer.konghq.com/deck/file/lint/)
- [V] Kiali: 72 validations, correctness-oriented, no permissiveness judgement, score or compliance mapping. — [Kiali validations](https://kiali.io/docs/features/validations)
- [V] n8n audit: five report categories, single instance. — [n8n audit API docs](https://docs.n8n.io/connect/n8n-api/instance-operations/audit)
- [S] Kafka ACL open source manages or logs ACLs (kafka-security-manager, Klaw) but no analyser for unused/wildcard ACLs was found. — [conduktor/kafka-security-manager](https://github.com/conduktor/kafka-security-manager); [aiven/klaw](https://github.com/aiven/klaw)
- [V] No CIS benchmark exists for Kafka, RabbitMQ, Redis, NATS, Kong, Istio or Airflow, so there is no kube-bench-style reference implementation to build on. — [CIS Benchmarks list](https://www.cisecurity.org/cis-benchmarks)
- [3P] MCP: Snyk Agent Scan, Cisco MCP Scanner, NVIDIA SkillSpector and several open-source gateways are free. — [Agent Security Index](https://agentsecurityindex.com/category/mcp-security/)

### Inferences
- The DIY stack is at least six tools with six output formats, none of which share an asset model. For a team of 0-3 security people the integration effort is the product.
- The DIY stack is strongest exactly where VectaSec is least differentiated (AWS managed-service flags, MCP tool scanning) and empty where VectaSec claims depth (inside-the-broker rules, credential last-used, attack paths, fix-and-verify).

### Gaps
- Not checked: Kubescape, Polaris, OPA/Conftest policy libraries, Steampipe mods (AWS/Azure/GCP compliance mods likely include some messaging controls), `istioctl analyze`, kube-bench relevance, Nuclei templates for exposed brokers/n8n/MFT (Nuclei almost certainly has exposure templates for many of these and is the most credible free substitute for the external exposure scan).
- Checkov counts are filename matches and may over- or under-count; do not quote them as exact.

---

## 9. Which capabilities are structurally hard for big platforms to copy, and the white-space list

### Takeaway
The defensible ground is what requires speaking each system's own admin protocol and holding per-system domain rules: inside-the-broker authorization analysis, derived credential-usage telemetry, and cross-family paths. Cloud-API-visible flags and MCP scanning are already commodity. Sixteen specific capabilities below were not found in any product or project I examined; each lists exactly what was checked, and each is "not found", not "proven absent".

### Cited Findings (structural points)
- [V] CSPM-style tools reach brokers only through cloud control-plane APIs: all 8 Prowler MSK checks and all 8 ElastiCache checks are cluster attributes (encryption, public, version, auth-enabled flag), none are ACL, user or topic checks. — [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services)
- [V] Enforcement vendors need the data path: Kong Event Gateway's security features are all gateway policies on proxied Kafka traffic. — [Kong Event Gateway changelog](https://developer.konghq.com/event-gateway/changelog/)
- [S] Credential usage must be derived: Confluent Cloud exposes authentication events in audit logs (7-day default retention) and documents a jq pipeline to extract key IDs, with no last-used field surfaced. — [Confluent audit logging best practices](https://docs.confluent.io/cloud/current/monitoring/audit-logging/best-practices.html)
- [V] First-party posture is single-vendor by design: Apigee's multi-gateway profiles cover Apigee variants only. — [Apigee API hub multi-gateway](https://docs.cloud.google.com/apigee/docs/apihub/manage-security-profiles-multi-gateway)
- [V] There is no neutral rule corpus to import: no CIS benchmark for any broker, gateway (other than NGINX), mesh or iPaaS product. — [CIS Benchmarks list](https://www.cisecurity.org/cis-benchmarks)

### Inferences

**Hard to copy (needs protocol access, derived telemetry or per-system rules)**
- Inside-the-broker authorization analysis (Kafka ACLs/RBAC bindings, RabbitMQ vhost permissions, NATS accounts, Redis ACL users). Needs an admin-protocol client per system; a cloud API never returns this.
- Credential last-used across systems that do not expose it. Must be derived from audit topics, broker logs or connection listings with short retention; a platform has to build and store this per system.
- Per-system domain rules without a public benchmark. Each rule set is original content; CNAPP vendors prioritise by installed base and have put effort into Bedrock (23 Prowler checks) rather than brokers (2-8).
- Cross-family attack paths (webhook to workflow credential to broker to datastore). Requires all the connectors above in one graph.
- Fix-then-verify per system. Needs the same protocol access to re-test.

**Easy to copy / already commodity (do not lead with these)**
- Managed-service flags visible via cloud APIs (public, encrypted, logging).
- MCP tool-description scanning and MCP gateways.
- Internet exposure detection of well-known ports and admin UIs.
- Compliance mapping as a feature in isolation (Salt already maps API posture to PCI/HIPAA/NIST; the mapping is easy once findings exist).

### White-space list (capabilities not found in anything examined)

Confidence: **High** = primary docs or repo read and capability absent. **Medium** = absent in vendor marketing/search summaries. **Low** = searched once, nothing found.

1. **One agentless posture view across Kafka, RabbitMQ, NATS, Redis and cloud queues.** Checked: Factor House comparison of 10 Kafka tools (all Kafka-only), Kong and Conduktor changelogs (Kafka only), Prowler provider list (no broker providers), two extended searches for a category player. Confidence: Medium. — [Factor House](https://factorhouse.io/articles/best-kafka-management-tools/); [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers)
2. **Inside-the-broker misconfiguration detection (ACLs, users, vhosts, default accounts, topic-level authz) as a scored assessment.** Checked: Prowler MSK/MQ/ElastiCache check names (all control-plane), Trivy, Kafka OSS ACL tools. Confidence: High for open source; Medium for commercial. — [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services)
3. **Unused and over-broad Kafka ACL detection.** Checked: search of GitHub ACL tooling; kafka-security-manager and Klaw manage/log but do not analyse. Confidence: Medium. — [conduktor/kafka-security-manager](https://github.com/conduktor/kafka-security-manager)
4. **Machine-credential inventory with last-used across brokers, gateways and iPaaS.** Checked: Confluent audit-log and API-key docs (summaries; no last-used field), NHI vendor descriptions (SaaS/cloud focus; no Confluent or broker connector surfaced). Confidence: Medium-Low; verify NHI vendor connector lists. — [Confluent API key best practices](https://docs.confluent.io/cloud/current/security/authenticate/workload-identities/service-accounts/api-keys/best-practices-api-keys.html); [guptadeepak.com NHI tools](https://guptadeepak.com/tools/top-10-non-human-identity-security-2026/)
5. **Streaming data-protection posture without inserting a proxy** (report where field encryption/masking is missing, rather than enforce it inline). Checked: Conduktor Gateway, Kong Event Gateway, Gravitee, all inline. Confidence: Medium. — [Kong Event Gateway changelog](https://developer.konghq.com/event-gateway/changelog/); [Conduktor Gateway docs](https://docs.conduktor.io/gateway.md)
6. **Runtime posture checks for Azure Service Bus, Event Hubs, Event Grid and GCP Pub/Sub in open source.** Checked: Prowler and Trivy trees (zero service directories). Confidence: High for these two tools; hyperscaler-native tools not checked. — [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers); [trivy-checks](https://github.com/aquasecurity/trivy-checks/tree/main/checks/cloud)
7. **Multi-vendor API gateway configuration posture (Kong + AWS + Apigee + Azure APIM in one rule engine).** Checked: Apigee risk assessment and multi-gateway docs (Apigee only), Defender for APIs (APIM only), decK lint (no rules), Salt posture page (no gateway named), Prowler (AWS 12, Azure 1, others 0). Confidence: Medium (seven API security vendors not read). — [Apigee multi-gateway](https://docs.cloud.google.com/apigee/docs/apihub/manage-security-profiles-multi-gateway); [Defender for APIs FAQ](https://learn.microsoft.com/en-us/azure/defender-for-cloud/faq-defender-for-apis)
8. **A shipped security ruleset for Kong configuration (admin API exposure, plugin gaps, plaintext upstreams, credential plugins).** Checked: decK lint docs; Trend Micro research shows the problem is known. Kong Konnect's own features not read. Confidence: Medium. — [decK file lint](https://developer.konghq.com/deck/file/lint/); [Trend Micro Kong case study](https://www.trendmicro.com/vinfo/it/security/news/virtualization-and-cloud/kong-api-gateway-misconfigurations-an-api-gateway-security-case-study)
9. **Self-hosted Azure APIM gateways and non-REST APIs in posture.** Checked: Microsoft docs summaries state self-hosted gateways and workspace APIs are not onboarded and only REST is analysed. Confidence: Medium (summary only). — [Defender for APIs prerequisites](https://learn.microsoft.com/sl-si/azure/defender-for-cloud/defender-for-apis-prepare)
10. **Mesh policy permissiveness analysis with a posture score and compliance mapping.** Checked: Kiali validations (72 checks, none on over-breadth, no score, no mapping). Tetrate/Solo/Buoyant/Isovalent not read. Confidence: High for Kiali, Low for the market. — [Kiali validations](https://kiali.io/docs/features/validations)
11. **Posture for n8n, Zapier, Make, Boomi, MuleSoft and Airflow from a security vendor.** Checked: Zenity docs navigation (only Workato of these), Nokod press coverage (Power Platform, ServiceNow, UiPath, Salesforce). SSPM vendor app lists not read. Confidence: Medium. — [Zenity documentation](https://docs.zenity.io/)
12. **Fleet-level n8n posture (multiple instances, network exposure, credential-to-workflow blast radius, history).** Checked: n8n audit API (single instance, five categories), four community tools (single-instance scripts). Confidence: High for n8n native; Medium overall. — [n8n audit API](https://docs.n8n.io/connect/n8n-api/instance-operations/audit); [Perufitlife/n8n-security](https://github.com/Perufitlife/n8n-security)
13. **Configuration posture for MFT products.** Checked: one search (advisories, footprint, vendor commentary only); Prowler has 3 AWS Transfer checks. Confidence: Low. — [Prowler repo](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services); [Bitsight GoAnywhere footprint](https://www.bitsight.com/groma-explorer/fortra/goanywheremanagedfiletransfer)
14. **Attack paths that traverse integration systems** (for example exposed webhook to workflow credential to broker topic to downstream store). Checked: nothing found in any Kafka, API, low-code or MCP vendor material read; CNAPP attack-path coverage of brokers not checked. Confidence: Low. — [Salt posture page](https://salt.security/use-cases/api-posture-management); [Zenity documentation](https://docs.zenity.io/)
15. **Compliance evidence packs for the integration layer** (broker, gateway, automation controls mapped to SOC 2/ISO/PCI). Checked: Salt maps API posture to frameworks (APIs only); Kiali none; Apigee risk assessment none; Kafka tools offer audit logs, not framework mapping, on the pages read. Confidence: Medium. — [Salt posture page](https://salt.security/use-cases/api-posture-management); [Apigee risk assessment](https://docs.cloud.google.com/apigee/docs/api-security/security-scores)
16. **Guided fix followed by automated re-verification for broker and gateway findings.** Checked: Apigee gives recommendations and scores with no notification of new scores and delays up to hours; Prowler/Kiali report only. Confidence: Medium-Low. — [Apigee risk assessment](https://docs.cloud.google.com/apigee/docs/api-security/security-scores)
17. **A public, vendor-neutral benchmark for Kafka, RabbitMQ, Redis, NATS, Kong, Istio and Airflow.** Checked: CIS catalogue (none). Publishing one is open ground; CIS did exactly this for MCP in September 2026. Confidence: High for CIS; DISA STIGs and vendor guides not enumerated. — [CIS Benchmarks list](https://www.cisecurity.org/cis-benchmarks); [CIS MCP benchmark release](https://www.cisecurity.org/about-us/media/press-release/cis-releases-cis-mcp-server-benchmark-v1-0-0)
18. **MCP posture joined to the integration estate** (which MCP servers hold credentials to which brokers, gateways and workflows). Checked: the 17-tool index (scanners inspect tool descriptions; gateways proxy traffic), Salt and Zenity (MCP plus APIs/agents, no brokers). Confidence: Medium. — [Agent Security Index](https://agentsecurityindex.com/category/mcp-security/)
19. **Vector-database posture beyond "is it exposed"** (auth defaults, RBAC, namespace isolation, key scope). Checked: Orca blog (exposure detection), Prowler (no vector DB provider). AI-SPM vendor docs not read. Confidence: Low. — [Orca blog](https://orca.security/resources/blog/vector-database-security-risks/)
20. **SMB-priced, self-serve posture across these families.** Checked public prices: Conduktor $1,200/seat/year, Kpow from $4,500/cluster/year, Lenses from $4,000/year (all Kafka consoles, vendor-comparison source); Apigee risk assessment needs a paid add-on; Akto ~$1,890/month per one third-party listing; Salt, Zenity, Kong Event Gateway show no public pricing in what I read. None is a cross-family posture product. Confidence: Medium. — [Factor House](https://factorhouse.io/articles/best-kafka-management-tools/); [Software Advice: Akto](https://www.softwareadvice.com/product/423223-Akto/)

### Gaps
- Every white-space item is "not found in the sources examined". Items rated Low (13, 14, 19) rest on a single search and should not be used in external messaging until re-checked.
- The largest untested risk to the white-space claim is the CNAPP tier: I did not read Wiz or Orca supported-technology or rule catalogues, and they may cover self-hosted Kafka/RabbitMQ/Redis via workload scanning (host configuration rules) in ways that overlap items 1, 2 and 14.
- Second largest: hyperscaler-native controls (AWS Security Hub, Defender for Cloud recommendations for Service Bus/Event Hubs, Google SCC for Pub/Sub) were not counted and likely narrow item 6 for buyers who already use them.
- Several CVE identifiers and funding figures appeared only in search summaries or vendor-authored comparisons and were not verified against NVD or primary releases; they are flagged [S] or [VC] above and should be re-verified before citation.
- Launch coverage for August-November 2026 is confirmed for Conduktor (Console 1.47.1-1.49.0, Gateway 3.22.0-3.23.0), Kong Event Gateway (1.2.1, 1.3.0, 1.2.2, 1.1.3), CIS MCP Server Benchmark (2026-09-16), Red Hat MCP Gateway GA (2026-10-16), IBM ContextForge 1.1.0 (2026-10-20), agentgateway 1.7.0 (2026-10-27), PointGuard AI Gateway and Mintive funding (2026-10-29), Latio AI Security report (September 2026), the n8n token-leak research (August 2026) and the Cyera-Oasis completion (reported 2026-09-08). For every other vendor in the brief I found no dated August-November 2026 launch, which means "not found", not "none occurred".
