# VectaSec — Complete Capability Atlas (v5 build spec)

**As of 2026-07-23.** Produced by a 29-agent research workflow (16 middleware categories + 10 competitor segments, synthesized then adversarially critiqued). This is the authoritative target: every capability a best-in-class integration-layer security platform needs, graded against VectaSec's real inventory. Status legend: built / partial / absent.

**Totals:** 58 capabilities — 6 built, 13 partial, 39 absent. By tier: 31 table-stakes, 22 differentiator, 5 emerging.

## Critic's verdict (the steering correction)

> If fully built, this atlas would make VectaSec the BROADEST integration-layer/NHI posture tool on the market and it correctly identifies a real, under-owned wedge (async/self-managed brokers + meshes + iPaaS + the NHI graph across them). But it would NOT unambiguously make it 'the best middleware-security tool,' and there is a genuine gap for four concrete reasons. (1) COVERAGE HOLES in the highest-value places: it omits the most-breached integration category outright (MFT/EDI - MOVEit/GoAnywhere/Cleo/Cl0p, ~90M records), the AI-era exposed data store the agents actually read (vector DBs, thousands unauth), and the coordination control planes (etcd/ZooKeeper/Nacos) whose compromise owns the very brokers it scans - so 45 capabilities is not the same as the RIGHT 45. (2) SEQUENCING INVERSION: it over-invests in a graph engine that has too few edges to traverse while under-investing in the cheap, high-ROI actionability layer (credential lifecycle + CVE/KEV enrichment) that would differentiate the data it ALREADY collects, and it self-contradicts by ranking ITDR last while claiming ITDR is the only thing that catches its flagship breach. (3) MISSING UNGLAMOROUS ENTERPRISE SURFACES that actually decide evaluations - finding-lifecycle (suppression/exceptions/SLA/dedup), scanner production-safety and least-priv onboarding, EASM reachability proof, and cert-lifecycle - none of which appear. (4) DEFENSIBILITY IS ASSERTED, NOT PROVEN: the strategy rests on 'unowned whitespace' claims that are systematically overstated (SSPMs and CNAPPs already touch iPaaS OAuth and vector-DB exposure) and on an on-prem/collector moat that is still vaporware, plus a cluster of post-cutoff 2026 CVEs and a not-yet-shipped MCP spec that anchor detectors before they are verified. Net: build this and VectaSec is a strong, differentiated platform with the widest protocol breadth in the category - but breadth plus an unproven moat is a defensible NICHE, not a decisive 'best-in-class' win, until the MFT/vector-DB/coordination-plane holes are closed, the lifecycle/onboarding/CVE-enrichment table stakes ship, and the collector round-trip is actually demonstrated."]


## The 58 capabilities

### 1. Kafka-protocol event-streaming posture (self-managed + Confluent Cloud + MSK + Redpanda) incl. footgun + tiered-storage detectors
- **Tier:** table-stakes  ·  **Status:** partial — self-managed Kafka connector built+tested and MSK via aws connector; Confluent Cloud REST, Redpanda Admin API, Schema Registry auth, UI/CVE fingerprinting, tiered-storage join, and the footgun detectors are absent.
- **Why:** Event streaming is near-ubiquitous and the log persists the actual sensitive payload, so one unauthenticated broker or exposed UI = full breach. Overwhelmingly config-detectable from read-only AdminClient RPCs. Confluent Cloud is the dominant managed substrate and a cheap extension of the tested connector.
- **Requires:** AdminClient describeConfigs/describeAcls/describeUserScramCredentials + listener probe; add the un-called-out footguns: allow.everyone.if.no.acl.found=true, super.users breadth, delegation-token config, inter-broker plaintext, ZK->KRaft migration ACL-enforcement gap (Kafka 4.0 KRaft-only), DLQ/compacted-topic sensitive accumulation; TIERED-STORAGE OBJECT-STORE EXPOSURE (log silently lands in S3 — a cross-resource join exactly like the KMS join); Confluent Cloud REST v2 (iam/api-keys/role-bindings/networking); MSK DescribeClusterV2/GetClusterPolicy/ListScramSecrets; Redpanda Admin API :9644; Schema Registry REST; ecosystem UI fingerprinting (Kafdrop/kafka-ui/AKHQ, kafka-ui CVE-2024-32030 confirmed real, CVE-2023-52251 to re-verify).
- **Competitors:** Conduktor/Confluent deep but Kafka-only and single-vendor; Wiz/PANW/CrowdStrike see the cloud-resource wrapper, not in-broker ACLs/SASL. Verify each 'unowned' claim with a dated teardown before using in marketing.

### 2. Classic MOM broker posture (RabbitMQ, IBM MQ, ActiveMQ Classic+Artemis, Solace)
- **Tier:** table-stakes  ·  **Status:** partial — RabbitMQ connector built+tested; IBM MQ, ActiveMQ Classic, Artemis, and Solace absent.
- **Why:** Enterprise/regulated backbone with default-cred, auth-off, wildcard-ACL, plaintext, and actively-exploited RCE history (ActiveMQ CVE-2023-46604, CISA-KEV, still ransomware-driven). Rich read-only admin planes.
- **Requires:** RabbitMQ Management HTTP API; IBM MQ mqweb REST + MQSC (CONNAUTH/CHLAUTH/MCAUSER, CHCKCLNT NONE/OPTIONAL); ActiveMQ Jolokia + activemq.xml/jetty-realm + OpenWire :61616 version->CVE; Artemis broker.xml/login.config (default/bootstrap admin creds + GuestLoginModule — verify Artemis default-cred specifics per version); Solace SEMP v2 (clientUsernames/aclProfiles, built-in 'default' user).
- **Competitors:** No cross-broker posture vendor; broker-native tools are Kafka-only. Largely unowned for MQ/ActiveMQ/Solace (confirm with teardown).

### 3. Modern lightweight broker posture (NATS/JetStream, Pulsar)
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** Growing edge/microservice footprint with a 2025-26 authz-bypass CVE wave and unauthenticated monitoring endpoints.
- **Requires:** NATS /varz-/connz-/jsz monitoring + nats-server.conf/JWT account model (auth_required=false / no_auth_user -> $SYS); Pulsar Admin REST (authenticationEnabled/authorizationEnabled flags, namespace grants, proxy TLS) + broker.conf/proxy.conf. NOTE: NATS CVE-2026-33222/2025-30215 and Pulsar CVE-2024-27894 are cited but post-cutoff/unverified — confirm CVE IDs, fix lines, and auth-context before anchoring detectors.
- **Competitors:** Largely unowned; verify.

### 4. IoT / edge message-broker posture (MQTT: Mosquitto/EMQX/HiveMQ; AMQP-1.0; CoAP)
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. Anonymous-by-default and massively internet-exposed; a whole substrate the atlas omitted (Solace was listed but pure MQTT/IoT posture was not). Config-detectable and high-signal.
- **Requires:** Mosquitto/EMQX/HiveMQ config + admin API: allow_anonymous, ACL default-action, TLS/mTLS, bridge config, listener exposure; AMQP-1.0 SASL mode; CoAP DTLS. Join to EASM reachability for true internet-exposure.
- **Competitors:** Unowned as a posture category.

### 5. Managed File Transfer / EDI gateway posture (MOVEit, GoAnywhere, Cleo, IBM Sterling, Axway, Aspera, GlobalScape/EFT, AS2/SFTP)
- **Tier:** table-stakes  ·  **Status:** absent — no MFT/EDI connectors.
- **Why:** CRITIQUE-ADDED, LARGEST OMISSION. The single most-exploited integration-middleware category of 2023-2025 (Cl0p: MOVEit CVE-2023-34362 ~90M individuals / ~2,500 orgs; GoAnywhere CVE-2023-0669; Cleo CVE-2024-50623 + CVE-2024-55956, 60+ victims Jan-2025). Credential-dense and cleanly config-detectable. Belongs in the top build tier by blast radius, ahead of several original differentiators.
- **Requires:** Exposed admin-console detection + EASM reachability; version->CVE + directory-traversal patch-state; AS2/SFTP auth mode + key/cert hygiene; external-exposure and partner-trust config; credential/NHI extraction for stored transfer accounts. Source anchors: cisa.gov/aa23-158a, Cleo advisories.
- **Competitors:** Not owned as a posture category by CNAPP/SSPM/API-SPM; RBVM tools flag the CVE but not the config posture. Genuine whitespace.

### 6. Cloud-managed messaging effective-exposure posture (SQS/SNS/EventBridge, Service Bus/Event Hubs, Pub/Sub)
- **Tier:** table-stakes  ·  **Status:** partial — basic name-matching packs exist via aws/azure/gcp connectors; condition-aware evaluation, KMS join, confused-deputy, and blast-radius modeling absent.
- **Why:** Highest-adoption slice; real 2025-26 abuse (SNS smishing/exfil, EventBridge cross-account injection). Differentiated value is condition-aware effective-exposure and the KMS-key-policy cross-resource join, which CNAPPs do not compute per-resource.
- **Requires:** Full Statement-array parsing honoring Deny/NotPrincipal/Conditions + org account-set; KMS GetKeyPolicy join; confused-deputy (SourceArn/SourceAccount) detection; Azure god-key/data-plane-role-scope; GCP push-without-OIDC/cross-project subs.
- **Competitors:** AWS Config/CIS/CNAPPs do name-level public-access; SOME CNAPPs evaluate SOME IAM conditions (do not claim 'none') — but per-resource condition-aware effective exposure + the CMK cross-resource join remain thin. Confirm with teardown.

### 7. API gateway config posture (Kong, AWS APIGW, Azure APIM, Apigee, NGINX, Traefik, Envoy Gateway, Tyk, KrakenD)
- **Tier:** table-stakes  ·  **Status:** partial — Kong connector built; AWS APIGW via aws connector; Apigee/APIM partially via gcp/azure; NGINX, Traefik, Envoy Gateway, Tyk, KrakenD absent.
- **Why:** The enforcement choke point for authn/authz/rate-limit/TLS across the API estate; fully declarative so config-evidence detection is clean. Active 2026 incidents (APIM privesc, exposed Kong Admin API).
- **Requires:** Resolve the effective auth chain per route (inherited+scoped plugins/policies), not name-match; Kong Admin/decK, AWS apigateway GET*, APIM policy XML, Apigee proxy bundles, nginx -T, Traefik/Envoy Gateway-API CRDs, Tyk JSON defs, KrakenD audit rules. Map findings to OWASP API Security Top-10 (2023).
- **Competitors:** Salt/Traceable/Akamai treat gateways as HTTP traffic taps, not posture objects; CNAPPs read only cloud-managed gateway config. Self-hosted gateway config posture largely open.

### 8. Service-mesh authz posture (Istio sidecar+ambient, Linkerd, Cilium, Consul)
- **Tier:** table-stakes  ·  **Status:** partial — k8s connector covers Istio sidecar + Linkerd ServerAuthorization; ambient mode, RequestAuthentication, meshConfig/egress, istiod version/CVE, Cilium, and Consul absent.
- **Why:** Where workload mTLS, SPIFFE identity and L4/L7 authz live; all declarative K8s CRDs. Documented bypass classes (RequestAuth-without-authz, ambient L7-policy-no-waypoint). Frame against NIST 800-207 zero-trust.
- **Requires:** Read PeerAuthentication/AuthorizationPolicy/RequestAuthentication + meshConfig ConfigMap + istiod image tag; model ambient dataplane-mode/waypoints; Linkerd default-inbound-policy/skip-ports; Cilium CNP/config; Consul intentions/ACL; vanilla NetworkPolicy default-deny. CIS ships Istio and Kubernetes benchmarks — map to them (do NOT repeat the over-broad 'no CIS benchmark exists' claim). NOTE: ISTIO-SECURITY-2026-001 JWT-bypass fix lines (<1.27.8/1.28.5/1.29.1) are post-cutoff/unverified — confirm before shipping the version detector.
- **Competitors:** Salt/Cequence ride the mesh as an HTTP proxy but never audit mesh config; CNAPPs see pods not mesh policy. Cilium/Consul posture thinly owned.

### 9. Coordination / service-discovery / config control-plane posture (etcd, ZooKeeper, Nacos, Consul KV, Eureka, Spring Cloud Config)
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. Compromise of these OWNS the very brokers/meshes VectaSec scans — unauth etcd/ZooKeeper = K8s/cluster takeover. Nacos auth-bypass CVE class; Spring Cloud Config CVE-2024-22243 SSRF; ZooKeeper still under HBase/Solr/legacy Kafka.
- **Requires:** etcd client/peer auth + TLS + exposure; ZooKeeper ACL/auth + four-letter-word exposure; Nacos auth-enabled/default-token; Consul KV ACL; Eureka auth; Spring Cloud Config Server auth + SSRF patch-state. Join to EASM reachability.
- **Competitors:** Unowned as a posture category.

### 10. iPaaS/ESB tenant-config posture (MuleSoft, Boomi, Workato, SnapLogic, Informatica, WSO2, TIBCO, Celigo, SAP Integration Suite/CPI/PI-PO/Gateway)
- **Tier:** differentiator  ·  **Status:** absent — no iPaaS/ESB connectors.
- **Why:** The densest NHI + standing-credential concentration in the enterprise and the exact Salesloft-Drift/Klue attack path. SAP integration backbone added per critique — the regulated-enterprise integration core, omitted while niche ESBs were enumerated.
- **Requires:** Read-only admin APIs: Anypoint Access Mgmt+API Manager, Boomi Platform API, Workato Developer API, SnapLogic/Informatica/WSO2/TIBCO/Celigo, SAP Integration Suite/CPI/PI-PO/Gateway; detect unauth published APIs, over-priv connected apps, plaintext/reused connection creds, no-SSO. VERIFY per-vendor that config reads are available under a least-privilege read-only role — several APIs gate reads behind broad admin scopes, which stresses the metadata-only safety story.
- **Competitors:** SSPMs (Valence/AppOmni) and PANW SSPM DO onboard MuleSoft/Boomi at the OAuth-grant/admin-settings layer — do NOT claim 'fully open'; the whitespace is the recipes/flows/connection-secret interior, not the app.

### 11. Dev-automation middleware posture (n8n, Zapier, Make, Tray, Apache Camel)
- **Tier:** differentiator  ·  **Status:** absent.
- **Why:** n8n is a master-key credential vault with actively-exploited 2025/26 RCEs and thousands of exposed instances, many no-auth; config-readable via REST + built-in /audit.
- **Requires:** n8n Public REST + /audit + env-flag/version/webhook-auth/encryption-key checks; Make/Tray REST (scenarios/hooks/RBAC); Zapier MFA/SSO/orphaned-OAuth enforcement state; Camel static route/BOM/Jolokia analysis (camel-core CVE-2025-27636). CORRECTIONS: CVE-2025-68613 (CVSS 9.9, KEV 2026-03-11) is AUTHENTICATED expression-injection RCE, NOT the unauth one; the UNauthenticated CVSS-10 webhook RCE is CVE-2026-21858 — keep them distinct. Exposure figure is ~24,700 unpatched exposed instances (Feb-2026), NOT ~60k.
- **Competitors:** SSPMs enumerate the OAuth grant only; nobody reads n8n workflow graph/webhook-auth/encryption-key provenance or Camel routes. Open.

### 12. RPC/API data-layer posture (gRPC, GraphQL federation, REST/OpenAPI, tRPC)
- **Tier:** table-stakes  ·  **Status:** absent — no gRPC/GraphQL/REST-spec connectors.
- **Why:** The application data plane directly exposes business data/mutations; every protocol ships a self-describing recon channel (gRPC reflection, GraphQL introspection, OpenAPI specs). Object/field-level authz is the real gap. Map to OWASP API Security Top-10 (BOLA/BOPLA).
- **Requires:** gRPC reflection + per-method authz + CVE map (gRPC-Go CVE-2026-33186 path-normalization bypass is post-cutoff/unverified — confirm); GraphQL introspection + multi-role field-diff (BOPLA) + federation subgraph reachability; OpenAPI static audit (42Crunch-style) + shadow-API reconcile; tRPC AST public-vs-protected.
- **Competitors:** API-SPM incumbents (Wiz/Escape/42Crunch/Salt) mature for REST, thin on gRPC per-method authz, federation subgraph exposure, and NHI correlation back to the integration layer.

### 13. Workflow/durable-orchestration posture (Airflow, Temporal, Step Functions, Camunda, Prefect, Dagster, Argo)
- **Tier:** differentiator  ·  **Status:** absent.
- **Why:** Runs business logic as credential-bearing DAGs; auth is frequently off-by-default and Airflow has a perennial author-to-RCE + secret-leak CVE stream. Dense multi-cloud credential vault, read-only-collectable.
- **Requires:** Airflow REST/config (auth_backends, fernet/secret key, expose_config, masking, version-CVE) + DAG secret scan; Temporal authorizer/mTLS/API-key (self-hosted default nopAuthorizer); SFN IAM PassRole/logging; plus Camunda/Prefect/Dagster/Argo auth-mode checks. NOTE: Airflow CVE-2026-33858 is post-cutoff/unverified — confirm before anchoring severity.
- **Competitors:** Unowned as a posture category by every segment.

### 14. CDC / streaming-integration posture (Debezium, Kafka Connect, Flink, Fivetran, Airbyte)
- **Tier:** differentiator  ·  **Status:** absent.
- **Why:** Holds replication-grade credentials to nearly every production DB; Kafka Connect REST and Flink ship with no authn/authz by design, with CISA-KEV file-read (Flink CVE-2020-17519) and plaintext-secret-over-REST exposure. Also the primary source of cross-fabric lineage edges the graph needs.
- **Requires:** Connect REST + __connect-configs topic + override-policy/JAAS/OAUTHBEARER checks; Debezium source-table->topic lineage; Flink REST/config (JAR-upload, SSL, SQL Gateway, version); Airbyte SECRET_PERSISTENCE; Fivetran grant scope. NOTE: Flink CVE-2026-35194 (SQL-codegen RCE) is post-cutoff/unverified — confirm; CVE-2020-17519 is verified KEV.
- **Competitors:** Runtime CNAPPs see the TCP session, not Connect config or CDC lineage. Open.

### 15. Vector database / RAG-store posture (Milvus, Qdrant, Chroma, Weaviate, pgvector, Pinecone)
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. The AI-era exposed-data class the agent section ignored — the data store MCP/A2A agents actually read from, the modern equivalent of exposed Elasticsearch. Thousands exposed with anonymous read/write (Chroma ~4,123 / Weaviate ~3,891 / Milvus ~2,156 / Qdrant ~1,443); embeddings reconstructable to >90% of source text; knowledge bases full of secrets/PII. For AI-forward buyers this is table-stakes in 2026, not emerging.
- **Requires:** Anonymous read/write probe on default ports (Milvus :19530, Qdrant :6333, Chroma :8000, Weaviate :8080); auth/API-key enforcement, TLS, RBAC, network exposure; pgvector via DB grants; Pinecone tenant key scope. Join to DSPM classification of collection contents + EASM reachability. Source: Orca vector-DB research (already published — do NOT claim unowned).
- **Competitors:** Orca has published vector-DB exposure research; treat as thinly-covered, not unowned.

### 16. MCP server posture + shadow-MCP fleet discovery
- **Tier:** table-stakes  ·  **Status:** partial — 24-rule dual-gen (2026-07-28-spec) MCP connector built; shadow-MCP fleet discovery, tool-poisoning content analysis, and manifest drift-hashing absent.
- **Why:** Fastest 2026 breach velocity (40+ CVEs, ~40% of live servers unauthenticated, first in-the-wild malicious server). For AI-forward buyers this is table-stakes now.
- **Requires:** Evidence-based auth-chain probing (unauth tools/list, open DCR, missing PRM/resource-indicator, token-passthrough); tool-manifest content analysis + drift-hashing (poisoning/rug-pull, CVE-2025-54136 class); shadow-MCP discovery from client configs + in-cluster CRDs. CORRECTIONS: the exposure figure is ~12,520 exposed MCP services at ~40% unauth (~8.5% OAuth) per Censys — drop the false-precision '40.55%'; first in-the-wild malicious server = postmark-mcp npm (~1.0.16, Snyk, Sept 2025) — verify framing. RISK: the '2026-07-28 stateless RC' is dated AFTER today (2026-07-23) — do NOT obsolete the initialize/Mcp-Session-Id detectors until the RC actually lands as described; keep dual-generation.
- **Competitors:** Crowded MCP-only field (Noma/Zenity/Pillar/Prompt/Lakera + gateways) but they stop at the AI layer; none tie MCP to the broker/mesh/iPaaS fabric it fronts.

### 17. AI-gateway / LLM-proxy / guardrail posture (LiteLLM, Portkey, Kong AI Gateway, Cloudflare AI Gateway, Bedrock Guardrails, Azure AI Content Safety)
- **Tier:** differentiator  ·  **Status:** absent.
- **Why:** CRITIQUE-EXPANDED from LiteLLM-only. A fast-growing category: exposed admin/UI, master-key hygiene, provider-credential storage, and guardrail-enforcement state. For AI-forward buyers, trending to table-stakes in 2026.
- **Requires:** LiteLLM version-CVE + exposed-unauth + weak-master-key + plaintext-provider-cred (CVE-2026-42208 pre-auth SQLi is post-cutoff/unverified — confirm); Portkey/Kong-AI/Cloudflare-AI admin exposure + key hygiene; Bedrock Guardrails / Azure Content Safety enforcement-state and scope; prompt-firewall/guardrail on/off posture.
- **Competitors:** Thinly owned; the broader gateway category is largely open.

### 18. A2A AgentCard posture
- **Tier:** differentiator  ·  **Status:** absent.
- **Why:** Adjacent agent-layer surface owned by no posture vendor: unsigned/no-auth AgentCards and secret-leaking extended cards. Trending to table-stakes for AI buyers.
- **Requires:** A2A /.well-known/agent-card.json signature/securitySchemes/secret-leak checks. Map to EU AI Act / ISO 42001 conformance where the agent layer is in regulatory scope.
- **Competitors:** Unowned.

### 19. Secrets-manager / Vault posture as a scanned target (HashiCorp Vault, CyberArk Conjur, Akeyless, cloud Secrets Manager)
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. An NHI-dense control plane squarely in the integration layer — the atlas stored VectaSec's own creds in Vault but never audited Vault itself.
- **Requires:** Vault audit-device-off, root-token present, auth-method/policy misconfig, unseal/recovery config, seal status; Conjur/Akeyless policy + admin exposure; cloud Secrets Manager rotation-off + permissive resource policy. Feeds the NHI inventory and credential-lifecycle overlay.
- **Competitors:** Cloud secret stores partly covered by CNAPP; self-managed Vault/Conjur posture thinly owned.

### 20. Identity / SSO-middleware posture (Keycloak, Ory, WSO2 IS, PingFederate, ForgeRock, Gluu, Authentik)
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. The customer's own OIDC/SAML broker is integration-layer middleware — the atlas consumes SSO for its own login but never audits the customer's identity broker.
- **Requires:** Client-secret hygiene, wildcard redirect-URI, weak/none signing alg, admin-console exposure, default realm, token-lifetime/refresh config, first-party-vs-public client. Feeds NHI graph.
- **Competitors:** ITDR/IdP-security vendors touch the IdP; self-managed identity-broker config posture thinly owned.

### 21. Search / data-grid / cache-sink posture (Elasticsearch/OpenSearch, Solr, Memcached, Hazelcast, Apache Ignite, Oracle Coherence)
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. The historical #1 exposed-data-leak class (Elasticsearch/Solr) plus the unauth-default data-grid family that carries data-in-motion. Redis is covered; the rest are not.
- **Requires:** Auth-enabled/anonymous, TLS, network bind/exposure, version->CVE; Memcached no-auth + amplification exposure; Coherence deserialization RCE by version; Ignite/Hazelcast cluster-join auth. Join to DSPM + EASM reachability.
- **Competitors:** CNAPPs flag exposed managed search; self-managed data-grid config posture thinly owned.

### 22. Database-proxy / connection-pooler posture (PgBouncer, ProxySQL, RDS Proxy, Vitess, Envoy DB filters)
- **Tier:** differentiator  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. Terminate auth and hold DB credentials — a classic integration-layer credential concentrator, absent entirely.
- **Requires:** Auth mode (auth_type/trust), TLS to client and to backend, admin-console exposure, stored backend credentials, RDS Proxy IAM/secret config. Feeds NHI + credential-lifecycle.
- **Competitors:** Unowned as a posture category.

### 23. Cross-fabric TLS / certificate-lifecycle posture
- **Tier:** table-stakes  ·  **Status:** absent — TLS checked per-connector, no unified cert-lifecycle capability.
- **Why:** CRITIQUE-ADDED as a first-class capability. Cert expiry, weak cipher/TLS-version, self-signed, mTLS enforced-vs-permissive, SAN/hostname validation, chain trust — a top outage cause and recurring breach vector across every broker/gateway/mesh. Today TLS is only mentioned piecemeal inside individual connectors.
- **Requires:** A unified certificate/TLS inventory-and-scoring layer that every connector feeds (endpoint TLS probe + config-declared cert refs), with expiry windows, weak-suite/protocol flags, self-signed/untrusted-chain detection, and mTLS permissive-mode findings.
- **Competitors:** Cert-lifecycle tools exist standalone; unified integration-layer TLS posture is thinly owned.

### 24. NHI / machine-identity discovery + inventory across the fabric
- **Tier:** table-stakes  ·  **Status:** built — NHI/CIEM derivation runs on all nine connectors.
- **Why:** VectaSec's core wedge; the integration layer is where NHIs concentrate and the OAuth-breach blast surface lives. Every connector's grants/credentials/owners form the graph everything else joins to.
- **Requires:** Per-connector identity/credential/grant extraction (SASL principals, broker users, gateway consumers, cloud IAM, mesh SVIDs) normalized into one model.
- **Competitors:** NHI vendors (Astrix/Oasis/Entro) cover cloud IAM/IdP/SaaS/code; Kafka principals, broker users, mesh SVIDs, and iPaaS connection creds are invisible to them. Integration-layer NHI is open.

### 25. Credential-lifecycle telemetry (rotation-age, TTL/expiry, last-used, leak-match)
- **Tier:** differentiator  ·  **Status:** absent — inventory exists but rotation-age/last-used/expiry staleness and leak-match are absent.
- **Why:** CRITIQUE-REPRIORITIZED to Tier 1. The atlas's own thesis is 'detection isn't the bottleneck, staleness/rotation is'; this layers cheaply onto the NHI inventory already present on all 9 connectors and is the highest-ROI differentiated output available today — arguably before the graph.
- **Requires:** Provider last-used/last-auth timestamps, rotation history, expires_at/notAfter, and hash-fingerprint matching against public-leak feeds (GitGuardian-style). NOTE: the '64% of 2022 secrets still valid' motivating stat is uncited — verify before using externally.
- **Competitors:** GitGuardian/Entro/Oasis do this for cloud/SaaS/vault; nobody does it for broker/mesh/iPaaS credentials.

### 26. Third-party OAuth-grant blast-radius modeling
- **Tier:** differentiator  ·  **Status:** absent.
- **Why:** The exact Salesloft-Drift/Gainsight attack: a valid, well-scoped token replayed for bulk export. Value = scope breadth x offline-refresh persistence x reachable sensitive data x staleness, scored against DSPM classification.
- **Requires:** Connected-app/grant inventory (scopes, offline_access, last-used) joined to reachable-resource classification and org/known-app allowlist.
- **Competitors:** SSPMs (AppOmni/Obsidian/Nudge/Valence) own SaaS-to-SaaS OAuth revoke but score scope, not scope x data-classification blast radius across a heterogeneous fabric.

### 27. NHI-ITDR: behavioral runtime detection + closed-loop response
- **Tier:** differentiator  ·  **Status:** absent — runtime/ITDR-response absent.
- **Why:** CRITIQUE-REPRIORITIZED up (was Tier 3, contradicting the marquee Drift argument). Static inventory would not have caught the Drift valid-token replay; only per-identity behavioral baselines plus a revoke/rotate response close the loop. Ship at least a thin last-used-anomaly layer early so the flagship narrative is not internally inconsistent.
- **Requires:** Per-identity baseline from auth/event logs (new UA/IP/consumer, volume spike, impossible travel); SSF/CAEP receiver for real-time revocation transport; wired revoke/rotate/quarantine runbooks with reversibility gating.
- **Competitors:** Astrix/Entro NHIDR do this for SaaS/cloud identities; CrowdStrike SGNL adds CAEP enforcement — but only where a CAEP/OAuth-aware PEP exists, never for broker/mesh/iPaaS native authz.

### 28. Agent/workload identity conformance (SPIFFE/WIMSE/AIMS)
- **Tier:** emerging  ·  **Status:** absent.
- **Why:** Workload+agent identity is standardizing (SPIFFE/SPIRE, WIMSE, AIMS); short-lived attested creds and OIDC-federation trust policies become new posture-checkable surfaces.
- **Requires:** SPIRE registration-entry/selector reads, SVID TTL, trust-domain federation scope, OIDC trust-policy aud/sub condition analysis, agent dual-identity/proof-token binding checks.
- **Competitors:** SPIFFE/SPIRE is DIY framework-level; no product sits on top to inventory/score these principals.

### 29. Owner attribution + offboarding / orphaned-NHI detection
- **Tier:** differentiator  ·  **Status:** absent — staleness/last-used and offboarding correlation absent.
- **Why:** OWASP NHI1: identities whose owner is deactivated or that show no recent successful use are dormant blast radius; requires joining last-activity to owner/user status.
- **Requires:** Owner labels on every NHI + last-used/last-activity join to disabled-principal state.
- **Competitors:** Astrix/Oasis do this for cloud/SaaS NHIs; open for integration-layer identities.

### 30. DSPM data classification at the integration layer
- **Tier:** table-stakes  ·  **Status:** partial — naming-based classification + one toxic-combination rule built; schema/Data-Contract/CSFLE introspection, CDC-lineage propagation, and consented sampling absent.
- **Why:** The same PII/PCI/PHI flows through topics/queues/routes/tool payloads as data-in-motion, largely unclassified; at-rest DSPM never sees the bus. A confidence ladder (declared > lineage > named > sampled) is the honest model.
- **Requires:** Confluent schema-tag/Data-Contract/CSFLE introspection (declared); Debezium CDC config lineage (derived); naming heuristics (marked inferred); optional consented in-network payload sampling (regex/Luhn/NER); also classify vector-DB/search-sink contents.
- **Competitors:** DSPM leaders (Cyera/Sentra/BigID/Wiz DSPM) center on data-at-rest; Macie is S3-only. Config-evidence classification of the message bus is thinly owned.

### 31. Toxic-combination correlation engine (classification x exposure x NHI grant x CMK)
- **Tier:** differentiator  ·  **Status:** partial — one hand-built toxic-combo rule (DATA.EXPOSURE.SENSITIVE_PLAINTEXT) exists; generalized engine does not.
- **Why:** The single most defensible integration-DSPM output and exactly what at-rest DSPM can't produce; a channel that carries sensitive data AND is exposed AND is reachable by an over-broad NHI is the highest-priority finding.
- **Requires:** A general cross-resource join engine over classification labels, effective-exposure verdicts, the NHI grant graph, and CMK key policy — not a hand-built single rule.
- **Competitors:** Wiz Security Graph does this for data-at-rest + cloud IAM, never the bus. Open at the integration layer.

### 32. Attack-path / NHI-reachability graph engine
- **Tier:** differentiator  ·  **Status:** absent — only a hand-built toxic-combo rule, no attack-path graph engine.
- **Why:** Buyers expect graph reasoning (Wiz Security Graph) that chains exposure -> identity -> sensitive data into ranked attack paths and computes blast radius. CRITIQUE CAVEAT: graph value scales with breadth — with 9 connectors and almost no cross-fabric lineage edges yet, sequence the lineage-producing connectors (CDC/iPaaS) alongside or before the engine so it is not an impressive engine over a near-empty graph.
- **Requires:** A real graph over identities -> credentials -> grants -> resources -> keys -> classifications -> cross-fabric lineage edges (service->topic->iPaaS flow->external SaaS), with path queries and blast-radius ranking.
- **Competitors:** Wiz/PANW own the cloud/data-at-rest graph; nobody has the integration-layer/NHI-in-motion equivalent.

### 33. CVE / version-to-vuln enrichment (EPSS/KEV feed) + framework tagging (ATT&CK, OWASP)
- **Tier:** table-stakes  ·  **Status:** absent — CVE feed/EPSS/KEV enrichment and ATT&CK/OWASP tagging absent.
- **Why:** Many of the highest-severity findings are version-evidence based; mapping collected version banners to a live CVE/KEV/EPSS feed drives patch prioritization. CRITIQUE-ADDED: also attach MITRE ATT&CK technique tags and OWASP API Security Top-10 references so SOC/enterprise buyers can triage — both are standard expectations the atlas omitted.
- **Requires:** Version-banner extraction per connector + a maintained CVE feed with KEV/EPSS enrichment and version->fix-line map; ATT&CK technique tagging + OWASP API Top-10 mapping on findings. A cheap Tier-0 prerequisite that makes today's 157 detectors' output prioritizable.
- **Competitors:** CNAPPs/RBVM do CVE enrichment for cloud/hosts; nobody maps middleware component versions (brokers/gateways/meshes/Connect) to CVEs.

### 34. EASM / internet-reachability verification (Shodan/Censys/passive-DNS join)
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED, self-referential gap. Multiple per-system checks assert 'internet-reachable instance' but the atlas supplies no external vantage point to establish reachability. Without it, exposure severity is guessed.
- **Requires:** Shodan/Censys/passive-DNS enrichment (or an out-of-network prober) to confirm a broker/gateway/store is actually externally reachable, feeding exposure scoring across every connector.
- **Competitors:** EASM vendors own reachability; integration-layer join is the differentiator.

### 35. General webhook / SSRF egress posture (fabric-wide)
- **Tier:** differentiator  ·  **Status:** absent — checked piecemeal per connector.
- **Why:** CRITIQUE-ADDED. Outbound webhook destination allowlisting, SSRF-to-cloud-metadata, and unsigned inbound webhook validation as a fabric-wide capability, not a per-connector afterthought scattered across n8n/Make/Pub-Sub.
- **Requires:** A shared egress/webhook analyzer: inbound signature/secret validation, outbound destination allowlist/FQDN policy, metadata-endpoint reachability checks, applied uniformly across connectors.
- **Competitors:** Thinly owned.

### 36. Multi-framework compliance control mapping
- **Tier:** table-stakes  ·  **Status:** built — mapping for PCI/DORA/HIPAA/NIS2/MCP with human attestation exists (ISO 27001:2022, SOC2 TSC, EU AI Act, ISO 42001, NIST 800-207 not yet listed).
- **Why:** Turns config evidence into per-control PASS/FAIL an auditor accepts; the integration layer is the evidence source GRC tools (Vanta/Drata) can't produce for brokers/meshes/MCP.
- **Requires:** RULE_TO_CONTROLS mapping against PCI 4.0.1/DORA/NIS2/HIPAA/ISO 27001:2022/SOC2 TSC/MCP, plus (per critique) EU AI Act + ISO/IEC 42001 for the MCP/A2A/agent layer, NIST 800-207 for the mesh, and CSA AI Controls Matrix; where CIS benchmarks exist (Kubernetes/Istio/NGINX) map to them rather than claiming none exist.
- **Competitors:** GRC platforms map cloud/IdP/CI evidence only; they never read Kafka ACLs, mesh mTLS, or MCP scopes.

### 37. Cross-framework control dedup (SCF/STRM set-theory mapping)
- **Tier:** differentiator  ·  **Status:** absent.
- **Why:** One config observation should satisfy PCI+DORA+NIS2+ISO+SOC2 at once; rigorous STRM relationship-typed mapping (per NIST IR 8477) beats name matching and prevents conflicting PASS/FAIL. Lower urgency than finding-lifecycle/onboarding per critique.
- **Requires:** Adopt SCF/STRM crosswalk with relationship-type + strength scoring, plus conflict/low-strength detectors.
- **Competitors:** GRC vendors offer crosswalks; none tie them to integration-layer config observations.

### 38. Tamper-evident evidence ledger + human attestation
- **Tier:** differentiator  ·  **Status:** built — hash-chained append-only ledger + human attestation + citation-gated AI triage built (verify_ledger not yet invoked).
- **Why:** Auditor-grade hand-off requires provenance-labeled, hash-chained, append-only evidence with attestation — a genuine VectaSec differentiator over alert-only tools.
- **Requires:** Hash-chained append-only observation ledger + verify_ledger + human-attestation workflow (wire verify_ledger into a callable path — currently uncalled).
- **Competitors:** Most GRC/CNAPP evidence stores are mutable; tamper-evidence is rare.

### 39. Signed evidence bundle (in-toto/DSSE/Sigstore + timestamp)
- **Tier:** emerging  ·  **Status:** absent.
- **Why:** 2026 auditor-grade practice is cryptographically signed, secure-timestamped receipts. CRITIQUE: lower priority than finding-lifecycle and onboarding — no buyer clears procurement on signed receipts while lacking suppression and safe onboarding.
- **Requires:** DSSE-wrapped in-toto attestation over the exported bundle with Sigstore/SLSA-style signing + secure timestamping.
- **Competitors:** Emerging even among GRC leaders.

### 40. OSCAL + report/PDF/CSV export
- **Tier:** table-stakes  ·  **Status:** absent — report/PDF/CSV/OSCAL export absent.
- **Why:** OSCAL is the credible machine-readable export target (FedRAMP RFC-0024) and PDF/CSV are basic buyer/auditor deliverables; without export the evidence ledger is trapped. Tier-0.
- **Requires:** OSCAL 1.1.x Component-Definition/SSP/Assessment-Results generation + schema validation, plus PDF/CSV renderers.
- **Competitors:** GRC/FedRAMP tooling emits OSCAL; CNAPPs emit PDF/CSV. Table-stakes everywhere.

### 41. SecOps finding-lifecycle state machine (suppression, risk-acceptance, dedup, SLA/aging, ownership routing, noise budgeting)
- **Tier:** table-stakes  ·  **Status:** absent — routing rules + senders exist, no lifecycle state machine.
- **Why:** CRITIQUE-ADDED, entirely absent and evaluated hard by buyers. With 157+ detectors there must be finding suppression/mute, risk-acceptance exceptions with expiry, cross-scan dedup, SLA/aging tracking, and ownership auto-routing — higher priority than the signed-bundle/SCF-STRM differentiators. Point-in-time findings with nowhere to go operationally do not clear procurement.
- **Requires:** A finding lifecycle model: states (open/acknowledged/suppressed/accepted/resolved/regressed), risk-acceptance with expiry + approver, deterministic cross-scan dedup/fingerprinting, SLA clocks by severity, owner auto-routing, and severity/noise budgeting.
- **Competitors:** Standard in mature CNAPP/ASPM; the atlas has senders/routing but no lifecycle state machine.

### 42. Scanner operational safety + least-privilege onboarding
- **Tier:** table-stakes  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. Onboarding friction is the #1 adoption blocker for agentless scanners, and describeConfigs/introspection storms can degrade PRODUCTION brokers. Unaddressed in the atlas.
- **Requires:** Read-load throttling/rate-limiting of describeConfigs/introspection; read-replica/passive-endpoint preference; per-connector least-privilege IAM/role onboarding templates; a dry-run/impact estimate before first scan; concurrency caps.
- **Competitors:** Mature scanners ship onboarding templates + throttling; a gap for new entrants.

### 43. Findings-import / aggregation API (SARIF + OCSF)
- **Tier:** differentiator  ·  **Status:** absent — findings-import + public read API absent.
- **Why:** The ArmorCode/DefectDojo aggregation pattern lets VectaSec ingest third-party scanner findings and become the correlation hub, not another silo.
- **Requires:** SARIF 2.1.0 + OCSF ingest with per-source auth/signature, schema validation, and dedup/correlation into the lifecycle model.
- **Competitors:** ASPM aggregators do this; posture-first tools rarely.

### 44. Public read API + SDK
- **Tier:** table-stakes  ·  **Status:** absent — public read API absent.
- **Why:** Enterprise buyers automate against a scoped API; no programmatic access blocks up-market adoption. Tier-0.
- **Requires:** GraphQL-or-REST public API + OAuth2 client-credentials service accounts with scoped/expiring tokens + Python SDK; per-token rate limits.
- **Competitors:** Wiz GraphQL + service accounts is the reference bar.

### 45. SSO/SAML/OIDC + SCIM 2.0 + platform RBAC
- **Tier:** table-stakes  ·  **Status:** partial — engine RBAC (viewer/editor/admin) + member mgmt + JWT/service-token auth built; SSO/SAML/OIDC and SCIM absent.
- **Why:** Deal-blocker for enterprise; SSO for login, SCIM for lifecycle (deprovision = PATCH active:false), RBAC for least privilege. Tier-0.
- **Requires:** SAML+OIDC (Okta/Entra), SCIM 2.0 provisioning with deprovision wiring, org RBAC beyond engine roles, MFA/step-up on destructive actions.
- **Competitors:** Universal enterprise expectation.

### 46. Bidirectional ticketing (Jira + ServiceNow) with re-validate-before-close
- **Tier:** table-stakes  ·  **Status:** partial — Jira sender built (one-way); ServiceNow and bidirectional close-loop absent.
- **Why:** Table-stakes workflow; the hard part is state-mapping and NOT auto-closing a finding when a ticket closes without a re-scan confirming the fix.
- **Requires:** Jira REST v3 + ServiceNow Table API bidirectional sync with re-validation gate and metadata-only ticket bodies (no secret leakage). Ties into the finding-lifecycle state machine.
- **Competitors:** Every platform ships this; re-validate-before-close is the quality bar.

### 47. SIEM/SOAR export normalized to OCSF
- **Tier:** table-stakes  ·  **Status:** built — OCSF SIEM export + routing rules + delivery bookkeeping + Slack/webhook/email/Jira senders built.
- **Why:** Findings must reach Splunk/Sentinel/SecOps/Falcon in a normalized schema (OCSF 1.6 finding classes) with signed webhooks; otherwise detections silently miss.
- **Requires:** OCSF-conformant emit + Splunk HEC/Sentinel Logs Ingestion/Google SecOps/CrowdStrike sinks + HMAC-signed webhooks + delivery bookkeeping.
- **Competitors:** Expected; full OCSF-native still differentiating.

### 48. Remediation tiers (guided config-fix -> IaC/Terraform snippet -> PR-based/auto-playbook)
- **Tier:** differentiator  ·  **Status:** absent — action layer routes findings but no remediation-artifact/one-click/PR tiers.
- **Why:** 2026 market default; a finding must offer a copy-paste artifact or one-click fix. For self-managed middleware the fix content (authored against vendor guides + OWASP NHI/MCP + the CIS benchmarks that DO exist for K8s/Istio/NGINX) IS the moat.
- **Requires:** Per-detector remediation artifacts (CLI/IaC/console steps), OPA-gated apply with dry-run diff + rollback snapshot, optional PR bot + SOAR delegation.
- **Competitors:** Wiz/Orca/PANW ship all three tiers; nobody has middleware-specific remediation content.

### 49. Policy-as-code custom rules (OPA/Rego)
- **Tier:** differentiator  ·  **Status:** absent — policy-as-code/OPA absent.
- **Why:** Enterprises want to author/tune their own detectors and gate remediation with signed, default-deny policy; the standard way to express custom benchmarks.
- **Requires:** OPA 1.0/Rego v1 engine, signed bundles, decision logs, authenticated policy API, default-deny guardrails.
- **Competitors:** Standard in CNAPP/PaC.

### 50. First-party Terraform/OpenTofu provider
- **Tier:** emerging  ·  **Status:** absent — Terraform provider absent.
- **Why:** Platform-as-code is an enterprise expectation for managing connectors/rules/RBAC/integrations declaratively; provider tokens must be sensitive-marked to avoid state leakage.
- **Requires:** A provider fronting the public API exposing connection/rule/service-account/automation resources.
- **Competitors:** Wiz has community + first-party providers.

### 51. Runtime axis: agentless admission/egress posture + optional eBPF sensor
- **Tier:** differentiator  ·  **Status:** absent — admission/egress config posture not yet built despite the k8s connector.
- **Why:** 2026 consensus is agentless posture + optional eBPF; even without a sensor, admission-control (fail-open webhooks, audit-only) and egress-policy (no default-deny, no FQDN) posture add a runtime axis from read-only K8s/CRD APIs. Do NOT rebuild a CNAPP runtime engine.
- **Requires:** T1 config-evidence: ValidatingWebhook/VAP/Kyverno/Gatekeeper + NetworkPolicy/CiliumNetworkPolicy/Hubble reads; T2 optional read-only DaemonSet or consume Tetragon/Falco/Hubble streams for NHI-token-read and egress-anomaly signals.
- **Competitors:** Runtime CNAPPs own eBPF but not integration-layer semantics; admission/egress config posture is buildable now in VectaSec's lane.

### 52. AI triage + natural-language query (evidence-grounded) + VectaSec MCP server
- **Tier:** differentiator  ·  **Status:** partial — citation-gated AI triage built; natural-language query / VectaSec-MCP-server surface absent.
- **Why:** Buyers now expect natural-language querying of the posture graph and citation-grounded triage; the safety bar is citation-gating so the AI can't fabricate findings.
- **Requires:** Citation-gated triage over stored evidence + a VectaSec MCP server exposing the graph to LLM hosts.
- **Competitors:** Wiz MCP Server, Salt AG-SPM graph, PANW AgentiX are the bar.

### 53. Secrets-in-config / hardcoded-credential detection across definitions
- **Tier:** table-stakes  ·  **Status:** partial — NHI derivation stores credential metadata, but explicit definition-scanning requires the (absent) iPaaS/workflow/CDC connectors.
- **Why:** The #1 real-world leak vector (Airflow DAGs, n8n flows, Connect configs, iPaaS recipes) and directly PCI 8.6.2; needs regex+entropy on config/flow/source, not name-match.
- **Requires:** Engine-agnostic static secret scan of workflow/DAG/state-machine/connector/flow definitions and stored variables, correlated to the NHI inventory.
- **Competitors:** GitGuardian/secrets tools scan repos; nobody scans middleware definitions in-place.

### 54. Dual SaaS/on-prem deployment + in-network collector (metadata-only egress) + BYO-KMS
- **Tier:** differentiator  ·  **Status:** partial — collector code exists but round-trip is unproven and the on-prem path has never been booted.
- **Why:** Regulated buyers of self-managed brokers/meshes/ESBs cannot ship credentials to a SaaS analytics plane; keeping creds in-network with metadata-only egress and a bootable on-prem control plane is a real moat the cloud-scoped incumbents lack. CRITIQUE: this moat is currently vaporware — unproven until demonstrated end-to-end; treat proving it as Tier-0, not a marketing claim.
- **Requires:** A PROVEN collector round-trip (findings out, credentials never leave) + a booted, supported on-prem/air-gapped deployment (never booted to date) + BYO-KMS/CMK. Also verify per-vendor that config reads work under least-privilege read-only roles.
- **Competitors:** Wiz Outpost / CrowdStrike / Salt are SaaS-first; on-prem self-managed middleware is outside their model.

### 55. Data-residency / cross-region lineage detection
- **Tier:** emerging  ·  **Status:** absent.
- **Why:** Sensitive channels replicated cross-region (MirrorMaker/cluster-links, SNS cross-region, Pub/Sub messageStoragePolicy, Event Hubs geo-DR) are GDPR/DORA/NIS2 sovereignty exposures readable from replication config.
- **Requires:** Replication/residency config reads joined to classification + region policy.
- **Competitors:** At-rest DSPM does region residency for stores, not the bus.

### 56. Continuous scheduled scanning + snapshot-continuity/freshness detection
- **Tier:** table-stakes  ·  **Status:** built — continuous scanning via pg_cron; snapshot-gap/freshness detectors not yet called out.
- **Why:** Point-in-time is insufficient; SOC2 Type II and DORA need a continuous-evidence window and drift detection.
- **Requires:** Scheduler (pg_cron) + per-connection cadence + snapshot-continuity gap detection + evidence-freshness TTL.
- **Competitors:** Universal.

### 57. Posture scoring + trend snapshots (confidence-weighted)
- **Tier:** table-stakes  ·  **Status:** built — posture score + trend snapshots built (confidence-weighting refinement still needed).
- **Why:** Buyers need a single ranked risk number and time-series; scoring must weight by classification/evidence confidence so inferred findings don't masquerade as proven.
- **Requires:** Weighted scoring model + posture_snapshots time-series with provenance/confidence weighting.
- **Competitors:** Universal.

### 58. MSSP / multi-tenant partner mode + peer benchmarking
- **Tier:** emerging  ·  **Status:** absent.
- **Why:** CRITIQUE-ADDED. A concrete channel and enterprise-buyer requirement with no place in the atlas — partner/MSSP multi-tenancy and industry/peer benchmarking.
- **Requires:** Tenant isolation model, per-tenant RBAC/branding, cross-tenant rollups for the MSSP, and anonymized industry/peer posture benchmarking.
- **Competitors:** Mature CNAPP/GRC ship MSSP mode; a gap for new entrants.

## Per-system build priorities

- MFT/EDI FIRST-WAVE (new, highest blast radius): MOVEit / GoAnywhere / Cleo / IBM Sterling / Axway — exposed admin console + version->CVE + directory-traversal patch-state + AS2/SFTP auth mode, joined to EASM reachability. The most-exploited integration category of 2023-2025 (Cl0p, ~90M records) and absent from the original atlas.
- Vector-DB / RAG first-wave (new, AI-era exposed-data): Chroma :8000 / Weaviate :8080 / Milvus :19530 / Qdrant :6333 anonymous read/write + auth-key/TLS/RBAC, joined to DSPM classification of collection contents — the store the MCP/A2A agents actually read from.
- Coordination control planes (new): unauth etcd (client/peer TLS+auth) and ZooKeeper (ACL/four-letter-word exposure) = takeover of the very brokers/meshes VectaSec scans; add Nacos auth-bypass and Spring Cloud Config SSRF patch-state.
- CVE/KEV/EPSS enrichment + ATT&CK/OWASP-API tagging across ALL existing 157 detectors (cheap Tier-0): banner extraction + feed join makes today's version-evidence findings prioritizable before any new connector.
- Confluent Cloud (REST v2, cheap extension of the tested Kafka connector): over-privileged RBAC role-bindings (OrganizationAdmin/CloudClusterAdmin/ResourceOwner) + unscoped/non-expiring API keys — a quick revenue-relevant win, not to be buried behind net-new connectors.
- Kafka footguns on the ALREADY-BUILT connector: allow.everyone.if.no.acl.found=true, super.users breadth, inter-broker plaintext, ZK->KRaft migration ACL gap, and TIERED-STORAGE object-store (S3) exposure as a cross-resource join like the KMS join.
- Kafka Schema Registry: DECLARED-but-UNPROTECTED — a field tagged PII with no Data-Contract ENCRYPT/masking rule (plaintext sensitive on the wire) — unlocks the DSPM confidence ladder.
- Redpanda (Admin API :9644): admin_api_require_auth=false / enable_sasl=false / kafka_enable_authorization=false — cheap reuse of the Kafka detector model.
- Kafka management-UI fingerprint: unauthenticated Kafdrop/kafka-ui/AKHQ + kafka-ui RCE (CVE-2024-32030 confirmed; CVE-2023-52251 re-verify), joined to EASM reachability.
- Certificate/TLS-lifecycle sweep across every connected endpoint: expiry windows, weak protocol/cipher, self-signed/untrusted-chain, mTLS permissive-vs-strict — a unified capability replacing piecemeal per-connector TLS checks.
- IBM MQ (mqweb REST + MQSC): CONNAUTH not enforced (CHCKCLNT NONE/OPTIONAL) — the single control gating all remote MQ access in banking/insurance.
- ActiveMQ Classic (Jolokia + activemq.xml): OpenWire :61616 deserialization RCE by version (CVE-2023-46604, CISA-KEV) — highest-severity, version-evidence based.
- ActiveMQ Artemis (broker.xml/login.config): default/bootstrap admin creds + enabled GuestLoginModule (verify per-version specifics).
- MQTT/IoT brokers (new substrate): Mosquitto/EMQX/HiveMQ allow_anonymous=true + ACL default-allow + no-TLS + open bridge, joined to EASM reachability.
- NATS (/varz + nats-server.conf): auth_required=false or no_auth_user mapping to $SYS (verify CVE-2026-33222 before anchoring version detector).
- Apache Pulsar (Admin REST + broker.conf): authenticationEnabled/authorizationEnabled=false (verify CVE-2024-27894).
- Solace PubSub+ (SEMP v2): built-in 'default' clientUsername enabled + ACL default-action allow.
- Cloud-managed messaging effective-exposure engine (SQS/SNS/EventBridge): condition-aware public/cross-account grant honoring Deny/Conditions/org-account-set — the differentiator over name-matching packs.
- KMS cross-resource join (all cloud messaging): CMK backing a queue/topic/stream grants kms:Decrypt to * or a foreign account (encryption theater).
- Azure Service Bus/Event Hubs: RootManageSharedAccessKey / namespace-scope Manage SAS + data-plane role at subscription/management-group scope (god-key blast radius).
- GCP Pub/Sub: push subscription to a non-run.app endpoint with no OIDC token (SSRF/spoofing/exfil) + cross-project subscription.
- API gateway effective-auth-chain rulepack (extend Kong; add NGINX/Traefik/Envoy Gateway/Tyk/KrakenD/APIM/Apigee): a published route/API with NO authentication in its resolved chain, tagged to OWASP API Top-10.
- Istio ambient modeling + RequestAuthentication: L7 AuthorizationPolicy on an ambient workload with no waypoint AND RequestAuthentication-without-companion-AuthorizationPolicy — the two documented bypass classes.
- istiod version/CVE: read the istiod Deployment image tag for ISTIO-SECURITY-2026-001 (VERIFY fix lines <1.27.8/1.28.5/1.29.1 before shipping).
- Cilium (new): CiliumNetworkPolicy/config policy-audit-mode or no default-deny (default-allow until an endpoint is selected).
- Consul (new): ACLDefaultPolicy=allow or '*'->'*' allow intention.
- Vanilla NetworkPolicy default-deny (cheap cross-mesh win): namespace with zero networking.k8s.io/NetworkPolicy.
- Vault-as-target (new): audit device off + root-token present + overly-permissive policy + unseal/recovery config.
- Identity-broker posture (new): Keycloak/Ory/WSO2-IS wildcard redirect-URI + none/weak signing alg + admin-console exposure + default realm.
- Search/data-grid sinks (new): Elasticsearch/OpenSearch/Solr anonymous access + Memcached no-auth/amplification + Coherence deserialization version.
- DB proxies/poolers (new): PgBouncer auth_type=trust / ProxySQL admin exposure + stored backend creds + no client/backend TLS.
- MuleSoft Anypoint (iPaaS, build first): managed API with no Client-ID/OAuth/JWT enforcement + over-privileged Connected App scopes.
- Boomi (Platform API): published API with authentication=None + connection credential reused across environments.
- Workato: API client with admin privileges and no IP allowlist + published endpoint with no access profile.
- SAP Integration Suite/CPI (new, regulated core): iflow endpoint with no auth + over-privileged integration user + stored plaintext connection creds.
- Informatica/WSO2/SnapLogic/Celigo/TIBCO (second-wave iPaaS): unauthenticated published API + over-privileged tenant role (WSO2 default admin/admin, Celigo full-access token).
- n8n (dev-automation, build first): internet-reachable instance in the CVE-2026-21858 (unauth webhook RCE) range and/or CVE-2025-68613 (authenticated) range — keep the two distinct — plus weak/auto-generated N8N_ENCRYPTION_KEY and authentication=none webhooks; ingest /audit reports.
- Make.com / Tray: custom-webhook trigger with no gatekeeper/secret validation (feeds the fabric-wide webhook/SSRF capability).
- Zapier: org-wide MFA/SSO not enforced (Feb-2025 breach root cause) + stale orphaned OAuth connections.
- Apache Camel (static): camel-core CVE-2025-27636 version + HTTP-consumer->camel-bean/exec route topology + plaintext creds in application.properties.
- gRPC (reflection collector): per-method authorization — a method reachable without an auth interceptor (verify gRPC-Go CVE-2026-33186 before the version detector).
- GraphQL federation: introspection in prod + directly-reachable subgraph bypassing router auth + multi-role field-diff (BOPLA).
- REST/OpenAPI: unauthenticated spec at a well-known path + operations declaring no security requirement + shadow-API reconcile.
- Apache Airflow (workflow, build first): unauthenticated REST/experimental API (auth_backends empty) + default/committed Fernet key + hardcoded-secret scan of DAGs/Variables (verify CVE-2026-33858).
- Temporal: self-hosted frontend running the default nopAuthorizer / Cloud namespace with no certificate filters.
- AWS Step Functions: execution-role iam:PassRole with Resource '*' + logging OFF.
- Kafka Connect (CDC, build first): REST API with no authentication extension + connector.client.config.override.policy=All (JAAS/JNDI RCE) + OAUTHBEARER SSRF — also emits the lineage edges the graph needs.
- Debezium: CDC source table.include.list referencing a sensitive table -> sensitivity propagates to the derived topic (config-evidence lineage) -> evaluate that topic's transport/authz.
- Apache Flink: unauthenticated REST/web UI with JAR-upload (RCE by design) + CVE-2020-17519 (verified KEV) / CVE-2026-35194 (VERIFY before anchoring).
- Airbyte (self-managed): SECRET_PERSISTENCE unset/NONE (all connector credentials plaintext in app Postgres).
- MCP fleet (extend the 24-rule pack): shadow-MCP discovery from client configs/in-cluster CRDs + unauth tools/list probe + open DCR — the ~40%-unauth reality (~12,520 exposed per Censys); keep dual-generation until the 2026-07-28 stateless RC actually lands.
- MCP tool-manifest content analysis: description-injection / manifest drift-hashing (tool-poisoning + rug-pull, CVE-2025-54136 class; postmark-mcp npm ~1.0.16 as the reference in-the-wild case).
- A2A AgentCard: no securitySchemes / unsigned card / secret leaked in the public card.
- AI-gateway layer (expanded beyond LiteLLM): LiteLLM exposed-unauth admin/UI + weak/default master key + plaintext provider creds (verify CVE-2026-42208); Portkey/Kong-AI/Cloudflare-AI admin exposure; Bedrock Guardrails / Azure Content Safety enforcement-state.
- Cross-fabric NHI/credential-lifecycle overlay (spans all connectors, HIGH-ROI now): stale/never-rotated/no-expiry credential + wildcard grant + shared-default identity + leak-feed hash-match, scored as blast radius — the wedge no connector-native tool computes.

## Architecture requirements (beyond point-in-time scanning)

- CVE/version enrichment + framework-tagging service (Tier-0 cheap prerequisite): version-banner extraction per connector joined to a maintained CVE/KEV/EPSS feed with version->fix-line maps, PLUS MITRE ATT&CK technique tags and OWASP API Security Top-10 references on every finding. Verify all cited 2026 CVEs (Flink 35194, Istio 2026-001, gRPC-Go 33186, Airflow 33858, NATS 33222, LiteLLM 42208, Pulsar 27894) against primary advisories before they anchor severity — several read as unconfirmed placeholders; do not ship a detector on an unverified CVE ID or fix line.
- Credential-lifecycle + leak-match telemetry (promote to Tier-1 — highest-ROI differentiated output today): rotation-age, TTL/expiry, last-used/last-auth, and hash-fingerprint matching against public-leak feeds, layered onto the existing NHI inventory on all 9 connectors. This differentiates data VectaSec ALREADY collects and should land before the graph.
- Finding-lifecycle state machine (Tier-0/1, currently absent): states + suppression/mute + risk-acceptance exceptions with expiry/approver + deterministic cross-scan dedup/fingerprinting + SLA/aging clocks + owner auto-routing + severity/noise budgeting across 157+ detectors. No buyer clears procurement on cryptographic evidence receipts while lacking suppression and dedup.
- Scanner operational safety + least-privilege onboarding (Tier-0, currently absent): read-load throttling of describeConfigs/introspection storms against PRODUCTION, read-replica/passive-endpoint preference, per-connector least-privilege IAM/role onboarding templates, and a pre-scan impact estimate. Onboarding friction is the #1 agentless-scanner adoption blocker.
- EASM / internet-reachability data source: a Shodan/Censys/passive-DNS join (or out-of-network prober) so every 'internet-reachable instance' assertion across MFT/brokers/gateways/vector-DBs/coordination-planes is evidence-backed rather than assumed.
- Unified TLS / certificate-lifecycle layer that every connector feeds (expiry, weak suite/protocol, self-signed, untrusted chain, mTLS permissive-vs-strict) as a first-class capability, not piecemeal per-connector checks.
- Attack-path / NHI-reachability graph engine, SEQUENCED WITH the lineage-producing connectors (CDC/Debezium + iPaaS), not before them: a real graph over identities -> credentials -> grants -> resources -> keys -> classifications -> cross-fabric lineage edges (service->topic->iPaaS flow->external SaaS), with path queries and blast-radius ranking. Building the engine before the connectors that populate its edges yields an impressive engine over a near-empty graph.
- Generalized toxic-combination correlation engine: a cross-resource join (classification x effective-exposure x NHI grant x CMK policy) parameterized over all connectors, replacing the one-off DATA.EXPOSURE.SENSITIVE_PLAINTEXT rule.
- Provenance-and-confidence weighting throughout: every classification and finding carries a provenance label (declared > lineage > named > sampled) and posture scoring weights by confidence so inferred findings never score as proven.
- NHI-ITDR response loop, with at least a thin last-used-anomaly tier shipped early to match the flagship Drift narrative: per-identity behavioral baselines (new UA/IP/consumer, volume spike, impossible travel) plus a wired revoke/rotate/quarantine capability, ideally over SSF/CAEP, with reversibility gating (auto-execute-with-notify for low-blast reversible actions; approve-then-execute for irreversible/mass actions).
- Remediation tiers: guided config-fix -> IaC/Terraform snippet -> PR-based/auto-playbook, every apply OPA-gated with a stored dry-run diff, pre-state snapshot, and rollback; middleware-specific fix content authored against vendor guides + OWASP NHI/MCP AND the CIS benchmarks that DO exist (Kubernetes/Istio/NGINX) — drop the over-broad 'no CIS benchmark exists' claim.
- Runtime axis (two tiers, agentless-first): (T1, buildable now) admission-control + egress-policy config posture from read-only K8s/CRD APIs; (T2, optional) a lightweight read-only DaemonSet or ingestion of Tetragon/Falco/Hubble streams — never a rebuilt CNAPP runtime engine.
- Evidence + compliance layer: OSCAL 1.1.x export (Component-Definition/SSP/Assessment-Results) + PDF/CSV (Tier-0) + SCF/STRM cross-framework dedup + a signed (in-toto/DSSE + secure-timestamp) evidence bundle on top of the existing hash-chained ledger (wire the currently-uncalled verify_ledger); add ISO 27001:2022, SOC2 TSC, EU AI Act, ISO/IEC 42001, NIST 800-207, CSA AICM to the framework set; plus DORA/NIS2 reporting-clock (4h/24h/72h/1-month) tracking and snapshot-continuity/evidence-freshness detectors.
- Enterprise platform plane (Tier-0 deal-blockers): SSO (SAML+OIDC) + SCIM 2.0 (deprovision = PATCH active:false) + org RBAC beyond engine roles + MFA/step-up on destructive actions; MSSP/multi-tenant partner mode + peer benchmarking; treat every integration token (SIEM/ticketing/SCIM/remediation write-back) as an NHI VectaSec detects on itself.
- Public API + SDK + findings-import (Tier-0): GraphQL-or-REST public read API with OAuth2 client-credentials scoped/expiring service accounts + Python SDK + per-token rate limits, and a SARIF/OCSF findings-import endpoint (per-source auth, schema validation, dedup into the lifecycle model) so VectaSec becomes the correlation hub.
- Bidirectional ticketing with re-validation: Jira REST v3 + ServiceNow Table API two-way sync that re-scans to confirm the fix before auto-closing a finding, metadata-only ticket bodies, wired into the finding-lifecycle state machine.
- Terraform/OpenTofu provider fronting the public API (connections/rules/RBAC/automation as code), provider tokens sensitive-marked to prevent state leakage.
- Deployment/data-residency moat — PROVE IT, don't assert it (Tier-0): demonstrate the customer-side collector round-trip end-to-end (findings out, credentials never leave the network), boot and support the on-prem/air-gapped control plane once (never booted to date), add BYO-KMS/CMK, and verify per-vendor that config reads actually work under least-privilege read-only roles (several APIs gate reads behind broad admin scopes, undercutting the metadata-only story). Until demonstrated, the moat is vaporware and must not headline positioning.
- Verify motivating facts before they anchor roadmap or marketing: n8n CVE labels (68613 authenticated vs 21858 unauth) and ~24,700 exposed count; MCP ~12,520 exposed / ~40% unauth (drop '40.55%') and postmark-mcp framing; GitGuardian '64% still valid' and 'Chattee/GiMe 43M' breach; and every 'unowned/fully open' whitespace claim with a dated competitive teardown (Orca already covers vector-DB exposure; SSPMs already onboard iPaaS OAuth; CNAPPs evaluate some IAM conditions).
- Natural-language surface: a VectaSec MCP server exposing the posture graph to LLM hosts, with citation-gating extended so the AI cannot fabricate findings.
- Connector scale-out framework: a normalized identity/credential/grant + classification + TLS/cert + version-banner extraction contract so each new substrate (MFT/EDI, vector-DB, coordination-plane, MQTT, iPaaS, workflow, CDC, gRPC/GraphQL, additional brokers, DB proxies, Vault, identity brokers) plugs into one model — breadth across protocols is the defensible position no single-system competitor can reach.

## Ranked gap analysis (the build plan)

Ranked build plan to become the go-to product for the whole integration layer, with the critique's corrections folded in. VectaSec's real assets today (grounded in the v4 build-state): 9 read-only connectors, 157 detectors, a working NHI/CIEM model on every connector, naming-based DSPM + one toxic-combo rule, multi-framework compliance mapping, a differentiated hash-chained evidence ledger, OCSF SIEM export, and continuous scanning. Honest deficits: no graph engine, no runtime/ITDR, no export, no enterprise plane (SSO/SCIM/API/Terraform), no remediation, no finding-lifecycle, no scanner-safety/onboarding, no EASM reachability, no unified cert-lifecycle — and the entire off-Kafka fabric plus four whole categories the original atlas OMITTED: MFT/EDI (the most-breached category of 2023-2025), vector-DB/RAG stores, coordination control planes (etcd/ZooKeeper/Nacos), and MQTT/IoT brokers. The stated on-prem/collector moat is unproven and must be demonstrated, not asserted.

TIER 0 (make the current product credibly sellable AND safe to run; weeks-to-a-quarter, but note each item is genuinely multi-week — do not understate): (1) CVE/KEV/EPSS enrichment + ATT&CK/OWASP-API tagging over the EXISTING 157 detectors — the cheapest change that makes today's version-evidence output prioritizable; verify every cited 2026 CVE first. (2) Finding-lifecycle state machine (suppression, risk-acceptance-with-expiry, cross-scan dedup, SLA/aging, owner routing) and scanner operational-safety + least-privilege onboarding templates — unglamorous surfaces that actually decide evaluations and are entirely absent. (3) Export + reporting: OSCAL 1.1.x + PDF/CSV, or the evidence ledger stays trapped. (4) Enterprise plane: SSO (SAML+OIDC) + SCIM + public read API + Python SDK. (5) PROVE the collector round-trip and boot the on-prem deployment once end-to-end — the differentiator that is currently vaporware; if the moat can't be demonstrated it isn't a moat.

TIER 1 (differentiate the data already collected, then the graph): (a) Credential-lifecycle + leak-match telemetry (rotation-age/last-used/expiry/hash-match) layered on the existing NHI inventory — highest-ROI differentiated output available today, promoted above the graph. (b) A thin NHI-ITDR last-used-anomaly + revoke/rotate layer, so the flagship Salesloft-Drift narrative (only behavioral ITDR catches valid-token replay) is not internally contradicted by shipping it last. (c) Generalize the one toxic-combo rule into a classification x exposure x NHI-grant x CMK correlation engine with provenance/confidence weighting. (d) Build the attack-path / NHI-reachability graph engine, but SEQUENCE it with the lineage-producing connectors (CDC/Debezium + iPaaS) rather than before them — with 9 connectors and almost no cross-fabric edges, the graph has nothing to traverse until those land. (e) EASM reachability join + unified TLS/cert-lifecycle layer as cross-cutting enablers.

TIER 2 (close the coverage whitespace, in blast-radius order — including the four omitted categories): (a) MFT/EDI (MOVEit/GoAnywhere/Cleo/Sterling/Axway) — the most-exploited integration category, top priority by blast radius. (b) iPaaS/ESB tenant posture (MuleSoft + Boomi first, then SAP Integration Suite/CPI, then Workato/Informatica) — the densest NHI concentration and the literal Salesloft-Drift path; these also produce the graph's lineage edges. (c) CDC/Kafka-Connect + Flink — replication-grade DB creds, auth-off-by-design control planes, more lineage edges. (d) Vector-DB/RAG stores + coordination control planes (etcd/ZooKeeper/Nacos) + MQTT/IoT brokers — the omitted exposed-data and takeover classes; cheap and high-signal. (e) Finish the brokers already half-done: Confluent Cloud REST + Redpanda + Schema Registry + Kafka footguns/tiered-storage (all cheap extensions, promoted out of the back of the queue), then IBM MQ + ActiveMQ/Artemis + NATS + Pulsar + Solace. (f) Workflow orchestration (Airflow + Step Functions + Temporal). (g) Service-mesh gaps: Istio ambient + RequestAuthentication + istiod-version, then Cilium + Consul + vanilla NetworkPolicy. (h) RPC/API data layer (gRPC reflection + GraphQL field-authz + OpenAPI). (i) Extend the MCP pack with shadow-MCP discovery + tool-manifest/drift analysis + A2A + the broadened AI-gateway layer (LiteLLM/Portkey/Kong-AI/guardrails) + vector-DB — the fastest-moving surface where VectaSec already has partial credibility. (j) Vault-as-target, identity-broker posture, search/data-grid sinks, and DB proxies/poolers as NHI-dense control planes.

TIER 3 (turn findings into outcomes + defend the wedge): (a) Third-party OAuth-grant blast-radius scored against DSPM classification + owner/offboarding correlation. (b) DSPM depth: Confluent schema-tag/Data-Contract/CSFLE introspection + CDC-config lineage (declared/derived tiers), with consented in-network sampling as a deliberate opt-in. (c) Remediation tiers + OPA policy-as-code + Terraform provider + bidirectional ServiceNow/Jira with re-validate-before-close. (d) Runtime axis as agentless admission/egress config posture from the existing k8s connector, plus optional Tetragon/Falco/Hubble consumption — never a rebuilt CNAPP sensor. (e) Signed in-toto/DSSE evidence bundle + SCF/STRM dedup + expanded framework set (ISO 27001/SOC2/EU AI Act/ISO 42001/NIST 800-207) + MSSP multi-tenant mode.

Strategic throughline (corrected): competitors are converging fast on MCP/AI-agent and cloud-control-plane posture, but the async/self-managed integration fabric (brokers, queues, meshes, iPaaS, ESB, CDC, MFT, coordination planes) and the NHI graph across it remain under-owned — though 'unowned' is overstated (Orca covers vector-DB exposure, SSPMs onboard iPaaS OAuth, CNAPPs evaluate some IAM conditions), so every whitespace claim needs a dated teardown before it anchors positioning. VectaSec's defensible position is breadth across protocols + the reachability graph + the NHI/credential-lifecycle wedge + a PROVEN on-prem collector for regulated buyers — NOT competing on cloud CSPM or inline AI-gateway enforcement. Net honest verdict: fully built, this is the broadest integration-layer/NHI posture tool on the market and a strong differentiated platform — but breadth plus an unproven moat is a defensible niche, not a decisive best-in-class win, until (1) the omitted high-blast categories ship (MFT/EDI, vector-DB, coordination planes), (2) the unglamorous table stakes land (finding-lifecycle, scanner-safety/onboarding, CVE-enrichment, EASM, cert-lifecycle, export, enterprise plane), and (3) the collector round-trip and on-prem boot are actually demonstrated. The fastest path: Tier 0 to be buyable and safe, Tier 1 to differentiate the data already held, and MFT/EDI + iPaaS + CDC in Tier 2 to own the whitespace before the SSPM and NHI vendors extend into it.