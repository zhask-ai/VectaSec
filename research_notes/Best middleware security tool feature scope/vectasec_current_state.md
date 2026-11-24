# VectaSec current state (code audit, 2026-10-17) — grade every proposed feature against this

# VectaSec feature audit (from code, 2026-10-17)

Code: engine 47k LOC py, console 19.7k LOC tsx, 39 connectors, ~440 detector ids, 80 test files.
Last commit 2026-08-07. STATUS.md last verified 2026-08-03.

## Console surfaces (15)
| # | Nav | What it does | Evidence | SMB value |
|---|---|---|---|---|
| 1 | Overview | posture score+grade, 30pt sparkline, top findings, control summary | page.tsx 522 | high (but score formula duplicated JS/SQL) |
| 2 | Findings + detail | faceted queue, status/assign/suppress, AI triage w/ citations, remediation text | 630 | high |
| 3 | Systems/Connections | 39 connectors, test/scan now/remove, cadence, health; Systems = catalogue of coverage | 656+629 | high but catalogue is marketing |
| 4 | Discovery | network fingerprint pre-auth, shadow middleware correlation | 410 | medium-high, needs CIDR; good demo |
| 5 | Identities | NHI inventory, credential lifecycle findings (7 rules, mostly not_assessable today) | 544 | high IF last-used lands |
| 6 | Data | naming-based classification, DATA.EXPOSURE toxic combo | 581 | low-medium (inference only; thin) |
| 7 | Assets | raw inventory | 442 | low as a top nav |
| 8 | Attack paths | 3 ATTACKPATH rules over label graph | 604 | high (the flagship), but currently a separate page from findings |
| 9 | Runtime | live clients from 5 sources, "never observed" gated | 494 | medium; dev-facing; belongs in identities |
| 10 | Supply chain | SBOM CycloneDX, OSV+NVD, licensing, EOL, plugins, IaC, VEX | 560 | medium; licensing + VEX are enterprise/auditor |
| 11 | Compliance | PCI/DORA/HIPAA/NIS2/MCP controls, attest, OSCAL/CSV export | 1043 | high for SOC2-seeking SMB but SOC2/ISO27001 NOT in catalogue |
| 12 | Scans | run history | - | low as nav |
| 13 | Settings/Integrations | Slack/Teams/webhook/email/Jira/SIEM(OCSF) + routing rules | 281 | high |
| 14 | Members/RBAC | viewer/editor/admin; no SSO | - | ok |
| 15 | Admin | super-admin orgs/users | - | internal |

Non-console: collector (round trip proven 08-03), on-prem (never booted), CLI, public API none.

## Engine capability stack
- discovery -> connect (39) -> detect (440) -> identity derive -> classify -> graph_engine/attack_path -> compliance evaluate -> notify -> runtime_evidence -> osv/nvd/lifecycle -> sbom/vex/report
- remediation = free text string per rule (615 strings). No IaC snippet, no PR, no verify-after-fix.
- credential lifecycle: most rules fire not_assessable (no last-used telemetry from connectors). AWS connector does no iam:List*, no CloudTrail.

## Connector tiers by SMB relevance
Tier A (SMB, cloud-new): aws, gcp, azure, k8s, kafka/msk/confluent/redpanda, rabbitmq, redis, kong, openapi, graphql, mcp, n8n, vault, keycloak, schema_registry, kafka_connect, iac, discovery, vectordb, pgbouncer, nats, elasticsearch
Tier B (enterprise/regulated): ibmmq, solace, mft, mulesoft, boomi, workato, activemq, pulsar, flink, airflow, solr, memcached, coordination(etcd/zk/nacos/consul), mqtt, grpc

## Known unproven / risky
- CI never green on GitHub; on-prem never booted; no SOC2; no customer; no design partner
- engine trusts console-asserted actor under service token
- posture formula duplicated; scheduler mirror
- no SSO; no billing/metering; no public API; no pricing page; no self-serve trial path beyond signup

## Prior internal docs (read for context)
- docs/vectasec-capability-atlas.md: 58-capability target from July 2026 (6 built, 13 partial, 39 absent at the time; code has moved since)
- docs/vectasec-smb-strategy-2026-10.md: this month's anchor/consolidation decision (Access page anchor, 15 nav -> 6, 39 connectors -> 12 on shelf)
- docs/research/smb-market-2026-10.md: competitor and SMB research sources

## Compliance catalogue today
Frameworks mapped in services/engine/src/vectasec/compliance/map.py: PCI_DSS_4_0_1, DORA, NIS2, HIPAA, MCP_SPEC_2025_11_25. SOC 2 and ISO 27001 absent.

## Rule families in code (count of rule-id prefixes)
  11 "SOLACE.VPN.
  11 "IBMMQ.CHANNEL.
  10 "SOLACE.CLIENT_USERNAME.
   8 "SUPPLY.IAC.
   8 "GCP.PUBSUB.
   7 "MULESOFT.API.
   7 "MCP.AUTH.
   7 "CREDENTIAL.LIFECYCLE.
   6 "RABBITMQ.USER.
   6 "KEYCLOAK.REALM.
   6 "KEYCLOAK.CLIENT.
   6 "IBMMQ.CONNAUTH.
   5 "MCP.TOOL.
   5 "KONG.ROUTE.
   5 "AWS.MSK.
   4 "MCP.TRANSPORT.
   4 "MCP.LIFECYCLE.
   4 "KONG.ADMIN.
   4 "KAFKA.DURABILITY.
   4 "KAFKA.AUTHZ.
   4 "KAFKA.ACL.
   4 "COORD.NACOS.
   4 "COORD.ETCD.
   4 "COORD.CONSUL.
   4 "BOOMI.API.
   4 "AWS.SQS.
   4 "AWS.SNS.
   4 "AWS.APIGW.
   3 "WORKATO.APICLIENT.
   3 "VECTORDB.PGVECTOR.
   3 "VECTORDB.AUTH.
   3 "VAULT.AUTH.
   3 "SUPPLY.LIFECYCLE.
   3 "OPENAPI.AUTH.
   3 "MCP.SESSION.
   3 "KAFKA.ZK.
   3 "KAFKA.TOPIC.
   3 "KAFKA.SASL.
   3 "IBMMQ.QUEUE.
   3 "GRAPHQL.DOS.
   3 "ELASTICSEARCH.TLS.
   3 "ELASTICSEARCH.SECURITY.
   3 "COORD.ZOOKEEPER.
   3 "CONFLUENT.APIKEY.
   3 "AZURE.APIM.
   3 "AWS.EVENTBRIDGE.
   2 "WORKATO.CONNECTION.
   2 "VECTORDB.COLLECTION.
   2 "VAULT.POLICY.
   2 "TLS.CERT.
   2 "SOLR.AUTH.
   2 "RUNTIME.IDENTITY.
   2 "REDIS.NETWORK.
   2 "RABBITMQ.VERSION.
   2 "RABBITMQ.TLS.
   2 "RABBITMQ.PERMISSION.
   2 "RABBITMQ.AUTH.
   2 "PULSAR.NAMESPACE.
   2 "PULSAR.AUTH.
   2 "PGBOUNCER.TLS.
   2 "PGBOUNCER.AUTH.
   2 "NHI.CREDENTIAL.
   2 "NATS.AUTH.
   2 "MQTT.LISTENER.
   2 "MQTT.DASHBOARD.
   2 "MQTT.BRIDGE.
   2 "MQTT.AUTH.
   2 "MQTT.API.
   2 "MFT.TRANSFER.
   2 "MFT.SFTP.
   2 "MFT.GOANYWHERE.
   2 "MFT.CLEO.
   2 "MFT.AS2.
   2 "MFT.ADMIN.
   2 "MEMCACHED.NETWORK.
   2 "KONG.VERSION.
   2 "KAFKA.SSL.
   2 "KAFKA.SCAN.
   2 "KAFKA.LISTENER.
   2 "IBMMQ.CHLAUTH.
   2 "GRPC.REFLECTION.
   2 "GRAPHQL.INTROSPECTION.
   2 "GCP.PROJECT.
   2 "GCP.APIGEE.
   2 "DISCOVERY.SCOPE.
   2 "CONFLUENT.RBAC.
   2 "AZURE.LOGICAPP.
   2 "AIRFLOW.CONFIG.
   2 "AIRFLOW.AUTH.
   2 "ACTIVEMQ.AUTH.
   1 "WORKATO.ENDPOINT.
   1 "VECTORDB.TLS.
   1 "VECTORDB.RBAC.
   1 "VECTORDB.METRICS.
   1 "VECTORDB.COLLECT.
   1 "VAULT.TOKEN.
   1 "VAULT.TLS.
   1 "VAULT.SERVER.
   1 "VAULT.SEAL.
   1 "VAULT.MOUNT.
   1 "VAULT.AUDIT.
   1 "TLS.PROTOCOL.
   1 "TLS.MTLS.
   1 "TLS.LISTENER.
   1 "SOLR.VERSION.
   1 "SOLR.NETWORK.
   1 "SOLR.AUTHZ.
   1 "SOLR.ADMIN.
   1 "SOLACE.MGMT.
   1 "SOLACE.BROKER.
   1 "RUNTIME.TRANSPORT.
   1 "RUNTIME.CREDENTIAL.
   1 "RUNTIME.ACCESS.
   1 "REDPANDA.TLS.
   1 "REDPANDA.AUTHZ.
   1 "REDPANDA.AUTH.
   1 "REDPANDA.ADMIN_API.
   1 "REDIS.VERSION.
   1 "REDIS.USER.
   1 "REDIS.TLS.
   1 "REDIS.AUTH.
   1 "RABBITMQ.VHOST.
   1 "RABBITMQ.SCAN.
   1 "RABBITMQ.MGMT.
   1 "RABBITMQ.LISTENER.
   1 "RABBITMQ.CVE.
   1 "RABBITMQ.CLUSTER.
   1 "PULSAR.VERSION.
   1 "PULSAR.TOPIC.
   1 "PULSAR.TENANT.
   1 "PULSAR.PROXY.
   1 "PULSAR.CLUSTER.
   1 "PULSAR.BROKER.
   1 "PGBOUNCER.POOL.
   1 "PGBOUNCER.ADMIN.
   1 "OPENAPI.TRANSPORT.
   1 "OPENAPI.SPEC.
   1 "OPENAPI.OPS.
   1 "OPENAPI.DOS.
   1 "OPENAPI.CORS.
   1 "NHI.IDENTITY.
   1 "NHI.GRANT.
   1 "NATS.VERSION.
   1 "NATS.TLS.
   1 "NATS.SYSTEM_ACCOUNT.
   1 "NATS.MONITORING.
   1 "NATS.LEAFNODE.
   1 "NATS.GATEWAY.
   1 "NATS.ACCOUNT.
   1 "MULESOFT.APP.
   1 "MQTT.TLS.
   1 "MQTT.POSTURE.
   1 "MQTT.AUTHZ.
   1 "MFT.TLS.
   1 "MFT.SERVER.
   1 "MFT.PATCH.
   1 "MFT.MOVEIT.
   1 "MEMCACHED.SERVER.
   1 "MEMCACHED.AUTH.
   1 "MCP.SERVER.
   1 "KONG.SCOPE.
   1 "KONG.RBAC.
   1 "KONG.RATELIMIT.
   1 "KONG.PLUGIN.
   1 "KONG.CORS.
   1 "KONG.CONSUMER.
   1 "KONG.AUTH.
   1 "KAFKA.INTERBROKER.
   1 "KAFKA.DELEGATION_TOKEN.
   1 "IBMMQ.SCAN.
   1 "GRPC.TRANSPORT.
   1 "GRPC.TLS.
   1 "GRPC.HEALTH.
   1 "GRPC.AUTH.
   1 "GRAPHQL.TRANSPORT.
   1 "GRAPHQL.TLS.
   1 "GRAPHQL.SCHEMA.
   1 "GRAPHQL.AUTHZ.
   1 "FLINK.WEB.
   1 "FLINK.VERSION.
   1 "FLINK.TLS.
   1 "FLINK.REST.
   1 "ELASTICSEARCH.SNAPSHOT.
   1 "ELASTICSEARCH.INDEX.
   1 "ELASTICSEARCH.HTTP.
   1 "ELASTICSEARCH.CLUSTER.
   1 "ELASTICSEARCH.AUDIT.
   1 "DISCOVERY.TRANSPORT.
   1 "DISCOVERY.TLS.
   1 "DISCOVERY.MCP.
   1 "DISCOVERY.DISCLOSURE.
   1 "DISCOVERY.API.
   1 "DISCOVERY.ADMIN_API.
   1 "DISCOVERY.ACCESS.
   1 "DATA.SENSITIVE.
   1 "DATA.EXPOSURE.
   1 "CONFLUENT.NETWORK.
   1 "BOOMI.ROLE.
   1 "BOOMI.CONNECTION.
   1 "AZURE.SUBSCRIPTION.
   1 "AZURE.SERVICEBUS.
   1 "AZURE.EVENTHUB.
   1 "AWS.ACCOUNT.
   1 "AUTH.ANONYMOUS_LOGIN_ENABLED.
   1 "ARTEMIS.TLS.
   1 "ARTEMIS.SECURITY.
   1 "ARTEMIS.CREDS.
   1 "ARTEMIS.AUTH.
   1 "AIRFLOW.VERSION.
   1 "AIRFLOW.TRANSPORT.
   1 "AIRFLOW.DAG.
   1 "AIRFLOW.CONNECTION.
   1 "ACTIVEMQ.TLS.
   1 "ACTIVEMQ.OPENWIRE.
   1 "ACTIVEMQ.CONSOLE.
   1 "ACTIVEMQ.AUTHZ.
