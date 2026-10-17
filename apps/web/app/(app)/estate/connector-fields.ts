/* The connect-form vocabulary: which systems can be connected and what a human must supply.
 *
 * GENERATED from the engine registry (services/engine/src/vectasec/registry.py CONNECTOR_FIELDS,
 * served at GET /connectors). It MIRRORS the registry rather than fetching it so the form renders
 * — and says what it *would* accept — while the engine is down. The engine re-validates every
 * submission against its own spec, so drift here costs a round trip and an error, never a wrong
 * write. Regenerate with the registry dump when connectors change (the engine's is authoritative).
 *
 * `secret` fields render as password inputs and are never echoed back after a failed submit. They
 * travel browser -> Server Action -> engine -> Vault (creds_ref), never written to Supabase by the
 * browser and never SELECTed by any console page.
 */

export type ConnectorField = {
  key: string;
  label: string;
  required?: boolean;
  secret?: boolean;
  placeholder?: string;
  help?: string;
};

export type ConnectorSpec = {
  type: string;
  label: string;
  /** One honest sentence for the picker — what connecting this actually inspects. */
  blurb: string;
  /** Detector count, stated in the picker ("N checks"). Generated from the registry. */
  rules: number;
  fields: ConnectorField[];
};

export const CONNECTORS: ConnectorSpec[] = [
  {
    type: "activemq",
    label: "ActiveMQ / Artemis",
    blurb: "JMS broker via Jolokia — auth plugins, OpenWire RCE, default creds, transport TLS.",
    rules: 6,
    fields: [
      { key: "jolokia_url", label: "Jolokia URL", required: true, placeholder: "http://localhost:8161/api/jolokia", help: "Base Jolokia endpoint. Read-only: only JMX read/search are issued." },
      { key: "username", label: "Console user", required: true, placeholder: "admin", help: "Jolokia/console user. read-only JMX is enough." },
      { key: "password", label: "Password", required: true, secret: true },
      { key: "flavor", label: "Flavor", required: true, placeholder: "classic", help: "'classic' for ActiveMQ 5.x, 'artemis' for ActiveMQ Artemis." },
    ],
  },
  {
    type: "airflow",
    label: "Apache Airflow",
    blurb: "Workflow orchestration REST API — anonymous access, expose_config, DAG/connection secrets.",
    rules: 8,
    fields: [
      { key: "base_url", label: "Airflow base URL", required: true, placeholder: "https://airflow.example.com", help: "Base URL of the Airflow webserver. The stable REST API at /api/v1/ is read with GET-only calls." },
      { key: "username", label: "Username", help: "For basic auth (with password)." },
      { key: "password", label: "Password", secret: true, help: "For basic auth (with username)." },
      { key: "token", label: "Bearer token", secret: true, help: "For token auth instead of username/password." },
    ],
  },
  {
    type: "aws",
    label: "Amazon Web Services",
    blurb: "Agentless via a read-only role — SQS/SNS/EventBridge/MSK/API Gateway policy, encryption, exposure.",
    rules: 21,
    fields: [
      { key: "regions", label: "Regions", required: true, placeholder: "us-east-1,eu-west-1", help: "Comma-separated AWS regions to scan. Every call is read-only (List*/Get*/Describe*); the SecurityAudit or ReadOnlyAccess managed policy is sufficient. Last-used telemetry additionally uses iam:ListUsers/ListRoles/GetRole/ListAccessKeys/GetAccessKeyLastUsed, iam:Generate+GetServiceLastAccessedDetails (Access Advisor, global) and cloudtrail:LookupEvents (per region); owner labels are read from tags (owner/team/service/contact/email/vectasec:owner/created-by) via iam:ListUserTags/ListRoleTags, sqs:ListQueueTags and sns:ListTagsForResource. A denied action is recorded as a coverage gap, never as a clean result. See deploy/aws/ for the role template." },
      { key: "role_arn", label: "Role ARN", placeholder: "arn:aws:iam::123456789012:role/vectasec-readonly", help: "Cross-account read-only role to assume (the agentless path). Leave empty to use a profile or key pair instead." },
      { key: "external_id", label: "External ID", help: "ExternalId condition on the role's trust policy, if it sets one." },
      { key: "profile", label: "Named profile", placeholder: "prod-readonly", help: "AWS shared-config profile to use instead of a role or key pair." },
      { key: "access_key_id", label: "Access key ID", help: "Static credential pair — prefer the cross-account role." },
      { key: "secret_access_key", label: "Secret access key", secret: true, help: "Used to open the session, never persisted into any resource." },
      { key: "session_token", label: "Session token", secret: true, help: "Only for temporary (STS) credentials." },
    ],
  },
  {
    type: "azure",
    label: "Microsoft Azure",
    blurb: "Service Bus / Event Hubs / APIM / Logic Apps — SAS keys, network access, legacy TLS, open triggers.",
    rules: 16,
    fields: [
      { key: "tenant_id", label: "Tenant ID", required: true, placeholder: "00000000-0000-0000-0000-000000000000", help: "Entra (Azure AD) tenant of the app registration." },
      { key: "client_id", label: "Client ID", required: true, help: "App registration (service principal) with the Reader role on the subscription. Every call is a read-only ARM GET; SAS keys and connection strings are never fetched." },
      { key: "client_secret", label: "Client secret", required: true, secret: true, help: "Used to obtain a bearer token, never persisted into any resource." },
      { key: "subscription_id", label: "Subscription ID", required: true, placeholder: "11111111-1111-1111-1111-111111111111", help: "Azure subscription to scan." },
    ],
  },
  {
    type: "boomi",
    label: "Boomi",
    blurb: "AtomSphere iPaaS — published-API auth, reused connection credentials, over-broad roles.",
    rules: 6,
    fields: [
      { key: "account_id", label: "Account ID", required: true, placeholder: "myaccount-ABC123", help: "Boomi AtomSphere account id to scan." },
      { key: "username", label: "Username / token username", required: true, placeholder: "BOOMI_TOKEN.name@example.com", help: "HTTP Basic username: your email, or 'BOOMI_TOKEN.<email>' for an API token." },
      { key: "token", label: "API token / password", secret: true, help: "The API token (or password). Used only to authenticate; never persisted." },
      { key: "host", label: "API host", placeholder: "https://api.boomi.com", help: "AtomSphere API host (change only for a dedicated/partner cloud)." },
    ],
  },
  {
    type: "confluent",
    label: "Confluent Cloud",
    blurb: "Managed Kafka REST v2 — over-privileged role bindings, stale API keys, public networking.",
    rules: 6,
    fields: [
      { key: "api_key", label: "Cloud API key", required: true, placeholder: "ABC123XYZ...", help: "A Confluent Cloud API key with the Cloud resource scope (owned by a service account with at least OrganizationAdmin read or the MetadataViewer/Operator roles). Read-only — every call is a GET." },
      { key: "api_secret", label: "Cloud API secret", required: true, secret: true, help: "The secret half of the Cloud API key. Used to open the Basic-auth session and never persisted into any resource." },
    ],
  },
  {
    type: "coord",
    label: "Coordination planes",
    blurb: "etcd / ZooKeeper / Nacos / Consul — auth, TLS, ACL default-allow, default credentials.",
    rules: 15,
    fields: [
      { key: "system", label: "System", required: true, placeholder: "etcd", help: "Which coordination system to scan: etcd, zookeeper, nacos, or consul. Every call is read-only (status/config reads and unauthenticated reachability probes; no writes, no key scans)." },
      { key: "host", label: "Host", required: true, placeholder: "10.0.0.10", help: "Hostname/IP the engine or worker can reach." },
      { key: "port", label: "Port", placeholder: "2379 / 2181 / 8848 / 8500", help: "Defaults per system (etcd 2379, zookeeper 2181, nacos 8848, consul 8500) when left empty." },
      { key: "peer_port", label: "etcd peer port", placeholder: "2380", help: "etcd only: the peer port probed (plaintext) for peer-TLS enablement." },
      { key: "username", label: "Username", placeholder: "nacos", help: "Nacos login user for the default-credential probe / etcd RBAC user." },
      { key: "password", label: "Password", secret: true, help: "Used to open the session, never persisted into any resource." },
      { key: "token", label: "ACL token", secret: true, help: "Consul ACL/management token or Nacos accessToken. Read-only; its value is never copied into a resource. A management token lets the scan read the ACL token/policy inventory for the NHI view." },
      { key: "tls", label: "Use TLS", placeholder: "false", help: "'true' to connect to the HTTP systems over https." },
    ],
  },
  {
    type: "discovery",
    label: "Network discovery",
    blurb: "Read-only, pre-auth fingerprinting of declared hosts/CIDRs — finds shadow middleware without sending a credential.",
    rules: 9,
    fields: [
      { key: "targets", label: "Targets", required: true, placeholder: "10.0.0.0/24, kafka.internal:9092, 10.1.2.3", help: "Hosts, host:port, or CIDRs to probe — comma or newline separated. Only what you name here is ever contacted, and only if you are authorized to probe it." },
      { key: "ports", label: "Ports", placeholder: "9092, 6379, 5672", help: "Override the default middleware port set for targets that do not name their own port." },
      { key: "allow_public", label: "Allow public IP ranges", placeholder: "false", help: "Off by default. Set true ONLY if you are authorized to scan the public addresses you named — scanning hosts you do not own is not something to do by accident." },
      { key: "timeout", label: "Per-probe timeout (seconds)", placeholder: "3" },
    ],
  },
  {
    type: "elasticsearch",
    label: "Elasticsearch / OpenSearch",
    blurb: "Search cluster — anonymous access, security-plugin state, transport/HTTP TLS, CORS.",
    rules: 11,
    fields: [
      { key: "base_url", label: "Base URL", required: true, placeholder: "https://localhost:9200", help: "Elasticsearch or OpenSearch REST endpoint. GET-only — no writes, no document reads." },
      { key: "username", label: "Username", placeholder: "vectasec_ro", help: "Basic-auth user with a read/monitoring role (the `monitor` cluster privilege plus read on the security indices for the NHI inventory)." },
      { key: "password", label: "Password", secret: true, help: "Used to open the session; never persisted into any resource." },
      { key: "api_key", label: "API key", secret: true, help: "Base64 'id:api_key' as an alternative to username/password (Elasticsearch). Sent as the Authorization: ApiKey header." },
      { key: "verify_tls", label: "Verify TLS", placeholder: "true", help: "'false' only for a self-signed dev cluster." },
    ],
  },
  {
    type: "flink",
    label: "Apache Flink",
    blurb: "Stream-processing REST — unauthenticated web UI / job submission, TLS, version CVEs.",
    rules: 4,
    fields: [
      { key: "url", label: "Flink REST URL", required: true, placeholder: "http://flink-jobmanager:8081", help: "Apache Flink REST/dashboard base URL (default port 8081). Read-only — only GETs against /overview, /jobmanager/config and /jobs; no job is ever submitted." },
      { key: "username", label: "Username", help: "Only if a reverse proxy fronts Flink with Basic auth. Flink itself has no built-in auth; leave empty to test anonymous reachability." },
      { key: "password", label: "Password", secret: true, help: "Used to open the session, never persisted into any resource." },
      { key: "verify", label: "Verify TLS", placeholder: "true", help: "'false' to skip TLS verification for a self-signed REST cert." },
    ],
  },
  {
    type: "gcp",
    label: "Google Cloud",
    blurb: "Pub/Sub & Apigee — public IAM bindings, push-endpoint auth, CMEK, target TLS.",
    rules: 12,
    fields: [
      { key: "service_account_key", label: "Service account key (JSON)", secret: true, help: "Paste the full JSON key of a read-only service account (roles/viewer, or pubsub.viewer + apigee.readOnlyAdmin). Used to sign one OAuth assertion; never persisted into any resource." },
      { key: "access_token", label: "Access token", secret: true, help: "Alternative to a key for short-lived use: a token from `gcloud auth print-access-token`. Expires within an hour." },
      { key: "project_id", label: "Project ID", placeholder: "acme-prod", help: "Project to scan. Optional when the service-account key carries project_id; required with a bare access token." },
      { key: "apigee_org", label: "Apigee organization", help: "Apigee org name if it differs from the project id (they usually match). Apigee is skipped gracefully when the API is not enabled." },
    ],
  },
  {
    type: "graphql",
    label: "GraphQL API",
    blurb: "Introspection exposure, field suggestions, unauthenticated mutations, query-depth/DoS, TLS.",
    rules: 9,
    fields: [
      { key: "url", label: "GraphQL endpoint", required: true, placeholder: "https://api.example.com/graphql", help: "The HTTP endpoint that answers POST introspection queries. Read-only — no mutations are ever sent." },
      { key: "auth_header_value", label: "Auth header value", secret: true, help: "Only if the endpoint requires auth, e.g. 'Bearer eyJ...'. Passive checks run with and without it to measure unauthenticated reach." },
      { key: "auth_header_name", label: "Auth header name", placeholder: "Authorization", help: "Header the auth value is sent in (default Authorization)." },
    ],
  },
  {
    type: "grpc",
    label: "gRPC service",
    blurb: "Server reflection exposure, plaintext transport, per-RPC auth, health endpoint.",
    rules: 6,
    fields: [
      { key: "target", label: "gRPC target", required: true, placeholder: "api.example.com:443", help: "host:port of the gRPC server. Read-only — only server reflection is called, never an application method." },
      { key: "tls", label: "Use TLS", placeholder: "true", help: "'true' to connect over TLS. The connector also checks whether plaintext h2c is accepted regardless." },
      { key: "token", label: "Bearer token", secret: true, help: "Only if the server requires per-RPC auth. Reflection is probed both with and without it to measure unauthenticated reach." },
    ],
  },
  {
    type: "ibmmq",
    label: "IBM MQ",
    blurb: "mqweb REST + MQSC — CONNAUTH/CHLAUTH enforcement, channel MCAUSER, channel TLS.",
    rules: 11,
    fields: [
      { key: "base_url", label: "mqweb URL", required: true, placeholder: "https://mq.example:9443", help: "Base URL of the IBM MQ mqweb server. Read-only: only MQSC DISPLAY commands are issued." },
      { key: "username", label: "Admin user", required: true, help: "An mqweb user in the MQWebAdmin/MQWebAdminRO role. DISPLAY-only here." },
      { key: "password", label: "Password", required: true, secret: true },
      { key: "qmgr", label: "Queue manager", required: true, placeholder: "QM1" },
      { key: "tls", label: "Use TLS", placeholder: "true", help: "'true' if the mqweb URL is https (recommended)." },
    ],
  },
  {
    type: "k8s",
    label: "Kubernetes & service mesh",
    blurb: "Istio/Linkerd/Gateway-API/ingress/RBAC + admission/egress — mTLS, allow-all authz, cluster-admin.",
    rules: 23,
    fields: [
      { key: "kubeconfig", label: "Kubeconfig path", placeholder: "~/.kube/config", help: "Path to a kubeconfig the engine/worker can read. Leave empty with in_cluster=true to use the pod's mounted service-account, or set api_server+token instead. Only LIST/GET is ever issued." },
      { key: "context", label: "Kubeconfig context", placeholder: "kind-vectasec-dev", help: "Optional context name inside the kubeconfig." },
      { key: "api_server", label: "API server URL", placeholder: "https://10.0.0.1:6443", help: "Direct token auth: the cluster API endpoint (used when no kubeconfig)." },
      { key: "token", label: "Bearer token", secret: true, help: "A read-only ServiceAccount token (bind it to the built-in `view` ClusterRole plus get/list on RBAC and the mesh CRD groups)." },
      { key: "ca_cert", label: "CA certificate path", placeholder: "/etc/vectasec/k8s-ca.crt", help: "CA bundle for the API server when using api_server+token." },
      { key: "in_cluster", label: "In-cluster", placeholder: "false", help: "'true' when the engine runs inside the target cluster." },
    ],
  },
  {
    type: "kafka",
    label: "Apache Kafka",
    blurb: "Brokers, topics, ACLs — listener security, authorization, footguns, durability posture.",
    rules: 25,
    fields: [
      { key: "bootstrap", label: "Bootstrap servers", required: true, placeholder: "broker-1:9092,broker-2:9092", help: "Comma-separated host:port list the engine or worker can reach. Read-only AdminClient — nothing is written to the cluster." },
    ],
  },
  {
    type: "kafka_connect",
    label: "Kafka Connect",
    blurb: "Connector REST — unauthenticated API (RCE), plaintext connector secrets, TLS, installed-plugin inventory.",
    rules: 5,
    fields: [
      { key: "url", label: "Connect REST URL", required: true, placeholder: "http://connect:8083", help: "Kafka Connect REST base URL (default port 8083). Read-only — only GETs against /, /connectors, /connectors/{name} and /connector-plugins; no connector is created or modified." },
      { key: "username", label: "Username", help: "Only if the REST API is behind Basic auth. Leave empty to test whether the endpoint is anonymously reachable." },
      { key: "password", label: "Password", secret: true, help: "Used to open the session, never persisted into any resource." },
      { key: "verify", label: "Verify TLS", placeholder: "true", help: "'false' to skip TLS verification for a self-signed REST cert." },
    ],
  },
  {
    type: "keycloak",
    label: "Keycloak",
    blurb: "Identity broker — wildcard redirect URIs, weak/none signing, admin exposure, default realm.",
    rules: 12,
    fields: [
      { key: "base_url", label: "Keycloak base URL", required: true, placeholder: "https://keycloak.example.com", help: "Base URL of the Keycloak server. Include the legacy '/auth' suffix only if this deployment still serves it. Read-only: only the realm, its clients, and its OIDC discovery document are fetched." },
      { key: "realm", label: "Realm", required: true, placeholder: "myrealm", help: "The realm to assess." },
      { key: "token", label: "Admin bearer token", secret: true, help: "An admin access token with view-clients / view-realm. Alternatively supply client_id + client_secret to mint one. Never stored." },
      { key: "client_id", label: "Service-account client ID", placeholder: "vectasec-scanner", help: "A confidential client with view permissions, used with client_secret to obtain a token via the client-credentials grant." },
      { key: "client_secret", label: "Service-account client secret", secret: true, help: "Secret for the client-credentials grant. Used to authenticate, never stored on any resource." },
      { key: "token_realm", label: "Token realm", placeholder: "master", help: "Realm to authenticate the client-credentials grant against (defaults to the scanned realm)." },
      { key: "verify_tls", label: "Verify TLS", placeholder: "true", help: "'false' to skip TLS verification for a self-signed dev server." },
    ],
  },
  {
    type: "kong",
    label: "Kong Gateway",
    blurb: "Admin API — routes, services, plugins, consumer credentials, exposure.",
    rules: 17,
    fields: [
      { key: "url", label: "Admin API URL", required: true, placeholder: "http://localhost:8001", help: "Kong Admin API base URL. GETs only." },
      { key: "admin_token", label: "Admin token", secret: true, help: "Kong-Admin-Token for RBAC-enabled gateways — use a read-only role." },
    ],
  },
  {
    type: "mcp",
    label: "MCP server",
    blurb: "Model Context Protocol servers & agent gateways — transport, auth-spec, tool poisoning, spec lifecycle.",
    rules: 24,
    fields: [
      { key: "url", label: "MCP endpoint", required: true, placeholder: "https://mcp.example.com/mcp", help: "Streamable HTTP endpoint of the MCP server or gateway." },
      { key: "token", label: "Bearer token", secret: true, help: "Only if the server requires auth. Passive checks by default — active probes stay off unless enabled in config." },
    ],
  },
  {
    type: "memcached",
    label: "Memcached",
    blurb: "Cache — SASL auth, UDP amplification, non-loopback bind.",
    rules: 4,
    fields: [
      { key: "host", label: "Host", required: true, placeholder: "localhost", help: "Hostname/IP the engine or worker can reach. Read-only — sends only `version` and `stats settings`, no key access." },
      { key: "port", label: "Port", placeholder: "11211" },
    ],
  },
  {
    type: "mft",
    label: "Managed File Transfer",
    blurb: "MOVEit / GoAnywhere / Cleo / Sterling / Axway — exposed consoles, version CVEs, AS2/SFTP hygiene.",
    rules: 16,
    fields: [
      { key: "base_urls", label: "Base URLs", required: true, placeholder: "https://mft.example.com,https://as2.example.com", help: "Comma-separated admin/API base URLs of the MFT appliances (MOVEit, GoAnywhere, Cleo, Sterling File Gateway, Axway SecureTransport). Every call is a read-only GET — no transfers, no config writes." },
      { key: "product", label: "Product hint", placeholder: "moveit", help: "Optional: moveit|goanywhere|cleo|sterling|axway. Leave empty to fingerprint from the server banner and login page." },
      { key: "admin_token", label: "Admin API token", secret: true, help: "Only if reading AS2/SFTP + partner-account config via the appliance admin API. Used to open the session, never persisted into any resource." },
      { key: "verify_tls", label: "Verify TLS", placeholder: "true", help: "'false' to accept a self-signed appliance certificate (the cert is still assessed and reported); defaults to verifying." },
    ],
  },
  {
    type: "mqtt",
    label: "MQTT / IoT brokers",
    blurb: "Mosquitto / EMQX / HiveMQ — anonymous access, ACL default-allow, listener TLS, open bridges.",
    rules: 13,
    fields: [
      { key: "system", label: "Broker system", required: true, placeholder: "mosquitto", help: "One of: mosquitto, emqx, hivemq. Selects how posture is read." },
      { key: "config_path", label: "Mosquitto config path", placeholder: "/etc/mosquitto/mosquitto.conf", help: "Mosquitto only: path to a mosquitto.conf the engine can read. Read-only, parsed as text — no MQTT connection is opened." },
      { key: "config_text", label: "Mosquitto config text", help: "Mosquitto only: paste the mosquitto.conf contents instead of a path." },
      { key: "base_url", label: "Admin API base URL", placeholder: "http://emqx:18083", help: "EMQX Dashboard API (:18083) or HiveMQ REST API (:8888) base URL. GETs only." },
      { key: "api_key", label: "API key / username", help: "EMQX API key or HiveMQ REST user (HTTP Basic). Use a read-only role." },
      { key: "api_secret", label: "API secret", secret: true, help: "Secret half of the API key — opens the session, never persisted." },
      { key: "token", label: "Bearer token", secret: true, help: "Alternative to api_key/api_secret: a bearer token for the admin API." },
    ],
  },
  {
    type: "mulesoft",
    label: "MuleSoft Anypoint",
    blurb: "iPaaS API Manager — missing client-id/OAuth/JWT policy, over-privileged Connected Apps.",
    rules: 8,
    fields: [
      { key: "org_id", label: "Organization ID", required: true, placeholder: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", help: "Anypoint business-group (organization) id to scan." },
      { key: "environments", label: "Environments", placeholder: "Production,Sandbox", help: "Comma-separated environment names (or ids) to scan. Empty = discover all." },
      { key: "host", label: "Anypoint host", placeholder: "https://anypoint.mulesoft.com", help: "Control-plane host; use https://eu1.anypoint.mulesoft.com for the EU plane." },
      { key: "client_id", label: "Connected App client ID", help: "A Connected App with read-only API Manager + Access Management scopes." },
      { key: "client_secret", label: "Connected App client secret", secret: true, help: "Used only to obtain a bearer token; never persisted into any resource." },
      { key: "access_token", label: "Access token", secret: true, help: "A pre-obtained bearer token, used instead of client_id/secret." },
    ],
  },
  {
    type: "n8n",
    label: "n8n",
    blurb: "Automation — CVE-range exposure, unauthenticated webhooks, credential encryption, MFA.",
    rules: 10,
    fields: [
      { key: "base_url", label: "Instance URL", required: true, placeholder: "https://n8n.example.com", help: "Root URL of the n8n instance. The public API is read under {base}/api/v1; GETs only, plus one unauthenticated GET {base}/rest/settings." },
      { key: "api_key", label: "API key", secret: true, help: "An n8n public-API key (X-N8N-API-KEY). Use a key scoped to workflow:read, user:read and audit — the connector never creates, updates, or deletes." },
    ],
  },
  {
    type: "iac",
    label: "Deployment manifests",
    blurb: "Integration-as-code — literal secrets, default credentials, anonymous access, plaintext listeners, unpinned images.",
    rules: 8,
    fields: [
      { key: "source_path", label: "Manifest path", placeholder: "/srv/deploy", help: "A directory or single file the engine can read. Walked read-only for docker-compose files, Kubernetes workload manifests and Kafka Connect connector JSON. Nothing is written and no repository is cloned." },
      { key: "source_text", label: "Manifest text", help: "Paste a manifest instead of giving a path — useful for CI, or when the repository is not on a filesystem the engine can reach." },
      { key: "source_name", label: "Manifest name", placeholder: "docker-compose.yml", help: "Filename to attribute pasted text to, so findings point somewhere a human can open. Defaults to docker-compose.yml." },
    ],
  },
  {
    type: "nats",
    label: "NATS / JetStream",
    blurb: "Lightweight broker — auth_required, system-account exposure, TLS, JetStream authz CVE.",
    rules: 9,
    fields: [
      { key: "monitoring_url", label: "Monitoring URL", required: true, placeholder: "http://localhost:8222", help: "NATS HTTP monitoring base URL (the -m / http port, 8222 by default). GETs only: /varz, /jsz, /connz. These endpoints have no auth of their own and should be network-isolated behind TLS." },
      { key: "username", label: "Monitoring username", help: "Only if a reverse proxy in front of the monitoring port adds HTTP Basic. NATS itself does not authenticate /varz." },
      { key: "password", label: "Monitoring password", secret: true, help: "Used to open the monitoring request, never stored in any resource." },
      { key: "config_json", label: "Server config (JSON)", help: "Optional. The nats-server configuration as JSON (accounts, authorization, no_auth_user, leafnodes, gateway). nats-server's config format is a JSON superset, so a converted nats-server.conf works. Required for the account / no_auth_user / leafnode / gateway checks; without it those report 'not assessable'." },
    ],
  },
  {
    type: "openapi",
    label: "REST / OpenAPI",
    blurb: "OpenAPI spec posture — unauthenticated operations, apiKey-in-query, http servers, rate-limit.",
    rules: 8,
    fields: [
      { key: "spec_url", label: "OpenAPI/Swagger URL", placeholder: "https://api.example.com/openapi.json", help: "URL of the JSON spec. Read-only — the described operations are never called; only the document is analysed." },
      { key: "spec", label: "Pasted spec (JSON)", help: "Paste the JSON spec directly instead of a URL." },
    ],
  },
  {
    type: "pgbouncer",
    label: "PgBouncer",
    blurb: "Connection pooler — auth_type trust, client/server TLS, stored backend credentials.",
    rules: 6,
    fields: [
      { key: "host", label: "Host", required: true, placeholder: "localhost", help: "PgBouncer host the engine or worker can reach. Read-only — only SHOW commands on the admin console." },
      { key: "port", label: "Port", placeholder: "6432" },
      { key: "admin_user", label: "Admin user", required: true, placeholder: "pgbouncer", help: "A user listed in PgBouncer's `admin_users` (needed to run SHOW on the admin console)." },
      { key: "admin_password", label: "Admin password", secret: true, help: "Used to open the admin connection; never persisted into any resource." },
      { key: "sslmode", label: "SSL mode", placeholder: "prefer", help: "psycopg sslmode for the admin connection (disable/prefer/require/verify-full)." },
    ],
  },
  {
    type: "pulsar",
    label: "Apache Pulsar",
    blurb: "Admin REST — authentication/authorization disabled, namespace grants, proxy TLS.",
    rules: 10,
    fields: [
      { key: "admin_url", label: "Admin API URL", required: true, placeholder: "http://localhost:8080", help: "Pulsar Admin REST base URL (the web service port, 8080 by default). GETs only. A superuser or a role with cluster/namespace read is enough." },
      { key: "token", label: "Auth token", secret: true, help: "Bearer token for the Admin API when authentication is enabled. Used to open the request, never stored in any resource." },
      { key: "tls", label: "Use TLS", placeholder: "false", help: "'true' if admin_url is https and the certificate should be verified." },
      { key: "broker_config", label: "broker.conf (JSON)", help: "Optional. broker.conf as a JSON object, used when the runtime config endpoint is not reachable." },
      { key: "proxy_config", label: "proxy.conf (JSON)", help: "Optional. proxy.conf as a JSON object — enables the proxy-TLS check." },
    ],
  },
  {
    type: "rabbitmq",
    label: "RabbitMQ",
    blurb: "Management API — users, vhosts, TLS, guest access, policy posture.",
    rules: 18,
    fields: [
      { key: "url", label: "Management API URL", required: true, placeholder: "http://localhost:15672", help: "RabbitMQ management plugin base URL. GETs only." },
      { key: "username", label: "Username", required: true, help: "A user with the read-only 'monitoring' tag is enough." },
      { key: "password", label: "Password", required: true, secret: true },
    ],
  },
  {
    type: "redis",
    label: "Redis",
    blurb: "Cache / streams / queue — auth, protected-mode, TLS, ACL users, RediShell CVE.",
    rules: 6,
    fields: [
      { key: "host", label: "Host", required: true, placeholder: "localhost", help: "Hostname/IP the engine or worker can reach. Read-only — no writes, no key scans." },
      { key: "port", label: "Port", placeholder: "6379" },
      { key: "password", label: "Password", secret: true, help: "Only if the server sets requirepass or an ACL password." },
      { key: "tls", label: "Use TLS", placeholder: "false", help: "'true' to connect over TLS (rediss://)." },
    ],
  },
  {
    type: "redpanda",
    label: "Redpanda",
    blurb: "Kafka-API broker Admin API — SASL/authorization disabled, admin-API auth, TLS.",
    rules: 4,
    fields: [
      { key: "url", label: "Admin API URL", required: true, placeholder: "http://redpanda:9644", help: "Redpanda Admin API base URL (default port 9644). Read-only — only GETs against /v1/cluster_config, /v1/node_config and /v1/brokers." },
      { key: "username", label: "Admin username", placeholder: "admin", help: "Only if admin_api_require_auth is true. Basic-auth superuser." },
      { key: "password", label: "Admin password", secret: true, help: "Used to open the session, never persisted into any resource." },
      { key: "verify", label: "Verify TLS", placeholder: "true", help: "'false' to skip TLS verification for a self-signed Admin API cert." },
    ],
  },
  {
    type: "schema_registry",
    label: "Schema Registry",
    blurb: "Confluent Schema Registry — anonymous access, TLS, open compatibility.",
    rules: 3,
    fields: [
      { key: "url", label: "Registry URL", required: true, placeholder: "http://schema-registry:8081", help: "Schema Registry REST base URL (default port 8081). Read-only — only GETs against /config, /mode and /subjects; no schema is ever written." },
      { key: "username", label: "Username", help: "Only if the registry requires Basic auth. Leave empty to test whether the registry is anonymously readable." },
      { key: "password", label: "Password", secret: true, help: "Used to open the session, never persisted into any resource." },
      { key: "verify", label: "Verify TLS", placeholder: "true", help: "'false' to skip TLS verification for a self-signed registry cert." },
    ],
  },
  {
    type: "solace",
    label: "Solace PubSub+",
    blurb: "SEMP config — default clientUsername, ACL default-allow, message-VPN TLS.",
    rules: 10,
    fields: [
      { key: "semp_url", label: "SEMP URL", required: true, placeholder: "https://localhost:1943", help: "Solace SEMP base URL (the SEMP service port; 1943 for TLS, 8080 for plaintext). The connector appends /SEMP/v2/config. GETs only." },
      { key: "username", label: "Admin username", required: true, help: "A management user with read access to the config API." },
      { key: "password", label: "Admin password", required: true, secret: true, help: "Used to open the SEMP request via HTTP Basic, never stored in any resource." },
    ],
  },
  {
    type: "solr",
    label: "Apache Solr",
    blurb: "Search — authentication/authorization plugins, admin exposure, TLS, auth-bypass CVE.",
    rules: 6,
    fields: [
      { key: "base_url", label: "Base URL", required: true, placeholder: "http://localhost:8983", help: "Solr node base URL (without the trailing /solr). GET-only — admin info endpoints, no collection reads." },
      { key: "username", label: "Username", placeholder: "solr", help: "Basic-auth user, if BasicAuthPlugin is configured. Leave empty to also observe the unauthenticated admin surface." },
      { key: "password", label: "Password", secret: true, help: "Used to open the session; never persisted into any resource." },
      { key: "verify_tls", label: "Verify TLS", placeholder: "true" },
    ],
  },
  {
    type: "vault",
    label: "HashiCorp Vault",
    blurb: "Secrets store as a target — audit devices, root tokens, over-broad policies, TLS, seal config.",
    rules: 11,
    fields: [
      { key: "base_url", label: "Vault address", required: true, placeholder: "https://vault.example.com:8200", help: "Vault API address. Use https:// — an http:// address means the token and every secret cross the network in plaintext. Read-only: only sys/* metadata and policy/mount/auth config are ever fetched." },
      { key: "token", label: "Vault token", required: true, secret: true, help: "A read-only token. A policy with read+list on sys/audit, sys/auth, sys/mounts, sys/policies/acl and the auth role paths is sufficient. The token value is used to authenticate and is NEVER stored." },
      { key: "namespace", label: "Namespace", placeholder: "admin", help: "Vault Enterprise namespace (X-Vault-Namespace). Leave empty for OSS." },
      { key: "verify_tls", label: "Verify TLS", placeholder: "true", help: "'false' to skip TLS verification for a self-signed dev Vault. Leave true in production." },
    ],
  },
  {
    type: "vectordb",
    label: "Vector databases",
    blurb: "Chroma / Weaviate / Qdrant / Milvus / pgvector — anonymous read/write, auth, TLS, RBAC.",
    rules: 12,
    fields: [
      { key: "engine", label: "Engine", required: true, placeholder: "chroma | weaviate | qdrant | milvus | pgvector", help: "Which vector store this connection points at. One connector, read-only, covers all five." },
      { key: "base_url", label: "Base URL", placeholder: "http://localhost:8000", help: "Full REST base URL (chroma/weaviate/qdrant/milvus). Overrides host/port/tls." },
      { key: "host", label: "Host", placeholder: "localhost", help: "Hostname/IP (used with port/tls if base_url is empty)." },
      { key: "port", label: "Port", placeholder: "8000 / 8080 / 6333 / 9091" },
      { key: "tls", label: "Use TLS", placeholder: "false", help: "'true' to connect over https. Read-only either way." },
      { key: "api_key", label: "API key / token", secret: true, help: "Only if the store requires one. The unauthenticated probe runs first regardless — it is the posture signal." },
      { key: "dsn", label: "Postgres DSN", secret: true, placeholder: "postgresql://user:pass@host:5432/db", help: "pgvector only. The password is read to learn presence, then dropped — never stored. All queries are read-only." },
    ],
  },
  {
    type: "zapier",
    label: "Zapier",
    blurb: "Zaps and the app connections they hold — public catch-hook triggers, automations that write to production systems, shared or ownerless connections.",
    rules: 6,
    fields: [
      { key: "base_url", label: "API base URL", placeholder: "https://api.zapier.com", help: "Root of the Zapier Workflow API. Leave as https://api.zapier.com unless Zapier gives you a regional or dedicated host. GETs only." },
      { key: "access_token", label: "Access token", required: true, secret: true, help: "An OAuth2 bearer token for the Zapier Workflow API, issued to a Zapier OAuth app with scopes zap:all (or zap:account:all for a Team/Enterprise account), connection:read and profile. The connector reads Zaps, connections and the token's profile; it never creates, edits, runs or deletes a Zap, and connection secrets are not exposed by the API." },
      { key: "account_id", label: "Account ID", placeholder: "123456", help: "Optional Team/Enterprise account id, recorded on the account resource. When set, Zaps shared within the account are included (needs zap:account:all)." },
    ],
  },
  {
    type: "workato",
    label: "Workato",
    blurb: "iPaaS — admin API clients without IP allowlist, endpoints without access profiles, shared connections.",
    rules: 6,
    fields: [
      { key: "api_token", label: "API token", required: true, secret: true, help: "A Workato API token (sent as a Bearer token). Use a token scoped read-only to recipes, connections, API clients, and API platform." },
      { key: "data_center", label: "Data center", placeholder: "us", help: "Workato data center the token belongs to: us, eu, jp, sg, au, or il." },
      { key: "host", label: "API host override", placeholder: "https://www.workato.com", help: "Explicit API host; overrides data_center (for a custom/embedded plane)." },
    ],
  },
];

export function specFor(type: string): ConnectorSpec | undefined {
  return CONNECTORS.find((c) => c.type === type);
}
