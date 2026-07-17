# KAFKA Rulepack

Implementation spec for the Apache Kafka posture detector. Verified against Apache Kafka 4.1 docs and `apache/kafka` trunk source. Latest GA at time of writing: 4.3.1 (2026-06-25); 4.2.0 shipped 2026-02-17. ZooKeeper mode was fully removed in Kafka 4.0 (2025-03-18), so ZK rules apply only to clusters `< 4.0`.

## What the scanner sees

The connector authenticates as a single Kafka principal and uses **read-only AdminClient calls only**. Everything in this rulepack is derived from:

| Call | Required ACL | Returns |
| --- | --- | --- |
| `describeCluster()` | none (connection only) | broker ids, hosts, controller, cluster id |
| `describeConfigs(ConfigResource(BROKER, "<id>"))` | `DescribeConfigs` on `CLUSTER` | static `server.properties` values + built-in defaults + dynamic overrides, each with a `ConfigSource` |
| `describeConfigs(ConfigResource(TOPIC, "<name>"))` | `DescribeConfigs` on the topic (or Cluster) | effective topic config incl. inherited values |
| `describeAcls(AclBindingFilter.ANY)` | `Describe` on `CLUSTER` | all ACL bindings, or `SecurityDisabledException` if no authorizer |
| `listTopics()` / `describeTopics()` | `Describe` on the topics | topic names, partitions, replication factor |
| `describeClientQuotas(ClientQuotaFilter.all())` | `Describe`/`DescribeConfigs` on `CLUSTER`, brokers ≥ 2.6.0 | quota entities |
| `describeUserScramCredentials()` | `Describe` on `CLUSTER` | SCRAM usernames, mechanism, iterations (never salt/storedKey) |

### Three invariants that govern every rule

**1. `ConfigResource(BROKER, name)` MUST carry a concrete broker id.** Per KIP-133/KIP-226, an empty resource name (`""`) returns *only* cluster-wide dynamic defaults. Every static security setting (`listeners`, `authorizer.class.name`, `ssl.client.auth`, …) is invisible that way, producing a false negative on essentially every rule here. Enumerate ids from `describeCluster().nodes()` and issue one request per node. `ConfigHelper.scala` throws `InvalidRequestException` if the request lands on a broker whose id does not match; the Java AdminClient routes correctly, a raw-protocol client must do it itself. **Scan every broker** — listener and SSL settings can legitimately diverge per broker, and a misconfigured minority is a real finding.

**2. Record the actual `ConfigSource` per finding; never hardcode one.** `DEFAULT_CONFIG` (never configured) vs `STATIC_BROKER_CONFIG` (deliberately set) vs `DYNAMIC_*` (set at runtime) changes the remediation. The complete enum (4.1 javadoc) is: `DYNAMIC_TOPIC_CONFIG`, `DYNAMIC_BROKER_CONFIG`, `DYNAMIC_DEFAULT_BROKER_CONFIG`, `DYNAMIC_BROKER_LOGGER_CONFIG`, `DYNAMIC_CLIENT_METRICS_CONFIG`, `DYNAMIC_GROUP_CONFIG`, `STATIC_BROKER_CONFIG`, `DEFAULT_CONFIG`, `UNKNOWN`.

**3. Absence of evidence is not evidence of absence.** If the scanner principal lacks the ACL, calls fail with `ClusterAuthorizationException` / `TopicAuthorizationException`. That is **INDETERMINATE**, never a PASS. An empty `describeAcls` result means either "no ACLs exist" (a serious finding) or "I may not see them" (indeterminate) — do not conflate. Managed platforms (Confluent Cloud, MSK Serverless, Azure Event Hubs, Redpanda, WarpStream) commonly deny broker-level `DescribeConfigs` entirely; emit `NOT_APPLICABLE`, not a finding.

### Sensitive configs return null

`DescribeConfigs` nulls the value of any `PASSWORD`-typed config. Consequently `sasl.jaas.config`, `listener.name.<x>.<mech>.sasl.jaas.config`, and all keystore/truststore passwords **cannot be inspected read-only**. This caps `KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT` at medium confidence, makes the CVE-2025-27819/27818 login-module payload undetectable, and makes weak keystore passwords undetectable.

### Severity chaining

These rules compose. Score combinations, not bindings in isolation:

- **PLAINTEXT listener + (no authorizer OR `allow.everyone.if.no.acl.found=true`)** → fully open cluster reachable by anyone with network access. This is the genuinely critical pattern; escalate.
- `auto.create.topics.enable=true` is **low** alone, **high** when authorization is absent.
- `KAFKA.ACL.ANONYMOUS_PRINCIPAL` is latent (**medium**) when no listener can actually mint an ANONYMOUS principal. Correlate before scoring.
- Durability rules (`min.insync.replicas`, `unclean.leader.election`) are integrity/availability findings. **Report them in a separate class** so they don't dilute the access-control signal.

### Parsing gotchas

1. `super.users` is **semicolon**-delimited (TLS distinguished names contain commas). A comma-split parser is wrong.
2. PrincipalType `User` is **case-sensitive**.
3. `User:*` is a valid ACL wildcard but is **not** honoured in `super.users` — flag it there as ineffective config, not as a wildcard grant.
4. When `listener.security.protocol.map` is unset the implicit default is the **identity map**, so a listener literally named `PLAINTEXT` resolves to protocol PLAINTEXT. An absent map does not mean "no listeners".
5. Per-listener overrides use a **lowercased** listener name: `listener.name.<name>.ssl.client.auth`. `listeners` conventionally uses uppercase names. Lowercase before constructing the key or you will miss every override.
6. `ConfigResource.Type` is `BROKER`, `TOPIC`, `BROKER_LOGGER`, `GROUP`, `CLIENT_METRICS`, `UNKNOWN`. **There is no CLUSTER config resource type** — cluster-scoped settings are read via `BROKER`.
7. `listConsumerGroups` is deprecated since 4.1 in favour of `listGroups`.

### Not read-only-checkable (report NOT_ASSESSED, never PASS)

- **JMX unauthenticated remote access** — JMX is a separate JVM listener configured via system properties / `KAFKA_JMX_OPTS`, never through broker configs. It never appears in `describeConfigs`. Requires host inspection or a port probe.
- **Patch-level CVE rules** — AdminClient exposes no broker version string. `describeFeatures()` yields the finalized `metadata.version` feature level, which maps only to a release *range* (e.g. `3.9-IV0`) and cannot distinguish 3.9.0 from 3.9.1 — precisely the CVE-2025-27819 boundary. Version-based CVE rules need an out-of-band version source.

**There is no CIS Benchmark for Apache Kafka.** Do not cite one. Authoritative baselines are the Apache Kafka security docs, Confluent Platform security docs, and cloud-vendor docs (AWS MSK, Cloudera). Vendor guidance is directional, not a formal benchmark.

---

# Transport & listener rules

## KAFKA.LISTENER.PLAINTEXT

**Severity:** high (escalation conditions below)
**Kinds:** `broker`, `route`
**Title:** Broker listener mapped to PLAINTEXT security protocol
**FP risk:** medium

### Check

`describeConfigs(ConfigResource(BROKER, "<concrete broker id from describeCluster().nodes()>"))`.

Read:
- `listeners` — default `PLAINTEXT://:9092`
- `listener.security.protocol.map` — default identity map `PLAINTEXT:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL`
- `advertised.listeners` — default `null`, falls back to `listeners`
- `inter.broker.listener.name`, `controller.listener.names`
- `authorizer.class.name` (for escalation)

For each `{NAME}://{host}:{port}` entry in `listeners`, resolve NAME through the map. **FAIL if any resolved protocol == `PLAINTEXT`.**

Resolve through the map — do not name-match. A listener named `SSL` remapped via `SSL:PLAINTEXT` is a true positive and naive name-matching misses it.

Exclude names listed in `controller.listener.names` (report separately).

Severity assignment:

| Condition | Severity |
| --- | --- |
| `advertised.listeners` puts the listener on a routable / non-RFC1918 address **OR** it is the client-facing listener **AND** `authorizer.class.name` is unset | **critical** |
| Client-facing PLAINTEXT listener, authorizer configured | **high** |
| Listener is *only* the inter-broker/replication listener (`inter.broker.listener.name`) and is not advertised to clients | **medium** |
| host portion is `127.0.0.1` / `localhost` (admin/health-check listener) | **low / info** |

> ⚠️ **Verify before shipping:** the identity-map default string is confirmed verbatim only in KIP-103 (2016); the 4.1 generated-config page truncated on fetch. Circumstantial evidence it is unchanged: KRaft setups still require operators to add `CONTROLLER:PLAINTEXT` manually, implying no CONTROLLER entry in the default. Confirm against the target version's config table before relying on the literal string.

### Evidence claim

```
Broker <id>: listener `<NAME>://<host>:<port>` resolves to security protocol PLAINTEXT
via listener.security.protocol.map (config source
<STATIC_BROKER_CONFIG|DYNAMIC_BROKER_CONFIG|DEFAULT_CONFIG>); clients bind to
User:ANONYMOUS, the broker performs no authentication and applies no transport encryption.
```

Do **not** assert "traffic is unencrypted" absolutely. The check cannot observe the network path; under service-mesh mTLS (Istio/Linkerd) or a TLS-terminating sidecar the traffic *is* encrypted and the claim is false. Only the broker-side facts are provable from `describeConfigs`.

`listeners` has Update Mode "per-broker", so `DYNAMIC_BROKER_CONFIG` is a reachable source. A scanner matching only STATIC/DEFAULT misreports a dynamically-reconfigured listener.

### Remediation

Remap the offending listener NAME to `SSL` or `SASL_SSL` in `listener.security.protocol.map`, **or** drop that listener from `listeners`. (Do not remove `PLAINTEXT:PLAINTEXT` from the default map — that is a different config and is not the defect.) If a PLAINTEXT listener is required for a trusted internal path, bind it to a private interface and never expose it to client networks.

Operational caveat (KIP-103): adding a new listener-name-to-protocol mapping requires **two rolling bounces**.

### False positives & how to avoid them

- Service-mesh mTLS / TLS-terminating sidecar or LB — indistinguishable from broker config alone. Must be suppressible per-listener with an "encrypted by external transport" annotation.
- Loopback-bound admin listener — handled by the host-parsing downgrade above.
- PLAINTEXT on a private interface is a common deliberate architecture; note `security.inter.broker.protocol` itself **defaults to** PLAINTEXT.

### Source

https://kafka.apache.org/41/security/listener-configuration/

---

## KAFKA.LISTENER.SASL_PLAINTEXT

**Severity:** high (per-mechanism refinement below)
**Kinds:** `broker`, `route`
**Title:** SASL authentication offered without TLS (SASL_PLAINTEXT listener)
**FP risk:** medium

### Check

`describeConfigs(ConfigResource(BROKER, "<broker id>"))` — one per node, ids from `describeCluster()`. Required ACL: `DescribeConfigs` on `CLUSTER`. `listeners` and `listener.security.protocol.map` are non-sensitive and return unredacted.

Resolve every `listeners` entry through `listener.security.protocol.map` as in `KAFKA.LISTENER.PLAINTEXT`. **FAIL if any resolved protocol == `SASL_PLAINTEXT`.**

Then read `sasl.enabled.mechanisms` (default `GSSAPI`) and the per-listener override `listener.name.<lowercase-name>.sasl.enabled.mechanisms` (override **replaces**, does not merge) and qualify:

| Effective mechanism | Impact | Severity |
| --- | --- | --- |
| `PLAIN` | password transmitted in cleartext | high |
| `OAUTHBEARER` | bearer token transmitted in clear, directly replayable | high |
| `SCRAM-SHA-256` / `SCRAM-SHA-512` | password **not** transmitted (challenge-response); exchange interceptable → offline dictionary attack | high (all traffic unencrypted) / medium if scoped to auth only |
| `GSSAPI` | no password on the wire; Kerberos supplies its own auth | medium |

Flat `high` is defensible because **all** traffic on the listener is unencrypted regardless of mechanism, but the per-mechanism split is strictly better and costs no extra API call.

**Scope:** KRaft controller listeners named in `controller.listener.names` also appear in `listeners` and will fire. That is a true positive, but the credential-rotation remediation does not apply — handle as a distinct case or exclude and cover via a separate rule.

### Evidence claim

```
Broker <id>: listener `<NAME>://<host>:<port>` resolves to SASL_PLAINTEXT; SASL
authentication is offered over an unencrypted transport, so the authentication exchange
and all subsequent data traffic are transmitted without TLS.
```

Do **not** claim "credentials and the full SASL exchange traverse the wire in clear" — factually false for SCRAM (challenge-response, password never sent) and GSSAPI (no password sent). Kafka's own wording is narrower: "SCRAM should be used only with TLS-encryption to prevent interception of SCRAM exchanges."

### Remediation

Change the listener's mapping to `SASL_SSL` in `listener.security.protocol.map` and configure the keystore — broker-wide `ssl.keystore.location` / `ssl.keystore.password`, or per-listener `listener.name.<name>.ssl.keystore.location` / `.ssl.keystore.password`.

Rotate credentials **only** where one was actually exchanged: required for `PLAIN` and `OAUTHBEARER`; overreach for `GSSAPI`; arguable for `SCRAM`.

Flipping a listener to SASL_SSL is a **breaking change requiring client-side coordination**.

### False positives & how to avoid them

Add a documented per-listener suppression with an "encrypted by external transport" annotation. None of these are distinguishable from broker configs alone:

- Service-mesh / sidecar mTLS (Istio, Linkerd) terminating TLS outside the broker.
- TLS-terminating load balancer or cloud proxy fronting the listener.
- Loopback-bound SASL_PLAINTEXT listener for local admin tooling.

### Sources

- https://kafka.apache.org/41/security/authentication-using-sasl/ (SASL_PLAINTEXT vs SASL_SSL transport distinction)
- https://kafka.apache.org/41/security/listener-configuration/ (`listener.security.protocol.map` — the cited SASL page does not mention it at all)

---

## KAFKA.INTERBROKER.PLAINTEXT

**Severity:** high
**Kinds:** `broker`
**Title:** Inter-broker replication traffic is unencrypted
**FP risk:** low

### Check

`describeConfigs(ConfigResource(BROKER, "<broker id>"))` — the name must be the **actual broker id** (e.g. `"0"`). `ConfigResource(BROKER, "")` targets cluster-wide dynamic defaults and will **not** return these static read-only configs, silently yielding no evidence. Required ACL: `DescribeConfigs` on `CLUSTER`; if the scanner lacks it the rule must **error, not pass**.

**Evaluation order is load-bearing, not stylistic:**

1. If `inter.broker.listener.name` is set (default `null`), resolve that listener name through `listener.security.protocol.map`.
2. **Only if it is null**, read `security.inter.broker.protocol` (default `PLAINTEXT`).

`security.inter.broker.protocol` is *always returned with its default value* `PLAINTEXT` even when unset and `inter.broker.listener.name` IS set. Any implementation that reads it first emits a false PLAINTEXT finding against a correctly-secured SSL cluster. **Add a regression test:** `inter.broker.listener.name=INTERNAL` mapped to SSL must assert PASS.

**FAIL if the effective protocol is `PLAINTEXT` or `SASL_PLAINTEXT`.**

Notes:
- The two keys are mutually exclusive — setting both is a broker startup error.
- `listener.security.protocol.map` defaults to the identity map, so an unset map still resolves standard listener names correctly.
- A listener name absent from the map is a broker startup error and cannot occur on a live cluster — treat as a **scan error**, not a FAIL.
- Optional: suppress or downgrade on single-broker clusters, where no replication crosses a network.
- **Scope gap:** covers broker-to-broker only. In KRaft (all 4.x), controller traffic uses `controller.listener.names` and is not covered here.

### Evidence claim

```
Broker <id>: effective inter-broker protocol is <PLAINTEXT|SASL_PLAINTEXT> (from
<security.inter.broker.protocol=PLAINTEXT default | inter.broker.listener.name=<NAME>
mapped to <PROTOCOL>>); all replicated topic data crosses the network unencrypted.
```

Distinguish the two: pure PLAINTEXT additionally provides **no broker authentication** (network-adjacent impersonation vector); SASL_PLAINTEXT loses only confidentiality. Same severity, different remediation urgency.

### Remediation

Set `inter.broker.listener.name` to a listener mapped to `SSL` or `SASL_SSL`, **or** set `security.inter.broker.protocol=SSL` (never both). Roll brokers using the documented two-phase procedure in "Incorporating Security Features in a Running Cluster" so replication is not interrupted.

### False positives & how to avoid them

Detection is exact. Residual FPs are risk-acceptance cases only — encrypted underlay via IPsec/WireGuard/service-mesh mTLS, isolated VLAN, dev clusters. These warrant an **exception mechanism, not a severity reduction**. The rule fires frequently on self-managed clusters; that is a widespread true positive, not noise.

### Sources

- https://kafka.apache.org/43/security/listener-configuration/ (resolution logic + PLAINTEXT default)
- https://kafka.apache.org/43/configuration/broker-configs/ (mutual exclusivity: "It is an error to set this and security.inter.broker.protocol properties at the same time.")

Verified against trunk `ReplicationConfigs.java`, `SocketServerConfigs.java`. Both keys unchanged in 4.3.

---

# Authorization rules

## KAFKA.AUTHZ.NO_AUTHORIZER

**Severity:** high (critical when chained — see below)
**Kinds:** `broker`, `acl`
**Title:** No authorizer configured — every authenticated principal has full cluster access
**FP risk:** medium (drops to low with the required conjunct)

### Check

**Both conditions must hold. Fire only on the conjunction** — this single change collapses the main FP vector to near-zero.

1. `describeConfigs(ConfigResource(BROKER, "<numeric broker id>"))` per broker, routed to that node → `authorizer.class.name` is the **empty string** or reported with `ConfigSource == DEFAULT_CONFIG`.
2. `describeAcls(AclBindingFilter.ANY)` → fails with `SecurityDisabledException` (error code `SECURITY_DISABLED`, **54**), which positively confirms the finding and distinguishes it from a permissions problem.

**Do not trigger on "absent."** On real Apache Kafka the key is *always* present with value `""` because it has a ConfigDef default. "Absent" can only mean a non-Apache or proxied broker — never a genuine finding. Treat as INCONCLUSIVE.

**Implementation trap:** `ConfigHelper` returns only `currentDynamicDefaultConfigs` for an empty resource name. `authorizer.class.name` is static and will **never** appear there → guaranteed false "absent". It also throws `InvalidRequestException` if the request lands on a broker whose id doesn't match ("Unexpected broker id, expected X or empty string").

**PASS on any non-empty authorizer class**, not just the two Apache ones. Emit a separate **INFO** finding for an unrecognized class. Legitimate third-party authorizers that would FP against a two-item allowlist:
- `io.confluent.kafka.security.authorizer.ConfluentServerAuthorizer`
- `org.apache.ranger.authorization.kafka.authorizer.RangerKafkaAuthorizer`
- `org.openpolicyagent.kafka.OpaAuthorizer`
- `io.strimzi.kafka.oauth.server.authorizer.KeycloakAuthorizer`

Expected secure value: `org.apache.kafka.metadata.authorizer.StandardAuthorizer` (KRaft). **Do not expect `kafka.security.authorizer.AclAuthorizer`** — ZooKeeper-only, removed in Kafka 4.0 along with ZK mode; gate it on broker version `< 4.0` or drop it.

**Escalate to critical** only when chained with an unauthenticated/PLAINTEXT listener — with no authorizer, even `User:ANONYMOUS` gets full cluster access. That is the genuinely critical state. A single-tenant mTLS cluster where every client is already trusted would get a flat critical, which over-fires.

### Evidence claim

```
authorizer.class.name is unset on broker <id> (ConfigSource=DEFAULT_CONFIG) and
describe_acls returned SecurityDisabledException; no authorization is enforced, so any
principal that completes authentication may read, write, and administer every resource.
```

### Remediation

Set `authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer` on **KRaft brokers and controllers**, define `super.users` for the operator principals, provision ACLs for each client, and keep `allow.everyone.if.no.acl.found=false` (already the default — no-ACL resources are restricted to super users).

**Provision ACLs before enabling the authorizer** to avoid locking out clients.

`authorizer.class.name` is **read-only/static** — verified absent from `DynamicBrokerConfig.ALL_DYNAMIC_CONFIGS`. It cannot be set via `incrementalAlterConfigs` and requires a **rolling restart**.

### False positives & how to avoid them

The `describeAcls` conjunct is what makes this rule safe. Without it, the rule fires critical on Kafka-API-compatible platforms that enforce authz by other means and do not expose broker configs: **Confluent Cloud** (no broker-level DescribeConfigs; RBAC/ACLs external), **Redpanda** (uses `kafka_enable_authorization`, not `authorizer.class.name`), **Azure Event Hubs** Kafka endpoint, **AWS MSK Serverless** (IAM), **WarpStream**. All of these return real ACLs from `describeAcls`, so the conjunct suppresses them correctly.

Self-consistency note: when the finding is true, no authorizer exists, so every `authorize()` call passes and the scanner's own `DescribeConfigs` on CLUSTER succeeds.

### Sources

The docs pages do **not** state the default-unset behaviour or the SecurityDisabledException behaviour — the two most load-bearing parts of this check. Primary sources required:

- https://kafka.apache.org/43/security/authorization-and-acls/ (prescribes StandardAuthorizer, super.users, allow.everyone.if.no.acl.found)
- `server-common/src/main/java/org/apache/kafka/server/config/ServerConfigs.java` — `AUTHORIZER_CLASS_NAME_DEFAULT = ""`
- `core/src/main/scala/kafka/server/AclApis.scala` — `handleDescribeAcls` returns `Errors.SECURITY_DISABLED` ("No Authorizer is configured on the broker") when the plugin is None
- `clients/src/main/java/org/apache/kafka/common/protocol/Errors.java` — `SECURITY_DISABLED(54, "Security features are disabled.")`

---

## KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL

**Severity:** high (critical only when chained — see below)
**Kinds:** `broker`, `acl`
**Title:** `allow.everyone.if.no.acl.found=true` — resources without ACLs are open to all principals
**FP risk:** medium as written; **low** with preconditions 1–2 below

### Check

**Preconditions (evaluate first; skip the rule if either fails):**

1. **An authorizer must exist.** `authorizer.class.name` default is `""`; with no authorizer this setting is **inert** and the finding text is wrong. Gate on non-empty, or use `describeAcls` returning `SecurityDisabledException` as the gate signal.
2. **Not IAM-only MSK.** Gate via `DescribeCluster` `ClientAuthentication` **before emitting**. On MSK with IAM access control this property has no effect. Do not fire-then-tell-the-reader-to-ignore.

**Main check:** `describeConfigs(ConfigResource(BROKER, "<broker id>"))` — **never** the empty-name form. This key is *not* in KafkaConfig's ConfigDef; it is visible only because `ConfigHelperUtils.createResponseConfig` merges `config.originals()` when `perBrokerConfig=true`. `ConfigResource(BROKER, "")` returns only `currentDynamicDefaultConfigs` and will **not** show a static value.

**FAIL if `allow.everyone.if.no.acl.found` parses as true.** Use **trim + case-insensitive** parse — the broker uses `Boolean.parseBoolean(configValue.toString().trim())`, so `TRUE`, `True`, `" true "` all evade a literal `== "true"` compare (false negative).

Apache Kafka default is `false` (deny unless an ACL allows). **AWS MSK overrides this to `true` by default.** Prefer the **observed** value from the broker-id-scoped describe (which does surface originals); fall back to the MSK "assume true" heuristic only when the key is genuinely absent, and mark those findings **lower confidence**.

**Blast-radius enumeration:** cross-reference `listTopics()` against `describeAcls(AclBindingFilter.ANY)`. `describeAcls` returns LITERAL-name, LITERAL `*` (wildcard), and PREFIXED patterns — a naive name-set intersection **over-reports** topics already covered by a `*` or PREFIXED binding. Match pattern types properly. Exclude internal topics: `__consumer_offsets`, `__transaction_state`, `__amazon_msk_canary*`.

**Escalate to critical** only when an authorizer is configured **AND** unauthenticated access is reachable (PLAINTEXT listener → `User:ANONYMOUS`, or public access). Note MSK forbids that combination on public clusters, so the MSK worst case is **authenticated cross-tenant access**, not anonymous.

### Evidence claim

```
allow.everyone.if.no.acl.found=true on broker <id> (source=<STATIC_BROKER_CONFIG|
DEFAULT_CONFIG>); <N> of <M> topics have no matching ACL and are readable/writable by
every authenticated principal, including User:ANONYMOUS if any PLAINTEXT listener exists.
```

`DYNAMIC_DEFAULT_BROKER_CONFIG` is **not reachable** — the key is not in `DynamicBrokerConfig.ALL_DYNAMIC_CONFIGS` and cannot be set dynamically. Realistic sources are `STATIC_BROKER_CONFIG`, or `DEFAULT_CONFIG` if no synonym matches.

### Remediation

Set `allow.everyone.if.no.acl.found=false` and add explicit ALLOW ACLs for every legitimate client **before** the change.

On AWS MSK this must be set via an **MSK cluster configuration**. Setting it to `false` is required **when enabling public access** with SASL/SCRAM or mTLS: "If you're using the SASL/SCRAM, or mTLS access-control methods, you must first set Apache Kafka ACLs for your cluster. Then, update the cluster's configuration to set the `allow.everyone.if.no.acl.found` property to false." (This is scoped to public access — it is not a blanket SASL/SCRAM requirement.)

If the MSK cluster uses IAM access control, this property has no effect — the finding is suppressed at precondition 2.

### False positives & how to avoid them

- IAM-only MSK clusters — suppressed by precondition 2.
- Self-managed clusters with no authorizer at all — suppressed by precondition 1 (and covered by `KAFKA.AUTHZ.NO_AUTHORIZER`, a strictly worse finding).
- `critical` on every MSK cluster = alert fatigue. Hence the high base with a narrow escalation.

**Method note:** WebFetch's summarizer twice returned *wrong* answers on `ConfigHelper.scala` (claimed `originals` are excluded). The checkable verdict was only established by `curl` + `grep` on raw source. Also `server/.../ServerConfigs.java` 404s — the real path is `server-common/...` — so greps against the wrong path silently returned nothing.

### Sources

- https://docs.aws.amazon.com/msk/latest/developerguide/msk-acls.html — supports **only** the default-true claim: "Amazon MSK sets it to true by default."
- https://docs.aws.amazon.com/msk/latest/developerguide/public-access.html — the public-access + SASL/SCRAM/mTLS requirement
- https://docs.aws.amazon.com/msk/latest/developerguide/iam-access-control.html — "The `allow.everyone.if.no.acl.found` Apache Kafka setting has no effect if your cluster uses IAM access control."
- `metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java:60` — key name; `getDefaultResult`: `if (configValue == null) return DENIED;`

---

## KAFKA.ACL.WILDCARD_PRINCIPAL

**Severity:** operation-tiered (see table) — **not** flat critical
**Kinds:** `acl`
**Title:** ACL grants access to the wildcard principal `User:*`
**FP risk:** medium

### Check

`describeAcls(AclBindingFilter.ANY)`.

FAIL for any returned `AclBinding` where:

```java
b.entry().permissionType() == AclPermissionType.ALLOW
  && b.entry().principal().equals("User:*")
```

PrincipalType is **case-sensitive** — match `User:` exactly.

Record `pattern().resourceType()`, `pattern().name()`, `pattern().patternType()`, `entry().operation()`, `entry().host()`.

**Severity tiers** (flat critical is incoherent — the check said severity "escalates" for WRITE/ALTER but there is no tier above critical):

| Operation | Severity |
| --- | --- |
| `ALL`, `CLUSTER_ACTION`, `ALTER_CONFIGS` on the **CLUSTER** resource **AND** `host() == "*"` | **critical** |
| `ALL`, `WRITE`, `ALTER`, `ALTER_CONFIGS`, `CLUSTER_ACTION`, `DELETE` | **high** |
| `READ` | **medium** |
| `DESCRIBE`, `DESCRIBE_CONFIGS`, `IDEMPOTENT_WRITE` | **low / info** |

`User:*` grants to *authenticated* principals — this is privilege-escalation / lateral-movement, not unauthenticated access. Unauthenticated exposure is a property of the **listener** (separate rule), not this binding. Reserve critical for full-cluster-compromise-without-auth.

Evaluate `resourceType() == CLUSTER && patternType() == LITERAL && name() == "kafka-cluster"` as the highest-impact case.

**DENY correlation (required):** after collecting ALLOW `User:*` bindings, re-scan the same `describeAcls` result for DENY bindings whose `ResourcePattern` + operation **overlap** the ALLOW. Where an overriding DENY exists, **downgrade one tier and annotate** rather than suppressing (DENY coverage is often partial). Pattern overlap between LITERAL / PREFIXED / wildcard patterns must be **computed, not string-compared**.

**Error handling (prevents a silent false negative):** `describeAcls` throws `SecurityDisabledException` when no authorizer is set. Surface as explicit **UNKNOWN/ERROR, never PASS** — a cluster with no authorizer is a worse finding and belongs to `KAFKA.AUTHZ.NO_AUTHORIZER`. Requires `Describe` on Cluster; an under-privileged scanner gets a **filtered/partial** ACL list, which is also not a PASS.

### Evidence claim

```
ACL binding grants ALLOW <OPERATION> on <RESOURCE_TYPE>:<pattern_type>:<name> to principal
User:* from host <host>; every principal — including User:ANONYMOUS on unauthenticated
listeners — inherits this permission, unless narrowed by a matching DENY binding.
```

Two corrections baked in:

- **"every authenticated principal" understates scope.** `StandardAuthorizerData` builds `matchingPrincipals` as `Set.of(basePrincipal, WILDCARD_KAFKA_PRINCIPAL)` with `WILDCARD_PRINCIPAL = "User:*"` and **no exclusion for ANONYMOUS**. On a PLAINTEXT listener the principal is `User:ANONYMOUS`, which `User:*` matches. (Do not confuse with `super.users`, where wildcards are genuinely **not** expanded — `User:*` there does not make everyone a super user. That asymmetry is real; do not blur it.)
- **"regardless of identity" is false** when an overriding DENY exists. `StandardAuthorizerData.checkSection` short-circuits on DENY: `if (DENIED == result) { matchingRuleBuilder.denyAcl = acl; return; }`, and `build()` checks `denyAcl` before `allowAcl`.

### Remediation

**Sequence matters:** issue the narrowly-scoped per-principal ACLs **before** deleting the wildcard, or clients break between the two commands.

The bare `kafka-acls.sh --remove --allow-principal 'User:*'` **will error** — `--remove` needs a resource specifier:

```bash
bin/kafka-acls.sh --bootstrap-server <host:9092> --remove \
  --allow-principal 'User:*' --operation Read --topic <name> \
  [--resource-pattern-type literal|prefixed] --force
```

Quote `'User:*'` to stop shell glob expansion (the docs explicitly call this out). `--force` skips the interactive confirmation prompt in automation.

If a shared grant is genuinely needed (e.g. DESCRIBE on a public topic), keep the wildcard but restrict the operation to the minimum required.

### False positives & how to avoid them

These drive the tiering above:

1. **ALLOW DESCRIBE on a shared/public topic to `User:*`** — deliberate, low risk. Must not be critical.
2. **`IDEMPOTENT_WRITE` on CLUSTER to `User:*`** — widely deployed after Kafka 3.0 made `enable.idempotence=true` the producer default, breaking every producer lacking cluster IdempotentWrite. Grants no data access. Legacy pre-2.8 clusters carry these bindings persistently.
3. **Managed/operator-provisioned defaults** (Strimzi, Confluent, MSK) may ship wildcard DESCRIBE grants — consider an allowlist for operator-owned bindings.
4. **Allow-broad/deny-narrow designs** — handled by DENY correlation.

Confidence: high on the API surface, the ANONYMOUS behaviour, and DENY precedence (all read from trunk source). **Medium** on FP frequency for #2/#3 — deployment-dependent and not quantified by any fetched source.

### Source

https://kafka.apache.org/41/security/authorization-and-acls/ — supports the wildcard principal, "Default PrincipalType string 'User' is case sensitive", the `--allow-host` IP-only constraint, and `--remove`/`--allow-principal`. API surface confirmed against the Kafka 4.1 javadoc: `AclBindingFilter.ANY`, `AclBinding.entry()`/`pattern()`, `AccessControlEntry.principal()`/`host()`/`operation()`/`permissionType()`. `describeAcls` supported on brokers 0.11.0.0+.

---

## KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS

**Severity:** critical for CLUSTER/TOPIC; high for GROUP/TRANSACTIONAL_ID/DELEGATION_TOKEN
**Kinds:** `acl`, `topic`
**Title:** ACL grants operation ALL on the LITERAL wildcard resource `*`
**FP risk:** medium

### Check

`describeAcls(AclBindingFilter.ANY)`. FAIL where:

```java
binding.entry().permissionType() == AclPermissionType.ALLOW
  && binding.pattern().patternType() == PatternType.LITERAL
  && binding.pattern().name().equals(ResourcePattern.WILDCARD_RESOURCE)
  && binding.entry().operation() == AclOperation.ALL
```

`permissionType()` and `operation()` live on **`AccessControlEntry`, not `AclBinding`**. `AclBinding`'s real accessors are `pattern()`, `entry()`, `toFilter()`, `isUnknown()`. Compare against the constant `ResourcePattern.WILDCARD_RESOURCE`, not a hardcoded `"*"`.

**Companion condition (closes a false negative):** ACLs on the CLUSTER resource are conventionally written with LITERAL name `"kafka-cluster"`, **not** `"*"`. A `name() == "*"` test misses the single most dangerous grant. Also FAIL when `resourceType() == CLUSTER && operation() == ALL`, regardless of name.

**Severity by resource type:**

| Resource type | Severity |
| --- | --- |
| `CLUSTER`, `TOPIC` | critical |
| `GROUP`, `TRANSACTIONAL_ID`, `DELEGATION_TOKEN` | high |

Flag at **high** if patternType/name match but the operation is a single broad verb (`WRITE`, `READ`, `DELETE`, `ALTER`).

**DENY evaluation:** evaluate DENY bindings for the same principal/type and downgrade or annotate when present, rather than scoring each binding in isolation.

**Error paths — must not become a silent PASS:** `describeAcls` throws `SecurityDisabledException` when `authorizer.class.name` is unset (a **more** severe finding than this rule) and `ClusterAuthorizationException` if the scanner lacks Describe on CLUSTER (hardcoded name `"kafka-cluster"`, per `KafkaApis.handleDescribeAcls` → `authorizeClusterOperation`). Emit ERROR/INFO for these. The scanner's required grant: `--operation Describe --cluster`.

### Evidence claim

```
ACL binding grants <principal> from host <host> every operation on all resources of type
<RESOURCE_TYPE> (LITERAL:'*'), defeating per-resource ACLs — unless narrowed by a matching
DENY binding.
```

Do **not** say "equivalent to super-user rights over every resource of that type": (a) DENY ACLs override ALLOW absolutely, so a wildcard ALLOW constrained by DENY is not unconditional; (b) super-user rights are strictly broader.

### Remediation

Replace the `*` LITERAL binding with per-resource LITERAL ACLs or a tightly scoped PREFIXED pattern, and enumerate the specific operations (READ, WRITE, DESCRIBE) instead of ALL.

> 🚫 **Do NOT move the principal to `super.users`.** This is privilege **escalation**, not mitigation. `StandardAuthorizerData` matches super users **before** any ACL evaluation and returns ALLOWED unconditionally ("Superusers are authorized to do anything"; `if (superUsers.contains(principal.toString())) { rule = SuperUserRule.INSTANCE; }`). Moving a principal holding ALL on `TOPIC:LITERAL:'*'` into `super.users` widens it from one resource type to the **entire cluster** — ACL create/delete, broker config alteration, topic deletion — and makes it **immune to DENY ACLs**. It is also static config requiring a broker restart, and wildcards do not work there.

Correct wording: *"Scope the principal to the specific operations and resources it needs. Do not move it to `super.users` — that grants strictly more privilege and removes it from ACL-store auditing and DENY enforcement."*

### False positives & how to avoid them

The **high** tier needs a **principal allowlist**. MirrorMaker 2 requires READ on all replicated source topics (default `topics: ".*"`); Connect, Cruise Control, Schema Registry, and lag exporters hold comparable breadth. Support an allowlist of operator principals that downgrades the high tier to **info**.

Redundancy note: if the principal is already in `super.users`, the wildcard ACL is **dead config** — flag separately as cleanup, not as this finding.

### Sources

- https://kafka.apache.org/41/security/authorization-and-acls/ — supports wildcard `*`, the `All` operation, ALLOW/DENY, LITERAL/PREFIXED, `super.users`. It does **not** document DENY precedence, super-user bypass, or operation implication.
- `StandardAuthorizerData.java`, `StandardAcl.java` (apache/kafka trunk) — required for the DENY-precedence and super-user-bypass claims above.

---

## KAFKA.ACL.ANONYMOUS_PRINCIPAL

**Severity:** critical when fully reachable; tiered down otherwise (see below)
**Kinds:** `acl`, `broker`
**Title:** ACL grants access to `User:ANONYMOUS` (unauthenticated clients)
**FP risk:** medium

### Check

`describeAcls(AclBindingFilter.ANY)` (the Java method is `describeAcls`, camelCase). FAIL where:

```java
b.entry().permissionType() == AclPermissionType.ALLOW
  && b.entry().principal().equals("User:ANONYMOUS")
```

`AclBinding` has **no** `principal()` or `permissionType()`. Per the Kafka 4.0 javadoc its complete method set is `isUnknown()`, `pattern()`, `entry()`, `toFilter()`, `toString()`, `equals()`, `hashCode()`. Both fields live on `AccessControlEntry`, reached via `entry()`.

**Host gate (required — primary FP source):** the check must read `entry().host()`. The documented, recommended pattern for PLAINTEXT inter-broker migration is ANONYMOUS ACLs **scoped to broker IPs**:

```bash
kafka-acls --add --allow-principal User:ANONYMOUS \
  --allow-host 10.5.0.101 --allow-host 10.5.0.102 --operation All --topic '*' --cluster
```

That binding is **not** reachable by arbitrary unauthenticated clients.

**Listener correlation:** `describeConfigs(ConfigResource(BROKER, "<id>"))` → read `ssl.client.auth` (values `required` | `requested` | `none`, default **`none`**) plus **per-listener overrides**, and resolve each listener's protocol. ANONYMOUS is the principal assigned to clients arriving on a PLAINTEXT listener, or an SSL listener where `ssl.client.auth` is not `required`. Both `requested` and `none` yield ANONYMOUS.

> ⚠️ **Verify before shipping:** the per-listener prefix mechanism was confirmed only for `listener.name.internal.ssl.endpoint.identification.algorithm`. That `listener.name.<name>.ssl.client.auth` is documented as a supported per-listener override could **not** be verified against the target version's docs. The rule must read per-listener overrides (a broker-level `required` can be overridden per listener and vice versa) — confirm the prefix against the target Kafka version, because reading only the broker-level default produces **both FPs and FNs**.

**Severity matrix:**

| Condition | Severity |
| --- | --- |
| `host() == "*"` **AND** operation ∈ {ALL, WRITE, READ, CLUSTER_ACTION, ALTER} **AND** a reachable unauthenticated listener exists | **critical** |
| `host() == "*"`, narrower operation | high |
| No listener can produce an ANONYMOUS principal (latent) | medium |
| `host()` is a bounded IP list | low / info |

**Checkability caveat:** `describeAcls` throws `SecurityDisabledException` when no authorizer is configured. Handle explicitly — do **not** emit PASS. No authorizer means no authorization at all, a strictly worse state owned by `KAFKA.AUTHZ.NO_AUTHORIZER`. Requires `Describe` on Cluster; the listener correlation needs `describeConfigs` on the BROKER resource. Both read-only.

### Evidence claim

```
ACL binding grants ALLOW <OPERATION> on <RESOURCE_TYPE>:<name> to User:ANONYMOUS from host
<host>, and broker <id> exposes listener <NAME> with protocol <PLAINTEXT|SSL with
ssl.client.auth=<none|requested>>; unauthenticated clients that can reach listener <NAME>
can exercise this permission.
```

For a host-scoped binding, reframe: *"ANONYMOUS ACL scoped to hosts `<list>`; verify these are broker IPs only."*

"Unauthenticated clients can exercise this permission" (unqualified) overstates what an admin API can prove — the scanner cannot see network policy, security groups, or whether the listener is bound to a private interface. Include `host()` and the resolved operation/resource in the evidence string.

### Remediation

> ⚠️ **"Remove all `User:ANONYMOUS` ACLs" as a first step can break the cluster.** Per KAFKA-3687, brokers on a PLAINTEXT inter-broker listener authenticate as `User:ANONYMOUS` **themselves** — the `UpdateMetadataRequest` a broker sends at startup arrives as `User:ANONYMOUS` and gets denied by the authorizer. An ANONYMOUS ACL may be **load-bearing for replication**.

Correct sequence:

1. Move inter-broker to `SASL_SSL`, or `SSL` with `ssl.client.auth=required`, and set `security.inter.broker.protocol` accordingly.
2. Grant the real broker principal its rights.
3. **Only then** delete the ANONYMOUS ACLs.

Require real authentication on every client-facing listener. Do **not** paper over PLAINTEXT with `super.users` — Confluent's ACL overview explicitly warns against this.

### False positives & how to avoid them

- Broker-IP-scoped ANONYMOUS ACLs from an inter-broker migration — handled by the host gate.
- `ALLOW DESCRIBE` on one topic to ANONYMOUS — not critical; handled by the severity matrix.
- Latent bindings with no ANONYMOUS-producing listener — medium, not critical.

### Sources

- https://docs.confluent.io/platform/current/security/authorization/acls/overview.html — near-verbatim support: "If TLS is enabled, but client authentication is not configured, clients connect anonymously using the TLS port and appear to the server with the user name ANONYMOUS… The server also identifies the ANONYMOUS user when the PLAINTEXT security protocol is used. If you grant read and write permission to the ANONYMOUS user, anyone can access the brokers without authentication." This page does **not** document `ssl.client.auth` values.
- https://kafka.apache.org/39/security/encryption-and-authentication-using-ssl/ — `ssl.client.auth` values/default (cite this, not Confluent, for that half)
- https://issues.apache.org/jira/browse/KAFKA-3687 — brokers authenticate as ANONYMOUS on PLAINTEXT inter-broker

---

## KAFKA.ACL.PREFIXED_OVERBROAD

**Severity:** low
**Kinds:** `acl`, `topic`
**Title:** PREFIXED ACL pattern matches an excessive share of resources
**FP risk:** high

### Check

`describeAcls(AclBindingFilter.ANY)` and `listTopics()`.

For each binding where:

```java
binding.entry().permissionType() == AclPermissionType.ALLOW
  && binding.pattern().patternType() == PatternType.PREFIXED
  && binding.pattern().resourceType() == ResourceType.TOPIC
```

count topics whose name `startsWith(binding.pattern().name())`.

**FAIL if:**
- `pattern().name()` is **≤ 1 character** (consider raising to ≤ 2) — this is the only sound signal; a 1-char PREFIXED grant approximates `LITERAL '*'` / `ResourcePattern.WILDCARD_RESOURCE`; **or**
- the prefix matches **> 50% of topics** *and* `M >= 20` *and* `N >= 5`.

**Deleted clause:** ~~"matches >1 topic while `operation() == ALL`"~~. Kafka's own 4.1 Streams security doc recommends verbatim `--resource-pattern-type prefixed --topic your.application.id --operation All`. Every Streams app has ≥ 2 internal topics (`-changelog`, `-repartition`) under its `application.id` prefix, so this clause **fires on every correctly-configured Streams app** — reporting best practice as a finding. Remove it, or exempt Streams/Connect prefixes.

**Minimum-topic floor:** on a 3-topic dev cluster a 2-topic prefix is 67% and fires trivially. The ratio is meaningless at low M.

**Honor DENY:** a broad PREFIXED ALLOW narrowed by DENY bindings is not overbroad. Suppress when matching DENY bindings cover the same principal/prefix.

**Denominator caveat:** `Admin.listTopics()` returns only topics the scanning principal can DESCRIBE and excludes internal topics unless `ListTopicsOptions.listInternal(true)` is set — so M may be incomplete and the percentage overstated. Set `listInternal` explicitly; degrade to **info** if the principal lacks cluster-wide DESCRIBE.

**Precondition:** ownership/tenancy context (principal-to-prefix mapping). Without it, "prefix matches many topics" is **inventory, not a defect**.

### Evidence claim

```
ACL binding grants ALLOW <OPERATION> on TOPIC:PREFIXED:'<prefix>' to <principal>; this
prefix will silently cover any future topic created with the same prefix.
```

Include `matches <N> of <M> existing topics (<pct>%)` **only** when the `M >= 20` floor is met. The "will silently cover any future topic" half follows from documented PREFIXED semantics and should be kept.

### Remediation

Narrow the prefix so it maps to a single team or application namespace, split ALL into the specific operations required, and adopt a topic naming convention (e.g. `<team>.<app>.<dataset>`) so PREFIXED grants cannot leak across tenants. Re-audit PREFIXED ACLs whenever topics are added.

### False positives & how to avoid them

PREFIXED is the **documented mechanism for namespace grants**, not a misconfiguration. Absent tenancy context this is hygiene, not a vulnerability — hence severity `low`. Main FP sources: Kafka Streams application-id prefixes (removed clause), small clusters (topic floor), DENY-narrowed grants (correlation), incomplete denominator (`listInternal`).

### Source

https://kafka.apache.org/41/security/authorization-and-acls/ — supports **only** the narrow claim that prefixed resource patterns exist ("You can add acls on prefixed resource patterns, e.g. … 'Test-'"). It does **not** support the >50% threshold, the ALL heuristic, or the 1-char rule. **Cite those as heuristics, not documented thresholds.**

API facts confirmed against the 4.1 javadoc. **Correction #4 (`listTopics` ACL filtering and `listInternal` default) needs a source-code check before implementation** — the javadoc states neither explicitly.

---

# SASL rules

## KAFKA.SASL.PLAIN_WITHOUT_TLS

**Severity:** critical
**Kinds:** `broker`
**Title:** SASL/PLAIN enabled on a listener without TLS — cleartext passwords on the wire
**FP risk:** medium

### Check

`describeConfigs(ConfigResource(BROKER, "<broker id>"))` per broker. An empty resource name returns only `dynamicConfig.currentDynamicDefaultConfigs` and would **miss static `server.properties` values**; a non-matching id throws `InvalidRequestException`. Mechanisms can differ per broker — scan every one. Requires only `DescribeConfigs` on `CLUSTER`.

> 🚫 **Do NOT enumerate listeners from `listener.security.protocol.map`.** `LISTENER_SECURITY_PROTOCOL_MAP_DEFAULT` is built from `Arrays.stream(SecurityProtocol.values())` (trunk `SocketServerConfigs.java`) — an identity map present on **every** broker. A `SASL_PLAINTEXT` entry exists in the map even when no SASL_PLAINTEXT listener is configured. A scanner iterating map entries + a broker-wide `sasl.enabled.mechanisms` containing PLAIN (set legitimately for a SASL_SSL listener) fires a **false CRITICAL against a nonexistent listener.**

Correct procedure:

1. Enumerate the **actual `listeners`** config (type LIST, default `PLAINTEXT://:9092`).
2. Use `listener.security.protocol.map` **only to resolve** each configured listener's name → protocol. If a listener name has no explicit map entry but is itself a `SecurityProtocol` name, the protocol is the name (the default map makes this automatic).
3. Read `sasl.enabled.mechanisms` (type list, default `GSSAPI`, update-mode per-broker) and the per-listener override `listener.name.<lowercased-listener-name>.sasl.enabled.mechanisms`. Override wins, else fall back to the generic key (standard `AbstractConfig` semantics; runtime path is `KafkaConfig.saslEnabledMechanisms(listenerName)` → `valuesWithPrefixOverride(listenerName.configPrefix)`, where `ListenerName.configPrefix()` = `"listener.name." + value.toLowerCase(Locale.ROOT) + "."`).

**FAIL (critical)** if `PLAIN` is in the effective mechanism set for a listener whose resolved protocol is `SASL_PLAINTEXT`.

**PLAIN on a SASL_SSL listener: INFO/LOW, not medium.** PLAIN-over-TLS is the **documented-correct** usage ("SASL/PLAIN should be used only with SSL as transport layer") and is what AWS MSK, Confluent Cloud, Aiven, and Azure Event Hubs use — a medium here fires on nearly every managed cluster. The original "no channel binding" rationale is invalid: Kafka supports only SCRAM-SHA-256/512 with no `-PLUS` variants, so the recommended SCRAM alternative gives no channel binding either. The only defensible rationale for an info-grade note: **PLAIN transmits the cleartext password to the broker** (and to any TLS-terminating proxy), whereas SCRAM is challenge-response and never reveals it.

**Redaction:** values are **not** redacted here. `ConfigHelperUtils.createResponseConfig` merges `config.originals()` with `nonInternalValues()`, so listener-prefixed static configs are enumerated. `AbstractKafkaConfig.configType()` falls back to `DynamicBrokerConfig.brokerConfigSynonyms(name, true)` whose `LISTENER_CONFIG_REGEX = "listener\.name\.[^.]*\.(.*)"` strips the prefix to `sasl.enabled.mechanisms` → `Type.LIST` → not sensitive → value returned. **Caveat:** `[^.]*` means a listener name **containing a dot** will not resolve and its value **is redacted to null** — treat a null-valued `listener.name.*.sasl.enabled.mechanisms` as **UNKNOWN / unable-to-assess**, not as absent.

**True-positive strengthener** (confidence: medium — reasoned from source, not doc-verified): the broker requires a JAAS config for each enabled mechanism on each SASL listener at startup (`JaasContext.loadServerContext` throws otherwise). So on a **running** cluster, PLAIN in the effective mechanism set for a SASL_PLAINTEXT listener genuinely means the broker accepts PLAIN there. This materially reduces the FP rate of the critical branch.

### Evidence claim

```
Broker <id>: listener <NAME> resolves to SASL_PLAINTEXT and its effective
sasl.enabled.mechanisms includes PLAIN; usernames and passwords are transmitted
unencrypted, and Kafka documents that SASL/PLAIN should be used only with SSL as
transport layer.
```

### Remediation

Map the listener to `SASL_SSL`, or replace PLAIN with SCRAM-SHA-512 or OAUTHBEARER over TLS.

Rotate every credential configured for the PLAIN mechanism — they must be assumed disclosed. **The scanner cannot enumerate which users:** PLAIN credentials live in `listener.name.<x>.plain.sasl.jaas.config`, which is `ConfigDef.Type.PASSWORD` and is redacted to null by `describeConfigs`. Word the remediation so the operator knows to look in the broker JAAS config themselves.

### False positives & how to avoid them

Document suppressible exceptions for the critical branch — legitimate SASL_PLAINTEXT deployments the API cannot distinguish:

- Encryption at another layer (service-mesh mTLS sidecar e.g. Istio, IPsec, WireGuard).
- TLS-terminating proxy / LB in front of the broker.
- Listener bound only to loopback for admin tooling.

These are documented exceptions/suppressions, **not** reasons to drop the rule.

### Sources

- https://kafka.apache.org/41/security/authentication-using-sasl/ — verbatim: "SASL/PLAIN should be used only with SSL as transport layer to ensure that clear passwords are not transmitted on the wire without encryption" and "SASL may be used with PLAINTEXT or SSL as the transport layer using the security protocol SASL_PLAINTEXT or SASL_SSL respectively." It does **not** document `sasl.enabled.mechanisms` defaults, the per-listener override syntax, or `listener.security.protocol.map`.
- https://kafka.apache.org/41/generated/kafka_config.html — cite for those keys.

Verified against trunk: `SocketServerConfigs.java`, `KafkaConfig.scala`, `ListenerName.java`, `DynamicBrokerConfig.java`, `ConfigHelper.scala`, `ConfigHelperUtils.java`, `AbstractKafkaConfig.java`.

---

## KAFKA.SASL.SCRAM_WITHOUT_TLS

**Severity:** high
**Kinds:** `broker`, `user`
**Title:** SCRAM enabled without TLS — exchange is interceptable and replayable
**FP risk:** low

### Check

`describeConfigs(ConfigResource(BROKER, "<broker id>"))` — the concrete id is load-bearing (`ConfigHelper.scala:104-106`: an empty name returns **only** `currentDynamicDefaultConfigs` and misses static `server.properties`). Iterate each broker id (`ConfigHelper.scala:108` throws `InvalidRequestException` on mismatch; AdminClient routes automatically). Required ACL: `DescribeConfigs` on `CLUSTER` (`ConfigHelper.scala:57`) — read-only.

**Protocol resolution (must be specified, else the check is not implementable):** read `listeners` + `listener.security.protocol.map` from the **same** `describeConfigs` result and join listener NAME → protocol.

**Override precedence — state it explicitly:** `listener.name.<name>.sasl.enabled.mechanisms` **replaces** the global value for that listener; it does **not** merge/union. Implementing as "global OR override contains SCRAM" produces a **false positive** for the common config `global=SCRAM-SHA-512,PLAIN` with `listener.name.internal.sasl.enabled.mechanisms=PLAIN` (SCRAM is not actually enabled on that plaintext listener).

**FAIL** if the effective `sasl.enabled.mechanisms` contains `SCRAM-SHA-256` or `SCRAM-SHA-512` for a listener whose resolved protocol is `SASL_PLAINTEXT`.

**Downgrade/suppress loopback:** parse the bind host in `listeners` (and `advertised.listeners`). A SASL_PLAINTEXT listener bound to `localhost`/`127.0.0.1` makes the "interceptable" assertion factually weak.

**Enumerate credentials:** `describeUserScramCredentials()` — read-only, `Describe` on CLUSTER (KIP-1061), returns usernames/mechanism/iterations only, **never** salt/storedKey. This is **cluster-wide, not listener-scoped**. Consider downgrading when N=0 (mechanism enabled but no credentials provisioned = not exploitable in practice).

**Redaction resolves safely:** `createBrokerConfigEntry` nulls sensitive values, but `AbstractKafkaConfig.configType` falls back via `brokerConfigSynonyms(name, true)` → `sasl.enabled.mechanisms` → LIST → `maybeSensitive()=false`. `LISTENER_MECHANISM_CONFIGS` (jaas.config / login handlers) does not capture it. The value returns in plaintext.

### Evidence claim

```
Broker <id>: listener <NAME> is SASL_PLAINTEXT with SCRAM-SHA-<256|512> enabled; the
authentication exchange is interceptable and all traffic on this listener is unencrypted.
Cluster-wide, <N> SCRAM credentials are provisioned (via describeUserScramCredentials).
```

**Do not assert the CVE state as observed evidence.** A read-only admin client **cannot** determine the patch version: ApiVersions ranges are identical across 3.7.1 vs 3.7.2, and `metadata.version`/IBP resolves only to a minor (e.g. `3.7-IV4`). Move CVE-2024-56128 to remediation as a **conditional advisory**, or gate it on a version supplied out-of-band.

Reword the credential count as **cluster-wide** — the original "`<N>` SCRAM credentials provisioned" alongside a specific listener implies those N are tied to that listener.

### Remediation

Move SCRAM to a `SASL_SSL` listener.

Additionally, **if running an affected version**, this is also replayable: CVE-2024-56128 is a missing RFC 5802 nonce verification. **Affected set:** `(0.10.2.0 <= v <= 3.7.1) OR (v == 3.8.0)`. Fixed in 3.7.2, 3.8.1, 3.9.0 and later. (The lower bound matters — SCRAM did not exist before 0.10.2.0. Do **not** write the predicate as "`<3.7.2/<3.8.1`", which read literally collapses to `v < 3.8.1` and wrongly includes the **fixed** 3.7.2/3.7.3.) Deployments running SCRAM over TLS were not affected.

### False positives & how to avoid them

Low. Genuine FPs:

- TLS terminated by a sidecar / service mesh — uncommon and awkward for Kafka.
- Loopback-bound listeners — addressed by the host-parse downgrade.

The very common "internal listener on a trusted VPC/pod network" case is **not** a false positive — the assertion remains factually true and contradicts explicit Kafka guidance. That is risk acceptance, best handled by a suppression/exception workflow rather than by weakening the rule.

**Severity rationale:** `high` is defensible, not inflated. It sits below PLAIN-without-TLS (password directly recoverable = critical) and above informational: SCRAM keeps the password off the wire, but the exchange is interceptable (enabling offline dictionary/brute-force against the SCRAM proof), all data traffic on the listener is unencrypted, and on unpatched versions it escalates to full replay/auth-bypass.

### Sources

- https://kafka.apache.org/community/cve-list/ — supports the CVE claims verbatim: title "SCRAM authentication vulnerable to replay attacks when used without encryption", affected "0.10.2.0 - 3.7.1, 3.8.0", fixed "3.7.2, 3.8.1, 3.9.0", RFC 5802 nonce non-verification, "deployments using SCRAM with TLS are not affected". It does **not** support the "must be used only with TLS" guidance.
- https://kafka.apache.org/41/security/authentication-using-sasl/ — verbatim: "SCRAM should be used only with TLS-encryption to prevent interception of SCRAM exchanges."

Keys verified: `BrokerSecurityConfigs.java:97` (type LIST, default GSSAPI, defined line 177); `DynamicBrokerConfig.java:95` (`LISTENER_CONFIG_REGEX`).

---

## KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT

**Severity:** high
**Kinds:** `broker`
**Title:** SASL/OAUTHBEARER using the built-in unsecured JWT handler
**Confidence:** medium (the JAAS config that might name a custom handler is redacted)
**FP risk:** low

### Check

`describeConfigs(ConfigResource(BROKER, "<broker id>"))`, routed to the named broker. Requires `DescribeConfigs` on CLUSTER. The BROKER path returns `allConfigs(config)` = `config.originals.asScala.filter(_._2 != null) ++ config.nonInternalValues.asScala`, and `originals` carries every `server.properties` entry **including listener-prefixed keys not in the ConfigDef** (`ConfigHelper.scala`).

**Per-listener evaluation (required — the global-only form misses the majority real-world case):**

1. Enumerate SASL listeners from `listeners` + `listener.security.protocol.map`.
2. For each, compute the effective mechanism set: `listener.name.<name>.sasl.enabled.mechanisms` if present, else global `sasl.enabled.mechanisms` (default `GSSAPI`).
3. **FAIL** where `OAUTHBEARER` is in that listener's effective set **AND** `listener.name.<name>.oauthbearer.sasl.server.callback.handler.class` is absent / `ConfigSource=DEFAULT_CONFIG`.

The common OAUTHBEARER deployment enables it **per-listener** and never touches the global key, so a global-only check **misses it**. Per-listener pairing also removes the converse FP (OAUTHBEARER present globally but every SASL listener overriding it away, so it is never actually offered).

> 🚫 **The un-prefixed `sasl.server.callback.handler.class` must NOT count as a PASS.** Verified in `SaslChannelBuilder.createServerCallbackHandlers` (4.1):
> ```java
> String prefix = ListenerName.saslMechanismPrefix(mechanism);   // -> "oauthbearer."
> Class<...> clazz = (Class<...>) configs.get(prefix + BrokerSecurityConfigs.SASL_SERVER_CALLBACK_HANDLER_CLASS_CONFIG);
> if (clazz != null) callbackHandler = Utils.newInstance(clazz);
> ...
> else if (mechanism.equals(OAuthBearerLoginModule.OAUTHBEARER_MECHANISM))
>     callbackHandler = new OAuthBearerUnsecuredValidatorCallbackHandler();
> ```
> Only the **mechanism-prefixed** form is consulted. A bare `sasl.server.callback.handler.class` never disables the unsecured validator. Treating it as a PASS yields a **false negative on a genuinely broken broker** — and setting the un-prefixed key is exactly the mistake an operator makes. The 4.1 docs confirm the key "must be prefixed with listener prefix and SASL mechanism name in lower-case."

Kafka's default OAUTHBEARER implementation creates and validates **Unsecured JSON Web Tokens** — signatures are not verified, so any client can mint a token asserting any principal.

**Null values are fine:** Kafka redacts values for configs whose type it cannot resolve, so a listener-prefixed key may return `value=null`. This does **not** break the rule — presence + `ConfigSource` (`STATIC_BROKER_CONFIG` when set, absent when not) is all the check needs.

**Severity rationale:** if it fires truly, any client mints a token asserting any principal = unauthenticated full auth bypass (the analogous ASF CVE is CVSS 9.1). `high` rather than `critical` because the rule cannot tell whether the listener is externally exposed or whether this is a dev/test cluster — which the Kafka docs **explicitly sanction** as the unsecured handler's intended use.

### Evidence claim

```
Broker <id>, listener <name>: OAUTHBEARER enabled via <global|listener>
sasl.enabled.mechanisms, and listener.name.<name>.oauthbearer.sasl.server.callback.handler.class
is absent -> OAuthBearerUnsecuredValidatorCallbackHandler is in use, which Kafka documents
as only suitable for use in non-production Kafka installations.
```

Name the **specific listener**, not the broker as a whole.

### Remediation

Implement and configure a production `AuthenticateCallbackHandler` (or use the broker's OAuth/OIDC JWKS validation settings) via `listener.name.<name>.oauthbearer.sasl.server.callback.handler.class`, and verify issuer, audience, expiry, and signature.

**Separate, distinct issue — CVE-2026-33557** (verified against https://kafka.apache.org/community/cve-list/ and https://seclists.org/oss-sec/2026/q2/156): affects **4.1.0–4.1.1**; `sasl.oauthbearer.jwt.validator.class` defaults to `org.apache.kafka.common.security.oauthbearer.DefaultJwtValidator`, which accepts any JWT without validating signature/issuer/audience. Mitigate by setting `BrokerJwtValidator` explicitly. Fixed in **4.1.2 and 4.2.0**. This bites only **after** the operator follows this rule's remediation and configures the production handler — it is **not** what this rule detects.

### False positives & how to avoid them

Low. Managed platforms (Confluent Cloud, MSK) commonly restrict broker-level `DescribeConfigs`; **scope the rule to self-managed clusters and emit NOT_APPLICABLE rather than a finding when the describe is denied.**

Confidence is capped at medium because `sasl.jaas.config` — which could name a custom handler — is PASSWORD-typed and redacted.

### Sources

- https://kafka.apache.org/41/security/authentication-using-sasl/
- `clients/src/main/java/org/apache/kafka/common/network/SaslChannelBuilder.java` (branch 4.1) — the mechanism-prefixed lookup
- `core/src/main/scala/kafka/server/ConfigHelper.scala` — `originals` inclusion
- https://kafka.apache.org/community/cve-list/ — CVE-2026-33557

---

# TLS rules

## KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED

**Severity:** high for `none`; medium for `requested`
**Kinds:** `broker`
**Title:** SSL listener does not require client certificate authentication
**FP risk:** medium (driven almost entirely by corrections 1 and 2 below — implementation bugs, not defects in the premise)

> **Schema note:** this rule emits two severities from one check body. Split into two rule_ids, or make severity a **per-branch field**, so the rulepack schema stays honest.

### Check

`describeConfigs(ConfigResource(BROKER, "<concrete broker id>"))`. The name **must** be the concrete id — an empty/null name returns cluster defaults only (`perBrokerConfig=false`) and will **not** contain listener-prefixed or static values. Requires only `DescribeConfigs` on Cluster.

Broker configs are built as `config.originals.asScala.filter(_._2 != null) ++ config.nonInternalValues.asScala` (`ConfigHelper.scala`). Because `originals` is included when `perBrokerConfig=true`, listener-prefixed keys set in `server.properties` (and not in the ConfigDef) **are** returned. `listeners` and `listener.security.protocol.map` are likewise readable.

For every listener whose resolved protocol is `SSL` — **not** `SASL_SSL`, where SASL performs authentication:

| Effective `ssl.client.auth` | Severity |
| --- | --- |
| `none` (default) — clients unauthenticated, map to `User:ANONYMOUS` | **high** |
| `requested` | **medium** |
| `required` | PASS |

> ⚠️ **Correction 1 — lowercase the listener name (highest FP risk).** Kafka mandates the listener name in the prefix be **lowercase**: "all options starting with `ssl.` can be prefixed with `listener.name.<NameOfTheListener>.`, where the name of the listener has to be always in lower case." But `listeners` conventionally uses **uppercase** names (e.g. `CLIENT://:9093`, `listener.security.protocol.map=CLIENT:SSL`). A case-sensitive lookup of `listener.name.CLIENT.ssl.client.auth` **misses** the real override `listener.name.client.ssl.client.auth` and **falsely FAILs a listener actually set to `required`.**

> ⚠️ **Correction 2 — resolve the full precedence chain.** `ssl.client.auth` appears in `DynamicListenerConfig.ReconfigurableConfigs` (`DynamicBrokerConfig.scala`), so it can be set **dynamically**. Precedence:
> `DYNAMIC_BROKER(listener-prefixed)` > `DYNAMIC_BROKER(generic)` > `STATIC(listener-prefixed)` > `STATIC(generic)` > `DEFAULT`.
> Reading only DEFAULT/STATIC **misreports a broker hardened at runtime**.

**Correction 4 — scope.** In KRaft combined-mode nodes, the controller listener (`controller.listener.names`, update mode read-only) appears in `listeners` and can resolve to SSL. Firing there emits remediation ("distribute client keystores") that is **wrong for a controller**. Exclude listeners named in `controller.listener.names`, or emit a distinct finding/remediation. Same for `inter.broker.listener.name` — still a real finding, but remediation should say **inter-broker** keystore, not client keystore.

**Recommended noise reduction:** impact is contingent on the authorizer. With no `authorizer.class.name`, `User:ANONYMOUS` gets unrestricted access (arguably critical). With an authorizer set, `allow.everyone.if.no.acl.found=false`, and no ACLs bound to `User:ANONYMOUS`, exposure is materially lower. **Both keys are readable via the same `describeConfigs` call** — cross-reference and downgrade to medium/low (or annotate) when ANONYMOUS is provably denied, rather than firing high unconditionally.

### Evidence claim

```
Broker <id>: listener <name> resolves to SSL but effective ssl.client.auth=<none|requested>
(source=<DEFAULT_CONFIG|STATIC_BROKER_CONFIG|DYNAMIC_BROKER_CONFIG|DYNAMIC_DEFAULT_BROKER_CONFIG>);
TLS provides encryption only and connecting clients authenticate as User:ANONYMOUS.
```

Use `<name>` (lowercased) consistently — do not mix `<NAME>`/`<name>`.

The `User:ANONYMOUS` sub-claim is **true but not supported by the cited SSL page** (confidence high, corroborated by Red Hat and Confluent docs). Cite a second source (Kafka authorization docs / https://kafka.apache.org/41/security/listener-configuration/) or drop the assertion from the evidence string.

### Remediation

Set `listener.name.<name>.ssl.client.auth=required` on client-facing SSL listeners and distribute client keystores signed by the broker truststore CA. **Never use `requested`.** If mutual TLS is impractical, switch the listener to `SASL_SSL` so SASL supplies the client identity.

### False positives & how to avoid them

Accepted, not disqualifying:

- mTLS terminated upstream at an L4 proxy/NLB/service-mesh sidecar — uncommon for Kafka since the protocol needs direct broker addressing, but real.
- Deliberately anonymous-but-encrypted listeners fronting ACL-denied ANONYMOUS.

Neither is common enough to make the rule noise. The core rule is sound; fix corrections 1 and 2 to collapse the FP rate.

### Source

https://kafka.apache.org/41/security/encryption-and-authentication-using-ssl/ — directly supports the key name, the `none|requested|required` values, the `none` default, the per-listener prefix, and verbatim the `requested` discouragement: "The usage of 'requested' is discouraged as it provides a false sense of security and misconfigured clients will still connect successfully." It does **not** state the `User:ANONYMOUS` behaviour.

Verified: `clients/src/main/java/org/apache/kafka/common/config/internals/BrokerSecurityConfigs.java` (branch 4.1) — `SSL_CLIENT_AUTH_CONFIG = "ssl.client.auth"`, default `SslClientAuth.NONE.toString()`, validator `ConfigDef.ValidString.in(Utils.enumOptions(SslClientAuth.class))`.

---

## KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED

**Severity:** medium
**Kinds:** `broker`
**Title:** TLS hostname verification disabled (`ssl.endpoint.identification.algorithm` empty)
**Confidence:** medium
**FP risk:** medium

### Check

`describeConfigs(ConfigResource(BROKER, "<broker id>"))`.

**FAIL if** `ssl.endpoint.identification.algorithm` **OR any** `listener.name.<name>.ssl.endpoint.identification.algorithm` is present with an **empty-string value**. The default is `https` (hostname verification on by default since Kafka 2.0.0).

The listener-prefixed form is **required coverage, not optional** — it is the disable path the Kafka docs themselves demonstrate:

```bash
kafka-configs.sh --entity-type brokers --entity-name 0 --alter \
  --add-config listener.name.internal.ssl.endpoint.identification.algorithm=
```

Without it the rule has a large **false-negative hole**.

**Gate on outbound TLS actually being in use** (suppresses the main FP): if the broker's inter-broker protocol is `PLAINTEXT` or `SASL_PLAINTEXT` (check `security.inter.broker.protocol`, or resolve `inter.broker.listener.name` against `listener.security.protocol.map`), an empty value is an **inert leftover** in `server.properties` with no MITM exposure. Either suppress, or downgrade to info/low as config hygiene. For the listener-prefixed variant, gate on **that specific listener's** mapped protocol being `SSL` or `SASL_SSL`.

**Scope:** this governs the broker's own **outbound** TLS connections (inter-broker replication, controller). Verified in `DefaultSslEngineFactory.createSslEngine`, where `setEndpointIdentificationAlgorithm` is applied **only in the client-mode branch**; `createServerSslEngine` passes `endpointIdentification=null`. The config has **no effect on inbound/server-side engines** — evidence must not imply it protects client-to-broker traffic.

**Version assumption:** "present with empty value" is correct for Kafka ≥ 2.0.0, where *absent* means the `https` default applies. On pre-2.0.0 brokers the key was undefined by default and verification was simply not performed, so **absence** — not emptiness — was the vulnerable state. Pre-2.0 is long EOL; state the ≥ 2.0.0 assumption explicitly, or key the check off broker version.

### Evidence claim

```
Broker <id>: <ssl.endpoint.identification.algorithm|listener.name.<name>.ssl.endpoint.identification.algorithm>
is set to the empty string (source=<actual ConfigSource returned>), overriding the default
'https'; broker-initiated TLS connections do not verify the peer hostname against the
certificate.
```

**Do not hardcode `source=STATIC_BROKER_CONFIG`** — the setting is per-broker dynamically updatable and may legitimately be observed as `DYNAMIC_BROKER_CONFIG`. Report the source actually returned.

### Remediation

Remove the override so the value returns to `https`. If the setting exists to work around certificate SAN mismatches, **reissue broker certificates with correct SANs** (DNS names and/or IP SANs matching the advertised listener hosts) rather than disabling verification — the Kafka docs note verbatim: "Normally there is no good reason to disable hostname verification apart from being the quickest way to 'just get it to work' followed by the promise to 'fix it later when there is more time'!"

> 🚫 **Do not reference `ssl.principal.mapping.rules`.** Per KIP-371 it maps an X.500 distinguished name to a short principal name for **authorization of inbound mTLS clients**. It has no relationship to hostname verification or SAN mismatches, and does not appear on the cited source page.

### False positives & how to avoid them

The dominant FP is an **inert leftover** on a cluster whose inter-broker protocol is not TLS — handled by the outbound-TLS gate above.

### Source

https://kafka.apache.org/41/security/encryption-and-authentication-using-ssl/

---

# Topic & governance rules

## KAFKA.TOPIC.AUTO_CREATE_ENABLED

**Severity:** low standalone; **high** when chained (see below)
**Kinds:** `broker`, `topic`
**Title:** `auto.create.topics.enable=true` allows implicit topic creation
**FP risk:** medium (prevalence/weak-signal — the check itself never mis-reads)

### Check

`describeConfigs(ConfigResource(BROKER, "<broker id>"))` — **must enumerate real broker ids, never an empty resource name.** Per KIP-133: "If resource_type is Broker, the resource_name must be the id of the broker processing the request." An empty name returns only cluster-wide **dynamic** defaults and would **miss** this static/default-sourced config (false negative). Iterate every broker id from `DescribeCluster` — it is a static per-broker config and can drift across a rolling restart, so a **mixed cluster is possible and worth reporting**.

**FAIL if `auto.create.topics.enable` != `false`** (Kafka default is `true`). The value is returned as a **STRING, not a bool** — use a **case-insensitive** compare against `"false"`. Treat a missing/errored entry as **UNKNOWN/skip, not FAIL** (managed platforms restrict `DescribeConfigs` on BROKER resources).

> **Treat this rule as a severity MODIFIER on the authz rules, not a standalone finding.** The METADATA request (API key 3) auto-create path **is** authorization-checked: the broker checks `Create` on the Cluster resource, then falls back to `Create` on the Topic resource. And `allow.everyone.if.no.acl.found` defaults to **false** ("If a resource (R) does not have any ACLs defined… Kafka will restrict access to that resource"). Therefore on an authorizer-enabled, deny-by-default cluster, `auto.create.topics.enable=true` **crosses no security boundary** — a client that auto-creates already holds CREATE. Residual impact there is governance/durability (ungoverned topic spec, RF=1 durability landmine, topic sprawl), not a security finding.

**Escalate to high** when combined with `KAFKA.AUTHZ.NO_AUTHORIZER` or `KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL` — that pairing is where real unauthenticated topic-creation / resource-exhaustion lives. Auto-created topics inherit the broker default `num.partitions` (int, default 1) and `default.replication.factor` (int, default 1 — description: "The replication factor for automatically created topics") rather than a governed spec.

**Do not add a deprecation claim.** Secondary sources assert broker-side auto-creation is deprecated per KIP-487; KIP-487's status is still "Under Discussion" (last updated 2019) and the 4.1 broker-configs page carries no deprecation marker (importance: high). Likewise KIP-755 (proposed AUTO_CREATE ACL) is "Under Discussion" and **not shipped** — `CREATE` remains the operation gating both `CreateTopics` and auto-creation.

### Evidence claim

```
Broker <id>: auto.create.topics.enable=true (source=<DEFAULT_CONFIG|STATIC_BROKER_CONFIG>)
with authorizer.class.name=<value>; a metadata request (including the one a producer or
consumer issues on first access to an unknown topic) implicitly creates the topic with
default partitioning and replication.
```

"A metadata **or produce** request … implicitly creates it" is imprecise — `ProduceRequest` does not itself auto-create; creation is triggered by the underlying `MetadataRequest` the producer/consumer issues on first access.

### Remediation

Set `auto.create.topics.enable=false` on all brokers and provision topics explicitly via `AdminClient`/`CreateTopics` with reviewed partition counts and replication factors. Grant `CREATE` on the CLUSTER or TOPIC resource only to the provisioning principal (matches the documented Cluster-then-Topic check order).

> **Update Mode is read-only.** This **cannot** be changed via `incrementalAlterConfigs`/AdminClient — it requires editing `server.properties` on **every broker plus a rolling restart**. An implementer who attempts a dynamic `AlterConfigs` gets `INVALID_CONFIG`.

### False positives & how to avoid them

- Fires on **100% of stock self-managed clusters** (true is the shipped default). Defensible for a posture scanner but guarantees high volume — the **low base severity is what keeps it from being noise**.
- Deliberate and legitimate on dev/test/sandbox/CI clusters and ephemeral single-broker test harnesses. Most common benign firing.
- Legacy apps that intentionally rely on first-access auto-creation.
- Clusters with no Kafka-level authorizer but full network isolation / mTLS-only service mesh escalate to **high** via the NO_AUTHORIZER pairing despite compensating controls the scanner cannot observe — **the escalated finding should name the compensating-control caveat.**
- **Not** an FP source (so implementers don't chase it): Kafka Streams/Connect internal topics are created via AdminClient, and `__consumer_offsets` is broker-managed — none depend on this flag.
- Managed platforms (Confluent Cloud, MSK, HDInsight) largely ship this `false` and/or block `DescribeConfigs` on BROKER, so the rule mostly no-ops or errors there — provided the UNKNOWN/skip handling lands.

### Source

https://kafka.apache.org/41/configuration/broker-configs/ — verbatim: Description "Enable auto creation of topic on the server.", Type boolean, Default TRUE, Importance high, Update Mode read-only. `num.partitions` and `default.replication.factor` confirmed on the same page.

`DEFAULT_CONFIG`/`STATIC_BROKER_CONFIG` are real `ConfigSource` values (post-KIP-133/KIP-226) — confidence high, but not fetched from a KIP-226 primary; **medium confidence on the enum spelling only**. `is_default => BOOLEAN` in DescribeConfigs responses (KIP-133) confirms configs never explicitly set **are** returned, so a DEFAULT_CONFIG-sourced `true` is observable. "Update Mode: read-only" constrains **writes** only and does not impair the read.

---

## KAFKA.TOPIC.RETENTION_UNBOUNDED

**Severity:** low (arguably info — do not let the GDPR framing pull this upward)
**Kinds:** `topic`
**Title:** Topic retains data indefinitely (`retention.ms=-1`)
**Confidence:** medium
**FP risk:** medium

### Check

`listTopics()` then `describeConfigs(ConfigResource(TOPIC, "<topic>"))` — read-only, requires DESCRIBE on the topic and DESCRIBE_CONFIGS on the topic (or Cluster). `describeConfigs` returns **effective** values including defaults, distinguishable via `isDefault()`/`source()`. Supported on brokers 0.11.0.0+.

Read `cleanup.policy`, `retention.ms`, `retention.bytes`, and (if present) `remote.storage.enable` / `local.retention.ms`.

**FAIL only if:**

```
cleanup.policy contains "delete"
  AND effective retention.ms == -1
  AND effective retention.bytes == -1
```

> 🚫 **The `retention.bytes` conjunct is mandatory — without it the evidence claim is factually false for a legitimate config.** `retention.bytes` "controls the maximum size a partition … can grow to before we will discard old log segments … if we are using the 'delete' retention policy" (default `-1`). A topic with `cleanup.policy=delete, retention.ms=-1, retention.bytes=536870912` **is bounded** — segments are aged out by size. Claiming "records are never aged out … no expiry bound" is simply **wrong** for that topic.

If `retention.ms == -1` but `retention.bytes > 0`: either PASS, or emit a **distinct, lower-signal** finding ("time-unbounded, size-capped at N bytes"). **Do not reuse the "indefinitely" wording.**

**Broker fallback (mis-stated in the original):** precedence is `log.retention.ms` > `log.retention.minutes` > `log.retention.hours` (default 168h/7d, explicitly "tertiary to log.retention.ms property"). `log.retention.ms` itself accepts `-1` — a broker with `log.retention.ms=-1` makes **every** delete-policy topic infinite with no topic-level override. `describeConfigs` on the TOPIC resource already returns the **resolved effective value** — read that rather than reconstructing the chain.

**Compaction:** topics with `cleanup.policy=compact` retain the latest value per key **by design** — evaluate them separately, do not flag here.

**Tiered storage:** read `remote.storage.enable` and `local.retention.ms`. `remote.storage.enable=true` with `retention.ms=-1` is an **explicitly intended "infinite retention" architecture**, with `local.retention.ms` bounding broker-local disk. When tiering is on, the disk-exhaustion rationale evaporates and only the data-minimisation rationale survives — the evidence **must say so** rather than implying unbounded local disk growth.

**Split out the 90-day ceiling.** `retention.ms == -1` is a spec-grounded, objective condition. "> 90 days" (7776000000 ms — arithmetic checks out) is an **arbitrary organisational policy** with no basis in the Kafka spec and will fire on plenty of legitimate long-retention topics. Make it a **separate opt-in rule** (or a configurable threshold, default disabled) so the core `-1` check stays low-noise.

### Evidence claim

```
Topic <name>: cleanup.policy=delete with retention.ms=-1 and retention.bytes=-1
(source=<actual ConfigEntry.source() value>); records are never aged out by time or size,
so the topic accumulates data indefinitely with no expiry bound.
```

**Do not hardcode `DYNAMIC_TOPIC_CONFIG`.** It is a real constant, but if `retention.ms=-1` is inherited from a broker the source will be `STATIC_BROKER_CONFIG` or `DEFAULT_CONFIG`. Emit the actual `ConfigEntry.source()` and report `retention.bytes` alongside it.

### Remediation

Set an explicit `retention.ms` aligned to the data's retention policy via `AlterConfigs` on the TOPIC resource. For topics carrying regulated or personal data, retention must be bounded to satisfy data-minimisation and deletion obligations.

Where per-key deletion is required, the mechanism is **compaction + tombstones**; `cleanup.policy=compact,delete` is a valid combination (it is a comma-separated list; see KIP-71) paired with a retention bound. The knob that matters is **`delete.retention.ms`** — how long tombstones remain visible to consumers. Note that adding `delete` to `compact` **forfeits the compact-only guarantee** of retaining at least one record per key.

### False positives & how to avoid them

- Size-capped topics — eliminated by the `retention.bytes` conjunct.
- Tiered-storage topics — flag separately with corrected rationale.
- Long-retention-by-design topics — keep the 90-day ceiling as an opt-in rule.

**Severity rationale:** this is a data-minimisation / capacity-hygiene finding, not an exploitable vulnerability. No confidentiality/integrity impact, no attacker primitive.

### Sources

- **https://kafka.apache.org/41/configuration/topic-configs/** — the primary source. `retention.ms`: "This configuration controls the maximum time we will retain a log before we will discard old log segments to free up space if we are using the 'delete' retention policy." / "If set to -1, no time limit is applied." (default 604800000). `cleanup.policy`: valid values `[compact, delete]`, default `delete`. `retention.bytes` default `-1`.
- https://kafka.apache.org/41/configuration/broker-configs/ — **secondary only**, for the `log.retention.*` fallback chain. This page does **not** document `retention.ms` or `cleanup.policy` at all; it only cross-references topic configs. Citing it as the primary source is a defect.
- https://kafka.apache.org/41/operations/tiered-storage/
- https://kafka.apache.org/41/javadoc/org/apache/kafka/clients/admin/ConfigEntry.ConfigSource.html

---

## KAFKA.QUOTA.NO_LIMITS_DEFINED

**Severity:** low
**Kinds:** `broker`, `user`
**Title:** No client quotas defined — any client can monopolise broker resources
**Confidence:** medium
**FP risk:** high

### Check

**Guard 1 — `client.quota.callback.class` (the dominant FP; the rule has no defence without it).** Before evaluating emptiness, `describeConfigs(ConfigResource(BROKER, "<id>"))` and read `client.quota.callback.class` (read-only, needs `DescribeConfigs` on Cluster). **If a non-default callback is set, SKIP the rule** (or emit info-only). Per the Strimzi plugin README: "Only one quota plugin can be used in Kafka. Enabling this plugin, the built-in Kafka quotas plugin will be automatically disabled." Such plugins enforce limits from broker statics (`client.quota.callback.static.produce`/`.fetch`/`.request`), so `describeClientQuotas` returns an **empty map while quotas are strictly enforced**. Affects **Strimzi / Red Hat Streams for Apache Kafka** (a very common K8s deployment) and Confluent Cloud's multi-tenant callback. Without this guard the rule cleanly false-FAILs an entire deployment class.

**Guard 2 — error handling. "Cannot observe" must never be coerced into "not configured."** `describeClientQuotas` requires `Describe` on Cluster (KIP-546) and is only supported on brokers **≥ 2.6.0**. Three distinct outcomes:

| Outcome | Result |
| --- | --- |
| `ClusterAuthorizationException` | SKIP/ERROR — "insufficient ACL to evaluate". **Never FAIL.** |
| `UnsupportedVersionException` (brokers < 2.6.0) | SKIP — "API unavailable". **Never FAIL.** |
| Genuine empty map | FAIL |

Reporting the first two as "0 quota entities defined" is a **fabricated evidence string**.

**Main check:** `describeClientQuotas(ClientQuotaFilter.all())`. FAIL if the returned map is empty — i.e. no entity (user, client-id, or user+client-id) has any of `producer_byte_rate`, `consumer_byte_rate`, or `request_percentage` configured. Kafka quotas are unlimited by default.

> 🚫 **Deleted clause:** ~~"Also check `describe_configs` on BROKER for the deprecated static `quota.producer.default`/`quota.consumer.default` fallbacks."~~ These were deprecated in 0.11.0.0 and **removed in Kafka 3.0** via KAFKA-12591 (PR #10427, merged 2021-04-09). They **cannot** be returned by `describeConfigs` on 3.0+/4.x. The clause is dead code and misleads maintainers into thinking a fallback path exists. (Static quotas never supported request quotas at all.)

**Multi-tenancy precondition:** the "weight higher on multi-tenant clusters" heuristic is advisory prose, not a gating condition. Single-tenant clusters where one trusted app owns the whole broker legitimately run without quotas. Make the multi-tenant signal (**distinct principals from `describeAcls`**) an actual precondition for emitting, or accept the finding is **info-grade noise** there.

### Evidence claim

```
describe_client_quotas(ClientQuotaFilter.all()) returned 0 quota entities; no
producer_byte_rate, consumer_byte_rate, or request_percentage limit is enforced for any
user or client-id, so a single client can saturate broker network and I/O capacity.
```

The tail ("so a single client can saturate…") is an **inference, not an observation** — it is only true once guards 1 and 2 have passed.

### Remediation

Define default and per-principal quotas via `AlterClientQuotas` — set `producer_byte_rate` and `consumer_byte_rate` (bytes/sec) for bandwidth and `request_percentage` for CPU (percent out of `((num.io.threads + num.network.threads) * 100)%`). Apply a restrictive `<default>` entity quota and grant higher per-user quotas explicitly.

### False positives & how to avoid them

- **Quota callback plugins** (Strimzi, Confluent Cloud) — guard 1. This is the big one.
- **Under-privileged scanner / old brokers** — guard 2.
- **Single-tenant clusters** — multi-tenancy precondition.
- **Flagged but NOT verified:** managed services (Confluent Cloud / MSK / Aiven) may enforce ingress/egress at the platform tier outside client-quota entities. Plausible additional FP class, but the GCP Managed Kafka page fetched did not confirm platform limits independent of client quotas — **low confidence; verify before encoding a guard.**

### Sources

The originally-claimed https://docs.confluent.io/kafka/design/quotas.html exists and covers quotas generally (three entity types; bandwidth quotas 0.9+; request-rate quotas 0.11+; config precedence hierarchy) but contains **none of the three key names**, does **not** state quotas are unlimited by default, and never mentions the static configs. Keep it only as background for the entity-type/precedence model. Cite instead:

- https://docs.cloudera.com/runtime/7.3.2/kafka-configuring/topics/kafka-config-quotas.html — verbatim "By default, each client receives an unlimited quota"; defines all three keys; defines `request_percentage`.
- https://kafka.apache.org/40/javadoc/org/apache/kafka/common/quota/ClientQuotaFilter.html — `ClientQuotaFilter.all()` "Constructs and returns a quota filter that matches all configured entities."
- https://cwiki.apache.org/confluence/display/KAFKA/KIP-546:+Add+Client+Quota+APIs+to+the+Admin+Client — read-only, Describe on Cluster, brokers 2.6.0+.
- https://github.com/apache/kafka/pull/10427 — removal of the static quota configs.

---

# Durability & integrity rules

> Report this class **separately** from access-control findings so they do not dilute the security signal.

## KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE

**Severity:** medium (top of its range; `low` is defensible if this rulepack is strictly security-scoped)
**Kinds:** `topic`, `broker`
**Title:** `min.insync.replicas=1` on a replicated topic — acks=all silently degrades to single-copy durability when the ISR shrinks
**FP risk:** medium

### Check

`listTopics()` → `describeTopics(names)` for replication factor per partition, and `describeConfigs(ConfigResource(TOPIC, "<topic>"))` for the effective `min.insync.replicas` (topic override, else **cluster-level / static broker default**; Kafka default is `1`).

`describeConfigs` on the TOPIC resource **already returns the effective inherited value** — no separate broker-config read is needed.

**FAIL if `replicationFactor >= 3` AND effective `min.insync.replicas == 1`.**

**Gap (optional):** the `>= 3` gate misses `RF=2 + misr=1`, which has the identical defect. Consider `replicationFactor >= 2`.

**Version drift:** with ELR (KIP-966) enabled by default on new clusters from 4.1, `min.insync.replicas` is maintained as a **cluster-level** config, the previously-set broker-level value is removed, and broker-level alteration is not allowed. Do not describe the fallback as "broker default."

> 🚫 **The original mechanism was factually wrong and contradicted by its own cited source.** The claim "a producer using acks=all is satisfied by the leader alone" is **false**. Per the Kafka docs (`min.insync.replicas`): with acks=all "every in-sync replica must acknowledge a write for it to be considered successful" and "if a topic has replication.factor of 3 and the ISR set includes all three replicas, then all three replicas must acknowledge an acks=all write for it to succeed, **even if min.insync.replicas happens to be less than 3**."
>
> `min.insync.replicas` is a **floor on ISR size** gating whether the write is accepted at all (below it the producer gets `NotEnoughReplicas` / `NotEnoughReplicasAfterAppend`) — it is **not** the number of acks required.
>
> **Correct mechanism:** with `min.insync.replicas=1`, once the ISR has shrunk to the leader alone, the leader keeps accepting acks=all writes and acknowledges them with **only a single copy on disk**; if that leader then fails before followers catch up, those acknowledged records are lost. **The ISR-shrink precondition is required** — in a healthy RF=3 / ISR=3 topic, acks=all still waits for all three.

### Evidence claim

```
Topic <name>: replication.factor=<rf> but effective min.insync.replicas=1 (source=<actual>).
If the ISR shrinks to the leader alone, acks=all writes are still accepted and acknowledged
from a single replica; those acknowledged records are lost if the leader then fails.
```

Do **not** title or word this as "acks=all provides no real durability" — durability is normal while the ISR is healthy.

Source enum must be the full set: `DYNAMIC_TOPIC_CONFIG`, `DYNAMIC_BROKER_CONFIG`, `DYNAMIC_DEFAULT_BROKER_CONFIG`, `STATIC_BROKER_CONFIG`, `DEFAULT_CONFIG`. A topic inheriting the value reports `STATIC_BROKER_CONFIG` or `DYNAMIC_DEFAULT_BROKER_CONFIG`, not only `DEFAULT_CONFIG`/`DYNAMIC_TOPIC_CONFIG`.

### Remediation

Set `min.insync.replicas=2` for replication factor 3 (the standard quorum: tolerates one broker loss while keeping writes available) via `AlterConfigs` on the TOPIC resource, and ensure producers use `acks=all`. Setting `min.insync.replicas` **equal to** the replication factor makes the topic unavailable for writes on any single broker loss.

### False positives & how to avoid them

- **The rule cannot observe producer `acks` via AdminClient.** On topics where no producer uses acks=all the finding is vacuous and its impact unconfirmable read-only — **state this limitation in the finding** rather than asserting loss.
- Suppress or downgrade for topics that **intentionally** trade durability for write availability (metrics/telemetry/log/cache-invalidation), where RF=3 + misr=1 is a deliberate choice to survive rolling restarts and 2-broker loss.
- `__consumer_offsets` has RF default 3 and inherits misr=1, so this fires on **essentially every out-of-the-box cluster** — allowlist internal topics or flag them under a separate lower-noise finding.
- `__transaction_state` correctly will **not** fire (uses `transaction.state.log.min.isr`, default 2).

**Severity rationale:** reliability/durability with no security impact; realized loss requires a compound condition (producers on acks=all AND ISR degraded to the leader AND leader failure before catch-up). Retained at medium because the blast radius is **silent loss of records the producer was told were committed**, and misr=2 on RF=3 is standard industry hardening guidance.

### Sources

- https://kafka.apache.org/41/configuration/broker-configs/ and https://kafka.apache.org/41/configuration/topic-configs/ — key name, default 1, type int, valid values [1,…], topic-level and cluster-level applicability
- https://kafka.apache.org/42/operations/eligible-leader-replicas/ — ELR / cluster-level maintenance
- https://blog.2minutestreaming.com/p/kafka-acks-min-insync-replicas-explained — independent confirmation of the mechanism: "If you have three in-sync replicas, acks=all and min.insync.replicas=1, is it true the broker won't wait for the other two replicas before replying? No. It will wait for all the in-sync replicas."

---

## KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION

**Severity:** medium (defensible, not inflated — keep)
**Kinds:** `broker`, `topic`
**Title:** `unclean.leader.election.enable=true` permits silent committed-data loss
**FP risk:** low

### Check

> 🚫 **`ConfigResource(BROKER, "<broker id>")` is the wrong resource for KRaft.** Per apache/kafka PR #16866 (KAFKA-12670, fixed 3.9.0), KRaft resolves the effective value as:
> **dynamic topic config → dynamic node config → dynamic cluster config → the CONTROLLER's static configuration.**
> **Broker static config is NOT consulted.** Kafka 4.x is KRaft-only, so reading the broker id and reporting `source=STATIC_BROKER_CONFIG` can report an **inert value**.

Correct procedure:

1. `describeConfigs(ConfigResource(BROKER, ""))` for the **cluster-wide dynamic default**. The docs list update-mode = "cluster-wide", so the empty name **is** the correct resource here — this is the one rule that inverts the general invariant.
2. `describeConfigs(ConfigResource(TOPIC, "<topic>"))` for per-topic overrides.
3. For the static fallback, describe **controller** nodes via an AdminClient configured with `bootstrap.controllers` — a broker-bootstrapped client **cannot** see the controller's static config. If unavailable to the scanner, report the finding as **partial/indeterminate** rather than asserting the effective value.

**FAIL if the effective `unclean.leader.election.enable` == `true`.** Kafka default is `false`.

**Suppress when `replication.factor=1`** — with a single replica there is no out-of-sync replica to promote, so the config has no durability effect. Firing here is noise (common in dev/single-broker clusters).

**ELR context (mitigates, does not void):** Eligible Leader Replicas (KIP-966 Part 1) is enabled by default on new clusters from 4.1; election order is ISR → ELR (unfenced) → last known leader if unfenced. ELR reduces how often the unclean path is reached but does **not** make `true` safe — with ISR and ELR both empty, an out-of-sync replica can still be promoted.

> ⚠️ **Low confidence:** the frequently-quoted sentence "when ELR is enabled the semantics of the unclean leader election configuration changes" could **not** be verified verbatim in primary 4.1 docs (the ELR operations page does not contain it). **Do not cite that claim** without a verbatim primary source.

> 🚫 **Do not reference `unclean.recovery.strategy`.** A check of the full 4.1 broker config list confirms `unclean.leader.election.enable` is the **only** config containing "unclean". `unclean.recovery.strategy` is unshipped KIP-966 Part 2 proposal text; secondary sources and search summaries wrongly present it as shipped 4.1 behaviour. Keep it out of the rule and remediation.

**Optional precision:** scope the "committed and acknowledged" wording to **acks=all** — with acks=1/acks=0 records can be lost regardless of this setting, so the integrity framing is strongest for acks=all producers. Also note KAFKA-19552 (dynamic config precedence over topic-level static) as a known resolution edge case.

### Evidence claim

```
<Broker <id>|Topic <name>>: unclean.leader.election.enable=true (source=<STATIC_BROKER_CONFIG|
DYNAMIC_BROKER_CONFIG|DYNAMIC_DEFAULT_BROKER_CONFIG|DYNAMIC_TOPIC_CONFIG>), overriding the
default false; an out-of-sync replica can be promoted to leader and discard committed records.
```

The source enum must include `DYNAMIC_DEFAULT_BROKER_CONFIG` — given update-mode=cluster-wide, that is the **normal** path and the original template omitted it.

**Distinct, lower-severity finding — stale broker static:** if `true` appears **only** in a broker's static config (`source=STATIC_BROKER_CONFIG`) while cluster/topic/controller resolution yields `false`, the data loss **cannot occur**. This is the main false-positive path and is plausible in ZK→KRaft-migrated clusters (ZK mode honored broker static config; KRaft does not). Report as **informational config hygiene, not a durability FAIL.**

### Remediation

Set `unclean.leader.election.enable=false` at the cluster level and remove any topic-level override, accepting partition unavailability over data loss. If a specific topic genuinely prefers availability (e.g. reconstructible metrics), document the override and pair it with an explicit data-loss runbook.

### False positives & how to avoid them

- Stale broker-static value in a KRaft cluster — the dominant FP; report as hygiene.
- `replication.factor=1` topics — suppress.

**Severity rationale:** Kafka rates importance "high" and the loss is of committed/acked records, but it requires a coincident ISR-empty failure and is an explicit **non-default opt-in**. Keep medium.

### Sources

- https://kafka.apache.org/41/configuration/broker-configs/ — verbatim: "Indicates whether to enable replicas not in the ISR set to be elected as leader as a last resort, even though doing so may result in data loss"; default false; importance high; update-mode cluster-wide
- https://kafka.apache.org/41/configuration/topic-configs/ — topic-level override
- https://github.com/apache/kafka/pull/16866 — KRaft resolution order
- 4.1 `ConfigEntry.ConfigSource` javadoc — the real constant set

---

# Legacy mode

## KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES

**Severity:** medium (do not raise to high without network evidence; do not drop to low — ZK mode is EOL and the write-exposure is real when ZK is reachable)
**Kinds:** `broker`
**Title:** Cluster runs legacy ZooKeeper mode with unauthenticated / world-**writable** znodes
**Confidence:** medium
**FP risk:** medium

### Check

`describeConfigs(ConfigResource(BROKER, "<broker id>"))`. `DescribeConfigs` on a BROKER resource returns static broker configs with `config_source=STATIC_BROKER_CONFIG`/`DEFAULT_CONFIG` and `read_only=true` (KIP-226 synonyms/sources; KIP-524). None of these four keys are sensitive-typed, so values are returned rather than nulled. Requires only `DESCRIBE_CONFIGS` on CLUSTER or BROKER — genuinely read-only.

**Mode determination:** the cluster is in ZooKeeper mode if `process.roles` is absent/empty **AND** `zookeeper.connect` has a **non-null, non-empty VALUE**.

> ⚠️ **Implement `zookeeper.connect is present` as a value test, not a key-existence test.** In Kafka 3.x KRaft mode the key is **still in the DescribeConfigs response with a null value** — a key-existence test fires on **every 3.x KRaft broker**.

ZK mode is only possible on Kafka < 4.0 (ZooKeeper fully removed in 4.0, released 2025-03-18).

**Also read `zookeeper.metadata.migration.enable`:** ZK-mode brokers **mid-migration** match the predicate and would be mislabeled "legacy". Distinguish migrating from stale-legacy.

**Split the two arms — do not OR them into one finding.** The original is an OR of two conditions but the evidence describes only the `set.acl` arm; a cluster with `set.acl=true` but `ssl.client.enable=false` fires and emits a **false statement**.

| Arm | Condition | Notes |
| --- | --- | --- |
| A | `zookeeper.set.acl` != `true` (default `false`) | znodes created without secure ACLs |
| B | `zookeeper.ssl.client.enable` != `true` (default `false`, KIP-515) | plaintext ZK client connection |

Report `zookeeper.connect` endpoints as an exposure surface.

**Cannot verify from the Admin API whether the ZooKeeper port itself is network-reachable** — that requires host/network inspection. This disclaimer is correct and must stay.

### Evidence claim

> 🚫 **"World-readable" is backwards and must not be used.** The official docs describe the **SECURED** state as: "The metadata stored in ZooKeeper for the Kafka cluster is world-readable, but can only be modified by the brokers." Kafka metadata znodes remain **world-readable even with `zookeeper.set.acl=true`**. World-readability is therefore **not the defect** and is not fixed by the remediation.

Arm A:

```
Broker <id>: process.roles is unset and zookeeper.connect=<endpoints>;
zookeeper.set.acl=<false|unset>, so Kafka metadata znodes are created without secure ACLs —
any client that can reach ZooKeeper may modify cluster metadata, and sensitive znodes
(SCRAM credentials, delegation tokens) are not restricted to brokers.
```

The actual impact of `set.acl=false` is that znodes are **world-WRITABLE** (any ZK client can modify Kafka metadata) and that sensitive znodes such as SCRAM credentials / delegation tokens — which `set.acl=true` restricts to brokers only — are readable.

Arm B needs its own evidence string describing the plaintext ZK client connection.

### Remediation

Migrate to KRaft (`process.roles`, `controller.quorum.bootstrap.servers`) and upgrade to a 4.x release. **Direct upgrade from ZooKeeper mode to 4.0 is not supported** — migrate to KRaft on a 3.x release first (3.9 is the bridge).

Until then, **order matters** — `zookeeper.set.acl=true` is a **no-op unless ZK SASL (or mTLS) auth is configured first**:

1. Enable ZooKeeper client authentication (SASL or mTLS).
2. Set `zookeeper.set.acl=true`.
3. Run `bin/zookeeper-security-migration.sh` (the `ZkSecurityMigrator` tool) to re-ACL existing znodes.
4. Enable `zookeeper.ssl.client.enable=true`.
5. Restrict the ZooKeeper port to broker hosts only.

Clusters **mid-migration on 3.5.0–3.6.1** are also exposed to **CVE-2024-27309** (incorrect access control during ZooKeeper-to-KRaft migration; fixed in 3.6.2).

### False positives & how to avoid them

Why FP risk is medium, not low:

- **Arm B reports false when TLS-to-ZK was enabled via `-Dzookeeper.client.secure=true`**, which DescribeConfigs cannot see. Per KIP-515, "An explicit value overrides any value set via the `zookeeper.client.secure` system property (note the different name)" — so the Kafka config may be unset while ZK TLS is on. **Genuine FP.**
- **Arm B fires on essentially 100% of ZK-mode clusters** — plaintext ZK on an isolated subnet is the common, frequently deliberate design. Defensible only because ZK mode itself is post-EOL, but this makes the arm near-zero-signal on its own.
- **Managed services** (e.g. Amazon MSK ZK-based clusters) don't expose `zookeeper.set.acl` to customers — fires with no customer-actionable remediation.

### Sources

The claimed https://kafka.apache.org/community/cve-list/ supports **only** the CVE-2024-27309 sentence (verified verbatim: "Potential incorrect access control during migration from ZK mode to KRaft mode", affected 3.5.0–3.6.1, fixed 3.6.2). It says **nothing** about `zookeeper.set.acl`, znode ACLs, or world-readability. Primary sources:

- https://kafka.apache.org/39/security/zookeeper-authentication/
- https://kafka.apache.org/39/configuration/broker-configs/ — `zookeeper.set.acl` ("Set client to use secure ACLs", default false); `zookeeper.ssl.client.enable` (default false, KIP-515); `zookeeper.connect` (default null); `process.roles` (default `""`)
- https://kafka.apache.org/40/getting-started/upgrade/ — no direct ZK-mode → 4.0 upgrade
- https://kafka.apache.org/community/cve-list/ — CVE-2024-27309 only

---

# Implementation notes — what the connector must collect

## Collection sequence

```
1. describeCluster()
   -> cluster_id, controller node, nodes[] (id, host, port, rack)
   -> REQUIRED FIRST: every BROKER ConfigResource needs a concrete id from here.

2. For EACH node id in nodes[]:
     describeConfigs(ConfigResource(BROKER, String.valueOf(id)))
   -> store the full ConfigEntry set: name, value, source, isSensitive, isReadOnly, synonyms
   -> DO NOT collapse across brokers. Per-broker divergence is a finding.

3. describeConfigs(ConfigResource(BROKER, ""))
   -> cluster-wide DYNAMIC defaults only.
   -> Needed ONLY by KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION (update-mode cluster-wide).
   -> Never use as a substitute for step 2.

4. describeAcls(AclBindingFilter.ANY)
   -> capture the outcome, not just the result:
      OK(bindings[]) | SECURITY_DISABLED(54) | CLUSTER_AUTHORIZATION_FAILED | other
   -> SECURITY_DISABLED is a POSITIVE signal for KAFKA.AUTHZ.NO_AUTHORIZER.
   -> CLUSTER_AUTHORIZATION_FAILED => INDETERMINATE for every ACL rule.

5. listTopics(new ListTopicsOptions().listInternal(true))
   -> then describeTopics(names) for partitions[].replicas.size() (replication factor)

6. For EACH topic:
     describeConfigs(ConfigResource(TOPIC, name))
   -> returns EFFECTIVE values incl. inheritance; read source() per entry.

7. describeClientQuotas(ClientQuotaFilter.all())
   -> capture outcome: OK(map) | CLUSTER_AUTHORIZATION_FAILED | UNSUPPORTED_VERSION

8. describeUserScramCredentials()
   -> usernames, mechanism, iterations (cluster-wide)

9. OPTIONAL, KRaft controller static config:
     AdminClient with bootstrap.controllers -> describeConfigs(ConfigResource(BROKER, <controller id>))
   -> required for authoritative unclean.leader.election resolution.
   -> If unavailable, that rule reports PARTIAL/INDETERMINATE.
```

## Broker config keys the connector must capture

Listener / transport:
`listeners`, `advertised.listeners`, `listener.security.protocol.map`, `inter.broker.listener.name`, `security.inter.broker.protocol`, `controller.listener.names`, `process.roles`

Authorization:
`authorizer.class.name`, `super.users`, `allow.everyone.if.no.acl.found`

SASL:
`sasl.enabled.mechanisms`, `listener.name.<lowercase>.sasl.enabled.mechanisms`, `listener.name.<lowercase>.oauthbearer.sasl.server.callback.handler.class`, `sasl.oauthbearer.jwt.validator.class`

TLS:
`ssl.client.auth`, `listener.name.<lowercase>.ssl.client.auth`, `ssl.endpoint.identification.algorithm`, `listener.name.<lowercase>.ssl.endpoint.identification.algorithm`, `ssl.keystore.location`

Topics / quotas / ZK:
`auto.create.topics.enable`, `num.partitions`, `default.replication.factor`, `min.insync.replicas`, `unclean.leader.election.enable`, `log.retention.ms`, `log.retention.minutes`, `log.retention.hours`, `client.quota.callback.class`, `zookeeper.connect`, `zookeeper.set.acl`, `zookeeper.ssl.client.enable`, `zookeeper.metadata.migration.enable`

## Topic config keys

`cleanup.policy`, `retention.ms`, `retention.bytes`, `delete.retention.ms`, `min.insync.replicas`, `unclean.leader.election.enable`, `remote.storage.enable`, `local.retention.ms`

## Verified defaults (do not hardcode from memory — re-verify per target version)

| Key | Default |
| --- | --- |
| `listeners` | `PLAINTEXT://:9092` |
| `listener.security.protocol.map` | identity map `PLAINTEXT:PLAINTEXT,SSL:SSL,SASL_PLAINTEXT:SASL_PLAINTEXT,SASL_SSL:SASL_SSL` (⚠️ confirmed verbatim only in KIP-103) |
| `advertised.listeners` | `null` → falls back to `listeners` |
| `security.inter.broker.protocol` | `PLAINTEXT` |
| `inter.broker.listener.name` | `null` |
| `authorizer.class.name` | **`""`** (empty string; `ServerConfigs.java` `AUTHORIZER_CLASS_NAME_DEFAULT = ""`) — unset means **no authorization at all** |
| `allow.everyone.if.no.acl.found` | `false` in Apache Kafka; **`true` on AWS MSK** |
| `ssl.client.auth` | `none` (`BrokerSecurityConfigs.SSL_CLIENT_AUTH_DEFAULT = SslClientAuth.NONE`) |
| `sasl.enabled.mechanisms` | `GSSAPI` (`DEFAULT_SASL_ENABLED_MECHANISMS = List.of(SaslConfigs.GSSAPI_MECHANISM)`) |
| `ssl.endpoint.identification.algorithm` | `https` (on by default since 2.0.0) |
| `auto.create.topics.enable` | `true` |
| `delete.topic.enable` | `true` |
| `min.insync.replicas` | `1` |
| `unclean.leader.election.enable` | `false` |
| `retention.ms` | `604800000` (7d); `-1` = infinite |
| `retention.bytes` | `-1` |
| `cleanup.policy` | `delete` |
| `log.retention.hours` | `168` |
| `zookeeper.set.acl` | `false` |
| `zookeeper.ssl.client.enable` | `false` |
| client quotas | unlimited |

## Outcome model — three states, never two

Every rule must emit one of `PASS` / `FAIL` / `INDETERMINATE` / `NOT_APPLICABLE` / `NOT_ASSESSED`. Coercing an unobservable state into PASS is the single most dangerous failure mode in this rulepack:

- `ClusterAuthorizationException` on `describeConfigs`/`describeAcls`/`describeClientQuotas` → **INDETERMINATE**
- `SecurityDisabledException` on `describeAcls` → **FAIL for `KAFKA.AUTHZ.NO_AUTHORIZER`; INDETERMINATE for every other ACL rule**
- `UnsupportedVersionException` → **NOT_APPLICABLE**
- Broker-level `DescribeConfigs` denied (Confluent Cloud, MSK Serverless, Azure Event Hubs, Redpanda, WarpStream) → **NOT_APPLICABLE** for broker-config rules
- Null value on a listener-prefixed key whose listener name contains a dot (`LISTENER_CONFIG_REGEX` `[^.]*` fails to resolve) → **INDETERMINATE**, not "absent"
- JMX exposure, patch-level CVE state → **NOT_ASSESSED**

## Suppression / exception model

The connector must support **per-listener** and **per-binding** suppressions with a typed reason, because these states are indistinguishable from broker configs alone:

- `encrypted-by-external-transport` — service-mesh mTLS (Istio/Linkerd), sidecar, TLS-terminating LB/proxy, IPsec/WireGuard underlay
- `loopback-bound` — admin/health-check listener (also auto-derivable by parsing the host in `listeners`)
- `operator-principal` — allowlist for MirrorMaker 2, Connect, Cruise Control, Schema Registry, lag exporters, Strimzi/Confluent/MSK-provisioned bindings
- `intentional-availability-tradeoff` — durability rules on metrics/telemetry/cache topics
- `risk-accepted` — private-network PLAINTEXT, dev/test clusters

## Correlation pass (run after all rules evaluate)

```
if PLAINTEXT_or_SASL_PLAINTEXT_client_listener AND (NO_AUTHORIZER OR ALLOW_EVERYONE):
    escalate both to CRITICAL  # fully open cluster
if AUTO_CREATE_ENABLED AND (NO_AUTHORIZER OR ALLOW_EVERYONE):
    escalate AUTO_CREATE to HIGH, annotate "compensating network controls not observable"
if ACL_ANONYMOUS_PRINCIPAL AND no listener yields User:ANONYMOUS:
    downgrade to MEDIUM (latent)
if ACL_WILDCARD_* AND overlapping DENY binding exists:
    downgrade one tier, annotate
if ACL_WILDCARD_RESOURCE_ALL AND principal in super.users:
    reclassify as INFO "dead config — cleanup"
if SSL_CLIENT_AUTH_NOT_REQUIRED AND authorizer set AND no ANONYMOUS ACL AND allow_everyone=false:
    downgrade to MEDIUM/LOW, annotate "ANONYMOUS provably denied"
```

## Known primary-source verification traps

- **WebFetch summarizers return wrong answers on `ConfigHelper.scala`** — twice claimed `originals` are excluded. Verify with `curl` + `grep` on raw source.
- **`server/.../ServerConfigs.java` 404s** — the real path is `server-common/src/main/java/org/apache/kafka/server/config/ServerConfigs.java`. Greps against the wrong path silently return nothing (empty result ≠ absent).
- **The legacy `/documentation#security` anchors are JS redirect stubs** and cannot be fetched. Use the versioned per-section URLs (`/41/security/*`).
- **The 4.1 generated-config page truncates on fetch** — the `listener.security.protocol.map` default could not be re-confirmed there.
- **`unclean.recovery.strategy` does not exist in 4.1.** Secondary sources present unshipped KIP-966 Part 2 text as shipped.
- **KIP-487 (client-side auto topic creation) and KIP-755 (AUTO_CREATE ACL) are both "Under Discussion", not shipped.** Do not encode deprecation or new ACL operations from them.

## CVE cross-references (all from https://kafka.apache.org/community/cve-list/)

| CVE | Affects | Fixed | Relevance |
| --- | --- | --- | --- |
| CVE-2024-56128 | 0.10.2.0–3.7.1, 3.8.0 | 3.7.2 / 3.8.1 / 3.9.0 | SCRAM replay via missing RFC 5802 nonce verification. **Exploitable only without TLS** — makes `KAFKA.SASL.SCRAM_WITHOUT_TLS` CVE-backed, not just best practice. |
| CVE-2026-33557 | 4.1.0–4.1.1 | 4.1.2 / 4.2.0 | Missing JWT validation in OAUTHBEARER. Reinforces the OAUTHBEARER rule; notable for hitting recent releases. |
| CVE-2025-27819 | ≤ 3.9.0 | 3.9.1 / 4.0.0 | JndiLoginModule RCE/DoS via `sasl.jaas.config`. **Payload undetectable read-only** (config redacted); only the ALTER_CONFIGS ACL precondition is checkable. |
| CVE-2025-27818 | ≤ 3.9.0 | 3.9.1 / 4.0.0 | LdapLoginModule, same class. |
| CVE-2023-25194 | < 3.4.0 | 3.4.0 | Same class via Kafka Connect; 3.4.0 introduced the `-Dorg.apache.kafka.disallowed.login.modules` guard. |
| CVE-2026-41115 | 4.0.0–4.3.0 | **none listed as of 2026-07-17** | Improper authorization in CONSUMER_GROUP_DESCRIBE. **Treat as open and monitor.** |
| CVE-2024-27309 | 3.5.0–3.6.1 | 3.6.2 | Incorrect access control during ZK→KRaft migration. |
| CVE-2022-34917 | 2.8.0–3.2.1 | — | Unauthenticated clients trigger broker OOM. Additional argument for never exposing PLAINTEXT listeners. |

**Version detection is the blocker for all of these.** AdminClient exposes no broker version string; `describeFeatures()` resolves only to a release range. Every version-based CVE rule needs an out-of-band version source (deployment manifest, package inventory, MSK/Confluent control-plane API).
