"""AWS rulepack — config-time posture over what connect/aws.py collected.

Every rule reads REAL configuration evidence (the resource policy JSON, the MSK
ClientAuthentication block, the route's authorizationType) and cites it in the observation;
none of them guesses from names or tags. Rules run on the DISTINCT aws_* kinds the connector
emits, so they never collide with the Kafka/Kong/RabbitMQ/Redis packs.

Severity conventions (house):
  critical  anyone on the internet gets in (public policy with no Condition)
  high      plaintext transport, unauthenticated cluster access, wildcard actions, no-auth route
  medium    encryption at rest off, api-key-as-auth, cross-account trust to verify
  low       hygiene / observability (logging off, no WAF, no DLQ, DEFAULT monitoring)
  info      ranking hints and coverage notes

The third outcome is used throughout: attributes the connector recorded as unreadable, and
whole services that answered AccessDenied, become assessable=False coverage gaps — never a
clean pass, never a fabricated failure.
"""
from ..connect.aws import (arn_account, has_wildcard_action, is_public_statement,
                           policy_statements, principal_entries, statement_actions)
from ..contracts import Hit
from ..registry import detector


# ── shared: policy rules are the same shape for SQS / SNS / EventBridge ──────
def _attrs_gap(r, api_call: str) -> list:
    """The per-resource not-assessable Hit when the attribute call itself was denied."""
    return [Hit(
        observation=f"{api_call} was denied for '{r.name}', so its policy and encryption "
                    f"configuration could not be read",
        remediation=f"Grant the scan role {api_call} (covered by the SecurityAudit managed "
                    f"policy) so this resource's posture can be assessed.",
        detail=f"attributes_readable=False region={(r.raw or {}).get('region')}",
        assessable=False,
        assessment_reason=f"{api_call} returned AccessDenied",
        source_ref={"api": api_call},
    )]


def _public_policy_hits(r, service: str, remediation: str) -> list:
    """One Hit per Allow statement with Principal '*' and no Condition."""
    hits = []
    for i, stmt in enumerate(policy_statements((r.raw or {}).get("policy"))):
        if not is_public_statement(stmt):
            continue
        hits.append(Hit(
            observation=(f"{service} resource policy on '{r.name}' statement "
                         f"{stmt.get('Sid') or f'#{i}'} allows Principal \"*\" with actions "
                         f"{statement_actions(stmt)!r} and NO Condition — any AWS principal, "
                         f"in any account, can call it"),
            remediation=remediation,
            detail=f"sid={stmt.get('Sid')} actions={statement_actions(stmt)} condition=absent",
            source_ref={"policy_sid": stmt.get("Sid"), "statement_index": i},
        ))
    return hits


def _wildcard_action_hits(r, service: str, prefix: str, remediation: str) -> list:
    """One Hit per Allow statement whose Action is '*' or '<service>:*'. Fires alongside the
    public rule when a statement is both — two distinct defects, two distinct findings."""
    hits = []
    for i, stmt in enumerate(policy_statements((r.raw or {}).get("policy"))):
        if str(stmt.get("Effect", "")).lower() != "allow" or not has_wildcard_action(stmt):
            continue
        wild = [a for a in statement_actions(stmt) if a == "*" or a.endswith(":*")]
        hits.append(Hit(
            observation=(f"{service} resource policy on '{r.name}' statement "
                         f"{stmt.get('Sid') or f'#{i}'} allows wildcard action(s) {wild!r} to "
                         f"principal(s) {principal_entries(stmt)!r} — every {prefix}:* "
                         f"operation, including the destructive and permission-changing ones"),
            remediation=remediation,
            detail=f"sid={stmt.get('Sid')} actions={statement_actions(stmt)}",
            source_ref={"policy_sid": stmt.get("Sid"), "statement_index": i},
        ))
    return hits


# ══ SQS ═══════════════════════════════════════════════════════════════════════
@detector(kinds=["aws_sqs_queue"], rule_id="AWS.SQS.QUEUE_POLICY_PUBLIC", severity="critical",
          title="SQS queue policy grants access to any AWS principal")
def sqs_policy_public(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("attributes_readable", True):
        return _attrs_gap(r, "sqs:GetQueueAttributes")
    return _public_policy_hits(
        r, "SQS",
        remediation=("Scope the statement to a Principal or add a Condition, e.g. "
                     "`aws sqs set-queue-attributes --queue-url <url> --attributes "
                     "'{\"Policy\":\"...\"}'` with \"Condition\":{\"ArnEquals\":"
                     "{\"aws:SourceArn\":\"arn:aws:sns:...:my-topic\"}}. Terraform: restrict "
                     "`aws_sqs_queue_policy` principals — never `\"Principal\": \"*\"` bare."))


@detector(kinds=["aws_sqs_queue"], rule_id="AWS.SQS.POLICY_WILDCARD_ACTION", severity="high",
          title="SQS queue policy allows wildcard actions")
def sqs_policy_wildcard_action(r, ctx) -> list:
    if not (r.raw or {}).get("attributes_readable", True):
        return []   # the coverage gap is already filed by AWS.SQS.QUEUE_POLICY_PUBLIC
    return _wildcard_action_hits(
        r, "SQS", "sqs",
        remediation=("List the operations actually needed (usually sqs:SendMessage or "
                     "sqs:ReceiveMessage) instead of `sqs:*` — the wildcard includes "
                     "sqs:DeleteQueue, sqs:PurgeQueue and sqs:SetQueueAttributes, letting a "
                     "sender rewrite the policy that admits it. Fix via `aws sqs "
                     "set-queue-attributes` or the `aws_sqs_queue_policy` Terraform resource."))


@detector(kinds=["aws_sqs_queue"], rule_id="AWS.SQS.ENCRYPTION_AT_REST_OFF", severity="medium",
          title="SQS queue has no server-side encryption")
def sqs_encryption_off(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("attributes_readable", True):
        return _attrs_gap(r, "sqs:GetQueueAttributes")
    if raw.get("kms_master_key_id") or raw.get("sqs_managed_sse_enabled") is True:
        return []
    return [Hit(
        observation=(f"SQS queue '{r.name}' has no KmsMasterKeyId and SqsManagedSseEnabled is "
                     f"{raw.get('sqs_managed_sse_enabled')!r} — messages are stored "
                     f"unencrypted at rest"),
        remediation=("Enable SSE-SQS: `aws sqs set-queue-attributes --queue-url <url> "
                     "--attributes SqsManagedSseEnabled=true`, or SSE-KMS with "
                     "KmsMasterKeyId=<key-arn> for CloudTrail-audited key usage. Terraform: "
                     "`sqs_managed_sse_enabled = true` or `kms_master_key_id` on `aws_sqs_queue`."),
        detail=(f"kms_master_key_id={raw.get('kms_master_key_id')} "
                f"sqs_managed_sse_enabled={raw.get('sqs_managed_sse_enabled')}"),
        source_ref={"attributes": ["KmsMasterKeyId", "SqsManagedSseEnabled"]},
    )]


_DLQ_NAME_HINTS = ("dlq", "dead-letter", "deadletter", "dead_letter")


@detector(kinds=["aws_sqs_queue"], rule_id="AWS.SQS.NO_DEAD_LETTER_QUEUE", severity="low",
          title="SQS queue has no dead-letter queue configured")
def sqs_no_dlq(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("attributes_readable", True) or raw.get("redrive_policy"):
        return []
    if any(h in r.name.lower() for h in _DLQ_NAME_HINTS):
        return []   # a DLQ needing its own DLQ is not a defect
    # Ranking hint, not a filter: a queue whose policy admits other principals is an
    # integration boundary where silent message loss hurts most.
    shared = bool(policy_statements(raw.get("policy")))
    return [Hit(
        observation=(f"SQS queue '{r.name}' has no RedrivePolicy — messages that repeatedly "
                     f"fail processing are silently dropped after retention instead of being "
                     f"quarantined for inspection"),
        severity="low" if shared else "info",
        remediation=("Attach a DLQ: `aws sqs set-queue-attributes --queue-url <url> --attributes "
                     "'{\"RedrivePolicy\":\"{\\\"deadLetterTargetArn\\\":\\\"<dlq-arn>\\\","
                     "\\\"maxReceiveCount\\\":\\\"5\\\"}\"}'`. Terraform: `redrive_policy` on "
                     "`aws_sqs_queue`. Poison messages are also a security signal worth keeping."),
        detail=f"redrive_policy=absent has_resource_policy={shared}",
        source_ref={"attributes": ["RedrivePolicy"]},
    )]


# ══ SNS ═══════════════════════════════════════════════════════════════════════
@detector(kinds=["aws_sns_topic"], rule_id="AWS.SNS.TOPIC_POLICY_PUBLIC", severity="critical",
          title="SNS topic policy grants access to any AWS principal")
def sns_policy_public(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("attributes_readable", True):
        return _attrs_gap(r, "sns:GetTopicAttributes")
    return _public_policy_hits(
        r, "SNS",
        remediation=("Scope the statement to a Principal or add a Condition (aws:SourceOwner / "
                     "aws:SourceArn): `aws sns set-topic-attributes --topic-arn <arn> "
                     "--attribute-name Policy --attribute-value '<scoped-policy-json>'`. "
                     "A public sns:Subscribe lets anyone attach an endpoint and exfiltrate "
                     "every message; a public sns:Publish lets anyone inject events."))


@detector(kinds=["aws_sns_topic"], rule_id="AWS.SNS.POLICY_WILDCARD_ACTION", severity="high",
          title="SNS topic policy allows wildcard actions")
def sns_policy_wildcard_action(r, ctx) -> list:
    if not (r.raw or {}).get("attributes_readable", True):
        return []
    return _wildcard_action_hits(
        r, "SNS", "sns",
        remediation=("Replace `sns:*` with the operations actually needed (sns:Publish for "
                     "producers, sns:Subscribe for consumers) — the wildcard includes "
                     "sns:DeleteTopic, sns:RemovePermission and sns:SetTopicAttributes. Fix via "
                     "`aws sns set-topic-attributes --attribute-name Policy` or the "
                     "`aws_sns_topic_policy` Terraform resource."))


@detector(kinds=["aws_sns_topic"], rule_id="AWS.SNS.ENCRYPTION_AT_REST_OFF", severity="medium",
          title="SNS topic has no KMS encryption at rest")
def sns_encryption_off(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("attributes_readable", True):
        return _attrs_gap(r, "sns:GetTopicAttributes")
    if raw.get("kms_master_key_id"):
        return []
    return [Hit(
        observation=f"SNS topic '{r.name}' has no KmsMasterKeyId — messages are stored "
                    f"unencrypted at rest",
        remediation=("Set a KMS key: `aws sns set-topic-attributes --topic-arn <arn> "
                     "--attribute-name KmsMasterKeyId --attribute-value alias/aws/sns` (or a "
                     "customer-managed key for auditable access). Terraform: "
                     "`kms_master_key_id` on `aws_sns_topic`."),
        detail="KmsMasterKeyId=absent",
        source_ref={"attributes": ["KmsMasterKeyId"]},
    )]


@detector(kinds=["aws_sns_subscription"], rule_id="AWS.SNS.SUBSCRIPTION_PLAINTEXT_HTTP",
          severity="medium", title="SNS subscription delivers over plaintext HTTP")
def sns_subscription_http(r, ctx) -> list:
    raw = r.raw or {}
    if str(raw.get("protocol") or "").lower() != "http":
        return []
    return [Hit(
        observation=(f"SNS subscription on topic '{raw.get('topic_arn')}' delivers to "
                     f"'{raw.get('endpoint')}' with protocol http — every message crosses the "
                     f"network unencrypted and the endpoint cannot be authenticated"),
        remediation=("Re-subscribe the endpoint over https (`aws sns subscribe --protocol https "
                     "…`) and delete the http subscription (`aws sns unsubscribe "
                     "--subscription-arn <arn>`). SNS also signs messages — verify the "
                     "signature at the receiver."),
        detail=f"protocol=http endpoint={raw.get('endpoint')} pending={raw.get('pending')}",
        source_ref={"api": "sns:ListSubscriptionsByTopic", "attribute": "Protocol"},
    )]


# ══ EventBridge ═══════════════════════════════════════════════════════════════
@detector(kinds=["aws_event_bus"], rule_id="AWS.EVENTBRIDGE.BUS_POLICY_PUBLIC",
          severity="critical", title="EventBridge bus policy grants access to any AWS principal")
def event_bus_policy_public(r, ctx) -> list:
    return _public_policy_hits(
        r, "EventBridge",
        remediation=("Scope the bus policy to the sender accounts, or condition it on "
                     "aws:PrincipalOrgID: `aws events put-permission --event-bus-name <name> "
                     "--action events:PutEvents --principal <account-id>` (never `--principal "
                     "\"*\"` without `--condition`). A public PutEvents lets anyone inject "
                     "events that your rules will route into downstream targets."))


@detector(kinds=["aws_event_bus"], rule_id="AWS.EVENTBRIDGE.BUS_POLICY_WILDCARD_ACTION",
          severity="high", title="EventBridge bus policy allows wildcard actions")
def event_bus_policy_wildcard_action(r, ctx) -> list:
    return _wildcard_action_hits(
        r, "EventBridge", "events",
        remediation=("Grant only events:PutEvents to senders — `events:*` on a bus includes "
                     "events:PutRule, events:PutTargets and events:RemovePermission, i.e. the "
                     "ability to reroute the bus and rewrite the policy that admits the "
                     "grantee. Fix with `aws events put-permission` / `aws_cloudwatch_event_"
                     "bus_policy` scoped to explicit actions."))


@detector(kinds=["aws_event_rule"], rule_id="AWS.EVENTBRIDGE.CROSS_ACCOUNT_TARGET",
          severity="medium", title="EventBridge rule targets a resource in another AWS account")
def event_rule_cross_account_target(r, ctx) -> list:
    raw = r.raw or {}
    own = raw.get("account") or arn_account(raw.get("rule_arn"))
    hits = []
    for t in raw.get("targets") or []:
        tacct = arn_account(t.get("arn"))
        if not own or not tacct or tacct == own:
            continue
        hits.append(Hit(
            observation=(f"EventBridge rule '{r.name}' (account {own}) sends events to target "
                         f"{t.get('arn')} in account {tacct} — a cross-account event flow whose "
                         f"authorization lives in the DESTINATION account's resource policy, "
                         f"outside this account's control"),
            remediation=("Verify the destination bus/resource policy in account "
                         f"{tacct} restricts the sender — condition it on aws:PrincipalAccount "
                         "or the exact rule ARN (aws:SourceArn), not a bare principal. Remove "
                         "the target (`aws events remove-targets --rule <name> --ids "
                         f"{t.get('id')}`) if the flow is not intended."),
            detail=f"target_id={t.get('id')} target_arn={t.get('arn')} role_arn={t.get('role_arn')}",
            source_ref={"api": "events:ListTargetsByRule", "target_id": t.get("id")},
        ))
    return hits


# ══ MSK ═══════════════════════════════════════════════════════════════════════
@detector(kinds=["aws_msk_cluster"], rule_id="AWS.MSK.UNAUTHENTICATED_ACCESS", severity="high",
          title="MSK cluster allows unauthenticated client access")
def msk_unauthenticated(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("client_auth_unauthenticated"):
        return []
    public = raw.get("public_access_type") not in (None, "DISABLED")
    return [Hit(
        observation=(f"MSK cluster '{r.name}' has ClientAuthentication.Unauthenticated.Enabled "
                     f"= true — any client that can reach the brokers reads and writes every "
                     f"topic with no credential"
                     + (" — and PublicAccess is enabled, so 'reach' includes the internet"
                        if public else "")),
        severity="critical" if public else "high",
        remediation=("Enable SASL/IAM (`aws kafka update-security --cluster-arn <arn> "
                     "--client-authentication '{\"Sasl\":{\"Iam\":{\"Enabled\":true}},"
                     "\"Unauthenticated\":{\"Enabled\":false}}'`) or SASL/SCRAM / mutual TLS, "
                     "then disable unauthenticated access. Terraform: `client_authentication` "
                     "block on `aws_msk_cluster` with `unauthenticated = false`."),
        detail=(f"unauthenticated=true sasl_iam={raw.get('client_auth_sasl_iam')} "
                f"sasl_scram={raw.get('client_auth_sasl_scram')} tls={raw.get('client_auth_tls')} "
                f"public_access={raw.get('public_access_type')}"),
        source_ref={"api": "kafka:ListClustersV2", "field": "ClientAuthentication.Unauthenticated"},
    )]


@detector(kinds=["aws_msk_cluster"], rule_id="AWS.MSK.CLIENT_PLAINTEXT_IN_TRANSIT",
          severity="high", title="MSK cluster accepts plaintext client connections")
def msk_client_plaintext(r, ctx) -> list:
    raw = r.raw or {}
    cb = str(raw.get("encryption_in_transit_client_broker") or "")
    if cb not in ("PLAINTEXT", "TLS_PLAINTEXT"):
        return []
    return [Hit(
        observation=(f"MSK cluster '{r.name}' has EncryptionInTransit.ClientBroker = {cb} — "
                     f"client traffic (including SASL credentials on the plaintext listener) "
                     f"crosses the network unencrypted"),
        remediation=("Set client-broker encryption to TLS_ONLY: `aws kafka "
                     "update-cluster-configuration` / console → Security → Encryption, or "
                     "Terraform `encryption_info { encryption_in_transit { client_broker = "
                     "\"TLS\" } }`. Migrate clients to the TLS bootstrap brokers first, then "
                     "drop the plaintext listener."),
        detail=f"client_broker={cb}",
        source_ref={"api": "kafka:ListClustersV2",
                    "field": "EncryptionInfo.EncryptionInTransit.ClientBroker"},
    )]


@detector(kinds=["aws_msk_cluster"], rule_id="AWS.MSK.INTERBROKER_PLAINTEXT", severity="medium",
          title="MSK inter-broker replication is not encrypted")
def msk_interbroker_plaintext(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("cluster_type") != "PROVISIONED":
        return []
    if raw.get("encryption_in_transit_in_cluster") is not False:
        return []
    return [Hit(
        observation=f"MSK cluster '{r.name}' has EncryptionInTransit.InCluster = false — "
                    f"replication traffic between brokers crosses the VPC unencrypted",
        remediation=("Set `in_cluster = true` in the Terraform `encryption_in_transit` block "
                     "(console: Security → Encryption → within the cluster). Every produced "
                     "record transits broker-to-broker during replication."),
        detail="in_cluster=false",
        source_ref={"api": "kafka:ListClustersV2",
                    "field": "EncryptionInfo.EncryptionInTransit.InCluster"},
    )]


@detector(kinds=["aws_msk_cluster"], rule_id="AWS.MSK.PUBLIC_ACCESS_ENABLED", severity="high",
          title="MSK cluster brokers are publicly reachable")
def msk_public_access(r, ctx) -> list:
    raw = r.raw or {}
    pa = raw.get("public_access_type")
    if pa in (None, "DISABLED"):
        return []
    return [Hit(
        observation=(f"MSK cluster '{r.name}' has ConnectivityInfo.PublicAccess.Type = {pa} — "
                     f"the brokers carry public endpoints reachable from the internet, so "
                     f"authentication and TLS configuration are the only remaining controls"),
        remediation=("Disable public access unless internet-facing producers are a hard "
                     "requirement: `aws kafka update-connectivity --cluster-arn <arn> "
                     "--connectivity-info '{\"PublicAccess\":{\"Type\":\"DISABLED\"}}'`. If it "
                     "must stay, require SASL/IAM or mTLS and keep unauthenticated access off "
                     "(AWS enforces auth for public clusters — verify it here)."),
        detail=f"public_access_type={pa}",
        source_ref={"api": "kafka:ListClustersV2",
                    "field": "BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type"},
    )]


@detector(kinds=["aws_msk_cluster"], rule_id="AWS.MSK.ENHANCED_MONITORING_DEFAULT",
          severity="low", title="MSK enhanced monitoring is at the DEFAULT level")
def msk_monitoring_default(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("cluster_type") != "PROVISIONED":
        return []
    if str(raw.get("enhanced_monitoring") or "") != "DEFAULT":
        return []
    return [Hit(
        observation=(f"MSK cluster '{r.name}' has EnhancedMonitoring = DEFAULT — only "
                     f"cluster-level metrics are shipped, so per-broker and per-topic anomalies "
                     f"(one broker suddenly serving an unknown consumer) are invisible"),
        remediation=("Raise it: `aws kafka update-monitoring --cluster-arn <arn> "
                     "--enhanced-monitoring PER_TOPIC_PER_BROKER` (Terraform "
                     "`enhanced_monitoring`), and enable open monitoring with Prometheus for "
                     "detection use-cases."),
        detail="enhanced_monitoring=DEFAULT",
        source_ref={"api": "kafka:ListClustersV2", "field": "EnhancedMonitoring"},
    )]


# ══ API Gateway ═══════════════════════════════════════════════════════════════
_PREFLIGHT_METHODS = {"OPTIONS"}


@detector(kinds=["aws_api"], rule_id="AWS.APIGW.ROUTE_NO_AUTHORIZER", severity="high",
          title="API Gateway route has no authorizer")
def apigw_route_no_authorizer(r, ctx) -> list:
    raw = r.raw or {}
    hits = []
    for route in raw.get("routes") or []:
        if str(route.get("method") or "").upper() in _PREFLIGHT_METHODS:
            continue   # CORS preflight is unauthenticated by design
        if not route.get("details_readable", True):
            hits.append(Hit(
                observation=(f"API '{r.name}' ({raw.get('api_version')}) method "
                             f"{route.get('method')} {route.get('path')} returned no method "
                             f"detail, so its authorization type could not be read"),
                remediation="Grant apigateway:GET on the API's resources so method-level "
                            "authorization can be assessed.",
                detail=f"path={route.get('path')} method={route.get('method')}",
                assessable=False,
                assessment_reason="get_resources(embed=['methods']) returned no method detail",
                source_ref={"api": "apigateway:GET /resources"},
            ))
            continue
        if str(route.get("authorization_type") or "NONE").upper() != "NONE":
            continue
        if route.get("api_key_required"):
            continue   # reported by AWS.APIGW.ROUTE_API_KEY_ONLY — a different defect
        hits.append(Hit(
            observation=(f"API '{r.name}' ({raw.get('api_version')}, {raw.get('protocol')}) "
                         f"route {route.get('method')} {route.get('path')} has "
                         f"authorizationType NONE and apiKeyRequired false — the endpoint is "
                         f"callable by anyone who finds the URL"),
            remediation=("Attach an authorizer — IAM (`authorization_type = \"AWS_IAM\"`), a "
                         "JWT/Cognito authorizer, or a Lambda authorizer: `aws apigateway "
                         "update-method --rest-api-id <id> --resource-id <rid> --http-method "
                         f"{route.get('method')} --patch-operations "
                         "op=replace,path=/authorizationType,value=AWS_IAM` (v2: `aws "
                         "apigatewayv2 update-route --authorization-type JWT "
                         "--authorizer-id <id>`). Intentionally public routes should be "
                         "explicit and rate-limited."),
            detail=(f"path={route.get('path')} method={route.get('method')} "
                    f"authorization_type=NONE api_key_required=False"),
            source_ref={"route": f"{route.get('method')} {route.get('path')}"},
        ))
    return hits


@detector(kinds=["aws_api"], rule_id="AWS.APIGW.ROUTE_API_KEY_ONLY", severity="medium",
          title="API Gateway route uses an API key as its only access control")
def apigw_route_api_key_only(r, ctx) -> list:
    raw = r.raw or {}
    hits = []
    for route in raw.get("routes") or []:
        if str(route.get("method") or "").upper() in _PREFLIGHT_METHODS:
            continue
        if not route.get("details_readable", True):
            continue
        if str(route.get("authorization_type") or "NONE").upper() != "NONE":
            continue
        if not route.get("api_key_required"):
            continue
        hits.append(Hit(
            observation=(f"API '{r.name}' ({raw.get('api_version')}) route "
                         f"{route.get('method')} {route.get('path')} has authorizationType "
                         f"NONE with apiKeyRequired true — API keys are a metering feature, "
                         f"not authentication: long-lived, unsigned, routinely embedded in "
                         f"clients, and AWS documents them as unsuitable for access control"),
            remediation=("Add a real authorizer (IAM / JWT / Lambda) and keep the API key only "
                         "for usage plans: `aws apigateway update-method --patch-operations "
                         "op=replace,path=/authorizationType,value=AWS_IAM` on the method, "
                         "leaving apiKeyRequired for metering."),
            detail=(f"path={route.get('path')} method={route.get('method')} "
                    f"authorization_type=NONE api_key_required=True"),
            source_ref={"route": f"{route.get('method')} {route.get('path')}"},
        ))
    return hits


@detector(kinds=["aws_api_stage"], rule_id="AWS.APIGW.STAGE_LOGGING_DISABLED", severity="low",
          title="API Gateway stage has logging disabled")
def apigw_stage_logging_disabled(r, ctx) -> list:
    raw = r.raw or {}
    exec_level = str(raw.get("execution_logging_level") or "OFF").upper()
    if raw.get("access_log_enabled") or exec_level in ("ERROR", "INFO"):
        return []
    return [Hit(
        observation=(f"API stage '{r.name}' (api {raw.get('api_id')}, "
                     f"{raw.get('api_version')}) has no access log destination and execution "
                     f"logging is {exec_level} — requests to this stage leave no log to "
                     f"detect abuse or investigate an incident with"),
        remediation=("Enable access logging: `aws apigateway update-stage --rest-api-id <id> "
                     f"--stage-name {raw.get('stage_name')} --patch-operations "
                     "op=replace,path=/accessLogSettings/destinationArn,value=<log-group-arn>` "
                     "(v2: `aws apigatewayv2 update-stage --access-log-settings ...`), and set "
                     "execution logging to ERROR or INFO for REST APIs."),
        detail=f"access_log_enabled=False execution_logging_level={exec_level}",
        source_ref={"stage": raw.get("stage_name"),
                    "fields": ["accessLogSettings", "methodSettings.*/*.loggingLevel"]},
    )]


@detector(kinds=["aws_api_stage"], rule_id="AWS.APIGW.STAGE_NO_WAF", severity="low",
          title="API Gateway stage has no WAF web ACL associated")
def apigw_stage_no_waf(r, ctx) -> list:
    raw = r.raw or {}
    # WAF can only associate with REST (v1) stages; flagging an HTTP API for a control AWS
    # does not offer there would be a finding the customer cannot action.
    if not raw.get("waf_supported") or raw.get("web_acl_arn"):
        return []
    return [Hit(
        observation=f"REST API stage '{r.name}' (api {raw.get('api_id')}) has no webAclArn — "
                    f"no WAF web ACL filters requests before they reach the integration",
        remediation=("Associate a web ACL: `aws wafv2 associate-web-acl --web-acl-arn <acl-arn> "
                     "--resource-arn arn:aws:apigateway:<region>::/restapis/"
                     f"{raw.get('api_id')}/stages/{raw.get('stage_name')}` (Terraform "
                     "`aws_wafv2_web_acl_association`), starting from the "
                     "AWSManagedRulesCommonRuleSet."),
        detail="web_acl_arn=absent waf_supported=True",
        source_ref={"stage": raw.get("stage_name"), "field": "webAclArn"},
    )]


# ══ Account: the coverage-gap surface ═════════════════════════════════════════
@detector(kinds=["aws_account"], rule_id="AWS.ACCOUNT.SERVICE_NOT_ASSESSED", severity="info",
          title="An AWS service could not be assessed with the granted permissions")
def account_service_not_assessed(r, ctx) -> list:
    """The third honest outcome at account scope: a (service, region) whose List* call was
    AccessDenied is a COVERAGE GAP — the connector recorded it instead of failing the scan,
    and this rule surfaces it as not-assessable rather than letting the absence of resources
    read as a clean pass."""
    raw = r.raw or {}
    hits = []
    for key, rec in sorted((raw.get("collection") or {}).items()):
        if (rec or {}).get("outcome") != "access_denied":
            continue
        service, _, region = key.partition(":")
        hits.append(Hit(
            observation=(f"listing {service} in {region} was denied for "
                         f"{raw.get('caller_arn')} ({rec.get('error')}), so no {service} "
                         f"resource in {region} was assessed"),
            remediation=("Attach the AWS-managed SecurityAudit policy to the scan role, or "
                         f"grant the read-only List*/Get*/Describe* actions for {service}. "
                         "Until then this service's posture is unknown, not clean."),
            detail=f"service={service} region={region} error={rec.get('error')}",
            assessable=False,
            assessment_reason=f"{service} list call returned {rec.get('error')} in {region}",
            source_ref={"service": service, "region": region},
        ))
    return hits
