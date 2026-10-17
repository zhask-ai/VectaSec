"""AWS agentless connector — read-only, one connection fans out to five services.

This is the connector that makes "agentless via cross-account read-only role" true: the
customer creates an IAM role trusting our account (or hands us a profile / key pair), and one
connection collects the integration-layer surface of an AWS account — SQS queues, SNS topics,
EventBridge buses+rules, MSK clusters, and API Gateway (v1 REST and v2 HTTP/WebSocket) — with
STRICTLY read-only calls (List*/Get*/Describe* only; nothing here can mutate the account).

Three disciplines carried over from the other connectors:

  • Secrets are used, never persisted. `secret_access_key`/`session_token` are ConnectorField
    secret=True (console renders a password input, never echoes); the values build a boto3
    session inside collect() and are never copied into any Resource. AssumeRole temporary
    credentials likewise live and die inside collect().
  • Per-service error isolation. Each (service, region) collection runs in its own try/except:
    a role denied kafka:ListClusters records {"outcome": "access_denied"} on the aws_account
    resource instead of voiding the whole scan. detect/aws.py turns those records into
    not-assessable coverage-gap findings — never a pass, never a failure. Isolation alone is
    not enough: a CHILD read that fails inside a service that otherwise succeeded must also be
    recorded — as a *_readable flag on the parent resource, or as a child_gaps entry in the
    service's outcome record when the child leaves no resource behind. Swallowing one to
    []/None makes "denied" indistinguishable from "none exists", which is the secure state.
  • Resource policies are OBSERVATIONS, not secrets. A queue/topic/bus policy is authorization
    config, exactly the evidence a posture finding must cite, so the parsed JSON is stored in
    Resource.raw and quoted by detectors.

The parse layer (parse_queue, parse_topic, …) is pure: boto3 response dicts in, Resources out.
Tests exercise detectors against parse-layer output from golden fixture dicts, so boto3 (and a
live account) stays out of the test suite and a shape drift between connector and rulepack
fails a test instead of silently mis-firing in production.

Kinds are DISTINCT (aws_sqs_queue, aws_sns_topic, aws_event_bus, aws_event_rule,
aws_msk_cluster, aws_api, aws_api_stage, aws_iam_user, aws_iam_role, …) so no other rulepack
ever runs against an AWS resource by accident — the same reason connect/redis.py refuses to
reuse `broker`.

LAST-USED + OWNER (the Access-page telemetry). One global IAM pass (`_collect_iam`) lists IAM
users and roles (capped, truncation recorded), their access keys with GetAccessKeyLastUsed,
RoleLastUsed from GetRole, Access Advisor (GenerateServiceLastAccessedDetails →
GetServiceLastAccessedDetails, polled with a bounded wait) and tags; a per-region CloudTrail
LookupEvents pass adds the newest management event per principal. An owner label is derived
from a fixed, case-insensitive tag-key preference list (owner, team, service, contact, email,
vectasec:owner, created-by, CreatedBy) on IAM principals and on SQS/SNS/MSK/API Gateway
resources. Access-key IDs are stored MASKED (first 4 + … + last 4); no secret material of any
kind is read, let alone stored. Every one of these signals is three-valued: readable-and-set,
readable-and-empty (never used — the finding), or NOT readable (denied → recorded as a child
gap and the raw key is simply absent, which the lifecycle rules read as "not assessed").
"""
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector


# ── IAM policy reading — shared by the rulepack and the NHI extractor ─────────
def policy_statements(policy) -> list:
    """Statement list of a parsed policy document. Tolerates the single-statement dict form
    and anything malformed (returns [] — a rule must not crash on a hand-mangled policy)."""
    if not isinstance(policy, dict):
        return []
    st = policy.get("Statement")
    if isinstance(st, dict):
        return [st]
    return [s for s in st if isinstance(s, dict)] if isinstance(st, list) else []


def principal_entries(stmt: dict) -> list:
    """Every principal a statement names, flattened. `"Principal": "*"` and
    `{"AWS": "*"}` both come back as ["*"] — they are the same grant."""
    p = stmt.get("Principal")
    if p == "*":
        return ["*"]
    if not isinstance(p, dict):
        return []
    out = []
    for v in p.values():
        out.extend(v if isinstance(v, list) else [v])
    return [str(x) for x in out]


def statement_actions(stmt: dict) -> list:
    a = stmt.get("Action")
    if a is None:
        return []
    return [str(x) for x in (a if isinstance(a, list) else [a])]


def is_public_statement(stmt: dict) -> bool:
    """Allow + wildcard principal + NO Condition — the anyone-on-the-internet grant. A
    Condition (aws:SourceArn, aws:SourceAccount, aws:PrincipalOrgID…) scopes the wildcard,
    so a conditioned statement is deliberately NOT reported as public."""
    return (str(stmt.get("Effect", "")).lower() == "allow"
            and "*" in principal_entries(stmt)
            and not stmt.get("Condition"))


def has_wildcard_action(stmt: dict) -> bool:
    return any(a == "*" or a.endswith(":*") for a in statement_actions(stmt))


def arn_account(arn) -> str:
    """Account id field of an ARN ('' when absent/unparseable)."""
    parts = str(arn or "").split(":")
    return parts[4] if len(parts) > 4 else ""


def _parse_json(s):
    """Parse a policy/redrive JSON string boto3 returns; None when absent or unparseable
    (a policy we could not parse must read as 'unknown', never as 'no policy')."""
    if isinstance(s, dict):
        return s
    if not s:
        return None
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return None


# ── parse layer: boto3 response dicts → Resources (pure, no boto3) ────────────
def parse_queue(region: str, queue_url: str, attrs, tags=None) -> Resource:
    """One SQS queue from get_queue_attributes(AttributeNames=['All']). attrs=None means the
    per-queue attribute call itself failed (recorded, so detectors answer not-assessable
    instead of reading absence as a clean pass). `tags` is the ListQueueTags dict (None =
    not readable); an owner-ish tag lands in raw.owner."""
    name = queue_url.rstrip("/").rsplit("/", 1)[-1]
    a = attrs or {}
    arn = a.get("QueueArn") or f"sqs-{region}-{name}"
    return Resource(
        kind="aws_sqs_queue",
        name=name,
        ext_id=arn,
        namespace=region,
        labels={"region": region, "service": "sqs"},
        raw=_with_owner({
            "queue_url": queue_url,
            "queue_arn": a.get("QueueArn"),
            "region": region,
            "account": arn_account(a.get("QueueArn")),
            "attributes_readable": attrs is not None,
            "policy": _parse_json(a.get("Policy")),
            "kms_master_key_id": a.get("KmsMasterKeyId"),
            # boto3 returns attribute values as strings; normalise the SSE flag to bool/None.
            "sqs_managed_sse_enabled": (None if "SqsManagedSseEnabled" not in a
                                        else str(a.get("SqsManagedSseEnabled")).lower() == "true"),
            "redrive_policy": _parse_json(a.get("RedrivePolicy")),
            "visibility_timeout": a.get("VisibilityTimeout"),
            "fifo": name.endswith(".fifo"),
        }, tags),
    )


def parse_topic(region: str, topic_arn: str, attrs, subscriptions_readable: bool = True,
                tags=None) -> Resource:
    """One SNS topic. `subscriptions_readable` False means ListSubscriptionsByTopic failed for
    THIS topic: the subscription resources are missing, so a topic with no delivery endpoints
    and a topic whose endpoints were denied would otherwise look identical. `tags` is the
    ListTagsForResource list (None = not readable)."""
    a = attrs or {}
    return Resource(
        kind="aws_sns_topic",
        name=topic_arn.rsplit(":", 1)[-1],
        ext_id=topic_arn,
        namespace=region,
        labels={"region": region, "service": "sns"},
        raw=_with_owner({
            "topic_arn": topic_arn,
            "region": region,
            "account": arn_account(topic_arn),
            "attributes_readable": attrs is not None,
            "subscriptions_readable": subscriptions_readable,
            "policy": _parse_json(a.get("Policy")),
            "kms_master_key_id": a.get("KmsMasterKeyId"),
            "subscriptions_confirmed": a.get("SubscriptionsConfirmed"),
        }, tags),
    )


def parse_subscription(region: str, sub: dict) -> Resource:
    """One list_subscriptions_by_topic entry. A pending subscription has the literal
    'PendingConfirmation' instead of an ARN — still emitted (a pending http subscription is
    posture-relevant), with a synthesized ext_id unique within the topic."""
    arn = sub.get("SubscriptionArn") or ""
    topic_arn = sub.get("TopicArn") or ""
    endpoint = sub.get("Endpoint") or ""
    if not arn.startswith("arn:"):
        arn = f"{topic_arn}/pending/{sub.get('Protocol')}/{endpoint}"
    return Resource(
        kind="aws_sns_subscription",
        name=f"{sub.get('Protocol')}:{endpoint}" if endpoint else str(sub.get("Protocol")),
        ext_id=arn,
        namespace=region,
        labels={"region": region, "service": "sns", "protocol": str(sub.get("Protocol"))},
        raw={
            "subscription_arn": sub.get("SubscriptionArn"),
            "topic_arn": topic_arn,
            "protocol": sub.get("Protocol"),
            "endpoint": endpoint,
            "owner": sub.get("Owner"),
            "region": region,
            "pending": not str(sub.get("SubscriptionArn") or "").startswith("arn:"),
        },
    )


def parse_bus(region: str, bus: dict, policy, policy_readable=True) -> Resource:
    """One event bus. `policy` comes from describe_event_bus (a JSON string) — passed
    separately because list_event_buses omits it on older API versions.

    `policy_readable` is three-valued: True read, False the read was refused, None never
    attempted. A denied DescribeEventBus lands `policy=None`, which is byte-identical to "this
    bus has no resource policy" — the SECURE state. Without this flag a bus nobody may inspect
    renders as a clean bus, so the flag, not the None, is what detectors must branch on."""
    arn = bus.get("Arn") or f"event-bus-{region}-{bus.get('Name')}"
    return Resource(
        kind="aws_event_bus",
        name=str(bus.get("Name")),
        ext_id=arn,
        namespace=region,
        labels={"region": region, "service": "events"},
        raw={
            "bus_arn": bus.get("Arn"),
            "region": region,
            "account": arn_account(bus.get("Arn")),
            "policy_readable": policy_readable,
            "policy": _parse_json(policy),
        },
    )


def parse_rule(region: str, bus_ext: str, rule: dict, targets) -> tuple:
    """One EventBridge rule + its targets → (resources, edges): bus --routes_to--> rule,
    rule --targets--> each target. Target Input/InputTransformer payloads are deliberately
    NOT stored — they can embed message bodies, which are data, not posture.

    `targets=None` means ListTargetsByRule failed for THIS rule (recorded, so the
    cross-account rule answers not-assessable instead of reading an empty list as "this rule
    forwards nowhere"); `[]` means the rule genuinely has no targets."""
    arn = rule.get("Arn") or f"event-rule-{region}-{rule.get('Name')}"
    kept_targets = [{"id": t.get("Id"), "arn": t.get("Arn"), "role_arn": t.get("RoleArn")}
                    for t in (targets or [])]
    rule_res = Resource(
        kind="aws_event_rule",
        name=str(rule.get("Name")),
        ext_id=arn,
        namespace=region,
        labels={"region": region, "service": "events", "state": str(rule.get("State"))},
        raw={
            "rule_arn": rule.get("Arn"),
            "bus_name": rule.get("EventBusName") or "default",
            "state": rule.get("State"),
            "event_pattern": _parse_json(rule.get("EventPattern")),
            "schedule_expression": rule.get("ScheduleExpression"),
            "region": region,
            "account": arn_account(rule.get("Arn")),
            "targets_readable": targets is not None,
            "targets": kept_targets,
        },
    )
    resources = [rule_res]
    edges = [Edge(src_ext_id=bus_ext, dst_ext_id=arn, kind="routes_to")]
    for t in kept_targets:
        if not t["arn"]:
            continue
        text = f"{arn}/target/{t['id'] or t['arn']}"
        resources.append(Resource(
            kind="aws_event_target",
            name=str(t["arn"]).rsplit(":", 1)[-1],
            ext_id=text,
            namespace=region,
            labels={"region": region, "service": "events"},
            raw={"target_id": t["id"], "target_arn": t["arn"], "role_arn": t["role_arn"],
                 "rule_ext": arn, "account": arn_account(t["arn"]), "region": region},
        ))
        edges.append(Edge(src_ext_id=arn, dst_ext_id=text, kind="targets"))
    return resources, edges


def parse_msk_cluster(region: str, cluster: dict) -> Resource:
    """One list_clusters_v2 entry. The v2 shape carries the full describe payload for both
    PROVISIONED and SERVERLESS clusters, so no second call is needed. Serverless clusters
    are always IAM-authenticated and TLS-only by the service; the provisioned-only fields
    stay None for them and provisioned-only rules skip on cluster_type."""
    prov = cluster.get("Provisioned") or {}
    enc = prov.get("EncryptionInfo") or {}
    transit = enc.get("EncryptionInTransit") or {}
    auth = prov.get("ClientAuthentication") or {}
    sasl = auth.get("Sasl") or {}
    connectivity = (prov.get("BrokerNodeGroupInfo") or {}).get("ConnectivityInfo") or {}
    public = connectivity.get("PublicAccess") or {}
    arn = cluster.get("ClusterArn") or f"msk-{region}-{cluster.get('ClusterName')}"
    is_provisioned = (cluster.get("ClusterType") or "PROVISIONED").upper() == "PROVISIONED"
    return Resource(
        kind="aws_msk_cluster",
        name=str(cluster.get("ClusterName")),
        ext_id=arn,
        namespace=region,
        labels={"region": region, "service": "msk",
                "cluster_type": str(cluster.get("ClusterType") or "PROVISIONED")},
        raw=_with_owner({
            "cluster_arn": cluster.get("ClusterArn"),
            "cluster_name": cluster.get("ClusterName"),
            "cluster_type": (cluster.get("ClusterType") or "PROVISIONED").upper(),
            "state": cluster.get("State"),
            "region": region,
            "account": arn_account(cluster.get("ClusterArn")),
            "kafka_version": (prov.get("CurrentBrokerSoftwareInfo") or {}).get("KafkaVersion"),
            "number_of_broker_nodes": prov.get("NumberOfBrokerNodes"),
            "encryption_in_transit_client_broker": transit.get("ClientBroker") if is_provisioned else "TLS",
            "encryption_in_transit_in_cluster": transit.get("InCluster") if is_provisioned else True,
            "encryption_at_rest_kms_key": (enc.get("EncryptionAtRest") or {}).get("DataVolumeKMSKeyId"),
            "client_auth_unauthenticated": bool((auth.get("Unauthenticated") or {}).get("Enabled")),
            "client_auth_sasl_scram": bool((sasl.get("Scram") or {}).get("Enabled")),
            "client_auth_sasl_iam": bool((sasl.get("Iam") or {}).get("Enabled")) or not is_provisioned,
            "client_auth_tls": bool((auth.get("Tls") or {}).get("Enabled")),
            "public_access_type": public.get("Type") or "DISABLED",
            "enhanced_monitoring": prov.get("EnhancedMonitoring"),
        }, cluster.get("Tags") if "Tags" in cluster else None),
    )


def _stage_resource(region: str, api_ext: str, api_id: str, api_version: str, *,
                    stage_name: str, access_log_enabled: bool, execution_logging_level,
                    web_acl_arn, waf_supported: bool, tracing_enabled) -> Resource:
    return Resource(
        kind="aws_api_stage",
        name=stage_name,
        ext_id=f"{api_ext}/stage/{stage_name}",
        namespace=region,
        labels={"region": region, "service": "apigateway", "api_version": api_version},
        raw={
            "api_id": api_id,
            "api_ext": api_ext,
            "api_version": api_version,
            "stage_name": stage_name,
            "region": region,
            "access_log_enabled": access_log_enabled,
            "execution_logging_level": execution_logging_level,
            "web_acl_arn": web_acl_arn,
            "waf_supported": waf_supported,
            "tracing_enabled": tracing_enabled,
        },
    )


def parse_api_v1(region: str, api: dict, stages, authorizers, resource_items) -> tuple:
    """One REST API (API Gateway v1) → (resources, edges): the aws_api, one aws_api_stage per
    stage, api --exposes--> stage. Routes come from get_resources(embed=['methods']) —
    resourceMethods carries authorizationType/apiKeyRequired per method. A method whose
    detail dict is empty (embed not honoured) is recorded with authorization_type=None so
    detectors answer 'unknown', not 'unauthenticated'.

    Each child list is three-valued: None = that call failed, [] = the API genuinely has none.
    An unread stage list emits NO aws_api_stage resources at all, so every stage rule would
    have nothing to run on and the API would score clean — the flags are the only trace left."""
    api_id = api.get("id")
    ext = f"aws-api-{region}-{api_id}"
    routes = []
    for item in resource_items or []:
        for method, detail in (item.get("resourceMethods") or {}).items():
            d = detail or {}
            routes.append({
                "path": item.get("path"),
                "method": method,
                "authorization_type": d.get("authorizationType"),
                "authorizer_id": d.get("authorizerId"),
                "api_key_required": bool(d.get("apiKeyRequired")),
                "details_readable": bool(d),
            })
    api_res = Resource(
        kind="aws_api",
        name=str(api.get("name")),
        ext_id=ext,
        namespace=region,
        labels={"region": region, "service": "apigateway", "api_version": "v1",
                "protocol": "REST"},
        raw=_with_owner({
            "api_id": api_id,
            "api_version": "v1",
            "protocol": "REST",
            "region": region,
            "endpoint_types": (api.get("endpointConfiguration") or {}).get("types"),
            "api_key_source": api.get("apiKeySource"),
            "routes_readable": resource_items is not None,
            "routes": routes,
            "stages_readable": stages is not None,
            "authorizers_readable": authorizers is not None,
            "authorizers": [{"id": a.get("id"), "name": a.get("name"), "type": a.get("type")}
                            for a in (authorizers or [])],
        }, api.get("tags") if "tags" in api else None),
    )
    resources, edges = [api_res], []
    for s in stages or []:
        log_level = ((s.get("methodSettings") or {}).get("*/*") or {}).get("loggingLevel")
        stage = _stage_resource(
            region, ext, api_id, "v1",
            stage_name=str(s.get("stageName")),
            access_log_enabled=bool((s.get("accessLogSettings") or {}).get("destinationArn")),
            execution_logging_level=log_level,
            web_acl_arn=s.get("webAclArn"),
            waf_supported=True,   # REST APIs associate with WAF regional web ACLs
            tracing_enabled=s.get("tracingEnabled"),
        )
        resources.append(stage)
        edges.append(Edge(src_ext_id=ext, dst_ext_id=stage.ext_id, kind="exposes"))
    return resources, edges


def parse_api_v2(region: str, api: dict, stages, routes, authorizers) -> tuple:
    """One HTTP/WebSocket API (API Gateway v2) → same shape as parse_api_v1. RouteKey
    'GET /pets' splits into method+path; '$default' is the catch-all route. Child lists are
    three-valued exactly as in parse_api_v1: None = the call failed, [] = there are none."""
    api_id = api.get("ApiId")
    ext = f"aws-api-{region}-{api_id}"
    protocol = api.get("ProtocolType") or "HTTP"
    norm_routes = []
    for r in routes or []:
        key = str(r.get("RouteKey") or "")
        method, _, path = key.partition(" ")
        norm_routes.append({
            "path": path or key,                       # '$default' / '$connect' have no space
            "method": method if path else "ANY",
            "authorization_type": r.get("AuthorizationType") or "NONE",
            "authorizer_id": r.get("AuthorizerId"),
            "api_key_required": bool(r.get("ApiKeyRequired")),
            "details_readable": True,
        })
    api_res = Resource(
        kind="aws_api",
        name=str(api.get("Name")),
        ext_id=ext,
        namespace=region,
        labels={"region": region, "service": "apigateway", "api_version": "v2",
                "protocol": protocol},
        raw=_with_owner({
            "api_id": api_id,
            "api_version": "v2",
            "protocol": protocol,
            "region": region,
            "endpoint": api.get("ApiEndpoint"),
            "routes_readable": routes is not None,
            "routes": norm_routes,
            "stages_readable": stages is not None,
            "authorizers_readable": authorizers is not None,
            "authorizers": [{"id": a.get("AuthorizerId"), "name": a.get("Name"),
                             "type": a.get("AuthorizerType")} for a in (authorizers or [])],
        }, api.get("Tags") if "Tags" in api else None),
    )
    resources, edges = [api_res], []
    for s in stages or []:
        stage = _stage_resource(
            region, ext, api_id, "v2",
            stage_name=str(s.get("StageName")),
            access_log_enabled=bool((s.get("AccessLogSettings") or {}).get("DestinationArn")),
            execution_logging_level=(s.get("DefaultRouteSettings") or {}).get("LoggingLevel"),
            web_acl_arn=None,
            waf_supported=False,  # WAF cannot associate with HTTP/WebSocket APIs
            tracing_enabled=None,
        )
        resources.append(stage)
        edges.append(Edge(src_ext_id=ext, dst_ext_id=stage.ext_id, kind="exposes"))
    return resources, edges


# ── owner attribution + timestamps (pure helpers) ─────────────────────────────
# Tag keys that name an owner, in preference order, matched case-insensitively. The first key
# present wins; its value becomes the owner label and raw.owner.source records which key.
_OWNER_TAG_KEYS = ("owner", "team", "service", "contact", "email", "vectasec:owner",
                   "created-by", "createdby")


def _tags_as_dict(tags) -> dict | None:
    """Normalise the three tag shapes AWS returns — [{"Key","Value"}] (IAM, SNS),
    {key: value} (SQS, MSK, API Gateway) — to one dict. None stays None (= not readable)."""
    if tags is None:
        return None
    if isinstance(tags, dict):
        return {str(k): ("" if v is None else str(v)) for k, v in tags.items()}
    out = {}
    for t in tags if isinstance(tags, list) else []:
        if isinstance(t, dict) and t.get("Key") is not None:
            out[str(t["Key"])] = "" if t.get("Value") is None else str(t.get("Value"))
    return out


def owner_from_tags(tags) -> dict | None:
    """{"label": ..., "source": "tag:<Key>"} from the first owner-ish tag key present
    (case-insensitive, see _OWNER_TAG_KEYS), else None. An empty tag value counts as absent."""
    d = _tags_as_dict(tags)
    if not d:
        return None
    lowered = {}
    for k, v in d.items():
        lowered.setdefault(k.lower(), (k, v))
    for want in _OWNER_TAG_KEYS:
        hit = lowered.get(want)
        if hit and hit[1].strip():
            return {"label": hit[1].strip(), "source": f"tag:{hit[0]}"}
    return None


def _with_owner(raw: dict, tags) -> dict:
    """Attach tags_readable (+ owner when a tag names one) to a resource's raw dict. The owner
    key is deliberately ABSENT when no tag names one, so "no owner" and "owner not readable"
    are told apart by tags_readable alone."""
    raw["tags_readable"] = tags is not None
    owner = owner_from_tags(tags)
    if owner:
        raw["owner"] = owner
    return raw


def _iso(value):
    """datetime (boto3 returns tz-aware datetimes) or ISO string → canonical ISO-8601 UTC
    string; None/'' → None. Strings are passed through (the fixtures hold them already)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def _parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _newest(values):
    """The newest parseable ISO timestamp among `values` (None when none is set)."""
    best, best_dt = None, None
    for v in values:
        dt = _parse_iso(v)
        if dt is not None and (best_dt is None or dt > best_dt):
            best, best_dt = _iso(v), dt
    return best


def mask_key_id(key_id) -> str:
    """'AKIAIOSFODNN7EXAMPLE' → 'AKIA…MPLE'. The access-key id is an identifier, not a secret,
    but only the masked form is ever stored."""
    k = str(key_id or "")
    return f"{k[:4]}…{k[-4:]}" if len(k) > 8 else k


# ── parse layer: IAM principals, access keys, Access Advisor, CloudTrail ──────
# Service namespaces (as Access Advisor reports them) the integration-layer scan cares about.
_TRACKED_SERVICES = ("sqs", "sns", "events", "kafka", "execute-api", "apigateway")


def parse_access_key(meta: dict, last_used) -> dict:
    """One ListAccessKeys AccessKeyMetadata entry + its GetAccessKeyLastUsed response.
    `last_used=None` means that call was DENIED for this key: the `last_used_at` key is then
    left out entirely (the lifecycle rules read key-absence as "not assessed"). A readable
    response WITHOUT a LastUsedDate means the key exists but has never authenticated — that
    is recorded as last_used_at=None, the fact CREDENTIAL.LIFECYCLE.NEVER_USED fires on."""
    key_id = str(meta.get("AccessKeyId") or "")
    out = {
        "key_id_masked": mask_key_id(key_id),
        # stable, non-reversible discriminator so two keys on one user get distinct ext_ids
        "key_ref": hashlib.sha256(key_id.encode()).hexdigest()[:10] if key_id else "",
        "status": meta.get("Status"),
        "created_at": _iso(meta.get("CreateDate")),
        "last_used_readable": last_used is not None,
    }
    if last_used is not None:
        lu = (last_used or {}).get("AccessKeyLastUsed") or {}
        out["last_used_at"] = _iso(lu.get("LastUsedDate"))
        out["last_used_service"] = lu.get("ServiceName") if lu.get("LastUsedDate") else None
        out["last_used_region"] = lu.get("Region") if lu.get("LastUsedDate") else None
    return out


def parse_last_accessed(resp) -> dict | None:
    """GetServiceLastAccessedDetails (COMPLETED, all pages merged into ServicesLastAccessed) →
    {"last_authenticated": newest across ALL services or None,
     "services": [{"service", "last_authenticated"}] for the tracked namespaces only}.
    None in → None out (the job was denied/failed/timed out: not readable)."""
    if resp is None:
        return None
    services = (resp or {}).get("ServicesLastAccessed") or []
    tracked = [{"service": s.get("ServiceNamespace"),
                "last_authenticated": _iso(s.get("LastAuthenticated"))}
               for s in services if s.get("ServiceNamespace") in _TRACKED_SERVICES]
    return {
        "job_status": (resp or {}).get("JobStatus"),
        "last_authenticated": _newest(s.get("LastAuthenticated") for s in services),
        "services": tracked,
    }


def parse_cloudtrail_events(resp) -> dict | None:
    """cloudtrail:LookupEvents response → {"last_event_at": newest EventTime or None,
    "events": n}. None in (denied) → None out."""
    if resp is None:
        return None
    events = (resp or {}).get("Events") or []
    return {"last_event_at": _newest(e.get("EventTime") for e in events),
            "events": len(events)}


def last_used_summary(raw: dict) -> dict:
    """{"last_used_at": newest signal or None, "last_used_source": which} over the readable
    signals on an aws_iam_user/aws_iam_role raw dict — or {} when NO signal was readable, so
    the keys stay absent and nothing downstream mistakes "denied" for "never used"."""
    candidates = []   # (source, iso|None)
    if raw.get("access_advisor_readable"):
        candidates.append(("iam_access_advisor", raw.get("access_advisor_last_authenticated")))
    for k in raw.get("access_keys") or []:
        if k.get("last_used_readable"):
            candidates.append(("access_key", k.get("last_used_at")))
    if raw.get("role_last_used_readable"):
        candidates.append(("role_last_used", raw.get("role_last_used_at")))
    if raw.get("cloudtrail_readable"):
        candidates.append(("cloudtrail", raw.get("last_event_at")))
    if not candidates:
        return {}
    best_src, best, best_dt = "none", None, None
    for src, v in candidates:
        dt = _parse_iso(v)
        if dt is not None and (best_dt is None or dt > best_dt):
            best_src, best, best_dt = src, _iso(v), dt
    return {"last_used_at": best, "last_used_source": best_src}


def _principal_raw(kind_word: str, rec: dict, *, tags, last_accessed, cloudtrail) -> dict:
    raw = {
        "arn": rec.get("Arn"),
        "account": arn_account(rec.get("Arn")),
        f"{kind_word}_id": rec.get("UserId") if kind_word == "user" else rec.get("RoleId"),
        "path": rec.get("Path"),
        "created_at": _iso(rec.get("CreateDate")),
        "access_advisor_readable": last_accessed is not None,
        "cloudtrail_readable": None if cloudtrail == "unread" else cloudtrail is not None,
    }
    if last_accessed is not None:
        raw["access_advisor_last_authenticated"] = last_accessed.get("last_authenticated")
        raw["last_used_services"] = last_accessed.get("services") or []
    if cloudtrail not in (None, "unread"):
        raw["last_event_at"] = cloudtrail.get("last_event_at")
    return _with_owner(raw, tags)


def parse_iam_user(user: dict, *, access_keys, tags, last_accessed, cloudtrail="unread") -> Resource:
    """One IAM user → aws_iam_user. `access_keys` is a list of parse_access_key dicts, or
    None when ListAccessKeys was denied; `tags` None when ListUserTags was denied;
    `last_accessed` a parse_last_accessed dict or None; `cloudtrail` a parse_cloudtrail_events
    dict, None (denied) or the default "unread" (the CloudTrail pass has not run yet)."""
    name = str(user.get("UserName"))
    raw = _principal_raw("user", user, tags=tags, last_accessed=last_accessed,
                         cloudtrail=cloudtrail)
    raw.update({
        "user_name": name,
        "password_last_used": _iso(user.get("PasswordLastUsed")),
        "access_keys_readable": access_keys is not None,
        "access_keys": list(access_keys or []),
    })
    raw.update(last_used_summary(raw))
    labels = {"service": "iam", "identity_type": "iam_user", "account": raw["account"]}
    if raw.get("owner"):
        labels["owner_label"] = raw["owner"]["label"]
    return Resource(kind="aws_iam_user", name=name,
                    ext_id=user.get("Arn") or f"iam-user-{name}", labels=labels, raw=raw)


def parse_iam_role(role: dict, *, tags, last_accessed, cloudtrail="unread",
                   last_used_readable=True) -> Resource:
    """One IAM role (the GetRole record, which carries RoleLastUsed; ListRoles omits it) →
    aws_iam_role. `last_used_readable=False` means GetRole was denied and only the ListRoles
    record is in hand, so RoleLastUsed is unknown rather than 'never'."""
    name = str(role.get("RoleName"))
    raw = _principal_raw("role", role, tags=tags, last_accessed=last_accessed,
                         cloudtrail=cloudtrail)
    rlu = role.get("RoleLastUsed") or {}
    raw.update({
        "role_name": name,
        "service_linked": str(role.get("Path") or "").startswith("/aws-service-role/"),
        "role_last_used_readable": bool(last_used_readable),
    })
    if last_used_readable:
        raw["role_last_used_at"] = _iso(rlu.get("LastUsedDate"))
        raw["role_last_used_region"] = rlu.get("Region") if rlu.get("LastUsedDate") else None
    raw.update(last_used_summary(raw))
    labels = {"service": "iam", "identity_type": "iam_role", "account": raw["account"]}
    if raw.get("owner"):
        labels["owner_label"] = raw["owner"]["label"]
    return Resource(kind="aws_iam_role", name=name,
                    ext_id=role.get("Arn") or f"iam-role-{name}", labels=labels, raw=raw)


# ── collection: boto3 in, per-service isolation ──────────────────────────────
_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                 "AuthorizationError", "NotAuthorized", "UnauthorizedException"}


def _error_text(exc) -> str:
    """The ClientError's AWS error code, or the exception itself when it carries none."""
    code = ""
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = (resp.get("Error") or {}).get("Code") or ""
    return code or f"{type(exc).__name__}: {exc}"


def _outcome_for(exc) -> dict:
    """A ClientError → the honest per-service record. AccessDenied is a distinct outcome
    because detect/aws.py must surface it as a coverage gap, not an operational error."""
    text = _error_text(exc)
    return {"outcome": "access_denied" if text in _DENIED_CODES else "error", "error": text}


def _gap(parent, child: str, exc) -> dict:
    """A CHILD read that failed inside a (service, region) whose own List* succeeded.

    Per-service isolation alone is not enough: swallowing a child failure to []/None leaves
    outcomes[service] reading {"outcome": "ok"}, so AWS.ACCOUNT.SERVICE_NOT_ASSESSED reports
    full coverage over resources that were never collected. These records are what that rule
    names. Only failures NOT already visible on a collected resource are recorded here —
    a gap that some per-resource rule already files must stay filed exactly once."""
    return {"parent": str(parent), "child": child, "error": _error_text(exc)}


def _collect_sqs(session, region: str) -> tuple:
    sqs = session.client("sqs", region_name=region)
    resources = []
    for page in sqs.get_paginator("list_queues").paginate():
        for url in page.get("QueueUrls") or []:
            try:
                attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
            except Exception:
                attrs = None   # attributes denied for THIS queue — recorded, not raised
            try:
                tags = sqs.list_queue_tags(QueueUrl=url).get("Tags") or {}
            except Exception:
                tags = None    # owner attribution only: tags_readable=False rides on the queue
            resources.append(parse_queue(region, url, attrs, tags=tags))
    # No gap records: attributes_readable=False rides on the queue itself and the SQS rules
    # file it per resource.
    return resources, [], []


def _collect_sns(session, region: str) -> tuple:
    sns = session.client("sns", region_name=region)
    resources, edges, gaps = [], [], []
    for page in sns.get_paginator("list_topics").paginate():
        for t in page.get("Topics") or []:
            arn = t.get("TopicArn")
            if not arn:
                continue
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
            except Exception:
                attrs = None
            # Subscriptions are listed BEFORE the topic is parsed so their readability is part
            # of the topic resource rather than a fact lost in an except branch. A partial page
            # is kept: what was read is real, and the flag still says the list is incomplete.
            subs, subs_readable = [], True
            try:
                for spage in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=arn):
                    subs.extend(spage.get("Subscriptions") or [])
            except Exception as e:
                subs_readable = False
                gaps.append(_gap(arn, "subscriptions", e))
            try:
                tags = sns.list_tags_for_resource(ResourceArn=arn).get("Tags") or []
            except Exception:
                tags = None    # owner attribution only; rides on the topic as tags_readable
            topic = parse_topic(region, arn, attrs, subscriptions_readable=subs_readable,
                                tags=tags)
            resources.append(topic)
            for s in subs:
                sub = parse_subscription(region, s)
                resources.append(sub)
                edges.append(Edge(src_ext_id=topic.ext_id, dst_ext_id=sub.ext_id,
                                  kind="delivers_to"))
    return resources, edges, gaps


def _collect_events(session, region: str) -> tuple:
    events = session.client("events", region_name=region)
    resources, edges, gaps = [], [], []

    buses, token = [], None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = events.list_event_buses(**kwargs)
        buses.extend(page.get("EventBuses") or [])
        token = page.get("NextToken")
        if not token:
            break

    for bus in buses:
        name = bus.get("Name")
        policy = bus.get("Policy")
        if policy is not None:
            policy_readable = True          # list_event_buses carried it
        elif name:
            try:
                policy = events.describe_event_bus(Name=name).get("Policy")
                policy_readable = True      # authoritative: this bus really has no policy
            except Exception:
                policy_readable = False     # filed by AWS.EVENTBRIDGE.BUS_POLICY_PUBLIC
        else:
            policy_readable = None          # nameless bus: the read could not even be issued
        bus_res = parse_bus(region, bus, policy, policy_readable=policy_readable)
        resources.append(bus_res)

        token = None
        while True:
            kwargs = {"EventBusName": name}
            if token:
                kwargs["NextToken"] = token
            try:
                page = events.list_rules(**kwargs)
            except Exception as e:
                # The bus survives, but its rules — and every routing target behind them —
                # were never collected, and no rule resource exists to carry that fact.
                gaps.append(_gap(f"bus {name}", "rules", e))
                break
            for rule in page.get("Rules") or []:
                try:
                    targets = events.list_targets_by_rule(
                        Rule=rule.get("Name"), EventBusName=name).get("Targets") or []
                except Exception:
                    targets = None   # filed by AWS.EVENTBRIDGE.CROSS_ACCOUNT_TARGET
                rs, es = parse_rule(region, bus_res.ext_id, rule, targets)
                resources.extend(rs)
                edges.extend(es)
            token = page.get("NextToken")
            if not token:
                break
    return resources, edges, gaps


def _collect_msk(session, region: str) -> tuple:
    kafka = session.client("kafka", region_name=region)
    resources = []
    for page in kafka.get_paginator("list_clusters_v2").paginate():
        for c in page.get("ClusterInfoList") or []:
            resources.append(parse_msk_cluster(region, c))
    return resources, [], []


def _collect_apigw_v1(session, region: str) -> tuple:
    apigw = session.client("apigateway", region_name=region)
    resources, edges, gaps = [], [], []
    for page in apigw.get_paginator("get_rest_apis").paginate():
        for api in page.get("items") or []:
            api_id = api.get("id")
            try:
                stages = apigw.get_stages(restApiId=api_id).get("item") or []
            except Exception as e:
                # No aws_api_stage resource is emitted, so STAGE_LOGGING_DISABLED and
                # STAGE_NO_WAF have nothing to run on and report nothing at all.
                stages = None
                gaps.append(_gap(f"api {api_id}", "stages", e))
            try:
                authorizers = apigw.get_authorizers(restApiId=api_id).get("items") or []
            except Exception as e:
                authorizers = None
                gaps.append(_gap(f"api {api_id}", "authorizers", e))
            items = []
            try:
                for rpage in apigw.get_paginator("get_resources").paginate(
                        restApiId=api_id, embed=["methods"]):
                    items.extend(rpage.get("items") or [])
            except Exception:
                items = None   # filed by AWS.APIGW.ROUTE_NO_AUTHORIZER
            rs, es = parse_api_v1(region, api, stages, authorizers, items)
            resources.extend(rs)
            edges.extend(es)
    return resources, edges, gaps


def _collect_apigw_v2(session, region: str) -> tuple:
    apigw = session.client("apigatewayv2", region_name=region)
    resources, edges, gaps = [], [], []

    def _pages(fn, key, **kw):
        out, token = [], None
        while True:
            kwargs = dict(kw)
            if token:
                kwargs["NextToken"] = token
            page = fn(**kwargs)
            out.extend(page.get(key) or [])
            token = page.get("NextToken")
            if not token:
                break
        return out

    for api in _pages(apigw.get_apis, "Items"):
        api_id = api.get("ApiId")
        try:
            stages = _pages(apigw.get_stages, "Items", ApiId=api_id)
        except Exception as e:
            stages = None   # no aws_api_stage emitted — the stage rules never run
            gaps.append(_gap(f"api {api_id}", "stages", e))
        try:
            routes = _pages(apigw.get_routes, "Items", ApiId=api_id)
        except Exception:
            routes = None   # filed by AWS.APIGW.ROUTE_NO_AUTHORIZER
        try:
            authorizers = _pages(apigw.get_authorizers, "Items", ApiId=api_id)
        except Exception as e:
            authorizers = None
            gaps.append(_gap(f"api {api_id}", "authorizers", e))
        rs, es = parse_api_v2(region, api, stages, routes, authorizers)
        resources.extend(rs)
        edges.extend(es)
    return resources, edges, gaps


# ── IAM (global) + CloudTrail (per region): last-used and owner telemetry ─────
_IAM_MAX_PRINCIPALS = 500        # users + roles enumerated per scan; beyond → truncated=True
_ADVISOR_TRIES = 10              # GetServiceLastAccessedDetails polls per principal
_ADVISOR_SLEEP = 0.5             # seconds between polls (injected: tests pass a no-op)
_CLOUDTRAIL_DAYS = 90            # LookupEvents window
_CLOUDTRAIL_MAX_RESULTS = 5      # per principal; only the newest EventTime is kept
_CLOUDTRAIL_MAX_LOOKUPS = 50     # per region (LookupEvents is throttled at ~2 TPS)


def _iam_pages(fn, key: str, **kw) -> list:
    """Marker-paginated IAM list call, capped at _IAM_MAX_PRINCIPALS → (items, truncated)."""
    out, marker = [], None
    while True:
        kwargs = dict(kw)
        if marker:
            kwargs["Marker"] = marker
        page = fn(**kwargs)
        out.extend(page.get(key) or [])
        if len(out) >= _IAM_MAX_PRINCIPALS:
            return out[:_IAM_MAX_PRINCIPALS], True
        if not page.get("IsTruncated"):
            return out, False
        marker = page.get("Marker")


def _access_advisor(iam, arn: str, sleeper):
    """Access Advisor for one principal: generate the job, poll up to _ADVISOR_TRIES times.
    Returns the merged COMPLETED response, or None when the job never completed (timed out /
    FAILED) — the caller records that as a child gap. Denials propagate as exceptions."""
    job_id = iam.generate_service_last_accessed_details(Arn=arn)["JobId"]
    for attempt in range(_ADVISOR_TRIES):
        resp = iam.get_service_last_accessed_details(JobId=job_id)
        status = resp.get("JobStatus")
        if status == "COMPLETED":
            services = list(resp.get("ServicesLastAccessed") or [])
            marker, hops = resp.get("Marker"), 0
            while resp.get("IsTruncated") and marker and hops < 10:
                resp = iam.get_service_last_accessed_details(JobId=job_id, Marker=marker)
                services.extend(resp.get("ServicesLastAccessed") or [])
                marker, hops = resp.get("Marker"), hops + 1
            return {"JobStatus": "COMPLETED", "ServicesLastAccessed": services}
        if status == "FAILED":
            raise RuntimeError(f"access advisor job failed: "
                               f"{(resp.get('Error') or {}).get('Message') or 'unknown'}")
        if attempt + 1 < _ADVISOR_TRIES:
            sleeper(_ADVISOR_SLEEP)
    return None


def _own_policy_principals(resources: list, own_account: str) -> tuple:
    """(user ARNs, role ARNs) of OUR account named as principals in collected resource
    policies — the principals that must be enumerated even when the listing is truncated."""
    users, roles = set(), set()
    for r in resources:
        if r.kind not in _POLICY_KINDS:
            continue
        for stmt in policy_statements((r.raw or {}).get("policy")):
            for p in principal_entries(stmt):
                if not (p.startswith("arn:") and own_account and arn_account(p) == own_account):
                    continue
                if ":user/" in p:
                    users.add(p)
                elif ":role/" in p:
                    roles.add(p)
    return users, roles


def _collect_iam(session, region: str, own_account: str = "", policy_resources=(),
                 sleeper=time.sleep) -> tuple:
    """One GLOBAL pass over IAM users and roles → (resources, edges, gaps, meta).

    Per principal: ListAccessKeys + GetAccessKeyLastUsed per key (users), GetRole for
    RoleLastUsed (roles), ListUserTags/ListRoleTags, and Access Advisor. Each child read is
    isolated: a denial lands as a child gap and the corresponding raw key is left absent
    (never defaulted to "never used"). Service-linked roles are skipped (AWS-managed; the
    customer cannot decommission them). `meta` carries truncation + skip counts for the
    outcome record."""
    iam = session.client("iam", region_name=region)
    resources, gaps = [], []
    meta = {"truncated": False, "service_linked_skipped": 0}

    users, trunc_u = _iam_pages(iam.list_users, "Users")
    roles, trunc_r = _iam_pages(iam.list_roles, "Roles")
    meta["truncated"] = trunc_u or trunc_r

    # Principals a resource policy names must be covered even past the cap.
    want_users, want_roles = _own_policy_principals(list(policy_resources), own_account)
    listed_u = {u.get("Arn") for u in users}
    listed_r = {r.get("Arn") for r in roles}
    for arn in sorted(want_users - listed_u):
        try:
            users.append(iam.get_user(UserName=arn.rsplit("/", 1)[-1])["User"])
        except Exception as e:
            gaps.append(_gap(f"user {arn.rsplit('/', 1)[-1]}", "get_user", e))
    for arn in sorted(want_roles - listed_r):
        try:
            roles.append(iam.get_role(RoleName=arn.rsplit("/", 1)[-1])["Role"])
        except Exception as e:
            gaps.append(_gap(f"role {arn.rsplit('/', 1)[-1]}", "get_role", e))

    def advisor(label, arn):
        try:
            resp = _access_advisor(iam, arn, sleeper)
        except Exception as e:
            gaps.append(_gap(label, "access_advisor", e))
            return None
        if resp is None:
            gaps.append(_gap(label, "access_advisor", RuntimeError("job did not complete")))
            return None
        return parse_last_accessed(resp)

    for u in users:
        name = u.get("UserName")
        label = f"user {name}"
        try:
            metas, _ = _iam_pages(iam.list_access_keys, "AccessKeyMetadata", UserName=name)
            keys = []
            for m in metas:
                try:
                    lu = iam.get_access_key_last_used(AccessKeyId=m.get("AccessKeyId"))
                except Exception as e:
                    lu = None
                    gaps.append(_gap(label, "access_key_last_used", e))
                keys.append(parse_access_key(m, lu))
        except Exception as e:
            keys = None
            gaps.append(_gap(label, "access_keys", e))
        try:
            tags = iam.list_user_tags(UserName=name).get("Tags") or []
        except Exception as e:
            tags = None
            gaps.append(_gap(label, "tags", e))
        resources.append(parse_iam_user(u, access_keys=keys, tags=tags,
                                        last_accessed=advisor(label, u.get("Arn"))))

    for r in roles:
        name = r.get("RoleName")
        if str(r.get("Path") or "").startswith("/aws-service-role/"):
            meta["service_linked_skipped"] += 1
            continue
        label = f"role {name}"
        rec, last_used_readable = r, True
        if "RoleLastUsed" not in r:          # ListRoles omits it; GetRole carries it
            try:
                rec = iam.get_role(RoleName=name)["Role"]
            except Exception as e:
                last_used_readable = False
                gaps.append(_gap(label, "get_role", e))
        try:
            tags = iam.list_role_tags(RoleName=name).get("Tags") or []
        except Exception as e:
            tags = None
            gaps.append(_gap(label, "tags", e))
        resources.append(parse_iam_role(rec, tags=tags, last_accessed=advisor(label, r.get("Arn")),
                                        last_used_readable=last_used_readable))
    return resources, [], gaps, meta


def _cloudtrail_username(r: Resource) -> str:
    """The LookupEvents Username attribute: the IAM user name, or the role name (CloudTrail
    records assumed-role sessions under the session name, so this is best-effort for roles —
    RoleLastUsed is the authoritative role signal)."""
    raw = r.raw or {}
    return str(raw.get("user_name") or raw.get("role_name") or r.name)


def _collect_cloudtrail(session, region: str, principals: list, now=None) -> tuple:
    """Per-region CloudTrail LookupEvents for the collected IAM principals → (gaps, meta).
    Mutates each principal resource in place: raw.last_event_at (newest across regions),
    raw.cloudtrail_readable, and the recomputed last_used_at/last_used_source. Bounded to
    _CLOUDTRAIL_MAX_LOOKUPS per region, principals with NO other last-used signal first. The
    first AccessDenied is raised (it will deny every lookup) so the caller records the whole
    region as access_denied; other per-principal failures are child gaps."""
    ct = session.client("cloudtrail", region_name=region)
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=_CLOUDTRAIL_DAYS)
    ordered = sorted(principals, key=lambda r: ((r.raw or {}).get("last_used_at") is not None,
                                                r.name))
    gaps, meta = [], {"lookups": 0, "truncated": len(ordered) > _CLOUDTRAIL_MAX_LOOKUPS}
    for r in ordered[:_CLOUDTRAIL_MAX_LOOKUPS]:
        raw = r.raw
        try:
            resp = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "Username",
                                   "AttributeValue": _cloudtrail_username(r)}],
                StartTime=start, EndTime=now, MaxResults=_CLOUDTRAIL_MAX_RESULTS)
        except Exception as e:
            if _error_text(e) in _DENIED_CODES:
                raise
            gaps.append(_gap(_cloudtrail_username(r), "lookup_events", e))
            if raw.get("cloudtrail_readable") is None:
                raw["cloudtrail_readable"] = False
            continue
        meta["lookups"] += 1
        parsed = parse_cloudtrail_events(resp)
        raw["cloudtrail_readable"] = True
        raw["last_event_at"] = _newest([raw.get("last_event_at"), parsed["last_event_at"]])
        raw.update(last_used_summary(raw))
    return gaps, meta


_SERVICES = (
    ("sqs", _collect_sqs),
    ("sns", _collect_sns),
    ("events", _collect_events),
    ("msk", _collect_msk),
    ("apigateway", _collect_apigw_v1),
    ("apigatewayv2", _collect_apigw_v2),
)


def _build_session(config: dict):
    """(session, auth_method). Precedence: explicit key pair > named profile > default chain;
    then AssumeRole on top when role_arn is set — the agentless cross-account path. All
    credential material stays inside the returned session; nothing is copied to a Resource."""
    import boto3

    regions = [r.strip() for r in str(config.get("regions") or "").split(",") if r.strip()]
    if not regions:
        raise SystemExit("aws connector requires config['regions'] (comma-separated)")

    ak = (config.get("access_key_id") or "").strip()
    sk = (config.get("secret_access_key") or "").strip()
    profile = (config.get("profile") or "").strip()
    if ak and sk:
        session = boto3.session.Session(
            aws_access_key_id=ak, aws_secret_access_key=sk,
            aws_session_token=(config.get("session_token") or "").strip() or None)
        method = "access_key"
    elif profile:
        session = boto3.session.Session(profile_name=profile)
        method = "profile"
    else:
        session = boto3.session.Session()
        method = "default_chain"

    role_arn = (config.get("role_arn") or "").strip()
    if role_arn:
        sts = session.client("sts", region_name=regions[0])
        kwargs = {"RoleArn": role_arn, "RoleSessionName": "vectasec-readonly-scan"}
        external_id = (config.get("external_id") or "").strip()
        if external_id:
            kwargs["ExternalId"] = external_id
        creds = sts.assume_role(**kwargs)["Credentials"]
        session = boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"])
        method = "assume_role"
    return session, method, regions


@connector("aws", fields=[
    ConnectorField("regions", "Regions", required=True, placeholder="us-east-1,eu-west-1",
                   help="Comma-separated AWS regions to scan. Every call is read-only "
                        "(List*/Get*/Describe*); the SecurityAudit or ReadOnlyAccess managed "
                        "policy is sufficient. Last-used telemetry additionally uses "
                        "iam:ListUsers/ListRoles/GetRole/ListAccessKeys/GetAccessKeyLastUsed, "
                        "iam:Generate+GetServiceLastAccessedDetails (Access Advisor, global) "
                        "and cloudtrail:LookupEvents (per region); owner labels are read from "
                        "tags (owner/team/service/contact/email/vectasec:owner/created-by) via "
                        "iam:ListUserTags/ListRoleTags, sqs:ListQueueTags and "
                        "sns:ListTagsForResource. A denied action is recorded as a coverage "
                        "gap, never as a clean result. See deploy/aws/ for the role template."),
    ConnectorField("role_arn", "Role ARN",
                   placeholder="arn:aws:iam::123456789012:role/vectasec-readonly",
                   help="Cross-account read-only role to assume (the agentless path). Leave "
                        "empty to use a profile or key pair instead."),
    ConnectorField("external_id", "External ID",
                   help="ExternalId condition on the role's trust policy, if it sets one."),
    ConnectorField("profile", "Named profile", placeholder="prod-readonly",
                   help="AWS shared-config profile to use instead of a role or key pair."),
    ConnectorField("access_key_id", "Access key ID",
                   help="Static credential pair — prefer the cross-account role."),
    ConnectorField("secret_access_key", "Secret access key", secret=True,
                   help="Used to open the session, never persisted into any resource."),
    ConnectorField("session_token", "Session token", secret=True,
                   help="Only for temporary (STS) credentials."),
])
def collect(config: dict) -> Collected:
    session, auth_method, regions = _build_session(config)

    # Who we are — also proves the credentials work before fanning out. sts is global-ish;
    # a failure here is an auth failure and rightly fails the scan.
    sts = session.client("sts", region_name=regions[0])
    ident = sts.get_caller_identity()
    account_id = ident.get("Account") or ""

    resources: list[Resource] = []
    edges: list[Edge] = []
    outcomes: dict[str, dict] = {}

    # Per-(service, region) isolation: a denied service records honestly and the scan goes on.
    for region in regions:
        for service, fn in _SERVICES:
            key = f"{service}:{region}"
            try:
                rs, es, gaps = fn(session, region)
                resources.extend(rs)
                edges.extend(es)
                outcomes[key] = {"outcome": "ok", "error": None, "resources": len(rs)}
                if gaps:
                    # The service listed, but not everything under it did. Without this the
                    # record reads {"outcome": "ok"} and the coverage rule claims a service
                    # was fully assessed over children that were never collected.
                    outcomes[key]["child_gaps"] = gaps
            except Exception as e:
                outcomes[key] = _outcome_for(e)

    # IAM is global: one pass, from the first region's endpoint. Resource-policy principals
    # collected above are passed in so our own users/roles named there are always covered.
    principals: list[Resource] = []
    try:
        rs, es, gaps, meta = _collect_iam(session, regions[0], account_id, resources)
        principals = rs
        resources.extend(rs)
        edges.extend(es)
        outcomes["iam:global"] = {"outcome": "ok", "error": None, "resources": len(rs), **meta}
        if gaps:
            outcomes["iam:global"]["child_gaps"] = gaps
    except Exception as e:
        outcomes["iam:global"] = _outcome_for(e)

    # CloudTrail is regional; a denied LookupEvents is its own coverage gap — the IAM data
    # above has already landed and is not voided by it.
    for region in regions:
        key = f"cloudtrail:{region}"
        if not principals:
            outcomes[key] = {"outcome": "ok", "error": None, "resources": 0, "lookups": 0,
                             "skipped": "no IAM principals collected"}
            continue
        try:
            gaps, meta = _collect_cloudtrail(session, region, principals)
            outcomes[key] = {"outcome": "ok", "error": None, "resources": 0, **meta}
            if gaps:
                outcomes[key]["child_gaps"] = gaps
        except Exception as e:
            outcomes[key] = _outcome_for(e)

    account = Resource(
        kind="aws_account",
        name=account_id or "aws-account",
        ext_id=f"aws-account-{account_id or 'unknown'}",
        labels={"service": "sts", "auth_method": auth_method},
        raw={
            "account_id": account_id,
            "caller_arn": ident.get("Arn"),
            "auth_method": auth_method,     # never the credential itself
            "regions": regions,
            "collection": outcomes,
        },
    )
    return Collected(resources=[account] + resources, edges=edges)


# ── NHI: principals named in resource policies ───────────────────────────────
_POLICY_KINDS = ("aws_sqs_queue", "aws_sns_topic", "aws_event_bus")


def _classify_principal(principal: str, own_account: str) -> tuple:
    """(display_name, identity_type, external). '*' is the wildcard principal — its
    identity_type 'wildcard' lands in labels.identity_type, which is how the console and
    the NHI rulepack see it flagged."""
    p = str(principal)
    if p == "*":
        return "*", "wildcard", True
    if p.endswith(".amazonaws.com"):
        return p, "service_principal", False
    if p.startswith("arn:"):
        acct = arn_account(p)
        return p, "iam_principal", bool(acct and acct != own_account)
    if p.isdigit():
        return f"arn:aws:iam::{p}:root", "aws_account", p != own_account
    return p, "iam_principal", False


_IAM_KINDS = ("aws_iam_user", "aws_iam_role")


def _telemetry_labels(raw: dict) -> dict:
    """labels.last_used_at / last_used_source / owner_label — the console reads labels only,
    never raw, on identity/credential rows. last_used_at is the ISO string, "never" when the
    signal was readable and empty, and ABSENT when it was not readable."""
    labels = {}
    if "last_used_at" in raw:
        labels["last_used_at"] = raw.get("last_used_at") or "never"
        if raw.get("last_used_source"):
            labels["last_used_source"] = raw["last_used_source"]
    if raw.get("owner_label"):
        labels["owner_label"] = raw["owner_label"]
    return labels


def _slug_safe(s) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in str(s or "")).strip("-") or "key"


def _iam_identity(r: Resource, account_ext: str) -> tuple:
    """aws_iam_user / aws_iam_role → (identity, [credentials], [edges]). One `access_key`
    credential per key (ext_id made unique per key — _mk_credential's default would collide
    for two keys on one user), one `role_session` credential per role."""
    raw = r.raw or {}
    is_user = r.kind == "aws_iam_user"
    owner = raw.get("owner") or {}
    extra = {
        "arn": raw.get("arn"), "account": raw.get("account"),
        "created_at": raw.get("created_at"),
        "resource_ext_id": r.ext_id,
        "last_used_services": raw.get("last_used_services"),
    }
    if owner:
        extra["owner"] = owner
        extra["owner_label"] = owner.get("label")
    for k in ("last_used_at", "last_used_source", "last_event_at"):
        if k in raw:
            extra[k] = raw[k]
    idr = _mk_identity("aws", "iam_user" if is_user else "iam_role", str(raw.get("arn") or r.name),
                       external=False, source_ext=account_ext, extra=extra)
    idr.labels.update(_telemetry_labels(idr.raw))

    creds, edges = [], []
    if is_user:
        for k in raw.get("access_keys") or []:
            cextra = {"created_at": k.get("created_at"), "status": k.get("status"),
                      "identity_arn": raw.get("arn")}
            if "last_used_at" in k:            # readable; None = key exists, never used
                cextra["last_used_at"] = k.get("last_used_at")
                cextra["last_used_source"] = "access_key"
                cextra["last_used_service"] = k.get("last_used_service")
                cextra["last_used_region"] = k.get("last_used_region")
            if owner:
                cextra["owner_label"] = owner.get("label")
            c = _mk_credential("aws", idr.ext_id, "access_key", name=k.get("key_id_masked") or "key",
                               hashing="n/a", present=True, plaintext=False, extra=cextra)
            c.ext_id = f"{c.ext_id}:{k.get('key_ref') or _slug_safe(k.get('key_id_masked'))}"
            c.labels.update(_telemetry_labels(c.raw))
            creds.append(c)
    else:
        cextra = {"created_at": raw.get("created_at"), "identity_arn": raw.get("arn")}
        if raw.get("role_last_used_readable"):
            cextra["last_used_at"] = raw.get("role_last_used_at")
            cextra["last_used_source"] = "role_last_used"
            cextra["last_used_region"] = raw.get("role_last_used_region")
        if owner:
            cextra["owner_label"] = owner.get("label")
        c = _mk_credential("aws", idr.ext_id, "role_session",
                           name=f"{raw.get('role_name') or r.name}:role-session",
                           hashing="n/a", present=True, plaintext=False, extra=cextra)
        c.labels.update(_telemetry_labels(c.raw))
        creds.append(c)
    for c in creds:
        edges.append(Edge(src_ext_id=c.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
    return idr, creds, edges


@identity_extractor("aws")
def _from_aws(resources: list) -> tuple:
    """Two sources → the normalized NHI model.

    1. IAM users/roles the global IAM pass collected → one identity each (so the Access page
       lists every principal that holds a key, policy-named or not), one `access_key`
       credential per key / one `role_session` credential per role carrying created_at and —
       when readable — last_used_at (None = never used). Owner label and last-used ride on
       labels as well as raw.
    2. Principals appearing in SQS/SNS/EventBridge resource policies → one identity per
       principal (deduped, and merged with #1 when the ARN is one of ours), one grant per
       (principal, action, resource) with edges grant --granted_to--> identity and
       grant --grants_access--> the collected resource."""
    out: list[Resource] = []
    edges: list[Edge] = []
    account = next((r for r in resources if r.kind == "aws_account"), None)
    own_account = str((account.raw or {}).get("account_id") or "") if account else ""
    account_ext = account.ext_id if account else ""
    seen: dict[str, Resource] = {}
    seen_grants: set[str] = set()   # two statements can restate one (principal, action, target)

    for r in resources:
        if r.kind not in _IAM_KINDS:
            continue
        idr, creds, es = _iam_identity(r, account_ext)
        if idr.raw["principal"] in seen:
            continue
        seen[idr.raw["principal"]] = idr
        out.append(idr)
        out.extend(creds)
        edges.extend(es)

    for r in resources:
        if r.kind not in _POLICY_KINDS:
            continue
        policy = (r.raw or {}).get("policy")
        for stmt in policy_statements(policy):
            if str(stmt.get("Effect", "")).lower() != "allow":
                continue   # a Deny narrows access; it grants no identity anything
            conditioned = bool(stmt.get("Condition"))
            for principal in principal_entries(stmt):
                name, itype, external = _classify_principal(principal, own_account)
                idr = seen.get(name)
                if idr is None:
                    idr = _mk_identity(
                        "aws", itype, name, external=external,
                        tags=(["wildcard_principal"] if itype == "wildcard" else []),
                        source_ext=r.ext_id)
                    seen[name] = idr
                    out.append(idr)
                for action in statement_actions(stmt) or ["*"]:
                    g = _mk_grant(
                        "aws", idr.ext_id, action.lower(), r.ext_id,
                        wildcard=(itype == "wildcard" or action == "*" or action.endswith(":*")),
                        permission="allow",
                        extra={"conditioned": conditioned, "resource_kind": r.kind})
                    if g.ext_id in seen_grants:
                        continue
                    seen_grants.add(g.ext_id)
                    out.append(g)
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id,
                                      kind="granted_to"))
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=r.ext_id,
                                      kind="grants_access"))
    return out, edges
