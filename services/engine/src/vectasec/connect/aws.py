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
aws_msk_cluster, aws_api, aws_api_stage, …) so no other rulepack ever runs against an AWS
resource by accident — the same reason connect/redis.py refuses to reuse `broker`.
"""
import json

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_grant, _mk_identity, identity_extractor
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
def parse_queue(region: str, queue_url: str, attrs) -> Resource:
    """One SQS queue from get_queue_attributes(AttributeNames=['All']). attrs=None means the
    per-queue attribute call itself failed (recorded, so detectors answer not-assessable
    instead of reading absence as a clean pass)."""
    name = queue_url.rstrip("/").rsplit("/", 1)[-1]
    a = attrs or {}
    arn = a.get("QueueArn") or f"sqs-{region}-{name}"
    return Resource(
        kind="aws_sqs_queue",
        name=name,
        ext_id=arn,
        namespace=region,
        labels={"region": region, "service": "sqs"},
        raw={
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
        },
    )


def parse_topic(region: str, topic_arn: str, attrs, subscriptions_readable: bool = True) -> Resource:
    """One SNS topic. `subscriptions_readable` False means ListSubscriptionsByTopic failed for
    THIS topic: the subscription resources are missing, so a topic with no delivery endpoints
    and a topic whose endpoints were denied would otherwise look identical."""
    a = attrs or {}
    return Resource(
        kind="aws_sns_topic",
        name=topic_arn.rsplit(":", 1)[-1],
        ext_id=topic_arn,
        namespace=region,
        labels={"region": region, "service": "sns"},
        raw={
            "topic_arn": topic_arn,
            "region": region,
            "account": arn_account(topic_arn),
            "attributes_readable": attrs is not None,
            "subscriptions_readable": subscriptions_readable,
            "policy": _parse_json(a.get("Policy")),
            "kms_master_key_id": a.get("KmsMasterKeyId"),
            "subscriptions_confirmed": a.get("SubscriptionsConfirmed"),
        },
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
        raw={
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
        },
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
        raw={
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
        },
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
        raw={
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
        },
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
            resources.append(parse_queue(region, url, attrs))
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
            topic = parse_topic(region, arn, attrs, subscriptions_readable=subs_readable)
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
                        "policy is sufficient."),
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


@identity_extractor("aws")
def _from_aws(resources: list) -> tuple:
    """Principals appearing in SQS/SNS/EventBridge resource policies → the normalized NHI
    model: one identity per principal (deduped across resources), one grant per
    (principal, action, resource) with edges grant --granted_to--> identity and
    grant --grants_access--> the collected resource. AWS resource policies expose no
    credential material, so no credential resources are emitted — absence, not silence."""
    out: list[Resource] = []
    edges: list[Edge] = []
    own_account = next((str((r.raw or {}).get("account_id") or "")
                        for r in resources if r.kind == "aws_account"), "")
    seen: dict[str, Resource] = {}
    seen_grants: set[str] = set()   # two statements can restate one (principal, action, target)

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
