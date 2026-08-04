"""Azure agentless connector — read-only ARM REST, one connection fans out to four services.

Auth is a client-credentials OAuth grant against login.microsoftonline.com (an Entra app
registration with the Reader role on the subscription is sufficient), then plain httpx GETs
against management.azure.com — no Azure SDK, matching the repo's dependency-light style
(kong/rabbitmq are the httpx reference). One connection collects the integration-layer
surface of a subscription: Service Bus namespaces (+queues/topics), Event Hubs namespaces
(+hubs/consumer groups/capture), API Management services (+APIs, named-value metadata,
subscriptions), and Logic App workflows (+their triggers).

Three disciplines carried over from connect/aws.py:

  • Secrets are used, never persisted. `client_secret` is ConnectorField secret=True; it buys
    a bearer token inside collect() and is never copied into any Resource. SAS keys and
    connection strings are NEVER fetched — no listKeys/listConnectionStrings/listSecrets POST
    is ever issued. Only authorization-rule NAMES and RIGHTS are read (GET …/authorizationRules),
    which is exactly the grant evidence a posture finding needs. APIM named values are recorded
    as metadata (display name + secret flag), never their values.
  • Per-service error isolation. Each service collection runs in its own try/except: an app
    denied Microsoft.ApiManagement/read records {"outcome": "access_denied"} on the
    azure_subscription resource instead of voiding the whole scan. detect/azure.py turns those
    records into not-assessable coverage-gap findings — never a pass, never a failure.
    Isolation alone is not enough: a CHILD read that fails inside a service that otherwise
    succeeded is recorded too — as a *_readable flag on the parent resource, or as a
    child_gaps entry in the service's outcome record when the child leaves no resource behind.
    Collapsing one to []/None makes "denied" indistinguishable from "none exists", which is
    the secure state.
  • The parse layer (parse_sb_namespace, parse_event_hub, …) is pure: ARM response dicts in,
    Resources out. Tests exercise detectors against parse-layer output from golden fixtures,
    so httpx (and a live tenant) stays out of the test suite and a shape drift between
    connector and rulepack fails a test instead of silently mis-firing in production.

Kinds are DISTINCT (azure_servicebus_namespace, azure_sb_queue, azure_sb_topic,
azure_eventhub_namespace, azure_event_hub, azure_apim, azure_api, azure_logic_app,
azure_subscription) so no other rulepack ever runs against an Azure resource by accident.
Edges: namespace --contains--> queue/topic/hub, apim --exposes--> api.
"""
import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

_ARM = "https://management.azure.com"
_SB_API = "2024-01-01"        # Microsoft.ServiceBus, current stable
_EH_API = "2024-01-01"        # Microsoft.EventHub, current stable
_APIM_API = "2024-05-01"      # Microsoft.ApiManagement, current stable
_LOGIC_API = "2019-05-01"     # Microsoft.Logic, current stable
_STORAGE_API = "2023-01-01"   # Microsoft.Storage (capture-destination posture read)


class _Denied(Exception):
    """ARM answered 401/403 — a permissions gap to record honestly, not an operational error."""
    def __init__(self, status: int, detail: str = ""):
        super().__init__(f"http_{status}{f' {detail}' if detail else ''}")
        self.status = status


def _outcome_for(exc) -> dict:
    if isinstance(exc, _Denied):
        return {"outcome": "access_denied", "error": str(exc)}
    return {"outcome": "error", "error": f"{type(exc).__name__}: {exc}"}


def _error_text(exc) -> str:
    return str(exc) if isinstance(exc, _Denied) else f"{type(exc).__name__}: {exc}"


def _gap(parent, child: str, exc) -> dict:
    """A CHILD read that failed inside a service whose own list call succeeded.

    Per-service isolation alone is not enough: swallowing a child failure to []/None leaves
    outcomes[service] reading {"outcome": "ok"}, so AZURE.SUBSCRIPTION.SERVICE_NOT_ASSESSED
    reports full coverage over resources that were never collected. These records are what
    that rule names. Only failures NOT already visible on a collected resource are recorded
    here — a gap some per-resource rule already files must stay filed exactly once."""
    return {"parent": str(parent), "child": child, "error": _error_text(exc)}


def _ext(arm_id, fallback: str) -> str:
    """ARM ids are case-insensitive and ARM answers with inconsistent casing across APIs, so
    the lowercased id is the stable ext_id (edges must match Resources exactly)."""
    return str(arm_id or fallback).lower()


# ── HTTP layer (kept out of the parse layer and out of the tests) ─────────────
def _get_token(client: httpx.Client, tenant_id: str, client_id: str, client_secret: str) -> str:
    r = client.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={"grant_type": "client_credentials", "client_id": client_id,
              "client_secret": client_secret,
              "scope": "https://management.azure.com/.default"},
    )
    r.raise_for_status()          # an auth failure rightly fails the scan, like AWS sts
    return r.json()["access_token"]


def _arm_get(client: httpx.Client, headers: dict, path: str, api_version: str) -> dict:
    r = client.get(f"{_ARM}{path}", params={"api-version": api_version}, headers=headers)
    if r.status_code in (401, 403):
        raise _Denied(r.status_code)
    r.raise_for_status()
    return r.json()


def _arm_list(client: httpx.Client, headers: dict, path: str, api_version: str) -> list:
    """Collection GET following nextLink (absolute URL carrying its own query string)."""
    out: list = []
    url: str | None = f"{_ARM}{path}"
    params: dict | None = {"api-version": api_version}
    while url:
        r = client.get(url, params=params, headers=headers)
        if r.status_code in (401, 403):
            raise _Denied(r.status_code)
        r.raise_for_status()
        body = r.json()
        out.extend(body.get("value") or [])
        url = body.get("nextLink")
        params = None
    return out


# ── parse layer: ARM response dicts → Resources (pure, no httpx) ──────────────
def _parse_auth_rules(auth_rules) -> list | None:
    """authorizationRules list → [{name, rights}]. None in = unreadable (recorded, so the
    detector answers not-assessable instead of reading absence as 'no SAS rules'). Only the
    rule NAME and RIGHTS survive — keys are never fetched, so there is nothing to drop."""
    if auth_rules is None:
        return None
    return [{"name": r.get("name"),
             "rights": [str(x) for x in (r.get("properties") or {}).get("rights") or []]}
            for r in auth_rules]


def _namespace_raw(ns: dict, auth_rules, service: str) -> dict:
    p = ns.get("properties") or {}
    rules = _parse_auth_rules(auth_rules)
    return {
        "arm_id": ns.get("id"),
        "service": service,
        "location": ns.get("location"),
        "sku": (ns.get("sku") or {}).get("name"),
        # ARM default when the field is absent (older namespaces) is public-enabled.
        "public_network_access": p.get("publicNetworkAccess") or "Enabled",
        "disable_local_auth": bool(p.get("disableLocalAuth")),
        "minimum_tls_version": p.get("minimumTlsVersion"),
        "private_endpoint_connections": len(p.get("privateEndpointConnections") or []),
        "authorization_rules_readable": rules is not None,
        "authorization_rules": rules or [],
    }


def parse_sb_namespace(ns: dict, auth_rules, queues_readable: bool = True,
                       topics_readable: bool = True) -> Resource:
    """One Service Bus namespace. `queues_readable` / `topics_readable` False mean that child
    listing failed: NO azure_sb_queue / azure_sb_topic resource exists for this namespace, so
    every entity rule is silent for want of a subject and the namespace would otherwise read
    as an empty — that is, clean — one."""
    raw = _namespace_raw(ns, auth_rules, "servicebus")
    raw["queues_readable"] = queues_readable
    raw["topics_readable"] = topics_readable
    raw["endpoint"] = (ns.get("properties") or {}).get("serviceBusEndpoint")
    return Resource(
        kind="azure_servicebus_namespace", name=str(ns.get("name")),
        ext_id=_ext(ns.get("id"), f"sb-ns-{ns.get('name')}"),
        namespace=ns.get("location"),
        labels={"service": "servicebus", "location": str(ns.get("location")),
                "sku": str(raw["sku"])},
        raw=raw,
    )


def parse_sb_queue(ns_ext: str, q: dict) -> Resource:
    p = q.get("properties") or {}
    return Resource(
        kind="azure_sb_queue", name=str(q.get("name")),
        ext_id=_ext(q.get("id"), f"{ns_ext}/queues/{q.get('name')}"),
        labels={"service": "servicebus"},
        raw={
            "arm_id": q.get("id"),
            "namespace_ext": ns_ext,
            "status": p.get("status"),
            "dead_lettering_on_message_expiration": bool(p.get("deadLetteringOnMessageExpiration")),
            "max_delivery_count": p.get("maxDeliveryCount"),
            "requires_duplicate_detection": bool(p.get("requiresDuplicateDetection")),
            "requires_session": bool(p.get("requiresSession")),
        },
    )


def parse_sb_topic(ns_ext: str, t: dict) -> Resource:
    p = t.get("properties") or {}
    return Resource(
        kind="azure_sb_topic", name=str(t.get("name")),
        ext_id=_ext(t.get("id"), f"{ns_ext}/topics/{t.get('name')}"),
        labels={"service": "servicebus"},
        raw={
            "arm_id": t.get("id"),
            "namespace_ext": ns_ext,
            "status": p.get("status"),
            "requires_duplicate_detection": bool(p.get("requiresDuplicateDetection")),
            "support_ordering": bool(p.get("supportOrdering")),
        },
    )


def parse_eh_namespace(ns: dict, auth_rules, event_hubs_readable: bool = True) -> Resource:
    """One Event Hubs namespace. `event_hubs_readable` False means the hub listing failed: no
    azure_event_hub resource exists under this namespace, so the capture rules have nothing to
    run on and the namespace would otherwise read as an empty — that is, clean — one."""
    raw = _namespace_raw(ns, auth_rules, "eventhub")
    raw["event_hubs_readable"] = event_hubs_readable
    p = ns.get("properties") or {}
    raw["kafka_enabled"] = bool(p.get("kafkaEnabled"))
    return Resource(
        kind="azure_eventhub_namespace", name=str(ns.get("name")),
        ext_id=_ext(ns.get("id"), f"eh-ns-{ns.get('name')}"),
        namespace=ns.get("location"),
        labels={"service": "eventhub", "location": str(ns.get("location")),
                "sku": str(raw["sku"])},
        raw=raw,
    )


def parse_event_hub(ns_ext: str, hub: dict, consumer_groups, capture_storage) -> Resource:
    """One event hub. `consumer_groups` None = unreadable. `capture_storage` is the posture of
    the capture-destination storage account when capture is enabled: {"readable": bool,
    "allow_blob_public_access": …, "public_network_access": …} — None when capture is off."""
    p = hub.get("properties") or {}
    capture = p.get("captureDescription") or {}
    dest = (capture.get("destination") or {})
    dest_props = dest.get("properties") or {}
    return Resource(
        kind="azure_event_hub", name=str(hub.get("name")),
        ext_id=_ext(hub.get("id"), f"{ns_ext}/eventhubs/{hub.get('name')}"),
        labels={"service": "eventhub"},
        raw={
            "arm_id": hub.get("id"),
            "namespace_ext": ns_ext,
            "status": p.get("status"),
            "partition_count": p.get("partitionCount"),
            "message_retention_in_days": p.get("messageRetentionInDays"),
            "consumer_groups_readable": consumer_groups is not None,
            "consumer_groups": [str(c.get("name")) for c in (consumer_groups or [])],
            "capture_enabled": bool(capture.get("enabled")),
            "capture_destination": dest.get("name"),
            "capture_storage_account_id": dest_props.get("storageAccountResourceId"),
            "capture_blob_container": dest_props.get("blobContainer"),
            "capture_storage": capture_storage,
        },
    )


def parse_capture_storage(sa) -> dict:
    """Storage-account GET → the two capture-relevant posture facts. None in = the read was
    denied/failed: readable=False so the detector answers not-assessable, never a clean pass."""
    if not isinstance(sa, dict):
        return {"readable": False, "allow_blob_public_access": None,
                "public_network_access": None}
    p = sa.get("properties") or {}
    return {
        "readable": True,
        # Azure's default for absent allowBlobPublicAccess flipped to False in 2023; absent is
        # recorded as None (unknown), never guessed either way.
        "allow_blob_public_access": p.get("allowBlobPublicAccess"),
        "public_network_access": p.get("publicNetworkAccess") or "Enabled",
    }


def parse_apim(svc: dict, named_values, subscriptions, apis_readable: bool = True) -> Resource:
    """One API Management service. `named_values` and `subscriptions` are metadata-only lists
    (None = unreadable): named-value VALUES and subscription KEYS are never fetched — reading
    them requires /listValue and /listSecrets POSTs this connector never issues.
    `apis_readable` False means the API listing failed: no azure_api resource exists under
    this gateway, so the per-API auth rules have nothing to run on."""
    p = svc.get("properties") or {}
    nv = None if named_values is None else [
        {"name": v.get("name"),
         "display_name": (v.get("properties") or {}).get("displayName"),
         "secret": bool((v.get("properties") or {}).get("secret"))}
        for v in named_values]
    subs = None if subscriptions is None else [
        {"name": s.get("name"),
         "display_name": (s.get("properties") or {}).get("displayName"),
         "scope": (s.get("properties") or {}).get("scope"),
         "state": (s.get("properties") or {}).get("state")}
        for s in subscriptions]
    return Resource(
        kind="azure_apim", name=str(svc.get("name")),
        ext_id=_ext(svc.get("id"), f"apim-{svc.get('name')}"),
        namespace=svc.get("location"),
        labels={"service": "apim", "location": str(svc.get("location")),
                "sku": str((svc.get("sku") or {}).get("name"))},
        raw={
            "arm_id": svc.get("id"),
            "location": svc.get("location"),
            "sku": (svc.get("sku") or {}).get("name"),
            "public_network_access": p.get("publicNetworkAccess") or "Enabled",
            "virtual_network_type": p.get("virtualNetworkType") or "None",
            "gateway_url": p.get("gatewayUrl"),
            "public_ip_addresses": p.get("publicIPAddresses") or [],
            "custom_properties": p.get("customProperties") or {},
            "apis_readable": apis_readable,
            "named_values_readable": nv is not None,
            "named_values": nv or [],
            "subscriptions_readable": subs is not None,
            "subscriptions": subs or [],
        },
    )


def parse_apim_api(apim_ext: str, api: dict) -> Resource:
    p = api.get("properties") or {}
    auth = p.get("authenticationSettings") or {}
    return Resource(
        kind="azure_api", name=str(api.get("name")),
        ext_id=_ext(api.get("id"), f"{apim_ext}/apis/{api.get('name')}"),
        labels={"service": "apim"},
        raw={
            "arm_id": api.get("id"),
            "apim_ext": apim_ext,
            "display_name": p.get("displayName"),
            "path": p.get("path"),
            "protocols": [str(x) for x in p.get("protocols") or []],
            # ARM's default when the field is absent is subscription-required.
            "subscription_required": (True if "subscriptionRequired" not in p
                                      else bool(p.get("subscriptionRequired"))),
            "oauth2_configured": bool(auth.get("oAuth2") or auth.get("oAuth2AuthenticationSettings")),
            "openid_configured": bool(auth.get("openid") or auth.get("openidAuthenticationSettings")),
        },
    )


_HTTP_TRIGGER_TYPES = ("Request", "HttpWebhook")


def parse_logic_app(wf: dict) -> Resource:
    """One workflow from its individual GET (the list response omits the definition). A GET
    that failed is passed as a list-shape dict with no definition — triggers_readable=False,
    so the HTTP-trigger rule answers not-assessable instead of 'no HTTP trigger'."""
    p = wf.get("properties") or {}
    definition = p.get("definition")
    triggers = None if not isinstance(definition, dict) else [
        {"name": name, "type": str(t.get("type")), "kind": t.get("kind")}
        for name, t in (definition.get("triggers") or {}).items() if isinstance(t, dict)]
    ac_triggers = ((p.get("accessControl") or {}).get("triggers") or {})
    ip_ranges = [str(r.get("addressRange")) for r in ac_triggers.get("allowedCallerIpAddresses") or []]
    return Resource(
        kind="azure_logic_app", name=str(wf.get("name")),
        ext_id=_ext(wf.get("id"), f"logic-{wf.get('name')}"),
        namespace=wf.get("location"),
        labels={"service": "logic", "location": str(wf.get("location")),
                "state": str(p.get("state"))},
        raw={
            "arm_id": wf.get("id"),
            "state": p.get("state"),
            "triggers_readable": triggers is not None,
            "triggers": triggers or [],
            "http_triggers": [t for t in (triggers or []) if t["type"] in _HTTP_TRIGGER_TYPES],
            "trigger_ip_restrictions": ip_ranges,
        },
    )


# ── collection: httpx in, per-service isolation ───────────────────────────────
def _collect_servicebus(client, headers, sub: str) -> tuple:
    resources, edges, gaps = [], [], []
    base = f"/subscriptions/{sub}/providers/Microsoft.ServiceBus/namespaces"
    for ns in _arm_list(client, headers, base, _SB_API):
        nsid = ns.get("id")
        try:
            rules = _arm_list(client, headers, f"{nsid}/authorizationRules", _SB_API)
        except Exception:
            # rule listing denied for THIS namespace — recorded, not raised. No gap record:
            # authorization_rules_readable rides on the namespace and AZURE.*.MANAGE_SAS_RULE
            # files it there.
            rules = None
        # Children are listed BEFORE the namespace is parsed so their readability is part of
        # the namespace resource rather than a fact lost in a `continue`.
        children, readable = {}, {}
        for sub_path in ("queues", "topics"):
            try:
                children[sub_path] = _arm_list(client, headers, f"{nsid}/{sub_path}", _SB_API)
                readable[sub_path] = True
            except Exception as e:
                children[sub_path], readable[sub_path] = [], False
                gaps.append(_gap(ns.get("name"), sub_path, e))
        ns_res = parse_sb_namespace(ns, rules, queues_readable=readable["queues"],
                                    topics_readable=readable["topics"])
        resources.append(ns_res)
        for sub_path, parse in (("queues", parse_sb_queue), ("topics", parse_sb_topic)):
            for item in children[sub_path]:
                child = parse(ns_res.ext_id, item)
                resources.append(child)
                edges.append(Edge(src_ext_id=ns_res.ext_id, dst_ext_id=child.ext_id,
                                  kind="contains"))
    return resources, edges, gaps


def _collect_eventhub(client, headers, sub: str) -> tuple:
    resources, edges, gaps = [], [], []
    base = f"/subscriptions/{sub}/providers/Microsoft.EventHub/namespaces"
    for ns in _arm_list(client, headers, base, _EH_API):
        nsid = ns.get("id")
        try:
            rules = _arm_list(client, headers, f"{nsid}/authorizationRules", _EH_API)
        except Exception:
            rules = None   # filed by AZURE.EVENTHUB.MANAGE_SAS_RULE
        try:
            hubs = _arm_list(client, headers, f"{nsid}/eventhubs", _EH_API)
            hubs_readable = True
        except Exception as e:
            hubs, hubs_readable = [], False
            gaps.append(_gap(ns.get("name"), "eventhubs", e))
        ns_res = parse_eh_namespace(ns, rules, event_hubs_readable=hubs_readable)
        resources.append(ns_res)
        for hub in hubs:
            try:
                groups = _arm_list(client, headers, f"{hub.get('id')}/consumergroups", _EH_API)
            except Exception as e:
                # consumer_groups_readable lands on the hub, but no rule reads it — without a
                # gap record the hub's consumer surface reads as "no consumer groups".
                groups = None
                gaps.append(_gap(hub.get("name"), "consumergroups", e))
            capture_storage = None
            sa_id = (((hub.get("properties") or {}).get("captureDescription") or {})
                     .get("destination") or {}).get("properties", {}).get("storageAccountResourceId")
            if ((hub.get("properties") or {}).get("captureDescription") or {}).get("enabled") and sa_id:
                try:
                    capture_storage = parse_capture_storage(
                        _arm_get(client, headers, sa_id, _STORAGE_API))
                except Exception:
                    capture_storage = parse_capture_storage(None)
            hub_res = parse_event_hub(ns_res.ext_id, hub, groups, capture_storage)
            resources.append(hub_res)
            edges.append(Edge(src_ext_id=ns_res.ext_id, dst_ext_id=hub_res.ext_id,
                              kind="contains"))
    return resources, edges, gaps


def _collect_apim(client, headers, sub: str) -> tuple:
    resources, edges, gaps = [], [], []
    base = f"/subscriptions/{sub}/providers/Microsoft.ApiManagement/service"
    for svc in _arm_list(client, headers, base, _APIM_API):
        sid = svc.get("id")
        try:
            named_values = _arm_list(client, headers, f"{sid}/namedValues", _APIM_API)
        except Exception as e:
            # named_values_readable lands on the service, but no rule reads it — without a gap
            # record an unreadable list reads as "this gateway holds no named values".
            named_values = None
            gaps.append(_gap(svc.get("name"), "namedValues", e))
        try:
            subscriptions = _arm_list(client, headers, f"{sid}/subscriptions", _APIM_API)
        except Exception as e:
            subscriptions = None
            gaps.append(_gap(svc.get("name"), "subscriptions", e))
        try:
            apis = _arm_list(client, headers, f"{sid}/apis", _APIM_API)
            apis_readable = True
        except Exception as e:
            apis, apis_readable = [], False
            gaps.append(_gap(svc.get("name"), "apis", e))
        svc_res = parse_apim(svc, named_values, subscriptions, apis_readable=apis_readable)
        resources.append(svc_res)
        for api in apis:
            api_res = parse_apim_api(svc_res.ext_id, api)
            resources.append(api_res)
            edges.append(Edge(src_ext_id=svc_res.ext_id, dst_ext_id=api_res.ext_id,
                              kind="exposes"))
    return resources, edges, gaps


def _collect_logic(client, headers, sub: str) -> tuple:
    resources = []
    base = f"/subscriptions/{sub}/providers/Microsoft.Logic/workflows"
    for wf in _arm_list(client, headers, base, _LOGIC_API):
        try:
            full = _arm_get(client, headers, str(wf.get("id")), _LOGIC_API)
        except Exception:
            full = wf   # definition unreadable — parse records triggers_readable=False
        resources.append(parse_logic_app(full))
    # No gap records: triggers_readable=False rides on the workflow and
    # AZURE.LOGICAPP.HTTP_TRIGGER_OPEN files it there.
    return resources, [], []


_SERVICES = (
    ("servicebus", _collect_servicebus),
    ("eventhub", _collect_eventhub),
    ("apim", _collect_apim),
    ("logic", _collect_logic),
)


@connector("azure", fields=[
    ConnectorField("tenant_id", "Tenant ID", required=True,
                   placeholder="00000000-0000-0000-0000-000000000000",
                   help="Entra (Azure AD) tenant of the app registration."),
    ConnectorField("client_id", "Client ID", required=True,
                   help="App registration (service principal) with the Reader role on the "
                        "subscription. Every call is a read-only ARM GET; SAS keys and "
                        "connection strings are never fetched."),
    ConnectorField("client_secret", "Client secret", required=True, secret=True,
                   help="Used to obtain a bearer token, never persisted into any resource."),
    ConnectorField("subscription_id", "Subscription ID", required=True,
                   placeholder="11111111-1111-1111-1111-111111111111",
                   help="Azure subscription to scan."),
])
def collect(config: dict) -> Collected:
    tenant = str(config.get("tenant_id") or "").strip()
    sub = str(config.get("subscription_id") or "").strip()
    timeout = float(config.get("timeout", 30))

    resources: list[Resource] = []
    edges: list[Edge] = []
    outcomes: dict[str, dict] = {}

    with httpx.Client(timeout=timeout) as client:
        # Token first — an auth failure here is an auth failure and rightly fails the scan.
        token = _get_token(client, tenant, str(config.get("client_id") or "").strip(),
                           str(config.get("client_secret") or ""))
        headers = {"Authorization": f"Bearer {token}"}

        # Per-service isolation: a denied provider records honestly and the scan goes on.
        for service, fn in _SERVICES:
            try:
                rs, es, gaps = fn(client, headers, sub)
                resources.extend(rs)
                edges.extend(es)
                outcomes[service] = {"outcome": "ok", "error": None, "resources": len(rs)}
                if gaps:
                    # The provider listed, but not everything under it did. Without this the
                    # record reads {"outcome": "ok"} and the coverage rule claims a service
                    # was fully assessed over children that were never collected.
                    outcomes[service]["child_gaps"] = gaps
            except Exception as e:
                outcomes[service] = _outcome_for(e)

    subscription = Resource(
        kind="azure_subscription",
        name=sub or "azure-subscription",
        ext_id=f"azure-sub-{sub or 'unknown'}",
        labels={"service": "arm"},
        raw={
            "subscription_id": sub,
            "tenant_id": tenant,
            "client_id": str(config.get("client_id") or "").strip(),  # app id, not a secret
            "collection": outcomes,
        },
    )
    return Collected(resources=[subscription] + resources, edges=edges)


# ── NHI: SAS authorization rules and APIM subscriptions ───────────────────────
_SAS_NAMESPACE_KINDS = ("azure_servicebus_namespace", "azure_eventhub_namespace")


@identity_extractor("azure")
def _from_azure(resources: list) -> tuple:
    """SAS authorization rules → the normalized NHI model: each rule is a shared-credential
    identity whose rights are grants against the namespace it lives on. Manage rights include
    the right to mint further rules and read every key, so a Manage rule is labelled
    wildcard-equivalent. APIM subscriptions become identities with subscription-key credential
    METADATA (2 keys exist by construction; their values are never fetched — /listSecrets is
    never called, so there is no secret to drop)."""
    out: list[Resource] = []
    edges: list[Edge] = []
    seen_grants: set[str] = set()

    for r in resources:
        if r.kind in _SAS_NAMESPACE_KINDS:
            raw = r.raw or {}
            for rule in raw.get("authorization_rules") or []:
                rights = [str(x) for x in rule.get("rights") or []]
                manage = "Manage" in rights
                idr = _mk_identity(
                    "azure", "sas_policy", f"{r.name}/{rule.get('name')}",
                    tags=(["wildcard_equivalent"] if manage else []),
                    source_ext=r.ext_id,
                    extra={"rights": rights, "rule_name": rule.get("name"),
                           "namespace_kind": r.kind})
                out.append(idr)
                # A SAS rule IS a credential: two live keys exist for it by construction.
                cred = _mk_credential(
                    "azure", idr.ext_id, "sas_key", name=f"{rule.get('name')}:sas_key",
                    hashing="n/a", present=True, plaintext=None, count=2)
                out.append(cred)
                edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id,
                                  kind="credential_of"))
                for right in rights:
                    g = _mk_grant(
                        "azure", idr.ext_id, right.lower(), r.ext_id,
                        wildcard=(right == "Manage"),
                        extra={"rule": rule.get("name"), "resource_kind": r.kind})
                    if g.ext_id in seen_grants:
                        continue
                    seen_grants.add(g.ext_id)
                    out.append(g)
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id,
                                      kind="granted_to"))
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=r.ext_id,
                                      kind="grants_access"))

        elif r.kind == "azure_apim":
            raw = r.raw or {}
            for s in raw.get("subscriptions") or []:
                label = s.get("display_name") or s.get("name") or "subscription"
                idr = _mk_identity(
                    "azure", "apim_subscription", f"{r.name}/{label}",
                    source_ext=r.ext_id,
                    extra={"state": s.get("state"), "scope": s.get("scope")})
                out.append(idr)
                cred = _mk_credential(
                    "azure", idr.ext_id, "subscription_key",
                    name=f"{label}:subscription_key", hashing="n/a", present=True,
                    plaintext=None, count=2)
                out.append(cred)
                edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id,
                                  kind="credential_of"))
                g = _mk_grant("azure", idr.ext_id, "call-api",
                              str(s.get("scope") or r.ext_id),
                              wildcard=str(s.get("scope") or "").endswith("/apis"),
                              extra={"state": s.get("state")})
                if g.ext_id not in seen_grants:
                    seen_grants.add(g.ext_id)
                    out.append(g)
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id,
                                      kind="granted_to"))
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=r.ext_id,
                                      kind="grants_access"))
    return out, edges
