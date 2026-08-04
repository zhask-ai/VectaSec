"""GCP agentless connector — read-only REST, one connection fans out to three surfaces.

Auth is either a service-account JSON key (the standard grant: build a signed RS256 JWT with
the key and exchange it for an OAuth2 access token at oauth2.googleapis.com — pyjwt[crypto]
is already a dependency, so no Google SDK is added, matching the repo's dependency-light
style) or a short-lived access token pasted directly. One connection collects the
integration-layer surface of a project: Pub/Sub topics + subscriptions (with their
per-resource IAM policies, CMEK, push endpoints and dead-letter config), the Apigee org and
its deployed proxies (with target-endpoint TLS where readable), and the project IAM policy
(bindings + audit configs) for posture and NHI.

Three disciplines carried over from connect/aws.py:

  • Secrets are used, never persisted. `service_account_key` / `access_token` are
    ConnectorField secret=True; the key signs one JWT inside collect() and neither the key
    nor the minted token is ever copied into any Resource.
  • Per-service error isolation. Each surface (pubsub / apigee / resourcemanager) runs in its
    own try/except: a 403 records {"outcome": "access_denied"} — or "api_disabled" when the
    error says the API is not enabled on the project — on the gcp_project resource instead of
    voiding the whole scan. detect/gcp.py turns those records into not-assessable
    coverage-gap findings — never a pass, never a failure. Isolation alone is not enough: a
    CHILD read that fails inside a surface that otherwise succeeded is recorded too — as a
    *_readable flag on the parent resource, or as a child_gaps entry in the service's outcome
    record when the child leaves no resource behind. Collapsing one to []/None makes "denied"
    indistinguishable from "none exists", which is the secure state.
  • IAM policies are OBSERVATIONS, not secrets. A binding names principals and roles — the
    exact evidence a posture finding must cite — so bindings are stored in Resource.raw and
    quoted by detectors. No credential material appears in any IAM read.

The parse layer (parse_pubsub_topic, parse_apigee_proxy, …) is pure: REST response dicts in,
Resources out. Tests exercise detectors against parse-layer output from golden fixtures, so
httpx (and a live project) stays out of the test suite.

Kinds are DISTINCT (gcp_project, gcp_pubsub_topic, gcp_pubsub_subscription, gcp_apigee_org,
gcp_apigee_proxy). Edges: topic --delivers_to--> subscription, org --exposes--> proxy.
"""
import json
import time

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

_PUBSUB = "https://pubsub.googleapis.com/v1"
_APIGEE = "https://apigee.googleapis.com/v1"
_CRM = "https://cloudresourcemanager.googleapis.com/v1"
_TOKEN_URI = "https://oauth2.googleapis.com/token"
# Read-only scope: the token cannot mutate anything even if a bug tried to.
_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"

# 403 reasons that mean "the API is not enabled on this project" — a different honest
# outcome from a permissions denial, and a different remediation.
_API_DISABLED_REASONS = {"SERVICE_DISABLED", "accessNotConfigured"}


class _Denied(Exception):
    def __init__(self, status: int, reason: str = "", message: str = ""):
        super().__init__(f"http_{status}{f' {reason}' if reason else ''}")
        self.status = status
        self.reason = reason
        self.message = message


def _outcome_for(exc) -> dict:
    if isinstance(exc, _Denied):
        if exc.reason in _API_DISABLED_REASONS or "has not been used" in exc.message:
            return {"outcome": "api_disabled", "error": str(exc)}
        return {"outcome": "access_denied", "error": str(exc)}
    return {"outcome": "error", "error": f"{type(exc).__name__}: {exc}"}


def _error_text(exc) -> str:
    return str(exc) if isinstance(exc, _Denied) else f"{type(exc).__name__}: {exc}"


def _gap(parent, child: str, exc) -> dict:
    """A CHILD read that failed inside a service whose own list call succeeded.

    Per-service isolation alone is not enough: swallowing a child failure to []/None leaves
    outcomes[service] reading {"outcome": "ok"}, so GCP.PROJECT.SERVICE_NOT_ASSESSED reports
    full coverage over resources that were never collected. These records are what that rule
    names. Only failures NOT already visible on a collected resource are recorded here — a
    gap some per-resource rule already files must stay filed exactly once."""
    return {"parent": str(parent), "child": child, "error": _error_text(exc)}


def _short(name) -> str:
    """'projects/p/topics/orders' → 'orders'."""
    return str(name or "").rsplit("/", 1)[-1]


# ── HTTP layer (kept out of the parse layer and out of the tests) ─────────────
def _error_reason(r: httpx.Response) -> tuple:
    try:
        err = (r.json() or {}).get("error") or {}
    except ValueError:
        return "", ""
    reasons = [d.get("reason") for d in err.get("details") or [] if isinstance(d, dict)]
    reasons += [e.get("reason") for e in err.get("errors") or [] if isinstance(e, dict)]
    return next((x for x in reasons if x), ""), str(err.get("message") or "")


def _check(r: httpx.Response) -> dict:
    if r.status_code in (401, 403):
        reason, message = _error_reason(r)
        raise _Denied(r.status_code, reason, message)
    r.raise_for_status()
    return r.json()


def _gget(client: httpx.Client, headers: dict, url: str, params: dict | None = None) -> dict:
    return _check(client.get(url, params=params, headers=headers))


def _gpost(client: httpx.Client, headers: dict, url: str, body: dict) -> dict:
    """Only used for cloudresourcemanager projects:getIamPolicy — a POST-shaped READ in
    Google's API surface; it mutates nothing."""
    return _check(client.post(url, json=body, headers=headers))


def _paged(client, headers, url: str, key: str) -> list:
    out, token = [], None
    while True:
        params = {"pageToken": token} if token else None
        body = _gget(client, headers, url, params)
        out.extend(body.get(key) or [])
        token = body.get("nextPageToken")
        if not token:
            return out


def _token_from_key(client: httpx.Client, key: dict) -> str:
    """Service-account JSON key → OAuth2 access token: sign a JWT assertion with the key's
    private key (RS256 via pyjwt, already a dependency) and exchange it. The key never
    travels anywhere except as this signature; the token lives and dies inside collect()."""
    import jwt as pyjwt

    now = int(time.time())
    token_uri = key.get("token_uri") or _TOKEN_URI
    assertion = pyjwt.encode(
        {"iss": key["client_email"], "scope": _SCOPE, "aud": token_uri,
         "iat": now, "exp": now + 3600},
        key["private_key"], algorithm="RS256")
    r = client.post(token_uri, data={
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion})
    r.raise_for_status()          # an auth failure rightly fails the scan
    return r.json()["access_token"]


# ── parse layer: REST response dicts → Resources (pure, no httpx) ─────────────
def _parse_iam(policy) -> dict:
    """getIamPolicy response → the dict shape detectors read. None in = the call failed for
    THIS resource (recorded, so detectors answer not-assessable instead of reading absence
    as 'no bindings')."""
    if not isinstance(policy, dict):
        return {"readable": False, "bindings": []}
    return {
        "readable": True,
        "bindings": [
            {"role": str(b.get("role") or ""),
             "members": [str(m) for m in b.get("members") or []]}
            for b in policy.get("bindings") or [] if isinstance(b, dict)],
    }


def parse_pubsub_topic(project: str, t: dict, policy) -> Resource:
    name = _short(t.get("name"))
    return Resource(
        kind="gcp_pubsub_topic", name=name,
        ext_id=str(t.get("name") or f"projects/{project}/topics/{name}"),
        namespace=project,
        labels={"service": "pubsub", "project": project},
        raw={
            "full_name": t.get("name"),
            "project": project,
            "kms_key_name": t.get("kmsKeyName") or None,
            "message_retention_duration": t.get("messageRetentionDuration"),
            "labels": t.get("labels") or {},
            "iam_policy": _parse_iam(policy),
        },
    )


def parse_pubsub_subscription(project: str, s: dict, policy) -> Resource:
    name = _short(s.get("name"))
    push = s.get("pushConfig") or {}
    endpoint = push.get("pushEndpoint") or None
    dlp = s.get("deadLetterPolicy") or {}
    return Resource(
        kind="gcp_pubsub_subscription", name=name,
        ext_id=str(s.get("name") or f"projects/{project}/subscriptions/{name}"),
        namespace=project,
        labels={"service": "pubsub", "project": project,
                "delivery": "push" if endpoint else "pull"},
        raw={
            "full_name": s.get("name"),
            "project": project,
            "topic": s.get("topic"),
            "push_endpoint": endpoint,
            # OIDC config is metadata (which service account signs the push token) — the
            # token itself never appears in this API.
            "push_oidc_service_account": (push.get("oidcToken") or {}).get("serviceAccountEmail"),
            "dead_letter_topic": dlp.get("deadLetterTopic"),
            "max_delivery_attempts": dlp.get("maxDeliveryAttempts"),
            "ack_deadline_seconds": s.get("ackDeadlineSeconds"),
            "message_retention_duration": s.get("messageRetentionDuration"),
            "iam_policy": _parse_iam(policy),
        },
    )


def _parse_ssl(detail: dict) -> tuple:
    """TargetEndpoint config → (url, ssl_enabled, protocols). Apigee serialises sSLInfo.enabled
    as the string 'true'/'false'; absent sSLInfo is None (unknown), never guessed False."""
    conn = detail.get("connection") or {}
    url = detail.get("uRL") or detail.get("url") or conn.get("uRL") or conn.get("url")
    ssl = detail.get("sSLInfo") or detail.get("sslInfo") or conn.get("sSLInfo")
    if not isinstance(ssl, dict):
        return url, None, []
    enabled = ssl.get("enabled")
    if isinstance(enabled, str):
        enabled = enabled.lower() == "true"
    return url, (bool(enabled) if enabled is not None else None), \
        [str(p) for p in ssl.get("protocols") or []]


def parse_apigee_proxy(org: str, name: str, deployments, targets,
                       unreadable_targets=()) -> Resource:
    """One API proxy. `deployments` are this proxy's rows from the org deployments list, or
    None when the deployments list itself could not be read; `targets` is a list of
    TargetEndpoint detail dicts for the deployed revision, or None when target configs could
    not be read (recorded → not-assessable, not 'no targets').

    `unreadable_targets` names the individual targets whose detail GET failed while siblings
    succeeded. Dropping one silently while leaving targets_readable True is the worst shape
    available: the detector believes the list is complete, so a target with ssl_enabled=False
    simply disappears from the assessment. Any unreadable target therefore clears the flag,
    and the targets that WERE read stay in the list so their real defects still fire."""
    items = None if targets is None else []
    for detail in targets or []:
        url, ssl_enabled, protocols = _parse_ssl(detail or {})
        items.append({"name": (detail or {}).get("name"), "url": url,
                      "ssl_enabled": ssl_enabled, "protocols": protocols})
    unreadable = [str(t) for t in unreadable_targets or ()]
    if deployments is None:
        deployed = "unknown"
    else:
        deployed = "true" if deployments else "false"
    return Resource(
        kind="gcp_apigee_proxy", name=name,
        ext_id=f"organizations/{org}/apis/{name}",
        namespace=org,
        labels={"service": "apigee", "org": org, "deployed": deployed},
        raw={
            "org": org,
            "proxy": name,
            "deployments_readable": deployments is not None,
            "deployments": [{"environment": d.get("environment"),
                             "revision": d.get("revision")} for d in deployments or []],
            "targets_readable": items is not None and not unreadable,
            "unreadable_targets": unreadable,
            "targets": items or [],
        },
    )


def parse_apigee_org(org: dict, envgroups, proxies_readable: bool = True) -> Resource:
    name = _short(org.get("name"))
    return Resource(
        kind="gcp_apigee_org", name=name,
        ext_id=f"organizations/{name}",
        labels={"service": "apigee",
                "runtime_type": str(org.get("runtimeType") or "")},
        raw={
            "org": name,
            "runtime_type": org.get("runtimeType"),
            # False means the proxy listing failed: NO gcp_apigee_proxy resource exists for
            # this org, so every Apigee proxy rule is silent for want of a subject.
            "proxies_readable": proxies_readable,
            "envgroups_readable": envgroups is not None,
            "envgroups": [{"name": g.get("name"),
                           "hostnames": [str(h) for h in g.get("hostnames") or []]}
                          for g in (envgroups or [])],
        },
    )


def parse_project(project: str, iam, outcomes: dict, auth_method: str) -> Resource:
    """The project resource: IAM posture (bindings + auditConfigs) and the per-service
    collection record. `iam` is the raw getIamPolicy response or None when unreadable."""
    readable = isinstance(iam, dict)
    parsed = _parse_iam(iam)
    parsed["audit_configs"] = [
        {"service": str(a.get("service") or ""),
         "log_types": [str((c or {}).get("logType") or "")
                       for c in a.get("auditLogConfigs") or []]}
        for a in (iam.get("auditConfigs") or [] if readable else []) if isinstance(a, dict)]
    return Resource(
        kind="gcp_project", name=project,
        ext_id=f"projects/{project}",
        labels={"service": "resourcemanager", "auth_method": auth_method},
        raw={
            "project_id": project,
            "auth_method": auth_method,      # never the credential itself
            "iam": parsed,
            "collection": outcomes,
        },
    )


# ── collection: httpx in, per-service isolation ───────────────────────────────
def _collect_pubsub(client, headers, project: str) -> tuple:
    resources, edges = [], []
    topic_exts = set()
    for t in _paged(client, headers, f"{_PUBSUB}/projects/{project}/topics", "topics"):
        try:
            policy = _gget(client, headers, f"{_PUBSUB}/{t.get('name')}:getIamPolicy")
        except Exception:
            policy = None   # IAM denied for THIS topic — recorded, not raised
        res = parse_pubsub_topic(project, t, policy)
        resources.append(res)
        topic_exts.add(res.ext_id)
    for s in _paged(client, headers, f"{_PUBSUB}/projects/{project}/subscriptions",
                    "subscriptions"):
        try:
            policy = _gget(client, headers, f"{_PUBSUB}/{s.get('name')}:getIamPolicy")
        except Exception:
            policy = None
        sub = parse_pubsub_subscription(project, s, policy)
        resources.append(sub)
        topic = str(s.get("topic") or "")
        # "_deleted-topic_" marks a detached subscription — no edge to a resource we hold.
        if topic in topic_exts:
            edges.append(Edge(src_ext_id=topic, dst_ext_id=sub.ext_id, kind="delivers_to"))
    # No gap records: iam_policy.readable=False rides on each resource and
    # GCP.PUBSUB.IAM_NOT_READABLE files it per resource.
    return resources, edges, []


def _collect_apigee(client, headers, org: str) -> tuple:
    resources, edges, gaps = [], [], []
    org_body = _gget(client, headers, f"{_APIGEE}/organizations/{org}")
    try:
        envgroups = _gget(client, headers, f"{_APIGEE}/organizations/{org}/envgroups"
                          ).get("environmentGroups") or []
    except Exception as e:
        # envgroups_readable lands on the org resource, but no rule reads it — without a gap
        # record the org's hostname surface silently reads as "no environment groups".
        envgroups = None
        gaps.append(_gap(f"organization {org}", "envgroups", e))

    proxies = None
    try:
        proxies = [p.get("name") for p in
                   (_gget(client, headers, f"{_APIGEE}/organizations/{org}/apis")
                    .get("proxies") or []) if p.get("name")]
    except Exception as e:
        gaps.append(_gap(f"organization {org}", "apis (proxy list)", e))
    deployments = None
    try:
        deployments = (_gget(client, headers, f"{_APIGEE}/organizations/{org}/deployments")
                       .get("deployments") or [])
    except Exception:
        # Filed by GCP.APIGEE.TARGET_NO_TLS off deployments_readable. Defaulting to [] here
        # would label every proxy deployed="false", and the TLS rules skip undeployed
        # proxies — a denied read would silently retire the whole Apigee surface.
        pass

    org_res = parse_apigee_org(org_body if org_body.get("name") else {"name": org}, envgroups,
                               proxies_readable=proxies is not None)
    resources.append(org_res)

    for name in proxies or []:
        deps = (None if deployments is None
                else [d for d in deployments if d.get("apiProxy") == name])
        targets, unreadable = None, []
        revisions = sorted({str(d.get("revision")) for d in deps or [] if d.get("revision")})
        if revisions:
            rev = revisions[-1]
            base = f"{_APIGEE}/organizations/{org}/apis/{name}/revisions/{rev}/targets"
            try:
                target_names = _gget(client, headers, base)
                target_names = target_names if isinstance(target_names, list) else \
                    target_names.get("targets") or []
                targets = []
                for tn in target_names:
                    tn = tn if isinstance(tn, str) else (tn or {}).get("name")
                    try:
                        targets.append(_gget(client, headers, f"{base}/{tn}"))
                    except Exception:
                        # Named, not dropped: a target that vanishes from a list the detector
                        # believes is complete takes its ssl_enabled=False with it.
                        unreadable.append(str(tn))
            except Exception:
                targets = None   # target configs unreadable — recorded, not raised
        proxy_res = parse_apigee_proxy(org, name, deps, targets,
                                       unreadable_targets=unreadable)
        resources.append(proxy_res)
        edges.append(Edge(src_ext_id=org_res.ext_id, dst_ext_id=proxy_res.ext_id,
                          kind="exposes"))
    return resources, edges, gaps


@connector("gcp", fields=[
    ConnectorField("service_account_key", "Service account key (JSON)", secret=True,
                   help="Paste the full JSON key of a read-only service account "
                        "(roles/viewer, or pubsub.viewer + apigee.readOnlyAdmin). Used to "
                        "sign one OAuth assertion; never persisted into any resource."),
    ConnectorField("access_token", "Access token", secret=True,
                   help="Alternative to a key for short-lived use: a token from "
                        "`gcloud auth print-access-token`. Expires within an hour."),
    ConnectorField("project_id", "Project ID", placeholder="acme-prod",
                   help="Project to scan. Optional when the service-account key carries "
                        "project_id; required with a bare access token."),
    ConnectorField("apigee_org", "Apigee organization",
                   help="Apigee org name if it differs from the project id (they usually "
                        "match). Apigee is skipped gracefully when the API is not enabled."),
])
def collect(config: dict) -> Collected:
    key = None
    key_text = str(config.get("service_account_key") or "").strip()
    if key_text:
        key = json.loads(key_text)

    project = (str(config.get("project_id") or "").strip()
               or str((key or {}).get("project_id") or "").strip())
    if not project:
        raise SystemExit("gcp connector requires project_id "
                         "(or a service-account key that carries one)")
    org = str(config.get("apigee_org") or "").strip() or project
    timeout = float(config.get("timeout", 30))

    resources: list[Resource] = []
    edges: list[Edge] = []
    outcomes: dict[str, dict] = {}

    with httpx.Client(timeout=timeout) as client:
        access_token = str(config.get("access_token") or "").strip()
        if access_token:
            token, auth_method = access_token, "access_token"
        elif key:
            token, auth_method = _token_from_key(client, key), "service_account_key"
        else:
            raise SystemExit("gcp connector requires service_account_key or access_token")
        headers = {"Authorization": f"Bearer {token}"}

        for service, fn, arg in (("pubsub", _collect_pubsub, project),
                                 ("apigee", _collect_apigee, org)):
            try:
                rs, es, gaps = fn(client, headers, arg)
                resources.extend(rs)
                edges.extend(es)
                outcomes[service] = {"outcome": "ok", "error": None, "resources": len(rs)}
                if gaps:
                    # The service listed, but not everything under it did. Without this the
                    # record reads {"outcome": "ok"} and the coverage rule claims a service
                    # was fully assessed over children that were never collected.
                    outcomes[service]["child_gaps"] = gaps
            except Exception as e:
                outcomes[service] = _outcome_for(e)

        # Project IAM (bindings + audit configs) — POST-shaped read, isolated like the rest.
        iam = None
        try:
            iam = _gpost(client, headers,
                         f"{_CRM}/projects/{project}:getIamPolicy", {})
            outcomes["resourcemanager"] = {"outcome": "ok", "error": None, "resources": 1}
        except Exception as e:
            outcomes["resourcemanager"] = _outcome_for(e)

    project_res = parse_project(project, iam, outcomes, auth_method)
    return Collected(resources=[project_res] + resources, edges=edges)


# ── NHI: principals named in IAM bindings ─────────────────────────────────────
_IAM_RESOURCE_KINDS = ("gcp_pubsub_topic", "gcp_pubsub_subscription")
_WILDCARD_MEMBERS = ("allUsers", "allAuthenticatedUsers")
_BROAD_ROLES = ("roles/owner", "roles/editor", "roles/pubsub.admin")
_MEMBER_TYPES = {"serviceAccount": "service_account", "user": "user", "group": "group",
                 "domain": "domain", "deleted": "deleted_principal"}


def _classify_member(member: str) -> tuple:
    """(identity_type, external). allUsers/allAuthenticatedUsers are THE wildcard principals
    — identity_type 'wildcard' lands in labels.identity_type, which is how the console and
    the NHI rulepack see them flagged."""
    if member in _WILDCARD_MEMBERS:
        return "wildcard", True
    prefix = member.split(":", 1)[0]
    return _MEMBER_TYPES.get(prefix, "principal"), False


def _resource_bindings(r) -> list:
    raw = r.raw or {}
    if r.kind == "gcp_project":
        return ((raw.get("iam") or {}).get("bindings")) or []
    return ((raw.get("iam_policy") or {}).get("bindings")) or []


@identity_extractor("gcp")
def _from_gcp(resources: list) -> tuple:
    """Principals appearing in Pub/Sub resource IAM policies and the project IAM policy →
    the normalized NHI model: one identity per member (deduped across resources), one grant
    per (member, role, resource) with edges grant --granted_to--> identity and
    grant --grants_access--> the collected resource. IAM bindings expose no credential
    material, so no credential resources are emitted — absence, not silence."""
    out: list[Resource] = []
    edges: list[Edge] = []
    seen: dict[str, Resource] = {}
    seen_grants: set[str] = set()

    for r in resources:
        if r.kind not in _IAM_RESOURCE_KINDS and r.kind != "gcp_project":
            continue
        for binding in _resource_bindings(r):
            role = str(binding.get("role") or "")
            for member in binding.get("members") or []:
                member = str(member)
                itype, external = _classify_member(member)
                idr = seen.get(member)
                if idr is None:
                    idr = _mk_identity(
                        "gcp", itype, member, external=external,
                        tags=(["wildcard_principal"] if itype == "wildcard" else []),
                        source_ext=r.ext_id)
                    seen[member] = idr
                    out.append(idr)
                g = _mk_grant(
                    "gcp", idr.ext_id, role, r.ext_id,
                    wildcard=(itype == "wildcard" or role in _BROAD_ROLES),
                    permission="allow",
                    extra={"resource_kind": r.kind})
                if g.ext_id in seen_grants:
                    continue
                seen_grants.add(g.ext_id)
                out.append(g)
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id,
                                  kind="granted_to"))
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=r.ext_id,
                                  kind="grants_access"))
    return out, edges
