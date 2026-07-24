"""GCP rulepack — config-time posture over what connect/gcp.py collected.

Every rule reads REAL configuration evidence (the IAM binding's role and members, the
subscription's pushConfig, the target endpoint's sSLInfo, the project's auditConfigs) and
cites it in the observation; none of them guesses from names or tags. Rules run on the
DISTINCT gcp_* kinds the connector emits, so they never collide with the other packs.

Severity conventions (house):
  critical  anyone on the internet gets in (allUsers / allAuthenticatedUsers binding)
  high      broad roles on a resource, plaintext push delivery, no-TLS / legacy-TLS backends
  medium    unauthenticated push endpoints
  low       hygiene (no CMEK, no dead-letter on push, audit logging off)
  info      ranking hints and coverage notes

The third outcome is used throughout: per-resource IAM reads the connector recorded as
unreadable, unreadable Apigee target configs, and whole services that answered 403 or
API-disabled become assessable=False coverage gaps — never a clean pass, never a
fabricated failure.
"""
from ..connect.gcp import _WILDCARD_MEMBERS, _BROAD_ROLES
from ..contracts import Hit
from ..registry import detector

_PUBSUB_KINDS = ("gcp_pubsub_topic", "gcp_pubsub_subscription")


def _iam(r) -> dict:
    return (r.raw or {}).get("iam_policy") or {}


def _public_binding_hits(r, noun: str, risk: str) -> list:
    hits = []
    for b in _iam(r).get("bindings") or []:
        wild = [m for m in b.get("members") or [] if m in _WILDCARD_MEMBERS]
        if not wild:
            continue
        hits.append(Hit(
            observation=(f"Pub/Sub {noun} '{r.name}' IAM policy binds {b.get('role')!r} to "
                         f"{wild!r} — {'any Google-authenticated account' if wild == ['allAuthenticatedUsers'] else 'anyone on the internet'} "
                         f"holds that role, so {risk}"),
            remediation=(f"Remove the binding: `gcloud pubsub {noun}s remove-iam-policy-binding "
                         f"{r.name} --member={wild[0]} --role={b.get('role')}` and grant the "
                         f"role to explicit service accounts instead. Terraform: never use "
                         f"`allUsers`/`allAuthenticatedUsers` in `google_pubsub_{noun}_iam_*` "
                         f"members."),
            detail=f"role={b.get('role')} members={wild}",
            source_ref={"api": "pubsub getIamPolicy", "role": b.get("role")},
        ))
    return hits


# ══ Pub/Sub IAM ═══════════════════════════════════════════════════════════════
@detector(kinds=["gcp_pubsub_topic"], rule_id="GCP.PUBSUB.TOPIC_IAM_PUBLIC",
          severity="critical", title="Pub/Sub topic is bound to allUsers or allAuthenticatedUsers")
def topic_iam_public(r, ctx) -> list:
    return _public_binding_hits(
        r, "topic",
        risk="anyone matching it can publish forged events into every subscriber, or "
             "attach a subscription and read the stream")


@detector(kinds=["gcp_pubsub_subscription"], rule_id="GCP.PUBSUB.SUBSCRIPTION_IAM_PUBLIC",
          severity="critical",
          title="Pub/Sub subscription is bound to allUsers or allAuthenticatedUsers")
def subscription_iam_public(r, ctx) -> list:
    return _public_binding_hits(
        r, "subscription",
        risk="anyone matching it can pull, ack (destroy) or replay this subscription's "
             "messages")


@detector(kinds=list(_PUBSUB_KINDS), rule_id="GCP.PUBSUB.BROAD_ROLE_BINDING", severity="high",
          title="Pub/Sub resource grants a broad role")
def pubsub_broad_role(r, ctx) -> list:
    hits = []
    for b in _iam(r).get("bindings") or []:
        role = str(b.get("role") or "")
        if role not in _BROAD_ROLES:
            continue
        # Wildcard members are already a critical finding — this rule is about the ROLE
        # breadth granted to concrete principals; two defects, two findings.
        members = [m for m in b.get("members") or [] if m not in _WILDCARD_MEMBERS]
        if not members:
            continue
        hits.append(Hit(
            observation=(f"Pub/Sub {r.kind.rsplit('_', 1)[-1]} '{r.name}' IAM policy binds "
                         f"{role!r} to {members!r} — that role carries admin-grade "
                         f"permissions (delete, setIamPolicy, reconfigure) far beyond "
                         f"publish/consume, so any of those principals can rewrite the "
                         f"policy that admits them"),
            remediation=(f"Grant least privilege instead: roles/pubsub.publisher or "
                         f"roles/pubsub.subscriber per principal, and reserve "
                         f"{role} for humans behind group-based admin access. "
                         f"`gcloud pubsub topics|subscriptions set-iam-policy` with the "
                         f"narrowed policy, or tighten the `google_pubsub_*_iam_binding` "
                         f"Terraform resources."),
            detail=f"role={role} members={members}",
            source_ref={"api": "pubsub getIamPolicy", "role": role},
        ))
    return hits


@detector(kinds=list(_PUBSUB_KINDS), rule_id="GCP.PUBSUB.IAM_NOT_READABLE", severity="info",
          title="Pub/Sub resource IAM policy could not be read")
def pubsub_iam_not_readable(r, ctx) -> list:
    if _iam(r).get("readable", False):
        return []
    return [Hit(
        observation=(f"getIamPolicy on Pub/Sub resource '{r.name}' was denied, so who can "
                     f"publish to or consume from it could not be determined"),
        remediation=("Grant the scan principal pubsub.topics.getIamPolicy / "
                     "pubsub.subscriptions.getIamPolicy (covered by roles/pubsub.viewer) so "
                     "access posture can be assessed. Until then it is unknown, not clean."),
        detail="iam_policy.readable=False",
        assessable=False,
        assessment_reason="getIamPolicy returned 403 for this resource",
        source_ref={"api": "pubsub getIamPolicy"},
    )]


# ══ Pub/Sub configuration ═════════════════════════════════════════════════════
@detector(kinds=["gcp_pubsub_topic"], rule_id="GCP.PUBSUB.TOPIC_NO_CMEK", severity="low",
          title="Pub/Sub topic has no customer-managed encryption key")
def topic_no_cmek(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("kms_key_name"):
        return []
    return [Hit(
        observation=(f"Pub/Sub topic '{r.name}' has no kmsKeyName — messages are encrypted "
                     f"only with Google-managed keys, so key rotation, access revocation and "
                     f"CMEK audit trails do not apply to this stream"),
        remediation=("If policy requires CMEK, recreate the topic with one: `gcloud pubsub "
                     f"topics create {r.name} --topic-encryption-key=projects/<p>/locations/"
                     "<l>/keyRings/<kr>/cryptoKeys/<k>` (kmsKeyName is immutable after "
                     "creation). Terraform: `kms_key_name` on `google_pubsub_topic`."),
        detail="kms_key_name=absent",
        source_ref={"api": "pubsub topics.list", "field": "kmsKeyName"},
    )]


@detector(kinds=["gcp_pubsub_subscription"], rule_id="GCP.PUBSUB.PUSH_ENDPOINT_NOT_HTTPS",
          severity="high", title="Pub/Sub push subscription delivers over plaintext HTTP")
def push_not_https(r, ctx) -> list:
    raw = r.raw or {}
    endpoint = str(raw.get("push_endpoint") or "")
    if not endpoint or not endpoint.lower().startswith("http://"):
        return []
    return [Hit(
        observation=(f"Pub/Sub subscription '{r.name}' pushes to {endpoint!r} — every "
                     f"message (and any OIDC token attached to the push) crosses the network "
                     f"unencrypted, and the endpoint cannot be authenticated"),
        remediation=("Point the push at an HTTPS endpoint: `gcloud pubsub subscriptions "
                     f"update {r.name} --push-endpoint=https://…`. Pub/Sub requires a valid "
                     "certificate on the receiver; there is no supported plaintext push in "
                     "production."),
        detail=f"push_endpoint={endpoint}",
        source_ref={"api": "pubsub subscriptions.list", "field": "pushConfig.pushEndpoint"},
    )]


@detector(kinds=["gcp_pubsub_subscription"], rule_id="GCP.PUBSUB.PUSH_NO_AUTH",
          severity="medium", title="Pub/Sub push subscription attaches no OIDC token")
def push_no_auth(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("push_endpoint") or raw.get("push_oidc_service_account"):
        return []
    return [Hit(
        observation=(f"Pub/Sub subscription '{r.name}' pushes to "
                     f"{raw.get('push_endpoint')!r} with no oidcToken configured — the "
                     f"receiving endpoint gets no signed identity to verify, so it cannot "
                     f"distinguish genuine Pub/Sub deliveries from anyone else POSTing to it"),
        remediation=("Attach an OIDC identity: `gcloud pubsub subscriptions update "
                     f"{r.name} --push-auth-service-account=<sa>@<project>.iam."
                     "gserviceaccount.com` and verify the JWT (audience + issuer "
                     "accounts.google.com) at the receiver. Terraform: `oidc_token` block in "
                     "`push_config` on `google_pubsub_subscription`."),
        detail=f"push_endpoint={raw.get('push_endpoint')} oidc_token=absent",
        source_ref={"api": "pubsub subscriptions.list", "field": "pushConfig.oidcToken"},
    )]


@detector(kinds=["gcp_pubsub_subscription"], rule_id="GCP.PUBSUB.SUBSCRIPTION_NO_DEAD_LETTER",
          severity="low", title="Pub/Sub subscription has no dead-letter topic")
def subscription_no_dead_letter(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("dead_letter_topic"):
        return []
    push = bool(raw.get("push_endpoint"))
    # Ranking hint, not a filter: on a push subscription a persistently failing endpoint
    # means messages retry until retention expires, then vanish without trace.
    return [Hit(
        observation=(f"Pub/Sub subscription '{r.name}' has no deadLetterPolicy — messages "
                     f"that repeatedly fail delivery are dropped when retention expires "
                     f"instead of being quarantined for inspection"),
        severity="low" if push else "info",
        remediation=("Attach one: `gcloud pubsub subscriptions update "
                     f"{r.name} --dead-letter-topic=<dl-topic> "
                     "--max-delivery-attempts=5` (grant the Pub/Sub service agent publish on "
                     "the DL topic). Terraform: `dead_letter_policy` on "
                     "`google_pubsub_subscription`. Poison messages are also a security "
                     "signal worth keeping."),
        detail=f"dead_letter_policy=absent delivery={'push' if push else 'pull'}",
        source_ref={"api": "pubsub subscriptions.list", "field": "deadLetterPolicy"},
    )]


# ══ Apigee ════════════════════════════════════════════════════════════════════
@detector(kinds=["gcp_apigee_proxy"], rule_id="GCP.APIGEE.TARGET_NO_TLS", severity="high",
          title="Apigee proxy target does not use TLS to its backend")
def apigee_target_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("deployments"):
        return []   # an undeployed proxy has no live traffic path to assess
    if not raw.get("targets_readable", True):
        return [Hit(
            observation=(f"target endpoint configs of deployed Apigee proxy '{r.name}' could "
                         f"not be read, so whether its backend traffic uses TLS is unknown"),
            remediation=("Grant the scan principal apigee.proxyrevisions.get (covered by "
                         "roles/apigee.readOnlyAdmin) so target TLS posture can be assessed."),
            detail="targets_readable=False",
            assessable=False,
            assessment_reason="revision targets GET was denied or failed",
            source_ref={"api": "apigee revisions/targets GET"},
        )]
    hits = []
    for t in raw.get("targets") or []:
        url = str(t.get("url") or "")
        plaintext_url = url.lower().startswith("http://")
        ssl_off = t.get("ssl_enabled") is False
        if not plaintext_url and not ssl_off:
            continue
        hits.append(Hit(
            observation=(f"Apigee proxy '{r.name}' target '{t.get('name')}' points at "
                         f"{url!r} with sSLInfo.enabled={t.get('ssl_enabled')} — every "
                         f"request the gateway forwards (including any credentials it "
                         f"injects) crosses the network to the backend unencrypted"),
            remediation=("Enable TLS on the TargetEndpoint: set `<SSLInfo><Enabled>true"
                         "</Enabled></SSLInfo>` and an https:// URL in the target's "
                         "HTTPTargetConnection, redeploy the revision, and pin a truststore "
                         "for the backend certificate."),
            detail=f"target={t.get('name')} url={url} ssl_enabled={t.get('ssl_enabled')}",
            source_ref={"api": "apigee revisions/targets GET", "target": t.get("name")},
        ))
    return hits


_LEGACY_TLS_PROTOCOLS = ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3")


@detector(kinds=["gcp_apigee_proxy"], rule_id="GCP.APIGEE.TARGET_LEGACY_TLS", severity="high",
          title="Apigee proxy target allows TLS below 1.2")
def apigee_target_legacy_tls(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("deployments") or not raw.get("targets_readable", True):
        return []   # the unreadable-targets gap is already filed by GCP.APIGEE.TARGET_NO_TLS
    hits = []
    for t in raw.get("targets") or []:
        legacy = [p for p in t.get("protocols") or [] if p in _LEGACY_TLS_PROTOCOLS]
        if not legacy:
            continue
        hits.append(Hit(
            observation=(f"Apigee proxy '{r.name}' target '{t.get('name')}' allows TLS "
                         f"protocols {legacy!r} in sSLInfo — the gateway will negotiate a "
                         f"protocol with known downgrade and decryption attacks to the "
                         f"backend"),
            remediation=("Restrict `<SSLInfo><Protocols>` on the TargetEndpoint to "
                         "`<Protocol>TLSv1.2</Protocol>` (and 1.3 where supported), then "
                         "redeploy the revision."),
            detail=f"target={t.get('name')} protocols={t.get('protocols')}",
            source_ref={"api": "apigee revisions/targets GET", "target": t.get("name")},
        ))
    return hits


# ══ Project posture ═══════════════════════════════════════════════════════════
_AUDIT_SERVICES = ("allServices", "pubsub.googleapis.com")


@detector(kinds=["gcp_project"], rule_id="GCP.PROJECT.AUDIT_LOGGING_DISABLED", severity="low",
          title="Data-access audit logging is not enabled for Pub/Sub")
def project_audit_logging(r, ctx) -> list:
    raw = r.raw or {}
    iam = raw.get("iam") or {}
    if not iam.get("readable", False):
        return [Hit(
            observation=(f"the IAM policy of project '{r.name}' could not be read, so its "
                         f"audit-logging configuration is unknown"),
            remediation=("Grant the scan principal resourcemanager.projects.getIamPolicy "
                         "(covered by roles/viewer) so audit posture can be assessed."),
            detail="iam.readable=False",
            assessable=False,
            assessment_reason="projects.getIamPolicy was denied",
            source_ref={"api": "cloudresourcemanager projects.getIamPolicy"},
        )]
    covered = [a for a in iam.get("audit_configs") or []
               if a.get("service") in _AUDIT_SERVICES and a.get("log_types")]
    if covered:
        return []
    return [Hit(
        observation=(f"project '{r.name}' has no auditConfig for pubsub.googleapis.com or "
                     f"allServices — data-access calls (publish, pull, getIamPolicy) leave "
                     f"no audit trail, so message-stream abuse is invisible after the fact"),
        remediation=("Enable Data Access audit logs: IAM & Admin → Audit Logs → Cloud "
                     "Pub/Sub (DATA_READ + DATA_WRITE), or add an `auditConfigs` entry via "
                     "`gcloud projects set-iam-policy` / Terraform "
                     "`google_project_iam_audit_config` with service "
                     "\"pubsub.googleapis.com\"."),
        detail="audit_configs=[] (no pubsub/allServices entry)",
        source_ref={"api": "cloudresourcemanager projects.getIamPolicy",
                    "field": "auditConfigs"},
    )]


@detector(kinds=["gcp_project"], rule_id="GCP.PROJECT.SERVICE_NOT_ASSESSED", severity="info",
          title="A GCP service could not be assessed with the granted permissions")
def project_service_not_assessed(r, ctx) -> list:
    """The third honest outcome at project scope: a service whose list call answered 403 —
    or whose API is not enabled on the project — is a COVERAGE GAP the connector recorded
    instead of failing the scan; surfaced here as not-assessable, never a clean pass."""
    raw = r.raw or {}
    hits = []
    for service, rec in sorted((raw.get("collection") or {}).items()):
        outcome = (rec or {}).get("outcome")
        if outcome not in ("access_denied", "api_disabled"):
            continue
        if outcome == "api_disabled":
            observation = (f"the {service} API is not enabled on project "
                           f"'{raw.get('project_id')}' ({rec.get('error')}), so no {service} "
                           f"resource was assessed")
            remediation = (f"If {service} is in use elsewhere this is fine; otherwise enable "
                           f"it (`gcloud services enable`) or ignore this surface. Until "
                           f"then its posture is unknown, not clean.")
        else:
            observation = (f"listing {service} resources in project "
                           f"'{raw.get('project_id')}' was denied ({rec.get('error')}), so "
                           f"no {service} resource was assessed")
            remediation = ("Grant the scan service account roles/viewer (or "
                           "pubsub.viewer / apigee.readOnlyAdmin per surface). Until then "
                           "this service's posture is unknown, not clean.")
        hits.append(Hit(
            observation=observation,
            remediation=remediation,
            detail=f"service={service} outcome={outcome} error={rec.get('error')}",
            assessable=False,
            assessment_reason=f"{service}: {rec.get('error')}",
            source_ref={"service": service},
        ))
    return hits
