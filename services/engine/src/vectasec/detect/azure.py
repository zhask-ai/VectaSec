"""Azure rulepack — config-time posture over what connect/azure.py collected.

Every rule reads REAL configuration evidence (the namespace's publicNetworkAccess /
disableLocalAuth / minimumTlsVersion fields, the authorization rule's rights list, the APIM
customProperties cipher toggles, the workflow's trigger types and accessControl block) and
cites it in the observation; none of them guesses from names or tags. Rules run on the
DISTINCT azure_* kinds the connector emits, so they never collide with the other packs.

Severity conventions (house):
  critical  anyone on the internet gets in
  high      legacy TLS floors, Manage-rights SAS at namespace scope, unrestricted HTTP triggers
  medium    public network access, SAS/local auth where AAD-only is possible, key-only APIs,
            capture to public storage
  low       hygiene (no dead-lettering on a shared queue, public APIM with no net restrictions)
  info      ranking hints and coverage notes

The third outcome is used throughout: sub-reads the connector recorded as unreadable, and
whole services that answered 401/403, become assessable=False coverage gaps — never a clean
pass, never a fabricated failure.
"""
from ..contracts import Hit
from ..registry import detector

_NS_KINDS = ("azure_servicebus_namespace", "azure_eventhub_namespace")


# ── shared: the namespace posture surface is identical for Service Bus / Event Hubs ──
def _service_word(r) -> str:
    return "Service Bus" if r.kind == "azure_servicebus_namespace" else "Event Hubs"


def _cli_word(r) -> str:
    return "servicebus" if r.kind == "azure_servicebus_namespace" else "eventhubs"


def _public_network_hits(r) -> list:
    raw = r.raw or {}
    if str(raw.get("public_network_access") or "Enabled").lower() == "disabled":
        return []
    pec = raw.get("private_endpoint_connections") or 0
    svc, cli = _service_word(r), _cli_word(r)
    return [Hit(
        observation=(f"{svc} namespace '{r.name}' has publicNetworkAccess "
                     f"{raw.get('public_network_access')!r} and {pec} private endpoint "
                     f"connection(s) — the namespace endpoint is reachable from the public "
                     f"internet, so authentication and TLS are the only remaining controls"
                     + ("" if pec else " and no private-endpoint path exists to fall back to")),
        remediation=(f"Disable public access and connect via Private Link: `az {cli} namespace "
                     f"update -g <rg> -n {r.name} --public-network-access Disabled` after "
                     f"creating a private endpoint (`az network private-endpoint create …`). "
                     f"Terraform: `public_network_access_enabled = false` on the namespace "
                     f"resource plus an `azurerm_private_endpoint`."),
        detail=(f"public_network_access={raw.get('public_network_access')} "
                f"private_endpoint_connections={pec}"),
        source_ref={"api": "ARM namespaces GET", "field": "properties.publicNetworkAccess"},
    )]


def _local_auth_hits(r) -> list:
    raw = r.raw or {}
    if raw.get("disable_local_auth"):
        return []
    svc, cli = _service_word(r), _cli_word(r)
    return [Hit(
        observation=(f"{svc} namespace '{r.name}' has disableLocalAuth false — SAS "
                     f"(shared-key) authentication is accepted alongside Entra ID, so a leaked "
                     f"connection string is a full credential with no identity, no MFA and no "
                     f"conditional access behind it"),
        remediation=(f"Move clients to Entra ID (managed identity + the Azure {svc} data-plane "
                     f"roles), then disable local auth: `az {cli} namespace update -g <rg> -n "
                     f"{r.name} --disable-local-auth true`. Terraform: `local_auth_enabled = "
                     f"false` on the namespace resource."),
        detail="disable_local_auth=False",
        source_ref={"api": "ARM namespaces GET", "field": "properties.disableLocalAuth"},
    )]


_LEGACY_TLS = ("1.0", "1.1")


def _tls_hits(r) -> list:
    raw = r.raw or {}
    tls = raw.get("minimum_tls_version")
    if str(tls) not in _LEGACY_TLS:
        return []   # absent means the platform default (1.2) applies — not a defect
    svc, cli = _service_word(r), _cli_word(r)
    return [Hit(
        observation=(f"{svc} namespace '{r.name}' has minimumTlsVersion {tls!r} — clients may "
                     f"negotiate a protocol with known downgrade and decryption attacks, and "
                     f"every SAS token they present crosses that channel"),
        remediation=(f"Raise the floor: `az {cli} namespace update -g <rg> -n {r.name} "
                     f"--minimum-tls-version 1.2` (Terraform: `minimum_tls_version = \"1.2\"`). "
                     f"Update any legacy clients first — they will be refused afterwards."),
        detail=f"minimum_tls_version={tls}",
        source_ref={"api": "ARM namespaces GET", "field": "properties.minimumTlsVersion"},
    )]


def _manage_sas_hits(r) -> list:
    raw = r.raw or {}
    if not raw.get("authorization_rules_readable", True):
        return [Hit(
            observation=(f"listing authorization rules on {_service_word(r)} namespace "
                         f"'{r.name}' was denied, so its SAS grant surface could not be read"),
            remediation=("Grant the scan principal the Reader role on the namespace (listing "
                         "rule names and rights needs no listKeys permission) so SAS posture "
                         "can be assessed."),
            detail="authorization_rules_readable=False",
            assessable=False,
            assessment_reason="authorizationRules GET returned 401/403",
            source_ref={"api": "ARM authorizationRules GET"},
        )]
    hits = []
    for rule in raw.get("authorization_rules") or []:
        rights = rule.get("rights") or []
        if "Manage" not in rights:
            continue
        svc, cli = _service_word(r), _cli_word(r)
        hits.append(Hit(
            observation=(f"{svc} namespace '{r.name}' authorization rule "
                         f"'{rule.get('name')}' carries rights {rights!r} at NAMESPACE scope — "
                         f"Manage is wildcard-equivalent: either of its two keys can send to, "
                         f"listen on and reconfigure every entity in the namespace, including "
                         f"minting further rules"),
            remediation=(f"Replace uses of '{rule.get('name')}' with entity-scoped Listen/Send "
                         f"rules (`az {cli} queue/topic/eventhub authorization-rule create "
                         f"--rights Listen`) or Entra ID data-plane roles, then stop "
                         f"distributing the Manage keys. The default RootManageSharedAccessKey "
                         f"cannot be deleted — treat its keys as break-glass and rotate them."),
            detail=f"rule={rule.get('name')} rights={rights}",
            source_ref={"api": "ARM authorizationRules GET", "rule": rule.get("name")},
        ))
    return hits


def _mk_ns_rule(kind: str, rule_id: str, severity: str, title: str, impl):
    @detector(kinds=[kind], rule_id=rule_id, severity=severity, title=title)
    def _rule(r, ctx, _impl=impl) -> list:
        return _impl(r)
    return _rule


for _kind, _prefix in (("azure_servicebus_namespace", "AZURE.SERVICEBUS"),
                       ("azure_eventhub_namespace", "AZURE.EVENTHUB")):
    _svc = "Service Bus" if "servicebus" in _kind else "Event Hubs"
    _mk_ns_rule(_kind, f"{_prefix}.PUBLIC_NETWORK_ACCESS", "medium",
                f"{_svc} namespace allows public network access", _public_network_hits)
    _mk_ns_rule(_kind, f"{_prefix}.LOCAL_AUTH_ENABLED", "medium",
                f"{_svc} namespace accepts SAS (local) authentication", _local_auth_hits)
    _mk_ns_rule(_kind, f"{_prefix}.TLS_MIN_LEGACY", "high",
                f"{_svc} namespace accepts TLS below 1.2", _tls_hits)
    _mk_ns_rule(_kind, f"{_prefix}.MANAGE_SAS_RULE", "high",
                f"{_svc} namespace has a Manage-rights SAS rule", _manage_sas_hits)


# ══ Service Bus entities ══════════════════════════════════════════════════════
@detector(kinds=["azure_sb_queue"], rule_id="AZURE.SERVICEBUS.QUEUE_NO_DEAD_LETTERING",
          severity="low", title="Service Bus queue does not dead-letter expired messages")
def sb_queue_no_dead_lettering(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("dead_lettering_on_message_expiration"):
        return []
    return [Hit(
        observation=(f"Service Bus queue '{r.name}' has deadLetteringOnMessageExpiration "
                     f"false — expired messages are silently deleted instead of being "
                     f"quarantined in the dead-letter subqueue for inspection"),
        remediation=("Enable it: `az servicebus queue update -g <rg> --namespace-name <ns> "
                     f"-n {r.name} --enable-dead-lettering-on-message-expiration true` "
                     "(Terraform: `dead_lettering_on_message_expiration = true`). Silently "
                     "dropped messages are also a security signal worth keeping."),
        detail="dead_lettering_on_message_expiration=False",
        source_ref={"api": "ARM queues GET",
                    "field": "properties.deadLetteringOnMessageExpiration"},
    )]


# ══ Event Hubs capture ════════════════════════════════════════════════════════
@detector(kinds=["azure_event_hub"], rule_id="AZURE.EVENTHUB.CAPTURE_PUBLIC_STORAGE",
          severity="medium", title="Event Hubs capture writes to a publicly accessible storage account")
def eh_capture_public_storage(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("capture_enabled"):
        return []
    storage = raw.get("capture_storage") or {}
    if not storage.get("readable"):
        return [Hit(
            observation=(f"event hub '{r.name}' captures every event to storage account "
                         f"{raw.get('capture_storage_account_id')!r}, but that account's "
                         f"network posture could not be read"),
            remediation=("Grant the scan principal Reader on the capture storage account so "
                         "its allowBlobPublicAccess / publicNetworkAccess settings can be "
                         "assessed — until then the capture archive's exposure is unknown."),
            detail=f"capture_enabled=True storage_account={raw.get('capture_storage_account_id')}",
            assessable=False,
            assessment_reason="capture-destination storage account GET was denied or failed",
            source_ref={"api": "ARM storageAccounts GET"},
        )]
    blob_public = storage.get("allow_blob_public_access")
    net_public = str(storage.get("public_network_access") or "Enabled").lower() != "disabled"
    if not blob_public and not net_public:
        return []
    return [Hit(
        observation=(f"event hub '{r.name}' captures every event to storage account "
                     f"{raw.get('capture_storage_account_id')!r} (container "
                     f"'{raw.get('capture_blob_container')}'), which has "
                     f"allowBlobPublicAccess={blob_public} and publicNetworkAccess="
                     f"{storage.get('public_network_access')} — the full message archive "
                     f"inherits that storage account's exposure"),
        remediation=("Harden the capture destination: `az storage account update -g <rg> -n "
                     "<account> --allow-blob-public-access false --public-network-access "
                     "Disabled` (plus a private endpoint), or point capture at a locked-down "
                     "account. Terraform: `allow_nested_items_to_be_public = false`, "
                     "`public_network_access_enabled = false` on `azurerm_storage_account`."),
        detail=(f"allow_blob_public_access={blob_public} "
                f"public_network_access={storage.get('public_network_access')} "
                f"container={raw.get('capture_blob_container')}"),
        source_ref={"api": "ARM storageAccounts GET",
                    "fields": ["allowBlobPublicAccess", "publicNetworkAccess"]},
    )]


# ══ API Management ════════════════════════════════════════════════════════════
_LEGACY_PROP_MARKERS = ("Protocols.Tls10", "Protocols.Tls11", "Protocols.Ssl30", "TripleDes")


@detector(kinds=["azure_apim"], rule_id="AZURE.APIM.LEGACY_TLS_CIPHERS", severity="high",
          title="API Management accepts legacy TLS protocols or ciphers")
def apim_legacy_tls(r, ctx) -> list:
    custom = (r.raw or {}).get("custom_properties") or {}
    enabled = sorted(k for k, v in custom.items()
                     if str(v).lower() == "true" and any(m in k for m in _LEGACY_PROP_MARKERS))
    if not enabled:
        return []
    short = [k.rsplit("Security.", 1)[-1] for k in enabled]
    return [Hit(
        observation=(f"API Management service '{r.name}' has legacy protocol/cipher toggles "
                     f"enabled in customProperties: {short!r} — the gateway will negotiate "
                     f"TLS 1.0/1.1, SSL 3.0 or 3DES with clients or backends, protocols with "
                     f"known downgrade and decryption attacks"),
        remediation=("Disable each toggle: `az apim update -g <rg> -n " + str(r.name) +
                     " --set customProperties.\"Microsoft.WindowsAzure.ApiManagement.Gateway."
                     "Security.Protocols.Tls10\"=false` (repeat per key), or portal → "
                     "Protocols + ciphers. Terraform: the `security` block on "
                     "`azurerm_api_management` (`enable_back_end_tls10 = false`, …)."),
        detail=f"enabled_legacy_properties={short}",
        source_ref={"api": "ARM service GET", "field": "properties.customProperties"},
    )]


@detector(kinds=["azure_api"], rule_id="AZURE.APIM.API_SUBSCRIPTION_KEY_ONLY",
          severity="medium", title="APIM API relies on a subscription key as its only access control")
def apim_api_key_only(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("subscription_required"):
        return []
    if raw.get("oauth2_configured") or raw.get("openid_configured"):
        return []
    return [Hit(
        observation=(f"APIM API '{raw.get('display_name') or r.name}' (path "
                     f"'{raw.get('path')}') has subscriptionRequired true and no OAuth2 or "
                     f"OpenID Connect authentication settings — subscription keys are "
                     f"long-lived, unsigned bearer strings routinely embedded in clients; "
                     f"they meter usage, they do not authenticate a caller"),
        remediation=("Attach real authentication: portal → API → Settings → security (OAuth "
                     "2.0 / OpenID Connect) plus a validate-jwt policy, e.g. `<validate-jwt "
                     "header-name=\"Authorization\">` in the API policy. Keep the "
                     "subscription key for metering only. Terraform: `oauth2_authorization` / "
                     "`openid_authentication` blocks on `azurerm_api_management_api`."),
        detail=(f"subscription_required=True oauth2_configured=False openid_configured=False "
                f"protocols={raw.get('protocols')}"),
        source_ref={"api": "ARM apis GET",
                    "fields": ["subscriptionRequired", "authenticationSettings"]},
    )]


@detector(kinds=["azure_apim"], rule_id="AZURE.APIM.PUBLIC_NO_NETWORK_RESTRICTIONS",
          severity="low", title="API Management gateway is public with no network restrictions")
def apim_public_no_restrictions(r, ctx) -> list:
    raw = r.raw or {}
    if str(raw.get("public_network_access") or "Enabled").lower() == "disabled":
        return []
    if str(raw.get("virtual_network_type") or "None").lower() != "none":
        return []   # Internal/External VNet injection is itself a network restriction
    return [Hit(
        observation=(f"API Management service '{r.name}' has publicNetworkAccess "
                     f"{raw.get('public_network_access')!r} and virtualNetworkType 'None' — "
                     f"the gateway {raw.get('gateway_url')!r} is reachable from the whole "
                     f"internet with no VNet or private-endpoint boundary in front of it"),
        remediation=("If the APIs are internal, inject the service into a VNet (`az apim "
                     "update --virtual-network Internal`) or disable public access behind a "
                     "private endpoint (`--public-network-access false` + `az network "
                     "private-endpoint create`). If it must be public, put WAF/Front Door and "
                     "ip-filter policies in front of sensitive APIs."),
        detail=(f"public_network_access={raw.get('public_network_access')} "
                f"virtual_network_type={raw.get('virtual_network_type')} "
                f"public_ips={raw.get('public_ip_addresses')}"),
        source_ref={"api": "ARM service GET",
                    "fields": ["publicNetworkAccess", "virtualNetworkType"]},
    )]


# ══ Logic Apps ════════════════════════════════════════════════════════════════
@detector(kinds=["azure_logic_app"], rule_id="AZURE.LOGICAPP.HTTP_TRIGGER_OPEN",
          severity="high", title="Logic App HTTP trigger has no caller restriction")
def logic_http_trigger_open(r, ctx) -> list:
    raw = r.raw or {}
    if str(raw.get("state") or "") != "Enabled":
        return []   # a disabled workflow's callback URL is inert; reported by WORKFLOW_DISABLED
    if not raw.get("triggers_readable", True):
        return [Hit(
            observation=(f"the definition of Logic App workflow '{r.name}' could not be read, "
                         f"so whether it exposes an HTTP trigger is unknown"),
            remediation=("Grant the scan principal Reader (Microsoft.Logic/workflows/read "
                         "returning the definition) so trigger exposure can be assessed."),
            detail="triggers_readable=False",
            assessable=False,
            assessment_reason="workflow GET did not return a definition",
            source_ref={"api": "ARM workflows GET"},
        )]
    http_triggers = raw.get("http_triggers") or []
    if not http_triggers or raw.get("trigger_ip_restrictions"):
        return []
    names = [f"{t.get('name')} ({t.get('type')})" for t in http_triggers]
    return [Hit(
        observation=(f"Logic App workflow '{r.name}' is Enabled with HTTP trigger(s) "
                     f"{names!r} and accessControl.triggers.allowedCallerIpAddresses is empty "
                     f"— the trigger's callback URL is callable from anywhere on the "
                     f"internet, gated only by the SAS signature embedded in the URL itself"),
        remediation=("Restrict callers: `az logic workflow update` / portal → Workflow "
                     "settings → Access control → allowed inbound IP ranges, or Terraform "
                     "`access_control { trigger { allowed_caller_ip_address_range = [...] } }` "
                     "on `azurerm_logic_app_workflow`. For caller identity, front the trigger "
                     "with APIM and validate a JWT; rotate the callback URL's access key if "
                     "it may have leaked."),
        detail=f"http_triggers={names} trigger_ip_restrictions=[]",
        source_ref={"api": "ARM workflows GET",
                    "fields": ["definition.triggers", "accessControl.triggers"]},
    )]


@detector(kinds=["azure_logic_app"], rule_id="AZURE.LOGICAPP.WORKFLOW_DISABLED",
          severity="info", title="Logic App workflow is present but disabled")
def logic_workflow_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if str(raw.get("state") or "") != "Disabled":
        return []
    return [Hit(
        observation=(f"Logic App workflow '{r.name}' has state Disabled — it still exists "
                     f"with its connections, parameters and history, and re-enabling it "
                     f"reactivates whatever triggers and credentials it holds"),
        remediation=("If the workflow is retired, delete it (`az logic workflow delete -g "
                     f"<rg> -n {r.name}`) so its API connections and callback URLs stop "
                     "existing; if it is seasonal, review its connections and access control "
                     "before the next enable."),
        detail="state=Disabled",
        source_ref={"api": "ARM workflows GET", "field": "properties.state"},
    )]


# ══ Subscription: the coverage-gap surface ════════════════════════════════════
_MAX_NAMED_GAPS = 8


def _named_gaps(gaps: list) -> str:
    """'queues of sb-open (http_403); apis of apim-legacy (http_403)' — capped so one denied
    permission across a thousand resources cannot produce an unreadable observation."""
    named = [f"{g.get('child')} of {g.get('parent')} ({g.get('error')})"
             for g in gaps[:_MAX_NAMED_GAPS]]
    rest = len(gaps) - len(named)
    return "; ".join(named) + (f"; and {rest} more" if rest > 0 else "")


@detector(kinds=["azure_subscription"], rule_id="AZURE.SUBSCRIPTION.SERVICE_NOT_ASSESSED",
          severity="info", title="An Azure service could not be assessed with the granted permissions")
def subscription_service_not_assessed(r, ctx) -> list:
    """The third honest outcome at subscription scope: a provider whose list call answered
    401/403 is a COVERAGE GAP — the connector recorded it instead of failing the scan, and
    this rule surfaces it as not-assessable rather than letting the absence of resources
    read as a clean pass.

    The same is true one level down. A provider that listed fine can still have lost whole
    child collections (a namespace's queues, a gateway's APIs), and those children leave NO
    resource behind to carry the gap: every rule keyed to them simply has nothing to run on.
    Those are the connector's child_gaps records, reported here too so a partially collected
    service is never counted as fully assessed."""
    raw = r.raw or {}
    hits = []
    for service, rec in sorted((raw.get("collection") or {}).items()):
        rec = rec or {}
        if rec.get("outcome") == "access_denied":
            hits.append(Hit(
                observation=(f"listing {service} resources in subscription "
                             f"{raw.get('subscription_id')} was denied for app "
                             f"{raw.get('client_id')} ({rec.get('error')}), so no {service} "
                             f"resource was assessed"),
                remediation=("Assign the built-in Reader role on the subscription to the app "
                             "registration (`az role assignment create --assignee "
                             f"{raw.get('client_id')} --role Reader --scope /subscriptions/"
                             f"{raw.get('subscription_id')}`). Until then this service's posture "
                             "is unknown, not clean."),
                detail=f"service={service} error={rec.get('error')}",
                assessable=False,
                assessment_reason=f"{service} list call returned {rec.get('error')}",
                source_ref={"service": service},
            ))
            continue
        gaps = rec.get("child_gaps") or []
        if not gaps:
            continue
        hits.append(Hit(
            observation=(f"{service} resources in subscription {raw.get('subscription_id')} "
                         f"listed successfully, but {len(gaps)} read(s) beneath them were "
                         f"denied or failed for app {raw.get('client_id')}, so those "
                         f"resources were never collected and every rule keyed to them had "
                         f"nothing to run on: {_named_gaps(gaps)}"),
            remediation=("Assign the built-in Reader role at subscription scope (`az role "
                         f"assignment create --assignee {raw.get('client_id')} --role Reader "
                         f"--scope /subscriptions/{raw.get('subscription_id')}`) — a role "
                         "scoped to the parent resources only leaves these child reads "
                         "denied. The parents were assessed; the children named here were "
                         "not, so their posture is unknown, not clean."),
            detail=f"service={service} child_gaps={len(gaps)}",
            assessable=False,
            assessment_reason=f"{len(gaps)} child read(s) under {service} were denied or failed",
            source_ref={"service": service, "child_gaps": gaps},
        ))
    return hits
