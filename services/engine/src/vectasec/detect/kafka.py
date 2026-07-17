"""KAFKA rulepack — read-only posture detectors.

Two facts about the real Admin API shape everything below:

  * The broker REDACTS every PASSWORD-typed config to None, including
    `allow.everyone.if.no.acl.found`. A rule written as `config.get(k) == "true"` can never fire
    against a real broker. Where a value is unreadable these rules say so instead of guessing.
  * `describe_acls` with no authorizer returns `[]` on some brokers and raises
    SECURITY_DISABLED on others, so an empty ACL list distinguishes nothing on its own. Only
    `authorizer.class.name` can.

Everything is read from the per-broker describe_configs snapshot the connector took against a
CONCRETE broker id; `cluster_dynamic_config` (the empty-resource-name snapshot) is used by
exactly one rule, whose update mode is genuinely cluster-wide.
"""
import ipaddress

from ..contracts import Hit
from ..registry import detector

_PROTOCOLS = {"PLAINTEXT", "SSL", "SASL_PLAINTEXT", "SASL_SSL"}
_LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
_INTERNAL_TOPICS = ("__consumer_offsets", "__transaction_state", "__amazon_msk_canary")

# Fallback only — the connector resolves source names itself. A snapshot captured before it did
# (the test fixture) carries the raw librdkafka int. Values read off ConfigSource in
# confluent-kafka 2.15.0; note GROUP_CONFIG is 8, not 6 — the enum is not contiguous.
_SOURCE = {0: "UNKNOWN_CONFIG", 1: "DYNAMIC_TOPIC_CONFIG", 2: "DYNAMIC_BROKER_CONFIG",
           3: "DYNAMIC_DEFAULT_BROKER_CONFIG", 4: "STATIC_BROKER_CONFIG", 5: "DEFAULT_CONFIG",
           8: "GROUP_CONFIG"}

_RANK = ["info", "low", "medium", "high", "critical"]


# ── config access ─────────────────────────────────────────────────────────
def _entry(cfg: dict, key: str):
    return (cfg or {}).get(key)


def _val(cfg: dict, key: str):
    e = _entry(cfg, key)
    return None if e is None else e.get("value")


def _source(entry) -> str:
    if entry is None:
        return "ABSENT"
    return entry.get("source_name") or _SOURCE.get(entry.get("source"), f"source={entry.get('source')}")


def _is_true(entry) -> bool:
    """The broker parses these with Boolean.parseBoolean(value.trim()), so 'TRUE' and ' true '
    are true and a literal `== "true"` compare is a false negative. A None value (redacted or
    unset) is NOT false — callers must handle that case separately."""
    v = entry.get("value") if entry else None
    return v is not None and v.strip().lower() == "true"


def _names(cfg: dict, key: str) -> set:
    v = _val(cfg, key)
    return {n.strip() for n in v.split(",") if n.strip()} if v else set()


def _lname(name) -> str:
    """Kafka's ListenerName.normalised() — toUpperCase(Locale.ROOT).

    The broker puts EVERY listener name through this before comparing anything: the entries of
    `listeners` and `advertised.listeners` (EndPoint.createEndPoint), the keys of
    `listener.security.protocol.map`, `controller.listener.names`, and
    `inter.broker.listener.name`. Case is therefore never significant on the broker, and a
    case-sensitive compare here silently drops a listener out of a rule (fail-open) or hands one
    rule a listener that belongs to another. Every listener-name comparison in this module goes
    through this function; the raw string is still what gets written into the observation.

    The `listener.name.<name>.<key>` config PREFIX is the one place the broker LOWERcases, which
    is why _effective/_mechanisms use .lower() rather than this.
    """
    return (name or "").strip().upper()


def _controller(cfg: dict) -> set:
    """Normalised controller.listener.names — the broker reads it through ListenerName.normalised
    too, so `controller.listener.names=CONTROLLER` matches a listener written `controller://`."""
    return {_lname(n) for n in _names(cfg, "controller.listener.names")}


def _effective(cfg: dict, key: str, listener: str):
    """Resolve `key` for one listener -> (entry, is_listener_scoped).

    The per-listener prefix requires the listener name LOWERCASED while `listeners` conventionally
    uses uppercase — a case-sensitive lookup misses the override and misreports a hardened
    listener. A dynamically-set value outranks a static one, and at equal source the
    listener-scoped key outranks the generic one; ConfigSource ints happen to already sort that
    way (DYNAMIC_BROKER=2 < STATIC=4 < DEFAULT=5), so the source doubles as the rank.
    """
    cands = []
    if listener:
        p = _entry(cfg, f"listener.name.{listener.lower()}.{key}")
        if p is not None:
            cands.append((p.get("source", 5), 0, p, True))
    g = _entry(cfg, key)
    if g is not None:
        cands.append((g.get("source", 5), 1, g, False))
    if not cands:
        return None, False
    cands.sort(key=lambda c: (c[0], c[1]))
    return cands[0][2], cands[0][3]


# ── listeners ─────────────────────────────────────────────────────────────
def _listeners(cfg: dict) -> list:
    """(name, host, port) per `listeners` entry. An empty host means the broker binds every
    interface, which is not the same as an unset listener."""
    raw = _val(cfg, "listeners")
    if not raw:
        return []
    out = []
    for part in raw.split(","):
        name, sep, hostport = part.strip().partition("://")
        if not sep:
            continue
        host, _, port = hostport.rpartition(":")   # rpartition keeps an IPv6 [::1] literal intact
        out.append((name.strip(), host.strip(), port.strip()))
    return out


def _advertised(cfg: dict) -> dict:
    """name -> advertised host. `advertised.listeners` defaults to null and falls back to
    `listeners`, so an absent value does not mean nothing is advertised.

    Keyed on the NORMALISED name (_lname): `advertised.listeners` and `listeners` are independent
    operator-written strings that the broker matches case-insensitively, so
    `listeners=EXTERNAL://...` + `advertised.listeners=external://host:9092` is one listener to the
    broker and must be one listener here."""
    raw = _val(cfg, "advertised.listeners")
    if not raw:
        return {_lname(n): h for n, h, _ in _listeners(cfg)}
    out = {}
    for part in raw.split(","):
        name, sep, hostport = part.strip().partition("://")
        if sep:
            out[_lname(name)] = hostport.rpartition(":")[0].strip()
    return out


def _resolve(cfg: dict, name: str):
    """Listener NAME -> security protocol, or None when unresolvable.

    Resolve through the map, never by name-matching: `SSL:PLAINTEXT` remaps a listener called SSL
    to PLAINTEXT and a name test misses it. When the map is unset the default is the identity
    map, so a listener called PLAINTEXT really is PLAINTEXT — an absent map is not "no listeners".
    A name that resolves nowhere is a broker startup error and cannot occur on a live cluster, so
    it is a scan gap (None), not a FAIL.

    Both sides of the map lookup are normalised (_lname) because the broker normalises both:
    `listener.security.protocol.map` keys go through ListenerName.normalised() in
    KafkaConfig.listenerSecurityProtocolMap and `listeners` names through the same call in
    EndPoint.createEndPoint. A case-sensitive compare here is fail-open twice over — it drops the
    listener out of every transport rule when the map key case differs from the listeners case,
    and it falls through to the exact name-test this docstring forbids, reporting a listener
    named SSL but remapped to PLAINTEXT as encrypted.
    """
    key = _lname(name)
    raw = _val(cfg, "listener.security.protocol.map")
    if raw:
        for pair in raw.split(","):
            n, _, p = pair.strip().partition(":")
            if _lname(n) == key:
                return p.strip().upper()
    return key if key in _PROTOCOLS else None


def _mechanisms(cfg: dict, listener: str):
    """Effective SASL mechanism set for one listener, or None when unreadable.

    The per-listener override REPLACES the global value rather than merging with it; implementing
    it as a union false-positives on `global=SCRAM-SHA-512,PLAIN` + `listener...=PLAIN`.
    """
    p = _entry(cfg, f"listener.name.{listener.lower()}.sasl.enabled.mechanisms")
    if p is not None:
        v = p.get("value")
        if v is None:
            return None   # a listener name containing a dot defeats the broker's own prefix regex
        return [m.strip().upper() for m in v.split(",") if m.strip()]
    v = _val(cfg, "sasl.enabled.mechanisms") or "GSSAPI"
    return [m.strip().upper() for m in v.split(",") if m.strip()]


def _routable(host: str) -> bool:
    """True only for a literal, non-private IP. A DNS name resolves nowhere a config scan can
    see, so it stays unknown rather than being assumed public."""
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
                or ip.is_multicast or ip.is_reserved)


def _authorizer(cfg: dict):
    """(entry, state) where state is set | unset | absent.

    On real Apache Kafka the key is ALWAYS present with a ConfigDef default of "", so absent
    means a non-Apache or proxied broker — inconclusive, never a finding.
    """
    e = _entry(cfg, "authorizer.class.name")
    if e is None:
        return None, "absent"
    return e, ("unset" if not (e.get("value") or "").strip() else "set")


def _anonymous_listeners(ctx) -> list:
    """Listeners that mint User:ANONYMOUS, across every broker (listener config can legitimately
    diverge per broker). PLAINTEXT always does; SSL does unless ssl.client.auth is `required` —
    both `none` and `requested` yield ANONYMOUS."""
    out = []
    for b in ctx.of_kind("broker"):
        cfg = b.raw.get("config") or {}
        controller = _controller(cfg)
        for name, _host, _port in _listeners(cfg):
            if _lname(name) in controller:
                continue
            proto = _resolve(cfg, name)
            if proto == "PLAINTEXT":
                out.append((b.raw.get("id"), name, "PLAINTEXT"))
            elif proto == "SSL":
                e, _ = _effective(cfg, "ssl.client.auth", name)
                v = ((e.get("value") if e else None) or "none").strip().lower()
                if v != "required":
                    out.append((b.raw.get("id"), name, f"SSL with ssl.client.auth={v}"))
    return out


# ── ACL helpers ───────────────────────────────────────────────────────────
# confluent-kafka's ResourceType has NO CLUSTER member (UNKNOWN, ANY, TOPIC, GROUP, BROKER,
# TRANSACTIONAL_ID), so an ACL on Kafka's CLUSTER resource — conventionally the LITERAL name
# "kafka-cluster" — surfaces here as restype BROKER. That is why the cluster-level severity tiers
# below test for BROKER and not for a "CLUSTER" string that can never appear.
def _acls(resource):
    """(bindings, outcome). Only a cluster-scoped broker owns the ACL rules, so one cluster-wide
    fact yields one finding rather than one per broker."""
    a = resource.raw.get("acls") or {}
    return a.get("bindings") or [], a.get("outcome")


def _patterns_overlap(ta, na, tb, nb) -> bool:
    """Do two resource patterns admit a common name? LITERAL '*' is the wildcard resource and
    matches everything, so patterns must be reasoned about, not string-compared."""
    if (ta, na) == ("LITERAL", "*") or (tb, nb) == ("LITERAL", "*"):
        return True
    if ta == "LITERAL" and tb == "LITERAL":
        return na == nb
    if ta == "LITERAL" and tb == "PREFIXED":
        return na.startswith(nb)
    if ta == "PREFIXED" and tb == "LITERAL":
        return nb.startswith(na)
    if ta == "PREFIXED" and tb == "PREFIXED":
        return na.startswith(nb) or nb.startswith(na)
    return False


def _denied_by(allow: dict, bindings: list):
    """An overriding DENY for the same principal, if one exists. DENY short-circuits ALLOW in the
    authorizer, so a wildcard ALLOW narrowed by DENY is not unconditional — but DENY coverage is
    usually partial, so this downgrades and annotates rather than suppressing."""
    for b in bindings:
        if b.get("permission_type") != "DENY" or b.get("principal") != allow.get("principal"):
            continue
        if b.get("restype") != allow.get("restype"):
            continue
        if not _patterns_overlap(allow.get("pattern"), allow.get("name") or "",
                                 b.get("pattern"), b.get("name") or ""):
            continue
        if not (b.get("operation") == allow.get("operation")
                or "ALL" in (b.get("operation"), allow.get("operation"))):
            continue
        if not (b.get("host") == allow.get("host") or "*" in (b.get("host"), allow.get("host"))):
            continue
        return b
    return None


def _covers(binding: dict, topic: str) -> bool:
    pat, name = binding.get("pattern"), binding.get("name") or ""
    if pat == "LITERAL":
        return name in ("*", topic)
    if pat == "PREFIXED":
        return topic.startswith(name)
    return False


def _downgrade(sev: str) -> str:
    return _RANK[max(0, _RANK.index(sev) - 1)]


def _worst(sevs) -> str:
    return max(sevs, key=_RANK.index)


def _uniform(hits: list) -> list:
    """Every Hit a detector returns for one resource collapses into ONE finding (fingerprint is
    rule + resource), whose severity is whichever Hit the loop wrote last. Give the group the
    worst severity so the recorded severity does not depend on write order; each Hit still files
    its own observation in the ledger.

    A group either sets severity on every Hit or on none of them — an all-None group already
    resolves uniformly to the decorator's severity, so it is left alone.
    """
    sevs = [h.severity for h in hits if h.severity]
    if sevs and len(sevs) == len(hits):
        sev = _worst(sevs)
        for h in hits:
            h.severity = sev
    return hits


# ═══ Transport & listener rules ═══════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KAFKA.LISTENER.PLAINTEXT", severity="high",
          title="Broker listener mapped to PLAINTEXT security protocol")
def listener_plaintext(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    controller = _controller(cfg)
    inter = _val(cfg, "inter.broker.listener.name")
    adv = _advertised(cfg)
    _, authz_state = _authorizer(cfg)
    pmap = _val(cfg, "listener.security.protocol.map")
    src = _source(_entry(cfg, "listeners"))

    hits = []
    for name, host, port in _listeners(cfg):
        if _lname(name) in controller:
            continue   # controller listeners carry no client traffic; scoped out of this rule
        if _resolve(cfg, name) != "PLAINTEXT":
            continue
        adv_host = adv.get(_lname(name))
        if host in _LOOPBACK:
            sev = "low"           # admin/health-check listener, not reachable off-host
        elif adv_host and _routable(adv_host):
            sev = "critical"
        elif _lname(name) == _lname(inter) and _lname(name) not in adv:
            sev = "medium"        # replication-only path, never handed to clients
        elif authz_state == "unset":
            sev = "critical"      # client-facing + no authorizer = anyone with network access
        else:
            sev = "high"
        hits.append(Hit(
            observation=(
                f"Broker {bid}: listener `{name}://{host}:{port}` (config listeners, source={src}) "
                f"resolves to security protocol PLAINTEXT via listener.security.protocol.map="
                f"{pmap!r}; advertised.listeners host for {name} is {adv_host!r}, "
                f"authorizer.class.name is {'unset (empty)' if authz_state == 'unset' else authz_state}. "
                f"The broker performs no authentication and applies no transport encryption on "
                f"this listener; clients bind to User:ANONYMOUS."
            ),
            remediation=(
                f"Remap {name} to SSL or SASL_SSL in listener.security.protocol.map, or drop it "
                f"from `listeners`. Do not remove PLAINTEXT:PLAINTEXT from the default map — that "
                f"is a different config and is not the defect. If a PLAINTEXT path is genuinely "
                f"required, bind it to a private interface and keep it off client networks. "
                f"Adding a new listener-name-to-protocol mapping needs two rolling bounces "
                f"(KIP-103)."
            ),
            detail=(
                "Broker-side facts only: the scan cannot see the network path, so a "
                "TLS-terminating sidecar/LB or service-mesh mTLS would encrypt this traffic "
                "outside the broker. Suppress per-listener as encrypted-by-external-transport "
                "if that applies."
            ),
            severity=sev,
            source_ref={"config_key": "listeners", "listener": name,
                        "protocol_map": "listener.security.protocol.map"},
        ))
    return _uniform(hits)


@detector(kinds=["broker"], rule_id="KAFKA.LISTENER.SASL_PLAINTEXT", severity="high",
          title="SASL authentication offered without TLS (SASL_PLAINTEXT listener)")
def listener_sasl_plaintext(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    controller = _controller(cfg)

    hits = []
    for name, host, port in _listeners(cfg):
        if _resolve(cfg, name) != "SASL_PLAINTEXT":
            continue
        mechs = _mechanisms(cfg, name)
        if mechs is None:
            continue   # override present but redacted -> indeterminate, not a finding
        is_controller = _lname(name) in controller
        # Per-mechanism refinement: all traffic is unencrypted either way, but only PLAIN and
        # OAUTHBEARER put a replayable secret on the wire.
        if {"PLAIN", "OAUTHBEARER"} & set(mechs):
            sev = "high"
        elif {"SCRAM-SHA-256", "SCRAM-SHA-512"} & set(mechs):
            sev = "high"
        else:
            sev = "medium"   # GSSAPI: Kerberos supplies its own auth, no password on the wire
        if host in _LOOPBACK:
            sev = "low"
        override_key = f"listener.name.{name.lower()}.sasl.enabled.mechanisms"
        origin = (override_key if _entry(cfg, override_key) else
                  f"sasl.enabled.mechanisms, source={_source(_entry(cfg, 'sasl.enabled.mechanisms'))}")
        hits.append(Hit(
            observation=(
                f"Broker {bid}: listener `{name}://{host}:{port}` resolves to SASL_PLAINTEXT via "
                f"listener.security.protocol.map; its effective sasl.enabled.mechanisms is "
                f"{','.join(mechs)} (from {origin}). SASL authentication is offered over an "
                f"unencrypted transport, so the authentication exchange and all subsequent data "
                f"traffic are transmitted without TLS."
            ),
            remediation=(
                f"Map {name} to SASL_SSL in listener.security.protocol.map and configure the "
                f"keystore (listener.name.{name.lower()}.ssl.keystore.location / "
                f".ssl.keystore.password, or the broker-wide ssl.keystore.* keys). This is a "
                f"breaking change requiring client-side coordination. Rotate credentials only "
                f"where one was actually exchanged: required for PLAIN and OAUTHBEARER, arguable "
                f"for SCRAM, overreach for GSSAPI."
                + (" This is a KRaft controller listener, so the credential-rotation step does "
                   "not apply to client principals." if is_controller else "")
            ),
            detail=(
                "Not claimed: that credentials traverse the wire in clear. That is false for "
                "SCRAM (challenge-response, the password is never sent) and GSSAPI. Suppress "
                "per-listener if a mesh/sidecar/LB terminates TLS outside the broker."
            ),
            severity=sev,
            source_ref={"config_key": "listeners", "listener": name,
                        "mechanisms_key": "sasl.enabled.mechanisms"},
        ))
    return _uniform(hits)


@detector(kinds=["broker"], rule_id="KAFKA.INTERBROKER.PLAINTEXT", severity="high",
          title="Inter-broker replication traffic is unencrypted")
def interbroker_plaintext(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")

    # Evaluation order is load-bearing. security.inter.broker.protocol is ALWAYS returned with its
    # PLAINTEXT default even when inter.broker.listener.name is set and wins; reading it first
    # emits a false finding against a correctly-secured SSL cluster.
    inter = _val(cfg, "inter.broker.listener.name")
    if inter:
        proto = _resolve(cfg, inter)
        if proto is None:
            return []   # unmappable listener name cannot happen on a live broker -> scan gap
        origin = f"inter.broker.listener.name={inter} mapped to {proto}"
        ref = {"config_key": "inter.broker.listener.name", "listener": inter}
    else:
        e = _entry(cfg, "security.inter.broker.protocol")
        proto = (e.get("value") if e else None) or "PLAINTEXT"
        proto = proto.upper()
        origin = f"security.inter.broker.protocol={proto} (source={_source(e)})"
        ref = {"config_key": "security.inter.broker.protocol"}

    if proto not in ("PLAINTEXT", "SASL_PLAINTEXT"):
        return []

    # Pure PLAINTEXT additionally provides no broker authentication; SASL_PLAINTEXT loses only
    # confidentiality. Same severity, different urgency.
    extra = ("It also performs no broker authentication, so a network-adjacent host can "
             "impersonate a broker." if proto == "PLAINTEXT" else
             "Broker authentication still occurs via SASL; confidentiality is what is lost.")
    return [Hit(
        observation=(
            f"Broker {bid}: effective inter-broker protocol is {proto} (from {origin}); all "
            f"replicated topic data crosses the network unencrypted. {extra}"
        ),
        remediation=(
            "Set inter.broker.listener.name to a listener mapped to SSL or SASL_SSL, or set "
            "security.inter.broker.protocol=SSL — never both, setting both is a broker startup "
            "error. Roll brokers using the documented two-phase procedure in 'Incorporating "
            "Security Features in a Running Cluster' so replication is not interrupted."
        ),
        detail=(
            "Detection is exact; residual false positives are risk-acceptance cases only "
            "(IPsec/WireGuard underlay, isolated VLAN, dev cluster) and warrant a suppression "
            "rather than a lower severity. Covers broker-to-broker only — KRaft controller "
            "traffic uses controller.listener.names and is not in scope here."
        ),
        source_ref=ref,
    )]


# ═══ Authorization rules ══════════════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KAFKA.AUTHZ.NO_AUTHORIZER", severity="high",
          title="No authorizer configured — every authenticated principal has full cluster access")
def authz_no_authorizer(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    e, state = _authorizer(cfg)
    if state != "unset":
        return []
    bindings, outcome = _acls(resource)

    # The rulepack's conjunct is describe_acls raising SecurityDisabledException. The real broker
    # returns [] instead, so requiring the exception would make this rule undeadable. What the
    # conjunct actually defends against is Kafka-API-compatible platforms that enforce authz
    # elsewhere (Confluent Cloud, Redpanda, MSK Serverless, Event Hubs, WarpStream) — and those
    # all return REAL ACLs. Contradicting evidence, not a missing exception, is the gate.
    if outcome == "ok" and bindings:
        return []
    if outcome == "error":
        return []   # could not read ACLs -> indeterminate, never a pass and never a finding

    if outcome == "security_disabled":
        corroboration = "describe_acls raised SecurityDisabledException (error code 54)"
    elif outcome == "ok":
        corroboration = ("describe_acls returned 0 bindings, which on its own distinguishes "
                         "nothing — an authorizer with zero ACLs returns 0 bindings too")
    else:
        corroboration = "ACL state was not collected"

    plaintext = [f"broker {b}: {n} ({p})" for b, n, p in _anonymous_listeners(ctx)]
    sev = "critical" if plaintext else "high"
    return [Hit(
        observation=(
            f"Broker {bid}: authorizer.class.name is the empty string (is_default="
            f"{e.get('is_default')}, source={_source(e)}) and {corroboration}. No authorization "
            f"is enforced, so any principal that completes authentication may read, write, and "
            f"administer every resource."
            + (f" Listeners that admit unauthenticated clients as User:ANONYMOUS: "
               f"{'; '.join(plaintext)}." if plaintext else "")
        ),
        remediation=(
            "Set authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer on "
            "KRaft brokers AND controllers, define super.users for the operator principals, and "
            "keep allow.everyone.if.no.acl.found=false (already the default). Provision ACLs for "
            "every client BEFORE enabling the authorizer or you will lock them out. The key is "
            "static — it cannot be set via incrementalAlterConfigs and needs a rolling restart."
        ),
        detail=(
            "Any non-empty authorizer class passes this rule, not just the Apache ones — "
            "Ranger, OPA, Keycloak and ConfluentServerAuthorizer are all legitimate."
            + (" Escalated to critical: an unauthenticated listener exists, so User:ANONYMOUS "
               "gets full cluster access." if plaintext else "")
        ),
        severity=sev,
        source_ref={"config_key": "authorizer.class.name", "api": "describe_acls",
                    "acl_outcome": outcome},
    )]


@detector(kinds=["broker"], rule_id="KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", severity="high",
          title="allow.everyone.if.no.acl.found — resources without ACLs are open to all principals")
def authz_allow_everyone(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")

    # Precondition: with no authorizer this setting is inert and the finding text would be wrong.
    # That cluster has a strictly worse problem, owned by KAFKA.AUTHZ.NO_AUTHORIZER.
    _, state = _authorizer(cfg)
    if state != "set":
        return []

    e = _entry(cfg, "allow.everyone.if.no.acl.found")
    if e is None:
        return []   # genuinely absent -> the MSK "assume true" heuristic is a guess, not evidence

    bindings, outcome = _acls(resource)
    anon = _anonymous_listeners(ctx)

    if e.get("is_sensitive") and e.get("value") is None:
        # The real broker types this config PASSWORD and redacts it. is_default=false proves it was
        # explicitly configured; it does NOT prove the value is true (an explicit `=false` looks
        # identical). Report only what was read.
        if e.get("is_default"):
            return []
        return [Hit(
            observation=(
                f"Broker {bid}: allow.everyone.if.no.acl.found is explicitly configured "
                f"(is_default=false, source={_source(e)}) with authorizer.class.name="
                f"{_val(cfg, 'authorizer.class.name')!r}, but the broker reports it "
                f"is_sensitive=true and redacts its value to null, so the effective value cannot "
                f"be read through the Admin API. The Apache default is false; an explicit "
                f"override is either false (redundant) or true (every ACL-less resource is open "
                f"to every authenticated principal) and this scan cannot tell which."
            ),
            remediation=(
                "Read the effective value directly from server.properties (or the MSK cluster "
                "configuration) on this broker. If it is true, add explicit ALLOW ACLs for every "
                "legitimate client and then set allow.everyone.if.no.acl.found=false. On AWS MSK "
                "this is set via an MSK cluster configuration, not via AlterConfigs."
            ),
            detail=(
                "Severity is medium, not high: the trigger is an unreadable explicit override, "
                "not an observed `true`. This scan cannot reach the MSK control plane, so an "
                "IAM-access-control MSK cluster — where this property has no effect — cannot be "
                "excluded here and should be suppressed if that is the case."
            ),
            severity="medium",
            source_ref={"config_key": "allow.everyone.if.no.acl.found", "redacted": True},
        )]

    if not _is_true(e):
        return []

    detail = ""
    if outcome == "ok":
        topics = [t for t in ctx.of_kind("topic")
                  if not t.name.startswith(_INTERNAL_TOPICS)]
        uncovered = [t.name for t in topics
                     if not any(b.get("restype") == "TOPIC" and _covers(b, t.name)
                                for b in bindings)]
        detail = (f"Blast radius: {len(uncovered)} of {len(topics)} non-internal topics have no "
                  f"matching ACL binding (LITERAL, wildcard and PREFIXED patterns all counted as "
                  f"coverage) and are therefore readable/writable by every authenticated "
                  f"principal.")

    sev = "critical" if anon else "high"
    return [Hit(
        observation=(
            f"Broker {bid}: allow.everyone.if.no.acl.found={e.get('value')!r} (is_default="
            f"{e.get('is_default')}, source={_source(e)}) with authorizer.class.name="
            f"{_val(cfg, 'authorizer.class.name')!r}; any resource with no matching ACL is "
            f"readable and writable by every authenticated principal."
            + (f" Listeners admitting unauthenticated clients as User:ANONYMOUS: "
               f"{'; '.join(f'broker {b}: {n} ({p})' for b, n, p in anon)}." if anon else "")
        ),
        remediation=(
            "Add explicit ALLOW ACLs for every legitimate client FIRST, then set "
            "allow.everyone.if.no.acl.found=false. On AWS MSK this must be set through an MSK "
            "cluster configuration. If the MSK cluster uses IAM access control this property has "
            "no effect and the finding should be suppressed."
        ),
        detail=detail + (" Escalated to critical: unauthenticated access is reachable, so "
                         "User:ANONYMOUS inherits this too." if anon else ""),
        severity=sev,
        source_ref={"config_key": "allow.everyone.if.no.acl.found", "api": "describe_acls"},
    )]


@detector(kinds=["broker"], rule_id="KAFKA.ACL.WILDCARD_PRINCIPAL", severity="high",
          title="ACL grants access to the wildcard principal `User:*`")
def acl_wildcard_principal(resource, ctx):
    if not resource.raw.get("cluster_scope"):
        return []   # ACLs are one cluster-wide fact; one broker owns the rule
    bindings, outcome = _acls(resource)
    if outcome != "ok":
        return []   # SECURITY_DISABLED belongs to NO_AUTHORIZER; an error is indeterminate

    critical_ops = {"ALL", "CLUSTER_ACTION", "ALTER_CONFIGS"}
    high_ops = {"ALL", "WRITE", "ALTER", "ALTER_CONFIGS", "CLUSTER_ACTION", "DELETE"}
    anon = _anonymous_listeners(ctx)

    hits = []
    for b in bindings:
        # PrincipalType is case-sensitive — `user:*` is a different principal, not a match.
        if b.get("permission_type") != "ALLOW" or b.get("principal") != "User:*":
            continue
        op = b.get("operation")
        if b.get("restype") == "BROKER" and op in critical_ops and b.get("host") == "*":
            sev = "critical"
        elif op in high_ops:
            sev = "high"
        elif op == "READ":
            sev = "medium"
        else:
            sev = "low"   # DESCRIBE / DESCRIBE_CONFIGS / IDEMPOTENT_WRITE grant no data access
        deny = _denied_by(b, bindings)
        if deny:
            sev = _downgrade(sev)
        hits.append(Hit(
            observation=(
                f"ACL binding grants ALLOW {op} on "
                f"{b.get('restype')}:{b.get('pattern')}:{b.get('name')!r} to principal User:* "
                f"from host {b.get('host')!r} (read via describe_acls). Every principal — "
                f"including User:ANONYMOUS on unauthenticated listeners — inherits this "
                f"permission, unless narrowed by a matching DENY binding."
                + (f" An overriding DENY exists for the same principal: DENY "
                   f"{deny.get('operation')} on {deny.get('restype')}:{deny.get('pattern')}:"
                   f"{deny.get('name')!r} from host {deny.get('host')!r}." if deny else "")
                + (f" Listeners that mint User:ANONYMOUS: "
                   f"{'; '.join(f'broker {i}: {n} ({p})' for i, n, p in anon)}." if anon else "")
            ),
            remediation=(
                "Issue the narrowly-scoped per-principal ACLs FIRST, then remove the wildcard — "
                "the reverse order breaks clients between the two commands. `--remove` needs a "
                "resource specifier: kafka-acls.sh --bootstrap-server <host:9092> --remove "
                f"--allow-principal 'User:*' --operation {op} --{(b.get('restype') or '').lower()} "
                f"{b.get('name')} --resource-pattern-type {(b.get('pattern') or '').lower()} "
                "--force. Quote 'User:*' so the shell does not glob it. If a shared grant is "
                "genuinely needed, keep the wildcard but restrict the operation to the minimum."
            ),
            detail=(
                "User:* grants to authenticated principals — this is privilege escalation and "
                "lateral movement, not unauthenticated access; unauthenticated exposure is a "
                "property of the listener. IDEMPOTENT_WRITE on the cluster and DESCRIBE on a "
                "shared topic are widely deployed and benign; operator-provisioned bindings "
                "(Strimzi, Confluent, MSK) may ship wildcard DESCRIBE grants."
                + (" Downgraded one tier: an overriding DENY exists, but DENY coverage is often "
                   "partial — verify it covers the whole pattern." if deny else "")
            ),
            severity=sev,
            source_ref={"api": "describe_acls", "principal": "User:*", "operation": op,
                        "resource": f"{b.get('restype')}:{b.get('pattern')}:{b.get('name')}"},
        ))
    return _uniform(hits)


@detector(kinds=["broker"], rule_id="KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS",
          severity="critical", title="ACL grants operation ALL on the LITERAL wildcard resource `*`")
def acl_wildcard_resource_all(resource, ctx):
    if not resource.raw.get("cluster_scope"):
        return []
    bindings, outcome = _acls(resource)
    if outcome != "ok":
        return []

    # super.users is absent from a real describe_configs response entirely, so .get() — a
    # subscript raises KeyError. It is semicolon-delimited: TLS distinguished names contain commas.
    cfg = resource.raw.get("config") or {}
    supers = {s.strip() for s in (_val(cfg, "super.users") or "").split(";") if s.strip()}

    broad = {"WRITE", "READ", "DELETE", "ALTER"}
    hits = []
    for b in bindings:
        if b.get("permission_type") != "ALLOW":
            continue
        rt, pat, name, op = (b.get("restype"), b.get("pattern"), b.get("name") or "",
                             b.get("operation"))
        wildcard = pat == "LITERAL" and name == "*"
        # ACLs on the cluster resource are conventionally written LITERAL 'kafka-cluster', not
        # '*', so a name=='*' test alone misses the single most dangerous grant.
        cluster_all = rt == "BROKER" and op == "ALL"
        if not (wildcard and op == "ALL") and not cluster_all and not (wildcard and op in broad):
            continue
        if op == "ALL":
            sev = "critical" if rt in ("BROKER", "TOPIC") else "high"
        else:
            sev = "high"
        deny = _denied_by(b, bindings)
        if deny:
            sev = _downgrade(sev)
        # A principal already in super.users bypasses ACL evaluation entirely, so the binding
        # grants nothing it does not already have — that is cleanup, not this finding.
        dead = b.get("principal") in supers
        if dead:
            sev = "info"
        hits.append(Hit(
            observation=(
                f"ACL binding grants ALLOW {op} to {b.get('principal')} from host "
                f"{b.get('host')!r} on {rt}:{pat}:{name!r} (read via describe_acls); this covers "
                f"every resource of type {rt}, defeating per-resource ACLs — unless narrowed by a "
                f"matching DENY binding."
                + (f" An overriding DENY exists: DENY {deny.get('operation')} on "
                   f"{deny.get('restype')}:{deny.get('pattern')}:{deny.get('name')!r}." if deny else "")
                + (f" {b.get('principal')} is also listed in super.users="
                   f"{_val(cfg, 'super.users')!r}." if dead else "")
            ),
            remediation=(
                "Replace the '*' LITERAL binding with per-resource LITERAL ACLs or a tightly "
                "scoped PREFIXED pattern, and enumerate the specific operations (READ, WRITE, "
                "DESCRIBE) instead of ALL. Do NOT move the principal to super.users — that grants "
                "strictly more privilege (super users are matched before any ACL and are immune "
                "to DENY), removes it from ACL-store auditing, and needs a broker restart."
                if not dead else
                "Delete this binding: the principal is already in super.users, so super-user "
                "matching short-circuits ACL evaluation and the binding grants nothing. This is "
                "config cleanup, not a privilege change."
            ),
            detail=(
                "The high tier needs a principal allowlist: MirrorMaker 2 (default topics '.*'), "
                "Connect, Cruise Control, Schema Registry and lag exporters legitimately hold "
                "comparable breadth."
                + (" Downgraded one tier: an overriding DENY exists." if deny else "")
            ),
            severity=sev,
            source_ref={"api": "describe_acls", "principal": b.get("principal"),
                        "operation": op, "resource": f"{rt}:{pat}:{name}"},
        ))
    return _uniform(hits)


@detector(kinds=["broker"], rule_id="KAFKA.ACL.ANONYMOUS_PRINCIPAL", severity="high",
          title="ACL grants access to `User:ANONYMOUS` (unauthenticated clients)")
def acl_anonymous_principal(resource, ctx):
    if not resource.raw.get("cluster_scope"):
        return []
    bindings, outcome = _acls(resource)
    if outcome != "ok":
        return []

    anon = _anonymous_listeners(ctx)
    reachable_ops = {"ALL", "WRITE", "READ", "CLUSTER_ACTION", "ALTER"}

    hits = []
    for b in bindings:
        if b.get("permission_type") != "ALLOW" or b.get("principal") != "User:ANONYMOUS":
            continue
        host, op = b.get("host"), b.get("operation")
        # A host-scoped ANONYMOUS ACL is the documented PLAINTEXT inter-broker migration pattern
        # and is not reachable by arbitrary unauthenticated clients.
        if host != "*":
            sev = "low"
        elif not anon:
            sev = "medium"   # latent: no listener can currently mint an ANONYMOUS principal
        elif op in reachable_ops:
            sev = "critical"
        else:
            sev = "high"
        listeners = "; ".join(f"broker {i} listener {n} ({p})" for i, n, p in anon)
        hits.append(Hit(
            observation=(
                f"ACL binding grants ALLOW {op} on {b.get('restype')}:{b.get('pattern')}:"
                f"{b.get('name')!r} to User:ANONYMOUS from host {host!r} (read via describe_acls)"
                + (f", and these listeners assign the ANONYMOUS principal: {listeners}. Clients "
                   f"that can reach those listeners without authenticating can exercise this "
                   f"permission." if anon else
                   ". No collected listener resolves to PLAINTEXT or to SSL without "
                   "ssl.client.auth=required, so no listener currently mints an ANONYMOUS "
                   "principal and the binding is latent.")
                + (f" The binding is scoped to host {host!r} rather than '*'; verify those are "
                   f"broker IPs only." if host != "*" else "")
            ),
            remediation=(
                "Do not simply delete this: on a PLAINTEXT inter-broker listener the brokers "
                "themselves authenticate as User:ANONYMOUS (KAFKA-3687), so the binding may be "
                "load-bearing for replication. Sequence: (1) move inter-broker to SASL_SSL, or "
                "SSL with ssl.client.auth=required, and set security.inter.broker.protocol "
                "accordingly; (2) grant the real broker principal its rights; (3) only then "
                "delete the ANONYMOUS ACLs. Require real authentication on every client-facing "
                "listener; do not paper over PLAINTEXT with super.users."
            ),
            detail=(
                "The scan cannot see network policy, security groups, or whether the listener is "
                "bound to a private interface, so reachability of the listed listeners is not "
                "proven — only that the broker assigns User:ANONYMOUS on them."
            ),
            severity=sev,
            source_ref={"api": "describe_acls", "principal": "User:ANONYMOUS",
                        "operation": op, "host": host},
        ))
    return _uniform(hits)


@detector(kinds=["broker"], rule_id="KAFKA.ACL.PREFIXED_OVERBROAD", severity="low",
          title="PREFIXED ACL pattern matches an excessive share of resources")
def acl_prefixed_overbroad(resource, ctx):
    if not resource.raw.get("cluster_scope"):
        return []
    bindings, outcome = _acls(resource)
    if outcome != "ok":
        return []

    topics = [t.name for t in ctx.of_kind("topic")]
    m = len(topics)

    hits = []
    for b in bindings:
        if (b.get("permission_type") != "ALLOW" or b.get("pattern") != "PREFIXED"
                or b.get("restype") != "TOPIC"):
            continue
        prefix = b.get("name") or ""
        n = sum(1 for t in topics if t.startswith(prefix))
        # A <=1-char prefix approximates the LITERAL '*' wildcard — the only sound signal here.
        # The ratio test needs floors: on a 3-topic dev cluster a 2-topic prefix is 67%.
        short = len(prefix) <= 1
        ratio = m >= 20 and n >= 5 and n > m / 2
        if not (short or ratio):
            continue
        if _denied_by(b, bindings):
            continue   # a broad PREFIXED ALLOW narrowed by DENY is not overbroad
        hits.append(Hit(
            observation=(
                f"ACL binding grants ALLOW {b.get('operation')} on TOPIC:PREFIXED:{prefix!r} to "
                f"{b.get('principal')} from host {b.get('host')!r} (read via describe_acls); this "
                f"prefix will silently cover any future topic created with the same prefix."
                + (f" It matches {n} of {m} existing topics ({100 * n // m}%)." if ratio else "")
                + (f" The prefix is {len(prefix)} character(s) long, which approximates the "
                   f"LITERAL '*' wildcard resource." if short else "")
            ),
            remediation=(
                "Narrow the prefix so it maps to a single team or application namespace, split "
                "ALL into the specific operations required, and adopt a topic naming convention "
                "(e.g. <team>.<app>.<dataset>) so PREFIXED grants cannot leak across tenants. "
                "Re-audit PREFIXED ACLs whenever topics are added."
            ),
            detail=(
                "PREFIXED is the documented mechanism for namespace grants, not a "
                "misconfiguration. Without ownership/tenancy context this is inventory and "
                "hygiene, not a defect — hence low. The <=1-char and >50% thresholds are "
                "heuristics, not documented Kafka thresholds. The denominator is only the topics "
                "the scanning principal can DESCRIBE, so the percentage may be overstated."
            ),
            source_ref={"api": "describe_acls", "principal": b.get("principal"),
                        "resource": f"TOPIC:PREFIXED:{prefix}"},
        ))
    return _uniform(hits)


# ═══ SASL rules ═══════════════════════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KAFKA.SASL.PLAIN_WITHOUT_TLS", severity="critical",
          title="SASL/PLAIN enabled on a listener without TLS — cleartext passwords on the wire")
def sasl_plain_without_tls(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")

    # Enumerate the ACTUAL `listeners`, never listener.security.protocol.map: the default map is
    # built from every SecurityProtocol value, so a SASL_PLAINTEXT entry exists on every broker
    # even with no SASL_PLAINTEXT listener. Iterating the map fires a false critical against a
    # listener that does not exist.
    hits = []
    for name, host, port in _listeners(cfg):
        if _resolve(cfg, name) != "SASL_PLAINTEXT":
            continue
        mechs = _mechanisms(cfg, name)
        if mechs is None or "PLAIN" not in mechs:
            continue
        override = _entry(cfg, f"listener.name.{name.lower()}.sasl.enabled.mechanisms")
        origin = (f"listener.name.{name.lower()}.sasl.enabled.mechanisms" if override
                  else f"sasl.enabled.mechanisms (source={_source(_entry(cfg, 'sasl.enabled.mechanisms'))})")
        hits.append(Hit(
            observation=(
                f"Broker {bid}: listener `{name}://{host}:{port}` resolves to SASL_PLAINTEXT and "
                f"its effective sasl.enabled.mechanisms is {','.join(mechs)} (from {origin}), "
                f"which includes PLAIN. Usernames and passwords are transmitted unencrypted, and "
                f"Kafka documents that SASL/PLAIN should be used only with SSL as transport layer."
            ),
            remediation=(
                f"Map {name} to SASL_SSL in listener.security.protocol.map, or replace PLAIN with "
                f"SCRAM-SHA-512 or OAUTHBEARER over TLS. Rotate every credential configured for "
                f"the PLAIN mechanism — assume they are disclosed. This scan cannot enumerate "
                f"which users: PLAIN credentials live in "
                f"listener.name.{name.lower()}.plain.sasl.jaas.config, which is PASSWORD-typed "
                f"and redacted to null by describe_configs — read the broker JAAS config directly."
            ),
            detail=(
                "The broker requires a JAAS config for each enabled mechanism on each SASL "
                "listener at startup, so on a running cluster PLAIN in this listener's effective "
                "mechanism set means the broker really does accept PLAIN there. Suppressible if a "
                "mesh/sidecar/LB terminates TLS outside the broker, or the listener is "
                "loopback-bound."
            ),
            severity="low" if host in _LOOPBACK else "critical",
            source_ref={"config_key": origin, "listener": name},
        ))
    return _uniform(hits)


@detector(kinds=["broker"], rule_id="KAFKA.SASL.SCRAM_WITHOUT_TLS", severity="high",
          title="SCRAM enabled without TLS — exchange is interceptable and replayable")
def sasl_scram_without_tls(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")

    hits = []
    for name, host, port in _listeners(cfg):
        if _resolve(cfg, name) != "SASL_PLAINTEXT":
            continue
        mechs = _mechanisms(cfg, name)
        if mechs is None:
            continue
        scram = sorted({"SCRAM-SHA-256", "SCRAM-SHA-512"} & set(mechs))
        if not scram:
            continue
        hits.append(Hit(
            observation=(
                f"Broker {bid}: listener `{name}://{host}:{port}` resolves to SASL_PLAINTEXT with "
                f"{','.join(scram)} in its effective sasl.enabled.mechanisms "
                f"({','.join(mechs)}); the authentication exchange is interceptable and all "
                f"traffic on this listener is unencrypted."
            ),
            remediation=(
                "Move SCRAM to a SASL_SSL listener. Conditional advisory: on Kafka "
                "0.10.2.0 <= v <= 3.7.1 or v == 3.8.0 this is also replayable (CVE-2024-56128, "
                "missing RFC 5802 nonce verification; fixed in 3.7.2 / 3.8.1 / 3.9.0). The Admin "
                "API exposes no broker version string, so confirm the version out of band — "
                "deployments running SCRAM over TLS were never affected."
            ),
            detail=(
                "The scanner cannot determine the patch version read-only, so the CVE state is "
                "advisory, not observed. 'Internal listener on a trusted VPC' is risk acceptance, "
                "not a false positive — the assertion stays factually true. SCRAM credential "
                "count is not collected, so no claim is made about how many principals exist."
            ),
            severity="low" if host in _LOOPBACK else "high",
            source_ref={"config_key": "sasl.enabled.mechanisms", "listener": name},
        ))
    return _uniform(hits)


@detector(kinds=["broker"], rule_id="KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT", severity="high",
          title="SASL/OAUTHBEARER using the built-in unsecured JWT handler")
def sasl_oauthbearer_unsecured(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")

    hits = []
    for name, _host, _port in _listeners(cfg):
        proto = _resolve(cfg, name)
        if proto not in ("SASL_PLAINTEXT", "SASL_SSL"):
            continue
        mechs = _mechanisms(cfg, name)
        if mechs is None or "OAUTHBEARER" not in mechs:
            continue
        # Only the MECHANISM-PREFIXED key is consulted by SaslChannelBuilder. A bare
        # sasl.server.callback.handler.class never disables the unsecured validator, so treating
        # it as a pass is a false negative on a genuinely broken broker — and setting the
        # un-prefixed key is exactly the mistake an operator makes.
        key = f"listener.name.{name.lower()}.oauthbearer.sasl.server.callback.handler.class"
        handler = _entry(cfg, key)
        if handler is not None and not handler.get("is_default"):
            continue
        override = _entry(cfg, f"listener.name.{name.lower()}.sasl.enabled.mechanisms")
        bare = _val(cfg, "sasl.server.callback.handler.class")
        hits.append(Hit(
            observation=(
                f"Broker {bid}, listener {name}: OAUTHBEARER is in the effective mechanism set "
                f"{','.join(mechs)} (from "
                f"{'the listener override' if override else 'sasl.enabled.mechanisms'}) and "
                f"{key} is {'absent' if handler is None else 'source=' + _source(handler)}, so "
                f"OAuthBearerUnsecuredValidatorCallbackHandler is in use — Kafka documents it as "
                f"only suitable for non-production installations."
                + (f" The un-prefixed sasl.server.callback.handler.class is set to {bare!r}, "
                   f"which the broker does not consult for this mechanism." if bare else "")
            ),
            remediation=(
                f"Set {key} to a production AuthenticateCallbackHandler (or use the broker's "
                f"OAuth/OIDC JWKS validation settings) and verify issuer, audience, expiry and "
                f"signature. The key must carry both the listener prefix and the lower-case "
                f"mechanism name. Separately, on Kafka 4.1.0–4.1.1 set "
                f"sasl.oauthbearer.jwt.validator.class=BrokerJwtValidator — the default "
                f"DefaultJwtValidator accepts any JWT unvalidated (CVE-2026-33557, fixed in "
                f"4.1.2 / 4.2.0). That bites only after this remediation is applied."
            ),
            detail=(
                "Confidence is capped at medium: sasl.jaas.config is PASSWORD-typed and redacted, "
                "and it could name a custom handler this scan cannot see. High rather than "
                "critical because the scan cannot tell whether the listener is externally exposed "
                "or whether this is a dev cluster — which Kafka explicitly sanctions as the "
                "unsecured handler's intended use."
            ),
            source_ref={"config_key": key, "listener": name},
        ))
    return _uniform(hits)


# ═══ TLS rules ════════════════════════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED", severity="high",
          title="SSL listener does not require client certificate authentication")
def ssl_client_auth_not_required(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    controller = _controller(cfg)
    inter = _val(cfg, "inter.broker.listener.name")
    _, authz_state = _authorizer(cfg)
    bindings, outcome = _acls(resource)
    allow_all = _entry(cfg, "allow.everyone.if.no.acl.found")

    # ANONYMOUS is provably denied only when all three hold and are READABLE. The redacted
    # allow.everyone value cannot be assumed false.
    anon_denied = (
        authz_state == "set"
        and allow_all is not None and allow_all.get("value") is not None and not _is_true(allow_all)
        and outcome == "ok"
        and not any(b.get("principal") == "User:ANONYMOUS" and b.get("permission_type") == "ALLOW"
                    for b in bindings)
    )

    hits = []
    for name, _host, _port in _listeners(cfg):
        if _lname(name) in controller:
            continue   # a controller listener's remediation is not "distribute client keystores"
        # SASL_SSL is excluded: there SASL performs the authentication.
        if _resolve(cfg, name) != "SSL":
            continue
        e, scoped = _effective(cfg, "ssl.client.auth", name)
        v = ((e.get("value") if e else None) or "none").strip().lower()
        if v == "required":
            continue
        sev = "high" if v == "none" else "medium"
        if anon_denied:
            sev = _downgrade(sev)
        key = f"listener.name.{name.lower()}.ssl.client.auth" if scoped else "ssl.client.auth"
        hits.append(Hit(
            observation=(
                f"Broker {bid}: listener {name} resolves to SSL but its effective "
                f"ssl.client.auth={v} (read from {key}, source={_source(e)}); TLS provides "
                f"encryption only and connecting clients authenticate as User:ANONYMOUS."
            ),
            remediation=(
                f"Set listener.name.{name.lower()}.ssl.client.auth=required and distribute "
                f"{'inter-broker' if _lname(name) == _lname(inter) else 'client'} keystores signed by the broker "
                f"truststore CA. Never use 'requested' — Kafka documents it as providing a false "
                f"sense of security, since misconfigured clients still connect successfully. If "
                f"mutual TLS is impractical, switch the listener to SASL_SSL so SASL supplies the "
                f"client identity."
            ),
            detail=(
                f"authorizer.class.name is {authz_state}."
                + (" Downgraded one tier: an authorizer is set, allow.everyone.if.no.acl.found "
                   "reads false, and no ALLOW binding names User:ANONYMOUS, so ANONYMOUS is "
                   "provably denied." if anon_denied else
                   " ANONYMOUS is not provably denied from readable config, so no downgrade was "
                   "applied.")
                + " mTLS terminated upstream at an L4 proxy/NLB/mesh sidecar is a real but "
                  "uncommon exception; suppress per-listener if it applies."
            ),
            severity=sev,
            source_ref={"config_key": key, "listener": name},
        ))
    return _uniform(hits)


@detector(kinds=["broker"], rule_id="KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED", severity="medium",
          title="TLS hostname verification disabled (ssl.endpoint.identification.algorithm empty)")
def ssl_hostname_verification_disabled(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    key = "ssl.endpoint.identification.algorithm"

    # This governs the broker's own OUTBOUND TLS (replication, controller): the algorithm is
    # applied only to client-mode SSL engines, so it has no effect on inbound client connections.
    # If the broker makes no outbound TLS connections, an empty value is an inert leftover.
    inter = _val(cfg, "inter.broker.listener.name")
    inter_proto = _resolve(cfg, inter) if inter else (
        (_val(cfg, "security.inter.broker.protocol") or "PLAINTEXT").upper())
    outbound_tls = inter_proto in ("SSL", "SASL_SSL")

    hits = []
    candidates = [(key, _entry(cfg, key), None)]
    for name, _h, _p in _listeners(cfg):
        k = f"listener.name.{name.lower()}.{key}"
        if _entry(cfg, k) is not None:
            candidates.append((k, _entry(cfg, k), name))

    for k, e, listener in candidates:
        # Absent means the `https` default applies (Kafka >= 2.0.0). Only an explicit empty
        # string disables verification.
        if e is None or e.get("value") != "":
            continue
        if listener:
            gate = _resolve(cfg, listener) in ("SSL", "SASL_SSL")
        else:
            gate = outbound_tls
        hits.append(Hit(
            observation=(
                f"Broker {bid}: {k} is set to the empty string (source={_source(e)}), overriding "
                f"the default 'https'; broker-initiated TLS connections do not verify the peer "
                f"hostname against the certificate. The effective inter-broker protocol is "
                f"{inter_proto}."
            ),
            remediation=(
                "Remove the override so the value returns to 'https'. If it exists to work around "
                "certificate SAN mismatches, reissue broker certificates with correct SANs (DNS "
                "names and/or IP SANs matching the advertised listener hosts) rather than "
                "disabling verification."
            ),
            detail=(
                "This setting applies only to the broker's outbound/client-mode TLS engines "
                "(inter-broker replication, controller); it does not affect inbound client-to-"
                "broker traffic. Assumes Kafka >= 2.0.0, where absent means the https default."
                + ("" if gate else " Downgraded to low: no outbound TLS is in use here, so the "
                                   "empty value is an inert leftover with no MITM exposure — "
                                   "config hygiene rather than a live risk.")
            ),
            severity="medium" if gate else "low",
            source_ref={"config_key": k, "listener": listener},
        ))
    return _uniform(hits)


# ═══ Topic & governance rules ═════════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KAFKA.TOPIC.AUTO_CREATE_ENABLED", severity="low",
          title="auto.create.topics.enable=true allows implicit topic creation")
def topic_auto_create_enabled(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    e = _entry(cfg, "auto.create.topics.enable")
    if e is None:
        return []   # managed platforms restrict DescribeConfigs on BROKER -> unknown, not a fail
    v = e.get("value")
    if v is None or v.strip().lower() == "false":
        return []

    authz_e, authz_state = _authorizer(cfg)
    allow_all = _entry(cfg, "allow.everyone.if.no.acl.found")

    # Standalone this crosses no security boundary: the metadata auto-create path is
    # authorization-checked (Create on Cluster, then on Topic) and allow.everyone defaults to
    # false. It is a severity modifier on the authz rules — real impact needs authz to be absent.
    #
    # allow.everyone.if.no.acl.found has THREE states, not two, and _is_true() collapses two of
    # them (its own docstring says so). The broker types this config PASSWORD and redacts the
    # value to None, so `not _is_true(entry)` does NOT mean the value is false — it usually means
    # the value is unreadable. Escalating on an unknown would be a false positive; concluding
    # "no security boundary is crossed" from an unknown is a false PASS written into the ledger,
    # which is worse. So: escalate only on a readable true, and where the value is explicitly
    # configured but redacted, say that instead of claiming a clean bill of health.
    # (is_default=true + redacted is the shipped default `false` and needs no caveat.)
    allow_all_unknown = (
        allow_all is not None
        and allow_all.get("value") is None
        and not allow_all.get("is_default")
    )
    escalate = authz_state == "unset" or (allow_all is not None and _is_true(allow_all))
    return [Hit(
        observation=(
            f"Broker {bid}: auto.create.topics.enable={v!r} (is_default={e.get('is_default')}, "
            f"source={_source(e)}) with authorizer.class.name="
            f"{(authz_e.get('value') if authz_e else None)!r}; a metadata request — including the "
            f"one a producer or consumer issues on first access to an unknown topic — implicitly "
            f"creates the topic with num.partitions="
            f"{_val(cfg, 'num.partitions')!r} and default.replication.factor="
            f"{_val(cfg, 'default.replication.factor')!r} rather than a governed spec."
        ),
        remediation=(
            "Set auto.create.topics.enable=false on all brokers and provision topics explicitly "
            "via AdminClient/CreateTopics with reviewed partition counts and replication factors. "
            "Grant CREATE on the CLUSTER or TOPIC resource only to the provisioning principal. "
            "Update Mode is read-only: this cannot be changed via incrementalAlterConfigs — it "
            "needs an edit to server.properties on every broker plus a rolling restart."
        ),
        detail=(
            "true is the shipped Kafka default, so this fires on essentially every stock "
            "self-managed cluster; the low base severity is what keeps it from being noise. It is "
            "deliberate and legitimate on dev/test/CI clusters."
            + (" Escalated to high: no authorization is enforced on this cluster, so implicit "
               "topic creation and resource exhaustion are reachable without a CREATE grant. "
               "Compensating network controls (isolation, mesh mTLS) are not observable from the "
               "Admin API and may reduce real exposure." if escalate else
               " Not escalated: an authorizer is configured. Whether a security boundary is "
               "crossed was NOT established by this scan: allow.everyone.if.no.acl.found is "
               "explicitly configured (is_default=false) and the broker redacts it to null "
               "because it is typed PASSWORD, so this scan cannot read whether it is true. If it "
               "is true, a client with no CREATE grant can auto-create topics and this is high, "
               "not low. Read the value from server.properties to settle it. See "
               "KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL on this broker."
               if allow_all_unknown else
               " Not escalated: an authorizer is configured and allow.everyone.if.no.acl.found "
               "is readable and not true, so a client that auto-creates a topic already holds "
               "CREATE and no security boundary is crossed — the residual impact is governance "
               "and durability, not access control.")
        ),
        severity="high" if escalate else "low",
        source_ref={"config_key": "auto.create.topics.enable"},
    )]


@detector(kinds=["topic"], rule_id="KAFKA.TOPIC.RETENTION_UNBOUNDED", severity="low",
          title="Topic retains data indefinitely (retention.ms=-1)")
def topic_retention_unbounded(resource, ctx):
    cfg = resource.raw.get("config") or {}
    if not cfg:
        return []   # topic DescribeConfigs not readable -> indeterminate

    policy = _entry(cfg, "cleanup.policy")
    ms = _entry(cfg, "retention.ms")
    by = _entry(cfg, "retention.bytes")
    if policy is None or ms is None or by is None:
        return []
    # Compaction retains the latest value per key by design — a different question entirely.
    if "delete" not in (policy.get("value") or "").lower():
        return []
    # The retention.bytes conjunct is mandatory: retention.ms=-1 with retention.bytes=536870912 is
    # BOUNDED — segments age out by size — and the "indefinitely" claim would be simply false.
    if (ms.get("value") or "").strip() != "-1" or (by.get("value") or "").strip() != "-1":
        return []

    tiered = _is_true(_entry(cfg, "remote.storage.enable"))
    if tiered:
        obs_tail = (f"Tiered storage is enabled (remote.storage.enable=true) with "
                    f"local.retention.ms={_val(cfg, 'local.retention.ms')!r} bounding broker-local "
                    f"disk, so this is an intended infinite-retention architecture; what remains "
                    f"is a data-minimisation question, not unbounded local disk growth.")
    else:
        obs_tail = ("Records are never aged out by time or size, so the topic accumulates data "
                    "indefinitely with no expiry bound.")

    return [Hit(
        observation=(
            f"Topic {resource.name}: cleanup.policy={policy.get('value')!r} (source="
            f"{_source(policy)}) with retention.ms=-1 (source={_source(ms)}) and "
            f"retention.bytes=-1 (source={_source(by)}). {obs_tail}"
        ),
        remediation=(
            "Set an explicit retention.ms aligned to the data's retention policy via AlterConfigs "
            "on the TOPIC resource. For topics carrying regulated or personal data, retention "
            "must be bounded to satisfy data-minimisation and deletion obligations. Where "
            "per-key deletion is required the mechanism is compaction plus tombstones — "
            "cleanup.policy=compact,delete is a valid combination paired with a retention bound, "
            "and delete.retention.ms controls how long tombstones stay visible to consumers "
            "(note that adding delete forfeits the compact-only guarantee of keeping at least one "
            "record per key)."
        ),
        detail=(
            "Data-minimisation and capacity hygiene, not an exploitable vulnerability — no "
            "confidentiality or integrity impact and no attacker primitive. Topics that are "
            "time-unbounded but size-capped (retention.bytes > 0) are deliberately not flagged."
        ),
        severity="info" if tiered else "low",
        source_ref={"config_key": "retention.ms", "cleanup_policy": policy.get("value"),
                    "retention_bytes": by.get("value")},
    )]


# ═══ Durability & integrity rules ═════════════════════════════════════════
# Reported as a separate class so they do not dilute the access-control signal.
@detector(kinds=["topic"], rule_id="KAFKA.DURABILITY.MIN_INSYNC_REPLICAS_ONE", severity="medium",
          title="min.insync.replicas=1 on a replicated topic — acks=all degrades to single-copy "
                "durability when the ISR shrinks")
def durability_min_insync_replicas_one(resource, ctx):
    cfg = resource.raw.get("config") or {}
    rf = resource.raw.get("replication_factor")
    if not cfg or rf is None:
        return []
    # describeConfigs on the TOPIC resource already returns the effective inherited value, so
    # there is no broker-config chain to reconstruct.
    e = _entry(cfg, "min.insync.replicas")
    if e is None or (e.get("value") or "").strip() != "1":
        return []
    if rf < 2:
        return []   # nothing to be in-sync with; the setting has no durability effect

    internal = resource.raw.get("internal") or resource.name.startswith("__")
    return [Hit(
        observation=(
            f"Topic {resource.name}: replication.factor={rf} but effective min.insync.replicas=1 "
            f"(source={_source(e)}). If the ISR shrinks to the leader alone, acks=all writes are "
            f"still accepted and acknowledged from a single replica; those acknowledged records "
            f"are lost if the leader then fails."
        ),
        remediation=(
            f"Set min.insync.replicas=2 for replication factor 3 via AlterConfigs on the TOPIC "
            f"resource (the standard quorum: tolerates one broker loss while keeping writes "
            f"available) and ensure producers use acks=all. Setting min.insync.replicas equal to "
            f"the replication factor makes the topic unavailable for writes on any single broker "
            f"loss."
        ),
        detail=(
            "min.insync.replicas is a floor on ISR size gating whether a write is accepted at "
            "all — it is NOT the number of acks required. With RF=3 and a healthy ISR of 3, "
            "acks=all still waits for all three; durability is normal until the ISR degrades. "
            "The Admin API cannot observe producer acks settings, so on topics where no producer "
            "uses acks=all this finding is vacuous and the loss is unconfirmable read-only. "
            "RF>=2 is used rather than the rulepack's RF>=3 gate, since RF=2 with misr=1 has the "
            "identical defect."
            + (" This is an internal topic, which inherits misr=1 out of the box on essentially "
               "every cluster — downgraded to low." if internal else "")
        ),
        severity="low" if internal else "medium",
        source_ref={"config_key": "min.insync.replicas", "replication_factor": rf},
    )]


@detector(kinds=["broker", "topic"], rule_id="KAFKA.DURABILITY.UNCLEAN_LEADER_ELECTION",
          severity="medium",
          title="unclean.leader.election.enable=true permits silent committed-data loss")
def durability_unclean_leader_election(resource, ctx):
    key = "unclean.leader.election.enable"

    if resource.kind == "topic":
        cfg = resource.raw.get("config") or {}
        e = _entry(cfg, key)
        if e is None or not _is_true(e) or e.get("is_default"):
            return []
        rf = resource.raw.get("replication_factor")
        if rf is not None and rf < 2:
            return []   # no out-of-sync replica exists to promote
        return [Hit(
            observation=(
                f"Topic {resource.name}: {key}={e.get('value')!r} (source={_source(e)}), "
                f"overriding the default false; an out-of-sync replica can be promoted to leader "
                f"and discard committed records."
            ),
            remediation=(
                "Remove the topic-level override so the topic follows the cluster setting, "
                "accepting partition unavailability over data loss. If this topic genuinely "
                "prefers availability (e.g. reconstructible metrics), document the override and "
                "pair it with an explicit data-loss runbook."
            ),
            detail=("The integrity framing is strongest for acks=all producers — with acks=1 or "
                    "acks=0 records can be lost regardless of this setting."),
            source_ref={"config_key": key, "resource_type": "TOPIC"},
        )]

    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    # KRaft resolves this as: dynamic topic -> dynamic node -> dynamic cluster -> the CONTROLLER's
    # static config. Broker static config is NOT consulted, so reading the broker id and reporting
    # STATIC_BROKER_CONFIG can report an inert value. The empty-resource-name snapshot is the
    # correct source here — the one rule that inverts the general invariant.
    dyn = resource.raw.get("cluster_dynamic_config")
    cluster_e = _entry(dyn, key) if dyn else None
    if cluster_e is not None and _is_true(cluster_e):
        origin, e = "cluster-wide dynamic config (ConfigResource(BROKER, ''))", cluster_e
    else:
        static_e = _entry(cfg, key)
        if static_e is None or not _is_true(static_e):
            return []
        roles = _names(cfg, "process.roles")
        if "controller" in roles:
            # Combined-mode KRaft node: this broker IS the controller, so its static config is
            # exactly the controller static config KRaft falls back to.
            origin, e = (f"this node's static config, which is authoritative because "
                         f"process.roles={_val(cfg, 'process.roles')!r} makes it a combined "
                         f"broker+controller"), static_e
        elif roles:
            # Broker-only KRaft node: the value is a stale leftover KRaft never consults, and the
            # controller's static config is unreachable from a broker-bootstrapped client.
            return [Hit(
                observation=(
                    f"Broker {bid}: {key}={static_e.get('value')!r} appears only in this broker's "
                    f"static config (source={_source(static_e)}) while process.roles="
                    f"{_val(cfg, 'process.roles')!r} makes it a broker-only KRaft node, and the "
                    f"cluster-wide dynamic config "
                    f"{'does not set it' if dyn is not None else 'was not readable'}. KRaft "
                    f"resolves this key from dynamic topic/node/cluster config and then the "
                    f"CONTROLLER's static config — never a broker's — so this value may be inert. "
                    f"The controller's static config is not reachable from a broker-bootstrapped "
                    f"Admin client, so the effective value is not established here."
                ),
                remediation=(
                    "Remove the stale broker-static setting for config hygiene, and confirm the "
                    "effective value by describing the controller nodes with an Admin client "
                    "configured with bootstrap.controllers. Set unclean.leader.election.enable="
                    "false at the cluster level if it is in fact true."
                ),
                detail=("Informational, not a durability failure: no data loss can be attributed "
                        "to a value KRaft does not consult. This is the dominant false-positive "
                        "path for this rule and is plausible on ZK-to-KRaft-migrated clusters."),
                severity="info",
                source_ref={"config_key": key, "resolution": "partial"},
            )]
        else:
            origin, e = f"this broker's static config (source={_source(static_e)})", static_e

    # With a single replica there is no out-of-sync replica to promote. Only suppress when the
    # topic replication factors were actually collected.
    rfs = [t.raw.get("replication_factor") for t in ctx.of_kind("topic")]
    known = [r for r in rfs if r is not None]
    if known and max(known) < 2:
        return []

    return [Hit(
        observation=(
            f"Broker {bid}: {key}={e.get('value')!r} (source={_source(e)}), read from {origin}, "
            f"overriding the default false; an out-of-sync replica can be promoted to leader and "
            f"discard committed records."
        ),
        remediation=(
            "Set unclean.leader.election.enable=false at the cluster level and remove any "
            "topic-level override, accepting partition unavailability over data loss. If a "
            "specific topic genuinely prefers availability, document that override and pair it "
            "with an explicit data-loss runbook."
        ),
        detail=(
            "Eligible Leader Replicas (KIP-966 Part 1, default on new clusters from 4.1) reduce "
            "how often the unclean path is reached — election order is ISR, then unfenced ELR, "
            "then last known leader if unfenced — but do not make true safe: with ISR and ELR "
            "both empty an out-of-sync replica can still be promoted. The integrity framing is "
            "strongest for acks=all producers."
        ),
        source_ref={"config_key": key, "resolution": origin},
    )]


# ═══ Legacy mode ══════════════════════════════════════════════════════════
def _zk_mode(cfg: dict):
    """(is_zk, zk_endpoints). ZooKeeper mode means process.roles is absent/empty AND
    zookeeper.connect has a non-null, non-empty VALUE. A key-existence test fires on every 3.x
    KRaft broker, where the key is still returned with a null value."""
    if _names(cfg, "process.roles"):
        return False, None
    zk = (_val(cfg, "zookeeper.connect") or "").strip()
    return bool(zk), (zk or None)


@detector(kinds=["broker"], rule_id="KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES", severity="medium",
          title="Legacy ZooKeeper mode with znodes created without secure ACLs")
def zk_legacy_unsecured_znodes(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    is_zk, zk = _zk_mode(cfg)
    if not is_zk:
        return []
    e = _entry(cfg, "zookeeper.set.acl")
    if e is None or _is_true(e):
        return []
    migrating = _is_true(_entry(cfg, "zookeeper.metadata.migration.enable"))
    return [Hit(
        observation=(
            f"Broker {bid}: process.roles is unset and zookeeper.connect={zk!r}; "
            f"zookeeper.set.acl={e.get('value')!r} (source={_source(e)}), so Kafka metadata "
            f"znodes are created without secure ACLs — any client that can reach ZooKeeper may "
            f"modify cluster metadata, and sensitive znodes (SCRAM credentials, delegation "
            f"tokens) are not restricted to brokers. zookeeper.metadata.migration.enable="
            f"{_val(cfg, 'zookeeper.metadata.migration.enable')!r}, so this cluster is "
            f"{'mid-migration to KRaft' if migrating else 'stale legacy ZooKeeper mode'}."
        ),
        remediation=(
            "Migrate to KRaft (process.roles, controller.quorum.bootstrap.servers) and upgrade to "
            "a 4.x release — a direct upgrade from ZooKeeper mode to 4.0 is not supported, so "
            "migrate to KRaft on a 3.x release first (3.9 is the bridge). Until then, order "
            "matters, because zookeeper.set.acl=true is a no-op unless ZK auth is configured "
            "first: (1) enable ZooKeeper client authentication (SASL or mTLS); (2) set "
            "zookeeper.set.acl=true; (3) run bin/zookeeper-security-migration.sh to re-ACL "
            "existing znodes; (4) enable zookeeper.ssl.client.enable=true; (5) restrict the "
            "ZooKeeper port to broker hosts only."
            + (" Clusters mid-migration on 3.5.0–3.6.1 are also exposed to CVE-2024-27309 "
               "(incorrect access control during ZK-to-KRaft migration; fixed in 3.6.2)."
               if migrating else "")
        ),
        detail=(
            "The defect is that znodes are world-WRITABLE and that sensitive znodes are not "
            "restricted to brokers. Kafka metadata znodes stay world-READABLE even with "
            "zookeeper.set.acl=true, so world-readability is not the defect and is not what the "
            "remediation fixes. The Admin API cannot verify whether the ZooKeeper port is "
            "network-reachable — that needs host or network inspection. Managed ZK-based "
            "services do not expose this setting to customers."
        ),
        source_ref={"config_key": "zookeeper.set.acl", "zookeeper_connect": zk},
    )]


@detector(kinds=["broker"], rule_id="KAFKA.ZK.LEGACY_MODE_PLAINTEXT_ZK", severity="medium",
          title="Legacy ZooKeeper mode with an unencrypted ZooKeeper client connection")
def zk_legacy_plaintext_client(resource, ctx):
    cfg = resource.raw.get("config") or {}
    bid = resource.raw.get("id")
    is_zk, zk = _zk_mode(cfg)
    if not is_zk:
        return []
    e = _entry(cfg, "zookeeper.ssl.client.enable")
    if e is None or _is_true(e):
        return []
    return [Hit(
        observation=(
            f"Broker {bid}: process.roles is unset and zookeeper.connect={zk!r}; "
            f"zookeeper.ssl.client.enable={e.get('value')!r} (source={_source(e)}), so this "
            f"broker's ZooKeeper client connection is configured without TLS and cluster metadata "
            f"exchanged with ZooKeeper is not encrypted in transit by Kafka."
        ),
        remediation=(
            "Set zookeeper.ssl.client.enable=true with the zookeeper.ssl.* keystore/truststore "
            "settings, restrict the ZooKeeper port to broker hosts only, and migrate to KRaft "
            "(ZooKeeper mode is removed in Kafka 4.0; migrate on 3.9 as the bridge release)."
        ),
        detail=(
            "Genuine false positive to check first: per KIP-515 an explicit Kafka value overrides "
            "the -Dzookeeper.client.secure system property, so ZK TLS can be enabled via that "
            "property while this config reads false — DescribeConfigs cannot see it. This arm "
            "also fires on essentially every ZK-mode cluster, where plaintext ZK on an isolated "
            "subnet is a common and frequently deliberate design; it is near-zero-signal on its "
            "own and is reported separately from the znode-ACL arm because the two have different "
            "evidence and different fixes."
        ),
        source_ref={"config_key": "zookeeper.ssl.client.enable", "zookeeper_connect": zk},
    )]
