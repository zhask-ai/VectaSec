"""The attack-path / toxic-combination correlation engine — pure, testable functions.

WHAT THIS IS. VectaSec's flagship differentiator is that it does not stop at "this broker is
plaintext" and "this NHI has a wildcard grant" and "this topic is named like PCI" as three
unrelated medium findings. A human attacker chains them: reach the exposed surface, act as the
over-privileged non-human identity, read the sensitive data. This module generalises the ONE
hand-built toxic-combination in detect/data.py (DATA.EXPOSURE.SENSITIVE_PLAINTEXT, Kafka-only)
into a real correlation engine that runs over ANY connector's resources.

It correlates three orthogonal signals, each read from the label-encoded graph a scan already
produces (contracts.Resource.labels / .raw), never from a live probe:

  EXPOSURE       a surface an attacker can reach without proper controls — a PLAINTEXT listener,
                 a broker with no authorizer, an unauthenticated/anonymous/public endpoint.
                 Read from broker config (raw.config), Redis server config (raw), or the generic
                 exposure labels a connector may set (public / unauthenticated / plaintext / …).
  OVER-PRIVILEGE a non-human identity that holds more than it needs — a wildcard ALLOW grant, or
                 a shared/default principal (guest / admin / default / anonymous). Read from the
                 identity/credential/grant resources identity.py derives, via their label links
                 (grant.labels["identity"], credential.labels["owner"], identity.raw source).
  SENSITIVITY    a data-carrying resource classified as regulated/sensitive by classify.py, read
                 from the data_classes / data_sensitivity / data_signals labels.

It then walks the label-encoded links (grant -> identity via grant.labels["identity"];
identity -> the surface it lives on via identity.raw["source_ext_id"]; grant -> a target
resource via grant.raw["target"], e.g. "topic:payments" -> ext_id "topic-payments") to build
ordered ATTACK PATHS: each is a list of hops, and every hop cites the resource ext_id and the
exact signal read at that hop, so the finding it becomes can be defended hop-by-hop.

HONESTY — READ THIS BEFORE TRUSTING A PATH. This is correlation over the CURRENT, label-encoded
graph WITHIN a single scan's resource set. It is not data lineage. Specifically:

  • "Reachable" here means an authorization or hosting relationship encoded in the labels of the
    resources we collected (a wildcard grant of the right resource type; a shared surface). It is
    NOT a proven network path, and it is NOT multi-hop lineage across systems. A wildcard topic
    grant means the identity is authorized to every topic including the sensitive one — we assert
    exactly that, not that a packet has ever flowed.
  • Co-location is coarse. When we cannot resolve a grant to a specific target, or a data resource
    to a specific hosting surface, we fall back to "in the same scanned system", which mirrors the
    existing hand-built rule (detect/data.py checks "any broker in this scan is exposed"). The
    observation says so.
  • Deep, cross-system data lineage — a payment flowing broker -> connector -> warehouse -> BI —
    is out of scope until CDC / iPaaS lineage connectors exist. We do not claim it.
  • When a needed signal is absent (a surface exists but its exposure config is unreadable), the
    path is marked not-assessable rather than silently dropped: a coverage gap, not a clean pass.

Nothing here reads a payload, a message, or a secret value; it reads the metadata graph only.
"""
from dataclasses import dataclass, field
from typing import Optional

# The data-carrying kinds classify.py tags. Mirrored (not imported) so this stays a pure module
# with no import-time side effects, and so a future data kind is a one-line change here.
_DATA_KINDS = frozenset({
    "topic", "queue", "stream", "exchange", "subject",
    "route", "service", "mcp_tool", "keyspace", "channel",
})

# Kinds that represent a reachable host/entry surface. A resource of another kind can still count
# as a surface if it carries explicit exposure labels (a Kong route with no auth plugin is its own
# surface) — see assess_exposure.
_SURFACE_KINDS = frozenset({
    "broker", "redis_server", "mcp_server", "node", "server", "gateway",
    "cluster", "nats_server", "mqtt_broker", "pulsar_broker",
})

# High-regulatory data classes (classify.py's _HIGH). A path onto these is critical, not high.
_HIGH_CLASSES = frozenset({"pci", "phi", "secrets"})

# Leaf names that mark a shared / default / anonymous principal — an over-privilege signal on its
# own (mirrors detect/identity.py's shared-default rule, kept local to stay pure).
_SHARED_DEFAULT_NAMES = frozenset({
    "guest", "admin", "administrator", "default", "anonymous", "root", "public", "test",
})

# Generic exposure signal keys a connector may set on a surface's labels or raw. Read case- and
# location-insensitively (labels first, then raw). Truthy value => the condition holds.
_PLAINTEXT_KEYS = ("plaintext", "cleartext", "no_tls", "tls_disabled")
_UNAUTH_KEYS = ("unauthenticated", "no_auth", "no_authorizer", "anonymous", "anonymous_login",
                "auth_disabled", "no_credentials")
_PUBLIC_KEYS = ("public", "internet_reachable", "internet_exposed", "exposed", "bind_all",
                "publicly_accessible")


# ── result shapes ─────────────────────────────────────────────────────────────
@dataclass
class Exposure:
    """The exposure verdict for one surface resource.

    `exposed` is tri-state on purpose (mirrors contracts.Hit.assessable): True = a signal proved
    it, False = a signal proved it is NOT exposed, None = it is a surface but no signal was
    readable (a coverage gap). `plaintext` / `unauth` / `public` are the specific facts that back
    a True, used for severity. `evidence` is the human string cited in a hop."""
    ext_id: str
    kind: str
    exposed: Optional[bool]
    plaintext: bool = False
    unauth: bool = False
    public: bool = False
    evidence: str = ""

    @property
    def fully_open(self) -> bool:
        """Cleartext on the wire AND no access control — the worst surface state."""
        return bool(self.plaintext and self.unauth)


@dataclass
class Hop:
    """One step in an attack path. Every hop names a real resource and the signal read at it, so
    a path can be defended citation-by-citation."""
    ext_id: str
    kind: str
    role: str      # "exposure" | "nhi" | "grant" | "data"
    signal: str
    name: str = ""

    def cite(self) -> str:
        label = f"{self.kind} '{self.name}'" if self.name else self.kind
        return f"[{label} ({self.ext_id}): {self.signal}]"


@dataclass
class AttackPath:
    """An ordered, cited toxic-combination chain.

    `anchor_ext_id` is the resource the emitting detector keys on (the anchor-once discipline from
    detect/data.py): each path is emitted exactly once, by the detector firing on its anchor, so
    the same chain can never be written twice from two different resources."""
    category: str          # EXPOSED_NHI_SENSITIVE | PUBLIC_OVERPRIVILEGED | SENSITIVE_ON_EXPOSED
    severity: str
    hops: list             # list[Hop], ordered entry -> target
    anchor_ext_id: str
    anchor_kind: str
    assessable: bool = True
    assessment_reason: str = ""
    factors: dict = field(default_factory=dict)

    @property
    def rule_id(self) -> str:
        return f"ATTACKPATH.{self.category}"

    def chain(self) -> str:
        """The hop-by-hop chain string, each hop cited, for the Hit observation."""
        return " -> ".join(h.cite() for h in self.hops)


# ── small readers over labels / raw ─────────────────────────────────────────────
def _label(r, *keys, default=None):
    src = {**(r.raw or {}), **(r.labels or {})}  # labels win over raw on collision
    for k in keys:
        if k in src and src[k] is not None:
            return src[k]
    return default


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "on", "enabled")
    return bool(v)


def _cfg_value(cfg: dict, key: str):
    """A broker config entry is either a scalar or {"value": ...} (see detect/data.py)."""
    e = (cfg or {}).get(key)
    return e.get("value") if isinstance(e, dict) else e


def data_classes(r) -> list:
    raw = (r.labels or {}).get("data_classes") or ""
    return [c for c in raw.split(",") if c]


def data_signals(r) -> str:
    return (r.labels or {}).get("data_signals") or ""


def is_sensitive(r) -> bool:
    return r.kind in _DATA_KINDS and bool(data_classes(r))


def is_high_sensitive(r) -> bool:
    return any(c in _HIGH_CLASSES for c in data_classes(r))


def is_overprivileged_grant(r) -> bool:
    """A grant is over-privileged when it is a WILDCARD ALLOW. A deny wildcard is a guardrail, not
    a privilege (mirrors detect/identity.grant_wildcard)."""
    if r.kind != "grant":
        return False
    wildcard = _truthy(_label(r, "wildcard", default=False))
    permission = str(_label(r, "permission", default="allow")).lower()
    return wildcard and permission != "deny"


def is_shared_default_identity(r) -> bool:
    """A principal whose leaf name is a well-known shared/default account. The leaf is the part
    after the last ':' so "User:guest" and "identity:kafka:guest" both resolve to "guest"."""
    if r.kind != "identity":
        return False
    name = str(r.name or "")
    leaf = name.split(":")[-1].strip().lower()
    return leaf in _SHARED_DEFAULT_NAMES


# ── exposure ────────────────────────────────────────────────────────────────────
def _kafka_broker_exposure(b) -> Exposure:
    """Read a Kafka-style broker's config for the two facts that make it an exposed surface: a
    PLAINTEXT client listener and no authorizer. Parses listener.security.protocol.map directly
    (the coarse "is any client listener PLAINTEXT" fact), the same readable keys detect/data.py
    uses. An empty config is a coverage gap (exposed=None), not a clean pass."""
    cfg = (b.raw or {}).get("config") or {}
    if not cfg:
        return Exposure(b.ext_id, b.kind, exposed=None,
                        evidence="broker config not readable")

    authz = _cfg_value(cfg, "authorizer.class.name")
    no_authorizer = not (authz and str(authz).strip())

    controllers = {n.strip().lower() for n in
                   str(_cfg_value(cfg, "controller.listener.names") or "").split(",") if n.strip()}
    pmap = str(_cfg_value(cfg, "listener.security.protocol.map") or "")
    plaintext = False
    listener = ""
    for pair in pmap.split(","):
        if ":" not in pair:
            continue
        nm, proto = pair.split(":", 1)
        if proto.strip().upper() == "PLAINTEXT" and nm.strip().lower() not in controllers:
            plaintext = True
            listener = nm.strip()
            break

    ev = []
    if plaintext:
        ev.append(f"client listener {listener} maps to PLAINTEXT")
    if no_authorizer:
        ev.append("authorizer.class.name is unset (no ACL enforcement)")
    exposed = bool(plaintext or no_authorizer)
    return Exposure(b.ext_id, b.kind, exposed=exposed, plaintext=plaintext,
                    unauth=no_authorizer, evidence="; ".join(ev) or "encrypted and authorized")


def _redis_exposure(s, resources) -> Exposure:
    """Read a Redis server's config: unauthenticated when there is no requirepass and the default
    ACL user is nopass; plaintext when tls-port is 0; public when protected-mode is off or it
    binds all interfaces (mirrors detect/redis.py's checks, read-only)."""
    raw = s.raw or {}
    has_pass = _truthy(raw.get("has_requirepass"))
    default_nopass = False
    users = [r for r in resources if r.kind == "redis_user"]
    if users:
        default_nopass = any((u.raw or {}).get("username") == "default" and _truthy((u.raw or {}).get("nopass"))
                             for u in users)
    else:
        default_nopass = True  # no ACL list => Redis <6 / ACL off; default is historically nopass
    unauth = (not has_pass) and default_nopass

    tls_port = str(raw.get("tls_port") or "0").strip()
    plaintext = tls_port in ("", "0")
    bind = str(raw.get("bind") or "").strip()
    bind_all = (not bind) or "0.0.0.0" in bind or "*" in bind or "::" in bind
    protected_off = str(raw.get("protected_mode") or "").lower() == "no"
    public = bind_all or protected_off

    ev = []
    if unauth:
        ev.append("no requirepass and default user is nopass")
    if plaintext:
        ev.append("tls-port is 0 (traffic in cleartext)")
    if public:
        ev.append("protected-mode off or binds all interfaces")
    exposed = bool(unauth or plaintext or public)
    return Exposure(s.ext_id, s.kind, exposed=exposed, plaintext=plaintext, unauth=unauth,
                    public=public, evidence="; ".join(ev) or "authenticated")


def _generic_exposure(r) -> Optional[Exposure]:
    """Exposure from the generic label/raw keys any connector may set. Returns None when the
    resource is not a surface at all (not a surface kind and carries no exposure keys)."""
    plaintext = any(_truthy(_label(r, k, default=False)) for k in _PLAINTEXT_KEYS)
    unauth = any(_truthy(_label(r, k, default=False)) for k in _UNAUTH_KEYS)
    public = any(_truthy(_label(r, k, default=False)) for k in _PUBLIC_KEYS)

    # An explicit tls=false / authenticated=false is also a plaintext / unauth signal.
    for key in ("tls", "tls_enabled", "encrypted"):
        v = _label(r, key)
        if v is not None and not _truthy(v):
            plaintext = True
    for key in ("authenticated", "auth_required", "requires_auth"):
        v = _label(r, key)
        if v is not None and not _truthy(v):
            unauth = True

    has_any_signal = plaintext or unauth or public
    if not has_any_signal and r.kind not in _SURFACE_KINDS:
        return None
    if not has_any_signal:
        # A surface kind with no readable exposure signal at all => coverage gap.
        return Exposure(r.ext_id, r.kind, exposed=None, evidence="no exposure signal readable")

    ev = []
    if plaintext:
        ev.append("plaintext / TLS not enabled")
    if unauth:
        ev.append("unauthenticated / no access control")
    if public:
        ev.append("publicly reachable")
    return Exposure(r.ext_id, r.kind, exposed=True, plaintext=plaintext, unauth=unauth,
                    public=public, evidence="; ".join(ev))


def assess_exposure(r, resources=()) -> Optional[Exposure]:
    """The exposure verdict for a resource, or None if it is not a surface. Connector-specific
    config parsers first (Kafka broker, Redis server), then the generic label reader."""
    if r.kind == "broker" and isinstance((r.raw or {}).get("config"), dict):
        return _kafka_broker_exposure(r)
    if r.kind == "redis_server":
        return _redis_exposure(r, resources)
    return _generic_exposure(r)


# ── link maps ────────────────────────────────────────────────────────────────────
def _by_ext(resources) -> dict:
    return {r.ext_id: r for r in resources}


def identity_source_surface(identity) -> Optional[str]:
    """The ext_id of the surface an identity lives on (identity.py records it as source_ext_id)."""
    src = (identity.raw or {}).get("source_ext_id")
    return src or None


def grant_holder_ext(grant) -> Optional[str]:
    """The identity ext_id a grant is held by, from its label link."""
    return _label(grant, "identity") or (grant.raw or {}).get("identity_ext_id")


def _grant_target_ext_ids(grant, by_ext: dict) -> list:
    """Resolve a grant's raw target ("topic:payments", "vhost:orders") to any collected resource
    ext_id it names, using the "<type>:<name>" -> "<type>-<name>" convention the connectors use."""
    target = str((grant.raw or {}).get("target") or "")
    out = []
    if ":" in target:
        rtype, name = target.split(":", 1)
        cand = f"{rtype.strip()}-{name.strip()}"
        if cand in by_ext:
            out.append(cand)
    if target in by_ext:
        out.append(target)
    return out


def _grant_reaches(grant, data_resource, by_ext: dict) -> bool:
    """Does this grant authorize access to `data_resource`? True when the grant literally names it,
    OR the grant is a wildcard whose resource type matches the data kind (a wildcard topic grant
    reaches every topic, including the sensitive one). Wildcards with an unknown/blank restype are
    treated as reaching any data resource in the system — the coarse fallback, worded honestly."""
    if data_resource.ext_id in _grant_target_ext_ids(grant, by_ext):
        return True
    if not is_overprivileged_grant(grant):
        return False
    restype = str((grant.raw or {}).get("restype") or "").strip().lower()
    if restype and restype not in ("*", "all", "any"):
        return restype == data_resource.kind
    return True  # wildcard grant with no specific resource type => reaches all data resources


# ── the engine ─────────────────────────────────────────────────────────────────
def _exposed_surfaces(resources) -> list:
    """Every surface with a definite exposure=True, plus the indeterminate ones (exposed=None),
    returned separately so callers can distinguish "exposed" from "could not tell"."""
    exposed, unknown = [], []
    for r in resources:
        ex = assess_exposure(r, resources)
        if ex is None:
            continue
        if ex.exposed is True:
            exposed.append(ex)
        elif ex.exposed is None:
            unknown.append(ex)
    return exposed, unknown


def _worst_exposure(exposures: list) -> Optional[Exposure]:
    """Prefer a fully-open surface (plaintext AND unauth), then any plaintext, then any."""
    if not exposures:
        return None
    return sorted(exposures, key=lambda e: (e.fully_open, e.plaintext, e.unauth, e.public),
                  reverse=True)[0]


def _overprivileged_nhis(resources, by_ext: dict) -> list:
    """(identity, grant, source_exposure) for every over-privileged NHI, where source_exposure is
    the exposure of the surface the identity lives on (or None)."""
    out = []
    for g in resources:
        if not is_overprivileged_grant(g):
            continue
        holder = grant_holder_ext(g)
        identity = by_ext.get(holder) if holder else None
        src_ex = None
        if identity is not None:
            surf = identity_source_surface(identity)
            if surf and surf in by_ext:
                src_ex = assess_exposure(by_ext[surf], resources)
        out.append((identity, g, src_ex))
    return out


def _sensitive_hop(d) -> Hop:
    classes = ",".join(data_classes(d))
    sig = f"named like {classes} data (matched {data_signals(d)})" if data_signals(d) \
        else f"classified {classes}"
    return Hop(d.ext_id, d.kind, "data", sig, name=d.name)


def _exposure_hop(ex: Exposure) -> Hop:
    return Hop(ex.ext_id, ex.kind, "exposure", f"exposed — {ex.evidence}")


def _sensitive_severity(high: bool, ex: Exposure) -> str:
    # Mirrors detect/data.py: critical only when regulated data rides a fully-open surface.
    return "critical" if (high and ex.fully_open) else "high"


def compute_paths(resources: list) -> list:
    """The pure core. Compute every attack path in a resource set, each anchored on exactly one
    resource so a per-resource detector emits it exactly once. Precedence for a sensitive data
    resource: the 3-factor EXPOSED_NHI_SENSITIVE supersedes the 2-factor SENSITIVE_ON_EXPOSED,
    which supersedes a not-assessable coverage gap — a data resource yields at most one such
    path, never a duplicate pair."""
    resources = list(resources or [])
    by_ext = _by_ext(resources)
    exposed, unknown = _exposed_surfaces(resources)
    worst = _worst_exposure(exposed)
    overpriv = _overprivileged_nhis(resources, by_ext)

    paths: list = []

    # ── PUBLIC_OVERPRIVILEGED: an over-privileged NHI on an exposed/public surface, no sensitive
    # data required. Anchored on the GRANT so it is emitted once per over-privileged grant.
    for identity, grant, src_ex in overpriv:
        surf_ex = src_ex if (src_ex and src_ex.exposed is True) else worst
        if not (surf_ex and surf_ex.exposed is True):
            continue
        hops = [_exposure_hop(surf_ex)]
        if identity is not None:
            marks = ["principal an attacker reaching the surface can act as"]
            if is_shared_default_identity(identity):
                marks.append("shared/default account")
            hops.append(Hop(identity.ext_id, "identity", "nhi", "; ".join(marks), name=identity.name))
        action = str((grant.raw or {}).get("action") or _label(grant, "action") or "")
        hops.append(Hop(grant.ext_id, "grant", "grant",
                        f"wildcard ALLOW grant ({action or 'all'})", name=grant.name))
        admin_like = action.lower() in ("all", "*", "admin", "superuser", "configure")
        sev = "critical" if (surf_ex.fully_open and admin_like) else "high"
        paths.append(AttackPath(
            "PUBLIC_OVERPRIVILEGED", sev, hops, anchor_ext_id=grant.ext_id, anchor_kind="grant",
            factors={"exposed": True, "overprivileged": True,
                     "fully_open": surf_ex.fully_open, "admin_like": admin_like}))

    # ── data-anchored paths: one per sensitive data resource, strongest wins.
    for d in resources:
        if not is_sensitive(d):
            continue
        high = is_high_sensitive(d)

        # 3-factor: an over-privileged NHI on an exposed surface that reaches THIS data resource.
        triad = None
        for identity, grant, src_ex in overpriv:
            if not _grant_reaches(grant, d, by_ext):
                continue
            surf_ex = src_ex if (src_ex and src_ex.exposed is True) else worst
            if not (surf_ex and surf_ex.exposed is True):
                continue
            triad = (identity, grant, surf_ex)
            break
        if triad is not None:
            identity, grant, surf_ex = triad
            hops = [_exposure_hop(surf_ex)]
            if identity is not None:
                marks = ["over-privileged non-human identity reachable via the exposed surface"]
                if is_shared_default_identity(identity):
                    marks.append("shared/default account")
                hops.append(Hop(identity.ext_id, "identity", "nhi", "; ".join(marks),
                                name=identity.name))
            hops.append(Hop(grant.ext_id, "grant", "grant",
                            "holds a wildcard ALLOW grant that authorizes this resource",
                            name=grant.name))
            hops.append(_sensitive_hop(d))
            sev = "critical" if high else "high"
            paths.append(AttackPath(
                "EXPOSED_NHI_SENSITIVE", sev, hops, anchor_ext_id=d.ext_id, anchor_kind=d.kind,
                factors={"exposed": True, "overprivileged": True, "sensitive": True,
                         "high": high, "fully_open": surf_ex.fully_open}))
            continue

        # 2-factor: sensitive data in a system that has an exposed surface (self or co-located).
        self_ex = assess_exposure(d, resources)
        surf_ex = self_ex if (self_ex and self_ex.exposed is True) else worst
        if surf_ex and surf_ex.exposed is True:
            if surf_ex.ext_id == d.ext_id:
                hops = [Hop(d.ext_id, d.kind, "exposure",
                            f"exposed — {surf_ex.evidence}", name=d.name), _sensitive_hop(d)]
            else:
                hops = [_exposure_hop(surf_ex), _sensitive_hop(d)]
            paths.append(AttackPath(
                "SENSITIVE_ON_EXPOSED", _sensitive_severity(high, surf_ex), hops,
                anchor_ext_id=d.ext_id, anchor_kind=d.kind,
                factors={"exposed": True, "sensitive": True, "high": high,
                         "fully_open": surf_ex.fully_open}))
            continue

        # not-assessable: this data resource is sensitive and a surface exists, but that surface's
        # exposure could not be read — a coverage gap, never a silent pass.
        if unknown:
            u = unknown[0]
            hops = [Hop(u.ext_id, u.kind, "exposure",
                        f"exposure not determinable — {u.evidence}", name=""), _sensitive_hop(d)]
            paths.append(AttackPath(
                "SENSITIVE_ON_EXPOSED", "high", hops, anchor_ext_id=d.ext_id, anchor_kind=d.kind,
                assessable=False,
                assessment_reason=(f"surface {u.ext_id} may host this sensitive resource but its "
                                   f"exposure could not be read"),
                factors={"sensitive": True, "high": high, "exposed": None}))

    return paths


def paths_for(resource, resources: list) -> list:
    """Every path anchored on `resource` — the detector's per-resource entry point. Computes the
    whole graph once and filters to this anchor, so each path is emitted exactly once."""
    return [p for p in compute_paths(resources) if p.anchor_ext_id == resource.ext_id]
