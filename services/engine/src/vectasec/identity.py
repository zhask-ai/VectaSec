"""Non-Human Identity (NHI) derivation — the normalized identity model.

WHY THIS EXISTS. The integration layer is where non-human identities live: broker principals,
gateway API consumers, message-queue service users, OAuth clients for agent gateways. They are
the actual attack surface of the 2023–2025 integration breaches (the Salesloft Drift / Gainsight
OAuth-token pattern), and no single console shows them together — each system has its own users
screen. This pass reads what the connectors ALREADY collect (Kafka ACL principals, Kong
consumers + their credential counts, RabbitMQ users + permissions, MCP OAuth clients) and
normalizes it into ONE model with three kinds:

  identity    a non-human principal (a service account, API consumer, broker user, OAuth client)
  credential  a secret that authenticates an identity (password, API key, JWT, OAuth secret) —
              its METADATA only: type, hashing, default?, present?, count. Never the value.
  grant       an authorization an identity holds (Kafka ACL, RabbitMQ permission, scope, group)

…plus edges: credential --credential_of--> identity, grant --granted_to--> identity, and
grant --grants_access--> target when the grant names a resource we collected.

WHY A DERIVATION, NOT A CONNECTOR CHANGE. It reads `resource.raw` that connectors already
produce, so a new connector gets NHI coverage the moment it emits users/consumers/ACLs — and
the extractor for a system lives in one place here, the same "add a file" spirit as connectors
and detectors. Detectors then run on `identity`/`credential`/`grant` like any other kind, and
the console gets a cross-system NHI inventory for free.

NO SECRETS CROSS THE BOUNDARY. A credential resource records that a secret EXISTS and what
shape it has; it never records the secret. Kong key values are already collected as counts, not
values (connect/kong.py); RabbitMQ password hashes are verified-then-dropped at the connector;
Kafka exposes no principal secrets at all (recorded honestly as "no credential material
readable"). This layer preserves that: it copies metadata, never a secret field.
"""
import hashlib
from typing import Callable

from .contracts import Collected, Edge, Resource

# type -> extractor(resources) -> (new_resources, new_edges). One per connector family; a
# connector with no extractor simply contributes no NHIs (honest — not everything has them).
IDENTITY_EXTRACTORS: dict[str, Callable[[list], tuple]] = {}


def identity_extractor(type_: str):
    def wrap(fn: Callable) -> Callable:
        IDENTITY_EXTRACTORS[type_] = fn
        return fn
    return wrap


def derive_identities(type_: str, collected: Collected) -> Collected:
    """Append the normalized NHI model for `type_` to `collected`. Idempotent by ext_id
    (persist upserts on (connection_id, ext_id)), so a re-scan restates, never accumulates."""
    fn = IDENTITY_EXTRACTORS.get(type_)
    if not fn:
        return collected
    new_resources, new_edges = fn(collected.resources)
    collected.resources.extend(new_resources)
    collected.edges.extend(new_edges)
    return collected


# ── automation labelling ─────────────────────────────────────────────────────
# Systems whose identities are held by an automation or agent rather than a service a human
# operates directly. The strategy doc's "Belongs to an automation or agent" column is answered
# from this label on every identity / credential / grant, so the console never has to know which
# connector a row came from. A tag of "automation" on the identity sets it too, for connectors
# (Kafka, Kong, …) whose principal is used by an automation even though the system is not one.
AUTOMATION_SYSTEMS = {"n8n", "zapier", "make", "workato", "boomi", "mulesoft", "mcp", "airflow"}


def _is_automation(system: str, tags: list | None = None) -> bool:
    return system in AUTOMATION_SYSTEMS or "automation" in (tags or [])


def _bool_label(v: bool) -> str:
    return "true" if v else "false"


# ── builders ────────────────────────────────────────────────────────────────
def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in (s or "").lower()).strip("-") or "unknown"


def _grant_ext(system: str, identity_ext: str, action: str, target: str) -> str:
    h = hashlib.sha256(f"{identity_ext}|{action}|{target}".encode()).hexdigest()[:12]
    return f"grant:{system}:{h}"


def _mk_identity(system: str, itype: str, name: str, *, external: bool = False,
                 tags: list | None = None, source_ext: str = "", extra: dict | None = None) -> Resource:
    automation = _is_automation(system, tags)
    return Resource(
        kind="identity",
        name=name,
        ext_id=f"identity:{system}:{_slug(name)}",
        labels={"identity_type": itype, "system": system,
                "external": "true" if external else "false",
                "automation": _bool_label(automation)},
        raw={"identity_type": itype, "system": system, "principal": name,
             "external": external, "tags": tags or [], "source_ext_id": source_ext,
             "automation": automation,
             **(extra or {})},
    )


def _mk_credential(system: str, owner_ext: str, ctype: str, *, name: str,
                   hashing: str = "unknown", is_default: bool = False, present: bool = True,
                   plaintext=None, count: int = 1, extra: dict | None = None) -> Resource:
    return Resource(
        kind="credential",
        name=name,
        ext_id=f"cred:{system}:{_slug(owner_ext)}:{ctype}",
        # `owner` is in labels (not just raw) so the console can group a credential under its
        # identity without ever selecting the leak-risk `raw` column.
        labels={"credential_type": ctype, "system": system, "owner": owner_ext,
                "hashing": hashing, "default": "true" if is_default else "false",
                "automation": _bool_label(_is_automation(system))},
        raw={"credential_type": ctype, "system": system, "owner_ext_id": owner_ext,
             "hashing": hashing, "is_default": is_default, "present": present,
             "plaintext": plaintext, "count": count, **(extra or {})},
    )


def _mk_grant(system: str, identity_ext: str, action: str, target: str, *,
              wildcard: bool = False, permission: str = "allow", scope: str = "",
              extra: dict | None = None) -> Resource:
    return Resource(
        kind="grant",
        name=f"{action} → {target}" if target else action,
        ext_id=_grant_ext(system, identity_ext, action, target),
        namespace=scope or None,
        # `identity` in labels lets the console link a grant to its holder without reading `raw`;
        # `target` is there for the same reason — the Access page renders "can <action> <target>"
        # from labels alone, never from the leak-risk `raw` column.
        labels={"system": system, "action": action, "identity": identity_ext,
                "target": target or "",
                "wildcard": "true" if wildcard else "false", "permission": permission,
                "automation": _bool_label(_is_automation(system))},
        raw={"system": system, "identity_ext_id": identity_ext, "action": action,
             "target": target, "wildcard": wildcard, "permission": permission,
             "scope": scope, **(extra or {})},
    )


# ── Kafka: ACL principals + bindings ──────────────────────────────────────────
@identity_extractor("kafka")
def _from_kafka(resources: list) -> tuple:
    out: list[Resource] = []
    edges: list[Edge] = []
    seen: dict[str, Resource] = {}

    for r in resources:
        if r.kind != "broker":
            continue
        acls = (r.raw or {}).get("acls") or {}
        for b in acls.get("bindings") or []:
            principal = b.get("principal") or ""
            if not principal:
                continue
            # "User:alice" / "Group:admins" — the prefix is the principal TYPE Kafka uses.
            itype = "group" if principal.lower().startswith("group:") else "service_account"
            idr = seen.get(principal)
            if idr is None:
                idr = _mk_identity("kafka", itype, principal, source_ext=r.ext_id)
                seen[principal] = idr
                out.append(idr)

            restype = (b.get("restype") or "").lower()
            res_name = b.get("name") or "*"
            op = (b.get("operation") or "").lower()
            pattern = (b.get("pattern") or "").upper()
            target = f"{restype}:{res_name}"
            wildcard = res_name == "*" or op == "all" or pattern == "PREFIXED"
            g = _mk_grant("kafka", idr.ext_id, op, target,
                          wildcard=wildcard, permission=(b.get("permission_type") or "allow").lower(),
                          extra={"restype": restype, "pattern": pattern, "host": b.get("host")})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
            # Resolve a LITERAL topic grant to the collected topic (ext_id topic-<name>).
            if restype == "topic" and pattern == "LITERAL" and res_name != "*":
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=f"topic-{res_name}",
                                  kind="grants_access"))
    # Kafka exposes no principal secrets via AdminClient — recorded as absence, not silence.
    return out, edges


# ── RabbitMQ: users, permissions, OAuth ───────────────────────────────────────
_WEAK_HASH = {"md5", "sha1"}


@identity_extractor("rabbitmq")
def _from_rabbitmq(resources: list) -> tuple:
    out: list[Resource] = []
    edges: list[Edge] = []
    id_by_user: dict[str, str] = {}

    for r in resources:
        if r.kind != "user":
            continue
        raw = r.raw or {}
        name = raw.get("name") or r.name
        tags = raw.get("tags") or []
        itype = "admin" if "administrator" in tags else "service_account"
        idr = _mk_identity("rabbitmq", itype, name, tags=tags, source_ext=r.ext_id)
        id_by_user[name] = idr.ext_id
        out.append(idr)

        if raw.get("has_internal_password"):
            hashing = (raw.get("hashing_algorithm") or "unknown").lower()
            cred = _mk_credential(
                "rabbitmq", idr.ext_id, "password", name=f"{name}:password",
                hashing=hashing, is_default=bool(raw.get("default_password_confirmed")),
                present=True, plaintext=False)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

    for r in resources:
        if r.kind != "permission":
            continue
        raw = r.raw or {}
        user, vhost = raw.get("user"), raw.get("vhost")
        owner = id_by_user.get(user) or f"identity:rabbitmq:{_slug(user or '')}"
        for dim in ("configure", "write", "read"):
            regex = raw.get(dim)
            if not regex:              # empty regex == no access on this dimension
                continue
            g = _mk_grant("rabbitmq", owner, dim, f"vhost:{vhost}",
                          wildcard=(regex == ".*"), scope=str(vhost),
                          extra={"pattern": regex})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=owner, kind="granted_to"))
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=f"vhost-{vhost}", kind="grants_access"))

    # Node-level OAuth client (the broker's own IdP integration).
    for r in resources:
        if r.kind != "node":
            continue
        raw = r.raw or {}
        if raw.get("oauth_enabled") and raw.get("oauth_client_id"):
            cid = raw.get("oauth_client_id")
            idr = _mk_identity("rabbitmq", "oauth_client", f"oauth:{cid}", external=True,
                               source_ext=r.ext_id)
            out.append(idr)
            if raw.get("oauth_client_secret_present"):
                cred = _mk_credential("rabbitmq", idr.ext_id, "oauth_secret",
                                      name=f"oauth:{cid}:secret", hashing="n/a", present=True)
                out.append(cred)
                edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
    return out, edges


# ── Kong: consumers, credentials, ACL groups ──────────────────────────────────
_KONG_CRED_TYPES = {
    "key-auth": "api_key", "basic-auth": "basic", "jwt": "jwt",
    "oauth2": "oauth2", "hmac-auth": "hmac", "mtls-auth": "mtls",
}


@identity_extractor("kong")
def _from_kong(resources: list) -> tuple:
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "consumer":
            continue
        raw = r.raw or {}
        name = raw.get("username") or raw.get("custom_id") or r.name
        idr = _mk_identity("kong", "api_consumer", name, source_ext=r.ext_id,
                           extra={"custom_id": raw.get("custom_id")})
        out.append(idr)

        creds = (raw.get("credentials") or {})
        for path, meta in creds.items():
            ctype = _KONG_CRED_TYPES.get(path)
            if not ctype:
                continue                       # "acls" lives here too — handled as grants below
            count = (meta or {}).get("count", 0) if isinstance(meta, dict) else 0
            if not count:
                continue
            # Kong stores key-auth keys in cleartext by default; basic-auth is hashed. We hold
            # only counts, so we record the type and leave storage strength to the detector's
            # own knowledge rather than asserting plaintext from data we don't have.
            cred = _mk_credential("kong", idr.ext_id, ctype, name=f"{name}:{ctype}",
                                  hashing="unknown", present=True, count=count)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        # ACL group memberships are authorizations.
        acl_meta = creds.get("acls") if isinstance(creds, dict) else None
        for grp in ((acl_meta or {}).get("groups") or []) if isinstance(acl_meta, dict) else []:
            g = _mk_grant("kong", idr.ext_id, "group-member", f"acl-group:{grp}")
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges


# ── Redis: ACL users ──────────────────────────────────────────────────────────
@identity_extractor("redis")
def _from_redis(resources: list) -> tuple:
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "redis_user":
            continue
        raw = r.raw or {}
        name = raw.get("username") or r.name
        idr = _mk_identity("redis", "service_account", name, source_ext=r.ext_id,
                           extra={"enabled": raw.get("enabled")})
        out.append(idr)

        # Credential: a password unless the user is nopass. We only know presence, never a value.
        if not raw.get("nopass"):
            cred = _mk_credential("redis", idr.ext_id, "password", name=f"{name}:password",
                                  hashing="sha256", present=True, plaintext=False)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        # Grant: the ACL key + command scope. `~*` (all keys) or `+@all`/`allcommands` is god-mode.
        keys = str(raw.get("keys") or "")
        commands = str(raw.get("commands") or "")
        wildcard = ("~*" in keys or "allkeys" in keys.lower()
                    or "+@all" in commands or "allcommands" in commands.lower())
        g = _mk_grant("redis", idr.ext_id, "acl", f"keys={keys or '?'} commands={commands or '?'}",
                      wildcard=wildcard, extra={"keys": keys, "commands": commands})
        out.append(g)
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges


# ── MCP: OAuth client + advertised scopes ─────────────────────────────────────
@identity_extractor("mcp")
def _from_mcp(resources: list) -> tuple:
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "mcp_server":
            continue
        raw = r.raw or {}
        issuer = raw.get("issuer") or (raw.get("as_metadata") or {}).get("issuer")
        client_name = raw.get("client_name")
        if not (issuer or client_name):
            continue
        label = client_name or f"oauth:{issuer}"
        idr = _mk_identity("mcp", "oauth_client", label, external=True, source_ext=r.ext_id,
                           extra={"issuer": issuer})
        out.append(idr)

        as_meta = raw.get("as_metadata") or {}
        scopes = as_meta.get("scopes_supported") or raw.get("scopes_supported") or []
        for sc in scopes if isinstance(scopes, list) else []:
            g = _mk_grant("mcp", idr.ext_id, "scope", str(sc),
                          wildcard=(str(sc) in ("*", "all") or str(sc).endswith(":*")))
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
