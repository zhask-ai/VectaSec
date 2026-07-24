"""HashiCorp Vault connector — read-only posture of the secrets/identity fabric ITSELF.

Vault is the middleware that IS the secrets fabric: the place other systems fetch their
credentials from. Scanning it as a target means reading its own guard rails — is there a
tamper-proof audit trail, is a root token still live, is any ACL policy effectively root,
are the identity-federation roles bound to a subject, does the unseal quorum actually
require a quorum. This connector reads ONLY the metadata APIs that answer those questions
and writes nothing:

  GET  /v1/sys/health           version, sealed?, initialized?, cluster identity (unauth-ok)
  GET  /v1/sys/seal-status      unseal shares `n` and threshold `t`, seal type (unauth-ok)
  GET  /v1/auth/token/lookup-self  the SCAN token's own policies + ttl — never its value
  GET  /v1/sys/audit            the enabled audit devices (needs a sudo-capable token)
  GET  /v1/sys/auth             the enabled auth methods (identity brokers into Vault)
  GET  /v1/sys/mounts           the enabled secret engines + their lease TTL config
  LIST /v1/sys/policies/acl     the ACL policy names, then GET each policy's rules (HCL/JSON)
  LIST auth/<m>/role + GET each  federation roles for approle/jwt/oidc/kubernetes auth

NEVER A SECRET VALUE. This is the hard line for a secrets store: no `kv` read, no
`auth/token/lookup-self` `id` field, no secret-id, no unseal key is ever fetched, stored,
logged, or returned. Only POLICY / MOUNT / AUTH / SEAL metadata — exactly the evidence a
posture finding must cite — crosses the boundary. `requirepass`-style discipline from the
Redis/RabbitMQ connectors, applied to the fabric that holds everyone else's secrets.

Vault is the canonical secret STORE for the whole product's fabric view: Vault, AWS Secrets
Manager, Azure Key Vault and GCP Secret Manager are the four backends other connectors' NHIs
ultimately resolve their credentials to. This connector makes the Vault one first-class.

Kinds are DISTINCT (vault_server, vault_mount, vault_policy, vault_auth_role) so no other
rulepack ever runs against a Vault resource by accident — the same discipline as
connect/redis.py refusing to reuse `broker`.

The parse layer (parse_server, parse_mount, parse_policy, parse_auth_role, _policy_paths) is
pure: Vault API JSON in, Resources out. Tests drive the detectors against parse-layer output
from golden fixture dicts, so httpx (and a live Vault) stay out of the test suite and a shape
drift between connector and rulepack fails a test instead of mis-firing in production.
"""
import json
import re
from urllib.parse import urlsplit

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# Secret engines whose whole purpose is short-lived, dynamically-generated credentials — the
# ones where the lease TTL is a real security control rather than irrelevant (kv/cubbyhole
# have no lease). A `0` TTL on these means "inherit the system default", NOT "never expires";
# the detector is worded to say exactly that and stays low-severity hygiene.
_DYNAMIC_ENGINES = {
    "database", "pki", "aws", "azure", "gcp", "ssh", "consul", "rabbitmq",
    "mongodbatlas", "nomad", "terraform", "kmip", "transform", "openldap",
}

# Auth methods that federate an external identity into Vault and carry per-role binding
# config we can read and assess (bound claims / bound service accounts / secret-id binding).
_FEDERATION_AUTH = {"approle", "jwt", "oidc", "kubernetes"}


# ── policy parsing (pure) ─────────────────────────────────────────────────────
_PATH_BLOCK_RE = re.compile(r'path\s+"([^"]+)"\s*\{(.*?)\}', re.S)
_CAPS_RE = re.compile(r'capabilities\s*=\s*\[([^\]]*)\]', re.S)
_QUOTED_RE = re.compile(r'"([^"]*)"')


def _policy_paths(rules) -> list:
    """Parse a Vault ACL policy into [{"path": glob, "capabilities": [...]}].

    Vault policies are HCL, but a JSON form is also valid. Tolerates both and anything
    malformed (returns [] — a rule must never crash on a hand-mangled policy). Only the
    path glob and its capabilities are extracted; that is all the rulepack needs to cite."""
    if isinstance(rules, dict):
        rules = json.dumps(rules)   # JSON policy passed as a dict
    text = str(rules or "")
    # JSON policy form: {"path": {"secret/*": {"capabilities": [...]}}}
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
            paths = doc.get("path") if isinstance(doc, dict) else None
            if isinstance(paths, dict):
                out = []
                for glob, spec in paths.items():
                    caps = (spec or {}).get("capabilities") if isinstance(spec, dict) else None
                    out.append({"path": str(glob),
                                "capabilities": [str(c).lower() for c in caps or []]})
                return out
        except (ValueError, TypeError):
            pass   # fall through to HCL parsing
    out = []
    for glob, body in _PATH_BLOCK_RE.findall(text):
        caps_m = _CAPS_RE.search(body)
        caps = [c.lower() for c in _QUOTED_RE.findall(caps_m.group(1))] if caps_m else []
        out.append({"path": glob, "capabilities": caps})
    return out


# ── parse layer: Vault API JSON → Resources (pure, no httpx) ───────────────────
def parse_server(base_url: str, *, health: dict, seal: dict, token: dict, audit: dict,
                 collection: dict) -> Resource:
    """The vault_server resource: seal quorum, version, the scan token's own policies, and the
    audit-device inventory — plus per-endpoint outcomes so a denied read reads as a coverage
    gap, never a clean pass. `health`/`seal`/`token`/`audit` are the raw API `data` payloads
    (or {} when the call failed — the matching *_readable flag records which)."""
    s = urlsplit(base_url)
    scheme = s.scheme or "https"

    seal_data = seal or {}
    health_data = health or {}
    token_data = token or {}
    audit_data = audit or {}

    audit_readable = collection.get("sys/audit", {}).get("outcome") == "ok"
    token_readable = collection.get("auth/token/lookup-self", {}).get("outcome") == "ok"
    seal_readable = collection.get("sys/seal-status", {}).get("outcome") == "ok"

    # audit devices come back keyed by path (e.g. "file/"); ignore response-wrapper keys.
    devices = [{"path": p, "type": (d or {}).get("type")}
               for p, d in audit_data.items()
               if isinstance(d, dict) and str(p).endswith("/")]

    policies = token_data.get("policies")
    policies = [str(p) for p in policies] if isinstance(policies, list) else []

    return Resource(
        kind="vault_server",
        name=s.netloc or base_url,
        ext_id=f"vault-{s.netloc or base_url}",
        namespace=None,
        labels={"version": str(seal_data.get("version") or health_data.get("version") or "?"),
                "scheme": scheme,
                "sealed": "true" if seal_data.get("sealed") else "false"},
        raw={
            "base_url": base_url,
            "scheme": scheme,
            "tls": scheme == "https",
            "version": seal_data.get("version") or health_data.get("version"),
            "initialized": (seal_data.get("initialized")
                            if seal_data.get("initialized") is not None
                            else health_data.get("initialized")),
            "sealed": seal_data.get("sealed"),
            "cluster_name": health_data.get("cluster_name"),
            "seal_type": seal_data.get("type"),
            "seal_threshold": seal_data.get("t"),
            "seal_shares": seal_data.get("n"),
            "seal_recovery": bool(seal_data.get("recovery_seal")),
            "seal_status_readable": seal_readable,
            # token metadata ONLY — the token value (`id`) is never read into here.
            "token_policies": policies,
            "token_is_root": "root" in policies,
            "token_ttl": token_data.get("ttl"),
            "token_display_name": token_data.get("display_name"),
            "token_readable": token_readable,
            "audit_devices": devices,
            "audit_count": len(devices),
            "audit_readable": audit_readable,
            "collection": collection,
        },
    )


def parse_mount(path: str, mount: dict) -> Resource:
    """One secret-engine mount from sys/mounts. `default_lease_ttl`/`max_lease_ttl` of 0 mean
    'inherit the system default', which the detector states verbatim rather than calling it
    infinite."""
    cfg = (mount or {}).get("config") or {}
    name = str(path).rstrip("/")
    mtype = (mount or {}).get("type")
    return Resource(
        kind="vault_mount",
        name=name,
        ext_id=f"vault-mount-{name}",
        namespace=None,
        labels={"engine": str(mtype or "?"),
                "dynamic": "true" if mtype in _DYNAMIC_ENGINES else "false"},
        raw={
            "path": path,
            "type": mtype,
            "dynamic_engine": mtype in _DYNAMIC_ENGINES,
            "default_lease_ttl": cfg.get("default_lease_ttl"),
            "max_lease_ttl": cfg.get("max_lease_ttl"),
            "options": (mount or {}).get("options"),
            "accessor": (mount or {}).get("accessor"),
            "local": (mount or {}).get("local"),
            "description": (mount or {}).get("description"),
        },
    )


def parse_policy(name: str, rules) -> Resource:
    """One ACL policy: its name and the parsed (path, capabilities) blocks. `rules` is the raw
    HCL/JSON string from sys/policies/acl/<name> (`data.policy`)."""
    paths = _policy_paths(rules)
    return Resource(
        kind="vault_policy",
        name=str(name),
        ext_id=f"vault-policy-{name}",
        namespace=None,
        labels={"paths": str(len(paths))},
        raw={"name": str(name), "paths": paths},
    )


def parse_auth_role(mount_path: str, mount_type: str, role_name: str, data: dict) -> Resource:
    """One federation role (approle/jwt/oidc/kubernetes). Normalises the binding fields the
    rulepack and the NHI extractor read; list fields are always lists, never None."""
    d = data or {}
    mp = str(mount_path).rstrip("/")

    def _list(key):
        v = d.get(key)
        return [str(x) for x in v] if isinstance(v, list) else ([] if v is None else [str(v)])

    bound_claims = d.get("bound_claims")
    return Resource(
        kind="vault_auth_role",
        name=f"{mp}/{role_name}",
        ext_id=f"vault-role-{mp}-{role_name}",
        namespace=mp,
        labels={"auth_type": str(mount_type), "role": str(role_name)},
        raw={
            "mount_path": mount_path,
            "mount_type": mount_type,
            "role_name": str(role_name),
            "token_policies": _list("token_policies") or _list("policies"),
            # approle
            "bind_secret_id": d.get("bind_secret_id"),
            "secret_id_bound_cidrs": _list("secret_id_bound_cidrs"),
            "token_bound_cidrs": _list("token_bound_cidrs"),
            "secret_id_num_uses": d.get("secret_id_num_uses"),
            "secret_id_ttl": d.get("secret_id_ttl"),
            # jwt / oidc
            "role_type": d.get("role_type"),
            "bound_audiences": _list("bound_audiences"),
            "bound_subject": d.get("bound_subject"),
            "bound_claims": bound_claims if isinstance(bound_claims, dict) else None,
            "user_claim": d.get("user_claim"),
            # kubernetes
            "bound_service_account_names": _list("bound_service_account_names"),
            "bound_service_account_namespaces": _list("bound_service_account_namespaces"),
        },
    )


# ── collection (httpx in, per-endpoint isolation) ─────────────────────────────
def _endpoint(client, base: str, path: str, headers: dict, *, list_: bool = False) -> tuple:
    """One read, outcome recorded honestly. Returns (data_dict, outcome_record). A 403 becomes
    outcome 'forbidden' so the rulepack declines to assess (never 'pass') what the token could
    not read; a network error becomes 'error'. Vault wraps payloads under `data`; we unwrap it."""
    url = f"{base}/v1/{path}"
    params = {"list": "true"} if list_ else None
    try:
        r = client.get(url, headers=headers, params=params)
    except Exception as e:
        return {}, {"outcome": "error", "error": f"{type(e).__name__}: {e}"}
    if r.status_code in (403,):
        return {}, {"outcome": "forbidden", "error": "HTTP 403"}
    try:
        body = r.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        # health/seal-status answer non-200 (standby/sealed) but still return JSON; a truly
        # empty/……non-JSON body on a non-2xx is the honest error case.
        if r.status_code >= 400:
            return {}, {"outcome": "error", "error": f"HTTP {r.status_code}"}
        return {}, {"outcome": "ok", "error": None}
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    return data, {"outcome": "ok", "error": None}


def _list_map(client, base: str, path: str, headers: dict) -> tuple:
    """A sys/mounts | sys/auth | sys/audit style GET: the payload IS the map keyed by mount
    path. Returns (map, outcome)."""
    data, outcome = _endpoint(client, base, path, headers)
    return data, outcome


@connector("vault", fields=[
    ConnectorField("base_url", "Vault address", required=True,
                   placeholder="https://vault.example.com:8200",
                   help="Vault API address. Use https:// — an http:// address means the token "
                        "and every secret cross the network in plaintext. Read-only: only "
                        "sys/* metadata and policy/mount/auth config are ever fetched."),
    ConnectorField("token", "Vault token", required=True, secret=True,
                   help="A read-only token. A policy with read+list on sys/audit, sys/auth, "
                        "sys/mounts, sys/policies/acl and the auth role paths is sufficient. "
                        "The token value is used to authenticate and is NEVER stored."),
    ConnectorField("namespace", "Namespace", placeholder="admin",
                   help="Vault Enterprise namespace (X-Vault-Namespace). Leave empty for OSS."),
    ConnectorField("verify_tls", "Verify TLS", placeholder="true",
                   help="'false' to skip TLS verification for a self-signed dev Vault. "
                        "Leave true in production."),
])
def collect(config: dict) -> Collected:
    base = (config.get("base_url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("vault connector requires config['base_url']")
    token = (config.get("token") or "").strip()
    namespace = (config.get("namespace") or "").strip()
    timeout = float(config.get("timeout") or 15)
    verify = str(config.get("verify_tls", "true")).strip().lower() not in ("0", "false", "no", "off")

    headers = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    if namespace:
        headers["X-Vault-Namespace"] = namespace

    collection: dict = {}
    resources: list[Resource] = []
    edges: list[Edge] = []

    with httpx.Client(timeout=timeout, verify=verify, follow_redirects=True) as client:
        health, collection["sys/health"] = _endpoint(client, base, "sys/health", headers)
        seal, collection["sys/seal-status"] = _endpoint(client, base, "sys/seal-status", headers)
        token_info, collection["auth/token/lookup-self"] = _endpoint(
            client, base, "auth/token/lookup-self", headers)
        audit, collection["sys/audit"] = _list_map(client, base, "sys/audit", headers)
        auth_methods, collection["sys/auth"] = _list_map(client, base, "sys/auth", headers)
        mounts, collection["sys/mounts"] = _list_map(client, base, "sys/mounts", headers)

        server = parse_server(base, health=health, seal=seal, token=token_info, audit=audit,
                              collection=collection)
        resources.append(server)

        # ── secret-engine mounts ──
        for path, mount in (mounts or {}).items():
            if not (isinstance(mount, dict) and str(path).endswith("/")):
                continue
            m = parse_mount(path, mount)
            resources.append(m)
            edges.append(Edge(src_ext_id=server.ext_id, dst_ext_id=m.ext_id, kind="mounts"))

        # ── ACL policies ──
        policy_names, collection["sys/policies/acl"] = _endpoint(
            client, base, "sys/policies/acl", headers, list_=True)
        for name in (policy_names or {}).get("keys") or []:
            if name in ("root",):
                continue   # the implicit root policy cannot be read and needs no assessment
            data, _oc = _endpoint(client, base, f"sys/policies/acl/{name}", headers)
            rules = data.get("policy") if isinstance(data, dict) else None
            if rules is None and isinstance(data, dict):
                rules = data.get("rules")
            p = parse_policy(name, rules)
            resources.append(p)
            edges.append(Edge(src_ext_id=server.ext_id, dst_ext_id=p.ext_id, kind="defines"))

        # ── federation roles for the auth methods that carry bindings ──
        for apath, amethod in (auth_methods or {}).items():
            if not (isinstance(amethod, dict) and str(apath).endswith("/")):
                continue
            atype = amethod.get("type")
            if atype not in _FEDERATION_AUTH:
                continue
            role_names, roc = _endpoint(client, base, f"auth/{apath}role", headers, list_=True)
            if roc.get("outcome") != "ok":
                continue
            for rname in (role_names or {}).get("keys") or []:
                rdata, _rc = _endpoint(client, base, f"auth/{apath}role/{rname}", headers)
                role = parse_auth_role(apath, atype, rname, rdata)
                resources.append(role)
                edges.append(Edge(src_ext_id=server.ext_id, dst_ext_id=role.ext_id,
                                  kind="authenticates"))

    return Collected(resources=resources, edges=edges)


# ── NHI: federation roles → identity/credential/grant ─────────────────────────
@identity_extractor("vault")
def _from_vault(resources: list) -> tuple:
    """Vault's non-human identities in the normalized model:

      vault_auth_role  → identity (type "<auth>_role"); external for jwt/oidc (the subject is
                         minted by an outside IdP). An approle with bind_secret_id → a
                         credential (type secret_id, metadata only — Vault never showed a value).
      token_policies   → one grant per policy (action "policy", wildcard when the policy is
                         `root`). When a matching vault_policy was collected, the grant also
                         resolves to it with a grants_access edge.

    No unseal key, secret-id value, or token id is ever an NHI attribute — absence, not silence."""
    out: list[Resource] = []
    edges: list[Edge] = []
    policy_exts = {r.name: r.ext_id for r in resources if r.kind == "vault_policy"}

    for r in resources:
        if r.kind != "vault_auth_role":
            continue
        raw = r.raw or {}
        atype = raw.get("mount_type") or "auth"
        external = atype in ("jwt", "oidc")
        idr = _mk_identity("vault", f"{atype}_role", r.name, external=external,
                           source_ext=r.ext_id,
                           extra={"mount_path": raw.get("mount_path"), "auth_type": atype})
        out.append(idr)

        if atype == "approle" and raw.get("bind_secret_id"):
            cred = _mk_credential("vault", idr.ext_id, "secret_id",
                                  name=f"{r.name}:secret_id", hashing="n/a", present=True,
                                  plaintext=False)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        for pol in raw.get("token_policies") or []:
            g = _mk_grant("vault", idr.ext_id, "policy", pol, wildcard=(pol == "root"),
                          extra={"mount_type": atype})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
            if pol in policy_exts:
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=policy_exts[pol],
                                  kind="grants_access"))
    return out, edges
