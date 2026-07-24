"""ActiveMQ connector — Classic and Artemis, read-only Jolokia + supplied configuration.

WHY ONE MODULE FOR BOTH. "ActiveMQ" is two brokers: Classic (the 5.x line, OpenWire-native,
activemq.xml) and Artemis (the next-gen broker, broker.xml + JAAS login.config). They are
operated together and share a threat model, so one connector covers both, selected by a `flavor`
field. They emit DISTINCT kinds — `activemq_broker` (Classic), `artemis_broker` (Artemis), and a
shared `activemq_destination` for queues/topics — so a Classic-only rule (the OpenWire RCE) never
runs against an Artemis broker, which is not affected by it.

HOW IT READS. Runtime facts come from Jolokia, the JMX-over-HTTP agent both brokers ship on the
web-console port (`:8161/api/jolokia` Classic, `:8161/console/jolokia` Artemis). Only `read` and
`search` are issued — never `exec` — so no operation mutates broker state. Version (the evidence
for CVE-2023-46604) and the transport connectors / acceptors come from JMX attributes.

The posture that lives in files — authentication plugins, the web-console realm, security-enabled,
the JAAS guest module, user/role tables — cannot be read over JMX. Those are supplied to the
connector as configuration text (`activemq_xml`, `jetty_realm`, `broker_xml`, `login_config`,
`artemis_users`, `artemis_roles`) and parsed by the pure functions below. When a config is not
supplied, the rule that needs it reports "not assessed" rather than passing silently.

CREDENTIALS NEVER LEAVE THIS MODULE. The Jolokia password authenticates to the agent and is never
copied into `raw`. User passwords found in supplied config are reduced to booleans (present /
plaintext-vs-masked / looks-default) exactly as the RabbitMQ connector reduces password hashes —
the value itself is dropped before anything reaches a resource.
"""
import re
import xml.etree.ElementTree as ET

import httpx

from ..registry import ConnectorField, connector
from ..contracts import Resource, Edge, Collected
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor

# Plaintext user passwords that are well-known defaults / trivially weak. Used only to flag a
# credential as "looks default"; the value is never stored.
WEAK_DEFAULT_PASSWORDS = {"admin", "password", "guest", "artemis", "manager", "user", "activemq"}


def _localname(tag: str) -> str:
    """Strip any XML namespace — Artemis broker.xml uses urn:activemq namespaces, Classic
    activemq.xml uses the Spring beans namespace; matching on local name works for both."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _iter(elem):
    for child in elem.iter():
        yield child


# ── version → CVE-2023-46604 (Classic OpenWire RCE, CISA-KEV) ───────────────────
# Verified against the Apache advisory (CVE-2023-46604-announcement.txt): the fix landed in
# 5.15.16, 5.16.7, 5.17.6, 5.18.3. Everything in 5.x below its series floor is affected; 6.0.0+
# ships the fix. Stored as the minimum PATCH that is safe for each 5.x series.
_OPENWIRE_FIXED = {15: 16, 16: 7, 17: 6, 18: 3}


def parse_version(v):
    try:
        parts = [int(x) for x in str(v).strip().split("-")[0].split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    except (ValueError, TypeError, AttributeError):
        return None


def openwire_rce_vulnerable(version):
    """True/False when determinable, None when the version can't be placed against the advisory."""
    parsed = parse_version(version)
    if parsed is None:
        return None
    major, minor, patch = parsed
    if major > 5:
        return False                      # 6.0.0+ ships the fix
    if major < 5:
        return None                       # pre-5.x is unmapped territory
    if minor < 15:
        return True                       # everything before the 5.15 line: "before 5.15.16"
    floor = _OPENWIRE_FIXED.get(minor)
    if floor is None:
        return None                       # a 5.x series the advisory doesn't enumerate
    return patch < floor


# ── Classic: activemq.xml + jetty-realm.properties ─────────────────────────────
def parse_activemq_xml(xml_text: str) -> dict:
    """Authentication/authorization posture from Classic's activemq.xml. Returns readable=False on
    unparseable input so the rules that depend on it become not-assessable, not clean passes."""
    facts = {
        "readable": False, "has_plugins": False,
        "authentication_plugin": None, "has_authentication_plugin": False,
        "has_authorization_plugin": False, "anonymous_access_allowed": False,
        "users": [], "authorization_entries": [],
    }
    if not xml_text or not str(xml_text).strip():
        return facts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return facts
    facts["readable"] = True
    for e in _iter(root):
        tag = _localname(e.tag)
        if tag == "plugins":
            facts["has_plugins"] = True
        elif tag == "simpleAuthenticationPlugin":
            facts["has_authentication_plugin"] = True
            facts["authentication_plugin"] = "simple"
            if str(e.attrib.get("anonymousAccessAllowed", "")).strip().lower() == "true":
                facts["anonymous_access_allowed"] = True
        elif tag == "jaasAuthenticationPlugin":
            facts["has_authentication_plugin"] = True
            facts["authentication_plugin"] = "jaas"
        elif tag == "authorizationPlugin":
            facts["has_authorization_plugin"] = True
        elif tag == "authenticationUser":
            uname = e.attrib.get("username") or ""
            pw = e.attrib.get("password") or ""
            facts["users"].append({
                "username": uname,
                "has_password": bool(pw),
                # inline XML passwords are plaintext unless masked with Jetty/Artemis ENC()
                "plaintext": bool(pw) and not pw.startswith("ENC("),
                "looks_default": bool(pw) and (pw == uname or pw.lower() in WEAK_DEFAULT_PASSWORDS),
                "groups": [g.strip() for g in (e.attrib.get("groups") or "").split(",") if g.strip()],
            })
        elif tag == "authorizationEntry":
            facts["authorization_entries"].append({
                "queue": e.attrib.get("queue"), "topic": e.attrib.get("topic"),
                "read": e.attrib.get("read"), "write": e.attrib.get("write"),
                "admin": e.attrib.get("admin"),
            })
    return facts


def parse_jetty_realm(props_text: str) -> dict:
    """conf/jetty-realm.properties — the web-console credential store. `admin: admin, ...` is the
    factory default. Passwords are read only to compute has_default_admin, then dropped."""
    facts = {"readable": False, "has_default_admin": False, "users": []}
    if not props_text or not str(props_text).strip():
        return facts
    facts["readable"] = True
    for line in str(props_text).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        user, rest = line.split(":", 1)
        user = user.strip()
        parts = [p.strip() for p in rest.split(",")]
        password = parts[0] if parts else ""
        roles = [p for p in parts[1:] if p]
        facts["users"].append({"username": user, "roles": roles})
        if user == "admin" and password == "admin":
            facts["has_default_admin"] = True
    return facts


def parse_classic_broker(broker_name: str, base_url: str, mbean_value: dict,
                         transport_connectors: dict, xml_facts: dict | None,
                         realm_facts: dict | None, *, errors: dict | None = None) -> Resource:
    mv = mbean_value or {}
    connectors = {k: str(v) for k, v in (transport_connectors or {}).items()}
    has_ssl = any(str(uri).strip().lower().startswith(("ssl:", "tls:", "https:"))
                  or "ssl://" in str(uri).lower() for uri in connectors.values())
    xf = xml_facts or {"readable": False}
    rf = realm_facts or {"readable": False}
    version = mv.get("BrokerVersion") or mv.get("brokerVersion")
    return Resource(
        kind="activemq_broker",
        name=broker_name,
        ext_id=f"activemq-broker-{broker_name}",
        labels={"flavor": "classic", "version": str(version or "?")},
        raw={
            "flavor": "classic",
            "broker_name": broker_name,
            "base_url": base_url,
            "broker_version": version,
            "transport_connectors": connectors,
            "has_ssl_connector": has_ssl,
            "connector_count": len(connectors),
            # activemq.xml-derived posture
            "xml_readable": xf.get("readable", False),
            "has_authentication_plugin": xf.get("has_authentication_plugin", False),
            "authentication_plugin": xf.get("authentication_plugin"),
            "has_authorization_plugin": xf.get("has_authorization_plugin", False),
            "anonymous_access_allowed": xf.get("anonymous_access_allowed", False),
            "auth_users": xf.get("users", []),
            "authorization_entries": xf.get("authorization_entries", []),
            # jetty-realm-derived posture
            "realm_readable": rf.get("readable", False),
            "realm_has_default_admin": rf.get("has_default_admin", False),
            "realm_users": rf.get("users", []),
            "errors": errors or {},
        },
    )


# ── Artemis: broker.xml + login.config + user/role properties ──────────────────
def parse_broker_xml(xml_text: str) -> dict:
    """Artemis broker.xml: security-enabled (default true) and acceptors with their TLS flag."""
    facts = {"readable": False, "security_enabled": True, "security_enabled_explicit": False,
             "acceptors": [], "has_ssl_acceptor": False, "security_settings": []}
    if not xml_text or not str(xml_text).strip():
        return facts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return facts
    facts["readable"] = True
    for e in _iter(root):
        tag = _localname(e.tag)
        if tag == "security-enabled":
            facts["security_enabled_explicit"] = True
            facts["security_enabled"] = str(e.text or "").strip().lower() != "false"
        elif tag == "acceptor":
            uri = (e.text or "").strip()
            ssl = bool(re.search(r"sslEnabled\s*=\s*true", uri, re.I))
            facts["acceptors"].append({"name": e.attrib.get("name") or "", "uri": uri,
                                       "ssl_enabled": ssl})
            if ssl:
                facts["has_ssl_acceptor"] = True
        elif tag == "security-setting":
            roles = set()
            for perm in e.iter():
                if _localname(perm.tag) == "permission":
                    for role in (perm.attrib.get("roles") or "").split(","):
                        if role.strip():
                            roles.add(role.strip())
            facts["security_settings"].append({"match": e.attrib.get("match"),
                                               "roles": sorted(roles)})
    return facts


def parse_login_config(text: str) -> dict:
    """Artemis JAAS login.config. The GuestLoginModule lets clients with no (or invalid)
    credentials in as a guest identity — its presence is the finding."""
    facts = {"readable": False, "guest_login_module": False, "property_login_module": False,
             "guest_user": None, "guest_role": None}
    if not text or not str(text).strip():
        return facts
    facts["readable"] = True
    if "GuestLoginModule" in text:
        facts["guest_login_module"] = True
        mu = re.search(r"org\.apache\.activemq\.jaas\.guest\.user\s*=\s*\"?([^\";\s]+)", text)
        mr = re.search(r"org\.apache\.activemq\.jaas\.guest\.role\s*=\s*\"?([^\";\s]+)", text)
        facts["guest_user"] = mu.group(1) if mu else "guest"     # module default
        facts["guest_role"] = mr.group(1) if mr else "guests"    # module default
    if "PropertiesLoginModule" in text:
        facts["property_login_module"] = True
    return facts


def _parse_properties(text: str) -> dict:
    out: dict = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def parse_artemis_users(props_text: str) -> dict:
    """artemis-users.properties: username = password (plaintext) or username = ENC(...) (masked).
    Values are reduced to plaintext?/looks-default? and then dropped."""
    facts = {"readable": False, "users": []}
    if not props_text or not str(props_text).strip():
        return facts
    facts["readable"] = True
    for user, pw in _parse_properties(props_text).items():
        masked = pw.startswith("ENC(")
        facts["users"].append({
            "username": user,
            "hashing": "masked" if masked else "plaintext",
            "plaintext": not masked,
            "looks_default": (not masked) and (pw == user or pw.lower() in WEAK_DEFAULT_PASSWORDS),
        })
    return facts


def parse_artemis_roles(props_text: str) -> dict:
    """artemis-roles.properties: role = user1,user2. Returns role -> [users] for NHI grants."""
    out: dict[str, list] = {}
    for role, users in _parse_properties(props_text).items():
        out[role] = [u.strip() for u in users.split(",") if u.strip()]
    return out


def parse_artemis_broker(broker_name: str, base_url: str, mbean_value: dict,
                         broker_xml_facts: dict | None, login_facts: dict | None,
                         users_facts: dict | None, roles: dict | None = None, *,
                         errors: dict | None = None) -> Resource:
    mv = mbean_value or {}
    bx = broker_xml_facts or {"readable": False}
    lf = login_facts or {"readable": False}
    uf = users_facts or {"readable": False}
    version = mv.get("Version") or mv.get("version")
    return Resource(
        kind="artemis_broker",
        name=broker_name,
        ext_id=f"artemis-broker-{broker_name}",
        labels={"flavor": "artemis", "version": str(version or "?")},
        raw={
            "flavor": "artemis",
            "broker_name": broker_name,
            "base_url": base_url,
            "broker_version": version,
            # broker.xml
            "broker_xml_readable": bx.get("readable", False),
            "security_enabled": bx.get("security_enabled", True),
            "security_enabled_explicit": bx.get("security_enabled_explicit", False),
            "acceptors": bx.get("acceptors", []),
            "has_ssl_acceptor": bx.get("has_ssl_acceptor", False),
            "security_settings": bx.get("security_settings", []),
            # login.config
            "login_config_readable": lf.get("readable", False),
            "guest_login_module": lf.get("guest_login_module", False),
            "guest_user": lf.get("guest_user"),
            "guest_role": lf.get("guest_role"),
            # users/roles
            "users_readable": uf.get("readable", False),
            "auth_users": uf.get("users", []),
            "roles": roles or {},
            "errors": errors or {},
        },
    )


def parse_destination(broker_name: str, flavor: str, dest_name: str, dtype: str) -> Resource:
    dtype = (dtype or "queue").lower()
    return Resource(
        kind="activemq_destination",
        name=dest_name,
        ext_id=f"{flavor}-dest-{broker_name}-{dtype}-{dest_name}",
        namespace=broker_name,
        labels={"flavor": flavor, "destination_type": dtype},
        raw={"flavor": flavor, "broker_name": broker_name, "destination_name": dest_name,
             "destination_type": dtype,
             "broker_ext_id": f"{'artemis' if flavor == 'artemis' else 'activemq'}-broker-{broker_name}"},
    )


# ── Jolokia HTTP (kept out of the tested parse layer) ──────────────────────────
def _jolokia(client: httpx.Client, path: str, body: dict) -> dict:
    try:
        r = client.post(path, json=body)
    except httpx.HTTPError as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "error": f"http_{r.status_code}"}
    try:
        data = r.json()
    except ValueError:
        return {"ok": False, "error": "non_json_body"}
    if data.get("status") != 200:
        return {"ok": False, "status": data.get("status"), "error": data.get("error")}
    return {"ok": True, "value": data.get("value")}


@connector("activemq", fields=[
    ConnectorField("jolokia_url", "Jolokia URL", required=True,
                   placeholder="http://localhost:8161/api/jolokia",
                   help="Base Jolokia endpoint. Read-only: only JMX read/search are issued."),
    ConnectorField("username", "Console user", required=True, placeholder="admin",
                   help="Jolokia/console user. read-only JMX is enough."),
    ConnectorField("password", "Password", required=True, secret=True),
    ConnectorField("flavor", "Flavor", required=True, placeholder="classic",
                   help="'classic' for ActiveMQ 5.x, 'artemis' for ActiveMQ Artemis."),
])
def collect(config: dict) -> Collected:
    base = (config.get("jolokia_url") or "").rstrip("/")
    if not base:
        raise SystemExit("activemq connector requires config['jolokia_url']")
    flavor = (config.get("flavor") or "classic").strip().lower()
    if flavor not in ("classic", "artemis"):
        raise SystemExit("activemq connector: flavor must be 'classic' or 'artemis'")
    auth = (config.get("username") or "", config.get("password") or "")
    verify = config.get("verify_tls", True)
    timeout = float(config.get("timeout") or 15)
    errors: dict = {}

    with httpx.Client(base_url=base, timeout=timeout, verify=bool(verify),
                      follow_redirects=False, auth=auth) as client:
        if flavor == "classic":
            search = _jolokia(client, "/", {"type": "search",
                                            "mbean": "org.apache.activemq:type=Broker,brokerName=*"})
            mbean = (search.get("value") or [None])[0] if search.get("ok") else None
            if not search.get("ok"):
                errors["search"] = search.get("error")
            broker_name = "localhost"
            mbean_value, connectors = {}, {}
            if mbean:
                m = re.search(r"brokerName=([^,]+)", mbean)
                broker_name = m.group(1) if m else broker_name
                read = _jolokia(client, "/", {"type": "read", "mbean": mbean,
                                              "attribute": ["BrokerVersion", "TransportConnectors"]})
                if read.get("ok"):
                    mbean_value = read.get("value") or {}
                    connectors = mbean_value.get("TransportConnectors") or {}
                else:
                    errors["read"] = read.get("error")
        else:
            search = _jolokia(client, "/", {"type": "search",
                                            "mbean": "org.apache.activemq.artemis:broker=*"})
            mbean = None
            for cand in (search.get("value") or []) if search.get("ok") else []:
                if "component=" not in cand:      # the bare broker mbean, not a sub-component
                    mbean = cand
                    break
            if not search.get("ok"):
                errors["search"] = search.get("error")
            broker_name = "0.0.0.0"
            mbean_value = {}
            if mbean:
                m = re.search(r'broker="?([^",]+)"?', mbean)
                broker_name = m.group(1) if m else broker_name
                read = _jolokia(client, "/", {"type": "read", "mbean": mbean, "attribute": "Version"})
                if read.get("ok"):
                    mbean_value = {"Version": read.get("value")}
                else:
                    errors["read"] = read.get("error")

    resources: list = []
    edges: list = []

    if flavor == "classic":
        xml_facts = parse_activemq_xml(config.get("activemq_xml") or "")
        realm_facts = parse_jetty_realm(config.get("jetty_realm") or "")
        broker = parse_classic_broker(broker_name, base, mbean_value, connectors,
                                      xml_facts, realm_facts, errors=errors)
    else:
        bx = parse_broker_xml(config.get("broker_xml") or "")
        lf = parse_login_config(config.get("login_config") or "")
        uf = parse_artemis_users(config.get("artemis_users") or "")
        roles = parse_artemis_roles(config.get("artemis_roles") or "")
        broker = parse_artemis_broker(broker_name, base, mbean_value, bx, lf, uf, roles,
                                      errors=errors)
    resources.append(broker)

    return Collected(resources=resources, edges=edges)


# ── NHI: broker users/roles → identity / credential / grant ────────────────────
@identity_extractor("activemq")
def _from_activemq(resources: list) -> tuple:
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        raw = r.raw or {}
        if r.kind == "activemq_broker":
            # Classic: users declared in simpleAuthenticationPlugin, groups are their grants.
            for u in raw.get("auth_users") or []:
                name = u.get("username") or ""
                if not name:
                    continue
                itype = "admin" if any(g.lower() in ("admins", "admin") for g in u.get("groups") or []) \
                    else "service_account"
                idr = _mk_identity("activemq", itype, name, source_ext=r.ext_id)
                out.append(idr)
                if u.get("has_password"):
                    cred = _mk_credential(
                        "activemq", idr.ext_id, "password", name=f"{name}:password",
                        hashing="plaintext" if u.get("plaintext") else "masked",
                        is_default=bool(u.get("looks_default")), present=True, plaintext=False)
                    out.append(cred)
                    edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id,
                                      kind="credential_of"))
                for grp in u.get("groups") or []:
                    g = _mk_grant("activemq", idr.ext_id, "group-member", f"group:{grp}",
                                  wildcard=(grp == ">" or grp == "*"))
                    out.append(g)
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))

        elif r.kind == "artemis_broker":
            roles = raw.get("roles") or {}
            user_roles: dict[str, list] = {}
            for role, members in roles.items():
                for m in members:
                    user_roles.setdefault(m, []).append(role)
            for u in raw.get("auth_users") or []:
                name = u.get("username") or ""
                if not name:
                    continue
                urs = user_roles.get(name, [])
                itype = "admin" if any(x.lower() in ("admin", "amq", "admins") for x in urs) \
                    else "service_account"
                idr = _mk_identity("artemis", itype, name, source_ext=r.ext_id)
                out.append(idr)
                cred = _mk_credential(
                    "artemis", idr.ext_id, "password", name=f"{name}:password",
                    hashing=u.get("hashing") or "unknown",
                    is_default=bool(u.get("looks_default")), present=True, plaintext=False)
                out.append(cred)
                edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
                for role in urs:
                    g = _mk_grant("artemis", idr.ext_id, "role", f"role:{role}")
                    out.append(g)
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
            # GuestLoginModule contributes an anonymous, external guest identity.
            if raw.get("guest_login_module"):
                guest = raw.get("guest_user") or "guest"
                idr = _mk_identity("artemis", "anonymous", f"guest:{guest}", external=True,
                                   source_ext=r.ext_id, extra={"guest_role": raw.get("guest_role")})
                out.append(idr)
                g = _mk_grant("artemis", idr.ext_id, "role", f"role:{raw.get('guest_role') or 'guests'}",
                              wildcard=True)
                out.append(g)
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))

    return out, edges
