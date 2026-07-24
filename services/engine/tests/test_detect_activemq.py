"""ActiveMQ (Classic + Artemis) connector parse-layer + detector + NHI tests. Fully offline: no
httpx client is constructed, no Jolokia agent is touched. Jolokia attribute values and the
broker configuration snippets live in the golden fixture, exactly as the connector consumes them."""
import json
import pathlib

from vectasec.contracts import ScanContext, Collected
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.activemq import (
    parse_version, openwire_rce_vulnerable, parse_activemq_xml, parse_jetty_realm,
    parse_classic_broker, parse_broker_xml, parse_login_config, parse_artemis_users,
    parse_artemis_roles, parse_artemis_broker, parse_destination,
)
from vectasec.detect import activemq as det

FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "activemq_responses.json").read_text())


def _ctx(resources, config=None):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources, config=config or {})


def classic(version_key="classic_jolokia_vuln", xml_key=None, realm_key=None, mbean=None):
    mv = mbean if mbean is not None else FIX[version_key]
    conns = mv.get("TransportConnectors") or {}
    xf = parse_activemq_xml(FIX.get(xml_key, "")) if xml_key else parse_activemq_xml("")
    rf = parse_jetty_realm(FIX.get(realm_key, "")) if realm_key else parse_jetty_realm("")
    return parse_classic_broker("localhost", "http://h:8161/api/jolokia", mv, conns, xf, rf)


def artemis(xml_key=None, login_key=None, users_key=None, roles_key="artemis_roles"):
    mv = FIX["artemis_jolokia"]
    bx = parse_broker_xml(FIX.get(xml_key, "")) if xml_key else parse_broker_xml("")
    lf = parse_login_config(FIX.get(login_key, "")) if login_key else parse_login_config("")
    uf = parse_artemis_users(FIX.get(users_key, "")) if users_key else parse_artemis_users("")
    roles = parse_artemis_roles(FIX.get(roles_key, "")) if roles_key else {}
    return parse_artemis_broker("0.0.0.0", "http://h:8161/console/jolokia", mv, bx, lf, uf, roles)


# ── registration + form fields ─────────────────────────────────────────────────
def test_connector_registered():
    assert "activemq" in CONNECTORS


def test_password_field_is_secret_and_flavor_required():
    fields = {f.key: f for f in CONNECTOR_FIELDS["activemq"]}
    assert fields["password"].secret is True
    assert not fields["jolokia_url"].secret and not fields["flavor"].secret
    assert fields["jolokia_url"].required and fields["flavor"].required


# ── version / CVE math ──────────────────────────────────────────────────────────
def test_parse_version_tolerates_qualifiers():
    assert parse_version("5.17.6") == (5, 17, 6)
    assert parse_version("5.18.3.redhat-00001") == (5, 18, 3)
    assert parse_version("6.0.0") == (6, 0, 0)
    assert parse_version("nope") is None


def test_openwire_cve_boundaries():
    assert openwire_rce_vulnerable("5.15.15") is True
    assert openwire_rce_vulnerable("5.15.16") is False
    assert openwire_rce_vulnerable("5.16.6") is True
    assert openwire_rce_vulnerable("5.16.7") is False
    assert openwire_rce_vulnerable("5.17.5") is True
    assert openwire_rce_vulnerable("5.17.6") is False
    assert openwire_rce_vulnerable("5.18.2") is True
    assert openwire_rce_vulnerable("5.18.3") is False
    assert openwire_rce_vulnerable("5.14.0") is True       # all pre-5.15 are affected
    assert openwire_rce_vulnerable("6.0.0") is False        # 6.x ships the fix
    assert openwire_rce_vulnerable("5.19.0") is None        # series the advisory doesn't enumerate
    assert openwire_rce_vulnerable("garbage") is None


# ── Classic parse layer ─────────────────────────────────────────────────────────
def test_parse_activemq_xml_insecure_vs_secure():
    ins = parse_activemq_xml(FIX["activemq_xml_insecure"])
    assert ins["readable"] and not ins["has_authentication_plugin"] and not ins["has_authorization_plugin"]
    sec = parse_activemq_xml(FIX["activemq_xml_secure"])
    assert sec["has_authentication_plugin"] and sec["authentication_plugin"] == "simple"
    assert sec["has_authorization_plugin"] and not sec["anonymous_access_allowed"]
    assert {u["username"] for u in sec["users"]} == {"admin", "app"}
    anon = parse_activemq_xml(FIX["activemq_xml_anonymous"])
    assert anon["anonymous_access_allowed"] is True
    assert anon["users"][0]["looks_default"] is True       # admin/admin
    assert parse_activemq_xml("<not-xml")["readable"] is False


def test_parse_jetty_realm():
    d = parse_jetty_realm(FIX["jetty_realm_default"])
    assert d["readable"] and d["has_default_admin"] is True
    c = parse_jetty_realm(FIX["jetty_realm_changed"])
    assert c["readable"] and c["has_default_admin"] is False
    assert parse_jetty_realm("")["readable"] is False


def test_parse_classic_broker_ssl_detection():
    assert classic("classic_jolokia_vuln").raw["has_ssl_connector"] is False
    assert classic("classic_jolokia_safe").raw["has_ssl_connector"] is True
    assert classic("classic_jolokia_vuln").raw["broker_version"] == "5.17.5"


# ── Classic detectors ───────────────────────────────────────────────────────────
def test_openwire_rce_fire_clean_notassessable():
    assert det.openwire_rce(classic("classic_jolokia_vuln"), _ctx([]))
    assert det.openwire_rce(classic("classic_jolokia_safe"), _ctx([])) == []
    na = det.openwire_rce(classic(mbean={}), _ctx([]))
    assert na and na[0].assessable is False and "CVE-2023-46604" in str(na[0].source_ref)


def test_classic_no_authentication_plugin():
    assert det.classic_no_authn(classic(xml_key="activemq_xml_insecure"), _ctx([]))
    assert det.classic_no_authn(classic(xml_key="activemq_xml_secure"), _ctx([])) == []
    na = det.classic_no_authn(classic(), _ctx([]))              # no activemq.xml supplied
    assert na and na[0].assessable is False


def test_classic_anonymous_access():
    assert det.classic_anonymous(classic(xml_key="activemq_xml_anonymous"), _ctx([]))
    assert det.classic_anonymous(classic(xml_key="activemq_xml_secure"), _ctx([])) == []
    assert det.classic_anonymous(classic(), _ctx([])) == []     # not readable → owned by NO_AUTHN


def test_classic_no_authorization_plugin():
    assert det.classic_no_authz(classic(xml_key="activemq_xml_insecure"), _ctx([]))
    assert det.classic_no_authz(classic(xml_key="activemq_xml_secure"), _ctx([])) == []
    assert det.classic_no_authz(classic(), _ctx([])) == []


def test_classic_default_console():
    assert det.classic_default_console(classic(realm_key="jetty_realm_default"), _ctx([]))
    assert det.classic_default_console(classic(realm_key="jetty_realm_changed"), _ctx([])) == []
    na = det.classic_default_console(classic(), _ctx([]))       # no realm supplied
    assert na and na[0].assessable is False


def test_classic_no_tls_connector():
    assert det.classic_no_tls(classic("classic_jolokia_vuln"), _ctx([]))
    assert det.classic_no_tls(classic("classic_jolokia_safe"), _ctx([])) == []
    na = det.classic_no_tls(classic(mbean={}), _ctx([]))        # no connectors readable
    assert na and na[0].assessable is False


# ── Artemis parse layer ─────────────────────────────────────────────────────────
def test_parse_broker_xml():
    ins = parse_broker_xml(FIX["broker_xml_insecure"])
    assert ins["readable"] and ins["security_enabled"] is False and ins["has_ssl_acceptor"] is False
    sec = parse_broker_xml(FIX["broker_xml_secure"])
    assert sec["security_enabled"] is True and sec["has_ssl_acceptor"] is True
    assert sec["acceptors"][0]["ssl_enabled"] is True
    assert parse_broker_xml("")["readable"] is False
    # security-enabled defaults to true when the element is absent
    assert parse_broker_xml("<configuration><core/></configuration>")["security_enabled"] is True


def test_parse_login_config_guest():
    g = parse_login_config(FIX["login_config_guest_admin"])
    assert g["guest_login_module"] is True and g["guest_role"] == "amq"
    n = parse_login_config(FIX["login_config_noguest"])
    assert n["readable"] and n["guest_login_module"] is False
    assert parse_login_config("")["readable"] is False


def test_parse_artemis_users_and_roles():
    d = parse_artemis_users(FIX["artemis_users_default"])
    users = {u["username"]: u for u in d["users"]}
    assert users["admin"]["plaintext"] is True and users["admin"]["looks_default"] is True
    assert users["app"]["hashing"] == "masked" and users["app"]["looks_default"] is False
    assert parse_artemis_roles(FIX["artemis_roles"]) == {"amq": ["admin"], "app": ["app"]}


# ── Artemis detectors ───────────────────────────────────────────────────────────
def test_artemis_security_disabled():
    assert det.artemis_security_disabled(artemis(xml_key="broker_xml_insecure"), _ctx([]))
    assert det.artemis_security_disabled(artemis(xml_key="broker_xml_secure"), _ctx([])) == []
    na = det.artemis_security_disabled(artemis(), _ctx([]))
    assert na and na[0].assessable is False


def test_artemis_guest_login_severity():
    hi = det.artemis_guest_login(artemis(login_key="login_config_guest_admin"), _ctx([]))
    assert hi and hi[0].severity == "critical"             # guest role is amq (admin-ish)
    lo = det.artemis_guest_login(artemis(login_key="login_config_guest_low"), _ctx([]))
    assert lo and lo[0].severity == "high"                 # guest role is guests
    assert det.artemis_guest_login(artemis(login_key="login_config_noguest"), _ctx([])) == []
    na = det.artemis_guest_login(artemis(), _ctx([]))       # no login.config supplied
    assert na and na[0].assessable is False


def test_artemis_default_user():
    assert det.artemis_default_user(artemis(users_key="artemis_users_default"), _ctx([]))
    assert det.artemis_default_user(artemis(users_key="artemis_users_masked"), _ctx([])) == []
    na = det.artemis_default_user(artemis(), _ctx([]))
    assert na and na[0].assessable is False


def test_artemis_no_tls_acceptor():
    assert det.artemis_no_tls(artemis(xml_key="broker_xml_insecure"), _ctx([]))
    assert det.artemis_no_tls(artemis(xml_key="broker_xml_secure"), _ctx([])) == []
    na = det.artemis_no_tls(artemis(), _ctx([]))            # no broker.xml supplied
    assert na and na[0].assessable is False


def test_openwire_cve_never_runs_on_artemis():
    # The CVE detector is registered for activemq_broker only — an Artemis broker of a "low"
    # version must not be flagged with the Classic OpenWire RCE.
    from vectasec.registry import DETECTORS
    cve = next(d for d in DETECTORS if d.rule_id == "ACTIVEMQ.OPENWIRE.RCE_CVE_2023_46604")
    assert cve.kinds == ("activemq_broker",) and "artemis_broker" not in cve.kinds


# ── destinations ─────────────────────────────────────────────────────────────
def test_parse_destination_distinct_ext_id():
    q = parse_destination("localhost", "classic", "APP.ORDERS", "queue")
    t = parse_destination("0.0.0.0", "artemis", "events", "topic")
    assert q.kind == "activemq_destination" and q.labels["destination_type"] == "queue"
    assert t.raw["broker_ext_id"] == "artemis-broker-0.0.0.0"
    assert q.ext_id != t.ext_id


# ── NHI ──────────────────────────────────────────────────────────────────────
def test_has_extractor():
    assert "activemq" in IDENTITY_EXTRACTORS


def test_nhi_classic_users_credentials_grants():
    broker = classic(xml_key="activemq_xml_secure")
    col = derive_identities("activemq", Collected(resources=[broker]))
    identities = {i.name: i for i in col.resources if i.kind == "identity"}
    assert identities["admin"].labels["identity_type"] == "admin"
    assert identities["app"].labels["identity_type"] == "service_account"
    creds = [c for c in col.resources if c.kind == "credential"]
    assert creds and all(c.raw["plaintext"] is False for c in creds)   # value never stored
    assert any(c.raw["hashing"] == "plaintext" for c in creds)          # but shape is recorded
    grants = {g.raw["target"] for g in col.resources if g.kind == "grant"}
    assert "group:admins" in grants and "group:app" in grants


def test_nhi_classic_default_password_flagged():
    broker = classic(xml_key="activemq_xml_anonymous")   # admin/admin
    col = derive_identities("activemq", Collected(resources=[broker]))
    admin_cred = next(c for c in col.resources if c.kind == "credential")
    assert admin_cred.raw["is_default"] is True


def test_nhi_artemis_roles_and_guest_identity():
    broker = artemis(xml_key="broker_xml_secure", login_key="login_config_guest_admin",
                     users_key="artemis_users_default")
    col = derive_identities("activemq", Collected(resources=[broker]))
    identities = {i.name: i for i in col.resources if i.kind == "identity"}
    assert identities["admin"].labels["identity_type"] == "admin"        # admin holds role amq
    assert identities["app"].labels["identity_type"] == "service_account"
    # role grants derived from artemis-roles.properties
    targets = {g.raw["target"] for g in col.resources if g.kind == "grant"}
    assert "role:amq" in targets and "role:app" in targets
    # the GuestLoginModule contributes an external anonymous identity with a wildcard grant
    guest = identities.get("guest:guest")
    assert guest and guest.labels["identity_type"] == "anonymous" and guest.labels["external"] == "true"
    assert any(g.raw["wildcard"] for g in col.resources
               if g.kind == "grant" and g.raw["identity_ext_id"] == guest.ext_id)


def test_nhi_artemis_credential_hashing_recorded():
    broker = artemis(users_key="artemis_users_default")
    col = derive_identities("activemq", Collected(resources=[broker]))
    creds = {c.name: c for c in col.resources if c.kind == "credential"}
    assert creds["admin:password"].raw["hashing"] == "plaintext"
    assert creds["admin:password"].raw["is_default"] is True
    assert creds["app:password"].raw["hashing"] == "masked"
