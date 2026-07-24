"""Airflow rulepack + parse-layer + NHI tests. Offline: no httpx, no live Airflow.

The pure parse layers (parse_version/parse_config/parse_connection/parse_dag_details/parse_users)
are exercised against the golden Airflow REST fixture; detectors run against resources built from
those same parse layers; and the in-file NHI extractor is exercised end-to-end. Every rule gets
fire / does-not-fire / not-assessable, and the version→CVE rule pins the honest boundary behaviour.
"""
import json
import pathlib

from vectasec.contracts import Resource, ScanContext
from vectasec.contracts import Collected
from vectasec.registry import DETECTORS
from vectasec.identity import derive_identities
from vectasec.connect import airflow as c
from vectasec.detect import airflow as a

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "airflow_responses.json").read_text())

BASE = "https://airflow.example.com"
API = f"{BASE}/api/v1"
INST_EXT = f"airflow-{BASE}"

EXPECTED_RULES = {
    "AIRFLOW.AUTH.ANONYMOUS_ACCESS", "AIRFLOW.CONFIG.EXPOSE_CONFIG",
    "AIRFLOW.CONFIG.TEST_CONNECTION_ENABLED", "AIRFLOW.TRANSPORT.NO_TLS",
    "AIRFLOW.AUTH.DEFAULT_ADMIN_USER", "AIRFLOW.DAG.SECRET_IN_PARAMS",
    "AIRFLOW.CONNECTION.STORED_SECRET", "AIRFLOW.VERSION.KNOWN_CVE",
}


def ctx():
    return ScanContext(connection_id="c", tenant_id="t", resources=[], config={})


def instance(**over) -> Resource:
    """A hardened instance: authenticated only, expose_config off, users readable with no default
    admin, https, recent version. Tests override into findings."""
    raw = {
        "base_url": BASE, "api_base": API, "host": "airflow.example.com", "scheme": "https",
        "version": "2.6.3", "git_version": None, "version_status": 200, "version_error": None,
        "config": {"readable": False, "expose_config_on": False, "status": 403,
                   "test_connection": None, "sections_present": None},
        "unauth_probe": {"status": 403, "error": None, "anonymous_access": False},
        "users_readable": True, "users_status": 200,
        "users": [{"username": "svc_reporting", "active": True, "roles": ["Viewer"]}],
        "connection_count": 0, "dag_count": 0, "authenticated_scan": True,
    }
    raw.update(over)
    return Resource(kind="airflow_instance", name="af", ext_id=INST_EXT, raw=raw)


def dag(**over) -> Resource:
    raw = {"dag_id": "safe_dag", "is_paused": True, "tags": [], "owners": ["data"],
           "param_keys": ["lookback_days"], "secret_param_keys": [], "instance_ext_id": INST_EXT}
    raw.update(over)
    return Resource(kind="airflow_dag", name=raw["dag_id"], ext_id=f"airflow-dag-{raw['dag_id']}",
                    raw=raw)


def conn(**over) -> Resource:
    raw = {"connection_id": "s3_readonly", "conn_type": "aws", "host": None, "login": "AKIA",
           "has_password": False, "password_key_present": True, "extra_keys": ["region_name"],
           "secret_extra_keys": [], "instance_ext_id": INST_EXT}
    raw.update(over)
    return Resource(kind="airflow_connection", name=raw["connection_id"],
                    ext_id=f"airflow-conn-{raw['connection_id']}", raw=raw)


# ── parse layers against the golden fixture ────────────────────────────────
def test_parse_version():
    assert c.parse_version(FIX["version"])["version"] == "2.6.3"
    assert c.parse_version(None)["version"] is None


def test_parse_config_exposed():
    cfg = c.parse_config(200, FIX["config_exposed"])
    assert cfg["readable"] is True and cfg["expose_config_on"] is True
    assert cfg["test_connection"] == "Enabled"


def test_parse_config_hidden_is_good():
    cfg = c.parse_config(403, None)
    assert cfg["readable"] is False and cfg["expose_config_on"] is False


def test_parse_config_unknown():
    assert c.parse_config(500, None)["readable"] is None


def test_parse_connections_secret_key_detection():
    parsed = [c.parse_connection(x) for x in FIX["connections"]["connections"]]
    by_id = {p["connection_id"]: p for p in parsed}
    assert by_id["postgres_default"]["has_password"] is True
    assert by_id["slack_alerts"]["secret_extra_keys"] == ["webhook_token"]
    assert by_id["s3_readonly"]["has_password"] is False
    assert by_id["s3_readonly"]["secret_extra_keys"] == []   # login/region are not secrets


def test_parse_dag_details_secret_params():
    etl = c.parse_dag_details(FIX["dag_details_etl"])
    assert sorted(etl["secret_param_keys"]) == ["api_token", "db_password"]
    safe = c.parse_dag_details(FIX["dag_details_safe"])
    assert safe["secret_param_keys"] == []


def test_parse_users():
    users = c.parse_users(FIX["users"])
    assert {u["username"] for u in users} == {"admin", "svc_reporting"}
    admin = next(u for u in users if u["username"] == "admin")
    assert admin["roles"] == ["Admin"]


def test_looks_secret_narrow():
    assert c._looks_secret("db_password") and c._looks_secret("api_token")
    assert c._looks_secret("public_key_id") is False   # bare 'key' is not flagged
    assert c._looks_secret("lookback_days") is False


# ── registration ───────────────────────────────────────────────────────────
def test_rules_registered_once():
    got = [x.rule_id for x in DETECTORS if x.rule_id.startswith("AIRFLOW.")]
    assert sorted(got) == sorted(EXPECTED_RULES)
    for x in DETECTORS:
        if x.rule_id.startswith("AIRFLOW."):
            assert x.severity in ("info", "low", "medium", "high", "critical")
            assert x.kinds in (("airflow_instance",), ("airflow_dag",), ("airflow_connection",))


# ── anonymous access ───────────────────────────────────────────────────────
def test_anonymous_access_fires():
    r = instance(unauth_probe={"status": 200, "error": None, "anonymous_access": True})
    hits = a.anonymous_access(r, ctx())
    assert hits and hits[0].assessable and hits[0].severity is None


def test_anonymous_access_clean():
    assert a.anonymous_access(instance(), ctx()) == []


def test_anonymous_access_not_assessable():
    r = instance(unauth_probe={"status": None, "error": "ConnectTimeout", "anonymous_access": False})
    hits = a.anonymous_access(r, ctx())
    assert hits and hits[0].assessable is False


# ── expose_config ──────────────────────────────────────────────────────────
def test_expose_config_fires():
    r = instance(config={"readable": True, "expose_config_on": True, "status": 200,
                         "test_connection": "Disabled", "sections_present": 2})
    assert a.expose_config(r, ctx())


def test_expose_config_clean_when_hidden():
    assert a.expose_config(instance(), ctx()) == []


def test_expose_config_not_assessable():
    r = instance(config={"readable": None, "expose_config_on": None, "status": 500,
                         "test_connection": None, "sections_present": None})
    hits = a.expose_config(r, ctx())
    assert hits and hits[0].assessable is False


# ── test_connection ────────────────────────────────────────────────────────
def test_test_connection_enabled_fires():
    r = instance(config={"readable": True, "expose_config_on": True, "status": 200,
                         "test_connection": "Enabled", "sections_present": 2})
    assert a.test_connection_enabled(r, ctx())


def test_test_connection_clean_when_disabled():
    r = instance(config={"readable": True, "expose_config_on": True, "status": 200,
                         "test_connection": "Disabled", "sections_present": 2})
    assert a.test_connection_enabled(r, ctx()) == []


def test_test_connection_not_assessable_when_config_unreadable():
    hits = a.test_connection_enabled(instance(), ctx())   # config 403 (not readable)
    assert hits and hits[0].assessable is False


# ── TLS ────────────────────────────────────────────────────────────────────
def test_no_tls_fires():
    r = instance(scheme="http", host="airflow.example.com")
    assert a.no_tls(r, ctx())


def test_no_tls_clean_https():
    assert a.no_tls(instance(), ctx()) == []


def test_no_tls_clean_localhost():
    assert a.no_tls(instance(scheme="http", host="localhost"), ctx()) == []


# ── default admin ──────────────────────────────────────────────────────────
def test_default_admin_fires():
    r = instance(users=[{"username": "admin", "active": True, "roles": ["Admin"]}])
    assert a.default_admin_user(r, ctx())


def test_default_admin_clean_without_default():
    assert a.default_admin_user(instance(), ctx()) == []


def test_default_admin_not_assessable_when_users_unreadable():
    r = instance(users_readable=False, users_status=403, users=[])
    hits = a.default_admin_user(r, ctx())
    assert hits and hits[0].assessable is False


# ── DAG secret params ──────────────────────────────────────────────────────
def test_dag_secret_in_params_fires():
    r = dag(dag_id="etl_pipeline", secret_param_keys=["db_password", "api_token"],
            param_keys=["target_date", "db_password", "api_token"])
    assert a.dag_secret_in_params(r, ctx())


def test_dag_secret_in_params_clean():
    assert a.dag_secret_in_params(dag(), ctx()) == []


# ── connection stored secret ───────────────────────────────────────────────
def test_connection_stored_secret_fires_on_password():
    r = conn(connection_id="postgres_default", conn_type="postgres", has_password=True)
    assert a.connection_stored_secret(r, ctx())


def test_connection_stored_secret_fires_on_extra_key():
    r = conn(connection_id="slack_alerts", conn_type="slack",
             secret_extra_keys=["webhook_token"], extra_keys=["webhook_token", "timeout"])
    assert a.connection_stored_secret(r, ctx())


def test_connection_stored_secret_clean():
    assert a.connection_stored_secret(conn(), ctx()) == []


# ── version → CVE ──────────────────────────────────────────────────────────
def test_version_cve_fires_below_boundary():
    hits = a.version_known_cve(instance(version="1.10.12"), ctx())
    assert hits and hits[0].assessable
    assert hits[0].source_ref.get("cve") == "CVE-2020-17526"


def test_version_cve_not_assessable_in_disputed_band():
    hits = a.version_known_cve(instance(version="1.10.15"), ctx())
    assert hits and hits[0].assessable is False


def test_version_cve_clean_on_recent():
    assert a.version_known_cve(instance(version="2.6.3"), ctx()) == []


def test_version_cve_not_assessable_on_garbage():
    hits = a.version_known_cve(instance(version="not-a-version"), ctx())
    assert hits and hits[0].assessable is False


# ── NHI extractor ──────────────────────────────────────────────────────────
def _nhi(resources):
    collected = Collected(resources=list(resources), edges=[])
    derived = derive_identities("airflow", collected)
    return derived.resources, derived.edges


def test_nhi_user_becomes_identity_with_role_grant():
    inst = instance(users=[{"username": "admin", "active": True, "roles": ["Admin"]},
                           {"username": "svc_reporting", "active": True, "roles": ["Viewer"]}])
    resources, edges = _nhi([inst])
    ids = {r.name: r for r in resources if r.kind == "identity"}
    assert ids["admin"].labels["identity_type"] == "admin"
    assert ids["svc_reporting"].labels["identity_type"] == "service_account"
    # a password credential exists for each user (present only, no value)
    creds = [r for r in resources if r.kind == "credential" and r.raw.get("credential_type") == "password"]
    assert len(creds) == 2 and all(cr.raw["plaintext"] is False for cr in creds)
    # Admin role grant is wildcard
    admin_grants = [r for r in resources if r.kind == "grant"
                    and r.raw["identity_ext_id"] == ids["admin"].ext_id]
    assert any(gr.raw["wildcard"] for gr in admin_grants)


def test_nhi_connection_becomes_external_identity_with_credential():
    conn_pg = conn(connection_id="postgres_default", conn_type="postgres",
                   host="db.internal", has_password=True)
    resources, edges = _nhi([conn_pg])
    idr = next(r for r in resources if r.kind == "identity")
    assert idr.labels["external"] == "true"
    assert idr.raw["conn_type"] == "postgres"
    cred = next(r for r in resources if r.kind == "credential")
    assert cred.raw["credential_type"] == "connection_secret" and cred.raw["plaintext"] is False
    grant = next(r for r in resources if r.kind == "grant")
    assert grant.raw["action"] == "connect" and "db.internal" in grant.raw["target"]


def test_nhi_connection_without_secret_emits_no_credential():
    resources, _ = _nhi([conn()])   # s3_readonly: no password, no secret extra keys
    assert not [r for r in resources if r.kind == "credential"]
    assert [r for r in resources if r.kind == "identity"]


# ── robustness ─────────────────────────────────────────────────────────────
def test_no_detector_raises_on_degraded_instance():
    r = Resource(kind="airflow_instance", name="x", ext_id=INST_EXT, raw={
        "base_url": BASE, "api_base": API, "scheme": "https", "version": None,
        "config": {"readable": None, "status": None}, "unauth_probe": {"status": None},
        "users_readable": False, "users_status": None, "users": []})
    for x in DETECTORS:
        if x.rule_id.startswith("AIRFLOW.") and x.kinds == ("airflow_instance",):
            x.fn(r, ctx())
