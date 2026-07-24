"""Airflow rulepack — detectors over what connect/airflow.py read from the Airflow REST API.

Runs on the DISTINCT airflow_instance / airflow_dag / airflow_connection kinds. Every observation
states a value read from the API. The version→CVE rule asserts only the one boundary the public
advisories agree on (CVE-2020-17526, "prior to 1.10.14" per NVD); the range where sources disagree
on the fixed version is reported as not-assessable rather than asserted, and unknown versions are a
coverage gap, never a clean pass.
"""
from ..registry import detector
from ..contracts import Hit


def _parse_version(v):
    try:
        parts = [int(x) for x in str(v).split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    except (ValueError, TypeError):
        return None


@detector(kinds=["airflow_instance"], rule_id="AIRFLOW.AUTH.ANONYMOUS_ACCESS", severity="critical",
          title="Airflow API is reachable without authentication")
def anonymous_access(r, ctx) -> list:
    raw = r.raw or {}
    probe = raw.get("unauth_probe") or {}
    if probe.get("status") is None:
        return [Hit(
            observation=f"unauthenticated reachability probe of {raw.get('api_base')}/dags did not "
                        f"complete (error: {probe.get('error')})",
            remediation="Confirm the Airflow webserver is reachable from the scanner and re-run.",
            detail="unauth probe did not complete",
            assessable=False,
            assessment_reason="unauthenticated probe did not return a status",
            source_ref={"api": f"GET {raw.get('api_base')}/dags"},
        )]
    if not probe.get("anonymous_access"):
        return []
    return [Hit(
        observation=f"Airflow API at {raw.get('api_base')}/dags answered HTTP 200 with NO "
                    f"credentials — the webserver accepts anonymous access",
        remediation="Set an auth backend that requires authentication (e.g. "
                    "auth_backends = airflow.api.auth.backend.session) and ensure "
                    "AUTH_ROLE_PUBLIC is not Admin/User in webserver_config.py. An unauthenticated "
                    "Airflow is full control of every DAG and Connection to anyone who can reach it.",
        detail=f"unauth_status={probe.get('status')}",
        source_ref={"api": f"GET {raw.get('api_base')}/dags (no auth)"},
    )]


@detector(kinds=["airflow_instance"], rule_id="AIRFLOW.CONFIG.EXPOSE_CONFIG", severity="high",
          title="Airflow exposes its configuration over the API")
def expose_config(r, ctx) -> list:
    raw = r.raw or {}
    cfg = raw.get("config") or {}
    if cfg.get("readable") is None:
        return [Hit(
            observation=f"Airflow {raw.get('api_base')}/config returned status {cfg.get('status')}; "
                        f"expose_config state could not be determined",
            remediation="Re-run with sufficient permissions to read /config, or verify "
                        "expose_config directly.",
            detail=f"config_status={cfg.get('status')}",
            assessable=False,
            assessment_reason="/config was neither 200 (exposed) nor 403 (hidden)",
            source_ref={"api": f"GET {raw.get('api_base')}/config"},
        )]
    if not cfg.get("expose_config_on"):
        return []
    return [Hit(
        observation=f"Airflow {raw.get('api_base')}/config returned HTTP 200 with "
                    f"{cfg.get('sections_present')} config section(s) — expose_config is enabled",
        remediation="Set expose_config = False (or 'non-sensitive-only') in [webserver]. An exposed "
                    "config leaks the fernet key, secret_key, backend connection strings, and other "
                    "sensitive settings to any authorized API caller.",
        detail=f"expose_config_on=True sections={cfg.get('sections_present')}",
        source_ref={"api": f"GET {raw.get('api_base')}/config", "config": "webserver.expose_config"},
    )]


@detector(kinds=["airflow_instance"], rule_id="AIRFLOW.CONFIG.TEST_CONNECTION_ENABLED", severity="medium",
          title="Airflow connection testing is enabled")
def test_connection_enabled(r, ctx) -> list:
    raw = r.raw or {}
    cfg = raw.get("config") or {}
    if not cfg.get("readable"):
        return [Hit(
            observation=f"Airflow test_connection setting could not be read (config not readable; "
                        f"status {cfg.get('status')})",
            remediation="Confirm core.test_connection is Disabled (the default since Airflow 2.7).",
            detail="config not readable",
            assessable=False,
            assessment_reason="config was not readable, so test_connection could not be determined",
            source_ref={"api": f"GET {raw.get('api_base')}/config"},
        )]
    val = str(cfg.get("test_connection") or "").strip().lower()
    if val in ("", "disabled"):
        return []
    return [Hit(
        observation=f"Airflow core.test_connection is set to {cfg.get('test_connection')!r} "
                    f"(not Disabled)",
        remediation="Set core.test_connection = Disabled (the secure default since Airflow 2.7). "
                    "The Test Connection feature can be abused for SSRF against internal services; "
                    "enable it only when edit-connection permission is tightly held.",
        detail=f"test_connection={cfg.get('test_connection')}",
        source_ref={"api": f"GET {raw.get('api_base')}/config", "config": "core.test_connection"},
    )]


@detector(kinds=["airflow_instance"], rule_id="AIRFLOW.TRANSPORT.NO_TLS", severity="medium",
          title="Airflow webserver is served over plaintext HTTP")
def no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if (raw.get("scheme") or "").lower() != "http":
        return []
    if (raw.get("host") or "") in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return []
    return [Hit(
        observation=f"Airflow base URL {raw.get('base_url')} uses plaintext http://",
        remediation="Serve Airflow over HTTPS (terminate TLS at the webserver or a proxy) and "
                    "redirect http to https. Over plaintext, session cookies and API credentials "
                    "cross the network in the clear.",
        detail=f"scheme=http host={raw.get('host')}",
        source_ref={"base_url": raw.get("base_url")},
    )]


@detector(kinds=["airflow_instance"], rule_id="AIRFLOW.AUTH.DEFAULT_ADMIN_USER", severity="medium",
          title="Airflow has a default 'admin' administrator account")
def default_admin_user(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("users_readable"):
        return [Hit(
            observation=f"Airflow user list was not readable (status {raw.get('users_status')}), so "
                        f"the presence of a default 'admin' account could not be assessed",
            remediation="Grant the scanner permission to read /users, or verify manually that no "
                        "default admin/admin account exists.",
            detail=f"users_status={raw.get('users_status')}",
            assessable=False,
            assessment_reason="/users was not readable",
            source_ref={"api": f"GET {raw.get('api_base')}/users"},
        )]
    admins = [u for u in (raw.get("users") or [])
              if u.get("username") == "admin" and "Admin" in (u.get("roles") or [])]
    if not admins:
        return []
    return [Hit(
        observation=f"Airflow has a user named 'admin' holding the Admin role "
                    f"(active={admins[0].get('active')})",
        remediation="Rename or remove the default admin account and ensure its password was changed "
                    "from any install default. This scan cannot read the password hash, so it can "
                    "only flag that the default-named admin account exists.",
        detail="username=admin role=Admin",
        source_ref={"api": f"GET {raw.get('api_base')}/users", "username": "admin"},
    )]


@detector(kinds=["airflow_dag"], rule_id="AIRFLOW.DAG.SECRET_IN_PARAMS", severity="high",
          title="Airflow DAG carries a secret-shaped parameter")
def dag_secret_in_params(r, ctx) -> list:
    raw = r.raw or {}
    secret_keys = raw.get("secret_param_keys") or []
    if not secret_keys:
        return []
    return [Hit(
        observation=f"Airflow DAG {raw.get('dag_id')!r} declares param key(s) whose names indicate "
                    f"a stored secret: {', '.join(secret_keys)}",
        remediation="Move secrets out of DAG params into a Secrets Backend (Vault, AWS/GCP secret "
                    "manager) or an Airflow Connection/Variable marked sensitive, and reference "
                    "them at runtime. Params are visible in the UI and API to anyone who can read "
                    "the DAG. (Flagged by key name only — the values were never read.)",
        detail=f"secret_param_keys={secret_keys}",
        source_ref={"api": f"GET .../dags/{raw.get('dag_id')}/details", "field": "params"},
    )]


@detector(kinds=["airflow_connection"], rule_id="AIRFLOW.CONNECTION.STORED_SECRET", severity="medium",
          title="Airflow Connection stores a credential")
def connection_stored_secret(r, ctx) -> list:
    raw = r.raw or {}
    has_pw = raw.get("has_password")
    secret_extra = raw.get("secret_extra_keys") or []
    if not (has_pw or secret_extra):
        return []
    where = []
    if has_pw:
        where.append("password field")
    if secret_extra:
        where.append(f"extra key(s) {', '.join(secret_extra)}")
    return [Hit(
        observation=f"Airflow Connection {raw.get('connection_id')!r} (type "
                    f"{raw.get('conn_type')}) stores a credential in its {', '.join(where)}",
        remediation="Store connection secrets in a Secrets Backend rather than the Airflow metadata "
                    "DB, and ensure the fernet key is set and rotated. This is a metadata-DB-stored "
                    "credential; the scan records only that a secret is present, never its value.",
        detail=f"has_password={bool(has_pw)} secret_extra_keys={secret_extra}",
        source_ref={"api": ".../connections", "connection_id": raw.get("connection_id")},
    )]


# CVE-2020-17526: incorrect session validation from a shared default [webserver] secret_key.
# NVD boundary: "prior to 1.10.14". Public sources disagree on whether the fix first shipped in
# 1.10.14 vs 1.10.15/2.0.2, so we ASSERT only for < 1.10.14 and report the disputed band as a gap.
_CVE_17526_ASSERT_BELOW = (1, 10, 14)
_CVE_17526_FIXED_CLEAR = (2, 0, 2)


@detector(kinds=["airflow_instance"], rule_id="AIRFLOW.VERSION.KNOWN_CVE", severity="high",
          title="Airflow version is affected by a known CVE")
def version_known_cve(r, ctx) -> list:
    raw = r.raw or {}
    version = raw.get("version")
    parsed = _parse_version(version)
    if parsed is None:
        return [Hit(
            observation=f"Airflow reported version {version!r}, which could not be parsed to a "
                        f"comparable release, so known-CVE exposure was not determined",
            remediation="Confirm the running Airflow version and compare it against the Apache "
                        "Airflow security advisories.",
            detail=f"version={version}",
            assessable=False,
            assessment_reason="version string not parseable",
            source_ref={"api": f"GET {raw.get('api_base')}/version"},
        )]
    if parsed < _CVE_17526_ASSERT_BELOW:
        return [Hit(
            observation=f"Airflow version {version} is before 1.10.14, the NVD-stated fix boundary "
                        f"for CVE-2020-17526 (incorrect session validation from a default "
                        f"[webserver] secret_key)",
            remediation="Upgrade to a supported release (>= 2.0.2) and set a unique [webserver] "
                        "secret_key. The default shared key lets a valid session on one Airflow "
                        "authenticate to another with the same default.",
            detail=f"version={version} affected_below=1.10.14",
            source_ref={"api": f"GET {raw.get('api_base')}/version", "cve": "CVE-2020-17526"},
        )]
    if parsed < _CVE_17526_FIXED_CLEAR:
        return [Hit(
            observation=f"Airflow version {version} is in the 1.10.14–2.0.1 band; public sources "
                        f"disagree on whether CVE-2020-17526's fix shipped in 1.10.14 vs "
                        f"1.10.15/2.0.2, so exposure is not asserted",
            remediation="Upgrade to >= 2.0.2 (unambiguously fixed) and set a unique [webserver] "
                        "secret_key regardless. Airflow 1.x is end-of-life.",
            detail=f"version={version} disputed_band=1.10.14..2.0.1",
            assessable=False,
            assessment_reason="fixed version for CVE-2020-17526 is reported inconsistently across "
                              "advisories for this band",
            source_ref={"api": f"GET {raw.get('api_base')}/version", "cve": "CVE-2020-17526"},
        )]
    return []
