"""PgBouncer rulepack — config-time posture over what connect/pgbouncer.py collected.

Every rule reads REAL settings from SHOW CONFIG (auth_type, the two TLS sslmode knobs,
admin_users) and cites them. Rules run on the DISTINCT `pgbouncer_pool` kind; the users and
backends the connector collected become identity/credential/grant via the NHI extractor and are
assessed by the generic detect/identity.py pack. When SHOW CONFIG was not readable, the coverage
gap is filed once by PGBOUNCER.POOL.NOT_ASSESSED and the value-specific rules stay quiet rather
than reading absence as a clean pass.
"""
from ..connect.pgbouncer import _TRUST_AUTH, _WEAK_AUTH, _SHARED_ADMIN
from ..contracts import Hit
from ..registry import detector


@detector(kinds=["pgbouncer_pool"], rule_id="PGBOUNCER.AUTH.TRUST", severity="critical",
          title="PgBouncer auth_type accepts clients without a password")
def auth_trust(r, ctx) -> list:
    raw = r.raw or {}
    auth_type = raw.get("auth_type")
    if auth_type is None:
        return []   # config unreadable — gap filed by PGBOUNCER.POOL.NOT_ASSESSED
    if str(auth_type).lower() not in _TRUST_AUTH:
        return []
    return [Hit(
        observation=(f"PgBouncer `auth_type = {auth_type}` — clients are accepted with no "
                     f"password check ('trust'), or with any password ('any'). Anyone who can "
                     f"reach the pooler port is proxied to the backend databases as whatever "
                     f"user they name"),
        remediation=("Set `auth_type = scram-sha-256` (or `md5` at minimum) with an auth_file / "
                     "auth_query so clients must authenticate. `trust`/`any` on a network-"
                     "reachable pooler is unauthenticated access to every database behind it."),
        detail=f"auth_type={auth_type}",
        source_ref={"setting": "auth_type"},
    )]


@detector(kinds=["pgbouncer_pool"], rule_id="PGBOUNCER.TLS.CLIENT_DISABLED", severity="high",
          title="PgBouncer accepts client connections without TLS")
def client_tls_disabled(r, ctx) -> list:
    raw = r.raw or {}
    mode = raw.get("client_tls_sslmode")
    if mode is None:
        return []
    if str(mode).lower() != "disable":
        return []
    return [Hit(
        observation=("PgBouncer `client_tls_sslmode = disable` — client-to-pooler connections "
                     "carry no TLS, so application credentials and every query and result cross "
                     "the network in plaintext"),
        remediation=("Set `client_tls_sslmode = require` (or verify-full with client certs) and "
                     "provide `client_tls_cert`/`client_tls_key`. Rotate any credentials that "
                     "have transited the plaintext listener."),
        detail=f"client_tls_sslmode={mode}",
        source_ref={"setting": "client_tls_sslmode"},
    )]


@detector(kinds=["pgbouncer_pool"], rule_id="PGBOUNCER.TLS.SERVER_DISABLED", severity="medium",
          title="PgBouncer connects to backends without TLS")
def server_tls_disabled(r, ctx) -> list:
    raw = r.raw or {}
    mode = raw.get("server_tls_sslmode")
    if mode is None:
        return []
    if str(mode).lower() != "disable":
        return []
    return [Hit(
        observation=("PgBouncer `server_tls_sslmode = disable` — the pooler-to-Postgres hop "
                     "carries no TLS, so the backend password PgBouncer sends and all data it "
                     "proxies cross the network to the database in plaintext"),
        remediation=("Set `server_tls_sslmode = verify-full` with `server_tls_ca` so PgBouncer "
                     "authenticates the backend and encrypts the hop. Even inside a VPC, the "
                     "backend credential should never travel in the clear."),
        detail=f"server_tls_sslmode={mode}",
        source_ref={"setting": "server_tls_sslmode"},
    )]


@detector(kinds=["pgbouncer_pool"], rule_id="PGBOUNCER.AUTH.WEAK_TYPE", severity="medium",
          title="PgBouncer uses a weak auth_type")
def auth_weak_type(r, ctx) -> list:
    raw = r.raw or {}
    auth_type = raw.get("auth_type")
    if auth_type is None:
        return []
    if str(auth_type).lower() not in _WEAK_AUTH:
        return []
    why = ("passwords are stored and sent in cleartext"
           if str(auth_type).lower() == "plain"
           else "MD5 is a broken hash and its challenge-response is replayable/crackable")
    return [Hit(
        observation=(f"PgBouncer `auth_type = {auth_type}` — {why}, weaker than SCRAM-SHA-256"),
        remediation=("Move to `auth_type = scram-sha-256` and store SCRAM verifiers in the "
                     "auth_file / via auth_query. SCRAM is the Postgres default since 14 and "
                     "resists offline cracking and replay that md5/plain do not."),
        detail=f"auth_type={auth_type}",
        source_ref={"setting": "auth_type"},
    )]


@detector(kinds=["pgbouncer_pool"], rule_id="PGBOUNCER.ADMIN.BROAD", severity="high",
          title="PgBouncer console admin is granted too broadly")
def admin_broad(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("config_readable"):
        return []
    admin_users = raw.get("admin_users") or []
    shared = sorted(u for u in admin_users if str(u).lower() in _SHARED_ADMIN)
    if not shared and len(admin_users) < 3:
        return []
    reason = (f"includes shared superuser account(s) {shared}" if shared
              else f"lists {len(admin_users)} accounts")
    return [Hit(
        observation=(f"PgBouncer `admin_users` {reason} ({admin_users}) — console admins can run "
                     f"PAUSE/RESUME/RELOAD/KILL and read SHOW output for every pool, so a broad "
                     f"or shared-superuser admin list widens who can disrupt or inspect all "
                     f"databases behind the pooler"),
        remediation=("Restrict `admin_users` to a dedicated, named operations account (not the "
                     "Postgres superuser or a shared login) and use `stats_users` for read-only "
                     "monitoring access instead of console admin."),
        detail=f"admin_users={admin_users} shared={shared}",
        source_ref={"setting": "admin_users"},
    )]


@detector(kinds=["pgbouncer_pool"], rule_id="PGBOUNCER.POOL.NOT_ASSESSED", severity="info",
          title="PgBouncer configuration could not be read")
def pool_not_assessed(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("config_readable"):
        return []
    outcomes = raw.get("endpoint_outcomes") or {}
    return [Hit(
        observation=(f"SHOW CONFIG returned no settings (outcomes={outcomes}), so PgBouncer's "
                     f"auth and TLS posture could not be assessed"),
        remediation=("Ensure the scan user is listed in PgBouncer's `admin_users` so it can run "
                     "SHOW CONFIG on the admin console. Until then the posture is unknown, not "
                     "clean."),
        detail=f"config_readable=False outcomes={outcomes}",
        assessable=False,
        assessment_reason="SHOW CONFIG returned no rows",
        source_ref={"command": "SHOW CONFIG"},
    )]
