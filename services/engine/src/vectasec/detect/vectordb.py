"""Vector-DB / RAG-store rulepack — config-time posture over what connect/vectordb.py collected.

Every rule reads REAL evidence the connector recorded (the status of the unauthenticated list
probe, the engine's own auth model, the Postgres SSL/role facts) and cites it in the observation;
none guesses from names. Rules run on the DISTINCT vectordb_server / vectordb_collection kinds, so
they never collide with the Kafka/Kong/RabbitMQ/Redis/AWS/K8s packs.

Severity conventions (house):
  critical  anyone on the network can WRITE the store (RAG poisoning) or reach a passwordless DB
  high      anyone on the network can READ the embeddings + source chunks; plaintext DB transport
  medium    no credential enforced, plaintext REST transport, RBAC supported-but-off, publicly
            listable collection, DB reached as a superuser
  low       telemetry/metrics exposed, collection in the shared default tenant
  info      coverage notes

The third honest outcome runs throughout: a signal the connector could not settle (the Milvus data
plane on 19530 we do not speak, an unreachable endpoint, a pg_hba we could not read) becomes an
assessable=False coverage gap — never a clean pass, never a fabricated failure.
"""
from ..contracts import Hit
from ..registry import detector

_ENGINE_LABEL = {"chroma": "Chroma", "weaviate": "Weaviate", "qdrant": "Qdrant",
                 "milvus": "Milvus", "pgvector": "pgvector"}


def _label(raw) -> str:
    return _ENGINE_LABEL.get((raw or {}).get("engine"), (raw or {}).get("engine") or "vector store")


def _unreadable_reason(raw) -> str:
    """Why an anonymous read/write signal is None, in the engine's own terms."""
    if (raw or {}).get("engine") == "milvus":
        return ("the Milvus data plane (gRPC :19530) was not spoken by this read-only scan, so "
                "collection read/write authorization was not determined")
    errs = (raw or {}).get("probe_errors") or {}
    if errs:
        return f"the collection-list probe did not return a conclusive status ({errs})"
    return "the collection-list probe returned an ambiguous status, so access was not determined"


# ══ vectordb_server: anonymous access ═════════════════════════════════════════
@detector(kinds=["vectordb_server"], rule_id="VECTORDB.AUTH.ANONYMOUS_READ", severity="high",
          title="Vector store allows unauthenticated reads")
def anonymous_read(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("engine") == "pgvector" or not raw.get("reachable"):
        return []   # pgvector auth is Postgres auth (own rules); unreachable → COLLECT files the gap
    read_ok = raw.get("unauth_read_ok")
    if read_ok is True:
        n = len([c for c in ctx.of_kind("vectordb_collection")
                 if (c.raw or {}).get("server_ext") == r.ext_id])
        return [Hit(
            observation=(f"{_label(raw)} at {raw.get('endpoint')} returned HTTP 200 to an "
                         f"UNAUTHENTICATED collection-list request ({n} collection(s) enumerated) "
                         f"— anyone who can reach the port can read the embeddings and the source "
                         f"chunks they were built from"),
            remediation=("Require an API key/token (Chroma auth provider, Weaviate API-key/OIDC, "
                         "Qdrant `service.api_key`) and firewall the port to the RAG app only. An "
                         "open vector store is a document-exfiltration surface."),
            detail=f"unauth_list_status={raw.get('unauth_list_status')} collections={n}",
            source_ref={"probe": "GET collections (no credential)",
                        "status": raw.get("unauth_list_status")},
        )]
    if read_ok is None:
        return [Hit(
            observation=f"{_label(raw)} anonymous read exposure was not determined: "
                        f"{_unreadable_reason(raw)}",
            remediation="Re-scan with reachability to the data-plane endpoint, or confirm the auth "
                        "posture out of band. This is a coverage gap, not a clean result.",
            detail=f"unauth_list_status={raw.get('unauth_list_status')}",
            assessable=False,
            assessment_reason="unauthenticated read signal unavailable",
            source_ref={"probe": "GET collections (no credential)"},
        )]
    return []


@detector(kinds=["vectordb_server"], rule_id="VECTORDB.AUTH.ANONYMOUS_WRITE", severity="critical",
          title="Vector store allows unauthenticated writes (RAG poisoning)")
def anonymous_write(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("engine") == "pgvector" or not raw.get("reachable"):
        return []
    write = raw.get("anon_write_possible")
    if write is True:
        return [Hit(
            observation=(f"{_label(raw)} at {raw.get('endpoint')} served an unauthenticated read "
                         f"and applies a single credential to reads and writes "
                         f"(auth_model={raw.get('engine_auth_model')}), so an anonymous client can "
                         f"also INSERT and DELETE vectors — direct RAG poisoning: injected chunks "
                         f"become authoritative context the LLM will quote"),
            remediation=("Enable authentication immediately and restrict the port. Until then, "
                         "assume the corpus is attacker-writable and audit recently upserted "
                         "vectors. Write access with no credential is the highest-severity vector-"
                         "store defect."),
            detail=f"anon_write_possible=True auth_model={raw.get('engine_auth_model')}",
            source_ref={"auth_model": raw.get("engine_auth_model"),
                        "unauth_list_status": raw.get("unauth_list_status")},
        )]
    if write is None:
        return [Hit(
            observation=(f"{_label(raw)} anonymous WRITE exposure was not determined: "
                         f"{_unreadable_reason(raw)}"
                         + ("; this engine can grant anonymous read-only access, so an open read "
                            "does not by itself prove writes are open"
                            if raw.get("engine_auth_model") == "split_possible" else "")),
            remediation="Confirm whether anonymous clients can write (attempt a scoped upsert with "
                        "no credential from a controlled host, or read the server's auth config). "
                        "Treat as unknown, not safe.",
            detail=f"auth_model={raw.get('engine_auth_model')} "
                   f"unauth_read_ok={raw.get('unauth_read_ok')}",
            assessable=False,
            assessment_reason="anonymous write signal not derivable from read exposure alone",
            source_ref={"auth_model": raw.get("engine_auth_model")},
        )]
    return []


@detector(kinds=["vectordb_server"], rule_id="VECTORDB.AUTH.NO_TOKEN_REQUIRED", severity="medium",
          title="Vector store enforces no API key or token")
def no_token_required(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("engine") == "pgvector" or not raw.get("reachable"):
        return []
    if raw.get("api_key_provided"):
        return []   # a token WAS configured — this rule is about a server that requires none
    enforced = raw.get("auth_enforced")
    if enforced is False:
        return [Hit(
            observation=(f"{_label(raw)} at {raw.get('endpoint')} was queried with NO API "
                         f"key/token and never issued an authentication challenge "
                         f"(no 401/403) — the server requires no credential at all"),
            remediation=("Configure an authentication provider and a key/token, then require it on "
                         "every endpoint. A vector store with no credential configured is open to "
                         "the whole network segment it sits on."),
            detail=f"api_key_provided=False auth_enforced=False "
                   f"status={raw.get('unauth_list_status')}",
            source_ref={"probe": "no-credential request", "status": raw.get("unauth_list_status")},
        )]
    if enforced is None:
        return [Hit(
            observation=f"{_label(raw)} credential enforcement was not determined: "
                        f"{_unreadable_reason(raw)}",
            remediation="Re-scan when the endpoint is reachable to confirm whether a credential is "
                        "required.",
            detail=f"status={raw.get('unauth_list_status')}",
            assessable=False,
            assessment_reason="no conclusive auth-challenge status observed",
            source_ref={"probe": "no-credential request"},
        )]
    return []


@detector(kinds=["vectordb_server"], rule_id="VECTORDB.RBAC.DISABLED", severity="medium",
          title="Vector store supports RBAC/authorization but none is enforced")
def rbac_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("rbac_supported"):
        return []   # engine has no fine-grained authz (e.g. Qdrant OSS) — rule not applicable
    enabled = raw.get("rbac_enabled")
    if enabled is False:
        note = (" (anonymous access is on and no OIDC/identity provider was discovered)"
                if raw.get("engine") == "weaviate" else "")
        return [Hit(
            observation=(f"{_label(raw)} supports role-based access control but none is in force"
                         f"{note} — every client that reaches it has the same, unrestricted "
                         f"authority over all collections"),
            remediation=("Enable the engine's authorization layer (Weaviate RBAC/OIDC + admin "
                         "list, Chroma authz, Milvus RBAC) and grant least privilege per identity, "
                         "so a single leaked credential is not full control."),
            detail=f"rbac_supported=True rbac_enabled=False engine={raw.get('engine')}",
            source_ref={"rbac_enabled": False},
        )]
    if enabled is None:
        return [Hit(
            observation=(f"{_label(raw)} authorization posture was not determined — the server did "
                         f"not expose whether RBAC/authorization is enforced to a read-only scan"),
            remediation="Confirm the authorization configuration out of band (admin API / config).",
            detail=f"rbac_supported=True rbac_enabled=None engine={raw.get('engine')}",
            assessable=False,
            assessment_reason="RBAC state not observable read-only",
            source_ref={"rbac_enabled": None},
        )]
    return []


# ══ vectordb_server: transport + telemetry ════════════════════════════════════
@detector(kinds=["vectordb_server"], rule_id="VECTORDB.TLS.DISABLED", severity="medium",
          title="Vector store REST endpoint is plaintext HTTP")
def tls_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("engine") == "pgvector" or not raw.get("reachable"):
        return []   # pgvector transport is covered by VECTORDB.PGVECTOR.SSL_DISABLED
    if raw.get("connected_via_tls"):
        return []
    return [Hit(
        observation=(f"{_label(raw)} was reached over plaintext HTTP at {raw.get('endpoint')} — "
                     f"queries, returned document chunks and any API key sent on the wire cross "
                     f"the network unencrypted"),
        remediation=("Terminate TLS at the store or a sidecar/ingress and connect over https. "
                     "Without it, the API key and every retrieved chunk are sniffable on-path."),
        detail=f"connected_via_tls=False endpoint={raw.get('endpoint')}",
        source_ref={"scheme": "http"},
    )]


@detector(kinds=["vectordb_server"], rule_id="VECTORDB.METRICS.EXPOSED", severity="low",
          title="Vector store metrics endpoint is exposed unauthenticated")
def metrics_exposed(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("engine") == "pgvector":
        return []
    exposed = raw.get("metrics_exposed")
    if exposed is True:
        return [Hit(
            observation=(f"{_label(raw)} served its Prometheus /metrics endpoint (HTTP 200) to an "
                         f"unauthenticated request — collection counts, vector dimensions and "
                         f"request patterns leak the shape of the corpus to anyone on the network"),
            remediation=("Bind /metrics to an internal interface or require auth on it; scrape it "
                         "from the monitoring network only, not the public listener."),
            detail=f"metrics_status={raw.get('metrics_status')}",
            source_ref={"probe": "GET /metrics (no credential)",
                        "status": raw.get("metrics_status")},
        )]
    if exposed is None and raw.get("reachable"):
        return [Hit(
            observation=f"{_label(raw)} /metrics exposure was not determined — the metrics probe "
                        f"did not return a conclusive status",
            remediation="Re-scan the /metrics path to confirm whether it is publicly reachable.",
            detail=f"metrics_status={raw.get('metrics_status')}",
            assessable=False,
            assessment_reason="metrics probe returned no conclusive status",
            source_ref={"probe": "GET /metrics (no credential)"},
        )]
    return []


# ══ vectordb_server: pgvector / host Postgres ═════════════════════════════════
@detector(kinds=["vectordb_server"], rule_id="VECTORDB.PGVECTOR.NO_PASSWORD", severity="critical",
          title="pgvector host Postgres accepts passwordless connections")
def pgvector_no_password(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("engine") != "pgvector":
        return []
    pg = raw.get("pgvector") or {}
    passwordless = pg.get("passwordless_auth")
    if passwordless is True:
        return [Hit(
            observation=(f"the Postgres hosting pgvector at {raw.get('endpoint')} has `trust` "
                         f"authentication rules in pg_hba — clients authenticate with NO password, "
                         f"so anyone who can reach the port has full access to the vector store and "
                         f"the database around it"),
            remediation=("Replace `trust` in pg_hba.conf with `scram-sha-256` (or `cert`), set "
                         "passwords/roles, reload Postgres, and firewall 5432. Passwordless "
                         "network Postgres is unauthenticated data and code access."),
            detail=f"passwordless_auth=True hba_readable={pg.get('hba_readable')}",
            source_ref={"pg_hba": "auth_method=trust"},
        )]
    if passwordless is None:
        return [Hit(
            observation=("whether the pgvector host Postgres accepts passwordless connections was "
                         "not determined — pg_hba_file_rules was not readable (needs superuser) and "
                         "the DSN carried no password to prove password auth"),
            remediation="Verify pg_hba.conf uses scram-sha-256 (not trust/peer with no password) "
                        "for the networks the RAG app connects from.",
            detail=f"hba_readable={pg.get('hba_readable')} dsn_has_password={pg.get('dsn_has_password')}",
            assessable=False,
            assessment_reason="pg_hba unreadable and DSN password absent",
            source_ref={"pg_hba": "unreadable"},
        )]
    return []


@detector(kinds=["vectordb_server"], rule_id="VECTORDB.PGVECTOR.SSL_DISABLED", severity="high",
          title="pgvector host Postgres connection is not encrypted")
def pgvector_ssl_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("engine") != "pgvector":
        return []
    pg = raw.get("pgvector") or {}
    ssl_in_use = pg.get("ssl_in_use")
    if ssl_in_use is False:
        return [Hit(
            observation=(f"the connection to the pgvector host Postgres at {raw.get('endpoint')} "
                         f"is NOT using SSL (pg_stat_ssl.ssl=false, server ssl setting "
                         f"'{pg.get('ssl_setting')}') — embeddings, queries and returned chunks "
                         f"cross the network in plaintext"),
            remediation=("Enable SSL on Postgres and require it from clients "
                         "(sslmode=verify-full). Without it the RAG corpus and credentials are "
                         "sniffable on-path."),
            detail=f"ssl_in_use=False ssl_setting={pg.get('ssl_setting')}",
            source_ref={"pg_stat_ssl": "ssl=false"},
        )]
    if ssl_in_use is None:
        return [Hit(
            observation=("pgvector host Postgres transport encryption was not determined — "
                         "pg_stat_ssl could not be read"),
            remediation="Confirm the connection uses SSL (sslmode=require or stronger).",
            detail=f"ssl_setting={pg.get('ssl_setting')}",
            assessable=False,
            assessment_reason="pg_stat_ssl not readable",
            source_ref={"pg_stat_ssl": "unreadable"},
        )]
    return []


@detector(kinds=["vectordb_server"], rule_id="VECTORDB.PGVECTOR.SUPERUSER_LOGIN", severity="medium",
          title="pgvector store is accessed as a Postgres superuser")
def pgvector_superuser_login(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("engine") != "pgvector":
        return []
    pg = raw.get("pgvector") or {}
    is_super = pg.get("is_superuser")
    if is_super is True:
        return [Hit(
            observation=(f"the pgvector store is accessed as Postgres role '{pg.get('current_user')}', "
                         f"which is a SUPERUSER — a compromise of the RAG app's database credential "
                         f"is full control of the entire Postgres instance, not just the vector "
                         f"tables"),
            remediation=("Create a least-privilege role that owns only the vector schema/tables "
                         "(GRANT SELECT/INSERT/UPDATE on them) and point the app at it; reserve "
                         "the superuser for migrations."),
            detail=f"current_user={pg.get('current_user')} rolsuper=True",
            source_ref={"role": pg.get("current_user"), "rolsuper": True},
        )]
    if is_super is None:
        return [Hit(
            observation=("whether the pgvector store is accessed as a superuser was not "
                         "determined — the connecting role's rolsuper could not be read"),
            remediation="Confirm the app connects with a least-privilege role, not a superuser.",
            detail=f"current_user={pg.get('current_user')}",
            assessable=False,
            assessment_reason="rolsuper of current_user not readable",
            source_ref={"role": pg.get("current_user")},
        )]
    return []


# ══ vectordb_collection ═══════════════════════════════════════════════════════
@detector(kinds=["vectordb_collection"], rule_id="VECTORDB.COLLECTION.PUBLICLY_LISTABLE",
          severity="medium", title="Collection is enumerable without authentication")
def collection_publicly_listable(r, ctx) -> list:
    raw = r.raw or {}
    listed = raw.get("listed_anonymously")
    if listed is True:
        return [Hit(
            observation=(f"collection '{raw.get('name')}' on the {_label(raw)} store was returned "
                         f"by an UNAUTHENTICATED listing — its existence, name and (for most "
                         f"engines) its contents are readable by anyone on the network"),
            remediation=("Require authentication on the list/collections API and restrict the "
                         "port. Even the collection inventory leaks what corpora exist and how "
                         "they are partitioned."),
            detail=f"listed_anonymously=True engine={raw.get('engine')}",
            source_ref={"listed_anonymously": True},
        )]
    if listed is None:
        return [Hit(
            observation=(f"collection '{raw.get('name')}' anonymous listability was not "
                         f"determined — the unauthenticated list probe errored, so it is unknown "
                         f"whether it is enumerable without a credential"),
            remediation="Re-scan with the list endpoint reachable to confirm anonymous "
                        "enumerability.",
            detail="listed_anonymously=None",
            assessable=False,
            assessment_reason="anonymous list probe did not complete",
            source_ref={"listed_anonymously": None},
        )]
    return []


@detector(kinds=["vectordb_collection"], rule_id="VECTORDB.COLLECTION.SHARED_DEFAULT_TENANT",
          severity="low", title="Collection lives in the shared default tenant")
def collection_shared_default_tenant(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("multitenancy_supported"):
        return []   # engine has no tenancy to use (e.g. Qdrant) — not applicable
    if not raw.get("default_tenant"):
        return []
    return [Hit(
        observation=(f"collection '{raw.get('name')}' on the {_label(raw)} store is in the shared "
                     f"default tenant/namespace (tenant={raw.get('tenant')!r}) — it has no "
                     f"per-tenant isolation from other data in the same store"),
        remediation=("Place each tenant's vectors in a dedicated tenant/namespace (Weaviate "
                     "multi-tenancy, Chroma tenant/database, a per-tenant Postgres schema) so a "
                     "query or credential scoped to one tenant cannot read another's chunks."),
        detail=f"default_tenant=True tenant={raw.get('tenant')} engine={raw.get('engine')}",
        source_ref={"tenant": raw.get("tenant")},
    )]


# ══ coverage honesty ══════════════════════════════════════════════════════════
@detector(kinds=["vectordb_server"], rule_id="VECTORDB.COLLECT.NOT_ASSESSED", severity="info",
          title="Vector store could not be reached or fully probed")
def collect_not_assessed(r, ctx) -> list:
    """The third outcome at server scope: an unreachable store, or individual probes that errored,
    are coverage gaps the other rules silently have — filed as not-assessable, never a pass."""
    raw = r.raw or {}
    if not raw.get("reachable"):
        return [Hit(
            observation=(f"the {_label(raw)} store at {raw.get('endpoint')} could not be reached by "
                         f"the read-only scan — no posture rule in this pack could evaluate it "
                         f"(errors: {raw.get('probe_errors') or 'connection failed'})"),
            remediation=("Confirm the endpoint/DSN and network reachability from the engine/worker, "
                         "then re-scan. An unreachable store is unknown, not clean."),
            detail=f"reachable=False probe_errors={raw.get('probe_errors')}",
            assessable=False,
            assessment_reason="store unreachable",
            source_ref={"probe_errors": raw.get("probe_errors")},
        )]
    errs = raw.get("probe_errors") or {}
    if errs:
        return [Hit(
            observation=(f"the {_label(raw)} store was reached but some probes errored ({errs}); "
                         f"rules depending on those endpoints could not run"),
            remediation="Ensure every listed endpoint is reachable and permitted, then re-scan to "
                        "close the coverage gap.",
            detail=f"probe_errors={errs}",
            assessable=False,
            assessment_reason=f"probe(s) errored: {', '.join(sorted(errs))}",
            source_ref={"probe_errors": errs},
        )]
    return []
