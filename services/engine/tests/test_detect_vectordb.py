"""Offline golden-fixture tests for the Vector-DB connector + rulepack.

Fixtures (fixtures/vectordb_responses.json) are the JSON BODIES each engine's REST API actually
returns (Chroma /collections list, Weaviate /v1/schema, Qdrant /collections envelope, Milvus
healthz) plus, for pgvector, the plain fact bundle the psycopg reads produce. Each body is wrapped
into a probe record {"status", "json"} and flowed through the connector's OWN pure parse layer
(normalize_* + build_collected) — the same normalisation the live collect uses — so httpx/psycopg
never enter the suite and a shape drift between connector and rulepack fails a test here.

Every detector gets a FIRES case, a SILENT (good-config) case, and — where the third outcome is
meaningful — a NOT-ASSESSABLE case. The credential-reduction discipline gets its own test: no
secret value ever appears in an emitted Resource, and the NHI layer records credential presence
without a value.
"""
import json
import pathlib

from vectasec.connect.vectordb import (build_collected, normalize_chroma, normalize_milvus,
                                       normalize_pgvector, normalize_qdrant, normalize_weaviate)
from vectasec.contracts import ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, DETECTORS, validate_config
import vectasec.detect.vectordb  # noqa: F401 — registers the VECTORDB.* rulepack

FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "vectordb_responses.json").read_text())

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("VECTORDB.")}

# Kept explicit so silently dropping a detector fails a test rather than shrinking coverage.
EXPECTED_RULES = {
    "VECTORDB.AUTH.ANONYMOUS_READ",
    "VECTORDB.AUTH.ANONYMOUS_WRITE",
    "VECTORDB.AUTH.NO_TOKEN_REQUIRED",
    "VECTORDB.RBAC.DISABLED",
    "VECTORDB.TLS.DISABLED",
    "VECTORDB.METRICS.EXPOSED",
    "VECTORDB.PGVECTOR.NO_PASSWORD",
    "VECTORDB.PGVECTOR.SSL_DISABLED",
    "VECTORDB.PGVECTOR.SUPERUSER_LOGIN",
    "VECTORDB.COLLECTION.PUBLICLY_LISTABLE",
    "VECTORDB.COLLECTION.SHARED_DEFAULT_TENANT",
    "VECTORDB.COLLECT.NOT_ASSESSED",
}


# ── evaluation helpers ────────────────────────────────────────────────────────
def _eval(coll, rule_id):
    d = RULES[rule_id]
    ctx = ScanContext("conn", "tenant", coll.resources)
    out = []
    for res in coll.resources:
        if res.kind in d.kinds:
            out.extend(d.fn(res, ctx))
    return out


def fires(coll, rule_id):
    return [h for h in _eval(coll, rule_id) if h.assessable]


def not_assessable(coll, rule_id):
    return [h for h in _eval(coll, rule_id) if not h.assessable]


def _probe(status, body=None, error=None):
    return {"status": status, "json": body, "error": error}


# ── scenario builders (probe records → parse layer → Collected) ───────────────
def chroma(*, list_status=200, collections=None, version_status=200, metrics=404,
           tls=False, api_key_provided=False, auth_list=None, list_error=None):
    cols = FIX["chroma"]["collections"] if collections is None else collections
    return build_collected(normalize_chroma(
        "chost", 8000, tls, api_key_provided=api_key_provided,
        version_probe=_probe(version_status, FIX["chroma"]["version"] if version_status == 200 else None),
        list_probe=_probe(list_status, cols if list_status == 200 else None, list_error),
        auth_list_probe=auth_list,
        metrics_probe=_probe(metrics)))


def weaviate(*, schema_status=200, schema=None, openid_status=404, metrics=404,
             tls=False, api_key_provided=False, auth_schema=None, schema_error=None):
    body = FIX["weaviate"]["schema_no_mt"] if schema is None else schema
    return build_collected(normalize_weaviate(
        "whost", 8080, tls, api_key_provided=api_key_provided,
        meta_probe=_probe(200, FIX["weaviate"]["meta"]),
        schema_probe=_probe(schema_status, body if schema_status == 200 else None, schema_error),
        auth_schema_probe=auth_schema,
        openid_probe=_probe(openid_status, FIX["weaviate"]["openid"] if openid_status == 200 else None),
        metrics_probe=_probe(metrics)))


def qdrant(*, list_status=200, metrics=200, tls=False, api_key_provided=False,
           root_status=200, auth_list=None, root_error=None, list_error=None):
    return build_collected(normalize_qdrant(
        "qhost", 6333, tls, api_key_provided=api_key_provided,
        root_probe=_probe(root_status, FIX["qdrant"]["root"] if root_status == 200 else None, root_error),
        list_probe=_probe(list_status, FIX["qdrant"]["collections"] if list_status == 200 else None, list_error),
        auth_list_probe=auth_list,
        metrics_probe=_probe(metrics)))


def milvus(*, health=200, metrics=200, tls=False):
    return build_collected(normalize_milvus(
        "mhost", 9091, tls, api_key_provided=False,
        health_probe=_probe(health, FIX["milvus"]["healthz"] if health == 200 else None),
        metrics_probe=_probe(metrics)))


def pgvector(profile="bad"):
    return build_collected(normalize_pgvector("pghost", 5432, "ragdb", pg=FIX["pgvector"][profile]))


def _server(coll):
    return next(r for r in coll.resources if r.kind == "vectordb_server")


# ══ registration guard ════════════════════════════════════════════════════════
def test_all_expected_rules_registered():
    assert set(RULES) == EXPECTED_RULES


def test_connector_fields_and_secrets():
    fields = {f.key: f for f in CONNECTOR_FIELDS["vectordb"]}
    assert "engine" in fields and fields["engine"].required
    assert fields["api_key"].secret and fields["dsn"].secret
    # engine is the only required field; a bare engine still validates (host/dsn checked at collect)
    assert validate_config("vectordb", {"engine": "qdrant", "host": "h"}) == []
    assert validate_config("vectordb", {}) == ["engine is required (Engine)"]


# ══ VECTORDB.AUTH.ANONYMOUS_READ ══════════════════════════════════════════════
def test_anonymous_read_fires_on_open_qdrant():
    hits = fires(qdrant(list_status=200), "VECTORDB.AUTH.ANONYMOUS_READ")
    assert len(hits) == 1
    assert "UNAUTHENTICATED" in hits[0].observation
    assert "2 collection" in hits[0].observation  # both fixture collections enumerated


def test_anonymous_read_silent_when_auth_enforced():
    assert fires(qdrant(list_status=401), "VECTORDB.AUTH.ANONYMOUS_READ") == []
    assert not_assessable(qdrant(list_status=401), "VECTORDB.AUTH.ANONYMOUS_READ") == []


def test_anonymous_read_not_assessable_on_opaque_milvus():
    na = not_assessable(milvus(), "VECTORDB.AUTH.ANONYMOUS_READ")
    assert len(na) == 1 and "19530" in na[0].observation


def test_anonymous_read_skips_pgvector():
    assert _eval(pgvector("bad"), "VECTORDB.AUTH.ANONYMOUS_READ") == []


# ══ VECTORDB.AUTH.ANONYMOUS_WRITE ═════════════════════════════════════════════
def test_anonymous_write_fires_critical_on_uniform_auth_open():
    hits = fires(qdrant(list_status=200), "VECTORDB.AUTH.ANONYMOUS_WRITE")
    assert len(hits) == 1
    assert RULES["VECTORDB.AUTH.ANONYMOUS_WRITE"].severity == "critical"
    assert "poison" in hits[0].observation.lower()


def test_anonymous_write_not_assessable_on_weaviate_split_auth():
    # Weaviate can grant anonymous read-only, so open read does NOT prove open write.
    na = not_assessable(weaviate(schema_status=200), "VECTORDB.AUTH.ANONYMOUS_WRITE")
    assert len(na) == 1 and "read-only" in na[0].observation


def test_anonymous_write_silent_when_auth_enforced():
    assert _eval(qdrant(list_status=403), "VECTORDB.AUTH.ANONYMOUS_WRITE") == []


# ══ VECTORDB.AUTH.NO_TOKEN_REQUIRED ═══════════════════════════════════════════
def test_no_token_required_fires_when_no_key_and_no_challenge():
    hits = fires(chroma(list_status=200, api_key_provided=False), "VECTORDB.AUTH.NO_TOKEN_REQUIRED")
    assert len(hits) == 1


def test_no_token_required_silent_when_key_configured():
    # A key WAS provided (open server) — ANONYMOUS_READ still fires, but this config rule does not.
    assert _eval(qdrant(list_status=200, api_key_provided=True), "VECTORDB.AUTH.NO_TOKEN_REQUIRED") == []
    assert fires(qdrant(list_status=200, api_key_provided=True), "VECTORDB.AUTH.ANONYMOUS_READ")


def test_no_token_required_silent_when_challenged():
    assert _eval(chroma(list_status=401), "VECTORDB.AUTH.NO_TOKEN_REQUIRED") == []


def test_no_token_required_not_assessable_on_ambiguous_status():
    # A 500 is neither 200 nor a 401 challenge → enforcement unknown, but server reachable (version).
    na = not_assessable(chroma(list_status=500, version_status=200), "VECTORDB.AUTH.NO_TOKEN_REQUIRED")
    assert len(na) == 1


# ══ VECTORDB.RBAC.DISABLED ════════════════════════════════════════════════════
def test_rbac_disabled_fires_on_weaviate_anon_no_oidc():
    hits = fires(weaviate(schema_status=200, openid_status=404), "VECTORDB.RBAC.DISABLED")
    assert len(hits) == 1 and "OIDC" in hits[0].observation


def test_rbac_disabled_silent_when_oidc_configured():
    assert _eval(weaviate(schema_status=401, openid_status=200), "VECTORDB.RBAC.DISABLED") == []


def test_rbac_disabled_not_assessable_on_milvus():
    # Milvus supports RBAC but the data plane was not spoken → enforcement unknown.
    na = not_assessable(milvus(), "VECTORDB.RBAC.DISABLED")
    assert len(na) == 1


def test_rbac_disabled_not_applicable_to_qdrant():
    # Qdrant OSS has no fine-grained RBAC → rule never emits, fire or not.
    assert _eval(qdrant(list_status=200), "VECTORDB.RBAC.DISABLED") == []
    assert _eval(qdrant(list_status=401), "VECTORDB.RBAC.DISABLED") == []


# ══ VECTORDB.TLS.DISABLED ═════════════════════════════════════════════════════
def test_tls_disabled_fires_on_plaintext_http():
    hits = fires(qdrant(list_status=200, tls=False), "VECTORDB.TLS.DISABLED")
    assert len(hits) == 1 and "plaintext" in hits[0].observation


def test_tls_disabled_silent_over_https():
    assert _eval(qdrant(list_status=200, tls=True), "VECTORDB.TLS.DISABLED") == []


def test_tls_disabled_skips_pgvector():
    # pgvector transport is covered by its own SSL rule, not the REST TLS rule.
    assert _eval(pgvector("bad"), "VECTORDB.TLS.DISABLED") == []


# ══ VECTORDB.METRICS.EXPOSED ══════════════════════════════════════════════════
def test_metrics_exposed_fires_when_200():
    hits = fires(qdrant(metrics=200), "VECTORDB.METRICS.EXPOSED")
    assert len(hits) == 1 and "Prometheus" in hits[0].observation


def test_metrics_exposed_silent_when_404():
    assert _eval(chroma(metrics=404), "VECTORDB.METRICS.EXPOSED") == []


def test_metrics_exposed_not_assessable_when_probe_errored():
    # metrics probe returned no status (network error) but the server is otherwise reachable.
    na = not_assessable(qdrant(list_status=200, metrics=None), "VECTORDB.METRICS.EXPOSED")
    assert len(na) == 1


# ══ VECTORDB.PGVECTOR.NO_PASSWORD ═════════════════════════════════════════════
def test_pgvector_no_password_fires_on_trust_auth():
    hits = fires(pgvector("bad"), "VECTORDB.PGVECTOR.NO_PASSWORD")
    assert len(hits) == 1 and RULES["VECTORDB.PGVECTOR.NO_PASSWORD"].severity == "critical"


def test_pgvector_no_password_silent_with_password():
    assert _eval(pgvector("good"), "VECTORDB.PGVECTOR.NO_PASSWORD") == []


def test_pgvector_no_password_not_assessable_when_hba_unreadable():
    na = not_assessable(pgvector("unknown"), "VECTORDB.PGVECTOR.NO_PASSWORD")
    assert len(na) == 1


def test_pgvector_no_password_skips_rest_engines():
    assert _eval(qdrant(list_status=200), "VECTORDB.PGVECTOR.NO_PASSWORD") == []


# ══ VECTORDB.PGVECTOR.SSL_DISABLED ════════════════════════════════════════════
def test_pgvector_ssl_disabled_fires():
    hits = fires(pgvector("bad"), "VECTORDB.PGVECTOR.SSL_DISABLED")
    assert len(hits) == 1 and "plaintext" in hits[0].observation


def test_pgvector_ssl_disabled_silent_when_encrypted():
    assert _eval(pgvector("good"), "VECTORDB.PGVECTOR.SSL_DISABLED") == []


def test_pgvector_ssl_disabled_not_assessable_when_unreadable():
    na = not_assessable(pgvector("unknown"), "VECTORDB.PGVECTOR.SSL_DISABLED")
    assert len(na) == 1


# ══ VECTORDB.PGVECTOR.SUPERUSER_LOGIN ═════════════════════════════════════════
def test_pgvector_superuser_login_fires():
    hits = fires(pgvector("bad"), "VECTORDB.PGVECTOR.SUPERUSER_LOGIN")
    assert len(hits) == 1 and "postgres" in hits[0].observation


def test_pgvector_superuser_login_silent_for_least_privilege_role():
    assert _eval(pgvector("good"), "VECTORDB.PGVECTOR.SUPERUSER_LOGIN") == []


def test_pgvector_superuser_login_not_assessable_when_unknown():
    na = not_assessable(pgvector("unknown"), "VECTORDB.PGVECTOR.SUPERUSER_LOGIN")
    assert len(na) == 1


# ══ VECTORDB.COLLECTION.PUBLICLY_LISTABLE ═════════════════════════════════════
def test_collection_publicly_listable_fires_from_anon_listing():
    coll = qdrant(list_status=200)
    hits = fires(coll, "VECTORDB.COLLECTION.PUBLICLY_LISTABLE")
    assert len(hits) == 2  # both qdrant collections came from the unauthenticated listing


def test_collection_publicly_listable_silent_when_auth_only():
    # Anon listing 401, but an authed listing supplied the inventory → not anonymously listable.
    coll = qdrant(list_status=401, api_key_provided=True,
                  auth_list=_probe(200, FIX["qdrant"]["collections"]))
    assert _eval(coll, "VECTORDB.COLLECTION.PUBLICLY_LISTABLE") == []


def test_collection_publicly_listable_not_assessable_when_anon_probe_errored():
    # Anon listing errored (no status) but authed listing found collections → anon listability unknown.
    coll = qdrant(list_status=None, list_error="ConnectError", api_key_provided=True,
                  auth_list=_probe(200, FIX["qdrant"]["collections"]))
    na = not_assessable(coll, "VECTORDB.COLLECTION.PUBLICLY_LISTABLE")
    assert len(na) == 2


# ══ VECTORDB.COLLECTION.SHARED_DEFAULT_TENANT ═════════════════════════════════
def test_shared_default_tenant_fires_on_default_chroma_collection():
    coll = chroma(list_status=200)
    hits = fires(coll, "VECTORDB.COLLECTION.SHARED_DEFAULT_TENANT")
    # only rag_docs is in default_tenant/default_database; tenant_a_docs is isolated
    assert [h for h in hits] and len(hits) == 1


def test_shared_default_tenant_silent_on_weaviate_mt_class():
    # A multi-tenancy-enabled class isolates its data → tenant is None, not the shared default.
    coll = weaviate(schema_status=200, schema=FIX["weaviate"]["schema_mt"])
    assert _eval(coll, "VECTORDB.COLLECTION.SHARED_DEFAULT_TENANT") == []


def test_shared_default_tenant_not_applicable_to_qdrant():
    # Qdrant collections are flat (no tenancy) → rule never emits.
    assert _eval(qdrant(list_status=200), "VECTORDB.COLLECTION.SHARED_DEFAULT_TENANT") == []


# ══ VECTORDB.COLLECT.NOT_ASSESSED ═════════════════════════════════════════════
def test_collect_not_assessed_fires_when_unreachable():
    coll = qdrant(root_status=None, root_error="ConnectTimeout",
                  list_status=None, list_error="ConnectTimeout", metrics=None)
    na = not_assessable(coll, "VECTORDB.COLLECT.NOT_ASSESSED")
    assert len(na) == 1 and "could not be reached" in na[0].observation
    # and no other server rule fires on an unreachable store
    assert fires(coll, "VECTORDB.AUTH.ANONYMOUS_READ") == []
    assert fires(coll, "VECTORDB.TLS.DISABLED") == []


def test_collect_not_assessed_fires_on_partial_probe_error():
    # Reachable (listing worked) but the version probe errored → partial coverage gap.
    coll = chroma(list_status=200, version_status=None)
    # inject a version error via a fresh normalize (version_status None already yields error=None);
    # use a metrics error instead to exercise the partial-error branch
    coll = build_collected(normalize_chroma(
        "chost", 8000, False, api_key_provided=False,
        version_probe=_probe(200, FIX["chroma"]["version"]),
        list_probe=_probe(200, FIX["chroma"]["collections"]),
        metrics_probe=_probe(None, None, "ConnectError: /metrics")))
    na = not_assessable(coll, "VECTORDB.COLLECT.NOT_ASSESSED")
    assert len(na) == 1 and "metrics" in na[0].assessment_reason


def test_collect_not_assessed_silent_when_clean():
    assert _eval(qdrant(list_status=200, metrics=200), "VECTORDB.COLLECT.NOT_ASSESSED") == []


# ══ NHI (identity / credential / grant) ═══════════════════════════════════════
def test_pgvector_roles_become_nhi_identities_and_grants():
    coll = derive_identities("vectordb", pgvector("bad"))
    ids = {r.name: r for r in coll.resources if r.kind == "identity"}
    assert set(ids) == {"postgres", "rag_app", "readonly_grp"}
    assert ids["postgres"].labels["identity_type"] == "database_superuser"
    assert ids["rag_app"].labels["identity_type"] == "database_login_role"
    assert ids["readonly_grp"].labels["identity_type"] == "database_group_role"

    grants = {g.raw["action"] for g in coll.resources if g.kind == "grant"}
    assert grants == {"superuser", "login", "nologin"}
    # the superuser grant is a wildcard grant
    sup = next(g for g in coll.resources if g.kind == "grant" and g.raw["action"] == "superuser")
    assert sup.labels["wildcard"] == "true"


def test_pgvector_credential_metadata_records_presence_not_value():
    coll = derive_identities("vectordb", pgvector("bad"))
    creds = {c.name: c for c in coll.resources if c.kind == "credential"}
    # postgres has_password False (present=False), rag_app has_password True (present=True),
    # readonly_grp cannot login / has_password None → NO credential emitted
    assert creds["postgres:password"].raw["present"] is False
    assert creds["rag_app:password"].raw["present"] is True
    assert "readonly_grp:password" not in creds
    # never a value, always metadata
    for c in creds.values():
        assert c.raw["plaintext"] is False
        assert "value" not in c.raw and "rolpassword" not in c.raw


def test_rest_engines_expose_no_nhi():
    # REST vector stores expose no enumerable principal list read-only → honest absence.
    for coll in (qdrant(list_status=200), weaviate(schema_status=200), chroma(list_status=200)):
        derived = derive_identities("vectordb", coll)
        assert [r for r in derived.resources if r.kind in ("identity", "credential", "grant")] == []


def test_vectordb_identity_extractor_registered():
    assert "vectordb" in IDENTITY_EXTRACTORS


# ══ secret-reduction discipline ═══════════════════════════════════════════════
def test_no_secret_material_in_emitted_resources():
    # The pure parse layer is never handed a key/DSN password; assert nothing key-shaped leaks into
    # any Resource.raw for either a REST store or the pgvector NHI model.
    blobs = []
    for coll in (qdrant(list_status=200, api_key_provided=True),
                 derive_identities("vectordb", pgvector("bad"))):
        for r in coll.resources:
            blobs.append(json.dumps(r.raw, default=str))
    haystack = " ".join(blobs)
    for banned in ("password=", "rolpassword", "secret", "api-key:", "Bearer "):
        assert banned not in haystack


# ══ engine coverage: every engine builds a distinct-kinded server ═════════════
def test_every_engine_emits_distinct_vectordb_kinds():
    for coll in (chroma(list_status=200), weaviate(schema_status=200), qdrant(list_status=200),
                 milvus(), pgvector("bad")):
        kinds = {r.kind for r in coll.resources}
        assert kinds <= {"vectordb_server", "vectordb_collection"}
        assert "vectordb_server" in kinds
        assert _server(coll).labels["engine"] in ("chroma", "weaviate", "qdrant", "milvus", "pgvector")
