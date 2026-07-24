"""Unit tests for the HashiCorp Vault connector parse layer, rulepack, and NHI extraction.

Offline: no httpx client is ever constructed, no Vault is touched. The baseline is the golden
fixture in fixtures/vault_responses.json — Vault API `data` payloads shaped as the API returns
them. Resources are built through the connector's OWN parse layer, so a shape drift between
connector and rulepack fails here first. Every rule gets a FIRE, a DOES-NOT-FIRE, and (where it
has one) a NOT-ASSESSABLE case.
"""
import json
import pathlib

from vectasec.contracts import Collected, Resource, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS, DETECTORS
import vectasec.detect.vault  # noqa: F401 — import registers the rulepack
from vectasec.connect.vault import (
    _policy_paths, parse_auth_role, parse_mount, parse_policy, parse_server,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "vault_responses.json").read_text()
)
BASE = "https://vault.example.com:8200"

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("VAULT.")}

EXPECTED_RULES = {
    "VAULT.AUDIT.NO_DEVICE",
    "VAULT.TLS.PLAINTEXT",
    "VAULT.TOKEN.ROOT_IN_USE",
    "VAULT.SEAL.LOW_THRESHOLD",
    "VAULT.SERVER.NOT_ASSESSED",
    "VAULT.MOUNT.DYNAMIC_NO_TTL_OVERRIDE",
    "VAULT.POLICY.SUDO_GRANT",
    "VAULT.POLICY.WILDCARD_WRITE",
    "VAULT.AUTH.APPROLE_UNBOUNDED",
    "VAULT.AUTH.JWT_NO_BOUND_CLAIMS",
    "VAULT.AUTH.KUBERNETES_WILDCARD_BINDING",
}

_OK = {"outcome": "ok", "error": None}
_FORBIDDEN = {"outcome": "forbidden", "error": "HTTP 403"}


# ── builders ──────────────────────────────────────────────────────────────────
def server(*, base=BASE, seal="seal_status_weak", token="token_root", audit="audit_empty",
           collection=None) -> Resource:
    col = {"sys/health": _OK, "sys/seal-status": _OK, "auth/token/lookup-self": _OK,
           "sys/audit": _OK, "sys/auth": _OK, "sys/mounts": _OK, "sys/policies/acl": _OK}
    col.update(collection or {})
    return parse_server(
        base, health=FIX["health"], seal=FIX[seal], token=FIX[token], audit=FIX[audit],
        collection=col)


def mount(name: str) -> Resource:
    return parse_mount(name, FIX["mounts"][name])


def policy(name: str) -> Resource:
    return parse_policy(name, FIX["policies"][name])


def role(name: str) -> Resource:
    d = FIX["roles"][name]
    mtype = {"approle_unbounded": "approle", "approle_bound": "approle",
             "jwt_unbounded": "jwt", "jwt_bound": "jwt",
             "kubernetes_wildcard": "kubernetes", "kubernetes_scoped": "kubernetes"}[name]
    mount_path = {"approle": "approle/", "jwt": "jwt/", "kubernetes": "kubernetes/"}[mtype]
    return parse_auth_role(mount_path, mtype, name, d)


def scan(*resources) -> ScanContext:
    return ScanContext(connection_id="c1", tenant_id="t1", resources=list(resources))


def fire(rule_id, resource, ctx=None) -> list:
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to kind={resource.kind}"
    return d.fn(resource, ctx or scan(resource)) or []


def sev(hits, rule_id) -> list:
    base = RULES[rule_id].severity
    return [h.severity or base for h in hits]


# ── pack + registration shape ──────────────────────────────────────────────────
def test_expected_rules_all_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rules_only_run_on_vault_kinds():
    for d in RULES.values():
        assert all(k.startswith("vault_") for k in d.kinds), d.rule_id


def test_connector_registered_and_token_is_secret():
    assert "vault" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["vault"]}
    assert fields["token"].secret and fields["token"].required
    assert fields["base_url"].required and not fields["base_url"].secret


# ── secret discipline ──────────────────────────────────────────────────────────
def test_server_never_stores_token_value():
    s = server(token="token_root")
    blob = json.dumps(s.raw)
    assert "SHOULD-NEVER-BE-STORED" not in blob        # the token id is never copied
    assert s.raw["token_display_name"] == "root"
    assert s.raw["token_is_root"] is True


# ── VAULT.AUDIT.NO_DEVICE ───────────────────────────────────────────────────────
def test_audit_no_device_fires_when_empty():
    hits = fire("VAULT.AUDIT.NO_DEVICE", server(audit="audit_empty"))
    assert len(hits) == 1 and hits[0].assessable
    assert sev(hits, "VAULT.AUDIT.NO_DEVICE") == ["critical"]
    assert "zero audit devices" in hits[0].observation


def test_audit_no_device_quiet_when_enabled():
    assert fire("VAULT.AUDIT.NO_DEVICE", server(audit="audit_enabled")) == []


def test_audit_no_device_not_assessable_when_denied():
    s = server(audit="audit_empty", collection={"sys/audit": _FORBIDDEN})
    hits = fire("VAULT.AUDIT.NO_DEVICE", s)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "sys/audit" in hits[0].assessment_reason


# ── VAULT.TLS.PLAINTEXT ─────────────────────────────────────────────────────────
def test_tls_plaintext_fire_and_pass():
    assert len(fire("VAULT.TLS.PLAINTEXT", server(base="http://vault.internal:8200"))) == 1
    assert fire("VAULT.TLS.PLAINTEXT", server(base="https://vault.internal:8200")) == []


# ── VAULT.TOKEN.ROOT_IN_USE ─────────────────────────────────────────────────────
def test_token_root_fire_scoped_pass():
    hits = fire("VAULT.TOKEN.ROOT_IN_USE", server(token="token_root"))
    assert len(hits) == 1 and "'root' policy" in hits[0].observation
    assert fire("VAULT.TOKEN.ROOT_IN_USE", server(token="token_scoped")) == []


def test_token_root_not_assessable_when_lookup_denied():
    s = server(token="token_scoped", collection={"auth/token/lookup-self": _FORBIDDEN})
    hits = fire("VAULT.TOKEN.ROOT_IN_USE", s)
    assert len(hits) == 1 and hits[0].assessable is False


# ── VAULT.SEAL.LOW_THRESHOLD ────────────────────────────────────────────────────
def test_seal_low_threshold_fires_on_one():
    hits = fire("VAULT.SEAL.LOW_THRESHOLD", server(seal="seal_status_weak"))
    assert len(hits) == 1 and "unseal-key threshold t=1" in hits[0].observation


def test_seal_low_threshold_recovery_wording():
    hits = fire("VAULT.SEAL.LOW_THRESHOLD", server(seal="seal_status_autounseal"))
    assert len(hits) == 1 and "recovery-key" in hits[0].observation


def test_seal_low_threshold_quiet_on_quorum():
    assert fire("VAULT.SEAL.LOW_THRESHOLD", server(seal="seal_status_hardened")) == []


def test_seal_low_threshold_not_assessable_when_denied():
    s = server(seal="seal_status_weak", collection={"sys/seal-status": _FORBIDDEN})
    hits = fire("VAULT.SEAL.LOW_THRESHOLD", s)
    assert len(hits) == 1 and hits[0].assessable is False


# ── VAULT.SERVER.NOT_ASSESSED ───────────────────────────────────────────────────
def test_server_not_assessed_reports_only_uncovered_denials():
    s = server(collection={"sys/mounts": _FORBIDDEN,
                           "sys/audit": _FORBIDDEN})   # audit has its own dedicated gap rule
    hits = fire("VAULT.SERVER.NOT_ASSESSED", s)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "sys/mounts" in hits[0].observation


def test_server_not_assessed_quiet_when_all_ok():
    assert fire("VAULT.SERVER.NOT_ASSESSED", server()) == []


# ── VAULT.MOUNT.DYNAMIC_NO_TTL_OVERRIDE ─────────────────────────────────────────
def test_mount_dynamic_no_ttl_fire_and_passes():
    hits = fire("VAULT.MOUNT.DYNAMIC_NO_TTL_OVERRIDE", mount("database/"))
    assert len(hits) == 1 and sev(hits, "VAULT.MOUNT.DYNAMIC_NO_TTL_OVERRIDE") == ["low"]
    assert "inherit the system default" in hits[0].observation
    # a tuned dynamic engine, a kv engine, and cubbyhole must all stay quiet
    assert fire("VAULT.MOUNT.DYNAMIC_NO_TTL_OVERRIDE", mount("pki-tuned/")) == []
    assert fire("VAULT.MOUNT.DYNAMIC_NO_TTL_OVERRIDE", mount("secret/")) == []
    assert fire("VAULT.MOUNT.DYNAMIC_NO_TTL_OVERRIDE", mount("cubbyhole/")) == []


# ── VAULT.POLICY.SUDO_GRANT ─────────────────────────────────────────────────────
def test_policy_sudo_grant_critical_on_broad_high_on_narrow():
    hits = fire("VAULT.POLICY.SUDO_GRANT", policy("admin-sudo"))
    assert len(hits) == 1 and sev(hits, "VAULT.POLICY.SUDO_GRANT") == ["critical"]
    assert "sys/*" in hits[0].observation
    narrow = fire("VAULT.POLICY.SUDO_GRANT", policy("narrow-sudo"))
    assert len(narrow) == 1 and sev(narrow, "VAULT.POLICY.SUDO_GRANT") == ["high"]


def test_policy_sudo_grant_quiet_without_sudo():
    assert fire("VAULT.POLICY.SUDO_GRANT", policy("app-scoped")) == []
    assert fire("VAULT.POLICY.SUDO_GRANT", policy("write-all")) == []


# ── VAULT.POLICY.WILDCARD_WRITE ─────────────────────────────────────────────────
def test_policy_wildcard_write_fire_and_pass():
    hits = fire("VAULT.POLICY.WILDCARD_WRITE", policy("write-all"))
    assert len(hits) == 1 and "every path" in hits[0].observation
    # "*" with only read/list is broad-read, not write-everywhere → quiet
    assert fire("VAULT.POLICY.WILDCARD_WRITE", policy("read-all")) == []
    # a scoped path is never "*"
    assert fire("VAULT.POLICY.WILDCARD_WRITE", policy("app-scoped")) == []


# ── VAULT.AUTH.APPROLE_UNBOUNDED ────────────────────────────────────────────────
def test_approle_unbounded_fire_and_pass():
    hits = fire("VAULT.AUTH.APPROLE_UNBOUNDED", role("approle_unbounded"))
    assert len(hits) == 1 and "bind_secret_id=false" in hits[0].observation
    assert fire("VAULT.AUTH.APPROLE_UNBOUNDED", role("approle_bound")) == []
    # wrong auth type never matches
    assert fire("VAULT.AUTH.APPROLE_UNBOUNDED", role("jwt_unbounded")) == []


# ── VAULT.AUTH.JWT_NO_BOUND_CLAIMS ──────────────────────────────────────────────
def test_jwt_no_bound_claims_fire_and_pass():
    hits = fire("VAULT.AUTH.JWT_NO_BOUND_CLAIMS", role("jwt_unbounded"))
    assert len(hits) == 1 and "no bound_claims" in hits[0].observation
    assert fire("VAULT.AUTH.JWT_NO_BOUND_CLAIMS", role("jwt_bound")) == []
    assert fire("VAULT.AUTH.JWT_NO_BOUND_CLAIMS", role("approle_unbounded")) == []


# ── VAULT.AUTH.KUBERNETES_WILDCARD_BINDING ──────────────────────────────────────
def test_kubernetes_wildcard_binding_fire_and_pass():
    hits = fire("VAULT.AUTH.KUBERNETES_WILDCARD_BINDING", role("kubernetes_wildcard"))
    assert len(hits) == 1 and "\"*\"" in hits[0].observation
    assert fire("VAULT.AUTH.KUBERNETES_WILDCARD_BINDING", role("kubernetes_scoped")) == []


# ── policy parsing (pure) ───────────────────────────────────────────────────────
def test_policy_paths_parses_hcl_and_json_and_tolerates_garbage():
    hcl = _policy_paths(FIX["policies"]["admin-sudo"])
    assert {"path": "sys/*", "capabilities": ["read", "list", "sudo"]} in hcl
    js = _policy_paths(FIX["policies"]["json-ro"])
    assert js == [{"path": "secret/data/team/*", "capabilities": ["read", "list"]}]
    assert _policy_paths(None) == []
    assert _policy_paths("not a policy") == []


# ── NHI extraction ──────────────────────────────────────────────────────────────
def _kinds(resources) -> dict:
    out: dict = {}
    for r in resources:
        out[r.kind] = out.get(r.kind, 0) + 1
    return out


def _derived() -> Collected:
    base = [server(), policy("app-scoped"), policy("write-all"),
            role("approle_unbounded"), role("approle_bound"),
            role("jwt_unbounded"), role("kubernetes_wildcard")]
    return derive_identities("vault", Collected(resources=list(base)))


def test_vault_has_an_extractor():
    assert "vault" in IDENTITY_EXTRACTORS


def test_roles_become_identities_with_correct_type_and_externality():
    col = _derived()
    ids = {r.name: r for r in col.resources if r.kind == "identity"}
    assert ids["approle/approle_unbounded"].labels["identity_type"] == "approle_role"
    assert ids["approle/approle_unbounded"].raw["external"] is False
    # jwt/oidc federate an outside IdP → external
    assert ids["jwt/jwt_unbounded"].labels["identity_type"] == "jwt_role"
    assert ids["jwt/jwt_unbounded"].raw["external"] is True


def test_approle_secret_id_credential_only_when_bound():
    col = _derived()
    creds = [r for r in col.resources if r.kind == "credential"]
    owners = {c.raw["owner_ext_id"] for c in creds}
    bound = next(r for r in col.resources
                 if r.kind == "identity" and r.name == "approle/approle_bound")
    unbound = next(r for r in col.resources
                   if r.kind == "identity" and r.name == "approle/approle_unbounded")
    assert bound.ext_id in owners           # bind_secret_id=true → a secret_id credential
    assert unbound.ext_id not in owners     # bind_secret_id=false → none (absence, not silence)
    assert all(c.raw["plaintext"] is False for c in creds)   # never a value


def test_policy_grants_resolve_to_collected_policy():
    col = _derived()
    grants = [r for r in col.resources if r.kind == "grant"]
    # jwt_unbounded holds app-scoped + read-all; app-scoped is a collected vault_policy
    jwt_id = next(r for r in col.resources
                  if r.kind == "identity" and r.name == "jwt/jwt_unbounded")
    targets = {g.raw["target"] for g in grants if g.raw["identity_ext_id"] == jwt_id.ext_id}
    assert {"app-scoped", "read-all"} <= targets
    edge_kinds = {(e.src_ext_id, e.kind, e.dst_ext_id) for e in col.edges}
    app_grant = next(g for g in grants if g.raw["target"] == "app-scoped"
                     and g.raw["identity_ext_id"] == jwt_id.ext_id)
    # resolves to the collected policy resource…
    assert (app_grant.ext_id, "grants_access", "vault-policy-app-scoped") in edge_kinds
    # …and every grant is linked back to its holder
    for g in grants:
        assert (g.ext_id, "granted_to", g.raw["identity_ext_id"]) in edge_kinds
