"""Unit tests for the coordination rulepack + connector parse layer + NHI extraction.

Offline: no httpx client is built, no raw socket is opened, no live etcd/ZooKeeper/Nacos/Consul
is touched. Resources are built by feeding the golden fixtures (fixtures/coordination_responses
.json) — the exact HTTP bodies and 4lw text the systems return — through the connector's OWN
parse layer, so the detectors here run against precisely the shapes connect/coordination.py
emits. A shape drift between connector and rulepack fails a test rather than mis-firing live.

Every rule gets a FIRE case, a DOES-NOT-FIRE (pass) case, and a NOT-ASSESSABLE case.
"""
import json
import pathlib

from vectasec.contracts import Collected, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS, DETECTORS
import vectasec.detect.coordination  # noqa: F401  — import registers the rulepack
from vectasec.connect.coordination import (
    _consul_policy_meta, _consul_token_meta, parse_consul, parse_etcd, parse_nacos,
    parse_zookeeper,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "coordination_responses.json").read_text()
)
E, Z, N, C = FIX["etcd"], FIX["zookeeper"], FIX["nacos"], FIX["consul"]

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("COORD.")}

EXPECTED_RULES = {
    "COORD.ETCD.AUTH_DISABLED",
    "COORD.ETCD.UNAUTHENTICATED_READ",
    "COORD.ETCD.CLIENT_TLS_DISABLED",
    "COORD.ETCD.PEER_TLS_DISABLED",
    "COORD.ZOOKEEPER.FOUR_LETTER_WORDS_EXPOSED",
    "COORD.ZOOKEEPER.NO_SASL_AUTH",
    "COORD.ZOOKEEPER.NO_TLS",
    "COORD.NACOS.AUTH_DISABLED",
    "COORD.NACOS.DEFAULT_CREDENTIALS",
    "COORD.NACOS.CONSOLE_EXPOSED",
    "COORD.NACOS.AUTH_BYPASS_CVE",
    "COORD.CONSUL.ACL_DEFAULT_ALLOW",
    "COORD.CONSUL.ANONYMOUS_TOKEN_POLICIES",
    "COORD.CONSUL.WILDCARD_INTENTION",
    "COORD.CONSUL.GOSSIP_ENCRYPTION_DISABLED",
}


# ── builders: fixture → parse layer → Resource ────────────────────────────────
def etcd(*, tls=False, version="fixture", status="fixture", auth="auth_off", kv="read_ok",
         peer="plaintext", user_roles=False):
    vj = E["version"] if version == "fixture" else version
    sj = E["status"] if status == "fixture" else status
    ap = E["auth_probe"][auth] if isinstance(auth, str) else auth
    kvp = E["kv_probe"][kv] if isinstance(kv, str) else kv
    pp = E["peer_probe"][peer] if isinstance(peer, str) else peer
    return parse_etcd("10.0.0.10", 2379, tls=tls, version_json=vj, status_json=sj,
                      auth_probe=ap, role_probe=E["role_probe"], kv_probe=kvp, peer_probe=pp,
                      peer_port=2380, user_roles=(E["user_roles"] if user_roles else None))


def zk(*, ruok="imok", conf="conf_open", envi="envi", stat="stat", tls=False):
    return parse_zookeeper("10.0.0.11", 2181, tls=tls,
                           ruok=(None if ruok is None else Z.get(ruok, ruok)),
                           conf=(None if conf is None else Z.get(conf, conf)),
                           envi=(None if envi is None else Z.get(envi, envi)),
                           stat=(None if stat is None else Z.get(stat, stat)))


def nacos(*, state="state_auth_off", console="console_reachable", login="login_default_invalid",
          bypass="bypass_blocked", users=None, admin_users=None, tls=False):
    return parse_nacos(
        "10.0.0.12", 8848, tls=tls,
        state_json=(N[state] if isinstance(state, str) else state),
        console_probe=(N[console] if isinstance(console, str) else console),
        login_probe=(N[login] if isinstance(login, str) else login),
        bypass_probe=(N[bypass] if isinstance(bypass, str) else bypass),
        users_json=users, admin_users=admin_users)


def consul(*, agent="agent_acl_allow", anon="anon_no_policies", intentions="intentions_explicit",
           tokens=None, policies=None, tls=False):
    return parse_consul(
        "10.0.0.13", 8500, tls=tls,
        agent_self=(C[agent] if isinstance(agent, str) else agent),
        anon_token=(C[anon] if isinstance(anon, str) else anon),
        intentions=(C[intentions] if isinstance(intentions, str) else intentions),
        tokens=tokens, policies=policies)


def ctx(*resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


def fire(rule_id, resource):
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to kind={resource.kind}"
    return d.fn(resource, ctx(resource)) or []


def sev(hits, rule_id):
    base = RULES[rule_id].severity
    return [h.severity or base for h in hits]


def is_gap(hits):
    return len(hits) == 1 and hits[0].assessable is False and bool(hits[0].assessment_reason)


# ── pack shape / registration ─────────────────────────────────────────────────
def test_expected_rules_all_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rules_only_run_on_coord_kinds():
    for d in RULES.values():
        assert all(k.startswith("coord_") for k in d.kinds), d.rule_id


def test_connector_registered_and_secret_fields_marked():
    assert "coord" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["coord"]}
    assert fields["password"].secret and fields["token"].secret
    assert fields["system"].required and fields["host"].required
    assert not fields["host"].secret and not fields["port"].secret


# ══ etcd ═══════════════════════════════════════════════════════════════════════
def test_etcd_auth_disabled():
    hits = fire("COORD.ETCD.AUTH_DISABLED", etcd(auth="auth_off"))
    assert len(hits) == 1 and hits[0].assessable
    assert "authentication is not enabled" in hits[0].observation
    assert sev(hits, "COORD.ETCD.AUTH_DISABLED") == ["critical"]
    assert fire("COORD.ETCD.AUTH_DISABLED", etcd(auth="auth_on_readable")) == []
    assert fire("COORD.ETCD.AUTH_DISABLED", etcd(auth="auth_on_denied")) == []
    assert is_gap(fire("COORD.ETCD.AUTH_DISABLED", etcd(auth="unreachable")))


def test_etcd_unauthenticated_read():
    hits = fire("COORD.ETCD.UNAUTHENTICATED_READ", etcd(kv="read_ok"))
    assert len(hits) == 1 and "cluster header" in hits[0].observation
    assert fire("COORD.ETCD.UNAUTHENTICATED_READ", etcd(kv="read_denied")) == []
    assert is_gap(fire("COORD.ETCD.UNAUTHENTICATED_READ", etcd(kv="unreachable")))


def test_etcd_client_tls_disabled():
    hits = fire("COORD.ETCD.CLIENT_TLS_DISABLED", etcd(tls=False))
    assert len(hits) == 1 and "plaintext" in hits[0].observation.lower()
    assert fire("COORD.ETCD.CLIENT_TLS_DISABLED", etcd(tls=True)) == []
    # unreachable client API → transport not observed → not assessable
    assert is_gap(fire("COORD.ETCD.CLIENT_TLS_DISABLED", etcd(version=None, status=None)))


def test_etcd_peer_tls_disabled():
    hits = fire("COORD.ETCD.PEER_TLS_DISABLED", etcd(peer="plaintext"))
    assert len(hits) == 1 and "peer TLS is off" in hits[0].observation
    assert fire("COORD.ETCD.PEER_TLS_DISABLED", etcd(peer="tls")) == []
    assert is_gap(fire("COORD.ETCD.PEER_TLS_DISABLED", etcd(peer="unreachable")))


# ══ ZooKeeper ══════════════════════════════════════════════════════════════════
def test_zk_four_letter_words_exposed():
    hits = fire("COORD.ZOOKEEPER.FOUR_LETTER_WORDS_EXPOSED", zk())
    assert len(hits) == 1 and "'conf'" in hits[0].observation
    assert sev(hits, "COORD.ZOOKEEPER.FOUR_LETTER_WORDS_EXPOSED") == ["high"]
    # only ruok answers, the sensitive commands are off the whitelist → not exposed
    guarded = zk(conf="conf_blocked", envi="envi_blocked", stat="stat_blocked")
    assert fire("COORD.ZOOKEEPER.FOUR_LETTER_WORDS_EXPOSED", guarded) == []
    # nothing answered at all → not assessable
    dead = zk(ruok=None, conf=None, envi=None, stat=None)
    assert is_gap(fire("COORD.ZOOKEEPER.FOUR_LETTER_WORDS_EXPOSED", dead))


def test_zk_no_sasl_auth():
    hits = fire("COORD.ZOOKEEPER.NO_SASL_AUTH", zk(conf="conf_open"))
    assert len(hits) == 1 and "world:anyone:cdrwa" in hits[0].observation
    assert fire("COORD.ZOOKEEPER.NO_SASL_AUTH", zk(conf="conf_hardened")) == []
    # conf that omits the flag → cannot be assessed from 4lw
    assert is_gap(fire("COORD.ZOOKEEPER.NO_SASL_AUTH", zk(conf="conf_minimal")))


def test_zk_no_tls():
    hits = fire("COORD.ZOOKEEPER.NO_TLS", zk(conf="conf_open"))
    assert len(hits) == 1 and "secureClientPort=-1" in hits[0].observation
    assert fire("COORD.ZOOKEEPER.NO_TLS", zk(conf="conf_hardened")) == []
    assert is_gap(fire("COORD.ZOOKEEPER.NO_TLS", zk(conf="conf_minimal")))


# ══ Nacos ══════════════════════════════════════════════════════════════════════
def test_nacos_auth_disabled():
    hits = fire("COORD.NACOS.AUTH_DISABLED", nacos(state="state_auth_off"))
    assert len(hits) == 1 and "auth_enabled=false" in hits[0].observation
    assert sev(hits, "COORD.NACOS.AUTH_DISABLED") == ["critical"]
    assert fire("COORD.NACOS.AUTH_DISABLED", nacos(state="state_auth_on")) == []
    assert is_gap(fire("COORD.NACOS.AUTH_DISABLED", nacos(state="state_no_flag")))


def test_nacos_default_credentials():
    hits = fire("COORD.NACOS.DEFAULT_CREDENTIALS", nacos(login="login_default_valid"))
    assert len(hits) == 1 and "nacos/nacos" in hits[0].observation
    assert fire("COORD.NACOS.DEFAULT_CREDENTIALS", nacos(login="login_default_invalid")) == []
    assert is_gap(fire("COORD.NACOS.DEFAULT_CREDENTIALS", nacos(login="login_unknown")))


def test_nacos_console_exposed_escalates_when_auth_off():
    # auth on + reachable console → medium (network exposure)
    on = nacos(state="state_auth_on", console="console_reachable")
    hits = fire("COORD.NACOS.CONSOLE_EXPOSED", on)
    assert len(hits) == 1 and sev(hits, "COORD.NACOS.CONSOLE_EXPOSED") == ["medium"]
    # auth off + reachable console → high (unauthenticated control panel)
    off = nacos(state="state_auth_off", console="console_reachable")
    assert sev(fire("COORD.NACOS.CONSOLE_EXPOSED", off), "COORD.NACOS.CONSOLE_EXPOSED") == ["high"]
    assert fire("COORD.NACOS.CONSOLE_EXPOSED", nacos(console="console_protected")) == []
    assert is_gap(fire("COORD.NACOS.CONSOLE_EXPOSED", nacos(console="console_unknown")))


def test_nacos_auth_bypass_cve_empirical_and_version():
    # empirical: the Nacos-Server User-Agent actually returned the user list
    hits = fire("COORD.NACOS.AUTH_BYPASS_CVE", nacos(bypass="bypass_ok"))
    assert len(hits) == 1 and hits[0].assessable and "Nacos-Server" in hits[0].observation
    assert hits[0].source_ref.get("cve") == "CVE-2021-29441"
    # version fallback: <1.4.1 fires when the probe was inconclusive
    old = nacos(bypass="bypass_unknown", state="state_old_version")
    hits = fire("COORD.NACOS.AUTH_BYPASS_CVE", old)
    assert len(hits) == 1 and "1.3.1" in hits[0].observation
    # patched version passes; a rejected (403) bypass probe passes
    assert fire("COORD.NACOS.AUTH_BYPASS_CVE", nacos(bypass="bypass_unknown", state="state_auth_on")) == []
    assert fire("COORD.NACOS.AUTH_BYPASS_CVE", nacos(bypass="bypass_blocked", state="state_auth_on")) == []
    # unparseable version + inconclusive probe → not assessable, never a silent pass
    unknown = nacos(bypass="bypass_unknown", state="state_unparseable")
    assert is_gap(fire("COORD.NACOS.AUTH_BYPASS_CVE", unknown))


# ══ Consul ═════════════════════════════════════════════════════════════════════
def test_consul_acl_default_allow():
    hits = fire("COORD.CONSUL.ACL_DEFAULT_ALLOW", consul(agent="agent_acl_allow"))
    assert len(hits) == 1 and "ACLDefaultPolicy=allow" in hits[0].observation
    assert sev(hits, "COORD.CONSUL.ACL_DEFAULT_ALLOW") == ["critical"]
    # ACLs disabled entirely also fires
    disabled = fire("COORD.CONSUL.ACL_DEFAULT_ALLOW", consul(agent="agent_acl_disabled"))
    assert len(disabled) == 1 and "off entirely" in disabled[0].observation
    assert fire("COORD.CONSUL.ACL_DEFAULT_ALLOW", consul(agent="agent_hardened")) == []
    assert is_gap(fire("COORD.CONSUL.ACL_DEFAULT_ALLOW", consul(agent="agent_no_acl_fields")))


def test_consul_anonymous_token_policies():
    hits = fire("COORD.CONSUL.ANONYMOUS_TOKEN_POLICIES", consul(anon="anon_with_policies"))
    assert len(hits) == 1 and "global-management" in hits[0].observation
    assert fire("COORD.CONSUL.ANONYMOUS_TOKEN_POLICIES", consul(anon="anon_no_policies")) == []
    assert is_gap(fire("COORD.CONSUL.ANONYMOUS_TOKEN_POLICIES", consul(anon="anon_denied")))


def test_consul_wildcard_intention():
    hits = fire("COORD.CONSUL.WILDCARD_INTENTION", consul(intentions="intentions_wildcard"))
    assert len(hits) == 1 and "SourceName '*'" in hits[0].observation
    # a '*'→specific allow still fires (any-source), a fully explicit list passes
    assert fire("COORD.CONSUL.WILDCARD_INTENTION", consul(intentions="intentions_wildcard_scoped"))
    assert fire("COORD.CONSUL.WILDCARD_INTENTION", consul(intentions="intentions_explicit")) == []
    assert is_gap(fire("COORD.CONSUL.WILDCARD_INTENTION", consul(intentions="intentions_denied")))


def test_consul_gossip_encryption_disabled():
    hits = fire("COORD.CONSUL.GOSSIP_ENCRYPTION_DISABLED", consul(agent="agent_acl_allow"))
    assert len(hits) == 1 and "serf_lan.encrypted=false" in hits[0].observation
    assert fire("COORD.CONSUL.GOSSIP_ENCRYPTION_DISABLED", consul(agent="agent_hardened")) == []
    assert is_gap(fire("COORD.CONSUL.GOSSIP_ENCRYPTION_DISABLED", consul(agent="agent_no_acl_fields")))


# ══ parse-layer sanity ═════════════════════════════════════════════════════════
def test_parse_kinds_are_distinct_and_prefixed():
    assert etcd().kind == "coord_etcd"
    assert zk().kind == "coord_zookeeper"
    assert nacos().kind == "coord_nacos"
    assert consul().kind == "coord_consul"


def test_consul_token_meta_drops_secret_id():
    meta = _consul_token_meta(C["tokens"])
    blob = json.dumps(meta)
    assert "SHOULD-NEVER-APPEAR" not in blob   # SecretID is never read into metadata
    assert meta[0]["accessor_id"] and meta[0]["policies"] == ["web-read"]


# ══ NHI extraction ═════════════════════════════════════════════════════════════
def test_extractor_registered():
    assert "coord" in IDENTITY_EXTRACTORS


def _consul_derived():
    r = consul(agent="agent_acl_allow", anon="anon_with_policies",
               tokens=_consul_token_meta(C["tokens"]), policies=_consul_policy_meta(C["policies"]))
    return derive_identities("coord", Collected(resources=[r]))


def test_consul_tokens_become_identities_credentials_grants():
    col = _consul_derived()
    ids = {i.name: i for i in col.resources if i.kind == "identity"}
    assert set(ids) == {"web service", "ci admin", "anonymous"}
    for i in ids.values():
        assert i.labels["identity_type"] == "acl_token" and i.labels["system"] == "consul"

    creds = [c for c in col.resources if c.kind == "credential"]
    # one credential per NAMED token; the anonymous token has no secret of its own
    assert len(creds) == 2
    for c in creds:
        assert c.raw["credential_type"] == "acl_token" and c.raw["present"] is True
        assert c.raw["plaintext"] is False
        assert any(e.kind == "credential_of" and e.src_ext_id == c.ext_id for e in col.edges)

    grants = [g for g in col.resources if g.kind == "grant"]
    gm = next(g for g in grants if g.raw["target"] == "global-management"
              and g.labels["identity"] == ids["ci admin"].ext_id)
    assert gm.raw["wildcard"] is True
    webr = next(g for g in grants if g.raw["target"] == "web-read")
    assert webr.raw["wildcard"] is False
    # the anonymous token's policy is a grant on the anonymous identity
    anon_grant = next(g for g in grants if g.labels["identity"] == ids["anonymous"].ext_id)
    assert anon_grant.raw["target"] == "global-management" and anon_grant.raw["wildcard"] is True
    for g in grants:
        assert any(e.kind == "granted_to" and e.src_ext_id == g.ext_id
                   and e.dst_ext_id == g.labels["identity"] for e in col.edges)


def test_consul_secret_id_never_crosses_into_nhi():
    col = _consul_derived()
    blob = json.dumps([{"raw": r.raw, "labels": r.labels} for r in col.resources])
    assert "SHOULD-NEVER-APPEAR" not in blob


def test_nacos_users_become_identities_admin_gets_grant():
    r = nacos(users=N["bypass_ok"]["body"], admin_users=N["admin_users"])
    # the collected nacos resource stores usernames only — never the password hashes
    assert "$2a$10$" not in json.dumps(r.raw)
    assert r.raw["users"] == ["nacos", "svc-config"]
    col = derive_identities("coord", Collected(resources=[r]))
    ids = {i.name: i for i in col.resources if i.kind == "identity"}
    assert set(ids) == {"nacos", "svc-config"}
    assert all(i.labels["identity_type"] == "service_account" for i in ids.values())
    grants = [g for g in col.resources if g.kind == "grant"]
    assert len(grants) == 1 and grants[0].labels["identity"] == ids["nacos"].ext_id
    assert grants[0].raw["target"] == "admin" and grants[0].raw["wildcard"] is True


def test_etcd_users_and_roles_become_identities_and_grants():
    r = etcd(auth="auth_on_readable", user_roles=True)
    col = derive_identities("coord", Collected(resources=[r]))
    ids = {i.name: i for i in col.resources if i.kind == "identity"}
    assert set(ids) == {"root", "alice"}
    grants = {g.raw["target"]: g for g in col.resources if g.kind == "grant"}
    assert grants["root"].raw["wildcard"] is True       # the etcd root role is god-mode
    assert grants["reader"].raw["wildcard"] is False
    for g in grants.values():
        assert any(e.kind == "granted_to" and e.src_ext_id == g.ext_id for e in col.edges)


def test_nhi_is_additive_and_all_edges_resolve():
    col = _consul_derived()
    ext_ids = {r.ext_id for r in col.resources}
    for e in col.edges:
        assert e.src_ext_id in ext_ids and e.dst_ext_id in ext_ids, (e.src_ext_id, e.dst_ext_id)
