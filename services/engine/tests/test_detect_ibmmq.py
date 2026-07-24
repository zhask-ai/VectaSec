"""IBM MQ connector parse-layer + detector + NHI tests. Fully offline: no httpx client is ever
constructed, no mqweb server is touched. The golden fixture holds MQSC runCommandJSON `parameters`
dicts shaped exactly as the connector consumes them, so a shape drift between the connector's
parse layer and the rulepack fails here first."""
import json
import pathlib

from vectasec.contracts import ScanContext, Collected
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.ibmmq import (
    parse_qmgr, parse_channel, parse_queue, parse_authrec, _attr,
)
from vectasec.detect import ibmmq as det

FIX = json.loads((pathlib.Path(__file__).parent / "fixtures" / "ibmmq_responses.json").read_text())


def _ctx(resources, config=None):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources, config=config or {})


def qmgr(scenario: str):
    s = FIX[scenario]
    return parse_qmgr(s["qmgr"]["queueManagerName"], "https://mq.example:9443",
                      s["qmgr"], s.get("authinfo"), s.get("authinfo_readable", False))


def channels(scenario: str):
    return [parse_channel(FIX[scenario]["qmgr"]["queueManagerName"], c)
            for c in FIX[scenario]["channels"]]


def queues(scenario: str):
    out = []
    s = FIX[scenario]
    authrecs = [parse_authrec(a) for a in s.get("authrecs", [])]
    for qp in s.get("queues", []):
        qname = qp["queueName"]
        matching = [a for a in authrecs if a["profile"] == qname]
        out.append(parse_queue(s["qmgr"]["queueManagerName"], qp, matching))
    return out


# ── registration + form fields ─────────────────────────────────────────────────
def test_connector_registered():
    assert "ibmmq" in CONNECTORS


def test_password_field_is_secret():
    fields = {f.key: f for f in CONNECTOR_FIELDS["ibmmq"]}
    assert fields["password"].secret is True
    assert not fields["base_url"].secret and not fields["username"].secret
    assert fields["base_url"].required and fields["qmgr"].required


# ── parse layer ──────────────────────────────────────────────────────────────
def test_attr_is_case_insensitive_and_alias_aware():
    p = {"channelType": "SVRCONN"}
    assert _attr(p, "chltype", "channelType") == "SVRCONN"
    assert _attr(p, "CHANNELTYPE") == "SVRCONN"          # case-insensitive
    assert _attr(p, "missing", default="x") == "x"


def test_parse_qmgr_reads_connauth_chlauth_authinfo():
    q = qmgr("hardened")
    assert q.kind == "ibmmq_qmgr" and q.ext_id == "ibmmq-qmgr-QMSAFE"
    assert q.raw["connauth"] == "SYSTEM.DEFAULT.AUTHINFO.IDPWOS"
    assert q.raw["chlauth_records"] == "ENABLED"          # normalized upper
    assert q.raw["authinfo_readable"] is True
    assert q.raw["chckclnt"] == "REQUIRED" and q.raw["chcklocl"] == "OPTIONAL"


def test_parse_qmgr_blank_connauth():
    q = qmgr("insecure")
    assert q.raw["connauth"] == ""
    assert q.raw["chlauth_records"] == "DISABLED"
    assert q.raw["authinfo_readable"] is False and q.raw["chckclnt"] is None


def test_parse_channel_classifies_svrconn_and_tls():
    by_name = {c.name: c for c in channels("insecure")}
    assert by_name["APP.SVRCONN"].raw["channel_type"] == "SVRCONN"
    assert by_name["APP.SVRCONN"].raw["mcauser"] == "" and by_name["APP.SVRCONN"].raw["sslciph"] == ""
    assert by_name["ADMIN.SVRCONN"].raw["mcauser"] == "mqm"
    assert by_name["TO.QM2"].raw["channel_type"] == "SENDER"
    tls = parse_channel("QM1", FIX["tls_optional_cauth_channel"])
    assert tls.raw["sslciph"] and tls.raw["sslcauth"] == "OPTIONAL"


def test_parse_authrec_normalizes_authorities():
    rec = parse_authrec({"profileName": "APP.ORDERS", "objectType": "queue",
                         "entityName": "mqm", "entityType": "group", "authorityAdd": ["ALL", "Put"]})
    assert rec["entity"] == "mqm" and rec["entity_type"] == "GROUP"
    assert rec["authorities"] == ["all", "put"]
    # string form (space/comma separated) is accepted too
    rec2 = parse_authrec({"profileName": "Q", "entityName": "u", "authorityAdd": "put, get browse"})
    assert rec2["authorities"] == ["put", "get", "browse"]


# ── qmgr detectors ───────────────────────────────────────────────────────────
def test_connauth_no_object():
    assert det.connauth_missing(qmgr("insecure"), _ctx([]))                 # blank CONNAUTH → fires
    assert det.connauth_missing(qmgr("hardened"), _ctx([])) == []           # CONNAUTH set → clean


def test_connauth_client_check_disabled_severity_and_not_assessable():
    # OPTIONAL → fires at high (severity override)
    q_opt = parse_qmgr("QM3", "u", FIX["chckclnt_optional"]["qmgr"],
                       FIX["chckclnt_optional"]["authinfo"], True)
    hits = det.connauth_chckclnt_open(q_opt, _ctx([]))
    assert hits and hits[0].severity == "high"
    # REQUIRED → clean
    assert det.connauth_chckclnt_open(qmgr("hardened"), _ctx([])) == []
    # blank CONNAUTH is owned by NO_OBJECT, not this rule
    assert det.connauth_chckclnt_open(qmgr("insecure"), _ctx([])) == []
    # CONNAUTH set but AUTHINFO unreadable → not assessable
    q_unk = parse_qmgr("QMx", "u", {"connectionAuthentication": "A.INFO"}, None, False)
    na = det.connauth_chckclnt_open(q_unk, _ctx([]))
    assert na and na[0].assessable is False and na[0].assessment_reason


def test_connauth_none_is_critical():
    q_none = parse_qmgr("QMn", "u", {"connectionAuthentication": "A.INFO"},
                        {"checkClient": "none"}, True)
    hits = det.connauth_chckclnt_open(q_none, _ctx([]))
    assert hits and hits[0].severity == "critical"


def test_chlauth_disabled():
    assert det.chlauth_disabled(qmgr("insecure"), _ctx([]))
    assert det.chlauth_disabled(qmgr("hardened"), _ctx([])) == []


def test_chcklocl_none_low():
    q = parse_qmgr("QM3", "u", FIX["chckclnt_optional"]["qmgr"],
                   FIX["chckclnt_optional"]["authinfo"], True)      # chcklocl=none
    assert det.connauth_chcklocl_none(q, _ctx([]))
    assert det.connauth_chcklocl_none(qmgr("hardened"), _ctx([])) == []   # OPTIONAL → clean
    # authinfo unreadable → not evaluated (returns [], the NOT_ASSESSABLE is owned by CLIENT_CHECK)
    assert det.connauth_chcklocl_none(qmgr("insecure"), _ctx([])) == []


# ── channel detectors ────────────────────────────────────────────────────────
def test_mcauser_privileged_and_blank():
    by = {c.name: c for c in channels("insecure")}
    assert det.channel_mcauser_privileged(by["ADMIN.SVRCONN"], _ctx([]))     # mqm → critical
    assert det.channel_mcauser_privileged(by["APP.SVRCONN"], _ctx([])) == []  # blank ≠ privileged
    assert det.channel_mcauser_blank(by["APP.SVRCONN"], _ctx([]))            # blank → fires
    assert det.channel_mcauser_blank(by["ADMIN.SVRCONN"], _ctx([])) == []    # mqm ≠ blank
    # a hardened svrconn (named low-priv user) fires neither
    hard = channels("hardened")[0]
    assert det.channel_mcauser_privileged(hard, _ctx([])) == []
    assert det.channel_mcauser_blank(hard, _ctx([])) == []
    # a non-SVRCONN channel is out of scope for both
    assert det.channel_mcauser_blank(by["TO.QM2"], _ctx([])) == []


def test_channel_no_tls_and_sslcauth_optional():
    by = {c.name: c for c in channels("insecure")}
    assert det.channel_no_tls(by["APP.SVRCONN"], _ctx([]))                   # sslciph blank → fires
    hard = channels("hardened")[0]
    assert det.channel_no_tls(hard, _ctx([])) == []                          # TLS set → clean
    assert det.channel_sslcauth_optional(hard, _ctx([])) == []              # SSLCAUTH required → clean
    tls_opt = parse_channel("QM1", FIX["tls_optional_cauth_channel"])
    assert det.channel_sslcauth_optional(tls_opt, _ctx([]))                 # TLS + OPTIONAL → fires
    assert det.channel_sslcauth_optional(by["APP.SVRCONN"], _ctx([])) == []  # no TLS → NO_TLS owns it


def test_system_svrconn_unprotected_is_cross_resource():
    q = qmgr("insecure")   # CHLAUTH disabled
    by = {c.name: c for c in channels("insecure")}
    sys_chan = by["SYSTEM.DEF.SVRCONN"]
    assert det.system_svrconn_unprotected(sys_chan, _ctx([q, sys_chan]))    # SYSTEM + CHLAUTH off
    # same channel, but CHLAUTH enabled → does not fire
    q_safe = qmgr("hardened")
    sys_chan2 = parse_channel("QMSAFE", {"channelName": "SYSTEM.DEF.SVRCONN",
                                         "channelType": "svrconn", "messageChannelAgentUserIdentifier": ""})
    assert det.system_svrconn_unprotected(sys_chan2, _ctx([q_safe, sys_chan2])) == []
    # a non-SYSTEM channel never fires this rule even with CHLAUTH off
    assert det.system_svrconn_unprotected(by["APP.SVRCONN"], _ctx([q, by["APP.SVRCONN"]])) == []


# ── queue detector ───────────────────────────────────────────────────────────
def test_queue_wide_authority():
    q = queues("insecure")[0]              # APP.ORDERS: mqm group +all, appuser +put/+get
    hits = det.queue_wide_authority(q, _ctx([]))
    assert len(hits) == 1 and "mqm" in hits[0].observation and hits[0].severity in (None, "high")
    safe = queues("hardened")[0]           # APP.PAYMENTS: appuser +put/+get only
    assert det.queue_wide_authority(safe, _ctx([])) == []


# ── NHI ──────────────────────────────────────────────────────────────────────
def test_has_extractor():
    assert "ibmmq" in IDENTITY_EXTRACTORS


def _derive(scenario):
    base = [qmgr(scenario)] + channels(scenario) + queues(scenario)
    return derive_identities("ibmmq", Collected(resources=list(base)))


def test_nhi_channel_mcauser_and_authrec_identities():
    col = _derive("insecure")
    identities = {i.name: i for i in col.resources if i.kind == "identity"}
    # blank MCAUSER svrconn → «flowed» identity; mqm channel → admin identity
    assert "«flowed»" in identities
    assert identities["mqm"].labels["identity_type"] == "admin"
    # authrec principals become identities too
    assert "appuser" in identities
    # groups keep their type
    assert identities["mqm"].raw["system"] == "ibmmq"


def test_nhi_grants_edges_and_no_credentials():
    col = _derive("insecure")
    grants = [g for g in col.resources if g.kind == "grant"]
    assert grants
    # svrconn access grant is wildcard when MCAUSER is blank or privileged
    svr = [g for g in grants if g.raw["action"] == "svrconn-access"]
    assert svr and any(g.raw["wildcard"] for g in svr)
    # MQ exposes no stored passwords over REST → no credential resources
    assert not [r for r in col.resources if r.kind == "credential"]
    # every grant carries a granted_to edge to its identity
    edge_kinds = {(e.src_ext_id, e.kind) for e in col.edges}
    for g in grants:
        assert (g.ext_id, "granted_to") in edge_kinds


def test_nhi_authrec_all_authority_is_wildcard_grant():
    col = _derive("insecure")
    mqm_grants = [g for g in col.resources if g.kind == "grant"
                  and g.raw.get("identity_ext_id", "").endswith(":mqm")]
    assert any(g.raw["wildcard"] for g in mqm_grants)   # mqm holds +all on APP.ORDERS
