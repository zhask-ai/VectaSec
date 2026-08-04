"""IBM MQ connector parse-layer + collect-wiring + detector + NHI tests. Fully offline: no httpx
client is ever constructed, no mqweb server is touched (collect() runs with `_run_mqsc` scripted
per MQSC qualifier). The golden fixture holds MQSC runCommandJSON `parameters` dicts shaped
exactly as the connector consumes them, so a shape drift between the connector's parse layer and
the rulepack fails here first.

The coverage-gap section is load-bearing: a queue manager that answers 403 to DISPLAY QMGR must
produce no finding from the rules that read its attributes and exactly one IBMMQ.SCAN.NOT_ASSESSABLE
naming them, because an unread attribute is neither blank nor clean."""
import json
import pathlib
import types

from vectasec.contracts import ScanContext, Collected
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS, DETECTORS
from vectasec.connect import ibmmq as conn
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
    # blank CONNAUTH → there is no AUTHINFO object to hold a CHCKLOCL, so this rule has nothing to
    # judge and CONNAUTH.NO_OBJECT (a critical) is what reports the queue manager.
    assert det.connauth_chcklocl_none(qmgr("insecure"), _ctx([])) == []
    assert det.connauth_missing(qmgr("insecure"), _ctx([]))
    # CONNAUTH named but its AUTHINFO denied → silent here, because CLIENT_CHECK_DISABLED files
    # the one not-assessable for that gap. Silence with the gap stated elsewhere, never alone.
    q_denied = parse_qmgr("QMx", "u", {"connectionAuthentication": "A.INFO"}, None, False)
    assert det.connauth_chcklocl_none(q_denied, _ctx([])) == []
    assert det.connauth_chckclnt_open(q_denied, _ctx([]))[0].assessable is False


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


# ── coverage gaps: a denied DISPLAY is not a hardened broker ─────────────────
# An MQWebAdminRO user without DISPLAY authority on the queue manager gets 403 on DISPLAY QMGR.
# Every attribute the qmgr rules read is then absent, and absent must behave as "unknown": no
# rule may fire on it, and the gap must be stated once rather than passed over.
DENIED = {"ok": False, "status": 403, "error": "http_403"}


def one(hits):
    assert len(hits) == 1, hits
    return hits[0]


def denied_qmgr(**kw):
    """The qmgr resource the connector builds when DISPLAY QMGR answers 403."""
    return parse_qmgr("QMRO", "https://mq.example:9443", {}, None, False,
                      errors={"qmgr": "http_403"}, qmgr_readable=False, **kw)


def test_denied_display_qmgr_fabricates_no_connauth_critical():
    q = denied_qmgr()
    assert q.raw["qmgr_readable"] is False
    assert q.raw["connauth"] is None and q.raw["chlauth_records"] is None   # absent, not blank
    assert det.connauth_missing(q, _ctx([])) == []          # the fabricated CRITICAL is gone
    assert det.connauth_chckclnt_open(q, _ctx([])) == []
    assert det.chlauth_disabled(q, _ctx([])) == []
    assert det.connauth_chcklocl_none(q, _ctx([])) == []


def test_denied_display_qmgr_files_one_not_assessable_naming_the_unevaluated_rules():
    h = one(det.scan_not_assessable(denied_qmgr(), _ctx([])))   # one per qmgr, not one per rule
    assert h.assessable is False and h.assessment_reason        # or it scores as a passed info
    assert "QMRO" in h.observation and "DISPLAY QMGR" in h.observation and "http_403" in h.observation
    for rule_id in ("IBMMQ.CONNAUTH.NO_OBJECT", "IBMMQ.CONNAUTH.CLIENT_CHECK_DISABLED",
                    "IBMMQ.CONNAUTH.LOCAL_CHECK_DISABLED", "IBMMQ.CHLAUTH.DISABLED",
                    "IBMMQ.CHANNEL.SYSTEM_SVRCONN_UNPROTECTED"):
        assert rule_id in h.observation, rule_id
    assert h.remediation.strip()


def test_a_recorded_error_alone_marks_the_read_unreadable():
    # Even without the explicit flag, an errors={"qmgr": ...} entry means nothing was read: the
    # connector's own record is never contradicted by a coerced default.
    q = parse_qmgr("QMRO", "u", {}, None, False, errors={"qmgr": "http_403"})
    assert q.raw["qmgr_readable"] is False
    assert det.connauth_missing(q, _ctx([])) == [] and det.scan_not_assessable(q, _ctx([]))


def test_denied_channel_read_is_not_assessable_not_silence():
    q = parse_qmgr("QMSAFE", "u", FIX["hardened"]["qmgr"], FIX["hardened"]["authinfo"], True,
                   errors={"channel": "http_403"}, channels_readable=False)
    h = one(det.scan_not_assessable(q, _ctx([])))
    assert h.assessable is False
    assert "DISPLAY CHANNEL(*)" in h.observation and "http_403" in h.observation
    for rule_id in ("IBMMQ.CHANNEL.NO_TLS", "IBMMQ.CHANNEL.MCAUSER_BLANK",
                    "IBMMQ.CHANNEL.MCAUSER_PRIVILEGED", "IBMMQ.CHANNEL.SSLCAUTH_OPTIONAL",
                    "IBMMQ.CHANNEL.SYSTEM_SVRCONN_UNPROTECTED"):
        assert rule_id in h.observation, rule_id
    # the qmgr half WAS read, so its rules ran and must not be claimed as unevaluated
    assert "IBMMQ.CHLAUTH.DISABLED" not in h.observation


def test_a_qmgr_with_no_channels_is_distinguishable_from_a_denied_channel_read():
    none_at_all = parse_qmgr("QMSAFE", "u", FIX["hardened"]["qmgr"], FIX["hardened"]["authinfo"],
                             True, channels_readable=True, channel_count=0)
    assert none_at_all.raw["channels_readable"] is True and none_at_all.raw["channel_count"] == 0
    assert det.scan_not_assessable(none_at_all, _ctx([])) == []      # genuinely empty ≠ denied
    denied = parse_qmgr("QMSAFE", "u", FIX["hardened"]["qmgr"], FIX["hardened"]["authinfo"], True,
                        errors={"channel": "http_403"}, channels_readable=False)
    assert denied.raw["channel_count"] is None and det.scan_not_assessable(denied, _ctx([]))


def test_a_read_that_was_never_attempted_is_not_reported_as_denied():
    q = qmgr("hardened")            # parse layer called without any collection flags
    assert q.raw["channels_readable"] is None and q.raw["queues_readable"] is None
    assert det.scan_not_assessable(q, _ctx([])) == []


def test_system_svrconn_does_not_fire_against_an_unread_qmgr():
    q = denied_qmgr()
    chan = parse_channel("QMRO", {"channelName": "SYSTEM.DEF.SVRCONN", "channelType": "svrconn",
                                  "messageChannelAgentUserIdentifier": ""})
    assert det.system_svrconn_unprotected(chan, _ctx([q, chan])) == []   # CHLAUTH never read
    assert "IBMMQ.CHANNEL.SYSTEM_SVRCONN_UNPROTECTED" in one(
        det.scan_not_assessable(q, _ctx([q, chan]))).observation


def test_readable_broker_findings_are_untouched_by_the_readability_gates():
    bad, safe = qmgr("insecure"), qmgr("hardened")
    assert bad.raw["qmgr_readable"] is True and safe.raw["qmgr_readable"] is True
    assert det.connauth_missing(bad, _ctx([])) and det.chlauth_disabled(bad, _ctx([]))
    assert det.connauth_missing(safe, _ctx([])) == [] and det.chlauth_disabled(safe, _ctx([])) == []
    # nothing was denied on either → no coverage finding at all
    assert det.scan_not_assessable(bad, _ctx([])) == []
    assert det.scan_not_assessable(safe, _ctx([])) == []


def test_coverage_rule_is_registered_and_names_only_real_rule_ids():
    rules = {d.rule_id: d for d in DETECTORS}
    cov = rules["IBMMQ.SCAN.NOT_ASSESSABLE"]
    assert cov.severity == "info" and cov.kinds == ("ibmmq_qmgr",)
    for _flag, _err_key, _command, gated in det._READ_GATES:
        for rule_id in gated:
            assert rule_id in rules, rule_id     # a typo here would silently under-report


# ── connector wiring: which read failed, and what the qmgr resource says ─────
def _collect(monkeypatch, **outcomes):
    """collect() with every MQSC call scripted by qualifier. No httpx client, no socket."""
    class _NoClient:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(conn, "httpx", types.SimpleNamespace(Client=_NoClient, HTTPError=Exception))
    monkeypatch.setattr(conn, "_run_mqsc",
                        lambda client, qm, command, qualifier, **kw: outcomes[qualifier])
    return conn.collect({"base_url": "https://mq.example:9443", "username": "ro",
                         "password": "x", "qmgr": "QM1"})


def _ok(rows):
    return {"ok": True, "status": 200, "responses": list(rows)}


def test_collect_records_a_denied_qmgr_read_and_still_assesses_the_channels(monkeypatch):
    col = _collect(monkeypatch, qmgr=DENIED,
                   channel=_ok(FIX["insecure"]["channels"]),
                   queue=_ok(FIX["insecure"]["queues"]), authrec=_ok(FIX["insecure"]["authrecs"]))
    q = next(r for r in col.resources if r.kind == "ibmmq_qmgr")
    ctx = _ctx(col.resources)
    assert q.raw["qmgr_readable"] is False and q.raw["errors"]["qmgr"] == "http_403"
    assert q.raw["channels_readable"] is True and q.raw["channel_count"] == 4
    assert det.connauth_missing(q, ctx) == []                    # no fabricated CRITICAL
    assert "DISPLAY QMGR" in one(det.scan_not_assessable(q, ctx)).observation
    # the reads that DID succeed are still assessed on their real evidence
    app = next(r for r in col.resources if r.name == "APP.SVRCONN")
    assert det.channel_mcauser_blank(app, ctx) and det.channel_no_tls(app, ctx)


def test_collect_records_a_denied_channel_read_rather_than_an_empty_broker(monkeypatch):
    col = _collect(monkeypatch, qmgr=_ok([FIX["insecure"]["qmgr"]]), channel=DENIED,
                   queue=_ok([]), authrec=_ok([]))
    q = next(r for r in col.resources if r.kind == "ibmmq_qmgr")
    ctx = _ctx(col.resources)
    assert [r for r in col.resources if r.kind == "ibmmq_channel"] == []
    assert q.raw["channels_readable"] is False and q.raw["channel_count"] is None
    assert "DISPLAY CHANNEL(*)" in one(det.scan_not_assessable(q, ctx)).observation
    assert det.chlauth_disabled(q, ctx)          # the readable half still reports its findings


def test_collect_treats_an_empty_display_qmgr_response_as_unread(monkeypatch):
    col = _collect(monkeypatch, qmgr=_ok([]), channel=_ok([]), queue=_ok([]), authrec=_ok([]))
    q = next(r for r in col.resources if r.kind == "ibmmq_qmgr")
    assert q.raw["qmgr_readable"] is False and q.raw["errors"]["qmgr"] == "empty"
    assert det.connauth_missing(q, _ctx(col.resources)) == []
    assert det.scan_not_assessable(q, _ctx(col.resources))


def test_collect_on_a_fully_readable_broker_files_no_coverage_gap(monkeypatch):
    col = _collect(monkeypatch, qmgr=_ok([FIX["hardened"]["qmgr"]]),
                   authinfo=_ok([FIX["hardened"]["authinfo"]]),
                   channel=_ok(FIX["hardened"]["channels"]), queue=_ok(FIX["hardened"]["queues"]),
                   authrec=_ok(FIX["hardened"]["authrecs"]))
    q = next(r for r in col.resources if r.kind == "ibmmq_qmgr")
    ctx = _ctx(col.resources)
    assert q.raw["qmgr_readable"] is True and q.raw["authinfo_readable"] is True
    assert q.raw["channels_readable"] and q.raw["queues_readable"] and q.raw["authrecs_readable"]
    assert q.raw["errors"] == {}
    assert det.scan_not_assessable(q, ctx) == []
    for rule in (det.connauth_missing, det.chlauth_disabled, det.connauth_chckclnt_open,
                 det.connauth_chcklocl_none):
        assert rule(q, ctx) == []                # a genuinely hardened broker is still clean


def test_collect_records_a_denied_authrec_read(monkeypatch):
    """Without authority records the queue rule has nothing to read — "no wide grant" would
    otherwise be indistinguishable from "DISPLAY AUTHREC was refused"."""
    col = _collect(monkeypatch, qmgr=_ok([FIX["insecure"]["qmgr"]]),
                   channel=_ok([]), queue=_ok(FIX["insecure"]["queues"]), authrec=DENIED)
    q = next(r for r in col.resources if r.kind == "ibmmq_qmgr")
    queue_res = next(r for r in col.resources if r.kind == "ibmmq_queue")
    assert q.raw["authrecs_readable"] is False
    assert det.queue_wide_authority(queue_res, _ctx(col.resources)) == []
    h = one(det.scan_not_assessable(q, _ctx(col.resources)))
    assert "DISPLAY AUTHREC" in h.observation and "IBMMQ.QUEUE.WIDE_AUTHORITY" in h.observation


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
