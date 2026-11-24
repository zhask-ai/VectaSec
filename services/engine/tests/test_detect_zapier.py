"""Zapier rulepack, offline. Resources come from the connector's own parse layer over the golden
fixture, so each rule is tested against exactly what collect() emits. Every rule gets fire,
silent and (where the rule has one) not-assessable.
"""
import json
import pathlib

from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.zapier as d
from vectasec.connect.zapier import assemble, build_account

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "zapier_responses.json").read_text())
BASE = "https://api.zapier.com"
RULES = {x.rule_id: x for x in DETECTORS if x.rule_id.startswith("ZAPIER.")}

EXPECTED_RULES = {
    "ZAPIER.ZAP.WEBHOOK_TRIGGER_UNAUTHENTICATED",
    "ZAPIER.ZAP.WRITES_TO_PRODUCTION_SYSTEM",
    "ZAPIER.CONNECTION.SHARED_ACROSS_ZAPS",
    "ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN",
    "ZAPIER.ACCOUNT.NOT_ASSESSED",
    "ZAPIER.ZAP.PAUSED_WITH_LIVE_CONNECTION",
    "ZAPIER.CONNECTION.UNUSED",
}


def _col(**over):
    kw = dict(account_id="123456", profile=FIX["profile"][0],
              zaps_raw=[z for p in FIX["zaps"] for z in p["data"]],
              auths_raw=[a for p in FIX["authentications"].values() for a in p["data"]],
              outcomes={"profile": {"outcome": "ok"}, "zaps": {"outcome": "ok"},
                        "authentications": {"outcome": "ok"}})
    kw.update(over)
    return assemble(BASE, **kw)


COL = _col()


def ctx(col=COL, **config):
    return ScanContext(connection_id="c", tenant_id="t", resources=list(col.resources),
                       config=config)


def res(kind, ident, col=COL):
    key = {"zapier_zap": "id", "zapier_webhook_trigger": "zap_id", "zapier_connection": "id"}[kind]
    return next(r for r in col.resources if r.kind == kind and r.raw.get(key) == ident)


def fire(rule_id, r, col=COL, **config):
    return RULES[rule_id].fn(r, ctx(col, **config))


def one(hits):
    assert len(hits) == 1, f"expected one hit, got {len(hits)}"
    return hits[0]


def test_all_expected_rules_registered_with_declared_severities():
    assert set(RULES) == EXPECTED_RULES
    sev = {k: v.severity for k, v in RULES.items()}
    assert sev["ZAPIER.ZAP.WEBHOOK_TRIGGER_UNAUTHENTICATED"] == "high"
    assert sev["ZAPIER.ZAP.WRITES_TO_PRODUCTION_SYSTEM"] == "medium"
    assert sev["ZAPIER.CONNECTION.SHARED_ACROSS_ZAPS"] == "medium"
    assert sev["ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN"] == "medium"
    assert sev["ZAPIER.ZAP.PAUSED_WITH_LIVE_CONNECTION"] == "low"


# ══ WEBHOOK_TRIGGER_UNAUTHENTICATED ═══════════════════════════════════════════
def test_webhook_trigger_fires_critical_when_it_writes_to_production():
    h = one(fire("ZAPIER.ZAP.WEBHOOK_TRIGGER_UNAUTHENTICATED",
                 res("zapier_webhook_trigger", "zap-hook-prod")))
    assert h.severity == "critical" and h.assessable
    assert "no authentication" in h.observation and "PostgreSQLAPI" in h.observation


def test_webhook_trigger_fires_high_without_production_write_and_info_when_paused():
    assert one(fire("ZAPIER.ZAP.WEBHOOK_TRIGGER_UNAUTHENTICATED",
                    res("zapier_webhook_trigger", "zap-hook-sheet"))).severity == "high"
    assert one(fire("ZAPIER.ZAP.WEBHOOK_TRIGGER_UNAUTHENTICATED",
                    res("zapier_webhook_trigger", "zap-hook-paused"))).severity == "info"


def test_app_triggered_zap_emits_no_webhook_resource_so_rule_is_silent():
    assert not [r for r in COL.resources
                if r.kind == "zapier_webhook_trigger" and r.raw["zap_id"] == "zap-sf-1"]


# ══ WRITES_TO_PRODUCTION_SYSTEM ═══════════════════════════════════════════════
def test_writes_to_production_fires_on_webhook_to_postgres():
    h = one(fire("ZAPIER.ZAP.WRITES_TO_PRODUCTION_SYSTEM", res("zapier_zap", "zap-hook-prod")))
    assert h.assessable and h.severity == "medium"
    assert "PostgreSQLAPI" in h.observation and "new_row" in h.observation


def test_writes_to_production_silent_for_sheets_and_for_app_triggered_zaps():
    assert fire("ZAPIER.ZAP.WRITES_TO_PRODUCTION_SYSTEM", res("zapier_zap", "zap-hook-sheet")) == []
    assert fire("ZAPIER.ZAP.WRITES_TO_PRODUCTION_SYSTEM", res("zapier_zap", "zap-sf-1")) == []


def test_writes_to_production_not_assessable_when_steps_unexpanded():
    h = one(fire("ZAPIER.ZAP.WRITES_TO_PRODUCTION_SYSTEM", res("zapier_zap", "zap-unexpanded")))
    assert h.assessable is False and "expand" in h.assessment_reason


# ══ SHARED_ACROSS_ZAPS ════════════════════════════════════════════════════════
def test_shared_connection_fires_at_default_threshold_of_five():
    h = one(fire("ZAPIER.CONNECTION.SHARED_ACROSS_ZAPS", res("zapier_connection", "auth-slack")))
    assert "5 Zaps" in h.observation and "threshold=5" in h.detail


def test_shared_connection_silent_below_threshold_and_honours_config():
    sf = res("zapier_connection", "auth-sf")          # used by 4
    assert fire("ZAPIER.CONNECTION.SHARED_ACROSS_ZAPS", sf) == []
    assert one(fire("ZAPIER.CONNECTION.SHARED_ACROSS_ZAPS", sf, zapier_shared_threshold=4))


# ══ OWNER_LEFT_OR_UNKNOWN ═════════════════════════════════════════════════════
def test_owner_rule_silent_when_owner_attributed_and_connection_live():
    assert fire("ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN", res("zapier_connection", "auth-pg")) == []


def test_owner_rule_fires_on_expired_connection():
    h = one(fire("ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN", res("zapier_connection", "auth-expired")))
    assert h.assessable and "is_expired=true" in h.observation


def test_owner_rule_fires_when_owner_missing_or_deactivated():
    col = _col(profile={"id": 1, "email": "gone@example.com", "is_deactivated": True})
    h = one(fire("ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN", res("zapier_connection", "auth-pg", col), col))
    assert "deactivated" in h.observation
    col2 = _col(profile={})                        # readable but empty → no owner field
    h2 = one(fire("ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN", res("zapier_connection", "auth-pg", col2), col2))
    assert "no owner field" in h2.observation and h2.assessable


def test_owner_rule_not_assessable_when_profile_unreadable():
    col = _col(profile=None, outcomes={"profile": {"outcome": "forbidden", "error": "HTTP 403"},
                                       "zaps": {"outcome": "ok"}, "authentications": {"outcome": "ok"}})
    h = one(fire("ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN", res("zapier_connection", "auth-pg", col), col))
    assert h.assessable is False and "profile" in h.assessment_reason


# ══ ACCOUNT.NOT_ASSESSED ══════════════════════════════════════════════════════
def test_account_not_assessed_silent_when_both_endpoints_readable():
    acct = next(r for r in COL.resources if r.kind == "zapier_account")
    assert fire("ZAPIER.ACCOUNT.NOT_ASSESSED", acct) == []


def test_account_not_assessed_fires_not_assessable_on_forbidden_zaps():
    acct = build_account(BASE, profile=None, account_id=None,
                         outcomes={"profile": {"outcome": "ok"},
                                   "zaps": {"outcome": "forbidden", "error": "HTTP 403"},
                                   "authentications": {"outcome": "skipped", "error": "zaps unreadable"}},
                         zap_count=0, connection_count=0)
    h = one(fire("ZAPIER.ACCOUNT.NOT_ASSESSED", acct))
    assert h.assessable is False
    assert "forbidden" in h.observation and "not an empty one" in h.observation


# ══ PAUSED_WITH_LIVE_CONNECTION ═══════════════════════════════════════════════
def test_paused_zap_with_live_connection_fires():
    h = one(fire("ZAPIER.ZAP.PAUSED_WITH_LIVE_CONNECTION", res("zapier_zap", "zap-hook-paused")))
    assert "auth-slack" in h.observation


def test_paused_rule_silent_for_enabled_zap_and_for_paused_zap_with_only_expired_connections():
    assert fire("ZAPIER.ZAP.PAUSED_WITH_LIVE_CONNECTION", res("zapier_zap", "zap-sf-1")) == []
    paused_expired = {"id": "zp", "title": "p", "is_enabled": False,
                      "steps": [{"action": {"id": "a", "key": "k", "action_type": "READ",
                                            "app": {"id": "app-github", "key": "GitHubAPI", "title": "GitHub"}},
                                 "authentication": {"id": "auth-expired", "is_expired": True}}]}
    col = _col(zaps_raw=[paused_expired])
    assert fire("ZAPIER.ZAP.PAUSED_WITH_LIVE_CONNECTION", res("zapier_zap", "zp", col), col) == []


def test_detector_module_exports_its_functions():
    assert callable(d.webhook_trigger_unauthenticated) and callable(d.account_not_assessed)


# ══ CONNECTION.UNUSED ═════════════════════════════════════════════════════════
def _conns(col):
    return [r for r in col.resources if r.kind == "zapier_connection"]


def test_unused_connection_fires_only_when_live_and_unreferenced():
    unused = {"id": "auth-orphan", "title": "Old Stripe", "is_expired": False,
              "app": {"id": "app-stripe", "key": "StripeCLIAPI", "title": "Stripe"}}
    col = _col(auths_raw=[*[a for p in FIX["authentications"].values() for a in p["data"]], unused])
    hits = fire("ZAPIER.CONNECTION.UNUSED", res("zapier_connection", "auth-orphan", col), col)
    assert len(hits) == 1 and "not referenced by any Zap" in hits[0].observation
    for c in _conns(col):
        if c.raw.get("used_by_zaps") or c.raw.get("is_expired"):
            assert fire("ZAPIER.CONNECTION.UNUSED", c, col) == []


def test_unused_is_not_claimed_when_the_zap_list_was_not_read():
    unused = {"id": "auth-orphan", "title": "Old Stripe", "is_expired": False, "app": {"id": "s", "title": "Stripe"}}
    col = _col(auths_raw=[unused], zaps_raw=[], outcomes={"profile": {"outcome": "ok"},
               "zaps": {"outcome": "forbidden"}, "authentications": {"outcome": "ok"}})
    assert fire("ZAPIER.CONNECTION.UNUSED", res("zapier_connection", "auth-orphan", col), col) == []
