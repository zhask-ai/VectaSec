"""Fix preview and least-privilege (impact.py). The contract under test is restraint:
no usage source -> unknown, short window -> unknown, Kafka (unattributed) -> never judged by
silence, "nothing seen" is only said with the window, and a wildcard is narrowed only to
targets that were actually observed."""
from datetime import datetime, timedelta, timezone

from vectasec import impact

NOW = datetime(2026, 11, 23, tzinfo=timezone.utc)
OLD, NEW = NOW - timedelta(days=40), NOW - timedelta(days=3)
F = {"id": "f1", "rule_id": "X"}


def ev(principal, peer="10.0.0.1", resource_ext=None, last=NOW):
    return {"principal": principal, "peer_host": peer, "resource_ext": resource_ext, "source": "s",
            "first_seen": OLD, "last_seen": last, "observed_scans": 3, "connection_id": "c1"}


def preview(resource, ctype, evidence=(), deps=(), window=OLD, siblings=()):
    return impact.build_preview(F, resource, {"type": ctype}, evidence, deps, siblings,
                                window_start=window, now=NOW)


def test_server_setting_affects_every_client():
    p = preview({"kind": "redis_server", "name": "cache", "ext_id": "redis-h"}, "redis",
                [ev("app"), ev("worker", "10.0.0.2"), ev("app")])
    assert p["scope"] == "everyone" and p["verdict"] == "will_affect" and p["consumers_total"] == 2
    assert "every client" in p["runbook"][0]


def test_credential_scopes_to_its_principal_case_insensitively():
    res = {"kind": "identity", "name": "Orders-Svc", "raw": {"principal": "Orders-Svc"}}
    p = preview(res, "rabbitmq", [ev("orders-svc"), ev("other")])
    assert p["scope"] == "principal" and [c["principal"] for c in p["consumers"]] == ["orders-svc"]
    assert p["runbook"][0].startswith("Create the replacement credential next to the old one")
    cred = {"kind": "credential", "name": "c", "labels": {"owner": "identity:rabbitmq:orders-svc"}}
    assert preview(cred, "rabbitmq", [ev("orders-svc")])["consumers_total"] == 1


def test_no_usage_source_is_unknown_not_safe():
    p = preview({"kind": "route", "name": "r", "ext_id": "r"}, "kong")
    assert p["verdict"] == "unknown" and "no usage signal" in p["why"] and p["usage_source"] is None


def test_kafka_identity_is_unknown_because_usage_is_unattributed():
    p = preview({"kind": "identity", "name": "User:etl"}, "kafka", [ev("etl")])
    assert p["verdict"] == "unknown" and "authenticated identity" in p["why"]


def test_short_window_is_unknown_long_window_says_the_window():
    res = {"kind": "identity", "name": "ghost"}
    assert preview(res, "redis", window=NEW)["verdict"] == "unknown"
    assert preview(res, "redis", window=None)["verdict"] == "unknown"
    p = preview(res, "redis", window=OLD)
    assert p["verdict"] == "no_use_seen" and "40 days" in p["why"] and "sampled" in p["why"]


def test_dependents_and_also_closes():
    p = preview({"kind": "n8n_credential", "name": "Slack", "ext_id": "x"}, "n8n",
                deps=[{"id": "w", "kind": "n8n_workflow", "name": "Alerts", "owner": "pat"}],
                siblings=[{"id": "f2", "rule_id": "B"}, {"id": "f3", "rule_id": "A"}])
    assert p["verdict"] == "unknown", "n8n has no usage source; dependents are still listed"
    assert p["dependents_total"] == 1 and [s["rule_id"] for s in p["also_closes"]] == ["A", "B"]


# ── least privilege ────────────────────────────────────────────────────────
def ident(name, cid="c1"):
    return {"id": f"r-{name}", "ext_id": f"identity:rabbitmq:{name}", "name": name, "labels": {},
            "raw": {"principal": name}, "connection_id": cid}


def grant(name, action, target, wildcard=False):
    return {"labels": {"identity": f"identity:rabbitmq:{name}", "action": action, "target": target,
                       "wildcard": "true" if wildcard else "false"}}


def recs(identities, grants, evidence, window=OLD, ctype="rabbitmq"):
    out = impact.build_recommendations(identities, grants, evidence, {"c1": window}, {"c1": ctype}, now=NOW)
    return {r["identity"]: r for r in out}


def test_wildcard_is_narrowed_only_to_observed_targets():
    r = recs([ident("svc")], [grant("svc", "configure", "*", True)],
             [ev("svc", resource_ext="vhost:orders"), ev("svc", resource_ext="vhost:billing")])["svc"]
    assert r["verdict"] == "narrow"
    assert [(d["op"], d["target"]) for d in r["diff"]] == [("-", "*"), ("+", "vhost:billing"), ("+", "vhost:orders")]


def test_unused_specific_grant_is_trimmed_used_one_kept():
    r = recs([ident("svc")], [grant("svc", "read", "orders"), grant("svc", "read", "legacy")],
             [ev("svc", resource_ext="vhost:orders")])["svc"]
    assert r["verdict"] == "trim" and [d["target"] for d in r["diff"]] == ["legacy"]
    ok = recs([ident("svc")], [grant("svc", "read", "orders")], [ev("svc", resource_ext="vhost:orders")])["svc"]
    assert ok["verdict"] == "right_sized" and ok["diff"] == []


def test_restraint():
    g = [grant("svc", "read", "*", True)]
    assert recs([ident("svc")], g, [], window=NEW)["svc"]["verdict"] == "cannot_assess"
    assert recs([ident("svc")], g, [ev("svc", resource_ext="t")], ctype="kafka")["svc"]["verdict"] == "cannot_assess"
    assert recs([ident("svc")], g, [ev("svc", resource_ext="t")], ctype="kong")["svc"]["verdict"] == "cannot_assess"
    seen_no_target = recs([ident("svc")], g, [ev("svc")])["svc"]
    assert seen_no_target["verdict"] == "cannot_assess" and seen_no_target["diff"] == []
    never = recs([ident("svc")], g, [ev("other", resource_ext="t")])["svc"]
    assert never["verdict"] == "remove_all" and "confirm with the owner" in never["reason"]
    assert recs([ident("nogrants")], [], []) == {}


def test_order_puts_actionable_first():
    out = impact.build_recommendations(
        [ident("a"), ident("b")], [grant("a", "read", "orders"), grant("b", "all", "*", True)],
        [ev("a", resource_ext="vhost:orders"), ev("b", resource_ext="vhost:x")], {"c1": OLD}, {"c1": "rabbitmq"}, now=NOW)
    assert [r["identity"] for r in out] == ["b", "a"]


# ── usage history ─────────────────────────────────────────────────────────
class UCur:
    def __init__(self, resource, rows):
        self.resource, self.rows, self.log = resource, rows, []

    def execute(self, sql, params=None):
        self.log.append((" ".join(sql.split()), params))
        self._one = self.resource if "from resources r join connections" in sql else None
        self._all = self.rows if "from runtime_evidence" in sql else []

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


def test_usage_history_matches_resource_or_assigned_topic_and_states_limits():
    cur = UCur(("topic", "payments", "topic-payments", "c1", "kafka", OLD),
               [("billing-consumer", "10.0.0.4", "kafka-describe-consumer-groups", OLD, NOW, 9, "billing-consumer")])
    out = impact.usage_history(cur, "t", "r")
    assert out["principals"] == ["billing-consumer"] and out["rows"][0]["via"] == "assigned to this topic"
    q = next(p for s, p in cur.log if "from runtime_evidence" in s)
    assert q[2] == ["topic-payments", "payments"] and q[3] == "payments"
    assert "self-reported" in out["note"], "Kafka usage is consumer groups only and says so"
    none = impact.usage_history(UCur(("route", "r", "r", "c", "kong", None), []), "t", "r")
    assert none["supported"] is False and "no usage signal" in none["note"]
    assert impact.usage_history(UCur(None, []), "t", "r") is None
