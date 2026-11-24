"""Findings that need the system's own evaluation rules, not one setting (effective.py).

Each rule here asks "what can actually happen", using the same evaluator the console's
"Who can reach this" panel uses, so a finding and the panel can never disagree.
"""
from ..contracts import Hit
from ..effective import (kafka_broker_view, kafka_topic_access, parse_redis_acl_line,
                         redis_user_access)
from ..registry import detector


def _sensitive(r) -> bool:
    return str((r.labels or {}).get("data_sensitivity") or "").lower() in ("high", "restricted", "confidential")


@detector(kinds=["topic"], rule_id="KAFKA.EFFECTIVE.TOPIC_OPEN_NO_ACL", severity="high",
          title="Topic is open to every client because no ACL matches it")
def topic_open_no_acl(r, ctx) -> list:
    view = kafka_broker_view(ctx.resources)
    if view is None or not view["authorizer"] or not view["allow_everyone"]:
        return []
    access = kafka_topic_access(r.name, view)
    if not access["everyone_read"]:
        return []
    return [Hit(
        observation=f"topic '{r.name}': no ACL among the broker's {len(view['bindings'])} matches it "
                    f"and allow.everyone.if.no.acl.found=true, so every authenticated client can "
                    f"read and write it",
        remediation="Add ACLs that name the principals allowed to read and write this topic, or set "
                    "allow.everyone.if.no.acl.found=false. Note the flag's trap: adding any ACL that "
                    "matches this topic closes it to everyone else at once, so add the consumers' "
                    "ACLs first.",
        detail=f"bindings={len(view['bindings'])} super_users={view['super_users']}",
        severity="critical" if _sensitive(r) else None,
        source_ref={"config_key": "allow.everyone.if.no.acl.found", "topic": r.name},
    )]


@detector(kinds=["topic"], rule_id="KAFKA.EFFECTIVE.TOPIC_WORLD_READABLE", severity="high",
          title="Every principal can read this topic through an ACL for User:*")
def topic_world_readable(r, ctx) -> list:
    view = kafka_broker_view(ctx.resources)
    if view is None or not view["authorizer"]:
        return []
    matching = [b for b in view["bindings"] if str(b.get("restype") or "").upper() == "TOPIC"]
    if not matching:
        return []
    access = kafka_topic_access(r.name, view)
    if not access["everyone_read"] or access["reason"].startswith("No ACL matches"):
        return []
    via = next((x["via"] for x in access["readers"] if x["principal"] == "User:*"), "an ACL for User:*")
    return [Hit(
        observation=f"topic '{r.name}' is readable by every principal: {via}",
        remediation="Replace the User:* ALLOW with ACLs for the specific consumer principals, or add "
                    "a DENY for User:* on this topic if it should be private. DENY takes precedence "
                    "over ALLOW.",
        severity="critical" if _sensitive(r) else None,
        source_ref={"acl": via, "topic": r.name},
    )]


def _redis_user(r):
    raw = r.raw or {}
    if not raw.get("enabled"):
        return None
    parsed = parse_redis_acl_line(raw.get("acl_line") or "") if raw.get("acl_line") else None
    if parsed is None:
        return None          # rules not stored in order (older scan): no claim either way
    return redis_user_access({"name": raw.get("username"), "enabled": raw.get("enabled"),
                              "nopass": raw.get("nopass"), "keys": parsed["keys"],
                              "commands": parsed["commands"], "selectors": parsed["selectors"]})


@detector(kinds=["redis_user"], rule_id="REDIS.ACL.KEYPATTERN_BYPASS", severity="high",
          title="Redis user is fenced to some keys but can still wipe or list all of them")
def keypattern_bypass(r, ctx) -> list:
    a = _redis_user(r)
    if not a or not a["keyless_bypass"]:
        return []
    bad = [x["command"] for x in a["risky"] if x["command"].split()[0].lower() in ("flushall", "flushdb", "swapdb", "keys", "monitor")]
    return [Hit(
        observation=f"redis ACL user '{a['user']}' has key patterns {(r.raw or {}).get('acl_line')!r} "
                    f"but its command rules allow {', '.join(bad)}, which key patterns do not restrict",
        remediation="Remove the whole-keyspace commands from this user, for example "
                    f"`ACL SETUSER {a['user']} -flushall -flushdb -swapdb -keys -monitor` (or drop "
                    "+@all / +@dangerous / +@keyspace in favour of the specific commands it needs).",
        source_ref={"acl_user": a["user"], "doc": "redis ACL: commands that operate on the whole keyspace are not limited by key patterns"},
    )]


@detector(kinds=["redis_user"], rule_id="REDIS.ACL.SELF_ESCALATION", severity="high",
          title="Restricted Redis user can rewrite its own restrictions")
def self_escalation(r, ctx) -> list:
    a = _redis_user(r)
    if not a or not a["self_escalation"] or a["user"] == "default" and a["all_keys"]:
        return []
    bad = [x["command"] for x in a["risky"] if x["command"] in ("ACL SETUSER", "CONFIG SET", "MODULE LOAD")]
    if not bad:
        return []
    return [Hit(
        observation=f"redis ACL user '{a['user']}' is not all-powerful but may run {', '.join(bad)}, "
                    "so it can grant itself any permission",
        remediation=f"Remove administrative commands from this user: `ACL SETUSER {a['user']} -acl -config "
                    "-module`. Keep administration on a separate, password-protected admin user.",
        source_ref={"acl_user": a["user"]},
    )]
