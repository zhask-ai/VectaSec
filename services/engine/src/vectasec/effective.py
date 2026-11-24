"""Effective access: who can ACTUALLY read or write a thing, evaluated the way the system does.

Most of the engine judges one setting at a time ("this grant is a wildcard"). Real exposure is
the result of the system's own evaluation rules applied to every grant at once, and those rules
have traps that a per-setting check cannot see:

  * Kafka: `allow.everyone.if.no.acl.found=true` opens a topic only while NO ACL matches it, so
    one wildcard ACL for an unrelated principal silently closes every topic, and deleting the
    last ACL on a topic silently opens it. DENY beats ALLOW. Super users bypass ACLs.
  * RabbitMQ: "who can consume queue Q" is exactly the users whose read regex for Q's vhost
    matches Q's name; `administrator` can grant itself anything.
  * Redis: key patterns do not restrict keyless commands, so a user fenced to `~tenant1:*`
    can still run FLUSHALL; a restricted user that keeps `ACL SETUSER` or `CONFIG SET` can
    rewrite its own fence.

This module implements those evaluation functions over what the connectors stored. No system is
contacted. Every result carries the binding or rule that produced it, so a person can check it.

Sources (official docs, read 2026-11; see research_notes/Middleware engine AI upgrade research/
engine_depth_techniques.md §B1-B3): Apache Kafka 4.4 authorization and ACLs, Confluent
Platform 8.4 ACL overview (deny precedence, implied DESCRIBE), RabbitMQ 4.4 access control,
Redis ACL documentation.

KNOWN LIMITS, stated in every result's `caveats`:
  * Kafka principals are matched as stored. An mTLS client whose principal is a full DN will not
    match an ACL written for `User:alice`; principal mapping rules are not evaluated.
  * Confluent RBAC role bindings are not read; only ACLs.
  * RabbitMQ regexes are evaluated unanchored (re.search). The docs do not say whether the server
    anchors them; that is called out wherever it changes the answer.
  * Redis command-category membership is a small built-in table for the commands this module
    asks about, not the live server's `ACL CAT` output.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

__all__ = ["kafka_topic_access", "kafka_broker_view", "rabbitmq_vhost_access",
           "parse_redis_acl_line", "redis_user_access", "redis_server_access", "who_can",
           "REDIS_RISKY"]


# ── Kafka ────────────────────────────────────────────────────────────────

_IMPLIES_DESCRIBE = {"READ", "WRITE", "DELETE", "ALTER"}


def _cfg_value(config: dict, key: str) -> Optional[str]:
    v = (config or {}).get(key)
    if isinstance(v, dict):
        v = v.get("value")
    return None if v is None else str(v)


def kafka_broker_view(resources: Iterable) -> Optional[dict]:
    """The first broker whose ACL read succeeded: {bindings, super_users, allow_everyone,
    authorizer}. None when no broker's ACLs could be read (a coverage gap, never 'no ACLs')."""
    for r in resources:
        kind = r.get("kind") if isinstance(r, dict) else getattr(r, "kind", None)
        raw = (r.get("raw") if isinstance(r, dict) else getattr(r, "raw", None)) or {}
        if kind != "broker":
            continue
        acls = raw.get("acls") or {}
        if acls.get("outcome") != "ok":
            continue
        cfg = raw.get("config") or {}
        supers = [p.strip() for p in (_cfg_value(cfg, "super.users") or "").split(";") if p.strip()]
        return {"bindings": [b for b in acls.get("bindings") or [] if isinstance(b, dict)],
                "super_users": supers,
                "allow_everyone": (_cfg_value(cfg, "allow.everyone.if.no.acl.found") or "false").lower() == "true",
                "authorizer": (_cfg_value(cfg, "authorizer.class.name") or "").strip()}
    return None


def _matches_topic(b: dict, topic: str) -> bool:
    if str(b.get("restype") or "").upper() != "TOPIC":
        return False
    name, pattern = str(b.get("name") or ""), str(b.get("pattern") or "LITERAL").upper()
    if pattern == "PREFIXED":
        return topic.startswith(name)
    return name == "*" or name == topic


def _grants(b: dict, op: str) -> bool:
    o = str(b.get("operation") or "").upper()
    return o in ("ALL", op) or (op == "DESCRIBE" and o in _IMPLIES_DESCRIBE)


def _label(b: dict) -> str:
    return (f"{b.get('permission_type')} {b.get('operation')} for {b.get('principal')} on "
            f"{str(b.get('pattern') or 'LITERAL').lower()} topic '{b.get('name')}'"
            + (f" from host {b.get('host')}" if b.get("host") not in (None, "*") else ""))


def kafka_topic_access(topic: str, view: Optional[dict]) -> dict:
    """{readers, writers, everyone_read, everyone_write, reason, caveats} for one topic.
    readers/writers: [{principal, via}] — via is the ACL or rule that grants it."""
    caveats = ["Principals are matched exactly as stored; mTLS distinguished names and principal "
               "mapping rules are not evaluated.", "Confluent RBAC role bindings are not read."]
    if view is None:
        return {"assessable": False, "readers": [], "writers": [], "everyone_read": None,
                "everyone_write": None, "reason": "The broker's ACLs could not be read, so who can "
                "reach this topic is unknown.", "caveats": caveats}
    supers = [{"principal": p, "via": "listed in super.users (bypasses all ACLs)"} for p in view["super_users"]]
    if not view["authorizer"]:
        return {"assessable": True, "readers": supers, "writers": supers, "everyone_read": True,
                "everyone_write": True, "caveats": caveats,
                "reason": "No authorizer is configured, so every client that can connect can read "
                          "and write this topic."}
    matching = [b for b in view["bindings"] if _matches_topic(b, topic)]
    if not matching:
        open_ = view["allow_everyone"]
        return {"assessable": True, "readers": supers, "writers": supers, "everyone_read": open_,
                "everyone_write": open_, "caveats": caveats,
                "reason": ("No ACL matches this topic and allow.everyone.if.no.acl.found is true, so "
                           "every authenticated client can read and write it. Adding any ACL that "
                           "matches it will close it to everyone else.") if open_ else
                          ("No ACL matches this topic, so only super users can reach it.")}

    def evaluate(op: str):
        denied = {str(b.get("principal")) for b in matching
                  if str(b.get("permission_type") or "").upper() == "DENY" and _grants(b, op)}
        allowed: dict[str, str] = {}
        for b in matching:
            if str(b.get("permission_type") or "").upper() != "ALLOW" or not _grants(b, op):
                continue
            p = str(b.get("principal"))
            if p in denied or "User:*" in denied:
                continue
            allowed.setdefault(p, _label(b))
        everyone = "User:*" in allowed
        rows = supers + [{"principal": p, "via": v} for p, v in sorted(allowed.items())]
        return rows, everyone, sorted(denied)

    readers, every_r, deny_r = evaluate("READ")
    writers, every_w, deny_w = evaluate("WRITE")
    reason = f"{len(matching)} ACL(s) match this topic. DENY beats ALLOW; super users bypass ACLs."
    if every_r:
        reason += " An ALLOW for User:* means every authenticated principal can read it."
    if deny_r or deny_w:
        reason += f" Denied: {', '.join(sorted(set(deny_r) | set(deny_w)))}."
    return {"assessable": True, "readers": readers, "writers": writers, "everyone_read": every_r,
            "everyone_write": every_w, "reason": reason, "caveats": caveats}


# ── RabbitMQ ─────────────────────────────────────────────────────────────

def _covers_everything(pattern: str) -> bool:
    p = (pattern or "").strip()
    return p in (".*", "^.*$", "^.*", ".*$", ".+", "^.+$")


def rabbitmq_vhost_access(vhost: str, permissions: Iterable[dict], users: Iterable[dict]) -> dict:
    """Per vhost: who can read (consume), write (publish), configure (declare/delete) every
    queue and exchange, who is limited by a pattern, and who can grant themselves anything.
    permissions: {user, vhost, configure, write, read}; users: {name, tags}."""
    tags = {str(u.get("name")): [str(t) for t in (u.get("tags") or [])] for u in users}
    rows = []
    for p in permissions:
        if str(p.get("vhost")) != vhost:
            continue
        user = str(p.get("user"))
        row = {"user": user, "tags": tags.get(user, [])}
        for op in ("read", "write", "configure"):
            pat = str(p.get(op) or "")
            if pat in ("", "^$"):
                row[op] = {"scope": "none", "pattern": pat}
            elif _covers_everything(pat):
                row[op] = {"scope": "all", "pattern": pat}
            else:
                unanchored = not (pat.startswith("^") and pat.endswith("$"))
                row[op] = {"scope": "some", "pattern": pat, "unanchored": unanchored}
        row["can_grant_itself_anything"] = "administrator" in row["tags"]
        rows.append(row)
    rows.sort(key=lambda r: (r["read"]["scope"] != "all", r["user"]))
    admins = sorted(u for u, t in tags.items() if "administrator" in t)
    return {"vhost": vhost, "users": rows,
            "read_everything": [r["user"] for r in rows if r["read"]["scope"] == "all"],
            "write_everything": [r["user"] for r in rows if r["write"]["scope"] == "all"],
            "administrators": admins,
            "reason": "A user can consume every queue in this vhost when its read pattern matches "
                      "every name; administrators can set any user's permissions, including their own.",
            "caveats": ["Patterns are treated as unanchored (a pattern 'orders' also matches "
                        "'preorders'); the RabbitMQ docs do not state whether they are anchored.",
                        "Topic permissions and external auth backends (LDAP, OAuth 2) are not evaluated."]}


def who_can_consume(queue: str, vhost: str, permissions: Iterable[dict]) -> list[dict]:
    out = []
    for p in permissions:
        if str(p.get("vhost")) != vhost:
            continue
        pat = str(p.get("read") or "")
        if pat in ("", "^$"):
            continue
        try:
            if re.search(pat, queue):
                out.append({"user": str(p.get("user")), "via": f"read pattern {pat!r} in vhost {vhost!r}"})
        except re.error:
            out.append({"user": str(p.get("user")), "via": f"read pattern {pat!r} (could not be parsed)"})
    return out


# ── Redis ────────────────────────────────────────────────────────────────

# Category membership for the commands this module asks about. Stable across Redis 6.2-8, but
# a built-in table, not the live server's ACL CAT (stated in caveats).
_CMD_CATS = {
    "flushall": {"keyspace", "write", "slow", "dangerous"},
    "flushdb": {"keyspace", "write", "slow", "dangerous"},
    "swapdb": {"keyspace", "write", "fast", "dangerous"},
    "keys": {"keyspace", "read", "slow", "dangerous"},
    "acl|setuser": {"admin", "slow", "dangerous"},
    "config|set": {"admin", "slow", "dangerous"},
    "module|load": {"admin", "slow", "dangerous"},
    "monitor": {"admin", "slow", "dangerous"},
    "replicaof": {"admin", "slow", "dangerous", "stale"},
    "eval": {"slow", "scripting"},
}

REDIS_RISKY = {
    "flushall": "erase every key in every database",
    "flushdb": "erase every key in the current database",
    "swapdb": "swap whole databases",
    "keys": "list every key name",
    "acl|setuser": "rewrite any user's permissions, including its own",
    "config|set": "change server configuration, including where it writes files",
    "module|load": "load native code into the server",
    "monitor": "watch every command every client sends",
    "replicaof": "make this server copy its data to or from another server",
    "eval": "run Lua scripts",
}
_KEYLESS = ("flushall", "flushdb", "swapdb", "keys", "monitor")
_ESCALATION = ("acl|setuser", "config|set", "module|load")


def parse_redis_acl_line(line: str) -> Optional[dict]:
    """`user <name> <rules...>` from ACL LIST → {name, flags, keys, channels, commands,
    selectors}. selectors: list of {keys, channels, commands}."""
    line = (line or "").strip()
    m = re.match(r"^user\s+(\S+)\s*(.*)$", line)
    if not m:
        return None
    name, rest = m.group(1), m.group(2)
    selectors_raw = re.findall(r"\(([^)]*)\)", rest)
    root = re.sub(r"\([^)]*\)", " ", rest)

    def split(text: str) -> dict:
        keys, channels, commands, flags = [], [], [], []
        for tok in text.split():
            if tok.startswith(("~", "%")) or tok == "allkeys" or tok == "resetkeys":
                keys.append(tok)
            elif tok.startswith("&") or tok in ("allchannels", "resetchannels"):
                channels.append(tok)
            elif tok.startswith(("+", "-")) or tok in ("allcommands", "nocommands"):
                commands.append(tok)
            elif not tok.startswith(("#", ">", "<", "!")):
                flags.append(tok)
        return {"keys": keys, "channels": channels, "commands": commands, "flags": flags}

    r = split(root)
    return {"name": name, "flags": r["flags"], "keys": r["keys"], "channels": r["channels"],
            "commands": r["commands"],
            "selectors": [{k: v for k, v in split(s).items() if k != "flags"} for s in selectors_raw]}


def _allowed(commands: list[str], cmd: str) -> bool:
    """Left-to-right evaluation of +/- command and category rules for one command (which may
    be `parent|sub`)."""
    parent = cmd.split("|")[0]
    cats = _CMD_CATS.get(cmd, set())
    state = False
    for tok in commands:
        t = tok.lower()
        if t in ("allcommands", "+@all"):
            state = True
        elif t in ("nocommands", "-@all"):
            state = False
        elif t.startswith(("+@", "-@")):
            if t[2:] in cats:
                state = t[0] == "+"
        elif t.startswith(("+", "-")):
            name = t[1:]
            if name == parent or name == cmd:
                state = t[0] == "+"
    return state


def _keys_unrestricted(keys: list[str]) -> bool:
    return any(k in ("~*", "allkeys", "%RW~*", "%R~*") for k in keys)


def redis_user_access(user: dict) -> dict:
    """What one Redis user can actually do. user: {name, enabled, nopass, keys, commands,
    selectors?} where keys/commands are lists of rule tokens (or space-separated strings)."""
    def toks(v) -> list[str]:
        if isinstance(v, list):
            return [str(x) for x in v]
        return [t for t in str(v or "").split() if t not in ("[]",)]

    root = {"keys": toks(user.get("keys")), "commands": toks(user.get("commands"))}
    sets = [root] + [{"keys": toks(s.get("keys")), "commands": toks(s.get("commands"))}
                     for s in user.get("selectors") or []]
    can = {cmd: any(_allowed(s["commands"], cmd) for s in sets) for cmd in REDIS_RISKY}
    all_keys = any(_keys_unrestricted(s["keys"]) for s in sets)
    restricted = bool(root["keys"]) and not all_keys
    commands_known = bool(root["commands"])
    return {
        "user": user.get("name") or user.get("username"),
        "enabled": bool(user.get("enabled")), "nopass": bool(user.get("nopass")),
        "commands_known": commands_known,
        "all_keys": all_keys, "key_restricted": restricted,
        "risky": [{"command": c.replace("|", " ").upper(), "effect": REDIS_RISKY[c]}
                  for c, ok in can.items() if ok],
        "keyless_bypass": restricted and any(can[c] for c in _KEYLESS),
        "self_escalation": any(can[c] for c in _ESCALATION) and (restricted or not all(can.values())),
        "anonymous": bool(user.get("enabled")) and bool(user.get("nopass")) and user.get("name", user.get("username")) == "default",
    }


def redis_server_access(server_raw: dict, users: Iterable[dict]) -> dict:
    rows = [redis_user_access(u) for u in users]
    exposed_bind = str((server_raw or {}).get("bind") or "") not in ("", "127.0.0.1", "::1", "127.0.0.1 ::1", "127.0.0.1 -::1")
    protected = str((server_raw or {}).get("protected_mode") or "").lower() == "yes"
    anon = next((r for r in rows if r["anonymous"]), None)
    reason = ("The default user is enabled with no password, so every client that connects is "
              "logged in as it without AUTH." if anon else
              "Every client must authenticate as one of the users below.")
    if anon and exposed_bind and not protected:
        reason += " The server listens on a non-loopback address with protected mode off."
    return {"users": rows, "anonymous_access": bool(anon), "exposed_bind": exposed_bind,
            "protected_mode": protected, "reason": reason,
            "caveats": ["Command categories come from a built-in table for the commands listed, "
                        "not from the server's ACL CAT.",
                        "Users stored before this version may lack their command rules; rescan "
                        "the connection to fill them in."]}


# ── dispatch for the API ──────────────────────────────────────────────────

def who_can(resource: dict, siblings: list[dict]) -> Optional[dict]:
    """Effective access for one stored resource, or None when this module has nothing to say
    about its kind. resource/siblings: {kind, name, raw, labels} from the same connection."""
    kind = resource.get("kind")
    if kind == "topic":
        view = kafka_broker_view(siblings)
        return {"system": "kafka", "kind": "topic", **kafka_topic_access(str(resource.get("name")), view)}
    if kind == "vhost":
        perms = [s.get("raw") or {} for s in siblings if s.get("kind") == "permission"]
        users = [s.get("raw") or {} for s in siblings if s.get("kind") == "user"]
        return {"system": "rabbitmq", "kind": "vhost",
                **rabbitmq_vhost_access(str((resource.get("raw") or {}).get("name") or resource.get("name")), perms, users)}
    if kind == "redis_server":
        users = []
        for s in siblings:
            if s.get("kind") != "redis_user":
                continue
            raw = s.get("raw") or {}
            if not raw:
                continue
            parsed = parse_redis_acl_line(raw.get("acl_line") or "") if raw.get("acl_line") else None
            users.append({"name": raw.get("username"), "enabled": raw.get("enabled"),
                          "nopass": raw.get("nopass"),
                          "keys": parsed["keys"] if parsed else raw.get("keys"),
                          "commands": parsed["commands"] if parsed else raw.get("commands"),
                          "selectors": parsed["selectors"] if parsed else []})
        return {"system": "redis", "kind": "redis_server",
                **redis_server_access(resource.get("raw") or {}, users)}
    return None
