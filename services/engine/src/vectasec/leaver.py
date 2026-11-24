"""The Leaver report: everything one person owns across the integration layer.

When someone leaves, their laptop is collected and their SSO account is disabled. Their
automations keep running: the Zap that uses their personal OAuth connection, the n8n workflow
they built, the service account whose only named owner was them. Offboarding checklists do
not cover these because no single system lists them.

This module joins what scans already stored. For one person (an email or a name) it returns:

  accounts    identities that ARE the person in a connected system (their n8n user, etc.)
  owns        resources whose recorded owner / creator / editor is the person
  breaks      things owned by SOMEONE ELSE (or nobody) that depend on something the person
              owns — a workflow using their connection. This is what stops working if the
              person's things are simply deleted, and what keeps running under a departed
              person's authority if they are not.

HONESTY
  * Ownership is whatever the system's API returned (an owner field, a creator, a tag). Where
    a system exposes no owner, its resources cannot appear here, and the report lists the
    connected systems that expose none so that silence is not read as "they own nothing".
  * Matching is exact on a normalised email / name, never fuzzy: a report that guesses which
    "alex" is meant would take the wrong person's automations down.
  * Read-only. Nothing is disabled, transferred or deleted.
"""
from __future__ import annotations

from typing import Iterable, Optional

__all__ = ["OWNER_KEYS", "owners_of", "list_people", "build_report", "load", "to_markdown"]

OWNER_KEYS = ("owner", "owner_confirmed", "owner_label", "owner_email", "owners", "created_by", "creator",
              "createdBy", "updated_by", "updatedBy", "last_modified_by", "author", "sponsor")
# Kinds that are a person's own account inside a system.
ACCOUNT_KINDS = frozenset({"n8n_user", "zapier_account", "identity", "workato_user", "boomi_user",
                           "keycloak_user", "rabbitmq_user", "user"})
_HUMANISH = ("owner", "admin", "member", "user", "human")
MAX_ITEMS = 1000


def _norm(v) -> str:
    return str(v or "").strip().lower()


def _values(v) -> list[str]:
    if isinstance(v, dict):
        v = v.get("email") or v.get("name") or v.get("id")
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            out += _values(x)
        return out
    if isinstance(v, str) and "," in v and "@" in v:
        return [_norm(x) for x in v.split(",") if _norm(x)]
    n = _norm(v)
    return [n] if n and n not in ("?", "unknown", "none", "null") else []


def owners_of(resource: dict) -> set[str]:
    """Every owner / creator / editor string the system recorded on this resource."""
    out: set[str] = set()
    for src in (resource.get("labels") or {}, resource.get("raw") or {}):
        if isinstance(src, dict):
            for k in OWNER_KEYS:
                if k in src:
                    out.update(_values(src[k]))
    # On credentials and grants, `owner` points at the owning IDENTITY (an ext_id such as
    # "identity:rabbitmq:guest"), not at a person. Those references are not people.
    return {v for v in out if not v.startswith(("identity:", "cred:", "grant:"))}


def _is_account(resource: dict) -> bool:
    if resource.get("kind") not in ACCOUNT_KINDS:
        return False
    kind = resource.get("kind")
    # Broker and generic "user" rows are mostly service logins (RabbitMQ's `guest`). They count
    # as a person's account only when the name is an email address.
    if kind in ("identity", "user", "rabbitmq_user"):
        if "@" not in str(resource.get("name") or ""):
            return False
        if kind != "identity":
            return True
        itype = _norm((resource.get("labels") or {}).get("identity_type"))
        return any(h in itype for h in _HUMANISH)
    return True


def list_people(resources: Iterable[dict]) -> list[dict]:
    """Distinct people the inventory names, with how much each owns. For the picker."""
    people: dict[str, dict] = {}
    for r in resources:
        if r.get("stale"):
            continue
        for person in owners_of(r):
            people.setdefault(person, {"person": person, "owns": 0, "accounts": 0})["owns"] += 1
        if _is_account(r):
            name = _norm(r.get("name"))
            if name:
                people.setdefault(name, {"person": name, "owns": 0, "accounts": 0})["accounts"] += 1
    return sorted(people.values(), key=lambda p: (-(p["owns"] + p["accounts"]), p["person"]))


def _item(r: dict, conns: dict) -> dict:
    labels = r.get("labels") or {}
    c = conns.get(str(r.get("connection_id") or ""), {})
    return {"id": r.get("id"), "kind": r.get("kind"), "name": r.get("name"),
            "system": c.get("type") or labels.get("system") or "",
            "connection": c.get("name") or "",
            "active": labels.get("active"),
            "last_used_at": labels.get("last_used_at") or "",
            "detail": labels.get("credential_type") or labels.get("app")
                      or labels.get("identity_type") or labels.get("role") or ""}


def build_report(person: str, resources: Iterable[dict], edges: Iterable[dict],
                 connections: Iterable[dict]) -> dict:
    """resources: {id, kind, name, labels, raw, connection_id, stale}; edges: {src, dst, kind};
    connections: {id, name, type}."""
    who = _norm(person)
    conns = {str(c["id"]): c for c in connections}
    live = [r for r in resources if not r.get("stale")]
    by_id = {str(r["id"]): r for r in live}

    accounts = [r for r in live if _is_account(r) and _norm(r.get("name")) == who]
    owned = [r for r in live if who in owners_of(r)]
    mine = {str(r["id"]) for r in owned} | {str(r["id"]) for r in accounts}

    breaks: dict[str, dict] = {}
    for e in edges:
        src, dst = str(e.get("src")), str(e.get("dst"))
        # A depends on B when A --uses--> B, or B --owns/credential_of--> ... is not a dependency.
        if e.get("kind") in ("uses_credential", "uses_connection", "uses", "triggers", "acts_as"):
            dependent, dependency = src, dst
        else:
            continue
        if dependency in mine and dependent not in mine and dependent in by_id:
            entry = breaks.setdefault(dependent, {**_item(by_id[dependent], conns), "because": []})
            via = by_id.get(dependency, {}).get("name")
            if via and via not in entry["because"]:
                entry["because"].append(via)
            entry["other_owners"] = sorted(owners_of(by_id[dependent]) - {who})

    silent = sorted({c.get("type") for c in conns.values()} - {
        conns.get(str(r.get("connection_id") or ""), {}).get("type")
        for r in live if owners_of(r)} - {None})

    order = lambda x: (x["system"], x["kind"] or "", str(x["name"]))
    return {
        "person": who,
        "accounts": sorted((_item(r, conns) for r in accounts), key=order)[:MAX_ITEMS],
        "owns": sorted((_item(r, conns) for r in owned if r not in accounts), key=order)[:MAX_ITEMS],
        "breaks": sorted(breaks.values(), key=order)[:MAX_ITEMS],
        "systems_without_owner_data": silent,
        "checklist": _checklist(bool(accounts), bool(owned), bool(breaks)),
        "scope_note": "Ownership is what each system's API returned. Systems listed as having "
                      "no owner data cannot appear here, so an empty list there is not proof "
                      "the person owns nothing. Nothing was changed.",
    }


def _checklist(accounts: bool, owned: bool, breaks: bool) -> list[str]:
    if not (accounts or owned):
        return ["No resource names this person as owner. Check the systems listed as having no "
                "owner data by hand."]
    steps = []
    if breaks:
        steps.append("First, move each item under 'Keeps running on their authority' to a team "
                     "or service owner. Deleting the person's connection before this stops them.")
    if owned:
        steps.append("Transfer or delete what they own. For OAuth connections, reconnect with a "
                     "service account, then revoke the old grant at the provider.")
    if accounts:
        steps.append("Disable their accounts in each system last. Disabling SSO does not remove "
                     "API keys or tokens the account created.")
    steps.append("Run a scan, then open this report again: it should be empty.")
    return steps


def load(cur, tenant_id: str) -> tuple[list, list, list]:
    cur.execute("select id::text, name, type from connections where tenant_id = %s", (tenant_id,))
    connections = [{"id": r[0], "name": r[1], "type": r[2]} for r in cur.fetchall() or []]
    cur.execute(
        """select id::text, kind, name, labels, raw, connection_id::text, stale
             from resources where tenant_id = %s and not stale limit 50000""", (tenant_id,))
    resources = [{"id": r[0], "kind": r[1], "name": r[2], "labels": r[3] or {}, "raw": r[4] or {},
                  "connection_id": r[5], "stale": r[6]} for r in cur.fetchall() or []]
    # Human-confirmed owners (identity_owners), keyed by ext_id; absent on older databases.
    cur.execute("savepoint leaver_owners")
    try:
        cur.execute("select r.id::text, o.owner from identity_owners o join resources r "
                    "on r.tenant_id = o.tenant_id and r.ext_id = o.identity_ext_id "
                    "where o.tenant_id = %s", (tenant_id,))
        confirmed = {r[0]: r[1] for r in cur.fetchall() or []}
        cur.execute("release savepoint leaver_owners")
    except Exception:
        cur.execute("rollback to savepoint leaver_owners")
        confirmed = {}
    for res in resources:
        if res["id"] in confirmed:
            res["labels"] = {**res["labels"], "owner_confirmed": confirmed[res["id"]]}
    cur.execute(
        """select src_resource_id::text, dst_resource_id::text, kind from edges
            where tenant_id = %s and kind = any(%s) limit 100000""",
        (tenant_id, ["uses_credential", "uses_connection", "uses", "triggers", "acts_as"]))
    edges = [{"src": r[0], "dst": r[1], "kind": r[2]} for r in cur.fetchall() or []]
    return resources, edges, connections


def _cell(v) -> str:
    return str(v if v not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def to_markdown(rep: dict, generated_at: str) -> str:
    lines = [f"# Leaver report: {rep['person']}", "",
             f"Generated {generated_at[:16].replace('T', ' ')} UTC by VectaSec.", "",
             f"> {rep['scope_note']}", "", "## What to do, in order", ""]
    lines += [f"{i}. {s}" for i, s in enumerate(rep["checklist"], 1)]
    for title, key, extra in (("Keeps running on their authority", "breaks", True),
                              ("They own", "owns", False), ("Their accounts", "accounts", False)):
        lines += ["", f"## {title} ({len(rep[key])})", ""]
        if not rep[key]:
            lines.append("None found.")
            continue
        head = "| Item | Kind | System | Connection |" + (" Depends on |" if extra else " Detail |")
        lines += [head, "|---|---|---|---|---|"]
        for x in rep[key]:
            last = "; ".join(x.get("because") or []) if extra else x.get("detail")
            lines.append(f"| {_cell(x['name'])} | {_cell(x['kind'])} | {_cell(x['system'])} | "
                         f"{_cell(x['connection'])} | {_cell(last)} |")
    if rep["systems_without_owner_data"]:
        lines += ["", "## Connected systems with no owner data", "",
                  ", ".join(rep["systems_without_owner_data"])]
    return "\n".join(lines) + "\n"
