"""Breach-day mode: match an advisory or a vendor breach to the inventory in seconds.

The day a product in your stack is being exploited, or a vendor that holds your tokens says it
was breached, the question is not "what is my posture". It is three questions, and they have to
be answered before the next scan could even finish:

  1. Do we run it, where, and is our version one of the affected ones?
  2. Which machine credentials does that system accept, and in what order do I rotate them?
  3. Which credentials for OTHER systems does that tool hold, that I must rotate over there?

Everything here is answered from what earlier scans stored. No network call is made, so the
brief is ready in the time it takes to read three tables.

HONESTY
  * A version is `affected`, `not_affected` or `unknown`. Unknown is not "not affected": a
    system whose version the scan could not read stays on the list.
  * A version the scan only INFERRED (Kafka's capability matrix) is reported as unknown for
    this purpose, exactly as detect/lifecycle.py refuses to assert on it.
  * The brief lists only systems VectaSec has connected or discovered. The text says so:
    "nothing found" means "nothing in what we can see", never "you are not exposed".
  * The rotation order is a ranking by what a credential can reach, with the reason on every
    row. It is advice to a human who owns the change, not an action taken.
"""
from __future__ import annotations

import json
import re
from typing import Iterable, Optional

from .sbom import _product_of, _version_of, parse_version

__all__ = ["build_brief", "load_inputs", "create_brief", "to_markdown", "parse_spec",
           "version_status", "ALIASES", "HELD_SECRET_KINDS"]

MAX_ROWS = 500

# What people type on the day → the connector types / product labels that mean it.
ALIASES: dict[str, tuple[str, ...]] = {
    "kafka": ("kafka", "msk", "confluent", "redpanda", "apache kafka"),
    "confluent": ("confluent", "kafka"),
    "redpanda": ("redpanda",),
    "rabbitmq": ("rabbitmq", "amqp"),
    "redis": ("redis", "valkey", "elasticache"),
    "valkey": ("valkey", "redis"),
    "nats": ("nats",),
    "kong": ("kong",),
    "n8n": ("n8n",),
    "zapier": ("zapier",),
    "make": ("make", "integromat"),
    "workato": ("workato",),
    "mulesoft": ("mulesoft", "anypoint"),
    "boomi": ("boomi",),
    "airflow": ("airflow",),
    "elasticsearch": ("elasticsearch", "opensearch"),
    "vault": ("vault",),
    "keycloak": ("keycloak",),
    "moveit": ("moveit", "mft"),
    "goanywhere": ("goanywhere", "mft"),
    "cleo": ("cleo", "mft"),
    "mcp": ("mcp",),
    "litellm": ("litellm",),
    "langflow": ("langflow",),
    "ingress-nginx": ("ingress-nginx", "ingress_nginx", "nginx-ingress"),
    "etcd": ("etcd", "coordination"),
    "zookeeper": ("zookeeper", "coordination"),
    "mqtt": ("mqtt", "mosquitto", "emqx", "hivemq"),
    "pulsar": ("pulsar",),
    "activemq": ("activemq", "artemis"),
    "solr": ("solr",),
    "memcached": ("memcached",),
}

# Resource kinds that are a credential the tool HOLDS for some other system. Rotating the
# tool's own password does nothing for these: they must be rotated at the destination.
HELD_SECRET_KINDS = frozenset({
    "n8n_credential", "zapier_connection", "make_connection", "workato_connection", "boomi_connection",
    "airflow_connection", "confluent_api_key", "k8s_sa_token_secret", "workato_api_client",
})

_SENS_RANK = {"restricted": 3, "confidential": 2, "internal": 1}


def _norm(s) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").lower()).strip("-")


def _terms(product: str) -> set[str]:
    p = _norm(product)
    return {_norm(t) for t in ALIASES.get(p, (p,))} | {p}


def parse_spec(spec: Optional[str]) -> list[tuple[str, tuple]]:
    """"<1.121.0", ">=7.0, <7.2.5", "=2.4.1" → [(op, (major, minor, patch))]. A clause that
    cannot be parsed raises ValueError: a mistyped range must not silently match nothing."""
    out = []
    for clause in re.split(r"[,\s]+and\s+|,", spec or ""):
        clause = clause.strip()
        if not clause:
            continue
        m = re.match(r"^(<=|>=|<|>|==|=)?\s*(.+)$", clause)
        op, ver = (m.group(1) or "="), parse_version(m.group(2)) if m else None
        if ver is None:
            raise ValueError(f"cannot read the version in {clause!r}")
        out.append(("=" if op == "==" else op, ver))
    return out


def version_status(version: Optional[str], inferred: bool, spec: list) -> str:
    """affected | not_affected | unknown."""
    if not spec:
        return "unknown" if not version or inferred else "affected"
    v = parse_version(version) if version and not inferred else None
    if v is None:
        return "unknown"
    ops = {"<": v.__lt__, "<=": v.__le__, ">": v.__gt__, ">=": v.__ge__, "=": v.__eq__}
    return "affected" if all(ops[op](bound) for op, bound in spec) else "not_affected"


def _priority(row: dict) -> tuple[int, list[str]]:
    score, why = 0, []
    sens = _SENS_RANK.get(str(row.get("highest_sensitivity") or "").lower(), 0)
    if sens >= 2:
        score += 3 + (sens - 2)
        why.append(f"reaches {row['highest_sensitivity']} data")
    if int(row.get("wildcard_grants") or 0) > 0:
        score += 3
        why.append("has wildcard grants")
    if str(row.get("external")).lower() in ("true", "yes", "1"):
        score += 2
        why.append("external party")
    lu = str(row.get("last_used_at") or "")
    if lu and lu not in ("never", "unknown"):
        score += 1
        why.append("in active use")
    elif lu == "never":
        why.append("never used: revoke instead of rotating")
    if int(row.get("grants") or 0) == 0:
        why.append("no grants recorded")
    return score, why


def build_brief(advisory: dict, connections: Iterable[dict], resources: Iterable[dict],
                register_rows: Iterable[dict]) -> dict:
    """The brief, from plain dicts. Pure and deterministic.

    advisory:    {product, kind, affected?, title?, reference?}
    connections: {id, name, type, last_scanned_at}
    resources:   {id, kind, name, ext_id, labels, raw, connection_id, connection_type, stale}
    register_rows: report.to_access_register_rows output
    """
    product = str(advisory.get("product") or "").strip()
    terms = _terms(product)
    spec = parse_spec(advisory.get("affected"))
    conns = {str(c["id"]): c for c in connections}

    def is_it(value) -> bool:
        n = _norm(value)
        return bool(n) and (n in terms or any(t and t in n.split("-") for t in terms))

    matched_conn_ids = {cid for cid, c in conns.items() if is_it(c.get("type"))}
    systems: dict[str, dict] = {}

    def system_entry(key: str, name: str, source: str, connection_id=None) -> dict:
        return systems.setdefault(key, {
            "name": name, "source": source, "connection_id": connection_id,
            "versions": [], "status": "unknown", "last_scanned_at": None, "resources": 0})

    for cid in matched_conn_ids:
        c = conns[cid]
        e = system_entry(f"conn:{cid}", c.get("name") or cid, "connected", cid)
        e["last_scanned_at"] = c.get("last_scanned_at")

    held: list[dict] = []
    for r in resources:
        if r.get("stale"):
            continue
        cid = str(r.get("connection_id") or "")
        prod = _product_of(r)
        in_conn = cid in matched_conn_ids
        discovered = r.get("kind") == "discovered_service" and is_it(prod)
        component = is_it(prod) and not in_conn and not discovered and r.get("kind") != "discovered_service"
        if in_conn or discovered or component:
            if discovered:
                e = system_entry(f"disc:{r.get('ext_id')}", str(r.get("name")), "discovered, not connected")
            elif in_conn:
                e = systems[f"conn:{cid}"]
            else:
                c = conns.get(cid, {})
                e = system_entry(f"comp:{cid}:{prod}", f"{prod} in {c.get('name') or 'a connection'}",
                                 "component of another connection", cid or None)
            e["resources"] += 1
            version, inferred = _version_of(r)
            if version and (in_conn is False or is_it(prod) or prod is None):
                status = version_status(version, inferred, spec)
                item = {"version": version, "inferred": inferred, "status": status,
                        "resource": str(r.get("name"))}
                if item not in e["versions"] and len(e["versions"]) < 20:
                    e["versions"].append(item)
        if in_conn and r.get("kind") in HELD_SECRET_KINDS and len(held) < MAX_ROWS:
            labels = r.get("labels") or {}
            held.append({
                "name": str(r.get("name")), "kind": r.get("kind"),
                "for": str(labels.get("credential_type") or labels.get("app")
                           or labels.get("provider") or labels.get("conn_type") or "unknown"),
                "owner": str(labels.get("owner") or labels.get("owner_label") or ""),
                "used_by": str(labels.get("used_by_count") or ""),
                "connection": conns.get(cid, {}).get("name") or ""})

    for e in systems.values():
        statuses = {v["status"] for v in e["versions"]}
        e["status"] = ("affected" if "affected" in statuses
                       else "unknown" if "unknown" in statuses or not statuses
                       else "not_affected")

    rotate = []
    for row in register_rows:
        if not is_it(row.get("system")):
            continue
        score, why = _priority(row)
        rotate.append({
            "identity": row.get("identity"), "system": row.get("system"),
            "identity_type": row.get("identity_type"), "owner": row.get("owner") or "",
            "credential_types": row.get("credential_types") or "",
            "last_used_at": row.get("last_used_at") or "unknown",
            "grants": int(row.get("grants") or 0),
            "wildcard_grants": int(row.get("wildcard_grants") or 0),
            "highest_sensitivity": row.get("highest_sensitivity") or "",
            "score": score, "why": why})
    rotate.sort(key=lambda r: (-r["score"], str(r["identity"])))
    for i, r in enumerate(rotate, 1):
        r["order"] = i
    held.sort(key=lambda h: (h["connection"], h["for"], h["name"]))

    sys_list = sorted(systems.values(), key=lambda e: (
        {"affected": 0, "unknown": 1, "not_affected": 2}[e["status"]], e["name"]))
    counts = {s: sum(1 for e in sys_list if e["status"] == s)
              for s in ("affected", "unknown", "not_affected")}
    kind = advisory.get("kind") or "vulnerability"
    if not sys_list:
        headline = (f"No connected or discovered system matches {product!r}. This covers only "
                    "what VectaSec can see.")
    elif kind == "vendor_breach":
        headline = (f"{len(sys_list)} system(s) match {product!r}: {len(held)} credential(s) it "
                    f"holds for other systems, {len(rotate)} identit(ies) it accepts.")
    else:
        headline = (f"{len(sys_list)} system(s) run {product!r}: {counts['affected']} on an "
                    f"affected version, {counts['unknown']} with an unknown version, "
                    f"{counts['not_affected']} not affected.")
    return {
        "product": product, "kind": kind, "affected": advisory.get("affected") or "",
        "title": advisory.get("title") or f"{product} advisory",
        "reference": advisory.get("reference") or "",
        "headline": headline, "systems": sys_list, "counts": counts,
        "rotate": rotate[:MAX_ROWS], "rotate_total": len(rotate),
        "held": held, "steps": _steps(kind, bool(sys_list), bool(held), bool(rotate)),
        "scope_note": "Built from stored scan results; no system was contacted. Only connected "
                      "and discovered systems are covered, and a version the scan could not "
                      "read is listed as unknown, not as safe.",
    }


def _steps(kind: str, any_system: bool, any_held: bool, any_rotate: bool) -> list[str]:
    if not any_system:
        return ["Check systems VectaSec is not connected to: laptops, other clouds, vendors' own tenants.",
                "If you do run it somewhere, connect it or add its address to discovery and run this again."]
    steps = []
    if kind == "vendor_breach":
        steps.append("Assume every credential the vendor holds is known to the attacker.")
        if any_held:
            steps.append("Rotate each held credential at its DESTINATION system (list below), then "
                         "update it in the tool. Revoking only inside the tool leaves the old "
                         "secret valid.")
        steps.append("For OAuth connections, revoke the grant at the provider: a password reset "
                     "does not end a refresh token.")
    else:
        steps.append("Patch or isolate the systems marked affected. Treat unknown versions as "
                     "affected until you have read the version yourself.")
        steps.append("If the affected system was reachable from the internet, assume the "
                     "credentials it accepts and holds are exposed.")
        if any_held:
            steps.append("Rotate the credentials the tool holds for other systems at their "
                         "destination (list below).")
    if any_rotate:
        steps.append("Rotate the identities the system accepts in the order below. Rows marked "
                     "'never used' should be revoked, not rotated.")
    steps.append("Sweep logs from the disclosure date back to the last scan before it: new "
                 "users, new API keys, new workflows or routes, and logins from new addresses.")
    steps.append("Run a scan when done, then press Verify on the related findings so the fix is "
                 "recorded.")
    return steps


# ── loading and persistence ───────────────────────────────────────────────

def load_inputs(cur, tenant_id: str, generated_at: str) -> tuple[list, list, list]:
    from .api.extra import load_access_register
    cur.execute("select id::text, name, type, last_scanned_at from connections where tenant_id = %s",
                (tenant_id,))
    connections = [{"id": r[0], "name": r[1], "type": r[2],
                    "last_scanned_at": r[3].isoformat() if hasattr(r[3], "isoformat") else r[3]}
                   for r in cur.fetchall() or []]
    cur.execute(
        """select r.id::text, r.kind, r.name, r.ext_id, r.labels, r.raw, r.connection_id::text,
                  c.type, r.stale
             from resources r left join connections c on c.id = r.connection_id
            where r.tenant_id = %s and not r.stale
              and (r.kind = any(%s) or r.kind = 'discovered_service'
                   or r.labels ? 'version' or r.labels ? 'product'
                   or r.raw ? 'version' or r.raw ? 'product')
            limit 20000""",
        (tenant_id, list(HELD_SECRET_KINDS)),
    )
    resources = [{"id": r[0], "kind": r[1], "name": r[2], "ext_id": r[3], "labels": r[4] or {},
                  "raw": r[5] or {}, "connection_id": r[6], "connection_type": r[7],
                  "stale": r[8]} for r in cur.fetchall() or []]
    rows, _coverage, _tenant = load_access_register(cur, tenant_id, generated_at=generated_at)
    return connections, resources, rows


def create_brief(cur, tenant_id: str, advisory: dict, actor: Optional[str], generated_at: str) -> dict:
    connections, resources, rows = load_inputs(cur, tenant_id, generated_at)
    brief = build_brief(advisory, connections, resources, rows)
    brief["generated_at"] = generated_at
    cur.execute(
        """insert into breach_briefs (tenant_id, title, product, kind, affected, reference,
                                      summary, created_by)
           values (%s,%s,%s,%s,%s,%s,%s,%s) returning id""",
        (tenant_id, brief["title"][:200], brief["product"][:100], brief["kind"],
         brief["affected"][:100] or None, brief["reference"][:500] or None,
         json.dumps(brief, default=str), actor),
    )
    brief["id"] = str(cur.fetchone()[0])
    return brief


def _cell(v) -> str:
    return str(v if v not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def to_markdown(brief: dict) -> str:
    lines = [f"# Breach-day brief: {brief.get('title')}", "",
             f"Product: {brief.get('product')} · Kind: {str(brief.get('kind')).replace('_', ' ')}"
             + (f" · Affected versions: {brief['affected']}" if brief.get("affected") else "")
             + (f" · Reference: {brief['reference']}" if brief.get("reference") else ""),
             f"Generated {str(brief.get('generated_at', ''))[:16].replace('T', ' ')} UTC by VectaSec.",
             "", f"> {brief.get('scope_note')}", "", f"**{brief.get('headline')}**", "",
             "## What to do, in order", ""]
    lines += [f"{i}. {s}" for i, s in enumerate(brief.get("steps") or [], 1)]
    lines += ["", "## Systems", ""]
    if brief.get("systems"):
        lines += ["| System | How we know | Status | Versions seen | Last scan |", "|---|---|---|---|---|"]
        for s in brief["systems"]:
            vers = ", ".join(f"{v['version']}{' (inferred)' if v['inferred'] else ''}" for v in s["versions"]) or "not read"
            lines.append(f"| {_cell(s['name'])} | {_cell(s['source'])} | {s['status'].replace('_', ' ')} | "
                         f"{_cell(vers)} | {_cell(str(s.get('last_scanned_at') or '')[:16])} |")
    else:
        lines.append("None matched.")
    lines += ["", "## Rotate these identities, in this order", ""]
    if brief.get("rotate"):
        lines += ["| # | Identity | Owner | Credential | Last used | Why this position |", "|---|---|---|---|---|---|"]
        lines += [f"| {r['order']} | {_cell(r['identity'])} | {_cell(r['owner'])} | "
                  f"{_cell(r['credential_types'])} | {_cell(r['last_used_at'])} | "
                  f"{_cell('; '.join(r['why']))} |" for r in brief["rotate"]]
    else:
        lines.append("No identity is recorded for this system.")
    lines += ["", "## Credentials the tool holds for other systems (rotate at the destination)", ""]
    if brief.get("held"):
        lines += ["| Credential | For | Owner | Used by | In |", "|---|---|---|---|---|"]
        lines += [f"| {_cell(h['name'])} | {_cell(h['for'])} | {_cell(h['owner'])} | "
                  f"{_cell(h['used_by'])} | {_cell(h['connection'])} |" for h in brief["held"]]
    else:
        lines.append("None recorded.")
    return "\n".join(lines) + "\n"
