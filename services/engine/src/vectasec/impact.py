"""Fix preview and least-privilege recommendations: what a change would touch, before it is made.

Two questions that stop people fixing things:

  fix_preview()      "What breaks if I fix this?"  For one finding: who was seen using the
                     resource, what depends on it, what else the fix closes, and a runbook.
  recommend()        "What could this identity lose without anyone noticing?"  For each
                     identity: grants versus what it was actually observed using, as a dry-run
                     diff. Nothing is applied.

Both are joins over what scans stored: grants and identities (identity.py), the runtime
evidence ledger (runtime_evidence.py) and the resource graph. No system is contacted.

HONESTY — the whole value of this module is not overclaiming:
  * Runtime evidence is SAMPLED at scan time. "Not observed" is reported with the window we
    watched and never as "unused". A system with no usage source gets the verdict `unknown`,
    with the reason, not an empty consumer list that reads as "safe".
  * A recommendation to narrow a wildcard is only made where usage was observed at a level
    that can name targets. Otherwise the row says why no recommendation is possible.
  * Kafka's source sees consumer groups only: producers are invisible, so Kafka grants are
    never recommended for removal on the basis of silence.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from .runtime_evidence import RUNTIME_SOURCES

__all__ = ["fix_preview", "build_preview", "recommend", "build_recommendations", "usage_history",
           "MIN_WINDOW_DAYS", "SERVER_KINDS"]

MIN_WINDOW_DAYS = 14          # below this, silence is not long enough to act on
# A setting on one of these affects every client of the connection, not one principal.
SERVER_KINDS = frozenset({
    "broker", "cluster", "redis_server", "nats_server", "memcached_server", "es_cluster",
    "mqtt_broker", "mqtt_listener", "vhost", "node", "redpanda_cluster", "redpanda_broker",
    "pulsar_cluster", "solace_broker", "vault_server", "pgbouncer_pool", "pgbouncer_database"})
CREDENTIAL_KINDS = frozenset({"identity", "credential", "grant", "redis_user", "rabbitmq_user",
                              "pgbouncer_user", "confluent_api_key", "n8n_credential",
                              "zapier_connection", "make_connection", "workato_connection", "litellm_key",
                              "airflow_connection"})
_USES = ("uses_credential", "uses_connection", "uses", "triggers", "acts_as")


def _days(since, now: datetime) -> Optional[float]:
    if since is None:
        return None
    if isinstance(since, str):
        since = datetime.fromisoformat(since.replace("Z", "+00:00"))
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return max(0.0, (now - since).total_seconds() / 86400)


def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else v


def _principal_of(resource: dict) -> Optional[str]:
    """The principal name runtime evidence would carry for this identity-like resource."""
    labels, raw = resource.get("labels") or {}, resource.get("raw") or {}
    kind = resource.get("kind")
    if kind == "identity":
        return str(raw.get("principal") or resource.get("name") or "") or None
    if kind in ("credential", "grant"):
        ext = str(labels.get("owner") or labels.get("identity") or raw.get("owner_ext_id")
                  or raw.get("identity_ext_id") or "")
        return ext.split(":", 2)[-1] if ext.startswith("identity:") else (ext or None)
    if kind in ("redis_user", "rabbitmq_user", "pgbouncer_user"):
        return str(resource.get("name") or "") or None
    return None


def build_preview(finding: dict, resource: dict, connection: dict, evidence: Iterable[dict],
                  dependents: Iterable[dict], siblings: Iterable[dict], *,
                  window_start=None, now: Optional[datetime] = None) -> dict:
    """Pure. evidence: runtime_evidence rows for the connection {principal, resource_ext,
    source, peer_host, first_seen, last_seen, observed_scans}; dependents: resources with a
    uses-edge into this one {id, kind, name, owner}; siblings: other open findings here."""
    now = now or datetime.now(timezone.utc)
    ctype = str(connection.get("type") or "")
    source = RUNTIME_SOURCES.get(ctype)
    kind = str(resource.get("kind") or "")
    scope = ("everyone" if kind in SERVER_KINDS
             else "principal" if kind in CREDENTIAL_KINDS else "resource")
    principal = _principal_of(resource) if scope == "principal" else None
    ext_id = str(resource.get("ext_id") or "")

    rows = list(evidence)
    if scope == "principal":
        hit = [e for e in rows if principal and str(e.get("principal") or "").lower() == principal.lower()]
    elif scope == "everyone":
        hit = rows
    else:
        hit = [e for e in rows if e.get("resource_ext") and str(e["resource_ext"]) == ext_id]

    consumers: dict[tuple, dict] = {}
    for e in hit:
        key = (e.get("principal") or "", e.get("peer_host") or "")
        cur = consumers.get(key)
        if cur is None or str(_iso(e.get("last_seen"))) > str(cur["last_seen"]):
            consumers[key] = {"principal": e.get("principal") or "not attributed",
                              "peer_host": e.get("peer_host") or "",
                              "last_seen": _iso(e.get("last_seen")),
                              "observed_scans": int(e.get("observed_scans") or 1),
                              "source": e.get("source") or ""}
    consumer_list = sorted(consumers.values(), key=lambda c: str(c["last_seen"]), reverse=True)

    window_days = _days(window_start, now)
    deps = sorted(dependents, key=lambda d: (str(d.get("kind")), str(d.get("name"))))
    if source is None:
        verdict = "unknown"
        why = (f"{ctype or 'This system'} gives VectaSec no usage signal, so who uses this is "
               "not known. Ask the owner before changing it.")
    elif scope == "principal" and not source.attributes:
        verdict = "unknown"
        why = ("This system's usage data does not carry an authenticated identity, so activity "
               "cannot be tied to this credential.")
    elif consumer_list or deps:
        n = len(consumer_list)
        verdict = "will_affect"
        why = (f"{n} client{'s' if n != 1 else ''} seen using it"
               + (f" and {len(deps)} thing{'s depend' if len(deps) != 1 else ' depends'} on it" if deps else "")
               + ". Update them first.")
    elif window_days is None or window_days < MIN_WINDOW_DAYS:
        verdict = "unknown"
        watched = "not yet" if window_days is None else f"only {window_days:.0f} day(s)"
        why = (f"Nothing was seen using it, but this connection has been watched {watched}. "
               f"That is too short to call it unused (the bar is {MIN_WINDOW_DAYS} days).")
    else:
        verdict = "no_use_seen"
        why = (f"Nothing was seen using it in {window_days:.0f} days of scans. Usage is sampled "
               "at scan time, so a client that connects briefly between scans can be missed.")

    return {
        "finding_id": finding.get("id"), "rule_id": finding.get("rule_id"),
        "resource": {"id": resource.get("id"), "kind": kind, "name": resource.get("name")},
        "scope": scope, "verdict": verdict, "why": why,
        "consumers": consumer_list[:50], "consumers_total": len(consumer_list),
        "dependents": deps[:50], "dependents_total": len(deps),
        "also_closes": sorted(siblings, key=lambda s: str(s.get("rule_id")))[:20],
        "usage_source": source.reads if source else None,
        "window_days": None if window_days is None else round(window_days, 1),
        "runbook": _runbook(scope, verdict, len(consumer_list), len(deps)),
    }


def _runbook(scope: str, verdict: str, consumers: int, deps: int) -> list[str]:
    if scope == "principal":
        steps = ["Create the replacement credential next to the old one. Do not delete the old one yet."]
        if consumers or deps:
            steps.append(f"Update the {consumers + deps} consumer(s) listed here to the new credential, one at a time.")
        else:
            steps.append("Find the consumers: none were observed, so ask the owner or search your "
                         "config and secret stores for this name.")
        steps += ["Watch Access → Live connections until the old credential has not been seen for "
                  "a full business cycle (a day for services, a month for monthly jobs).",
                  "Revoke the old credential.",
                  "Press Verify on this finding. The rescan closes it if the issue is gone."]
        return steps
    if scope == "everyone":
        steps = [f"This setting applies to every client of the system ({consumers} seen)."
                 if consumers else "This setting applies to every client of the system."]
        if verdict != "no_use_seen":
            steps.append("Prepare each client for the new setting first (credentials, TLS trust, "
                         "the new port) so they keep working the moment it changes.")
        steps += ["Make the change in a maintenance window and keep the old value to hand so "
                  "you can put it back.",
                  "Check Access → Live connections: the same clients should reconnect.",
                  "Press Verify on this finding."]
        return steps
    steps = []
    if consumers or deps:
        steps.append(f"Tell the owners of the {consumers + deps} consumer(s) listed here before changing it.")
    steps += ["Apply the guided fix below.", "Press Verify on this finding."]
    return steps


def fix_preview(cur, tenant_id: str, finding_id: str) -> Optional[dict]:
    cur.execute(
        """select f.id::text, f.rule_id, r.id::text, r.kind, r.name, r.ext_id, r.labels, r.raw,
                  c.id::text, c.type, c.name
             from findings f
             left join resources r on r.id = f.resource_id
             left join connections c on c.id = r.connection_id
            where f.tenant_id = %s and f.id = %s""", (tenant_id, finding_id))
    row = cur.fetchone()
    if not row:
        return None
    finding = {"id": row[0], "rule_id": row[1]}
    if row[2] is None or row[8] is None:
        return {"finding_id": row[0], "rule_id": row[1], "resource": None, "verdict": "unknown",
                "why": "The finding's resource or connection no longer exists.", "consumers": [],
                "consumers_total": 0, "dependents": [], "dependents_total": 0, "also_closes": [],
                "usage_source": None, "window_days": None, "scope": "resource", "runbook": []}
    resource = {"id": row[2], "kind": row[3], "name": row[4], "ext_id": row[5],
                "labels": row[6] or {}, "raw": row[7] or {}}
    connection = {"id": row[8], "type": row[9], "name": row[10]}

    cur.execute(
        """select principal, resource_ext, source, peer_host, first_seen, last_seen, observed_scans
             from runtime_evidence where tenant_id = %s and connection_id = %s
            order by last_seen desc limit 5000""", (tenant_id, connection["id"]))
    evidence = [{"principal": r[0], "resource_ext": r[1], "source": r[2], "peer_host": r[3],
                 "first_seen": r[4], "last_seen": r[5], "observed_scans": r[6]}
                for r in cur.fetchall() or []]
    cur.execute("select min(started_at) from scans where tenant_id = %s and connection_id = %s "
                "and status = 'done'", (tenant_id, connection["id"]))
    w = cur.fetchone()
    cur.execute(
        """select s.id::text, s.kind, s.name, coalesce(s.labels->>'owner', s.labels->>'owner_label', '')
             from edges e join resources s on s.id = e.src_resource_id
            where e.tenant_id = %s and e.dst_resource_id = %s and e.kind = any(%s)
              and not s.stale limit 500""", (tenant_id, resource["id"], list(_USES)))
    dependents = [{"id": r[0], "kind": r[1], "name": r[2], "owner": r[3]} for r in cur.fetchall() or []]
    cur.execute(
        """select id::text, rule_id, title, severity from findings
            where tenant_id = %s and resource_id = %s and status = 'open' and id <> %s""",
        (tenant_id, resource["id"], finding_id))
    siblings = [{"id": r[0], "rule_id": r[1], "title": r[2], "severity": r[3]}
                for r in cur.fetchall() or []]
    return build_preview(finding, resource, connection, evidence, dependents, siblings,
                         window_start=w[0] if w else None)


# ── least privilege ───────────────────────────────────────────────────────

def _matches(target: str, observed: str) -> bool:
    t, o = target.strip().lower(), observed.strip().lower()
    if not t or not o:
        return False
    return t == o or o.endswith(":" + t) or o.endswith("-" + t) or o.endswith("/" + t)


def build_recommendations(identities: Iterable[dict], grants: Iterable[dict],
                          evidence: Iterable[dict], windows: dict, connection_types: dict,
                          *, now: Optional[datetime] = None) -> list[dict]:
    """Pure. identities/grants: resource dicts {id, name, labels, raw, connection_id};
    evidence: runtime rows + connection_id; windows: connection_id -> first done scan;
    connection_types: connection_id -> type. One entry per identity that holds a grant."""
    now = now or datetime.now(timezone.utc)
    by_identity: dict[str, list] = {}
    for g in grants:
        labels = g.get("labels") or {}
        by_identity.setdefault(str(labels.get("identity") or ""), []).append(g)
    seen: dict[tuple, set] = {}
    any_seen: set = set()
    for e in evidence:
        key = (str(e.get("connection_id")), str(e.get("principal") or "").lower())
        any_seen.add(key)
        if e.get("resource_ext"):
            seen.setdefault(key, set()).add(str(e["resource_ext"]))

    out = []
    for ident in identities:
        ext = str(ident.get("ext_id") or "")
        mine = by_identity.get(ext) or []
        if not mine:
            continue
        cid = str(ident.get("connection_id") or "")
        ctype = str(connection_types.get(cid) or (ident.get("labels") or {}).get("system") or "")
        source = RUNTIME_SOURCES.get(ctype)
        name = str((ident.get("raw") or {}).get("principal") or ident.get("name") or "")
        key = (cid, name.lower())
        window = _days(windows.get(cid), now)
        observed = sorted(seen.get(key, set()))
        current = [{"action": str((g.get("labels") or {}).get("action") or ""),
                    "target": str((g.get("labels") or {}).get("target") or ""),
                    "wildcard": str((g.get("labels") or {}).get("wildcard")) == "true"}
                   for g in mine]
        current.sort(key=lambda g: (g["target"], g["action"]))
        wild = [g for g in current if g["wildcard"]]
        diff: list[dict] = []

        if source is None or not source.attributes:
            confidence, verdict = "none", "cannot_assess"
            reason = (f"{ctype or 'This system'} has no usage source that names an authenticated "
                      "identity, so there is nothing to compare its grants against."
                      if source is None else
                      "This system's usage data does not carry an authenticated identity.")
        elif window is None or window < MIN_WINDOW_DAYS:
            confidence, verdict = "none", "cannot_assess"
            reason = (f"Watched for {0 if window is None else window:.0f} day(s); "
                      f"{MIN_WINDOW_DAYS} are needed before silence means anything.")
        elif key not in any_seen:
            confidence, verdict = "medium", "remove_all"
            reason = (f"Never seen connecting in {window:.0f} days of scans. Candidate to disable; "
                      "confirm with the owner because usage is sampled.")
            diff = [{"op": "-", **g} for g in current]
        elif not observed:
            confidence, verdict = "low", "cannot_assess"
            reason = ("Seen connecting, but the usage source does not say which resources it "
                      "touched, so individual grants cannot be judged.")
        else:
            unused = [g for g in current if not g["wildcard"]
                      and not any(_matches(g["target"], o) for o in observed)]
            if wild:
                confidence, verdict = "medium", "narrow"
                reason = (f"Holds {len(wild)} wildcard grant(s) but was seen using only "
                          f"{len(observed)} resource(s) in {window:.0f} days.")
                diff = ([{"op": "-", **g} for g in wild]
                        + [{"op": "+", "action": wild[0]["action"], "target": o, "wildcard": False}
                           for o in observed[:25]])
            elif unused:
                confidence, verdict = "low", "trim"
                reason = (f"{len(unused)} of {len(current)} grant(s) cover resources it was not "
                          f"seen using in {window:.0f} days.")
                diff = [{"op": "-", **g} for g in unused]
            else:
                confidence, verdict = "high", "right_sized"
                reason = "Every grant matches something it was seen using."
        out.append({"identity": name, "ext_id": ext, "resource_id": ident.get("id"),
                    "system": ctype, "connection_id": cid, "verdict": verdict,
                    "confidence": confidence, "reason": reason, "grants": len(current),
                    "wildcards": len(wild), "observed": observed[:25], "diff": diff,
                    "window_days": None if window is None else round(window, 1)})
    rank = {"narrow": 0, "remove_all": 1, "trim": 2, "cannot_assess": 3, "right_sized": 4}
    out.sort(key=lambda r: (rank[r["verdict"]], -r["wildcards"], r["identity"]))
    return out


def recommend(cur, tenant_id: str) -> dict:
    def rows(kind):
        cur.execute(
            """select id::text, ext_id, name, labels, raw, connection_id::text from resources
                where tenant_id = %s and kind = %s and not stale limit 20000""", (tenant_id, kind))
        return [{"id": r[0], "ext_id": r[1], "name": r[2], "labels": r[3] or {}, "raw": r[4] or {},
                 "connection_id": r[5]} for r in cur.fetchall() or []]
    identities, grants = rows("identity"), rows("grant")
    cur.execute(
        """select connection_id::text, principal, resource_ext from runtime_evidence
            where tenant_id = %s and principal is not null limit 100000""", (tenant_id,))
    evidence = [{"connection_id": r[0], "principal": r[1], "resource_ext": r[2]}
                for r in cur.fetchall() or []]
    cur.execute(
        """select c.id::text, c.type, min(s.started_at) from connections c
             left join scans s on s.connection_id = c.id and s.status = 'done'
            where c.tenant_id = %s group by c.id, c.type""", (tenant_id,))
    windows, types = {}, {}
    for cid, ctype, first in cur.fetchall() or []:
        windows[cid], types[cid] = first, ctype
    recs = build_recommendations(identities, grants, evidence, windows, types)
    counts: dict[str, int] = {}
    for r in recs:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"recommendations": recs[:1000], "total": len(recs), "counts": counts,
            "min_window_days": MIN_WINDOW_DAYS,
            "scope_note": "A dry run. Nothing is changed. Usage is sampled at scan time, so each "
                          "row is a candidate to confirm with the owner, not proof of non-use."}


# ── usage history: "who used this, and when" ─────────────────────────────

def usage_history(cur, tenant_id: str, resource_id: str) -> Optional[dict]:
    """Every principal the runtime evidence saw using one resource, with first and last sighting.

    Answers the auditor question operators say they cannot ("who consumed from this topic last
    quarter"), within what was sampled: evidence exists from the connection's observation start,
    only at scan times, and only for systems with a usage source.
    """
    cur.execute(
        """select r.kind, r.name, r.ext_id, r.connection_id::text, c.type,
                  c.runtime_observation_started_at
             from resources r join connections c on c.id = r.connection_id
            where r.tenant_id = %s and r.id = %s""", (tenant_id, resource_id))
    row = cur.fetchone()
    if not row:
        return None
    kind, name, ext_id, cid, ctype, started = row
    source = RUNTIME_SOURCES.get(str(ctype or ""))
    cur.execute(
        """select principal, peer_host, source, first_seen, last_seen, observed_scans, resource_ext
             from runtime_evidence
            where tenant_id = %s and connection_id = %s
              and (resource_ext = any(%s) or detail->'topics' ? %s)
            order by last_seen desc limit 500""",
        (tenant_id, cid, [ext_id, name], name))
    rows = [{"principal": r[0] or "not attributed", "peer_host": r[1] or "", "source": r[2],
             "first_seen": _iso(r[3]), "last_seen": _iso(r[4]), "observed_scans": int(r[5] or 1),
             "via": "assigned to this topic" if kind == "topic" and r[6] != ext_id else "connected to this resource"}
            for r in cur.fetchall() or []]
    principals = sorted({r["principal"] for r in rows})
    if source is None:
        note = (f"{ctype} gives VectaSec no usage signal, so no use can be recorded here.")
    elif not source.attributes:
        note = ("Usage comes from consumer groups; producers are not visible and the client id is "
                "self-reported, not an authenticated identity.")
    else:
        note = "Sampled at scan times: a client that connects briefly between scans can be missed."
    return {"resource": {"kind": kind, "name": name}, "system": ctype,
            "observation_started_at": _iso(started), "supported": source is not None,
            "rows": rows, "principals": principals, "note": note,
            "usage_source": source.reads if source else None}
