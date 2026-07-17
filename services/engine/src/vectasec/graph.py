"""The asset graph: resources + edges in Postgres, walked with recursive CTEs.

There is no graph database and there deliberately isn't one. The graph is small (a
middleware estate is thousands of nodes, not billions), it must be read in the same
transaction as the findings it explains, and a second datastore would be a second thing
that can disagree with the system of record about what exists.

Every query filters on tenant_id explicitly. The engine connects as a trusted role that
bypasses RLS, so RLS is NOT a backstop here — these predicates are the only thing standing
between two customers' estates. Adding one to every query, including ones already scoped by
a resource id, is cheap; auditing which ones didn't need it is not.

All functions take an open cursor: the caller owns the transaction, so a graph read taken
during a scan sees that scan's own writes.
"""
from typing import Optional

# A blast-radius walk enumerates simple paths, so its cost grows with depth, not with node
# count. 4 hops covers what a security team actually asks ("what does this broker touch");
# past ~8 the answer is "most of the estate" and the query stops being worth its cost.
_MAX_DEPTH_CEILING = 8

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def neighbours(cur, tenant_id: str, resource_id: str) -> list:
    """Direct edges in both directions, as the other end of each edge.

    Direction is reported rather than filtered on: an edge's direction encodes containment
    or flow as the connector saw it, which is not the same as what a compromise of this
    resource reaches. The caller decides which of those it wants.
    """
    cur.execute(
        """select e.id, e.kind, e.labels,
                  case when e.src_resource_id = %(rid)s then 'out' else 'in' end as direction,
                  r.id, r.ext_id, r.kind, r.name, r.namespace, r.stale
           from edges e
           join resources r
             on r.tenant_id = %(tenant)s
            and r.id = case when e.src_resource_id = %(rid)s
                            then e.dst_resource_id else e.src_resource_id end
           where e.tenant_id = %(tenant)s
             and (e.src_resource_id = %(rid)s or e.dst_resource_id = %(rid)s)
           order by direction, r.kind, r.name""",
        {"tenant": tenant_id, "rid": resource_id},
    )
    return [
        {"edge_id": str(r[0]), "edge_kind": r[1], "edge_labels": r[2] or {}, "direction": r[3],
         "id": str(r[4]), "ext_id": r[5], "kind": r[6], "name": r[7],
         "namespace": r[8], "stale": r[9]}
        for r in cur.fetchall()
    ]


def blast_radius(cur, tenant_id: str, resource_id: str, max_depth: int = 4,
                 directed: bool = False) -> dict:
    """What is reachable from a resource, with the depth and path that reached it.

    Undirected by default. A broker→topic edge means "hosts", but an attacker on that broker
    reads the topic and an attacker on the topic learns the broker — reachability in a
    posture sense is symmetric even when the edge that records it is not. `directed=True`
    restricts to following edges src→dst for callers that want strict downstream flow.

    Cycle guard: each row carries the array of resource ids that produced it, and the
    recursive term refuses any next hop already in that array (`not (r.id = any(w.path))`).
    A per-path visited set, not a global one — a global one would be cheaper but would
    suppress the second, shorter path to a node just because a longer one found it first,
    and the path is the part a human acts on.

    The depth bound is a SECOND, independent guard, and it is not redundant: the path guard
    alone already terminates (a simple path can't exceed the node count), but it terminates
    by enumerating every simple path, which is exponential in a dense graph — terminating
    and finishing inside a query budget are different things. Conversely a depth bound alone
    terminates but answers wrong: on a graph with one 3-cycle it walks the root back to
    itself and reports it as its own blast radius. Cycles are not hypothetical here — a
    broker hosts a topic that mirrors to a topic that routes back to the broker.
    """
    depth = max(1, min(int(max_depth), _MAX_DEPTH_CEILING))

    # Chosen from a bool, never interpolated from caller data.
    hop = ("e.src_resource_id = w.id" if directed
           else "(e.src_resource_id = w.id or e.dst_resource_id = w.id)")

    cur.execute(
        f"""with recursive walk as (
              -- Anchor from `resources`, not from the literal: it proves the root exists and
              -- belongs to this tenant, so a foreign uuid walks nothing instead of walking
              -- the neighbours of someone else's resource.
              select r.id, 0 as depth, array[r.id] as path, array[r.ext_id] as path_ext,
                     null::text as via_edge_kind
                from resources r
               where r.tenant_id = %(tenant)s and r.id = %(rid)s
              union all
              select r.id, w.depth + 1, w.path || r.id, w.path_ext || r.ext_id, e.kind
                from walk w
                join edges e
                  on e.tenant_id = %(tenant)s and {hop}
                join resources r
                  on r.tenant_id = %(tenant)s
                 and r.id = case when e.src_resource_id = w.id
                                 then e.dst_resource_id else e.src_resource_id end
               where w.depth < %(depth)s
                 and not (r.id = any(w.path))
            )
            select distinct on (w.id)
                   w.id, w.depth, w.path_ext, w.via_edge_kind,
                   r.ext_id, r.kind, r.name, r.namespace, r.stale
              from walk w
              join resources r on r.id = w.id and r.tenant_id = %(tenant)s
             where w.depth > 0
             -- distinct on + this order keeps the SHORTEST path to each node: a node found at
             -- depth 1 and again at depth 3 is one hop away, and reporting the long way round
             -- would misstate how exposed it is.
             order by w.id, w.depth, w.path_ext""",
        {"tenant": tenant_id, "rid": resource_id, "depth": depth},
    )
    nodes = [
        {"id": str(r[0]), "depth": r[1], "path": r[2], "via_edge_kind": r[3],
         "ext_id": r[4], "kind": r[5], "name": r[6], "namespace": r[7], "stale": r[8]}
        for r in cur.fetchall()
    ]
    nodes.sort(key=lambda n: (n["depth"], n["kind"], n["name"]))

    cur.execute(
        "select id, ext_id, kind, name, namespace, stale from resources where tenant_id=%s and id=%s",
        (tenant_id, resource_id),
    )
    row = cur.fetchone()
    root: Optional[dict] = None
    if row:
        root = {"id": str(row[0]), "ext_id": row[1], "kind": row[2], "name": row[3],
                "namespace": row[4], "stale": row[5]}

    by_depth: dict[int, int] = {}
    by_kind: dict[str, int] = {}
    for n in nodes:
        by_depth[n["depth"]] = by_depth.get(n["depth"], 0) + 1
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1

    return {
        "root": root,
        "found": root is not None,
        "max_depth": depth,
        "directed": directed,
        # True when the frontier was still expanding when the depth bound stopped it — the
        # blast radius is at least this, and the caller must not present it as complete.
        "depth_bounded": bool(by_depth.get(depth)),
        "count": len(nodes),
        "by_depth": by_depth,
        "by_kind": by_kind,
        "nodes": nodes,
    }


def exposure_paths(cur, tenant_id: str) -> list:
    """Open findings, each with the resource it fired on and that resource's direct
    neighbours — "this exposure is on X, and X touches Y and Z".

    One hop, not a full blast radius: this is the estate-wide list, and it runs one query
    for every finding rather than one walk per finding. Call blast_radius() for the deep
    answer on a single finding.

    Resolved and suppressed findings are excluded — a human has already ruled on them, and
    leaving them in would pad the list with exposures that are not exposures.
    """
    cur.execute(
        f"""select f.id, f.rule_id, f.title, f.severity, f.status, f.fingerprint, f.last_seen,
                   r.id, r.ext_id, r.kind, r.name, r.namespace, r.stale,
                   coalesce(
                     jsonb_agg(distinct jsonb_build_object(
                       'id', n.id, 'ext_id', n.ext_id, 'kind', n.kind, 'name', n.name,
                       'edge_kind', e.kind,
                       'direction', case when e.src_resource_id = r.id then 'out' else 'in' end
                     )) filter (where n.id is not null), '[]'::jsonb) as touches
              from findings f
              join resources r on r.id = f.resource_id and r.tenant_id = %(tenant)s
              -- LEFT: a finding on a resource with no edges is still an exposure. An inner
              -- join here would silently drop every finding on an unlinked resource, which
              -- is most of them before a connector emits edges.
              left join edges e
                on e.tenant_id = %(tenant)s
               and (e.src_resource_id = r.id or e.dst_resource_id = r.id)
              left join resources n
                on n.tenant_id = %(tenant)s
               and n.id = case when e.src_resource_id = r.id
                               then e.dst_resource_id else e.src_resource_id end
             where f.tenant_id = %(tenant)s
               and f.status not in ('resolved', 'suppressed')
             group by f.id, r.id
             order by array_position(%(sev)s::text[], f.severity), f.last_seen desc""",
        {"tenant": tenant_id, "sev": _SEVERITY_ORDER},
    )
    return [
        {"finding_id": str(r[0]), "rule_id": r[1], "title": r[2], "severity": r[3],
         "status": r[4], "fingerprint": r[5], "last_seen": r[6],
         "resource": {"id": str(r[7]), "ext_id": r[8], "kind": r[9], "name": r[10],
                      "namespace": r[11], "stale": r[12]},
         "touches": r[13], "touch_count": len(r[13])}
        for r in cur.fetchall()
    ]


def summary(cur, tenant_id: str) -> dict:
    """Inventory shape: counts by kind, edge count, stale count."""
    cur.execute(
        """select kind, count(*), count(*) filter (where stale)
             from resources where tenant_id = %s group by kind order by 2 desc, 1""",
        (tenant_id,),
    )
    rows = cur.fetchall()
    by_kind = {r[0]: r[1] for r in rows}
    stale_by_kind = {r[0]: r[2] for r in rows if r[2]}

    cur.execute(
        "select kind, count(*) from edges where tenant_id = %s group by kind order by 2 desc, 1",
        (tenant_id,),
    )
    edges_by_kind = {r[0]: r[1] for r in cur.fetchall()}

    return {
        "resources": sum(by_kind.values()),
        "by_kind": by_kind,
        # Stale = collected before, absent now. Surfaced next to the live counts because a
        # resource vanishing is itself a signal, and a stale one still carries findings.
        "stale": sum(stale_by_kind.values()),
        "stale_by_kind": stale_by_kind,
        "edges": sum(edges_by_kind.values()),
        "edges_by_kind": edges_by_kind,
    }
