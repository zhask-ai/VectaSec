"""blast_radius must terminate on a cyclic graph and never report a node as its own blast
radius.

The guard that makes this true lives in the recursive CTE in graph.py — each walk row carries
the array of resource ids that produced it and the recursive term refuses any next hop already
in that array (`not (r.id = any(w.path))`). That guard is SQL, so the only honest test drives the
real query against a real Postgres; a Python reimplementation of the walk would test a different
thing than the one that ships. graph.py's own docstring names the exact shape that breaks a
naive walk: "a broker hosts a topic that mirrors to a topic that routes back to the broker", i.e.
broker -> topic -> mirror -> broker. Without the per-path visited set, a walk of depth >= 3 (or an
undirected walk) reaches the root again and files the broker inside its own blast radius.

Everything runs inside ONE transaction that is ALWAYS rolled back. The fixture inserts a throwaway
tenant + connection + resources + a 3-edge cycle; the tests read them back through blast_radius;
teardown ROLLS BACK and closes the connection, so nothing is ever committed and the live database
the engine points at is never mutated. If DATABASE_URL is unset or the database is unreachable the
module skips rather than failing, so an offline checkout still gets a green suite.
"""
import uuid

import pytest

psycopg = pytest.importorskip("psycopg")

from vectasec import graph


def _resolve_db_url() -> str:
    # An entry point reads .env; a test is allowed to do the same (test_config.py's boundary is
    # about *importing the engine* not injecting .env — an explicit load here is fine).
    from vectasec.config import load_env, settings
    load_env()
    return settings.database_url


_DB_URL = _resolve_db_url()
if not _DB_URL:
    pytest.skip("DATABASE_URL not configured; the graph walk needs a Postgres",
                allow_module_level=True)
try:
    _probe = psycopg.connect(_DB_URL, connect_timeout=10)
    _probe.close()
except Exception as exc:  # noqa: BLE001 — any connect failure means "no DB here", skip cleanly
    pytest.skip(f"database unreachable ({exc}); the graph walk needs a Postgres",
                allow_module_level=True)


# The cycle graph.py's docstring calls out. Kept as data so the shape is readable at a glance.
_NODES = [("broker", "broker-1", "broker-1"),
          ("topic", "payments", "topic-payments"),
          ("topic", "payments-mirror", "topic-payments-mirror")]
_CYCLE = [("broker-1", "topic-payments"),              # broker hosts topic
          ("topic-payments", "topic-payments-mirror"), # topic mirrors to mirror
          ("topic-payments-mirror", "broker-1")]       # mirror routes back to broker


@pytest.fixture
def cyclic_graph():
    """A rolled-back transaction holding broker -> topic -> mirror -> broker.

    Yields (cur, tenant_id, ext_id -> resource uuid). NOTHING is committed: teardown always rolls
    back, so this never touches the live estate even though it writes to the live database.
    """
    conn = psycopg.connect(_DB_URL, connect_timeout=10)
    conn.autocommit = False
    cur = conn.cursor()
    try:
        tenant = str(uuid.uuid4())          # a throwaway tenant: the walk filters on tenant_id,
        cur.execute("insert into tenants (id, name) values (%s, 'test-graph-cycle')", (tenant,))
        connection_id = str(uuid.uuid4())   # so only these three nodes are ever in scope.
        cur.execute(
            "insert into connections (id, tenant_id, type, name) values (%s,%s,'kafka','test-cycle')",
            (connection_id, tenant),
        )

        ids: dict[str, str] = {}
        for kind, name, ext in _NODES:
            rid = str(uuid.uuid4())
            cur.execute(
                "insert into resources (id, tenant_id, connection_id, kind, name, ext_id) "
                "values (%s,%s,%s,%s,%s,%s)",
                (rid, tenant, connection_id, kind, name, ext),
            )
            ids[ext] = rid

        for src, dst in _CYCLE:
            cur.execute(
                "insert into edges (tenant_id, src_resource_id, dst_resource_id, kind) "
                "values (%s,%s,%s,'hosts')",
                (tenant, ids[src], ids[dst]),
            )

        yield cur, tenant, ids
    finally:
        conn.rollback()   # never commit — the whole point is that nothing persists
        conn.close()


def test_blast_radius_terminates_on_a_cycle(cyclic_graph):
    """If the path guard were removed the recursive term would keep re-entering the cycle; the
    depth ceiling still bounds it, but returning a result at all is the first half of the claim."""
    cur, tenant, ids = cyclic_graph
    result = graph.blast_radius(cur, tenant, ids["broker-1"], max_depth=8)
    assert result["found"] is True


@pytest.mark.parametrize("root_ext", ["broker-1", "topic-payments", "topic-payments-mirror"])
@pytest.mark.parametrize("directed", [False, True])
def test_a_node_is_never_in_its_own_blast_radius(cyclic_graph, root_ext, directed):
    """THE cycle-safety assertion. Every node in the cycle can reach itself by going the whole way
    round; the guard must ensure it is never reported as reachable *from itself*. Checked from all
    three roots and in both directed and undirected mode — the mode that most nearly reintroduces
    the bug (directed, which must traverse all three hops before the closing edge is refused) is
    covered explicitly.
    """
    cur, tenant, ids = cyclic_graph
    result = graph.blast_radius(cur, tenant, ids[root_ext], max_depth=8, directed=directed)
    reached_ids = {n["id"] for n in result["nodes"]}
    assert ids[root_ext] not in reached_ids, (
        f"{root_ext} reached itself through the cycle (directed={directed})")
    assert result["root"]["ext_id"] == root_ext
    # No node is reported twice, and no path revisits a node — the walk stays simple.
    ext_ids = [n["ext_id"] for n in result["nodes"]]
    assert len(ext_ids) == len(set(ext_ids))
    for n in result["nodes"]:
        assert len(n["path"]) == len(set(n["path"])), f"path revisits a node: {n['path']}"


def test_directed_walk_traverses_the_whole_cycle_then_stops_at_the_root(cyclic_graph):
    """Directed broker -> topic -> mirror -> broker: the walk follows all three hops, and the
    closing edge back to the broker is refused by the PATH guard, not by the depth ceiling. So the
    reachable set is exactly {topic, mirror}, mirror sits one hop past topic, and depth_bounded is
    False (it terminated because the cycle closed, not because it ran out of depth budget).
    """
    cur, tenant, ids = cyclic_graph
    result = graph.blast_radius(cur, tenant, ids["broker-1"], max_depth=8, directed=True)
    reached = {n["ext_id"]: n for n in result["nodes"]}
    assert set(reached) == {"topic-payments", "topic-payments-mirror"}
    assert reached["topic-payments"]["depth"] == 1
    assert reached["topic-payments-mirror"]["depth"] == 2
    assert reached["topic-payments-mirror"]["path"] == [
        "broker-1", "topic-payments", "topic-payments-mirror"]
    assert result["depth_bounded"] is False


def test_undirected_walk_reaches_both_neighbours_without_looping(cyclic_graph):
    """Undirected, the broker touches both the topic (out edge) and the mirror (in edge) directly,
    so both are one hop away and the count is exactly two — the cycle does not inflate it."""
    cur, tenant, ids = cyclic_graph
    result = graph.blast_radius(cur, tenant, ids["broker-1"], max_depth=8, directed=False)
    assert {n["ext_id"] for n in result["nodes"]} == {"topic-payments", "topic-payments-mirror"}
    assert result["count"] == 2
