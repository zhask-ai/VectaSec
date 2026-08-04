"""Binding a collector-mode connection to the collector that runs it.

`GET /collector/jobs` dispatches on `connections.collector_id`. That column existed, and the two
collector endpoints read it, but NOTHING ever wrote it — so a collector-mode connection could be
created and scanned, and its scans sat `queued` forever with no collector able to claim them.
That is why the collector round trip had never been observed end to end.

The tenant check in `_resolve_collector` is the security-critical part and is what these tests
mostly pin: the collector id arrives in a REQUEST BODY, and a collector belonging to another
tenant would be handed a job carrying the NAME of a target in someone else's estate.
"""
import uuid

import pytest
from fastapi import HTTPException

from vectasec.api.main import _resolve_collector

TENANT = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"


class FakeCursor:
    """Speaks the two SELECT shapes _resolve_collector emits."""

    def __init__(self, collectors, tenant_of):
        self.collectors = collectors          # [(id, name)] visible to the queried tenant
        self.tenant_of = tenant_of            # id -> owning tenant
        self._one, self._all = None, []
        self.queries = []

    def execute(self, sql, params=()):
        s = " ".join(sql.split()).lower()
        self.queries.append((s, params))
        if "where id=%s and tenant_id=%s" in s:
            cid, tid = params
            self._one = (cid,) if self.tenant_of.get(cid) == tid else None
        elif "from collectors where tenant_id=%s" in s:
            tid = params[0]
            self._all = [(c, n) for c, n in self.collectors if self.tenant_of.get(c) == tid]
        else:
            raise AssertionError(f"unexpected SQL: {s}")

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


MINE = "aaaaaaaa-0000-0000-0000-000000000001"
ALSO_MINE = "aaaaaaaa-0000-0000-0000-000000000002"
THEIRS = "bbbbbbbb-0000-0000-0000-000000000001"


def cursor(*, mine=(MINE,), theirs=(THEIRS,)):
    collectors = [(c, f"collector-{c[:4]}") for c in (*mine, *theirs)]
    tenant_of = {**{c: TENANT for c in mine}, **{c: OTHER for c in theirs}}
    return FakeCursor(collectors, tenant_of)


def test_cloud_mode_never_binds_a_collector():
    cur = cursor()
    assert _resolve_collector(cur, TENANT, "cloud", uuid.UUID(MINE)) is None
    assert cur.queries == [], "cloud mode must not even look"


def test_an_explicitly_named_collector_of_this_tenant_is_bound():
    cur = cursor()
    assert _resolve_collector(cur, TENANT, "collector", uuid.UUID(MINE)) == MINE


def test_another_tenants_collector_is_refused():
    """The load-bearing test. Accepting it would dispatch a job — and the target NAME inside it —
    to an operator in a different organisation."""
    cur = cursor()
    with pytest.raises(HTTPException) as e:
        _resolve_collector(cur, TENANT, "collector", uuid.UUID(THEIRS))
    assert e.value.status_code == 400
    assert "no such collector" in e.value.detail
    # And the refusal must not confirm the id exists elsewhere — no cross-tenant oracle.
    assert THEIRS not in e.value.detail


def test_a_collector_id_that_exists_nowhere_is_refused_identically():
    cur = cursor()
    with pytest.raises(HTTPException) as e:
        _resolve_collector(cur, TENANT, "collector", uuid.uuid4())
    assert "no such collector" in e.value.detail


def test_a_sole_enrolled_collector_is_bound_without_being_named():
    """There is no ambiguity to resolve with exactly one, and requiring a uuid nobody has been
    shown is how a feature goes unused. The audit row records that we chose."""
    cur = cursor(mine=(MINE,))
    assert _resolve_collector(cur, TENANT, "collector", None) == MINE


def test_with_several_enrolled_the_request_must_choose():
    cur = cursor(mine=(MINE, ALSO_MINE))
    with pytest.raises(HTTPException) as e:
        _resolve_collector(cur, TENANT, "collector", None)
    assert "collector_id is required" in e.value.detail
    assert MINE in e.value.detail and ALSO_MINE in e.value.detail   # names the choices


def test_with_none_enrolled_the_error_says_what_to_do():
    """Otherwise the connection is created, scans queue, and nothing ever runs them — the exact
    silent dead end this whole change exists to remove."""
    cur = cursor(mine=())
    with pytest.raises(HTTPException) as e:
        _resolve_collector(cur, TENANT, "collector", None)
    assert "has none" in e.value.detail
    assert "cloud" in e.value.detail          # points at the working alternative


def test_the_sole_collector_shortcut_is_still_tenant_scoped():
    """One collector enrolled — but it belongs to somebody else. That must read as 'none'."""
    cur = cursor(mine=(), theirs=(THEIRS,))
    with pytest.raises(HTTPException) as e:
        _resolve_collector(cur, TENANT, "collector", None)
    assert "has none" in e.value.detail
