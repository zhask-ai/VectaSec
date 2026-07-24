"""RBAC on the engine API (api/main.py: editing/admin/_require_rank/would_drop_last_admin).

The matrix under test:

    viewer          — read-only: every GET, 403 on every mutation
    editor/analyst  — scans, triage, suppressions, connections (incl. PATCH)
    admin/owner     — everything, incl. integrations, routing rules and members

Two enforcement paths share it:
  • JWT: principal() loaded the role with the membership lookup (p.role).
  • Engine service token: the console asserts the server-verified user in X-VectaSec-Actor;
    the ENGINE resolves that user's role from tenant_members (_role_for_actor) and enforces.
    The console is trusted to name the actor, never to grant it capabilities.

Requests ride the real HTTP stack (TestClient) with the service token; the role lookup is
monkeypatched (no DB). "Allowed" is proven by a non-403 outcome — usually 400/404/422/503
from the handler itself, which can only be reached PAST the role gate.
"""
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from vectasec.api import main as api_main
from vectasec.api.main import (
    Principal,
    ROLE_RANK,
    app,
    admin,
    editing,
    would_drop_last_admin,
)

TENANT = "00000000-0000-0000-0000-000000000001"
OTHER_TENANT = "00000000-0000-0000-0000-000000000002"

VIEWER = "00000000-0000-0000-0000-0000000000a1"
EDITOR = "00000000-0000-0000-0000-0000000000a2"
ADMIN = "00000000-0000-0000-0000-0000000000a3"
NOBODY = "00000000-0000-0000-0000-0000000000a9"   # authenticated service names a non-member

ROLES = {VIEWER: "viewer", EDITOR: "analyst", ADMIN: "owner"}


@pytest.fixture(autouse=True)
def _service_auth(monkeypatch):
    """Engine service token on, dev trust off, roles resolved from the fake membership table.
    DATABASE_URL is cleared so anything that reaches a handler's DB call 503s (still non-403,
    which is all these tests assert for the 'allowed' half)."""
    monkeypatch.setenv("VECTASEC_ENGINE_TOKEN", "svc-secret")
    monkeypatch.delenv("VECTASEC_DEV_TRUST_HEADERS", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(api_main, "_role_for_actor",
                        lambda tenant, actor: ROLES.get(actor))


def h(actor: str) -> dict:
    return {"Authorization": "Bearer svc-secret",
            "X-VectaSec-Tenant": TENANT, "X-VectaSec-Actor": actor}


client = TestClient(app)


# ═══ The matrix over HTTP ═════════════════════════════════════════════════════
# (method, path, body) for each tier of mutation.
EDITOR_MUTATIONS = [
    ("POST", "/scans", {"type": "bogus-connector"}),
    ("POST", "/connections", {"type": "bogus", "name": "x"}),
    ("POST", f"/connections/{TENANT}/test", None),
    ("POST", f"/connections/{TENANT}/scan", None),
    ("DELETE", f"/connections/{TENANT}", None),
    ("PATCH", f"/connections/{TENANT}", {"scan_interval_minutes": 60}),
    ("POST", f"/findings/{TENANT}/status", {"status": "resolved"}),
    ("POST", f"/findings/{TENANT}/assign", {"assignee": None}),
    ("POST", f"/findings/{TENANT}/triage", None),
    ("POST", "/suppressions", {"rule_id": "KAFKA.X", "reason": "test"}),
    ("POST", "/compliance/PCI_DSS_4_0_1/1.2.3/attest", {"scope": "all"}),
]
ADMIN_MUTATIONS = [
    ("POST", "/integrations", {"type": "slack", "name": "x",
                               "config": {"webhook_url": "https://h"}}),
    ("DELETE", f"/integrations/{TENANT}", None),
    ("POST", f"/integrations/{TENANT}/test", None),
    ("POST", "/routing-rules", {"integration_id": TENANT, "match": {}}),
    ("DELETE", f"/routing-rules/{TENANT}", None),
    ("POST", "/members", {"email": "new@corp.io", "role": "viewer"}),
    ("PATCH", f"/members/{VIEWER}", {"role": "admin"}),
    ("DELETE", f"/members/{VIEWER}", None),
]


def _call(method, path, body, actor):
    return client.request(method, path, json=body, headers=h(actor))


@pytest.mark.parametrize("method,path,body", EDITOR_MUTATIONS + ADMIN_MUTATIONS)
def test_viewer_is_denied_every_mutation(method, path, body):
    res = _call(method, path, body, VIEWER)
    assert res.status_code == 403, f"{method} {path}: {res.status_code} {res.text}"
    assert "role" in res.json()["detail"]


@pytest.mark.parametrize("method,path,body", EDITOR_MUTATIONS)
def test_editor_passes_the_gate_on_editor_surface(method, path, body):
    res = _call(method, path, body, EDITOR)
    assert res.status_code != 403, f"{method} {path}: unexpectedly denied: {res.text}"


@pytest.mark.parametrize("method,path,body", ADMIN_MUTATIONS)
def test_editor_is_denied_admin_surface(method, path, body):
    res = _call(method, path, body, EDITOR)
    assert res.status_code == 403, f"{method} {path}: {res.status_code} {res.text}"


@pytest.mark.parametrize("method,path,body", EDITOR_MUTATIONS + ADMIN_MUTATIONS)
def test_admin_passes_every_gate(method, path, body):
    res = _call(method, path, body, ADMIN)
    assert res.status_code != 403, f"{method} {path}: unexpectedly denied: {res.text}"


@pytest.mark.parametrize("method,path,body", EDITOR_MUTATIONS + ADMIN_MUTATIONS)
def test_a_non_member_actor_is_denied_mutations(method, path, body):
    """The service token authenticates the CONSOLE; an actor with no membership row gets no
    capabilities from it."""
    res = _call(method, path, body, NOBODY)
    assert res.status_code == 403
    assert "not a member" in res.json()["detail"]


def test_reads_stay_open_to_every_member():
    """viewer is READ-only, not locked out: GETs never hit the role gate. (503 here: the
    handler ran and found no database, which is precisely 'past the gate'.)"""
    for path in ["/connectors", "/integrations", "/routing-rules", "/members"]:
        res = client.get(path, headers=h(VIEWER))
        assert res.status_code != 403, f"GET {path} denied for viewer: {res.text}"


def test_dev_header_trust_skips_the_role_gate(monkeypatch):
    """Dev mode already trusts self-asserted headers wholesale; a role check against a
    made-up actor would be theatre. The loud startup warning covers this mode."""
    monkeypatch.setenv("VECTASEC_DEV_TRUST_HEADERS", "1")
    res = client.post("/scans", json={"type": "bogus-connector"},
                      headers={"X-VectaSec-Tenant": TENANT, "X-VectaSec-Actor": "dev"})
    assert res.status_code == 400        # past authz, rejected by the handler's own logic
    assert "no connector" in res.json()["detail"]


def test_body_tenant_must_match_the_authenticated_tenant():
    res = client.post("/scans", json={"type": "kafka", "tenant_id": OTHER_TENANT},
                      headers=h(EDITOR))
    assert res.status_code == 403
    assert "tenant" in res.json()["detail"]


# ═══ The gate itself (direct, both auth paths) ════════════════════════════════
def test_jwt_principal_role_is_enforced_without_a_second_lookup(monkeypatch):
    """JWT requests carry the role from the membership lookup; _role_for_actor must not be
    consulted again (it would be a second DB round trip per mutation)."""
    monkeypatch.setattr(api_main, "_role_for_actor",
                        lambda t, a: (_ for _ in ()).throw(AssertionError("looked up twice")))
    viewer = Principal(tenant_id=TENANT, actor=VIEWER, via="jwt", role="viewer")
    with pytest.raises(HTTPException) as e:
        editing(viewer)
    assert e.value.status_code == 403

    analyst = Principal(tenant_id=TENANT, actor=EDITOR, via="jwt", role="analyst")
    assert editing(analyst) is analyst
    with pytest.raises(HTTPException) as e:
        admin(analyst)
    assert e.value.status_code == 403

    owner = Principal(tenant_id=TENANT, actor=ADMIN, via="jwt", role="owner")
    assert admin(owner) is owner


def test_service_path_resolves_the_named_actors_role(monkeypatch):
    seen = {}

    def fake_role(tenant, actor):
        seen["args"] = (tenant, actor)
        return "viewer"
    monkeypatch.setattr(api_main, "_role_for_actor", fake_role)
    p = Principal(tenant_id=TENANT, actor=EDITOR, via="service")
    with pytest.raises(HTTPException) as e:
        editing(p)
    assert e.value.status_code == 403
    assert seen["args"] == (TENANT, EDITOR)   # the ENGINE looked the actor up, in this tenant


def test_unknown_role_value_is_denied_not_defaulted(monkeypatch):
    monkeypatch.setattr(api_main, "_role_for_actor", lambda t, a: "superuser")
    with pytest.raises(HTTPException) as e:
        editing(Principal(tenant_id=TENANT, actor=EDITOR, via="service"))
    assert e.value.status_code == 403


def test_role_rank_maps_the_live_role_values():
    """tenant_members.role live values (console's MemberRole) all rank; editor is accepted as
    a synonym so the API vocabulary works too."""
    assert ROLE_RANK["owner"] == ROLE_RANK["admin"] == 3
    assert ROLE_RANK["analyst"] == ROLE_RANK["editor"] == 2
    assert ROLE_RANK["viewer"] == 1


# ═══ Last-admin protection (pure) ═════════════════════════════════════════════
MEMBERS = [(ADMIN, "owner"), (EDITOR, "analyst"), (VIEWER, "viewer")]


def test_cannot_remove_the_last_admin():
    assert would_drop_last_admin(MEMBERS, ADMIN, None) is True


def test_cannot_demote_the_last_admin():
    assert would_drop_last_admin(MEMBERS, ADMIN, "viewer") is True
    assert would_drop_last_admin(MEMBERS, ADMIN, "analyst") is True


def test_admin_to_admin_tier_change_is_fine():
    assert would_drop_last_admin(MEMBERS, ADMIN, "admin") is False   # owner → admin: still admin tier


def test_removing_a_non_admin_is_always_fine():
    assert would_drop_last_admin(MEMBERS, EDITOR, None) is False
    assert would_drop_last_admin(MEMBERS, VIEWER, "analyst") is False


def test_with_two_admins_either_may_go():
    members = MEMBERS + [(NOBODY, "admin")]
    assert would_drop_last_admin(members, ADMIN, None) is False
    assert would_drop_last_admin(members, NOBODY, "viewer") is False


# ═══ Request validation (past the gate) ══════════════════════════════════════
@pytest.mark.parametrize("bad", [0, 4, 10081, -5, "hourly"])
def test_patch_connection_rejects_out_of_range_intervals(bad):
    res = client.patch(f"/connections/{TENANT}", json={"scan_interval_minutes": bad},
                       headers=h(EDITOR))
    assert res.status_code == 422


def test_patch_connection_requires_the_field():
    res = client.patch(f"/connections/{TENANT}", json={}, headers=h(EDITOR))
    assert res.status_code == 400
    assert "scan_interval_minutes" in res.json()["detail"]


def _patch_conn_db(monkeypatch, previous=15):
    """A scripted DB for the PATCH happy path: one connection row, records the UPDATE."""
    state = {"updates": [], "audits": []}

    class Cur:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            s = " ".join(sql.split()).lower()
            if s.startswith("select type, name, scan_interval_minutes"):
                self._one = ("kafka", "prod", previous)
            elif s.startswith("update connections set scan_interval_minutes"):
                state["updates"].append(params)
                self._one = None
            elif s.startswith("insert into audit_log"):
                state["audits"].append(params)
            else:
                raise AssertionError(f"unexpected SQL: {s}")

        def fetchone(self):
            return self._one

    class Conn:
        autocommit = False

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def cursor(self):
            return Cur()

        def commit(self):
            state["committed"] = True

    monkeypatch.setattr(api_main, "_db", lambda: Conn())
    return state


def test_patch_connection_sets_the_interval_and_audits(monkeypatch):
    state = _patch_conn_db(monkeypatch, previous=15)
    res = client.patch(f"/connections/{TENANT}", json={"scan_interval_minutes": 60},
                       headers=h(EDITOR))
    assert res.status_code == 200
    body = res.json()
    assert body["scan_interval_minutes"] == 60 and body["previous"] == 15
    assert state["updates"] == [(60, TENANT, TENANT)]
    assert state["audits"], "PATCH without an audit row is an unaccountable mutation"
    assert state.get("committed")


def test_patch_connection_null_unschedules(monkeypatch):
    state = _patch_conn_db(monkeypatch, previous=60)
    res = client.patch(f"/connections/{TENANT}", json={"scan_interval_minutes": None},
                       headers=h(EDITOR))
    assert res.status_code == 200
    assert res.json()["scan_interval_minutes"] is None
    assert state["updates"] == [(None, TENANT, TENANT)]


@pytest.mark.parametrize("body", [{"email": "new@corp.io", "role": "root"},
                                  {"email": "not-an-email", "role": "viewer"},
                                  {"role": "viewer"}])
def test_add_member_validation(body):
    res = client.post("/members", json=body, headers=h(ADMIN))
    assert res.status_code == 422


def test_change_member_role_validation():
    res = client.patch(f"/members/{VIEWER}", json={"role": "root"}, headers=h(ADMIN))
    assert res.status_code == 422


@pytest.mark.parametrize("match,detail_hint", [
    ({"bogus_key": 1}, "unsupported match keys"),
    ({"min_severity": "urgent"}, "min_severity"),
    ({"connector_types": "kafka"}, "list of strings"),
    ({"notify_on": ["on_tuesdays"]}, "notify_on"),
])
def test_routing_rule_match_validation(match, detail_hint):
    res = client.post("/routing-rules", json={"integration_id": TENANT, "match": match},
                      headers=h(ADMIN))
    assert res.status_code == 422
    assert detail_hint in json.dumps(res.json())
