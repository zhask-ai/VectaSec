"""The engine API's authentication gate (api/main.py::principal — STATUS.md gap #5).

The contract under test, in order of trust:

  1. DEFAULT DENY. With no Authorization header, the request is 401 — the self-asserted
     X-VectaSec-* headers are worth nothing on their own. There is no localhost carve-out.
  2. Engine service token (VECTASEC_ENGINE_TOKEN): constant-time-compared shared secret for
     trusted server-to-server callers; tenant from the token's configured scope
     (VECTASEC_ENGINE_TOKEN_TENANT) or the authenticated service's tenant header.
  3. Supabase user JWT: verified against the project JWKS (stubbed here — no network), actor
     is the token's sub, tenant resolved from membership, never from the request.
  4. Dev header trust: ONLY when VECTASEC_DEV_TRUST_HEADERS is explicitly truthy, and it warns
     loudly at startup.

principal() is a plain function, so most of this drives it directly and asserts on the
HTTPException status codes; a TestClient pass proves the wiring end to end over HTTP.
"""
import time
import types

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from vectasec.api import auth
from vectasec.api import main as api_main
from vectasec.api.main import app, principal

TENANT = "00000000-0000-0000-0000-000000000001"
OTHER_TENANT = "00000000-0000-0000-0000-000000000002"


@pytest.fixture(autouse=True)
def _clean_auth_env(monkeypatch):
    """Every test starts from the shipped default: nothing enabled, nothing trusted."""
    for var in ("VECTASEC_DEV_TRUST_HEADERS", "VECTASEC_ENGINE_TOKEN",
                "VECTASEC_ENGINE_TOKEN_TENANT", "SUPABASE_URL"):
        monkeypatch.delenv(var, raising=False)


def _status(exc_info) -> int:
    return exc_info.value.status_code


# ── 1. Default deny: header trust is OFF unless explicitly enabled ─────────
def test_headers_alone_are_401_by_default():
    """The gap-#5 hole itself: self-asserted tenant/actor headers must buy nothing."""
    with pytest.raises(HTTPException) as e:
        principal(authorization=None, x_vectasec_tenant=TENANT, x_vectasec_actor="mallory")
    assert _status(e) == 401


def test_no_credentials_at_all_is_401():
    with pytest.raises(HTTPException) as e:
        principal(authorization=None, x_vectasec_tenant=None, x_vectasec_actor=None)
    assert _status(e) == 401


def test_default_deny_over_http():
    """Same thing through the real HTTP stack — the dependency is actually wired."""
    client = TestClient(app)
    res = client.get("/connectors",
                     headers={"X-VectaSec-Tenant": TENANT, "X-VectaSec-Actor": "mallory"})
    assert res.status_code == 401


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "disabled"])
def test_non_truthy_env_values_do_not_enable_header_trust(monkeypatch, value):
    """Only an EXPLICIT truthy opt-in opens the dev path — not presence, not typos."""
    monkeypatch.setenv("VECTASEC_DEV_TRUST_HEADERS", value)
    with pytest.raises(HTTPException) as e:
        principal(authorization=None, x_vectasec_tenant=TENANT, x_vectasec_actor="dev")
    assert _status(e) == 401


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", " TRUE "])
def test_explicit_truthy_env_enables_header_trust(monkeypatch, value):
    monkeypatch.setenv("VECTASEC_DEV_TRUST_HEADERS", value)
    p = principal(authorization=None, x_vectasec_tenant=TENANT, x_vectasec_actor="dev")
    assert (p.tenant_id, p.actor) == (TENANT, "dev")


def test_dev_trust_falls_back_to_demo_tenant(monkeypatch):
    from vectasec.config import DEMO_TENANT
    monkeypatch.setenv("VECTASEC_DEV_TRUST_HEADERS", "1")
    p = principal(authorization=None, x_vectasec_tenant=None, x_vectasec_actor=None)
    assert p.tenant_id == DEMO_TENANT and p.actor == ""


def test_enabling_header_trust_warns_loudly(monkeypatch, caplog):
    """The other half of the gate: the opt-in must be impossible to miss in the logs."""
    monkeypatch.setenv("VECTASEC_DEV_TRUST_HEADERS", "1")
    with caplog.at_level("WARNING", logger="vectasec.api"):
        api_main._warn_if_header_trust_enabled()
    assert "VECTASEC_DEV_TRUST_HEADERS is ENABLED" in caplog.text

    caplog.clear()
    monkeypatch.delenv("VECTASEC_DEV_TRUST_HEADERS")
    with caplog.at_level("WARNING", logger="vectasec.api"):
        api_main._warn_if_header_trust_enabled()
    assert caplog.text == ""


# ── 2. Engine service token (server-to-server bearer) ──────────────────────
def test_engine_token_authenticates_with_tenant_header(monkeypatch):
    monkeypatch.setenv("VECTASEC_ENGINE_TOKEN", "svc-secret")
    p = principal(authorization="Bearer svc-secret",
                  x_vectasec_tenant=TENANT, x_vectasec_actor="user-1")
    assert (p.tenant_id, p.actor) == (TENANT, "user-1")


def test_engine_token_wrong_value_is_401(monkeypatch):
    """A wrong bearer falls through to JWT verification and dies there — never to header trust."""
    monkeypatch.setenv("VECTASEC_ENGINE_TOKEN", "svc-secret")
    with pytest.raises(HTTPException) as e:
        principal(authorization="Bearer svc-secreT",
                  x_vectasec_tenant=TENANT, x_vectasec_actor="user-1")
    assert _status(e) == 401


def test_engine_token_unset_disables_the_path(monkeypatch):
    """No VECTASEC_ENGINE_TOKEN in the environment: no bearer value can hit the service path,
    including the empty string an unset console might send."""
    for bearer in ["Bearer ", "Bearer anything"]:
        with pytest.raises(HTTPException) as e:
            principal(authorization=bearer, x_vectasec_tenant=TENANT, x_vectasec_actor="x")
        assert _status(e) == 401


def test_engine_token_requires_a_tenant(monkeypatch):
    monkeypatch.setenv("VECTASEC_ENGINE_TOKEN", "svc-secret")
    with pytest.raises(HTTPException) as e:
        principal(authorization="Bearer svc-secret",
                  x_vectasec_tenant=None, x_vectasec_actor="user-1")
    assert _status(e) == 400


def test_engine_token_tenant_scope_pins_the_tenant(monkeypatch):
    monkeypatch.setenv("VECTASEC_ENGINE_TOKEN", "svc-secret")
    monkeypatch.setenv("VECTASEC_ENGINE_TOKEN_TENANT", TENANT)
    # No header: the scope supplies the tenant.
    p = principal(authorization="Bearer svc-secret",
                  x_vectasec_tenant=None, x_vectasec_actor="user-1")
    assert p.tenant_id == TENANT
    # A matching header is fine; a mismatched one is refused, not honoured.
    p = principal(authorization="Bearer svc-secret",
                  x_vectasec_tenant=TENANT, x_vectasec_actor="user-1")
    assert p.tenant_id == TENANT
    with pytest.raises(HTTPException) as e:
        principal(authorization="Bearer svc-secret",
                  x_vectasec_tenant=OTHER_TENANT, x_vectasec_actor="user-1")
    assert _status(e) == 403


def test_engine_token_over_http(monkeypatch):
    monkeypatch.setenv("VECTASEC_ENGINE_TOKEN", "svc-secret")
    client = TestClient(app)
    ok = client.get("/connectors", headers={"Authorization": "Bearer svc-secret",
                                            "X-VectaSec-Tenant": TENANT})
    assert ok.status_code == 200
    bad = client.get("/connectors", headers={"Authorization": "Bearer nope",
                                             "X-VectaSec-Tenant": TENANT})
    assert bad.status_code == 401


# ── 3. Supabase JWT against a stubbed JWKS ─────────────────────────────────
def _es256_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return private.public_key(), pem


def _install_stub_jwks(monkeypatch, public_key):
    """Point auth's cached JWK client at a stub that hands back our test public key —
    verify_supabase_jwt then runs its REAL signature/audience/expiry checks against it."""
    monkeypatch.setenv("SUPABASE_URL", "https://unit-test.supabase.co")
    monkeypatch.setattr(auth, "_jwk_url",
                        "https://unit-test.supabase.co/auth/v1/.well-known/jwks.json")
    monkeypatch.setattr(auth, "_jwk_client", types.SimpleNamespace(
        get_signing_key_from_jwt=lambda token: types.SimpleNamespace(key=public_key)))


def _user_jwt(pem: bytes, sub="user-42", aud="authenticated", exp_in=600) -> str:
    import jwt as pyjwt
    return pyjwt.encode({"sub": sub, "aud": aud, "exp": int(time.time()) + exp_in},
                        pem, algorithm="ES256")


def test_jwt_path_verifies_and_resolves_tenant_from_membership(monkeypatch):
    public, pem = _es256_keypair()
    _install_stub_jwks(monkeypatch, public)
    seen = {}

    def fake_membership(user_id, requested):
        seen["args"] = (user_id, requested)
        return TENANT, "analyst"     # _tenant_for_user returns (tenant, role) — see RBAC
    monkeypatch.setattr(api_main, "_tenant_for_user", fake_membership)

    p = principal(authorization=f"Bearer {_user_jwt(pem)}",
                  x_vectasec_tenant=None, x_vectasec_actor=None)
    assert (p.tenant_id, p.actor) == (TENANT, "user-42")
    # The tenant came from membership resolution, with the request's ask passed for checking,
    # and the membership row's role rides along for the RBAC layer.
    assert seen["args"] == ("user-42", None)
    assert (p.via, p.role) == ("jwt", "analyst")


def test_jwt_tenant_header_is_a_request_not_an_assertion(monkeypatch):
    """With a JWT, X-VectaSec-Tenant is only ever INPUT to the membership check."""
    public, pem = _es256_keypair()
    _install_stub_jwks(monkeypatch, public)
    monkeypatch.setattr(api_main, "_tenant_for_user",
                        lambda user_id, requested: (_ for _ in ()).throw(
                            HTTPException(403, "not a member of the requested tenant")))
    with pytest.raises(HTTPException) as e:
        principal(authorization=f"Bearer {_user_jwt(pem)}",
                  x_vectasec_tenant=OTHER_TENANT, x_vectasec_actor=None)
    assert _status(e) == 403


def test_jwt_bad_signature_is_401(monkeypatch):
    public, _pem = _es256_keypair()
    _other_public, other_pem = _es256_keypair()
    _install_stub_jwks(monkeypatch, public)   # JWKS serves key A…
    monkeypatch.setattr(api_main, "_tenant_for_user", lambda u, r: TENANT)
    with pytest.raises(HTTPException) as e:   # …token signed with key B
        principal(authorization=f"Bearer {_user_jwt(other_pem)}",
                  x_vectasec_tenant=None, x_vectasec_actor=None)
    assert _status(e) == 401


@pytest.mark.parametrize("kwargs", [
    {"exp_in": -60},                # expired
    {"aud": "another-audience"},    # minted for someone else
    {"sub": ""},                    # no subject to attribute actions to
])
def test_jwt_claim_failures_are_401(monkeypatch, kwargs):
    public, pem = _es256_keypair()
    _install_stub_jwks(monkeypatch, public)
    monkeypatch.setattr(api_main, "_tenant_for_user", lambda u, r: TENANT)
    with pytest.raises(HTTPException) as e:
        principal(authorization=f"Bearer {_user_jwt(pem, **kwargs)}",
                  x_vectasec_tenant=None, x_vectasec_actor=None)
    assert _status(e) == 401


def test_garbage_bearer_is_401_not_500():
    for junk in ["Bearer", "Bearer ...", "Bearer a.b.c", "Basic dXNlcjpwYXNz"]:
        with pytest.raises(HTTPException) as e:
            principal(authorization=junk, x_vectasec_tenant=None, x_vectasec_actor=None)
        assert _status(e) == 401
