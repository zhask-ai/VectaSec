"""The collector service-token scheme (api/auth.py): stateless HMAC, verifiable without a store,
and expiring on its own. No DB, no network — the token is self-contained by design."""
import time

import pytest

from vectasec.api import auth


def test_mint_then_verify_round_trips(monkeypatch):
    monkeypatch.setenv("VECTASEC_COLLECTOR_TOKEN_SECRET", "unit-secret")
    token, ttl = auth.mint_collector_token("tenant-1", "collector-9", ttl_seconds=3600)
    claims = auth.verify_collector_token(token)
    assert claims == {"tenant_id": "tenant-1", "collector_id": "collector-9"}
    assert ttl == 3600


def test_a_tampered_payload_fails(monkeypatch):
    monkeypatch.setenv("VECTASEC_COLLECTOR_TOKEN_SECRET", "unit-secret")
    token, _ = auth.mint_collector_token("tenant-1", "collector-9")
    payload, sig = token.split(".", 1)
    # Flip the payload but keep the (now-wrong) signature — must not verify.
    import base64, json
    bad = json.dumps({"t": "tenant-EVIL", "c": "collector-9", "exp": 9999999999}).encode()
    forged = base64.urlsafe_b64encode(bad).rstrip(b"=").decode() + "." + sig
    assert auth.verify_collector_token(forged) is None


def test_a_wrong_secret_fails(monkeypatch):
    monkeypatch.setenv("VECTASEC_COLLECTOR_TOKEN_SECRET", "secret-A")
    token, _ = auth.mint_collector_token("t", "c")
    monkeypatch.setenv("VECTASEC_COLLECTOR_TOKEN_SECRET", "secret-B")
    assert auth.verify_collector_token(token) is None, "a token signed by another secret must not verify"


def test_an_expired_token_fails(monkeypatch):
    monkeypatch.setenv("VECTASEC_COLLECTOR_TOKEN_SECRET", "unit-secret")
    token, _ = auth.mint_collector_token("t", "c", ttl_seconds=-1)   # already expired
    assert auth.verify_collector_token(token) is None


def test_garbage_input_returns_none_not_raises(monkeypatch):
    monkeypatch.setenv("VECTASEC_COLLECTOR_TOKEN_SECRET", "unit-secret")
    for junk in ["", "no-dot", "a.b.c.d", "....", "not base64!.sig"]:
        assert auth.verify_collector_token(junk) is None


def test_secret_is_never_the_supabase_keys(monkeypatch):
    """The collector token secret must be independent of any Supabase credential — a collector
    token is not a user token, and reusing a Supabase secret here would couple two trust domains."""
    monkeypatch.delenv("VECTASEC_COLLECTOR_TOKEN_SECRET", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://x")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sb_secret_do_not_reuse")
    secret = auth._collector_secret()
    assert b"sb_secret_do_not_reuse" not in secret
    assert isinstance(secret, bytes) and len(secret) == 32   # sha256 digest
