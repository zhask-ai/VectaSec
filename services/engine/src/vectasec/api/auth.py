"""Two token schemes the engine API verifies. Neither trusts a self-asserted header.

  1. Supabase user JWTs (console → engine). Verified against the project's PUBLIC JWKS — the
     project signs with ES256 (asymmetric), so no shared secret lives in the engine. The token's
     `sub` is the user; the tenant is resolved from tenant_members, never taken from the request.

  2. Collector service tokens (collector → engine). The collector authenticates outbound with a
     short-lived bearer token the engine mints at /collector/enroll. Stateless HMAC over a
     server-side secret: {tenant, collector, exp} + signature, so the engine verifies it without a
     session store and a leaked token expires on its own. This is NOT a Supabase JWT — collectors
     have no Supabase user.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Optional


# ── 1. Supabase user JWT ────────────────────────────────────────────────────
_jwk_client = None
_jwk_url = None


def _jwks_url() -> str:
    base = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    if not base:
        raise RuntimeError("SUPABASE_URL not set; cannot verify JWTs")
    return f"{base}/auth/v1/.well-known/jwks.json"


def verify_supabase_jwt(token: str) -> dict:
    """Return the verified claims, or raise. Signature + exp are checked against the live JWKS.

    PyJWKClient caches the fetched keys and refreshes on an unseen kid, so this is one network
    round trip at process start, not per request. audience is 'authenticated' for a logged-in
    Supabase user; we verify it to reject tokens minted for another audience.
    """
    global _jwk_client, _jwk_url
    import jwt  # local import: the collector imports this module's HMAC half without pyjwt present
    from jwt import PyJWKClient

    url = _jwks_url()
    if _jwk_client is None or _jwk_url != url:
        _jwk_client = PyJWKClient(url)
        _jwk_url = url

    signing_key = _jwk_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["ES256", "RS256"],   # accept whichever asymmetric alg the project rotates to
        audience="authenticated",
        options={"require": ["exp", "sub"]},
    )


# ── 2. Collector service token (stateless HMAC) ─────────────────────────────
def _collector_secret() -> bytes:
    """Server-side signing secret for collector tokens.

    Sourced from env; if unset, derived deterministically from the DB URL so a single-host dev
    deploy works without extra config, while a real deploy sets VECTASEC_COLLECTOR_TOKEN_SECRET
    to an independent value. Never the Supabase keys — a collector token is not a user token.
    """
    s = os.environ.get("VECTASEC_COLLECTOR_TOKEN_SECRET", "").strip()
    if s:
        return s.encode()
    seed = os.environ.get("DATABASE_URL", "vectasec-dev").encode()
    return hashlib.sha256(b"collector-token|" + seed).digest()


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint_collector_token(tenant_id: str, collector_id: str, ttl_seconds: int = 3600) -> tuple[str, int]:
    """Return (token, expires_in). Payload is signed, not encrypted — it carries no secret, only
    a tenant/collector binding and an expiry the engine re-checks on every call."""
    exp = int(time.time()) + int(ttl_seconds)
    payload = _b64u(json.dumps({"t": tenant_id, "c": collector_id, "exp": exp},
                               separators=(",", ":"), sort_keys=True).encode())
    sig = _b64u(hmac.new(_collector_secret(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}", ttl_seconds


def verify_collector_token(token: str) -> Optional[dict]:
    """Return {'tenant_id', 'collector_id'} for a valid, unexpired token, else None.

    Constant-time signature compare; explicit expiry check. Any malformed input returns None
    rather than raising — an unverifiable token is simply not authenticated.
    """
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        expected = _b64u(hmac.new(_collector_secret(), payload_b64.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig_b64, expected):
            return None
        claims = json.loads(_b64u_dec(payload_b64))
        if int(claims.get("exp", 0)) < int(time.time()):
            return None
        return {"tenant_id": claims["t"], "collector_id": claims["c"]}
    except Exception:
        return None
