"""Proof mode: show that a finding is reachable right now, with a transcript.

A detector reads configuration and says "anonymous access is enabled". That is a claim about a
setting. Proof mode turns it into a claim about the world: the engine makes the ONE request any
client makes before it authenticates, against the finding's own target, and records whether the
door actually opened. "Misconfigured" becomes "proven open at 14:02", and after the fix the same
button gives "not reproduced at 14:20".

THE LAW (the same one discover/probes.py is written under, and this module reuses those probes
precisely so it cannot drift from it):

  * No credential is sent, guessed, defaulted or sprayed. Not `guest/guest`, not `sk-1234`.
    Trying a default password is brute force with a nice UI, and it is how a scanner locks an
    account or trips an alarm. The proofs here are all "no credential was needed".
  * Nothing is written, published, enqueued or deleted. Reads only, and only reads a health
    check would make. No keys are listed, no messages are consumed, no documents are read.
  * The target is never taken from the caller. It is derived from the tenant's own connection
    config, or from a resource a scan of that connection returned. An API caller cannot aim
    this at a host of their choosing.
  * One attempt, short timeout, bounded read.

HONESTY. Four verdicts, and the difference between them is the point:

  proven          the unauthenticated action succeeded
  not_reproduced  the target answered and refused (auth required), or the open door is gone
  unreachable     the engine could not reach the target from where it runs — a private
                  network, a collector-mode connection, a host that is down. This says NOTHING
                  about exploitability and is never shown as "safe".
  unsupported     this rule has no safe proof. Most rules do not: a weak cipher, a wildcard
                  ACL or a missing audit log cannot be demonstrated without doing harm, and
                  the product does not pretend otherwise.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse

from .discover import http_probes as H
from .discover import probes as P

__all__ = ["PROVERS", "Prover", "ProofResult", "supported", "describe", "resolve_target",
           "run_proof", "prove_finding", "list_proofs", "NOT_DONE"]

TIMEOUT_S = 4.0
MAX_TRANSCRIPT = 12
NOT_DONE = "No credential is sent and nothing is written."


@dataclass
class ProofResult:
    verdict: str                      # proven | not_reproduced | unreachable | unsupported
    action: str
    target: Optional[str] = None
    transcript: list = field(default_factory=list)
    signals: dict = field(default_factory=dict)
    reason: Optional[str] = None
    duration_ms: int = 0

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "action": self.action, "target": self.target,
                "transcript": self.transcript, "signals": self.signals, "reason": self.reason,
                "duration_ms": self.duration_ms}


@dataclass(frozen=True)
class Prover:
    """How one rule is proven.

    probe:   a discover.* probe — (host, port, timeout) -> ProbeResult | None
    opened:  ProbeResult -> bool. True means the unauthenticated action succeeded.
    target:  (config, resource) -> (host, port) | None
    action:  the one sentence shown BEFORE the user presses the button, and stored with the
             result. It must say exactly what goes over the wire.
    """
    probe: Callable
    opened: Callable
    target: Callable
    action: str


# ── target resolution: only ever from the tenant's own connection / scanned resource ──────
def _host_port(value: str, default_port: int) -> Optional[tuple]:
    value = (value or "").strip()
    if not value:
        return None
    if "://" in value:
        u = urlparse(value)
        if not u.hostname:
            return None
        return u.hostname, u.port or (443 if u.scheme in ("https", "wss", "tls") else default_port)
    host, _, port = value.rpartition(":") if value.count(":") == 1 else (value, "", "")
    if not host:
        host, port = value, ""
    try:
        return host, int(port) if port else default_port
    except ValueError:
        return None


def _cfg(key: str, default_port: int, port_key: Optional[str] = None):
    def resolve(config: dict, resource: dict):
        got = _host_port(str(config.get(key) or ""), default_port)
        if got and port_key and config.get(port_key):
            try:
                return got[0], int(config[port_key])
            except (TypeError, ValueError):
                return got
        return got
    return resolve


def _first_bootstrap(config: dict, resource: dict):
    first = str(config.get("bootstrap") or "").split(",")[0]
    return _host_port(first, 9092)


def _discovered(config: dict, resource: dict):
    labels = resource.get("labels") or {}
    try:
        return str(labels["host"]), int(labels["port"])
    except (KeyError, TypeError, ValueError):
        return None


def _nats_client(config: dict, resource: dict):
    """The connector is given the MONITORING url; the client port is what varz reported."""
    mon = _host_port(str(config.get("monitoring_url") or ""), 8222)
    if not mon:
        return None
    raw = resource.get("raw") or {}
    try:
        port = int(raw.get("port") or raw.get("client_port") or 4222)
    except (TypeError, ValueError):
        port = 4222
    return mon[0], port


def _sweep_probe(host: str, port: int, timeout: float):
    """For a discovered service: whichever probe identifies that port, exactly as the sweep did."""
    from .discover.sweep import probes_for
    for probe in probes_for(port, True):
        try:
            got = probe(host, port, timeout)
        except Exception:                       # noqa: BLE001 - a probe must never raise out
            continue
        if got is not None:
            return got
    return None


def _no_auth(r) -> bool:
    return r.signals.get("auth_required") is False


PROVERS: dict[str, Prover] = {
    "REDIS.AUTH.NO_PASSWORD": Prover(
        P.probe_redis, _no_auth, _cfg("host", 6379, "port"),
        "Open a connection and send PING and INFO server without AUTH. No keys are read."),
    "MEMCACHED.AUTH.NO_SASL": Prover(
        P.probe_memcached, _no_auth, _cfg("host", 11211, "port"),
        "Open a connection and send `version` without SASL. No keys are read."),
    "NATS.AUTH.NOT_REQUIRED": Prover(
        P.probe_nats, _no_auth, _nats_client,
        "Open a connection to the client port and read the INFO line the server sends first. "
        "Nothing is subscribed or published."),
    "ELASTICSEARCH.SECURITY.ANONYMOUS_ACCESS": Prover(
        H.probe_elasticsearch, _no_auth, _cfg("base_url", 9200),
        "Send GET / with no Authorization header. No index or document is read."),
    "KONG.ADMIN.UNAUTHENTICATED": Prover(
        H.probe_kong_admin, lambda r: r.signals.get("admin_api_open") is True,
        _cfg("url", 8001),
        "Send GET / to the Admin API with no token. Nothing is created or changed."),
    "KAFKA.LISTENER.PLAINTEXT": Prover(
        P.probe_kafka, lambda r: r.transport == "plaintext", _first_bootstrap,
        "Open an unencrypted connection to the first bootstrap broker and send ApiVersions, the "
        "request every client sends before it authenticates. No topic is read."),
    "COORD.ETCD.AUTH_DISABLED": Prover(
        H.probe_etcd, _no_auth, _cfg("host", 2379, "port"),
        "Send GET /version with no credentials. No key is read."),
    "COORD.ETCD.UNAUTHENTICATED_READ": Prover(
        H.probe_etcd, _no_auth, _cfg("host", 2379, "port"),
        "Send GET /version with no credentials. No key is read."),
    "DISCOVERY.ACCESS.UNAUTHENTICATED": Prover(
        _sweep_probe, _no_auth, _discovered,
        "Repeat the pre-authentication handshake the discovery sweep made on this port."),
    "DISCOVERY.ADMIN_API.EXPOSED": Prover(
        _sweep_probe,
        lambda r: r.signals.get("admin_api_open") is True or r.signals.get("auth_required") is False,
        _discovered,
        "Repeat the unauthenticated GET the discovery sweep made against this admin API."),
}


def supported(rule_id: str) -> bool:
    return rule_id in PROVERS


def describe(rule_id: str) -> Optional[str]:
    p = PROVERS.get(rule_id)
    return f"{p.action} {NOT_DONE}" if p else None


def resolve_target(rule_id: str, config: dict, resource: dict) -> Optional[tuple]:
    p = PROVERS.get(rule_id)
    if not p:
        return None
    try:
        return p.target(config or {}, resource or {})
    except Exception:                           # noqa: BLE001 - a bad config is "no target"
        return None


def _safe_lines(items) -> list:
    """Probe evidence is already bounded facts; cap count and length and run the shared
    secret scrubber over it anyway — this text is tenant-readable."""
    from .redact import _SECRET_PATTERNS
    out = []
    for item in list(items or [])[:MAX_TRANSCRIPT]:
        text = str(item)
        for pattern, replacement in _SECRET_PATTERNS:
            text = pattern.sub(replacement, text)
        out.append(text[:400])
    return out


def _safe_signals(signals: dict) -> dict:
    return {k: v for k, v in (signals or {}).items()
            if isinstance(v, (bool, int, float, str)) or v is None}


def run_proof(rule_id: str, config: dict, resource: dict, *, mode: str = "cloud",
              timeout: float = TIMEOUT_S) -> ProofResult:
    """One attempt. Never raises; never sends a credential (it is given none — `config` here
    is the connection's NON-secret config, the Vault is not consulted)."""
    prover = PROVERS.get(rule_id)
    if prover is None:
        return ProofResult("unsupported", "No action was taken.",
                           reason="This rule has no safe, read-only proof. It describes a setting "
                                  "that cannot be demonstrated without sending a credential or "
                                  "changing something.")
    action = f"{prover.action} {NOT_DONE}"
    if mode == "collector":
        return ProofResult("unreachable", action,
                           reason="This connection is scanned by a collector inside your network. "
                                  "The engine cannot reach it from outside, which says nothing "
                                  "about whether the finding is exploitable from inside.")
    target = resolve_target(rule_id, config, resource)
    if not target:
        return ProofResult("unreachable", action,
                           reason="The connection does not record an address for this resource, "
                                  "so there is nothing to contact.")
    host, port = target
    label = f"{host}:{port}"
    t0 = time.time()
    try:
        result = prover.probe(host, port, timeout)
    except Exception as e:                      # noqa: BLE001 - never raise out of a proof
        return ProofResult("unreachable", action, label,
                           reason=f"The probe failed before reading a reply ({type(e).__name__}).",
                           duration_ms=int((time.time() - t0) * 1000))
    ms = int((time.time() - t0) * 1000)
    if result is None:
        return ProofResult("unreachable", action, label, duration_ms=ms,
                           reason="Nothing answered as this product at that address from where "
                                  "the engine runs. The host may be private, down or filtered.")
    transcript = _safe_lines(result.evidence)
    signals = _safe_signals(result.signals)
    try:
        opened = bool(prover.opened(result))
    except Exception:                           # noqa: BLE001
        opened = False
    return ProofResult("proven" if opened else "not_reproduced", action, label,
                       transcript, signals, None, ms)


# ── persistence (called from the API) ─────────────────────────────────────

def _load(cur, tenant_id: str, finding_id: str):
    cur.execute(
        """select f.rule_id, f.status, r.id, r.kind, r.name, r.labels, r.raw,
                  c.id, c.type, c.config, c.mode
             from findings f
             left join resources r on r.id = f.resource_id
             left join connections c on c.id = r.connection_id
            where f.tenant_id = %s and f.id = %s""",
        (tenant_id, finding_id),
    )
    return cur.fetchone()


def prove_finding(cur, tenant_id: str, finding_id: str, actor: Optional[str] = None,
                  *, runner: Callable = run_proof) -> Optional[dict]:
    """Run the proof for one finding and store the attempt. None if there is no such finding.

    A `proven` result also files an observation in the evidence ledger, so the proof is cited
    beside the configuration evidence the finding already carries.
    """
    row = _load(cur, tenant_id, finding_id)
    if not row:
        return None
    rule_id, _status, rid, _kind, _name, labels, raw, cid, _ctype, config, mode = row
    if cid is None:
        result = ProofResult("unreachable", describe(rule_id) or "No action was taken.",
                             reason="The finding's resource or connection no longer exists.")
        if not supported(rule_id):
            result = run_proof(rule_id, {}, {})
    else:
        result = runner(rule_id, config or {}, {"labels": labels or {}, "raw": raw or {}},
                        mode=mode or "cloud")
    cur.execute(
        """insert into finding_proofs
             (tenant_id, finding_id, rule_id, verdict, action, target, transcript, signals,
              reason, duration_ms, requested_by)
           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           returning id, created_at""",
        (tenant_id, finding_id, rule_id, result.verdict, result.action, result.target,
         json.dumps(result.transcript), json.dumps(result.signals), result.reason,
         result.duration_ms, actor),
    )
    pid, created_at = cur.fetchone()
    if result.verdict == "proven":
        first = result.transcript[0] if result.transcript else "the unauthenticated request succeeded"
        cur.execute(
            """insert into observations (tenant_id, finding_id, resource_id, claim, source_ref)
               values (%s,%s,%s,%s,%s)""",
            (tenant_id, finding_id, rid,
             f"Proven reachable without credentials at {result.target}: {first}",
             json.dumps({"kind": "proof", "proof_id": str(pid), "rule_id": rule_id,
                         "target": result.target})),
        )
    return {"id": str(pid), "finding_id": finding_id, "rule_id": rule_id,
            "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
            **result.as_dict()}


def list_proofs(cur, tenant_id: str, finding_id: str, limit: int = 10) -> list[dict]:
    cur.execute(
        """select id::text, verdict, action, target, transcript, signals, reason, duration_ms,
                  requested_by, created_at
             from finding_proofs where tenant_id = %s and finding_id = %s
            order by created_at desc limit %s""",
        (tenant_id, finding_id, limit),
    )
    return [{"id": r[0], "verdict": r[1], "action": r[2], "target": r[3],
             "transcript": r[4] or [], "signals": r[5] or {}, "reason": r[6],
             "duration_ms": r[7], "requested_by": r[8],
             "created_at": r[9].isoformat() if hasattr(r[9], "isoformat") else str(r[9])}
            for r in cur.fetchall() or []]
