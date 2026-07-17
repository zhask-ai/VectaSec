"""The collector loop: enroll → heartbeat → poll → run the job locally → push findings out.

This process runs inside the customer's network, next to their broker/gateway, and is VectaSec's
primary data path. Three properties define it, and every choice in this file serves one of them:

  1. OUTBOUND ONLY. There is no bind(), no listen(), no web framework and no port. Jobs are
     pulled; the control plane is talked to and never talks in. A collector therefore runs behind
     NAT with every ingress rule denied.
  2. CREDENTIALS STAY LOCAL. The customer's Kafka/Kong/RabbitMQ credential is read from local
     config, used in this process to dial the private system, and is never serialised into an
     outbound request. The control plane does not have it and has no way to ask for it.
  3. RAW CONFIG STAYS LOCAL. Connectors AND detectors both run here. What leaves is the
     conclusion — normalized findings, their observations, resource metadata — never the broker
     config, plugin config or topic settings those were derived from.

Connectors and detectors are imported from the engine package unmodified: the same code that
runs in the cloud path runs here. One codebase, two topologies.
"""
import argparse
import hashlib
import json
import logging
import random
import signal
import sys
import threading
import time

import httpx

from vectasec.contracts import Collected, ScanContext
from vectasec.registry import CONNECTORS, DETECTORS
# Imported rather than reimplemented so the same real-world issue stays ONE finding whether it was
# seen by the cloud engine or by a collector: a tenant that migrates an MSK cluster from the
# agentless path to a collector must not have its triage history reset. (Importing vectasec.scan
# does not pull in psycopg — the DB import lives inside run_scan.)
from vectasec.scan import fingerprint
from vectasec import connect as _connect   # noqa: F401  — import triggers connector auto-registration
from vectasec import detect as _detect     # noqa: F401  — import triggers detector auto-registration

from .config import Config, load_config, write_state
from .redact import redact

VERSION = "0.0.1"

# `preview` never talks to the control plane, so it has no enrolled tenant. Fingerprints it prints
# are shaped like the real thing but belong to no tenant, which is the point: preview output is
# for reading, not for loading.
PREVIEW_TENANT = "00000000-0000-0000-0000-000000000000"

log = logging.getLogger("collector")


class _SecretFilter(logging.Filter):
    """Scrub known credentials out of log records.

    Logs stay inside the customer's network — but their log shipper usually does not, and a
    connector's exception text can carry a URL with userinfo in it. Cheap belt to redact()'s
    braces.

    The scrub runs against the FORMATTED message, not against `record.msg` and the string
    members of `record.args`. Formatting first is what makes the control sound: a `%s` arg is
    very often not a str — `log.warning("...: %s", e)` passes the exception OBJECT, which
    logging stringifies at format time, i.e. after any filter has run. Scrubbing the parts and
    letting logging assemble them afterwards would leave exactly the input class this filter
    exists for — a credential-bearing exception — untouched. Same reason `exc_info` is resolved
    to text and scrubbed here: a traceback carries argument values.
    """

    def __init__(self, secrets):
        super().__init__()
        self._secrets = secrets

    def filter(self, record) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            # A broken format string must not become an unredacted record, or a way to bypass
            # this filter. Fall back to the raw parts and scrub those.
            msg = f"{record.msg!s} {record.args!s}"
        record.msg = redact(msg, self._secrets)
        # Already interpolated above; leaving args set would make logging apply `%` a second
        # time to the redacted text.
        record.args = ()

        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text, self._secrets)
            record.exc_info = None    # exc_text is what the formatter emits now; it is scrubbed
        if record.stack_info:
            record.stack_info = redact(record.stack_info, self._secrets)
        return True


class ControlPlane:
    """The outbound-only client. Every method here is a request WE initiate; nothing listens."""

    def __init__(self, cfg: Config):
        self._cfg = cfg
        # The read timeout must outlast a long-poll, or every idle poll() would look like a
        # network failure and drive the backoff.
        timeout = httpx.Timeout(cfg.timeout_s, read=max(cfg.timeout_s, cfg.poll_wait_s + 10))
        self._http = httpx.Client(
            base_url=cfg.control_plane_url,
            timeout=timeout,
            verify=cfg.verify_tls,
            headers={"user-agent": f"vectasec-collector/{VERSION}"},
        )
        self._token = ""          # tenant-scoped, short-lived, MEMORY ONLY — never written to disk
        self._token_expires = 0.0
        self.collector_id = ""
        self.tenant_id = ""

    def close(self) -> None:
        self._http.close()

    def _auth(self) -> dict:
        return {"authorization": f"Bearer {self._token}"}

    def _set_token(self, token: str, expires_in) -> None:
        if not token:
            raise SystemExit("enroll response omitted the service token")
        self._token = token
        # Renew a minute early: a token that expires mid-scan throws away work already spent
        # against the customer's production broker.
        self._token_expires = time.time() + max(float(expires_in or 3600) - 60, 30)

    def enroll(self) -> None:
        """Trade the long-lived enrollment token for a short-lived tenant-scoped one.

        The enrollment token is the only long-lived secret the collector holds, and it is not kept
        at rest: the state file gets sha256(token), which is useless to anyone who reads the
        volume. The service token that comes back lives in memory for the same reason.

        The hash is recorded for an operator to inspect, and nothing more — this process never
        reads the state file back, so a rotated enrollment token is not *detected* here. It does
        not need to be: a rotated token fails the POST below with a 401/403 and exits with a
        message naming the variable to fix. Every restart enrolls afresh and takes a new
        server-assigned collector id.
        """
        r = self._http.post("/collector/enroll", json={
            "enrollment_token": self._cfg.enroll_token,
            "name": self._cfg.collector_name,
            "version": VERSION,
        })
        if r.status_code in (401, 403):
            raise SystemExit("control plane rejected the enrollment token (401/403) — check "
                             "VECTASEC_ENROLL_TOKEN_FILE, or mint a new token in the console")
        r.raise_for_status()
        body = r.json() or {}

        self.collector_id = str(body.get("collector_id") or "")
        self.tenant_id = str(body.get("tenant_id") or "")
        if not self.tenant_id:
            # Findings are fingerprinted on the tenant. Without it this collector's findings would
            # not dedupe against the ones the console already holds, so refuse rather than write
            # a parallel history.
            raise SystemExit("enroll response omitted tenant_id — refusing to scan")
        self._set_token(str(body.get("token") or ""), body.get("expires_in"))

        write_state(self._cfg, {
            "collector_id": self.collector_id,
            "enroll_token_sha256": hashlib.sha256(self._cfg.enroll_token.encode()).hexdigest(),
            "enrolled_at": int(time.time()),
            "version": VERSION,
        })
        log.info("enrolled as collector %s (service token valid ~%ds)",
                 self.collector_id, int(self._token_expires - time.time()))

    def ensure_enrolled(self) -> None:
        if not self._token or time.time() >= self._token_expires:
            self.enroll()

    def heartbeat(self, status: str = "active") -> None:
        """Periodic liveness POST — drives collectors.last_heartbeat / collectors.status.

        Carries target names and types, and nothing else. The console has to show an operator what
        this collector is pointed at, but a hostname is an inventory of the customer's private
        network, so it stays here.
        """
        self._post("/collector/heartbeat", {
            "collector_id": self.collector_id,
            "version": VERSION,
            "status": status,
            "targets": [{"name": t.name, "type": t.type} for t in self._cfg.targets],
        })

    def poll(self) -> list:
        """Pull queued scan jobs. This is the whole reason no inbound port is needed.

        The request is ours; the control plane parks it until a job exists or `wait` seconds pass,
        then answers on the connection we opened. Dispatch therefore rides an outbound flow the
        customer's egress policy already allows, and the collector is never reachable.
        """
        r = self._http.get("/collector/jobs", headers=self._auth(),
                           params={"collector_id": self.collector_id,
                                   "wait": int(self._cfg.poll_wait_s)})
        if r.status_code == 204:
            return []   # long-poll expired against an empty queue — not an error
        if r.status_code in (401, 403):
            self.enroll()
            return []
        r.raise_for_status()
        jobs = (r.json() or {}).get("jobs") or []
        return [j for j in jobs if isinstance(j, dict)]

    def push_results(self, payload: dict) -> None:
        """Push one job's results outbound. `payload` MUST already have been through redact()."""
        self._post("/collector/results", payload)

    def _post(self, path: str, body: dict):
        r = self._http.post(path, headers=self._auth(), json=body)
        if r.status_code in (401, 403):
            # The token expired earlier than advertised, or the control plane rotated its signing
            # key. Re-enroll once; a second failure is a real error and belongs in the backoff.
            self.enroll()
            r = self._http.post(path, headers=self._auth(), json=body)
        r.raise_for_status()
        return r


def _run_detectors(ctx: ScanContext) -> tuple:
    """Run every registered detector locally. Mirrors the engine's scan loop, minus persistence.

    Detector isolation is copied deliberately: one detector that raises must not void a scan the
    customer's broker has already paid for.
    """
    findings: list = []
    errors: list = []
    for d in DETECTORS:
        for r in ctx.resources:
            if r.kind not in d.kinds:
                continue
            try:
                hits = d.fn(r, ctx) or []
            except Exception as e:
                errors.append(f"{d.rule_id} on {r.ext_id}: {type(e).__name__}: {e}")
                continue
            for h in hits:
                findings.append({
                    "rule_id": d.rule_id,
                    "fingerprint": fingerprint(ctx.tenant_id, ctx.connection_id,
                                               d.rule_id, r.ext_id),
                    "resource_ext_id": r.ext_id,
                    "title": d.title,
                    "severity": h.severity or d.severity,
                    "remediation": h.remediation,
                    "detail": h.detail,
                    "observation": h.observation,
                    "source_ref": {**h.source_ref, "rule_id": d.rule_id, "resource": r.ext_id},
                    # The third outcome travels with the finding, so a rule that could not read its
                    # evidence stays "not assessable" when the engine persists it, rather than
                    # silently becoming a plain low. Defaults keep older engines forward-compatible.
                    "assessable": getattr(h, "assessable", True),
                    "assessment_reason": getattr(h, "assessment_reason", ""),
                })
    return findings, errors


def run_job(job: dict, cfg: Config, tenant_id: str) -> dict:
    """Collect and detect locally; return the payload to push.

    A job is a REFERENCE to a locally configured target — {"target": "prod-kafka"} — never a
    connection config. That asymmetry is load-bearing: if the control plane could hand this
    process a host and a credential, then whoever took the control plane could aim the collector
    at any address inside the customer's network, or at a broker of their own, and the collector
    would dial it holding the customer's credentials. Config-shaped fields on an incoming job are
    ignored by construction — we never read one.
    """
    job_id = str(job.get("job_id") or "")
    connection_id = str(job.get("connection_id") or "")
    name = str(job.get("target") or "")
    t0 = time.time()

    base = {"job_id": job_id, "connection_id": connection_id, "target": name,
            "collector_version": VERSION}

    target = cfg.targets_by_name.get(name)
    if target is None:
        return {**base, "status": "error",
                "error": f"no target named {name!r} is configured on this collector"}
    if target.type not in CONNECTORS:
        return {**base, "status": "error",
                "error": f"no connector registered for type {target.type!r}"}
    base["type"] = target.type
    base["config"] = target.public_config()

    try:
        # The one place the customer's credential is used: it goes into a connector that dials a
        # host inside this network, over a socket that never leaves it.
        collected: Collected = CONNECTORS[target.type](target.config)
    except Exception as e:
        return {**base, "status": "error", "error": f"{type(e).__name__}: {e}"}

    # ScanContext carries the FULL config, credentials included, because detectors read posture
    # knobs out of it (`public_allowlist`, `source_is_loopback`, `active_probes`). That is safe:
    # detectors run here. The boundary is redact() at the payload edge, not the context.
    ctx = ScanContext(connection_id=connection_id, tenant_id=tenant_id,
                      resources=collected.resources, config=target.config)
    findings, errors = _run_detectors(ctx)

    # Resource.raw is deliberately not built into this payload. It is the broker's config, the
    # gateway's plugin config, the topic settings — the material the rules ran against — and
    # omitting it is the difference between "we send findings" and "we send your configuration".
    # The cloud path persists raw because it already holds the credential and has nothing left to
    # protect; the collector path gives it no route out.
    resources = [{"kind": r.kind, "name": r.name, "ext_id": r.ext_id,
                  "namespace": r.namespace, "labels": r.labels} for r in collected.resources]
    edges = [{"src_ext_id": e.src_ext_id, "dst_ext_id": e.dst_ext_id,
              "kind": e.kind, "labels": e.labels} for e in collected.edges]

    stats = {
        "resources": len(resources),
        "edges": len(edges),
        "findings": len(findings),
        "detectors_run": len(DETECTORS),
        "duration_ms": int((time.time() - t0) * 1000),
    }
    if errors:
        stats["detector_errors"] = errors

    return {**base, "status": "done", "stats": stats,
            "resources": resources, "edges": edges, "findings": findings}


def _handle(cp: ControlPlane, cfg: Config, job: dict) -> None:
    log.info("job %s: running target %r", job.get("job_id"), job.get("target"))
    payload = run_job(job, cfg, cp.tenant_id)
    # Our own enrolled id, never one echoed back from the job: what the collector reports about
    # itself has to come from the enrollment it did, not from the message it was handed.
    payload["collector_id"] = cp.collector_id

    # THE BOUNDARY. Nothing reaches the control plane except through this line. run_job() is
    # already assembled out of credential-free parts; redact() is what makes that a guarantee
    # rather than a promise — for this payload, and for every connector added after this file.
    payload = redact(payload, cfg.secret_values())
    cp.push_results(payload)

    stats = payload.get("stats") or {}
    if payload.get("status") == "error":
        log.warning("job %s: %s", job.get("job_id"), payload.get("error"))
    else:
        log.info("job %s: pushed %s findings over %s resources in %sms",
                 job.get("job_id"), stats.get("findings"), stats.get("resources"),
                 stats.get("duration_ms"))


def _validate_targets(cfg: Config) -> None:
    """Fail at boot rather than at the first job, when someone is watching the install."""
    unknown = sorted({t.type for t in cfg.targets} - set(CONNECTORS))
    if unknown:
        raise SystemExit(f"targets reference unknown connector types {unknown} "
                         f"(registered: {sorted(CONNECTORS)})")


def _stop_event() -> threading.Event:
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    return stop


def run_forever(cfg: Config) -> int:
    cp = ControlPlane(cfg)
    stop = _stop_event()
    backoff = 1.0
    next_heartbeat = 0.0
    try:
        while not stop.is_set():
            try:
                cp.ensure_enrolled()
                now = time.time()
                if now >= next_heartbeat:
                    cp.heartbeat()
                    next_heartbeat = now + cfg.heartbeat_interval_s

                jobs = cp.poll()
                for job in jobs:
                    if stop.is_set():
                        break
                    _handle(cp, cfg, job)

                backoff = 1.0
                if not jobs:
                    stop.wait(cfg.poll_interval_s)
            except SystemExit:
                raise
            except Exception as e:
                # A control plane that is down, rate-limiting, or mid-deploy must not turn a fleet
                # of collectors into a retry storm — jittered exponential backoff, not a tight loop.
                log.warning("cycle failed: %s: %s (retry in ~%.0fs)", type(e).__name__, e, backoff)
                stop.wait(backoff * (0.5 + random.random()))
                backoff = min(backoff * 2, cfg.max_backoff_s)
    finally:
        cp.close()
    log.info("shutdown complete")
    return 0


def preview(cfg: Config) -> int:
    """Offline dry run: scan every configured target and print exactly what WOULD be pushed.

    Enrolls nothing and sends nothing. This exists for the security review: rather than take our
    word for what leaves the network, an operator runs this against their real broker with their
    real credentials, reads the JSON, and decides for themselves.
    """
    for t in cfg.targets:
        payload = run_job({"job_id": "preview", "connection_id": "preview", "target": t.name},
                          cfg, tenant_id=PREVIEW_TENANT)
        payload = redact(payload, cfg.secret_values())
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0


def check(cfg: Config) -> int:
    """Validate config and connector wiring without touching either the targets or the network."""
    print(f"control plane : {cfg.control_plane_url}")
    print(f"collector name: {cfg.collector_name}")
    print(f"state dir     : {cfg.state_dir}")
    print(f"tls verify    : {cfg.verify_tls}")
    print(f"enroll token  : loaded, sha256="
          f"{hashlib.sha256(cfg.enroll_token.encode()).hexdigest()[:16]}…")
    print(f"detectors     : {len(DETECTORS)} registered")
    for t in cfg.targets:
        print(f"target        : {t.name} ({t.type}) -> {json.dumps(t.public_config(), sort_keys=True)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="vectasec-collector",
        description="VectaSec collector — runs inside your network, keeps your credentials there.")
    ap.add_argument("command", nargs="?", default="run", choices=("run", "preview", "check"),
                    help="run: the enroll/poll/scan loop. preview: scan locally and print what "
                         "would be sent, sending nothing. check: validate config only.")
    args = ap.parse_args()

    cfg = load_config()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    # The filter goes on the HANDLER, not the logger: a filter attached to a logger is not
    # consulted for records that propagate up from `vectasec.*`, which is exactly where a
    # connector's credential-bearing exception text would come from.
    handler.addFilter(_SecretFilter(cfg.secret_values()))
    logging.basicConfig(level=cfg.log_level, handlers=[handler], force=True)

    _validate_targets(cfg)

    if args.command == "check":
        return check(cfg)
    if args.command == "preview":
        return preview(cfg)

    log.info("vectasec-collector %s starting: %d target(s), outbound-only to %s",
             VERSION, len(cfg.targets), cfg.control_plane_url)
    return run_forever(cfg)


if __name__ == "__main__":
    raise SystemExit(main())
