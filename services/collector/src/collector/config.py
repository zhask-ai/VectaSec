"""Collector configuration — and the credential boundary.

Two kinds of secret pass through this process, and keeping them apart is the entire trust story
of the product:

  • The enrollment token and control-plane URL are OURS. They are meant to go outbound.
  • The target credentials — Kafka SASL password, Kong admin token, RabbitMQ password — are the
    CUSTOMER'S. They are read here, held in memory, handed to a connector that dials a private
    system, and are never serialised into anything the outbound client sends.

The split is structural rather than a habit: `Target.config` (credentials included) is only ever
passed to `CONNECTORS[type]`, and `Target.public_config()` is the only view of it that main.py
may put in a payload. redact.py is the backstop for when that discipline slips.

This module deliberately does not import the engine, so the credential boundary can be read and
tested without a broker, a database, or a control plane in the picture.
"""
import json
import os
import pathlib
import re
from dataclasses import dataclass

from .redact import is_cred_key, redact

DEFAULT_TARGETS_FILE = "/etc/vectasec/targets.json"
DEFAULT_STATE_DIR = "/var/lib/vectasec"
STATE_FILE = "state.json"

# ${VAR} inside the targets file. Exists so the file itself holds no secrets: it can live in git
# or a ConfigMap while the credential arrives at runtime from a Secret-backed env var or file.
_INTERP_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# The password half of a URL's userinfo (amqp://user:pw@host). Credentials hide here under
# innocent key names like "url", where a key-shape check cannot see them.
_URL_PW_RE = re.compile(r"://[^/\s:@]+:([^/\s@]+)@")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _num(name: str, default: float) -> float:
    raw = _env(name)
    try:
        return float(raw) if raw else default
    except ValueError:
        raise SystemExit(f"{name}={raw!r} is not a number")


_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


def _flag(name: str, default: bool = False) -> bool:
    """Strict, because one of these flags is a security control.

    Fail-closed is not enough here: `VECTASEC_VERIFY_TLS` defaults to True, so a flag that
    treated anything it did not recognise as False would let `VERIFY_TLS=enabled` — a plausible
    typo, not sabotage — silently turn off certificate verification on the connection that
    carries the tenant service token. An unparseable value is an operator mistake, and the only
    safe reading of a mistake is to stop, exactly as `_num` does.
    """
    raw = _env(name).lower()
    if not raw:
        return default
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise SystemExit(f"{name}={raw!r} is not a boolean "
                     f"(use one of: {', '.join(_TRUE + _FALSE)})")


def _secret(name: str) -> str:
    """Read a secret from ``<NAME>_FILE`` first, then ``<NAME>``.

    The file form is the documented one: an env var is readable from /proc/<pid>/environ, from
    `docker inspect`, from `kubectl describe pod`, and from most crash reporters — a mounted
    Secret is not. The env var stays for `docker run` ergonomics and is called out as the weaker
    option in the README rather than quietly treated as equivalent.
    """
    path = _env(f"{name}_FILE")
    if path:
        try:
            return pathlib.Path(path).read_text().strip()
        except OSError as e:
            raise SystemExit(f"{name}_FILE={path!r} is unreadable: {e}")
    return _env(name)


def _interpolate(node):
    if isinstance(node, dict):
        return {k: _interpolate(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_interpolate(v) for v in node]
    if not isinstance(node, str):
        return node

    def sub(m):
        val = os.environ.get(m.group(1))
        if val is None:
            # Failing at boot beats a connector authenticating with the literal string
            # "${KAFKA_PASSWORD}" and an operator debugging a bewildering auth error.
            raise SystemExit(f"targets file references ${{{m.group(1)}}} but that variable is not set")
        return val

    return _INTERP_RE.sub(sub, node)


def _secret_values(node) -> set:
    """Every literal credential string reachable in a config tree.

    Two sources, because a credential arrives in two shapes: under a credential-shaped key, and
    buried in the userinfo of a URL under a key named "url".
    """
    out: set = set()
    if isinstance(node, dict):
        for k, v in node.items():
            if is_cred_key(k) and isinstance(v, str) and v:
                out.add(v)
            out |= _secret_values(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            out |= _secret_values(v)
    elif isinstance(node, str):
        out |= set(_URL_PW_RE.findall(node))
    return out


@dataclass(frozen=True)
class Target:
    """One customer system this collector is permitted to scan.

    `config` is connector input and nothing else: it is the dict `CONNECTORS[type]` receives, it
    holds the credential, and it must never be handed to anything that serialises.
    """
    name: str
    type: str
    config: dict

    def secret_values(self) -> set:
        return _secret_values(self.config)

    def public_config(self) -> dict:
        """The only view of this config allowed outbound.

        Sent so the console can show what a connection points at — host, port, TLS flags — without
        the control plane holding what opens it.
        """
        return redact(self.config, self.secret_values())


@dataclass(frozen=True)
class Config:
    control_plane_url: str
    enroll_token: str
    collector_name: str
    targets: tuple
    state_dir: pathlib.Path
    verify_tls: object            # True | False | path to a CA bundle (egress proxies MITM TLS)
    timeout_s: float
    heartbeat_interval_s: float
    poll_wait_s: float
    poll_interval_s: float
    max_backoff_s: float
    log_level: str

    @property
    def targets_by_name(self) -> dict:
        return {t.name: t for t in self.targets}

    def secret_values(self) -> set:
        """Every literal secret this process holds — the input to redact()'s value scrub.

        The enrollment token is in here even though enroll() sends it on purpose: exactly one
        function is supposed to transmit it, and its turning up anywhere else — a heartbeat, a
        finding, a log line — is a bug that this set converts into a redaction instead of a leak.
        """
        out = {self.enroll_token} if self.enroll_token else set()
        for t in self.targets:
            out |= t.secret_values()
        return out


def _load_targets(path: pathlib.Path) -> tuple:
    try:
        doc = json.loads(path.read_text())
    except OSError as e:
        raise SystemExit(f"targets file {str(path)!r} is unreadable: {e} "
                         f"(set VECTASEC_TARGETS_FILE)")
    except json.JSONDecodeError as e:
        raise SystemExit(f"targets file {str(path)!r} is not valid JSON: {e}")

    items = doc.get("targets") if isinstance(doc, dict) else doc
    if not isinstance(items, list) or not items:
        raise SystemExit(f"targets file {str(path)!r} declares no targets")

    targets: list = []
    seen: set = set()
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise SystemExit(f"targets[{i}] is not an object")
        name = str(item.get("name") or "").strip()
        type_ = str(item.get("type") or "").strip()
        cfg = item.get("config")
        if not name or not type_:
            raise SystemExit(f"targets[{i}] needs both 'name' and 'type'")
        if not isinstance(cfg, dict):
            raise SystemExit(f"target {name!r} needs a 'config' object")
        if name in seen:
            # Jobs address a target by name; two targets sharing one would make dispatch
            # ambiguous, and the wrong resolution means scanning the wrong system.
            raise SystemExit(f"duplicate target name {name!r}")
        seen.add(name)
        targets.append(Target(name=name, type=type_, config=_interpolate(cfg)))
    return tuple(targets)


def load_config() -> Config:
    url = _env("VECTASEC_CONTROL_PLANE_URL").rstrip("/")
    if not url:
        raise SystemExit("VECTASEC_CONTROL_PLANE_URL is required (e.g. https://app.vectasec.com)")
    if not url.startswith("https://") and not _flag("VECTASEC_ALLOW_INSECURE_CONTROL_PLANE"):
        # Plaintext would put the tenant service token on the wire on every request. The escape
        # hatch exists for a local control plane during development and is named so it cannot be
        # set by accident.
        raise SystemExit(f"VECTASEC_CONTROL_PLANE_URL={url!r} is not https "
                         f"(set VECTASEC_ALLOW_INSECURE_CONTROL_PLANE=1 only for local dev)")

    token = _secret("VECTASEC_ENROLL_TOKEN")
    if not token:
        raise SystemExit("VECTASEC_ENROLL_TOKEN_FILE (preferred) or VECTASEC_ENROLL_TOKEN "
                         "is required — mint one in the console under Collectors")

    ca = _env("VECTASEC_CA_BUNDLE")
    if ca and not pathlib.Path(ca).exists():
        raise SystemExit(f"VECTASEC_CA_BUNDLE={ca!r} does not exist")
    verify: object = ca or _flag("VECTASEC_VERIFY_TLS", True)

    return Config(
        control_plane_url=url,
        enroll_token=token,
        collector_name=_env("VECTASEC_COLLECTOR_NAME") or os.uname().nodename,
        targets=_load_targets(pathlib.Path(_env("VECTASEC_TARGETS_FILE") or DEFAULT_TARGETS_FILE)),
        state_dir=pathlib.Path(_env("VECTASEC_STATE_DIR") or DEFAULT_STATE_DIR),
        verify_tls=verify,
        timeout_s=_num("VECTASEC_TIMEOUT_S", 30),
        heartbeat_interval_s=_num("VECTASEC_HEARTBEAT_INTERVAL_S", 60),
        poll_wait_s=_num("VECTASEC_POLL_WAIT_S", 25),
        poll_interval_s=_num("VECTASEC_POLL_INTERVAL_S", 5),
        max_backoff_s=_num("VECTASEC_MAX_BACKOFF_S", 300),
        log_level=(_env("VECTASEC_LOG_LEVEL") or "INFO").upper(),
    )


def write_state(cfg: Config, state: dict) -> None:
    """Persist enrollment state 0600, for an operator to read. Nothing in this process reads it.

    What lands here is deliberately useless to whoever steals the volume: a collector id and the
    sha256 of the enrollment token. The token itself and the short-lived tenant token are never
    written — a secret that never touches a disk cannot be lifted out of a snapshot or a backup.

    Write-only is a real limitation, stated rather than dressed up: the file is a record of the
    last enrollment, not state the collector resumes from. Every restart re-enrolls from scratch
    and takes a fresh server-assigned collector id, so nothing here is load-bearing and a torn or
    missing file costs nothing. The write is still atomic so that an operator (or a support
    bundle) never reads a half-written file.
    """
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    p = cfg.state_dir / STATE_FILE
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.chmod(0o600)
    tmp.replace(p)
