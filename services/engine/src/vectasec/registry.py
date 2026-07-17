"""Auto-registration: a connector or detector is added by dropping a file that
uses these decorators — no central list to edit."""
from dataclasses import dataclass
from typing import Callable


# ── Connectors: type -> collect(config) -> Collected ──────────────────────
CONNECTORS: dict[str, Callable] = {}

# type -> the config fields a human fills in to connect one. Declared by the connector
# itself (same add-a-file principle as the collect fn), consumed by the console's
# add-connection form (GET /connectors), the CLI (`vectasec connections add`), and
# validate_config below. A connector with no declared fields is still scannable — the
# spec exists for the humans, the collect fn stays the authority on what config means.
CONNECTOR_FIELDS: dict[str, list["ConnectorField"]] = {}


@dataclass(frozen=True)
class ConnectorField:
    """One entry in a connect form. `secret` marks credentials: the console renders a
    password input and never echoes the value back; storage is still connections.config
    (jsonb) either way — see docs/research/supabase-hardening.md on moving that to Vault."""
    key: str
    label: str
    required: bool = False
    secret: bool = False
    placeholder: str = ""
    help: str = ""

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "required": self.required,
                "secret": self.secret, "placeholder": self.placeholder, "help": self.help}


def connector(type_: str, fields: list[ConnectorField] | None = None):
    def wrap(fn: Callable) -> Callable:
        CONNECTORS[type_] = fn
        CONNECTOR_FIELDS[type_] = list(fields or [])
        return fn
    return wrap


def validate_config(type_: str, config: dict) -> list[str]:
    """Human-readable problems with a config, per the connector's declared fields.

    Empty list = acceptable. Only *declared required* keys are checked — extra keys pass
    through untouched (the collect fn reads what it reads; `timeout`, `verify_tls` and
    friends are legitimate without being on the form). An unknown type is an error here
    rather than a KeyError later inside a queued job no one is watching.
    """
    if type_ not in CONNECTORS:
        return [f"no connector for type {type_!r} (have: {', '.join(sorted(CONNECTORS))})"]
    problems = []
    for f in CONNECTOR_FIELDS.get(type_, []):
        if f.required and not str(config.get(f.key) or "").strip():
            problems.append(f"{f.key} is required ({f.label})")
    return problems


# ── Detectors ─────────────────────────────────────────────────────────────
@dataclass
class DetectorDef:
    kinds: tuple
    rule_id: str
    severity: str
    title: str
    fn: Callable


DETECTORS: list[DetectorDef] = []


def detector(kinds, rule_id: str, severity: str, title: str):
    def wrap(fn: Callable) -> Callable:
        DETECTORS.append(DetectorDef(tuple(kinds), rule_id, severity, title, fn))
        return fn
    return wrap
