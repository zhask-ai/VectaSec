"""Auto-registration: a connector or detector is added by dropping a file that
uses these decorators — no central list to edit."""
from dataclasses import dataclass
from typing import Callable


# ── Connectors: type -> collect(config) -> Collected ──────────────────────
CONNECTORS: dict[str, Callable] = {}


def connector(type_: str):
    def wrap(fn: Callable) -> Callable:
        CONNECTORS[type_] = fn
        return fn
    return wrap


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
