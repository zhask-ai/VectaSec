"""Compliance: which framework controls a finding is evidence against, and the controls table.

Unlike detect/ and connect/, there is nothing to auto-register here — a mapping is a claim
about a *published standard*, so it belongs in one reviewable table with its sources attached,
not scattered across files that each assert their own compliance meaning.
"""
from .map import (
    CONTROL_CATALOGUE,
    FRAMEWORKS,
    MISSING_RULES,
    NOT_MAPPED,
    OPEN_STATUSES,
    RULE_TO_CONTROLS,
    Control,
    ControlRef,
    controls_for,
    evaluate,
)

__all__ = [
    "CONTROL_CATALOGUE",
    "FRAMEWORKS",
    "MISSING_RULES",
    "NOT_MAPPED",
    "OPEN_STATUSES",
    "RULE_TO_CONTROLS",
    "Control",
    "ControlRef",
    "controls_for",
    "evaluate",
]
