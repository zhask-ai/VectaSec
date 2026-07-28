"""Network discovery: find the middleware estate instead of waiting to be told about it.

Three modules, deliberately separated by what they are allowed to do:

  * `targets.py`  — resolves scope. Pure functions, no sockets. The guardrail.
  * `probes.py`   — TCP protocol fingerprints. Read-only, pre-auth, no credentials, ever.
  * `http_probes.py` — the same discipline over HTTP admin/health/descriptor endpoints.
  * `sweep.py`    — routes ports to probes and runs them concurrently.

`connect/discovery.py` is the connector that turns the result into the product's resource
model; `detect/discovery.py` is the rulepack that judges it.
"""
from .sweep import Discovery, sweep
from .targets import MAX_HOSTS, Scope, Target, resolve_scope

__all__ = ["Discovery", "sweep", "Scope", "Target", "resolve_scope", "MAX_HOSTS"]
