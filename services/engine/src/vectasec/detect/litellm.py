"""LiteLLM proxy (AI gateway) rulepack (connect/litellm.py).

CVE table: GitHub Advisory Database entries for the `litellm` package with a confirmed fixed
version (queried 2026-11-23). Only the version reported by the proxy is compared; when the
proxy does not report it, the rule says so instead of guessing.
"""
import re

from ..contracts import Hit
from ..registry import detector

# (cve, summary, affected_from (inclusive) or None, fixed_in, severity)
LITELLM_ADVISORIES = [
    ("CVE-2024-2952", "server-side template injection", None, "1.34.42", "critical"),
    ("CVE-2024-4888", "arbitrary file deletion", None, "1.35.36", "high"),
    ("CVE-2024-5225", "SQL injection", None, "1.40.0", "critical"),
    ("CVE-2024-5751", "remote code execution through eval", None, "1.40.16", "critical"),
    ("CVE-2024-6587", "server-side request forgery", None, "1.44.8", "high"),
    ("CVE-2024-9606", "partial API keys written to logs", None, "1.44.12", "medium"),
    ("CVE-2025-0628", "improper authorization (viewer gets admin key)", None, "1.61.15", "high"),
    ("CVE-2026-35029", "privilege escalation through the config endpoint", None, "1.83.0", "high"),
    ("CVE-2026-35030", "OIDC authentication bypass", None, "1.83.0", "critical"),
    ("CVE-2026-42208", "SQL injection in key verification", "1.81.16", "1.83.7", "critical"),
    ("CVE-2026-42271", "MCP stdio remote code execution", "1.74.2", "1.83.7", "critical"),
    ("CVE-2026-40217", "sandbox escape (listed by CISA as exploited)", "1.81.8", "1.83.10", "critical"),
    ("CVE-2026-47102", "users can change their own role", None, "1.83.10", "high"),
    ("CVE-2026-47101", "internal users can create over-privileged keys", None, "1.83.14", "high"),
    ("CVE-2026-49468", "authentication bypass through the Host header", None, "1.84.0", "critical"),
]
# GHSA-5mg7-485q-xm76: these PyPI releases shipped credential-stealing malware.
MALICIOUS_RELEASES = ("1.82.7", "1.82.8")


def _v(s) -> tuple:
    nums = re.findall(r"\d+", str(s or "").split("-")[0].split("+")[0])
    return tuple(int(n) for n in nums[:3]) if nums else ()


def affected(version: str) -> list:
    v = _v(version)
    if not v:
        return []
    return [a for a in LITELLM_ADVISORIES
            if v < _v(a[3]) and (a[2] is None or v >= _v(a[2]))]


def _proxy_name(raw):
    return raw.get("base_url") or "LiteLLM proxy"


@detector(kinds=["litellm_proxy"], rule_id="LITELLM.AUTH.NO_MASTER_KEY", severity="critical",
          title="LiteLLM proxy answers key-management calls without any key")
def no_master_key(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("no_auth"):
        return []
    return [Hit(
        observation=(f"{_proxy_name(raw)} returned the virtual-key list (GET /key/list) to a request "
                     "with no key. With no master_key set, LiteLLM is open: anyone who reaches it can "
                     "create keys and spend on every provider account behind it"),
        remediation=("Set LITELLM_MASTER_KEY to a long random value stored in a secrets manager, restart "
                     "the proxy, and give apps scoped virtual keys. Then check provider bills for use "
                     "you did not expect."),
        source_ref={"api": "GET /key/list", "auth": "none"},
    )]


@detector(kinds=["litellm_proxy"], rule_id="LITELLM.AUTH.DEFAULT_MASTER_KEY", severity="critical",
          title="LiteLLM proxy accepts the docs' example key sk-1234")
def default_master_key(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("default_key_accepted"):
        return []
    return [Hit(
        observation=(f"{_proxy_name(raw)} accepted the example key 'sk-1234' from the LiteLLM docs on "
                     "GET /key/list. That key is public; security researchers found hundreds of "
                     "internet-facing gateways still using it"),
        remediation=("Replace the master key with a long random value from a secrets manager, rotate "
                     "every provider key the proxy holds (they may have been read), and set UI_PASSWORD "
                     "so the master key is not also the admin UI password."),
        source_ref={"api": "GET /key/list", "auth": "Bearer sk-1234"},
    )]


@detector(kinds=["litellm_proxy"], rule_id="LITELLM.VERSION.MALICIOUS_RELEASE", severity="critical",
          title="LiteLLM is running a release that shipped malware")
def malicious_release(r, ctx) -> list:
    raw = r.raw or {}
    if str(raw.get("version") or "").strip() not in MALICIOUS_RELEASES:
        return []
    return [Hit(
        observation=(f"{_proxy_name(raw)} reports version {raw.get('version')}. PyPI releases 1.82.7 and "
                     "1.82.8 were published with credential-stealing code (GHSA-5mg7-485q-xm76)"),
        remediation=("Treat the host as compromised: rotate the master key and every provider key and "
                     "secret on that machine, then reinstall from a clean, current release."),
        source_ref={"advisory": "GHSA-5mg7-485q-xm76", "version_source": raw.get("version_source")},
    )]


@detector(kinds=["litellm_proxy"], rule_id="LITELLM.VERSION.KNOWN_CVE", severity="high",
          title="LiteLLM version has known security advisories")
def known_cve(r, ctx) -> list:
    raw = r.raw or {}
    version = raw.get("version")
    if not version:
        return [Hit(
            observation=(f"{_proxy_name(raw)} did not report its version (newer releases hide it on "
                         "/health/readiness and /openapi.json may be turned off), so known advisories "
                         "could not be checked"),
            remediation="Check the running version by hand and compare it with the LiteLLM security advisories.",
            assessable=False, assessment_reason="version not reported",
            source_ref={"api": "/health/readiness, /openapi.json"},
        )]
    hits = affected(version)
    if not hits:
        return []
    worst = "critical" if any(h[4] == "critical" for h in hits) else "high"
    newest_fix = max((h[3] for h in hits), key=_v)
    return [Hit(
        observation=(f"{_proxy_name(raw)} runs LiteLLM {version}, which is affected by {len(hits)} "
                     f"advisories: " + "; ".join(f"{h[0]} ({h[1]})" for h in hits[:6])
                     + ("…" if len(hits) > 6 else "")),
        remediation=f"Upgrade to {newest_fix} or later (ideally the current release).",
        detail=" ".join(h[0] for h in hits),
        severity=worst,
        source_ref={"version_source": raw.get("version_source"), "advisories": [h[0] for h in hits]},
    )]


@detector(kinds=["litellm_proxy"], rule_id="LITELLM.PROXY.NOT_ASSESSED", severity="info",
          title="LiteLLM inventory could not be read — posture not assessed")
def not_assessed(r, ctx) -> list:
    raw = r.raw or {}
    gaps = {k: v for k, v in (raw.get("collection") or {}).items() if (v or {}).get("outcome") != "ok"}
    if not gaps:
        return []
    return [Hit(
        observation=(f"{_proxy_name(raw)}: " + "; ".join(f"{k}: {v.get('outcome')} ({v.get('error') or 'n/a'})"
                                                        for k, v in gaps.items())
                     + ". An unreadable list is not an empty one"),
        remediation=("Use a key with the proxy_admin_viewer role; other roles only see their own keys."),
        assessable=False, assessment_reason="one or more LiteLLM endpoints not readable",
        source_ref={"api": ", ".join(gaps)},
    )]


def _live(raw) -> bool:
    return not raw.get("blocked") and not raw.get("expired")


@detector(kinds=["litellm_key"], rule_id="LITELLM.KEY.NO_BUDGET", severity="medium",
          title="LiteLLM virtual key has no spending limit")
def key_no_budget(r, ctx) -> list:
    raw = r.raw or {}
    if not _live(raw) or raw.get("max_budget") is not None or raw.get("team_max_budget") is not None:
        return []
    return [Hit(
        observation=(f"LiteLLM key '{r.name}'" + (f" (owner {raw.get('owner')})" if raw.get("owner") else "")
                     + " has no max_budget and its team has none either; a leaked or looping client can "
                     f"spend without limit (spent so far: {raw.get('spend') or 0})"),
        remediation="Set max_budget with a budget_duration (for example a monthly cap) on the key or its team.",
        source_ref={"api": "GET /key/list", "key": raw.get("key_name"), "field": "max_budget"},
    )]


@detector(kinds=["litellm_key"], rule_id="LITELLM.KEY.NO_EXPIRY", severity="low",
          title="LiteLLM virtual key never expires")
def key_no_expiry(r, ctx) -> list:
    raw = r.raw or {}
    if not _live(raw) or raw.get("expires") or raw.get("auto_rotate"):
        return []
    return [Hit(
        observation=f"LiteLLM key '{r.name}' has no expiry date and no automatic rotation",
        remediation="Give keys a duration when you create them, or turn on auto_rotate with a rotation_interval.",
        source_ref={"api": "GET /key/list", "key": raw.get("key_name"), "field": "expires"},
    )]


@detector(kinds=["litellm_key"], rule_id="LITELLM.KEY.ALL_MODELS", severity="medium",
          title="LiteLLM virtual key can call every model")
def key_all_models(r, ctx) -> list:
    raw = r.raw or {}
    if not _live(raw) or not raw.get("all_models") or raw.get("team_restricts_models"):
        return []
    return [Hit(
        observation=(f"LiteLLM key '{r.name}' has an empty or wildcard model list, which LiteLLM reads as "
                     "access to every model on the proxy, including the most expensive ones"),
        remediation="List only the models this app needs in the key's `models` (or restrict its team).",
        source_ref={"api": "GET /key/list", "key": raw.get("key_name"), "field": "models"},
    )]


@detector(kinds=["litellm_key"], rule_id="LITELLM.KEY.NO_OWNER", severity="medium",
          title="LiteLLM virtual key belongs to no user and no team")
def key_no_owner(r, ctx) -> list:
    raw = r.raw or {}
    if not _live(raw) or raw.get("user_id") or raw.get("team_id"):
        return []
    return [Hit(
        observation=(f"LiteLLM key '{r.name}' is tied to no user and no team"
                     + (f" (created by {raw.get('created_by')})" if raw.get("created_by") else "")
                     + "; nobody will be asked about it when people leave or teams change"),
        remediation="Assign the key to the team that uses it, or delete it if nobody claims it.",
        source_ref={"api": "GET /key/list", "key": raw.get("key_name")},
    )]


@detector(kinds=["litellm_key"], rule_id="LITELLM.KEY.UNUSED", severity="low",
          title="LiteLLM virtual key has not been used for 90 days")
def key_unused(r, ctx) -> list:
    raw = r.raw or {}
    if not _live(raw) or not raw.get("last_active_known"):
        return []
    limit = int((ctx.config or {}).get("litellm_unused_days") or 90)
    idle = raw.get("days_since_active")
    if idle is None:
        idle = raw.get("days_since_created")
        if idle is None or idle <= limit:
            return []
        when = f"has never been used and was created {idle} days ago"
    elif idle <= limit:
        return []
    else:
        when = f"was last used {idle} days ago"
    return [Hit(
        observation=f"LiteLLM key '{r.name}' {when}, but still works",
        remediation="Block or delete the key (POST /key/block or /key/delete). Unused live keys are free access for whoever finds them.",
        detail=f"idle_days={idle} limit={limit}",
        source_ref={"api": "GET /key/list", "key": raw.get("key_name"), "field": "last_active"},
    )]
