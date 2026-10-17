"""Zapier rulepack — posture over what connect/zapier.py already collected.

Six rules on the DISTINCT zapier_* kinds. Every rule reads a fact the connector recorded; none
re-queries the API. The three honest outcomes are kept apart: a rule returns [] when it checked
and found nothing, a Hit when it found something, and a Hit with assessable=False when the fact
it needed was not readable (an unreadable endpoint is a coverage gap, never "no Zaps").

Order of signal: an anonymous webhook trigger (public URL, no auth by design) that drives a
write into a production-shaped system is the Zapier shape of the n8n unauthenticated-webhook
confused-deputy path; connection sprawl and ownerless connections are the lifecycle facts the
access map needs.
"""
from ..contracts import Hit
from ..registry import detector

# One authentication wired into this many Zaps is a single secret gating that much automation.
SHARED_THRESHOLD = 5


def _raw(r) -> dict:
    return r.raw or {}


# ══ ZAPIER.ZAP.WEBHOOK_TRIGGER_UNAUTHENTICATED ═════════════════════════════
@detector(kinds=["zapier_webhook_trigger"], rule_id="ZAPIER.ZAP.WEBHOOK_TRIGGER_UNAUTHENTICATED",
          severity="high",
          title="Zap is triggered by a Webhooks by Zapier catch hook — a public URL with no authentication")
def webhook_trigger_unauthenticated(r, ctx) -> list:
    raw = _raw(r)
    enabled = raw.get("is_enabled")
    writes = raw.get("production_writes") or []
    apps = raw.get("downstream_apps") or []
    if enabled is False:
        severity = "info"           # a paused Zap's hook URL does not fire — real but inert
    elif writes:
        severity = "critical"       # anonymous input straight into a system of record
    else:
        severity = "high"
    return [Hit(
        observation=(
            f"Zap '{raw.get('zap_title')}' (id {raw.get('zap_id')}, enabled={enabled}) is triggered "
            f"by {raw.get('app')} action {raw.get('action_key')!r}. Zapier catch-hook URLs carry no "
            f"authentication by design: any client that learns the hooks.zapier.com URL can start "
            f"the Zap. Downstream apps: {apps!r}."
            + (f" {len(writes)} step(s) write to production-shaped app(s) "
               f"{sorted({w['app'] for w in writes})!r} from that anonymous entry point."
               if writes else "")),
        severity=severity,
        remediation=("Replace the catch hook with an authenticated trigger (the app's native "
                     "trigger, or Webhooks by Zapier behind a gateway that validates a signature / "
                     "shared secret), or add a Filter step that verifies a secret header before any "
                     "write. Do not treat the random URL as a credential — it leaks in logs and "
                     "exports."),
        detail=f"enabled={enabled} action_key={raw.get('action_key')} "
               f"production_writes={len(writes)} connections={len(raw.get('connection_ids') or [])}",
        source_ref={"api": "GET /v2/zaps?expand=steps.action", "config_key": "steps[0].action.app"},
    )]


# ══ ZAPIER.ZAP.WRITES_TO_PRODUCTION_SYSTEM ═════════════════════════════════
@detector(kinds=["zapier_zap"], rule_id="ZAPIER.ZAP.WRITES_TO_PRODUCTION_SYSTEM", severity="medium",
          title="Zap fed by a webhook or email trigger writes to a production system")
def writes_to_production_system(r, ctx) -> list:
    raw = _raw(r)
    if not raw.get("has_anonymous_trigger"):
        return []
    writes = raw.get("production_writes") or []
    unexpanded = raw.get("steps_unexpanded") or []
    if not writes:
        if unexpanded:
            return [Hit(
                observation=(f"Zap '{raw.get('title')}' (id {raw.get('id')}) has an anonymous "
                             f"({'webhook' if raw.get('has_webhook_trigger') else 'email'}) trigger, "
                             f"but {len(unexpanded)} step(s) came back from /v2/zaps as bare action "
                             f"ids (no expand), so which apps it writes to was not determined."),
                remediation="Grant the token zap:all / zap:account:all and ensure the connector "
                            "requests expand=steps.action so step apps are named.",
                detail=f"steps_unexpanded={unexpanded}",
                assessable=False,
                assessment_reason="zap steps were not expanded; downstream apps unknown",
                source_ref={"api": "GET /v2/zaps", "config_key": "steps[].action"},
            )]
        return []
    apps = sorted({w["app"] for w in writes})
    return [Hit(
        observation=(
            f"Zap '{raw.get('title')}' (id {raw.get('id')}, enabled={raw.get('is_enabled')}) starts "
            f"from an anonymous {'webhook' if raw.get('has_webhook_trigger') else 'email'} trigger "
            f"and performs {len(writes)} WRITE-type action(s) against production-shaped app(s) "
            f"{apps!r} (actions {[w.get('action_key') for w in writes]!r}). Whoever can reach the "
            f"trigger can cause those writes with the Zap's stored connection."),
        severity="medium" if raw.get("is_enabled") else "low",
        remediation=("Put an authenticated trigger or a secret-verifying Filter step in front of the "
                     "write, scope the connection used by the write step to the minimum role in the "
                     "target app, and consider a dedicated connection for this Zap so its blast "
                     "radius is its own."),
        detail=f"enabled={raw.get('is_enabled')} production_apps={apps} writes={len(writes)}",
        source_ref={"api": "GET /v2/zaps?expand=steps.action",
                    "config_key": "steps[].action.action_type"},
    )]


# ══ ZAPIER.CONNECTION.SHARED_ACROSS_ZAPS ═══════════════════════════════════
@detector(kinds=["zapier_connection"], rule_id="ZAPIER.CONNECTION.SHARED_ACROSS_ZAPS",
          severity="medium",
          title="One Zapier connection is used by many Zaps")
def connection_shared_across_zaps(r, ctx) -> list:
    raw = _raw(r)
    threshold = int((ctx.config or {}).get("zapier_shared_threshold") or SHARED_THRESHOLD)
    used_by = raw.get("used_by_zaps") or []
    if len(used_by) < threshold:
        return []
    app = (raw.get("app") or {})
    return [Hit(
        observation=(
            f"Connection '{raw.get('title')}' (id {raw.get('id')}, app "
            f"{app.get('key') or app.get('title') or app.get('id')}) is used by {len(used_by)} Zaps "
            f"({len(raw.get('used_by_enabled_zaps') or [])} enabled), so one stored grant gates all "
            f"of them: revoking or rotating it breaks every Zap, and a compromise of any one Zap "
            f"reaches the upstream app with this connection's full permissions."),
        remediation=("Split into per-purpose connections (one per team or per Zap group) so a "
                     "rotation or a revocation is scoped, and review whether every Zap still needs "
                     "this app at all."),
        detail=f"used_by_count={len(used_by)} threshold={threshold}",
        source_ref={"api": "GET /v2/zaps?expand=steps.authentication",
                    "config_key": "steps[].authentication"},
    )]


# ══ ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN ════════════════════════════════
@detector(kinds=["zapier_connection"], rule_id="ZAPIER.CONNECTION.OWNER_LEFT_OR_UNKNOWN",
          severity="medium",
          title="Zapier connection has no attributable owner, a deactivated owner, or has expired")
def connection_owner_left_or_unknown(r, ctx) -> list:
    raw = _raw(r)
    owner = raw.get("owner")
    app = (raw.get("app") or {})
    app_label = app.get("key") or app.get("title") or app.get("id")
    if not owner and raw.get("owner_readable") is False:
        return [Hit(
            observation=(f"Connection '{raw.get('title')}' (id {raw.get('id')}, app {app_label}) — "
                         f"GET /v1/profiles/me was not readable with this token, so the owner of "
                         f"the connection could not be attributed."),
            remediation="Grant the token the `profile` scope so connections can be attributed to "
                        "the user who owns them.",
            detail="owner_readable=False",
            assessable=False,
            assessment_reason="profile endpoint not readable; owner not attributable",
            source_ref={"api": "GET /v1/profiles/me"},
        )]
    reasons = []
    if not owner or not (owner.get("email") or owner.get("id")):
        reasons.append("no owner field")
    elif owner.get("deactivated"):
        reasons.append(f"owner {owner.get('email')} is deactivated")
    if raw.get("is_expired") is True:
        reasons.append("is_expired=true (reconnect required — the upstream grant was revoked or the "
                       "owning account no longer authorizes it)")
    if not reasons:
        return []
    used = len(raw.get("used_by_zaps") or [])
    return [Hit(
        observation=(f"Connection '{raw.get('title')}' (id {raw.get('id')}, app {app_label}, used by "
                     f"{used} Zap(s)): {'; '.join(reasons)}. A connection without a live owner is a "
                     f"stored third-party grant that no access review will catch."),
        remediation=("Re-own the connection under a service account that is part of offboarding, or "
                     "delete it and reconnect from the Zaps that still need it. An expired "
                     "connection whose Zaps are enabled is already failing — remove it."),
        detail=f"owner={owner and owner.get('email')} is_expired={raw.get('is_expired')} used_by={used}",
        source_ref={"api": "GET /v2/authentications", "config_key": "is_expired"},
    )]


# ══ ZAPIER.ACCOUNT.NOT_ASSESSED ════════════════════════════════════════════
@detector(kinds=["zapier_account"], rule_id="ZAPIER.ACCOUNT.NOT_ASSESSED", severity="info",
          title="Zapier inventory could not be read — posture not assessed")
def account_not_assessed(r, ctx) -> list:
    raw = _raw(r)
    col = raw.get("collection") or {}
    gaps = {k: v for k, v in col.items()
            if k in ("zaps", "authentications") and v.get("outcome") != "ok"}
    if not gaps:
        return []
    parts = [f"{k}: {v.get('outcome')} ({v.get('error') or 'n/a'})" for k, v in gaps.items()]
    return [Hit(
        observation=(f"Zapier account '{raw.get('account_id') or r.name}' at {raw.get('base_url')}: "
                     f"{'; '.join(parts)}. Zaps read: {raw.get('zap_count')}; connections read: "
                     f"{raw.get('connection_count')}. An unreadable endpoint is not an empty one."),
        remediation=("Issue the token with scopes zap:all (or zap:account:all) and connection:read. "
                     "A 403 on /v2/zaps usually means the scope is `zap` only (the partner's own "
                     "integration), which returns a slice of the inventory."),
        detail=" ".join(f"{k}={v.get('outcome')}" for k, v in gaps.items()),
        assessable=False,
        assessment_reason="zaps and/or authentications endpoint not readable",
        source_ref={"api": ", ".join(f"GET /v2/{k}" for k in gaps)},
    )]


# ══ ZAPIER.ZAP.PAUSED_WITH_LIVE_CONNECTION ═════════════════════════════════
@detector(kinds=["zapier_zap"], rule_id="ZAPIER.ZAP.PAUSED_WITH_LIVE_CONNECTION", severity="low",
          title="Paused Zap still holds live connections")
def paused_with_live_connection(r, ctx) -> list:
    raw = _raw(r)
    if raw.get("is_enabled"):
        return []
    cids = raw.get("connection_ids") or []
    if not cids:
        return []
    conns = {c.raw.get("id"): c.raw for c in ctx.of_kind("zapier_connection")}
    live = [cid for cid in cids if (conns.get(cid) or {}).get("is_expired") is not True]
    if not live:
        return []
    return [Hit(
        observation=(f"Zap '{raw.get('title')}' (id {raw.get('id')}) is paused (is_enabled=false, "
                     f"last successful run {raw.get('last_successful_run_date') or 'never'}) but "
                     f"still references {len(live)} live connection(s) {live!r}. The stored grants "
                     f"remain valid while nothing legitimately uses them."),
        remediation=("Delete the Zap if it is retired, or move it off shared connections. A paused "
                     "Zap keeps its connections alive forever — they never show up as unused."),
        detail=f"live_connections={len(live)} total_connections={len(cids)}",
        source_ref={"api": "GET /v2/zaps", "config_key": "is_enabled"},
    )]
