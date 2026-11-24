"""Make (make.com) rulepack (connect/make.py).

Every rule here reads only what the Make API returns. Where the API is silent (who created a
connection, webhook authentication, other users' alert settings) no claim is made.
"""
from ..contracts import Hit
from ..registry import detector


@detector(kinds=["make_connection"], rule_id="MAKE.CONNECTION.PERSONAL_ACCOUNT", severity="high",
          title="Make connection runs under a personal email account")
def personal_account(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("personal_account"):
        return []
    n = len(raw.get("used_by_scenarios") or [])
    return [Hit(
        observation=(f"Make connection '{raw.get('name')}' to {raw.get('app') or 'an app'} authenticates as "
                     f"{raw.get('account_email')}, a personal {raw.get('account_domain')} account, and "
                     f"{n} scenario(s) use it"),
        remediation=("Reconnect it with a company-owned service account, switch the scenarios to the new "
                     "connection, then delete this one and revoke the grant in the personal account. "
                     "When the person leaves or changes their password, these scenarios stop or keep "
                     "running on access the company does not control."),
        source_ref={"api": "GET /connections", "connection": raw.get("id"), "field": "metadata"},
    )]


@detector(kinds=["make_connection"], rule_id="MAKE.CONNECTION.UNUSED", severity="medium",
          title="Make connection is not used by any scenario or webhook")
def connection_unused(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("usages_readable") or raw.get("expired"):
        return []
    if raw.get("used_by_scenarios") or raw.get("used_by_hooks"):
        return []
    return [Hit(
        observation=(f"Make connection '{raw.get('name')}' to {raw.get('app') or 'an app'}"
                     + (f" (account {raw.get('account_email')})" if raw.get("account_email") else "")
                     + " is used by no scenario and no webhook, but is still live"),
        remediation=("Delete the connection in Make (Connections), then revoke the grant or API key in "
                     "the connected app so it stops working there too."),
        source_ref={"api": "GET /connections cols[]=scenarioUsages,hookUsages", "connection": raw.get("id")},
    )]


@detector(kinds=["make_hook"], rule_id="MAKE.HOOK.ACTIVE_PUBLIC_WEBHOOK", severity="medium",
          title="Make webhook starts an active scenario for anyone with its URL")
def public_webhook(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("enabled") or raw.get("gone") or raw.get("scenario_active") is not True:
        return []
    if "webhook" not in str(raw.get("type_name") or "").lower():
        return []
    return [Hit(
        observation=(f"Make webhook '{raw.get('name')}' ({raw.get('type_name')}, host {raw.get('url_host')}) is "
                     f"enabled and starts active scenario {raw.get('scenario_id')}; the Make API exposes no "
                     "authentication setting for webhooks, so the URL itself is the only secret"),
        remediation=("Treat the URL as a password: do not paste it into tickets or front-end code. In the "
                     "scenario, reject requests that do not carry a shared secret header, and rotate the "
                     "webhook (create a new one) if the URL may have leaked."),
        source_ref={"api": "GET /hooks", "hook": raw.get("id")},
    )]


@detector(kinds=["make_organization"], rule_id="MAKE.ORG.TFA_NOT_ENFORCED", severity="medium",
          title="Make organization does not enforce two-factor sign-in")
def tfa_not_enforced(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("tfa_enforced") is not False:
        return []
    return [Hit(
        observation=(f"Make organization '{raw.get('name')}' reports tfaEnforced=false"
                     + (f" and SSO type {raw.get('sso_type')}" if raw.get("sso_type") else " and no SSO")),
        remediation=("Enforce two-factor authentication for the organization (Organization settings), or "
                     "sign in through company SSO. Anyone who signs in can read and change every "
                     "connection the scenarios use."),
        source_ref={"api": "GET /organizations", "field": "tfaEnforced"},
    )]


@detector(kinds=["make_account"], rule_id="MAKE.ACCOUNT.NOT_ASSESSED", severity="info",
          title="Make inventory could not be read — posture not assessed")
def account_not_assessed(r, ctx) -> list:
    raw = r.raw or {}
    col = raw.get("collection") or {}
    gaps = {k: v for k, v in col.items()
            if k in ("organizations", "teams", "scenarios", "connections", "hooks")
            and (v or {}).get("outcome") != "ok"}
    if not gaps:
        return []
    parts = [f"{k}: {v.get('outcome')} ({v.get('error') or 'n/a'})" for k, v in gaps.items()]
    return [Hit(
        observation=(f"Make at {raw.get('base_url')}: {'; '.join(parts)}. "
                     "An unreadable endpoint is not an empty one."),
        remediation=("Issue the API token with the read scopes organizations:read, teams:read, "
                     "scenarios:read, connections:read and hooks:read, and check the zone is right."),
        detail=" ".join(f"{k}={v.get('outcome')}" for k, v in gaps.items()),
        assessable=False,
        assessment_reason="one or more Make endpoints not readable",
        source_ref={"api": ", ".join(f"GET /{k}" for k in gaps)},
    )]
