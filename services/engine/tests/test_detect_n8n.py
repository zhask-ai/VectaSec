"""Offline unit tests for the n8n connector parse layer + rulepack.

No httpx, no live instance: every Resource is built by feeding golden REST-JSON shapes through
the connector's OWN parse layer (parse_workflow / parse_user / parse_credential / build_instance),
so a shape drift between connect/n8n.py and detect/n8n.py fails HERE, not in production.

Each detector gets a fires-on-bad, a does-not-fire-on-good, and (where the rule has one) a
not-assessable case. The two CVE version ranges are the ones verified against the GitHub advisories:
1.120.4 is the CVE-2026-21858 boundary that is fixed for CVE-2025-68613, and 1.121.0 is the reverse
— those two versions are the separators that prove each CVE rule keys on its own range.
"""
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.n8n  # noqa: F401  — import registers the rulepack
from vectasec.connect.n8n import (
    build_instance, parse_credential, parse_user, parse_workflow,
)

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("N8N.")}

EXPECTED_RULES = {
    "N8N.VERSION.CVE_2026_21858_WEBHOOK_RCE",
    "N8N.VERSION.CVE_2025_68613_EXPRESSION_RCE",
    "N8N.INSTANCE.OWNER_NOT_CONFIGURED",
    "N8N.INSTANCE.OUTDATED",
    "N8N.INSTANCE.ENCRYPTION_KEY_UNVERIFIABLE",
    "N8N.WORKFLOW.UNAUTHENTICATED_WEBHOOK",
    "N8N.CREDENTIAL.REACHABLE_VIA_UNAUTH_WEBHOOK",
    "N8N.CREDENTIAL.SHARED_ACROSS_WORKFLOWS",
    "N8N.USER.MFA_DISABLED",
    "N8N.USER.PENDING_INVITE",
}

BASE = "https://n8n.example.com"


# ── builders: raw REST JSON → parse layer → Resource ──────────────────────────
def instance(*, version="1.122.0", origin="remote", setup_pending=False, settings_status=200,
             audit=None, users_readable=True, extra_settings=None):
    settings = {
        "versionCli": version,
        "userManagement": {"showSetupOnFirstLoad": setup_pending, "smtpSetup": True},
        "endpointWebhook": "webhook",
    }
    if extra_settings:
        settings.update(extra_settings)
    return build_instance(BASE, settings=settings, settings_status=settings_status, origin=origin,
                          audit=audit, users_readable=users_readable, outcomes={})


def webhook_node(name="Webhook", *, auth="none", node_type="n8n-nodes-base.webhook", path="hook"):
    return {"name": name, "type": node_type, "webhookId": "wh-1",
            "parameters": {"httpMethod": "POST", "path": path, "authentication": auth}}


def exec_node(name="Run Command"):
    return {"name": name, "type": "n8n-nodes-base.executeCommand",
            "parameters": {"command": "echo hi"}}


def cred_node(name="HTTP Request", *, cred_id="cred-1", cred_name="My API",
              cred_type="httpHeaderAuth"):
    return {"name": name, "type": "n8n-nodes-base.httpRequest",
            "parameters": {}, "credentials": {cred_type: {"id": cred_id, "name": cred_name}}}


def workflow(*, id="wf-1", name="Demo", active=True, nodes=None):
    wf = {"id": id, "name": name, "active": active, "nodes": nodes or [], "connections": {},
          "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-02T00:00:00Z"}
    res, _refs = parse_workflow(wf)
    return res


def credential(*, id="cred-1", name="My API", cred_type="httpHeaderAuth", used_by=("wf-1",),
               unauth=False):
    return parse_credential({"id": id, "name": name, "type": cred_type},
                            list(used_by), unauth)


def user(*, id="u1", email="admin@example.com", role="global:owner", pending=False, mfa=True):
    u = {"id": id, "email": email, "role": role, "isPending": pending,
         "createdAt": "2026-01-01T00:00:00Z"}
    if mfa is not None:
        u["mfaEnabled"] = mfa
    return parse_user(u)


def ctx(*resources, **config):
    config.setdefault("base_url", BASE)
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1",
                       resources=list(resources), config=config)


def one(hits):
    assert len(hits) == 1, f"expected exactly one hit, got {len(hits)}"
    return hits[0]


def fire(fn, resource, *others):
    return fn(resource, ctx(resource, *others))


# ── registration ──────────────────────────────────────────────────────────────
def test_all_expected_rules_registered():
    assert set(RULES) == EXPECTED_RULES


def test_connector_registered_with_secret_api_key():
    from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
    assert "n8n" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["n8n"]}
    assert fields["api_key"].secret is True
    assert fields["base_url"].required is True


# ══ CVE-2026-21858 (Ni8mare, unauthenticated webhook RCE) ══════════════════
def test_cve_2026_21858_fires_in_range():
    h = one(fire(vectasec.detect.n8n.cve_2026_21858, instance(version="1.100.0")))
    assert h.severity is None and RULES[
        "N8N.VERSION.CVE_2026_21858_WEBHOOK_RCE"].severity == "critical"
    assert "CVE-2026-21858" in h.observation
    assert "GHSA-v4pr-fm98-w9pg" in h.source_ref["advisory"]
    assert "1.121.0" in h.detail


def test_cve_2026_21858_does_not_fire_at_fixed_version():
    assert fire(vectasec.detect.n8n.cve_2026_21858, instance(version="1.121.0")) == []


def test_cve_2026_21858_does_not_fire_below_affected_floor():
    # < 1.65.0 predates the vulnerable code path.
    assert fire(vectasec.detect.n8n.cve_2026_21858, instance(version="1.64.0")) == []


def test_cve_2026_21858_not_assessable_on_unparseable_version():
    h = one(fire(vectasec.detect.n8n.cve_2026_21858, instance(version="latest")))
    assert h.assessable is False
    assert "not determined" in h.observation


def test_cve_2026_21858_fires_on_boundary_that_68613_treats_as_fixed():
    # 1.120.4 is the CVE-2025-68613 fixed floor but still inside the 21858 affected range.
    assert len(fire(vectasec.detect.n8n.cve_2026_21858, instance(version="1.120.4"))) == 1


# ══ CVE-2025-68613 (authenticated expression-injection RCE) ════════════════
def test_cve_2025_68613_fires_in_first_range():
    h = one(fire(vectasec.detect.n8n.cve_2025_68613, instance(version="1.100.0")))
    assert h.severity is None and RULES[
        "N8N.VERSION.CVE_2025_68613_EXPRESSION_RCE"].severity == "high"
    assert "CVE-2025-68613" in h.observation
    assert "AUTHENTICATED" in h.observation


def test_cve_2025_68613_fires_on_1_121_0_which_21858_treats_as_fixed():
    # The clean separator: 1.121.0 is fixed for 21858 (range is <1.121.0) but vulnerable to 68613
    # (range >=1.121.0,<1.121.1).
    assert len(fire(vectasec.detect.n8n.cve_2025_68613, instance(version="1.121.0"))) == 1
    assert vectasec.detect.n8n.cve_2026_21858(instance(version="1.121.0"),
                                              ctx(instance(version="1.121.0"))) == []


def test_cve_2025_68613_does_not_fire_at_fixed_1_120_4():
    assert fire(vectasec.detect.n8n.cve_2025_68613, instance(version="1.120.4")) == []


def test_cve_2025_68613_does_not_fire_at_1_121_1():
    assert fire(vectasec.detect.n8n.cve_2025_68613, instance(version="1.121.1")) == []


def test_cve_2025_68613_does_not_fire_at_1_122_0():
    assert fire(vectasec.detect.n8n.cve_2025_68613, instance(version="1.122.0")) == []


def test_cve_2025_68613_not_assessable_on_unparseable_version():
    h = one(fire(vectasec.detect.n8n.cve_2025_68613, instance(version="v1.x")))
    assert h.assessable is False


# ══ N8N.INSTANCE.OWNER_NOT_CONFIGURED ══════════════════════════════════════
def test_owner_not_configured_fires_critical_when_remote():
    h = one(fire(vectasec.detect.n8n.owner_not_configured,
                 instance(setup_pending=True, origin="remote")))
    assert h.severity == "critical"
    assert "showSetupOnFirstLoad=true" in h.observation


def test_owner_not_configured_is_high_on_loopback():
    h = one(fire(vectasec.detect.n8n.owner_not_configured,
                 instance(setup_pending=True, origin="loopback")))
    assert h.severity == "high"


def test_owner_not_configured_does_not_fire_when_owner_exists():
    assert fire(vectasec.detect.n8n.owner_not_configured, instance(setup_pending=False)) == []


def test_owner_not_configured_does_not_fire_when_probe_absent():
    # settings probe failed → flag is None → do not assert.
    inst = build_instance(BASE, settings={}, settings_status=None, origin="remote", audit=None,
                          users_readable=True, outcomes={})
    assert fire(vectasec.detect.n8n.owner_not_configured, inst) == []


# ══ N8N.INSTANCE.OUTDATED ══════════════════════════════════════════════════
def _audit_outdated(current="1.90.0", next_versions=None):
    return {"Instance Risk Report": {"risk": "instance", "sections": [
        {"title": "Outdated instance",
         "settings": {"current_version": current},
         "nextVersions": next_versions or []}]}}


def test_instance_outdated_fires_high_with_security_release_pending():
    audit = _audit_outdated(next_versions=[{"name": "1.121.0", "hasSecurityFix": True},
                                           {"name": "1.122.0"}])
    h = one(fire(vectasec.detect.n8n.instance_outdated, instance(version="1.90.0", audit=audit)))
    assert h.severity == "high"
    assert "1.90.0" in h.observation


def test_instance_outdated_is_medium_without_security_release():
    audit = _audit_outdated(next_versions=[{"name": "1.122.0"}])
    assert one(fire(vectasec.detect.n8n.instance_outdated,
                    instance(audit=audit))).severity == "medium"


def test_instance_outdated_does_not_fire_when_audit_absent():
    assert fire(vectasec.detect.n8n.instance_outdated, instance(audit=None)) == []


def test_instance_outdated_does_not_fire_when_up_to_date():
    audit = _audit_outdated(next_versions=[])
    assert fire(vectasec.detect.n8n.instance_outdated, instance(audit=audit)) == []


# ══ N8N.INSTANCE.ENCRYPTION_KEY_UNVERIFIABLE ═══════════════════════════════
def test_encryption_key_unverifiable_is_not_assessable_with_credentials():
    inst, cred = instance(), credential()
    h = one(vectasec.detect.n8n.encryption_key_unverifiable(inst, ctx(inst, cred)))
    assert h.assessable is False
    assert "N8N_ENCRYPTION_KEY" in h.remediation


def test_encryption_key_unverifiable_does_not_fire_without_credentials():
    inst = instance()
    assert vectasec.detect.n8n.encryption_key_unverifiable(inst, ctx(inst)) == []


# ══ N8N.WORKFLOW.UNAUTHENTICATED_WEBHOOK ═══════════════════════════════════
def test_unauthenticated_webhook_fires_high_on_active_none_auth():
    wf = workflow(nodes=[webhook_node(auth="none")])
    h = one(fire(vectasec.detect.n8n.unauthenticated_webhook, wf))
    assert h.severity == "high"
    assert "authentication='none'" in h.observation


def test_unauthenticated_webhook_escalates_to_critical_with_execution_node():
    wf = workflow(nodes=[webhook_node(auth="none"), exec_node()])
    h = one(fire(vectasec.detect.n8n.unauthenticated_webhook, wf))
    assert h.severity == "critical"
    assert "executeCommand" in h.observation


def test_unauthenticated_webhook_is_info_when_workflow_inactive():
    wf = workflow(active=False, nodes=[webhook_node(auth="none")])
    assert one(fire(vectasec.detect.n8n.unauthenticated_webhook, wf)).severity == "info"


def test_unauthenticated_webhook_does_not_fire_when_authenticated():
    wf = workflow(nodes=[webhook_node(auth="headerAuth")])
    assert fire(vectasec.detect.n8n.unauthenticated_webhook, wf) == []


def test_unauthenticated_webhook_does_not_fire_without_a_webhook():
    wf = workflow(nodes=[cred_node()])
    assert fire(vectasec.detect.n8n.unauthenticated_webhook, wf) == []


def test_unauthenticated_webhook_treats_unset_authentication_as_none():
    wf = workflow(nodes=[{"name": "Webhook", "type": "n8n-nodes-base.webhook",
                          "parameters": {"httpMethod": "GET", "path": "x"}, "webhookId": "w"}])
    assert len(fire(vectasec.detect.n8n.unauthenticated_webhook, wf)) == 1


# ══ N8N.CREDENTIAL.REACHABLE_VIA_UNAUTH_WEBHOOK ════════════════════════════
def test_credential_reachable_unauth_fires():
    c = credential(unauth=True, used_by=["wf-1", "wf-2"])
    h = one(fire(vectasec.detect.n8n.credential_reachable_unauth, c))
    assert h.severity is None and RULES[
        "N8N.CREDENTIAL.REACHABLE_VIA_UNAUTH_WEBHOOK"].severity == "high"
    assert "anonymous caller" in h.observation


def test_credential_reachable_unauth_does_not_fire_when_not_reachable():
    c = credential(unauth=False)
    assert fire(vectasec.detect.n8n.credential_reachable_unauth, c) == []


# ══ N8N.CREDENTIAL.SHARED_ACROSS_WORKFLOWS ═════════════════════════════════
def test_credential_shared_fires_at_threshold():
    c = credential(used_by=["wf-1", "wf-2", "wf-3"])
    h = one(fire(vectasec.detect.n8n.credential_shared, c))
    assert h.severity is None and RULES["N8N.CREDENTIAL.SHARED_ACROSS_WORKFLOWS"].severity == "low"
    assert "3 workflows" in h.observation


def test_credential_shared_does_not_fire_below_threshold():
    c = credential(used_by=["wf-1", "wf-2"])
    assert fire(vectasec.detect.n8n.credential_shared, c) == []


# ══ N8N.USER.MFA_DISABLED ══════════════════════════════════════════════════
def test_user_mfa_disabled_fires_high_on_admin():
    u = user(role="global:owner", mfa=False)
    h = one(fire(vectasec.detect.n8n.user_mfa_disabled, u))
    assert h.severity == "high"
    assert "mfaEnabled=false" in h.observation


def test_user_mfa_disabled_fires_medium_on_member():
    u = user(email="m@example.com", role="global:member", mfa=False)
    assert one(fire(vectasec.detect.n8n.user_mfa_disabled, u)).severity == "medium"


def test_user_mfa_disabled_does_not_fire_when_enabled():
    assert fire(vectasec.detect.n8n.user_mfa_disabled, user(mfa=True)) == []


def test_user_mfa_disabled_not_assessable_when_field_absent():
    u = user(mfa=None)
    h = one(fire(vectasec.detect.n8n.user_mfa_disabled, u))
    assert h.assessable is False
    assert "not exposed" in h.assessment_reason


def test_user_mfa_disabled_does_not_fire_for_pending_user():
    assert fire(vectasec.detect.n8n.user_mfa_disabled, user(pending=True, mfa=False)) == []


# ══ N8N.USER.PENDING_INVITE ════════════════════════════════════════════════
def test_user_pending_invite_fires():
    u = user(email="invited@example.com", role="global:member", pending=True, mfa=None)
    h = one(fire(vectasec.detect.n8n.user_pending_invite, u))
    assert h.severity is None and RULES["N8N.USER.PENDING_INVITE"].severity == "low"
    assert "isPending=true" in h.observation


def test_user_pending_invite_does_not_fire_for_active_user():
    assert fire(vectasec.detect.n8n.user_pending_invite, user(pending=False)) == []
