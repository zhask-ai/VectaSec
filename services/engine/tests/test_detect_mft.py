"""Unit tests for the MFT/EDI rulepack. Offline: no httpx, no appliance, no network.

Every rule gets a FIRE case and a DOES-NOT-FIRE case, and every rule with a third outcome gets a
NOT-ASSESSABLE case. Resources are built by feeding the golden probe fixtures
(fixtures/mft_responses.json) through the connector's OWN pure parse layer
(build_resources / parse_server / parse_endpoint / parse_transfer_account), so the detectors here
run against exactly the shapes connect/mft.py emits — a hand-written dict cannot drift past this
suite. The CVE rules pin the verified affected/patched version boundaries (incl. the Cleo
incomplete-patch nuance: 5.8.0.21 fixes CVE-2024-50623 but is still vulnerable to CVE-2024-55956).
"""
import copy
import json
import pathlib

from vectasec.contracts import Collected, Resource, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import DETECTORS
import vectasec.detect.mft  # noqa: F401  — import registers the rulepack
from vectasec.connect.mft import (
    build_resources, fingerprint, parse_server,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "mft_responses.json").read_text()
)

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("MFT.")}

EXPECTED_RULES = {
    "MFT.ADMIN.CONSOLE_EXPOSED",
    "MFT.ADMIN.DEFAULT_ACCOUNT",
    "MFT.MOVEIT.SQLI_CVE_2023_34362",
    "MFT.GOANYWHERE.RCE_CVE_2023_0669",
    "MFT.GOANYWHERE.AUTH_BYPASS_CVE_2024_0204",
    "MFT.CLEO.FILE_RCE_CVE_2024_50623",
    "MFT.CLEO.AUTORUN_RCE_CVE_2024_55956",
    "MFT.PATCH.VENDOR_ADVISORY_REVIEW",
    "MFT.AS2.NO_MESSAGE_SIGNING",
    "MFT.AS2.NO_ENCRYPTION",
    "MFT.SFTP.PASSWORD_AUTH_ENABLED",
    "MFT.SFTP.WEAK_HOST_KEY",
    "MFT.TLS.WEAK_OR_EXPIRED",
    "MFT.TRANSFER.ANONYMOUS_ACCOUNT",
    "MFT.TRANSFER.STORED_CREDENTIAL",
    "MFT.SERVER.NOT_ASSESSABLE",
}


# ── builders: fixture → parse layer → Resource ────────────────────────────────
def _probe(name, **over):
    p = copy.deepcopy(FIX[name])
    p.update(over)
    return p


def server(name, **over):
    return parse_server(_probe(name, **over))


def built(name):
    return build_resources([copy.deepcopy(FIX[name])])


def endpoint(name, ep_name):
    col = built(name)
    return next(r for r in col.resources
               if r.kind == "mft_endpoint" and (r.raw or {}).get("name") == ep_name)


def account(name, username):
    col = built(name)
    return next(r for r in col.resources
               if r.kind == "mft_transfer_account" and (r.raw or {}).get("username") == username)


def scan(*resources):
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1", resources=list(resources))


def fire(rule_id, resource, ctx=None):
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to kind={resource.kind}"
    return d.fn(resource, ctx or scan(resource)) or []


def sev(hits, rule_id):
    base = RULES[rule_id].severity
    return [h.severity or base for h in hits]


# ── pack shape ────────────────────────────────────────────────────────────────
def test_expected_rules_all_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rules_only_run_on_mft_kinds():
    for d in RULES.values():
        assert all(k.startswith("mft_") for k in d.kinds), d.rule_id


# ── fingerprint / server ──────────────────────────────────────────────────────
def test_fingerprint_identifies_each_product_and_version():
    cases = {
        "moveit_vulnerable_exposed": ("moveit", "15.0.0"),
        "goanywhere_vulnerable": ("goanywhere", "7.1.1"),
        "cleo_vulnerable": ("cleo", "5.8.0.20"),
        "sterling": ("sterling", "6.1.2.0"),
        "axway": ("axway", "5.5"),
    }
    for name, (product, version) in cases.items():
        prod, ver, readable, _ = fingerprint(FIX[name])
        assert prod == product, name
        assert ver == version and readable is True, name


def test_unfingerprinted_server_records_outcome():
    s = server("unfingerprinted")
    assert s.raw["product"] == "unknown"
    assert s.raw["probe_outcome"] == "unfingerprinted"


def test_unreachable_server_records_error_outcome():
    s = server("unreachable")
    assert s.raw["probe_outcome"] == "error"
    assert "Connection refused" in s.raw["error"]


# ── exposed admin console ─────────────────────────────────────────────────────
def test_console_exposed_fires_on_unauthenticated_management_path():
    hits = fire("MFT.ADMIN.CONSOLE_EXPOSED", server("moveit_vulnerable_exposed"))
    assert len(hits) == 1 and hits[0].assessable
    assert "/human.aspx" in hits[0].observation


def test_console_exposed_quiet_when_console_is_gated():
    assert fire("MFT.ADMIN.CONSOLE_EXPOSED", server("moveit_patched")) == []


def test_console_exposed_not_assessable_when_no_path_probed():
    s = server("moveit_patched", admin_paths=[])
    hits = fire("MFT.ADMIN.CONSOLE_EXPOSED", s)
    assert len(hits) == 1 and hits[0].assessable is False


# ── default / anonymous admin account ─────────────────────────────────────────
def test_default_admin_fires_when_present():
    hits = fire("MFT.ADMIN.DEFAULT_ACCOUNT", server("moveit_vulnerable_exposed"))
    assert len(hits) == 1 and hits[0].assessable
    assert sev(hits, "MFT.ADMIN.DEFAULT_ACCOUNT") == ["critical"]


def test_default_admin_quiet_when_unauthenticated_scan():
    # admin_api not readable, but we never had a token — silence, not a false not-assessable.
    assert fire("MFT.ADMIN.DEFAULT_ACCOUNT", server("moveit_patched")) == []


def test_default_admin_not_assessable_when_token_but_api_unreadable():
    hits = fire("MFT.ADMIN.DEFAULT_ACCOUNT", server("moveit_patched", authenticated_scan=True))
    assert len(hits) == 1 and hits[0].assessable is False


# ── MOVEit CVE-2023-34362 ─────────────────────────────────────────────────────
def test_moveit_sqli_fires_below_floor_and_cites_advisory():
    hits = fire("MFT.MOVEIT.SQLI_CVE_2023_34362", server("moveit_vulnerable_exposed"))
    assert len(hits) == 1 and hits[0].assessable
    assert hits[0].source_ref.get("cve") == "CVE-2023-34362"
    assert "AA23-158A" in hits[0].source_ref.get("advisory", "")


def test_moveit_sqli_quiet_on_patched_build():
    assert fire("MFT.MOVEIT.SQLI_CVE_2023_34362", server("moveit_patched")) == []


def test_moveit_sqli_not_assessable_on_unreadable_and_unknown_series():
    for name in ("moveit_no_version", "moveit_unknown_series"):
        hits = fire("MFT.MOVEIT.SQLI_CVE_2023_34362", server(name))
        assert len(hits) == 1 and hits[0].assessable is False, name


def test_moveit_rule_ignores_other_products():
    assert fire("MFT.MOVEIT.SQLI_CVE_2023_34362", server("goanywhere_vulnerable")) == []


# ── GoAnywhere CVE-2023-0669 ──────────────────────────────────────────────────
def test_goanywhere_0669_fires_on_711_and_older():
    assert len(fire("MFT.GOANYWHERE.RCE_CVE_2023_0669", server("goanywhere_vulnerable"))) == 1
    assert len(fire("MFT.GOANYWHERE.RCE_CVE_2023_0669", server("goanywhere_pre_601"))) == 1


def test_goanywhere_0669_quiet_on_712_plus():
    assert fire("MFT.GOANYWHERE.RCE_CVE_2023_0669", server("goanywhere_patched")) == []
    assert fire("MFT.GOANYWHERE.RCE_CVE_2023_0669", server("goanywhere_0204_only")) == []


def test_goanywhere_0669_not_assessable_when_version_unreadable():
    hits = fire("MFT.GOANYWHERE.RCE_CVE_2023_0669",
                server("goanywhere_vulnerable", banner="GoAnywhere MFT"))
    assert len(hits) == 1 and hits[0].assessable is False


# ── GoAnywhere CVE-2024-0204 ──────────────────────────────────────────────────
def test_goanywhere_0204_fires_within_affected_range():
    assert len(fire("MFT.GOANYWHERE.AUTH_BYPASS_CVE_2024_0204",
                    server("goanywhere_vulnerable"))) == 1
    assert len(fire("MFT.GOANYWHERE.AUTH_BYPASS_CVE_2024_0204",
                    server("goanywhere_0204_only"))) == 1


def test_goanywhere_0204_quiet_at_and_above_fix_and_below_lower_bound():
    assert fire("MFT.GOANYWHERE.AUTH_BYPASS_CVE_2024_0204", server("goanywhere_patched")) == []
    # 6.0.0 is below the stated 6.0.1 lower bound for THIS CVE — must not over-claim.
    assert fire("MFT.GOANYWHERE.AUTH_BYPASS_CVE_2024_0204", server("goanywhere_pre_601")) == []


def test_goanywhere_0204_not_assessable_when_version_unreadable():
    hits = fire("MFT.GOANYWHERE.AUTH_BYPASS_CVE_2024_0204",
                server("goanywhere_vulnerable", banner="GoAnywhere MFT"))
    assert len(hits) == 1 and hits[0].assessable is False


# ── Cleo CVE-2024-50623 & CVE-2024-55956 (the incomplete-patch nuance) ─────────
def test_cleo_file_rce_fires_below_58021():
    assert len(fire("MFT.CLEO.FILE_RCE_CVE_2024_50623", server("cleo_vulnerable"))) == 1


def test_cleo_file_rce_quiet_at_58021_and_above():
    assert fire("MFT.CLEO.FILE_RCE_CVE_2024_50623", server("cleo_partial_patch")) == []
    assert fire("MFT.CLEO.FILE_RCE_CVE_2024_50623", server("cleo_patched")) == []


def test_cleo_autorun_rce_still_fires_on_partial_patch_58021():
    # 5.8.0.21 fixes CVE-2024-50623 but remained vulnerable to CVE-2024-55956 (fixed 5.8.0.24).
    assert len(fire("MFT.CLEO.AUTORUN_RCE_CVE_2024_55956", server("cleo_vulnerable"))) == 1
    assert len(fire("MFT.CLEO.AUTORUN_RCE_CVE_2024_55956", server("cleo_partial_patch"))) == 1


def test_cleo_autorun_rce_quiet_at_58024():
    assert fire("MFT.CLEO.AUTORUN_RCE_CVE_2024_55956", server("cleo_patched")) == []


def test_cleo_rules_not_assessable_when_version_unreadable():
    for rule in ("MFT.CLEO.FILE_RCE_CVE_2024_50623", "MFT.CLEO.AUTORUN_RCE_CVE_2024_55956"):
        hits = fire(rule, server("cleo_vulnerable", banner="Cleo Harmony"))
        assert len(hits) == 1 and hits[0].assessable is False, rule


# ── Sterling / Axway: honest not-assessable patch state ───────────────────────
def test_patch_state_not_assessable_for_unverified_products():
    for name in ("sterling", "axway"):
        hits = fire("MFT.PATCH.VENDOR_ADVISORY_REVIEW", server(name))
        assert len(hits) == 1 and hits[0].assessable is False, name


def test_patch_state_ignores_products_with_a_verified_floor():
    assert fire("MFT.PATCH.VENDOR_ADVISORY_REVIEW", server("moveit_vulnerable_exposed")) == []


# ── AS2 message security ──────────────────────────────────────────────────────
def test_as2_no_signing_fire_pass_and_not_assessable():
    assert len(fire("MFT.AS2.NO_MESSAGE_SIGNING",
                    endpoint("moveit_vulnerable_exposed", "partner-acme-as2"))) == 1
    assert fire("MFT.AS2.NO_MESSAGE_SIGNING",
                endpoint("moveit_vulnerable_exposed", "partner-globex-as2")) == []
    na = fire("MFT.AS2.NO_MESSAGE_SIGNING",
              endpoint("moveit_vulnerable_exposed", "partner-initech-as2"))
    assert len(na) == 1 and na[0].assessable is False


def test_as2_no_encryption_fire_pass_and_not_assessable():
    assert len(fire("MFT.AS2.NO_ENCRYPTION",
                    endpoint("moveit_vulnerable_exposed", "partner-acme-as2"))) == 1
    assert fire("MFT.AS2.NO_ENCRYPTION",
                endpoint("moveit_vulnerable_exposed", "partner-globex-as2")) == []
    na = fire("MFT.AS2.NO_ENCRYPTION",
              endpoint("moveit_vulnerable_exposed", "partner-initech-as2"))
    assert len(na) == 1 and na[0].assessable is False


def test_as2_rules_ignore_sftp_endpoints():
    assert fire("MFT.AS2.NO_MESSAGE_SIGNING",
                endpoint("moveit_vulnerable_exposed", "sftp-listener")) == []


# ── SFTP auth hygiene ─────────────────────────────────────────────────────────
def test_sftp_password_auth_fire_pass_and_not_assessable():
    assert len(fire("MFT.SFTP.PASSWORD_AUTH_ENABLED",
                    endpoint("moveit_vulnerable_exposed", "sftp-listener"))) == 1
    assert fire("MFT.SFTP.PASSWORD_AUTH_ENABLED",
                endpoint("moveit_vulnerable_exposed", "sftp-strong")) == []
    na = fire("MFT.SFTP.PASSWORD_AUTH_ENABLED",
              endpoint("moveit_vulnerable_exposed", "sftp-unknown"))
    assert len(na) == 1 and na[0].assessable is False


def test_sftp_weak_host_key_fire_pass_and_not_assessable():
    hits = fire("MFT.SFTP.WEAK_HOST_KEY",
                endpoint("moveit_vulnerable_exposed", "sftp-listener"))
    assert len(hits) == 1 and "ssh-rsa" in hits[0].observation
    assert fire("MFT.SFTP.WEAK_HOST_KEY",
                endpoint("moveit_vulnerable_exposed", "sftp-strong")) == []
    na = fire("MFT.SFTP.WEAK_HOST_KEY",
              endpoint("moveit_vulnerable_exposed", "sftp-unknown"))
    assert len(na) == 1 and na[0].assessable is False


# ── TLS hygiene ───────────────────────────────────────────────────────────────
_VALID_TLS = {"enabled": True, "cert_status": "valid", "negotiated": "TLSv1.3", "expired": False}


def test_tls_passes_on_valid_certificate():
    assert fire("MFT.TLS.WEAK_OR_EXPIRED", server("moveit_patched")) == []


def test_tls_fires_on_expired_certificate():
    tls = dict(_VALID_TLS, cert_status="invalid", expired=True)
    assert len(fire("MFT.TLS.WEAK_OR_EXPIRED", server("moveit_patched", tls=tls))) == 1


def test_tls_fires_on_weak_protocol_version():
    tls = dict(_VALID_TLS, negotiated="TLSv1.0")
    assert len(fire("MFT.TLS.WEAK_OR_EXPIRED", server("moveit_patched", tls=tls))) == 1


def test_tls_fires_on_plaintext_http_surface():
    hits = fire("MFT.TLS.WEAK_OR_EXPIRED", server("moveit_patched", scheme="http"))
    assert len(hits) == 1 and "plaintext" in hits[0].observation


def test_tls_not_assessable_when_probe_incomplete():
    tls = dict(_VALID_TLS, cert_status="unknown")
    hits = fire("MFT.TLS.WEAK_OR_EXPIRED", server("moveit_patched", tls=tls))
    assert len(hits) == 1 and hits[0].assessable is False


def test_tls_quiet_on_unreachable_target():
    assert fire("MFT.TLS.WEAK_OR_EXPIRED", server("unreachable")) == []


# ── transfer accounts ─────────────────────────────────────────────────────────
def test_transfer_anonymous_account_fires():
    hits = fire("MFT.TRANSFER.ANONYMOUS_ACCOUNT",
                account("moveit_vulnerable_exposed", "anonymous"))
    assert len(hits) == 1 and "anonymous" in hits[0].observation


def test_transfer_named_partner_account_passes():
    assert fire("MFT.TRANSFER.ANONYMOUS_ACCOUNT",
                account("moveit_vulnerable_exposed", "acme_edi")) == []


def test_transfer_enabled_default_account_fires():
    acct = account("moveit_vulnerable_exposed", "acme_edi")
    acct.raw["is_default"] = True
    assert len(fire("MFT.TRANSFER.ANONYMOUS_ACCOUNT", acct)) == 1


def test_transfer_stored_credential_severity_tracks_plaintext():
    plain = fire("MFT.TRANSFER.STORED_CREDENTIAL",
                 account("moveit_vulnerable_exposed", "acme_edi"))
    assert sev(plain, "MFT.TRANSFER.STORED_CREDENTIAL") == ["medium"]   # plaintext-capable
    hashed = fire("MFT.TRANSFER.STORED_CREDENTIAL",
                  account("moveit_vulnerable_exposed", "globex_sftp"))
    assert sev(hashed, "MFT.TRANSFER.STORED_CREDENTIAL") == ["low"]     # not plaintext-capable


def test_transfer_stored_credential_quiet_when_no_stored_secret():
    assert fire("MFT.TRANSFER.STORED_CREDENTIAL",
                account("moveit_vulnerable_exposed", "svc-batch")) == []


# ── coverage-gap anchor ───────────────────────────────────────────────────────
def test_server_not_assessable_on_unreachable_and_unfingerprinted():
    for name in ("unreachable", "unfingerprinted"):
        hits = fire("MFT.SERVER.NOT_ASSESSABLE", server(name))
        assert len(hits) == 1 and hits[0].assessable is False, name


def test_server_not_assessable_quiet_on_ok_target():
    assert fire("MFT.SERVER.NOT_ASSESSABLE", server("moveit_vulnerable_exposed")) == []


# ── NHI derivation ────────────────────────────────────────────────────────────
def _kinds(resources):
    out = {}
    for r in resources:
        out[r.kind] = out.get(r.kind, 0) + 1
    return out


def test_mft_extractor_is_registered():
    assert "mft" in IDENTITY_EXTRACTORS


def test_mft_accounts_become_identities_credentials_and_grants():
    col = derive_identities("mft", built("moveit_vulnerable_exposed"))
    k = _kinds(col.resources)
    assert k.get("identity") == 4       # anonymous + acme + globex + svc-batch
    assert k.get("credential") == 2     # acme (password) + globex (ssh_key); svc-batch has none
    assert k.get("grant") == 4          # one transfer grant per account
    # grants resolve to the endpoint each account transfers over (acme→as2, globex→sftp)
    assert sum(1 for e in col.edges if e.kind == "grants_access") == 2


def test_mft_partner_accounts_are_external_service_ones_internal():
    col = derive_identities("mft", built("moveit_vulnerable_exposed"))
    ids = {r.raw["principal"]: r for r in col.resources if r.kind == "identity"}
    assert ids["acme_edi"].raw["external"] is True
    assert ids["globex_sftp"].labels["identity_type"] == "partner_account"
    assert ids["svc-batch"].raw["external"] is False
    assert ids["svc-batch"].labels["identity_type"] == "transfer_account"


def test_mft_anonymous_account_grant_is_wildcard():
    col = derive_identities("mft", built("moveit_vulnerable_exposed"))
    anon = next(r for r in col.resources
                if r.kind == "identity" and r.raw["principal"] == "anonymous")
    grant = next(r for r in col.resources
                 if r.kind == "grant" and r.labels["identity"] == anon.ext_id)
    assert grant.raw["wildcard"] is True


def test_mft_stored_credential_is_metadata_only():
    col = derive_identities("mft", built("moveit_vulnerable_exposed"))
    cred = next(r for r in col.resources
                if r.kind == "credential" and r.raw["credential_type"] == "password")
    assert cred.raw["present"] is True and cred.raw["plaintext"] is True
    # never a secret value — only presence/type/shape metadata crosses the boundary
    assert "value" not in cred.raw and "secret" not in cred.raw
    assert any(e.kind == "credential_of" for e in col.edges)


def test_mft_extractor_noop_without_accounts():
    col = derive_identities("mft", Collected(resources=[
        Resource(kind="mft_server", name="s", ext_id="mft-server-x", raw={"product": "moveit"})]))
    assert _kinds(col.resources).get("identity") is None
