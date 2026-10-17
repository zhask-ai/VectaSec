"""The auditor access register (report.to_access_register_*): pure, deterministic, and honest
about last-used. Pinned here:

  • rows are ordered (system, identity) regardless of input order, and identical inputs give
    byte-identical CSV/Markdown
  • unknown (no source) vs never (a source read empty) vs dated are three distinct renderings
  • the controls column lists SOC2 CC6.1-3 and ISO A.5.16-18 always, PCI 8.6.x only in CDE scope
  • the CSV header is stable
  • the Markdown header names the systems with no last-used source and says unknown ≠ unused
"""
import csv
import io

from vectasec.report import (
    ACCESS_REGISTER_CONTROLS,
    ACCESS_REGISTER_CSV_COLUMNS,
    access_register_coverage,
    to_access_register_csv,
    to_access_register_markdown,
    to_access_register_rows,
)

GEN_AT = "2026-10-17T12:00:00+00:00"


def ident(system, name, **labels):
    return {"id": f"id-{system}-{name}", "ext_id": f"identity:{system}:{name}", "name": name,
            "labels": {"identity_type": "service_account", "system": system, "external": "false",
                       **labels}, "raw": {}}


def cred(system, owner_ext, ctype, **labels):
    return {"id": f"c-{owner_ext}-{ctype}", "ext_id": f"cred:{system}:{owner_ext}:{ctype}",
            "name": f"{owner_ext}:{ctype}",
            "labels": {"credential_type": ctype, "system": system, "owner": owner_ext, **labels},
            "raw": {}}


def grant(system, identity_ext, target, wildcard=False, n=0):
    return {"id": f"g-{identity_ext}-{n}", "ext_id": f"grant:{system}:{identity_ext}:{n}",
            "name": f"read → {target}",
            "labels": {"system": system, "action": "read", "identity": identity_ext,
                       "wildcard": "true" if wildcard else "false"},
            "raw": {"target": target}}


def fixture():
    identities = [
        ident("kong", "billing-svc"),                                   # no last-used source
        ident("aws", "deploy-key-user", last_used_at="never", last_used_source="access_key",
              owner_label="team-platform"),
        ident("aws", "etl-role", last_used_at="2026-10-10T00:00:00+00:00",
              last_used_source="role_last_used", automation="true"),
        ident("rabbitmq", "orders-worker"),                             # runtime evidence dated
    ]
    credentials = [
        cred("kong", "identity:kong:billing-svc", "key-auth"),
        cred("aws", "identity:aws:deploy-key-user", "access_key", last_used_at="never"),
    ]
    grants = [
        grant("aws", "identity:aws:etl-role", "arn:aws:sqs:payments", wildcard=True, n=1),
        grant("aws", "identity:aws:etl-role", "arn:aws:sqs:logs", n=2),
        grant("rabbitmq", "identity:rabbitmq:orders-worker", "vhost:/", n=3),
    ] + [grant("aws", "identity:aws:etl-role", f"arn:aws:sns:topic-{i}", n=10 + i) for i in range(6)]
    findings = [
        {"rule_id": "CREDENTIAL.LIFECYCLE.NEVER_USED", "status": "open",
         "resource_ext_id": "cred:aws:identity:aws:deploy-key-user:access_key"},
        {"rule_id": "NHI.GRANT.WILDCARD", "status": "open",
         "resource_ext_id": "grant:aws:identity:aws:etl-role:1"},
        {"rule_id": "CREDENTIAL.LIFECYCLE.ROTATION_STALE", "status": "resolved",   # closed: not a verdict
         "resource_ext_id": "cred:aws:identity:aws:deploy-key-user:access_key"},
        {"rule_id": "KAFKA.TOPIC.PUBLIC", "status": "open",                        # not an NHI rule
         "resource_ext_id": "identity:aws:etl-role"},
    ]
    runtime = {"orders-worker": {"last_seen": "2026-10-16T08:00:00+00:00",
                                 "source": "runtime_evidence:rabbitmq-management-api"}}
    return identities, credentials, grants, findings, runtime


def rows(**over):
    identities, credentials, grants, findings, runtime = fixture()
    kw = dict(runtime_last_seen=runtime, generated_at=GEN_AT, findings=findings,
              target_sensitivity={"arn:aws:sqs:payments": "high", "arn:aws:sqs:logs": "low"})
    kw.update(over)
    return to_access_register_rows(identities, credentials, grants, **kw)


def by_name(rs):
    return {r["identity"]: r for r in rs}


# ── ordering and determinism ───────────────────────────────────────────────
def test_rows_are_ordered_by_system_then_identity_regardless_of_input_order():
    identities, credentials, grants, findings, runtime = fixture()
    a = to_access_register_rows(identities, credentials, grants, runtime_last_seen=runtime,
                                generated_at=GEN_AT, findings=findings)
    b = to_access_register_rows(list(reversed(identities)), list(reversed(credentials)),
                                list(reversed(grants)), runtime_last_seen=runtime,
                                generated_at=GEN_AT, findings=list(reversed(findings)))
    assert a == b
    assert [(r["system"], r["identity"]) for r in a] == [
        ("aws", "deploy-key-user"), ("aws", "etl-role"), ("kong", "billing-svc"),
        ("rabbitmq", "orders-worker")]
    assert to_access_register_csv(a) == to_access_register_csv(b)
    cov = access_register_coverage(a)
    md1 = to_access_register_markdown(a, tenant_name="Acme", generated_at=GEN_AT, coverage=cov)
    md2 = to_access_register_markdown(b, tenant_name="Acme", generated_at=GEN_AT, coverage=cov)
    assert md1 == md2


# ── last-used: three distinct answers ──────────────────────────────────────
def test_unknown_never_and_dated_last_used_are_distinct():
    r = by_name(rows())
    assert (r["billing-svc"]["last_used_at"], r["billing-svc"]["last_used_source"]) == ("unknown", "unknown")
    assert r["billing-svc"]["days_idle"] == ""
    assert (r["deploy-key-user"]["last_used_at"], r["deploy-key-user"]["last_used_source"]) == ("never", "access_key")
    assert r["deploy-key-user"]["days_idle"] == ""
    assert r["etl-role"]["last_used_at"] == "2026-10-10T00:00:00+00:00"
    assert r["etl-role"]["last_used_source"] == "role_last_used"
    assert r["etl-role"]["days_idle"] == "7"
    # runtime evidence supplies a dated value for a system whose connector records none
    assert r["orders-worker"]["last_used_at"] == "2026-10-16T08:00:00+00:00"
    assert r["orders-worker"]["last_used_source"].startswith("runtime_evidence")
    assert r["orders-worker"]["days_idle"] == "1"


def test_dated_runtime_evidence_beats_a_connector_never():
    identities, credentials, grants, findings, _ = fixture()
    out = by_name(to_access_register_rows(
        identities, credentials, grants, generated_at=GEN_AT,
        runtime_last_seen={"deploy-key-user": "2026-10-01T00:00:00+00:00"}))
    assert out["deploy-key-user"]["last_used_at"] == "2026-10-01T00:00:00+00:00"
    assert out["deploy-key-user"]["last_used_source"] == "runtime_evidence"


def test_csv_renders_the_three_last_used_states_differently():
    text = to_access_register_csv(rows())
    parsed = list(csv.DictReader(io.StringIO(text)))
    cells = {p["identity"]: p["last_used_at"] for p in parsed}
    assert cells["billing-svc"] == "unknown"
    assert cells["deploy-key-user"] == "never"
    assert cells["etl-role"].startswith("2026-10-10")
    assert len({cells["billing-svc"], cells["deploy-key-user"], cells["etl-role"]}) == 3


# ── absent labels are unknown, not false ───────────────────────────────────
def test_absent_automation_and_owner_labels_read_as_unknown_or_blank():
    r = by_name(rows())
    assert r["billing-svc"]["automation"] == "unknown"
    assert r["etl-role"]["automation"] == "true"
    assert r["billing-svc"]["external"] == "false"
    assert r["billing-svc"]["owner"] == ""
    assert r["deploy-key-user"]["owner"] == "team-platform"


# ── grants, targets, sensitivity, verdicts ─────────────────────────────────
def test_grants_targets_sensitivity_and_verdicts():
    r = by_name(rows())
    etl = r["etl-role"]
    assert etl["grants"] == 8 and etl["wildcard_grants"] == 1
    assert len(etl["targets"]) == 5 and etl["targets_more"] == 3
    assert etl["highest_sensitivity"] == "high"
    assert etl["verdicts"] == ["NHI.GRANT.WILDCARD"]           # the KAFKA rule is not an NHI verdict
    dk = r["deploy-key-user"]
    assert dk["credentials"] == 1 and dk["credential_types"] == ["access_key"]
    assert dk["verdicts"] == ["CREDENTIAL.LIFECYCLE.NEVER_USED"]   # the resolved one is gone
    assert r["billing-svc"]["highest_sensitivity"] == "unknown"
    assert "+3" in to_access_register_csv([etl])


# ── controls column ────────────────────────────────────────────────────────
def test_controls_column_without_cde_declaration_lists_soc2_and_iso_only():
    r = by_name(rows())
    for row in r.values():
        assert row["controls"] == [
            "SOC2_TSC_2017:CC6.1", "SOC2_TSC_2017:CC6.2", "SOC2_TSC_2017:CC6.3",
            "ISO_27001_2022:A.5.16", "ISO_27001_2022:A.5.17", "ISO_27001_2022:A.5.18"]
        assert row["pci_scope"] == "not_declared"


def test_pci_controls_appear_only_for_systems_declared_in_cde_scope():
    r = by_name(rows(cde_systems={"aws"}))
    assert "PCI_DSS_4_0_1:8.6.3" in r["etl-role"]["controls"]
    assert "PCI_DSS_4_0_1:8.6.1" in r["etl-role"]["controls"]
    assert r["etl-role"]["pci_scope"] == "in_cde"
    assert not any(c.startswith("PCI") for c in r["billing-svc"]["controls"])
    assert r["billing-svc"]["pci_scope"] == "out_of_scope"


def test_control_catalogue_is_a_paraphrase_and_names_the_expected_ids():
    ids = {(c["framework"], c["control_id"]) for c in ACCESS_REGISTER_CONTROLS}
    assert ids == {("SOC2_TSC_2017", "CC6.1"), ("SOC2_TSC_2017", "CC6.2"), ("SOC2_TSC_2017", "CC6.3"),
                   ("ISO_27001_2022", "A.5.16"), ("ISO_27001_2022", "A.5.17"), ("ISO_27001_2022", "A.5.18"),
                   ("PCI_DSS_4_0_1", "8.6.1"), ("PCI_DSS_4_0_1", "8.6.2"), ("PCI_DSS_4_0_1", "8.6.3")}
    assert all(c["cde_only"] == (c["framework"] == "PCI_DSS_4_0_1") for c in ACCESS_REGISTER_CONTROLS)
    for c in ACCESS_REGISTER_CONTROLS:
        assert '"' not in c["evidence"]


# ── CSV ────────────────────────────────────────────────────────────────────
def test_csv_header_is_stable():
    assert ACCESS_REGISTER_CSV_COLUMNS == (
        "system", "identity", "identity_type", "owner", "external", "automation", "credentials",
        "credential_types", "last_used_at", "last_used_source", "days_idle", "grants",
        "wildcard_grants", "targets", "highest_sensitivity", "verdicts", "controls", "pci_scope")
    text = to_access_register_csv(rows())
    assert text.splitlines()[0] == ",".join(ACCESS_REGISTER_CSV_COLUMNS)
    assert "\r" not in text
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert len(parsed) == 4
    assert parsed[0]["controls"].startswith("SOC2_TSC_2017:CC6.1; ")


def test_csv_escapes_commas_in_names():
    identities = [ident("kong", 'svc, "quoted"')]
    text = to_access_register_csv(to_access_register_rows(identities, [], [], generated_at=GEN_AT))
    parsed = list(csv.reader(io.StringIO(text)))
    assert parsed[1][1] == 'svc, "quoted"'


# ── Markdown header ────────────────────────────────────────────────────────
def test_markdown_header_names_systems_without_last_used_and_says_unknown_is_not_unused():
    rs = rows()
    cov = access_register_coverage(rs, last_used_capable={"aws", "rabbitmq"})
    assert cov["systems"] == ["aws", "kong", "rabbitmq"]
    assert cov["systems_without_last_used"] == ["kong"]
    assert cov["rows"] == 4
    md = to_access_register_markdown(rs, tenant_name="Acme", generated_at=GEN_AT, coverage=cov)
    assert md.startswith("# Access register — Acme")
    assert "**No last-used source:** kong" in md
    assert "Unknown is not unused" in md
    assert "`never` means a source positively read an empty last-used value" in md
    # the controls table and the PCI caveat are in the document, and every row is present
    assert "| SOC2_TSC_2017 | CC6.1 |" in md and "| PCI_DSS_4_0_1 | 8.6.3 |" in md
    assert "interactive-login" in md
    for name in ("billing-svc", "deploy-key-user", "etl-role", "orders-worker"):
        assert f"| {name} |" in md
    assert "Truncated" not in md


def test_markdown_states_truncation_when_the_export_was_cut():
    rs = rows()
    cov = access_register_coverage(rs, truncated=True, limit=5000)
    md = to_access_register_markdown(rs, tenant_name="Acme", generated_at=GEN_AT, coverage=cov)
    assert "**Truncated:** this export stops at 5000 rows" in md


def test_capable_system_with_all_unknown_rows_is_not_listed_as_sourceless():
    """A system whose connector CAN read last-used but recorded nothing readable this run is a
    different statement from 'no source exists' — only the latter goes in the header."""
    rs = to_access_register_rows([ident("aws", "u1")], [], [], generated_at=GEN_AT)
    assert access_register_coverage(rs, last_used_capable={"aws"})["systems_without_last_used"] == []
    assert access_register_coverage(rs)["systems_without_last_used"] == ["aws"]


def test_empty_register_renders():
    md = to_access_register_markdown([], tenant_name="Acme", generated_at=GEN_AT,
                                     coverage=access_register_coverage([]))
    assert "no identities derived yet" in md
    assert to_access_register_csv([]).splitlines() == [",".join(ACCESS_REGISTER_CSV_COLUMNS)]
