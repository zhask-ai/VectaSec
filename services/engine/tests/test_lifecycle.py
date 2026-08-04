"""Offline unit tests for the support-lifecycle pack (SUPPLY.LIFECYCLE.*) and its dataset.

Every test pins "today" through ctx.config['lifecycle_today']; nothing here calls date.today() on
an assertion path. That is not tidiness — a lifecycle rule whose verdict tracks the wall clock
cannot be regression-tested at all, and would hand an unchanged estate a new high finding
overnight with no code change to point at.

Boundary dates are derived from a dataset date with timedelta rather than written out, so the
horizon tests stay exact if a future contributor re-verifies that row.
"""
from datetime import date, timedelta

import pytest

import vectasec.detect.lifecycle as lc
from vectasec.contracts import Resource, ScanContext
from vectasec.lifecycle import (
    APPROACHING, END_OF_LIFE, SUPPORT_LIFECYCLE, SUPPORTED, UNKNOWN_BRANCH, UNKNOWN_PRODUCT,
    nearest_supported_branch, parse_version, support_status,
)

TODAY = date(2026, 8, 3)


# ── helpers ────────────────────────────────────────────────────────────────────
def _ctx(today=TODAY, **cfg):
    return ScanContext(connection_id="c", tenant_id="t", resources=[],
                       config={"lifecycle_today": today.isoformat(), **cfg})


def res(kind, raw=None, labels=None, name="thing") -> Resource:
    return Resource(kind=kind, name=name, ext_id=f"{kind}-1",
                    labels=labels or {}, raw=raw or {})


def only(hits):
    assert len(hits) == 1, f"expected exactly one hit, got {len(hits)}"
    return hits[0]


def all_rules(r, ctx):
    return lc.end_of_life(r, ctx), lc.approaching_eol(r, ctx), lc.not_assessable(r, ctx)


def eol_of(product: str, branch: str) -> date:
    row = next(b for b in SUPPORT_LIFECYCLE[product]["branches"] if b["branch"] == branch)
    return date.fromisoformat(row["eol"])


# ── END_OF_LIFE ────────────────────────────────────────────────────────────────
def test_end_of_life_fires_high_and_cites_its_source():
    h = only(lc.end_of_life(res("redis_server", {"redis_version": "7.0.15"}), _ctx()))
    assert h.assessable is True
    assert "7.0" in h.observation and "2024-07-29" in h.observation
    assert "days ago" in h.observation
    assert h.source_ref["source"].startswith("https://")
    assert h.source_ref["source"] in h.remediation          # the URL travels with the claim
    assert h.source_ref["eol"] == "2024-07-29"
    assert h.source_ref["days_past_eol"] > 700


def test_end_of_life_names_the_nearest_supported_branch():
    h = only(lc.end_of_life(res("redis_server", {"redis_version": "6.0.20"}), _ctx()))
    target = nearest_supported_branch("redis", TODAY)
    assert target and f"Redis {target} branch" in h.remediation
    assert h.source_ref["nearest_supported"] == target


def test_end_of_life_quotes_the_vendors_own_definition_of_the_date():
    """Kong's table has a later 'sunset' column that ships no patches. The finding carries the
    basis text so a reader can check our reading of the policy instead of trusting it."""
    h = only(lc.end_of_life(res("broker", {"version": "3.11.0.1"}), _ctx()))
    assert "developer.konghq.com" in h.source_ref["source"]
    assert "sunset" in h.remediation.lower()
    assert h.source_ref["verified_on"] == "2026-08-03"


def test_end_of_life_reads_rabbitmq_version_from_the_overview_document():
    """RabbitMQ buries the version a level below where sbom's reader looks; the cluster row is
    also the only node that carries it."""
    cluster = res("node", {"role": "cluster", "overview": {"rabbitmq_version": "3.13.7"}})
    h = only(lc.end_of_life(cluster, _ctx()))
    assert "3.13" in h.observation and "2024-09-17" in h.observation

    member = res("node", {"role": "node", "overview": {"rabbitmq_version": "3.13.7"}})
    assert all_rules(member, _ctx()) == ([], [], [])        # not the version carrier at all


def test_end_of_life_matches_a_whole_major_row_when_the_vendor_dates_majors():
    """Elastic dates the 7.x line as one unit; a 7.17.9 must find it via the major fallback."""
    h = only(lc.end_of_life(res("es_cluster", {"distribution": "elasticsearch",
                                               "version": "7.17.9"}), _ctx()))
    assert h.source_ref["branch"] == "7" and h.source_ref["eol"] == "2026-01-15"


def test_opensearch_and_elasticsearch_are_separate_products_on_one_kind():
    h = only(lc.end_of_life(res("es_cluster", {"distribution": "opensearch",
                                               "version": "1.3.20"}), _ctx()))
    assert h.source_ref["product"] == "opensearch" and h.source_ref["eol"] == "2025-05-06"


def test_pulsar_remote_cluster_is_not_the_version_carrier():
    local = res("pulsar_cluster", {"is_local": True, "broker_version": "2.10.4"})
    assert only(lc.end_of_life(local, _ctx())).source_ref["eol"] == "2023-04-18"
    remote = res("pulsar_cluster", {"is_local": False, "broker_version": None})
    assert all_rules(remote, _ctx()) == ([], [], [])


# ── APPROACHING_EOL — the horizon boundary ─────────────────────────────────────
def test_approaching_fires_exactly_at_the_horizon_boundary():
    eol = eol_of("redis", "8.0")
    r = res("redis_server", {"redis_version": "8.0.3"})
    h = only(lc.approaching_eol(r, _ctx(today=eol - timedelta(days=180))))
    assert h.source_ref["days_remaining"] == 180
    assert h.source_ref["horizon_days"] == 180
    assert str(eol) in h.observation


def test_approaching_is_silent_one_day_outside_the_horizon():
    eol = eol_of("redis", "8.0")
    r = res("redis_server", {"redis_version": "8.0.3"})
    assert all_rules(r, _ctx(today=eol - timedelta(days=181))) == ([], [], [])


def test_the_day_eol_arrives_it_is_end_of_life_not_approaching():
    eol = eol_of("redis", "8.0")
    r = res("redis_server", {"redis_version": "8.0.3"})
    ctx = _ctx(today=eol)
    assert lc.approaching_eol(r, ctx) == []
    assert only(lc.end_of_life(r, ctx)).source_ref["days_past_eol"] == 0


def test_horizon_is_configurable_per_scan():
    r = res("redis_server", {"redis_version": "8.2.1"})
    assert all_rules(r, _ctx()) == ([], [], [])             # 2030 EOL, far outside 180 days
    h = only(lc.approaching_eol(r, _ctx(lifecycle_horizon_days=3650)))
    assert h.source_ref["horizon_days"] == 3650


def test_a_nonsense_horizon_falls_back_to_the_default_rather_than_crashing():
    r = res("redis_server", {"redis_version": "8.0.3"})
    ctx = _ctx(today=eol_of("redis", "8.0") - timedelta(days=180),
               lifecycle_horizon_days="not-a-number")
    assert only(lc.approaching_eol(r, ctx)).source_ref["horizon_days"] == 180


# ── supported: the fourth outcome, silence ─────────────────────────────────────
def test_supported_branch_fires_nothing_at_all():
    for raw in ({"redis_version": "8.10.0"},      # no announced end date
                {"redis_version": "7.2.15"}):     # dated far beyond the horizon
        assert all_rules(res("redis_server", raw), _ctx()) == ([], [], [])


def test_every_product_still_has_a_branch_that_receives_patches():
    """A dataset whose every product read as EOL would be a dataset that had rotted, and the
    remediation text would have no upgrade target to name. Pulsar legitimately lands on
    APPROACHING here — its newest branch is dated within the horizon — which is why this asserts
    'still patched', not 'comfortably supported'."""
    for product in SUPPORT_LIFECYCLE:
        branch = nearest_supported_branch(product, TODAY)
        assert branch, f"{product} has no supported branch in the dataset"
        version = branch if "." in branch else f"{branch}.0"
        assert support_status(product, f"{version}.0", TODAY)["status"] in (SUPPORTED, APPROACHING)


# ── NOT_ASSESSABLE (a): no version could be read ───────────────────────────────
def test_not_assessable_when_no_version_can_be_read():
    """A Kafka broker genuinely does not report its version over AdminClient. Silence here would
    be indistinguishable from 'checked, supported'."""
    h = only(lc.not_assessable(res("broker"), _ctx()))
    assert h.assessable is False
    assert h.assessment_reason == "no version could be read for this Apache Kafka component"
    assert "exposes no version at all" in h.observation
    assert h.source_ref["reason"] == "no_version"


def test_not_assessable_when_the_version_string_has_no_number():
    h = only(lc.not_assessable(res("redis_server", {"redis_version": "unstable"}), _ctx()))
    assert h.assessable is False
    assert "no parseable version number" in h.observation
    assert h.source_ref["reason"] == "unparseable_version"


def test_no_version_never_produces_an_eol_claim():
    assert lc.end_of_life(res("broker"), _ctx()) == []
    assert lc.approaching_eol(res("broker"), _ctx()) == []


# ── NOT_ASSESSABLE (b): product or branch absent from the dataset ──────────────
def test_not_assessable_for_a_product_outside_the_curated_dataset():
    """NATS is deliberately absent: it is widely called EOL at 2.10/2.11 but no primary source
    publishes a date, and the dataset carries no undated assertions."""
    h = only(lc.not_assessable(res("nats_server", {"version": "2.10.7"}), _ctx()))
    assert h.assessable is False
    assert h.source_ref["reason"] == UNKNOWN_PRODUCT
    assert "nats" in h.assessment_reason and "not in the curated" in h.assessment_reason
    assert all_rules(res("nats_server", {"version": "2.10.7"}), _ctx())[:2] == ([], [])


def test_not_assessable_for_a_branch_the_dataset_never_dated():
    h = only(lc.not_assessable(res("redis_server", {"redis_version": "4.0.14"}), _ctx()))
    assert h.assessable is False
    assert h.source_ref["reason"] == UNKNOWN_BRANCH
    assert h.source_ref["branch"] == "4.0"
    assert "not evidence of support" in h.remediation


def test_an_absent_branch_is_never_reported_as_end_of_life():
    """The banned inference: old branches are the ones most likely to be missing, which makes
    'absent' feel like 'dead'. It is not a fact, so it is not asserted."""
    r = res("redis_server", {"redis_version": "4.0.14"})
    assert lc.end_of_life(r, _ctx()) == []
    assert lc.approaching_eol(r, _ctx()) == []


def test_artemis_is_not_folded_into_activemq_classic():
    """Artemis 2.x and ActiveMQ Classic 5.x/6.x are different products; matching a 2.x Artemis
    against the Classic rows would be a category error, so it lands in not-assessable."""
    h = only(lc.not_assessable(res("artemis_broker", {"broker_version": "2.31.2"},
                                   labels={"flavor": "artemis"}), _ctx()))
    assert h.source_ref["reason"] == UNKNOWN_PRODUCT
    assert h.source_ref["product"] == "activemq-artemis"


# ── NOT_ASSESSABLE (c): the version was inferred, not read ─────────────────────
def test_an_inferred_version_is_downgraded_to_not_assessable():
    """Documented judgement call: an inferred version comes from a capability matrix at 0.5
    confidence and does not identify a branch, which is the granularity this pack decides on. The
    lead is still reported — it just is not asserted."""
    probe = res("discovered_service", {"product": "rabbitmq", "version": "3.11.5",
                                       "version_inferred": True})
    assert lc.end_of_life(probe, _ctx()) == []
    h = only(lc.not_assessable(probe, _ctx()))
    assert h.assessable is False
    assert "INFERRED" in h.observation
    assert "2023-06-01" in h.observation                    # the lead is still stated
    assert h.source_ref["version_inferred"] is True
    assert h.source_ref["provisional_status"] == END_OF_LIFE
    assert "inferred" in h.assessment_reason


def test_an_inferred_version_does_not_certify_support_either():
    probe = res("discovered_service", {"product": "redis", "version": "8.10.0",
                                       "version_inferred": True})
    h = only(lc.not_assessable(probe, _ctx()))
    assert h.source_ref["provisional_status"] == SUPPORTED
    assert h.assessable is False


def test_a_read_version_from_the_same_probe_is_assessed_normally():
    probe = res("discovered_service", {"product": "redis", "version": "7.0.15",
                                       "version_inferred": False})
    assert only(lc.end_of_life(probe, _ctx())).source_ref["eol"] == "2024-07-29"
    assert lc.not_assessable(probe, _ctx()) == []


def test_an_unfingerprinted_probe_hit_is_not_a_lifecycle_question():
    assert all_rules(res("discovered_service", {"product": None, "version": None}),
                     _ctx()) == ([], [], [])


# ── exactly one voice per resource ─────────────────────────────────────────────
@pytest.mark.parametrize("kind,raw", [
    ("redis_server", {"redis_version": "7.0.15"}),          # end of life
    ("redis_server", {"redis_version": "4.0.14"}),          # unknown branch
    ("redis_server", {"redis_version": "unstable"}),        # unparseable
    ("broker", {}),                                         # no version
    ("nats_server", {"version": "2.10.7"}),                 # unknown product
    ("discovered_service", {"product": "redis", "version": "7.0.15",
                            "version_inferred": True}),     # inferred
])
def test_at_most_one_rule_speaks_for_a_resource(kind, raw):
    fired = [h for hits in all_rules(res(kind, raw), _ctx()) for h in hits]
    assert len(fired) == 1


# ── pure-function behaviour ────────────────────────────────────────────────────
def test_parse_version_tolerates_the_shapes_connectors_actually_report():
    assert parse_version("8.2.1-alpine") == (8, 2)
    assert parse_version("v3.13.7+build") == (3, 13)
    assert parse_version("0.11.0.3") == (0, 11)             # kafka's four-part old scheme
    assert parse_version("9") == (9, 0)
    assert parse_version("unstable") is None
    assert parse_version(None) is None


def test_support_status_takes_today_as_an_argument_not_from_the_clock():
    eol = eol_of("kong", "3.11")
    assert support_status("kong", "3.11.0", eol - timedelta(days=1))["status"] == APPROACHING
    assert support_status("kong", "3.11.0", eol)["status"] == END_OF_LIFE
    assert support_status("kong", "3.11.0", eol - timedelta(days=900))["status"] == SUPPORTED


def test_an_exact_minor_row_wins_over_the_whole_major_row():
    """Elasticsearch has both 9.x minors and a bare '7'. A 9.0 must not fall back to a major row."""
    s = support_status("elasticsearch", "9.0.8", TODAY)
    assert s["matched_branch"] == "9.0" and s["eol"] == date(2025, 10, 2)


# ── dataset integrity — the guard against an unsourced guess ───────────────────
def test_every_entry_has_a_source_url_and_a_parseable_date():
    for product, spec in SUPPORT_LIFECYCLE.items():
        assert spec["display"] and spec["basis"], f"{product} must say what its dates mean"
        date.fromisoformat(spec["verified_on"])
        assert spec["branches"], f"{product} has no branches"
        seen = set()
        for b in spec["branches"]:
            where = f"{product} {b.get('branch')!r}"
            assert str(b["source_url"]).startswith("https://"), f"{where} has no source URL"
            assert b["branch"] not in seen, f"{where} is listed twice"
            seen.add(b["branch"])
            # An int-parseable branch key is what makes major-vs-minor matching total; a typo
            # like "3.13.x" would silently match nothing and read as a clean pass.
            assert all(p.isdigit() for p in b["branch"].split("."))
            assert 1 <= len(b["branch"].split(".")) <= 2
            if b["eol"] is not None:
                date.fromisoformat(b["eol"])                 # raises on a hand-typed date


def test_an_undated_branch_is_never_the_stale_end_of_its_own_line():
    """eol=None is a positive claim ('the source lists this branch as current'), and the way a
    'no date on file' null sneaks in wearing that claim's clothes is as an OLD branch. So an
    undated branch may not be superseded by a dated one in the SAME line.

    Comparison is within a line, not across the whole product, because projects legitimately
    maintain parallel majors: ActiveMQ still ships 5.19 alongside 6.3 while 6.0/6.1 are dated and
    dead. Whole-major rows (Solr's '8', OpenSearch's '1') are one line among themselves, which is
    what would catch an undated Solr 4 sitting beneath a dated Solr 8.
    """
    for product, spec in SUPPORT_LIFECYCLE.items():
        keys = {tuple(int(p) for p in b["branch"].split(".")): b["eol"] for b in spec["branches"]}
        for k, eol in keys.items():
            if eol is not None:
                continue
            same_line = [o for o in keys
                         if len(o) == len(k) and (len(k) == 1 or o[0] == k[0])]
            newer_dated = [o for o in same_line if keys[o] is not None and o > k]
            assert not newer_dated, (
                f"{product} branch {k} is undated but {newer_dated} are newer in the same line "
                f"and dated — an undated OLD branch means 'no date on file', not 'supported'")


def test_products_are_middleware_keys_the_sbom_already_uses():
    from vectasec.sbom import BITNAMI_PURL, CPE_VENDOR_PRODUCT
    known = set(CPE_VENDOR_PRODUCT) | BITNAMI_PURL
    assert set(SUPPORT_LIFECYCLE) <= known, "a lifecycle product key the SBOM does not recognise"


# ── catalogue hygiene ──────────────────────────────────────────────────────────
def test_rule_ids_are_unique_and_namespaced():
    from vectasec.registry import DETECTORS
    pack = [d for d in DETECTORS if d.rule_id.startswith("SUPPLY.LIFECYCLE.")]
    ids = [d.rule_id for d in pack]
    assert sorted(ids) == ["SUPPLY.LIFECYCLE.APPROACHING_EOL",
                           "SUPPLY.LIFECYCLE.END_OF_LIFE",
                           "SUPPLY.LIFECYCLE.NOT_ASSESSABLE"]
    assert len(ids) == len(set(ids))
    severities = {d.rule_id: d.severity for d in pack}
    assert severities["SUPPLY.LIFECYCLE.END_OF_LIFE"] == "high"
    assert severities["SUPPLY.LIFECYCLE.APPROACHING_EOL"] == "medium"
    assert severities["SUPPLY.LIFECYCLE.NOT_ASSESSABLE"] == "info"
    # Every rule runs on the same carrier kinds, so no resource can be assessed by one rule and
    # invisible to another — which is how a not-assessable gap would go unrecorded.
    assert {d.kinds for d in pack} == {tuple(lc._LIFECYCLE_KINDS)}
