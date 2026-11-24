"""The Integration-Layer Benchmark (benchmark.py). Pinned: it is generated from the registry
(every control is a real rule, none appears twice), numbering is deterministic, and the
scorecard never counts 'not assessed' or 'not scanned' as a pass."""
from vectasec import benchmark
from vectasec import detect as _detect  # noqa: F401
from vectasec.registry import DETECTORS


def test_catalogue_is_generated_from_real_rules():
    cat = benchmark.catalogue()
    rule_ids = {d.rule_id for d in DETECTORS}
    assert {"kafka", "rabbitmq", "redis", "nats", "kong"} <= set(cat)
    for bench in cat.values():
        ids = [c["rule_id"] for s in bench["sections"] for c in s["controls"]]
        assert ids and set(ids) <= rule_ids and len(ids) == len(set(ids)) == bench["control_count"]
        numbers = [c["number"] for s in bench["sections"] for c in s["controls"]]
        assert len(numbers) == len(set(numbers))
    assert benchmark.catalogue() == cat, "deterministic"
    kafka_ids = {c["rule_id"] for s in cat["kafka"]["sections"] for c in s["controls"]}
    assert all(i.startswith("KAFKA.") for i in kafka_ids)
    assert any(c["remediation"] for s in cat["kafka"]["sections"] for c in s["controls"])


def test_scorecard_never_counts_gaps_or_unscanned_as_pass():
    cat = benchmark.catalogue()
    redis_ids = [c["rule_id"] for s in cat["redis"]["sections"] for c in s["controls"]]
    findings = [{"rule_id": redis_ids[0], "status": "open", "assessment": "assessed"},
                {"rule_id": redis_ids[1], "status": "open", "assessment": "not_assessable"},
                {"rule_id": redis_ids[2], "status": "resolved", "assessment": "assessed"}]
    card = benchmark.scorecard(cat, ["redis"], findings)
    by = {s["key"]: s for s in card["systems"]}
    r = by["redis"]
    assert r["scanned"] and r["counts"]["fail"] == 1 and r["counts"]["not_assessed"] == 1
    assert r["counts"]["pass"] == len(redis_ids) - 2
    assert r["results"][redis_ids[2]]["result"] == "pass", "a resolved finding is a pass"
    assert r["score"] == round(100 * r["counts"]["pass"] / (r["counts"]["pass"] + 1))
    k = by["kafka"]
    assert not k["scanned"] and k["counts"]["pass"] == 0 and k["score"] is None
    assert k["counts"]["not_scanned"] == k["controls"]
    assert card["systems"][0]["scanned"], "scanned systems first"


def test_markdown_blank_and_filled():
    cat = benchmark.catalogue()
    blank = benchmark.to_markdown(cat["redis"])
    assert "kinds" not in blank
    assert "not a CIS document" in blank and "FAIL" not in blank and "## 1." in blank
    card = benchmark.scorecard(cat, ["redis"], [{"rule_id": "REDIS.AUTH.NO_PASSWORD", "status": "open", "assessment": "assessed"}])
    filled = benchmark.to_markdown(cat["redis"], next(s for s in card["systems"] if s["key"] == "redis"), generated_at="2026-11-23T00:00:00")
    assert "— FAIL" in filled and "Not assessed is never a pass" in filled


def test_a_control_with_nothing_to_run_against_is_not_a_pass():
    cat = benchmark.catalogue()
    controls = [c for s in cat["kafka"]["sections"] for c in s["controls"]]
    card = benchmark.scorecard(cat, ["kafka"], [], kinds_seen={"kafka": {"topic"}})
    k = next(s for s in card["systems"] if s["key"] == "kafka")
    topic_controls = [c for c in controls if "topic" in c["kinds"]]
    assert k["counts"]["pass"] == len(topic_controls) < len(controls)
    assert k["counts"]["not_assessed"] == len(controls) - len(topic_controls)
    empty = benchmark.scorecard(cat, ["kafka"], [], kinds_seen={})
    k = next(s for s in empty["systems"] if s["key"] == "kafka")
    assert k["counts"]["pass"] == 0 and k["score"] is None, "a scan that returned nothing proves nothing"
