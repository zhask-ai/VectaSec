"""Data-classification derivation — the pure name-based classifier and the resource pass."""
from vectasec.classify import classify_name, classify_resource, classify_resources, DATA_KINDS
from vectasec.contracts import Collected, Resource


def test_pci_signal():
    c = classify_name("payments")
    assert "pci" in c["classes"] and c["sensitivity"] == "high"


def test_pii_signal_medium():
    c = classify_name("customer-pii")
    assert c["classes"] == ["pii"] and c["sensitivity"] == "medium"


def test_worst_severity_wins_when_multiple():
    c = classify_name("customer-payments")   # pii (medium) + pci (high)
    assert set(c["classes"]) >= {"pci", "pii"} and c["sensitivity"] == "high"


def test_whole_token_match_no_false_positive():
    # 'card' must not match inside 'dashboard'; 'auth' must not match 'author'
    assert classify_name("dashboard")["classes"] == []
    assert classify_name("authorship")["classes"] == []


def test_camel_and_delimiters_tokenize():
    assert "pci" in classify_name("cardTransactions")["classes"]
    assert "pii" in classify_name("svc.customer.v2")["classes"]


def test_signals_recorded_for_evidence():
    c = classify_name("payments")
    assert ("pci", "payments") in c["signals"]


def test_classify_resource_only_data_kinds():
    topic = Resource(kind="topic", name="payments", ext_id="t1")
    broker = Resource(kind="broker", name="payments-broker", ext_id="b1")
    cred = Resource(kind="credential", name="secret", ext_id="c1")
    assert classify_resource(topic) is not None
    # a broker or a credential named like data must NOT be classified — they are not payloads
    assert classify_resource(broker) is None
    assert classify_resource(cred) is None


def test_classify_resources_writes_labels_idempotently():
    r = Resource(kind="topic", name="payments", ext_id="t1")
    col = Collected(resources=[r])
    classify_resources(col)
    assert r.labels["data_classes"] == "pci"
    assert r.labels["data_sensitivity"] == "high"
    assert "pci:payments" in r.labels["data_signals"]
    # re-run: same values, no accumulation
    classify_resources(col)
    assert r.labels["data_classes"] == "pci"


def test_all_data_kinds_are_frozenset_members():
    assert "topic" in DATA_KINDS and "route" in DATA_KINDS and "mcp_tool" in DATA_KINDS
