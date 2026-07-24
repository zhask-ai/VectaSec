"""Offline golden-fixture tests for the runtime admission/egress posture axis — the
NetworkPolicy (default-deny / allow-all), PodSecurity-enforce, and admission-webhook
(failurePolicy / presence) signals the k8s connector now collects.

Fixtures are plain-dict snapshots mirroring the JSON-wire shapes the K8s API returns
(NetworkPolicy spec, Validating/MutatingWebhookConfiguration, namespace labels — camelCase,
exactly as the client hands them back). They flow through connect/k8s._build_resources — the
same pure normalisation the live collect uses — with the kubernetes client entirely out of the
tests. Every detector gets a fires-on-bad AND a silent-on-good pair; forbidden collection gets
its own not-assessable case.
"""
from vectasec.connect.k8s import (_ADMISSION_KEYS, _build_resources, _CORE_KEYS, _GWAPI_KEYS,
                                  _ISTIO_KEYS, _LINKERD_KEYS)
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.admission  # noqa: F401  — registers the admission/egress detectors
import vectasec.detect.k8s        # noqa: F401  — for K8S.COLLECT.FORBIDDEN interplay

_ALL_KEYS = (*_CORE_KEYS, *_ISTIO_KEYS, *_LINKERD_KEYS, *_GWAPI_KEYS, *_ADMISSION_KEYS)


# ── snapshot builders ─────────────────────────────────────────────────────────
def S(**sections) -> dict:
    """A snapshot with every section absent unless given. A list value means outcome ok."""
    snap = {k: {"outcome": "absent", "items": [], "error": None} for k in _ALL_KEYS}
    snap["version"] = "v1.30.2"
    for k, v in sections.items():
        assert k in _ALL_KEYS, k
        snap[k] = {"outcome": "ok", "items": v, "error": None} if isinstance(v, list) else v
    return snap


def m(name, ns=None, labels=None, annotations=None) -> dict:
    md = {"name": name}
    if ns:
        md["namespace"] = ns
    if labels:
        md["labels"] = labels
    if annotations:
        md["annotations"] = annotations
    return md


def forbidden() -> dict:
    return {"outcome": "forbidden", "items": [], "error": "HTTP 403"}


def default_deny(ns, name="default-deny", types=("Ingress", "Egress")) -> dict:
    """podSelector {} with no rules for the listed directions → default-deny."""
    return {"metadata": m(name, ns), "spec": {"podSelector": {}, "policyTypes": list(types)}}


def allow_all_np(ns, name="open", types=("Ingress", "Egress")) -> dict:
    spec = {"podSelector": {}, "policyTypes": list(types)}
    if "Ingress" in types:
        spec["ingress"] = [{}]
    if "Egress" in types:
        spec["egress"] = [{}]
    return {"metadata": m(name, ns), "spec": spec}


def restricted_np(ns, name="api-allow") -> dict:
    return {"metadata": m(name, ns),
            "spec": {"podSelector": {"matchLabels": {"app": "api"}},
                     "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}],
                                  "ports": [{"port": 8080}]}]}}


def build(snapshot):
    return _build_resources(snapshot)


def hits_for(rule_id, resources):
    d = next(x for x in DETECTORS if x.rule_id == rule_id)
    ctx = ScanContext(connection_id="c", tenant_id="t", resources=resources, config={})
    out = []
    for r in resources:
        if r.kind in d.kinds:
            out.extend(d.fn(r, ctx) or [])
    return out


def rule(rule_id):
    return next(x for x in DETECTORS if x.rule_id == rule_id)


# ── connector normalisation ───────────────────────────────────────────────────
def test_new_kinds_are_distinct_and_prefixed():
    snap = S(namespaces=[{"metadata": m("prod")}],
             network_policies=[default_deny("prod"), allow_all_np("prod", "open")],
             validating_webhooks=[{"metadata": m("kyverno"),
                                   "webhooks": [{"name": "validate.kyverno.svc"}]}],
             mutating_webhooks=[{"metadata": m("inject"),
                                 "webhooks": [{"name": "mutate.istio"}]}])
    kinds = {r.kind for r in build(snap).resources}
    assert "k8s_networkpolicy" in kinds and "k8s_admission_webhook" in kinds
    for r in build(snap).resources:
        assert r.kind.startswith(("k8s_", "mesh_")), r.kind


def test_netpol_semantics_are_reduced_correctly():
    snap = S(network_policies=[default_deny("prod", "dd"),
                               allow_all_np("prod", "open"),
                               restricted_np("prod", "api")])
    by_name = {r.raw["name"]: r.raw for r in build(snap).resources
               if r.kind == "k8s_networkpolicy"}
    assert by_name["dd"]["default_deny_ingress"] and by_name["dd"]["default_deny_egress"]
    assert not by_name["dd"]["allow_all_ingress"]
    assert by_name["open"]["allow_all_ingress"] and by_name["open"]["allow_all_egress"]
    assert not by_name["open"]["default_deny_ingress"]
    # restricted: selects specific pods, concrete peer + ports → neither deny-all nor allow-all
    assert by_name["api"]["selects_all_pods"] is False
    assert by_name["api"]["ingress_effect"] == "restricted"


def test_webhook_default_failure_policy_is_fail():
    snap = S(validating_webhooks=[{"metadata": m("gk"),
                                   "webhooks": [{"name": "v.gatekeeper.sh"}]}])
    wh = next(r for r in build(snap).resources if r.kind == "k8s_admission_webhook")
    assert wh.raw["webhooks"][0]["failure_policy"] == "Fail"   # v1 default when unset
    assert wh.labels["fail_open"] == "false"


def test_cluster_admission_and_egress_presence_flags():
    snap = S(validating_webhooks=[{"metadata": m("kyverno"), "webhooks": []}],
             cilium_clusterwide_network_policies=[{"metadata": m("egress-lock")}])
    c = next(r for r in build(snap).resources if r.kind == "k8s_cluster")
    assert c.raw["admission_present"] and c.raw["egress_crd_present"]
    # forbidden still proves the API group exists → present
    snap = S()
    snap["validating_webhooks"] = forbidden()
    c = next(r for r in build(snap).resources if r.kind == "k8s_cluster")
    assert c.raw["admission_present"] and not c.raw["egress_crd_present"]


def test_pss_enforce_rides_on_namespace():
    snap = S(namespaces=[{"metadata": m("hardened", labels={
        "pod-security.kubernetes.io/enforce": "restricted"})}])
    ns = next(r for r in build(snap).resources if r.kind == "k8s_namespace")
    assert ns.raw["pss_enforce"] == "restricted"
    assert ns.labels["pss_enforce"] == "restricted"


# ── K8S.NETPOL.NO_DEFAULT_DENY ─────────────────────────────────────────────────
def test_no_default_deny_fires_and_protected_is_silent():
    snap = S(namespaces=[{"metadata": m("open-ns")}, {"metadata": m("locked-ns")}],
             network_policies=[default_deny("locked-ns")])
    hits = hits_for("K8S.NETPOL.NO_DEFAULT_DENY", build(snap).resources)
    assert len(hits) == 1
    assert "open-ns" in hits[0].observation
    assert hits[0].severity is None                # fully open → rule default (medium)


def test_no_default_deny_partial_coverage_is_low():
    # ingress default-deny present, egress still open → downgraded, egress named
    snap = S(namespaces=[{"metadata": m("half")}],
             network_policies=[default_deny("half", "dd-ingress", types=("Ingress",))])
    hits = hits_for("K8S.NETPOL.NO_DEFAULT_DENY", build(snap).resources)
    assert len(hits) == 1 and hits[0].severity == "low"
    assert "egress" in hits[0].observation and "ingress" not in hits[0].detail.split("open_directions=")[1]


def test_no_default_deny_notes_cni_engine_when_present():
    snap = S(namespaces=[{"metadata": m("prod")}],
             network_policies=[],
             cilium_clusterwide_network_policies=[{"metadata": m("egress-lock")}])
    hits = hits_for("K8S.NETPOL.NO_DEFAULT_DENY", build(snap).resources)
    assert len(hits) == 1 and "CNI-level policy engine" in hits[0].observation


def test_no_default_deny_absent_collection_is_silent():
    # network_policies never read (absent) → no claim, defers entirely
    snap = S(namespaces=[{"metadata": m("prod")}])
    assert hits_for("K8S.NETPOL.NO_DEFAULT_DENY", build(snap).resources) == []


def test_no_default_deny_forbidden_is_not_assessable():
    snap = S(namespaces=[{"metadata": m("prod")}])
    snap["network_policies"] = forbidden()
    hits = hits_for("K8S.NETPOL.NO_DEFAULT_DENY", build(snap).resources)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "403" in hits[0].observation and "prod" in hits[0].observation


# ── K8S.NETPOL.ALLOW_ALL ───────────────────────────────────────────────────────
def test_allow_all_fires_both_directions():
    snap = S(namespaces=[{"metadata": m("prod")}], network_policies=[allow_all_np("prod")])
    hits = hits_for("K8S.NETPOL.ALLOW_ALL", build(snap).resources)
    assert len(hits) == 1
    assert "allows all ingress and egress" in hits[0].observation


def test_allow_all_ingress_only():
    snap = S(network_policies=[allow_all_np("prod", "open-in", types=("Ingress",))])
    hits = hits_for("K8S.NETPOL.ALLOW_ALL", build(snap).resources)
    assert len(hits) == 1 and "allows all ingress" in hits[0].observation
    assert "egress" not in hits[0].observation


def test_allow_all_silent_on_default_deny_and_restricted():
    snap = S(network_policies=[default_deny("prod", "dd"), restricted_np("prod", "api")])
    assert hits_for("K8S.NETPOL.ALLOW_ALL", build(snap).resources) == []


def test_allow_all_silent_when_selector_is_scoped():
    # an empty rule but a real podSelector = allow-all to SPECIFIC pods, not the no-selector case
    snap = S(network_policies=[{"metadata": m("scoped", "prod"),
                                "spec": {"podSelector": {"matchLabels": {"app": "x"}},
                                         "policyTypes": ["Ingress"], "ingress": [{}]}}])
    assert hits_for("K8S.NETPOL.ALLOW_ALL", build(snap).resources) == []


# ── K8S.PSA.NO_ENFORCE ─────────────────────────────────────────────────────────
def test_psa_fires_on_unset_and_privileged_silent_on_restrictive():
    snap = S(namespaces=[
        {"metadata": m("unset")},
        {"metadata": m("priv", labels={"pod-security.kubernetes.io/enforce": "privileged"})},
        {"metadata": m("base", labels={"pod-security.kubernetes.io/enforce": "baseline"})},
        {"metadata": m("restr", labels={"pod-security.kubernetes.io/enforce": "restricted"})},
    ])
    hits = hits_for("K8S.PSA.NO_ENFORCE", build(snap).resources)
    fired = {h.source_ref["namespace"] for h in hits}
    assert fired == {"unset", "priv"}
    by_ns = {h.source_ref["namespace"]: h for h in hits}
    assert "unset" in by_ns["unset"].detail and "enforce=(unset)" in by_ns["unset"].detail
    assert "privileged" in by_ns["priv"].observation


# ── K8S.ADMISSION.WEBHOOK_FAIL_OPEN ────────────────────────────────────────────
def test_webhook_fail_open_validating_is_high_mutating_is_medium():
    snap = S(
        validating_webhooks=[
            {"metadata": m("policy"),
             "webhooks": [{"name": "enforce.v", "failurePolicy": "Ignore"},
                          {"name": "strict.v", "failurePolicy": "Fail"}]}],
        mutating_webhooks=[
            {"metadata": m("inject"),
             "webhooks": [{"name": "sidecar.m", "failurePolicy": "Ignore"}]}])
    hits = hits_for("K8S.ADMISSION.WEBHOOK_FAIL_OPEN", build(snap).resources)
    assert len(hits) == 2                                   # the two Ignore hooks, not the Fail one
    by_hook = {h.source_ref["webhook"]: h for h in hits}
    assert by_hook["enforce.v"].severity == "high"         # validating gate
    assert by_hook["sidecar.m"].severity is None           # mutating → rule default (medium)
    assert "strict.v" not in by_hook


def test_webhook_fail_open_silent_when_all_fail_closed():
    snap = S(validating_webhooks=[{"metadata": m("gk"),
                                   "webhooks": [{"name": "v", "failurePolicy": "Fail"},
                                                {"name": "w"}]}])  # w: unset → Fail
    assert hits_for("K8S.ADMISSION.WEBHOOK_FAIL_OPEN", build(snap).resources) == []


# ── K8S.ADMISSION.NO_VALIDATING_WEBHOOK ────────────────────────────────────────
def test_no_validating_webhook_fires_when_none_present():
    snap = S(validating_webhooks=[],                        # read ok, but zero
             mutating_webhooks=[{"metadata": m("inject"), "webhooks": []}])
    hits = hits_for("K8S.ADMISSION.NO_VALIDATING_WEBHOOK", build(snap).resources)
    assert len(hits) == 1 and "no ValidatingWebhookConfiguration" in hits[0].observation


def test_no_validating_webhook_silent_when_present():
    snap = S(validating_webhooks=[{"metadata": m("kyverno"),
                                   "webhooks": [{"name": "v", "failurePolicy": "Fail"}]}])
    assert hits_for("K8S.ADMISSION.NO_VALIDATING_WEBHOOK", build(snap).resources) == []


def test_no_validating_webhook_absent_is_silent():
    # never read the webhook API at all (absent) → no claim
    assert hits_for("K8S.ADMISSION.NO_VALIDATING_WEBHOOK", build(S()).resources) == []


def test_no_validating_webhook_forbidden_is_not_assessable():
    snap = S()
    snap["validating_webhooks"] = forbidden()
    hits = hits_for("K8S.ADMISSION.NO_VALIDATING_WEBHOOK", build(snap).resources)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "403" in hits[0].observation


# ── every rule carries remediation + observation ───────────────────────────────
def test_every_fired_admission_hit_has_remediation_and_observation():
    snap = S(
        namespaces=[{"metadata": m("open-ns")},
                    {"metadata": m("priv",
                                   labels={"pod-security.kubernetes.io/enforce": "privileged"})}],
        network_policies=[allow_all_np("open-ns")],
        validating_webhooks=[],
        mutating_webhooks=[{"metadata": m("inject"),
                            "webhooks": [{"name": "m", "failurePolicy": "Ignore"}]}])
    resources = build(snap).resources
    ctx = ScanContext(connection_id="c", tenant_id="t", resources=resources, config={})
    fired = 0
    for d in DETECTORS:
        if d.rule_id not in ("K8S.NETPOL.NO_DEFAULT_DENY", "K8S.NETPOL.ALLOW_ALL",
                             "K8S.PSA.NO_ENFORCE", "K8S.ADMISSION.WEBHOOK_FAIL_OPEN",
                             "K8S.ADMISSION.NO_VALIDATING_WEBHOOK"):
            continue
        for r in resources:
            if r.kind not in d.kinds:
                continue
            for h in (d.fn(r, ctx) or []):
                assert h.observation.strip(), d.rule_id
                assert h.remediation.strip(), d.rule_id
                fired += 1
    assert fired >= 5           # all five rules exercised in one snapshot
