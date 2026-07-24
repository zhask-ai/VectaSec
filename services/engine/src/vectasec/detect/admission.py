"""Runtime admission / egress posture detectors — the "T1 buildable now" axis: admission-control
and egress-policy configuration read from the same read-only Kubernetes APIs the k8s connector
already speaks (connect/k8s.py). Rules run on the DISTINCT `k8s_networkpolicy`,
`k8s_admission_webhook`, `k8s_namespace` and `k8s_cluster` kinds, carry the K8S.* prefix so they
count under the k8s connector, and read real config evidence from `raw` (a NetworkPolicy's
resolved default-deny/allow-all semantics, a webhook's failurePolicy, a namespace's PodSecurity
enforce label) — never a name-based guess.

Where the collecting credential was FORBIDDEN a resource type, the cluster-scoped rules file a
not-assessable coverage gap rather than a silent pass; the per-namespace default-deny rule does
the same, since a 403 on NetworkPolicy leaves each namespace's egress posture genuinely unknown.
"""
from ..contracts import Hit
from ..registry import detector


def _cluster(ctx):
    for c in ctx.of_kind("k8s_cluster"):
        return c
    return None


def _outcome(ctx, key: str) -> str:
    c = _cluster(ctx)
    return (((c.raw or {}).get("outcomes") or {}).get(key, "absent")) if c else "absent"


# ── Egress / NetworkPolicy ────────────────────────────────────────────────────
@detector(kinds=["k8s_namespace"], rule_id="K8S.NETPOL.NO_DEFAULT_DENY", severity="medium",
          title="Namespace has no default-deny NetworkPolicy")
def netpol_no_default_deny(r, ctx) -> list:
    """A namespace with no default-deny NetworkPolicy leaves its pods reachable from, and free to
    dial out to, anything the CNI permits. Egress freedom is the load-bearing half: a compromised
    pod with open egress can exfiltrate data and reach the metadata service / internet. Fires per
    namespace so the gap is attributable; when NetworkPolicy listing was 403'd the posture is
    unknown, not clean, so the finding is not-assessable."""
    ns = (r.raw or {}).get("name") or r.name
    outcome = _outcome(ctx, "network_policies")
    if outcome == "forbidden":
        return [Hit(
            observation=(f"the scanning credential was denied (HTTP 403) listing "
                         f"networking.k8s.io/networkpolicies, so whether namespace '{ns}' has a "
                         f"default-deny NetworkPolicy could not be determined"),
            remediation=("Grant the scanner get/list on networking.k8s.io NetworkPolicy (the "
                         "built-in `view` ClusterRole covers it) and re-scan to assess the "
                         "namespace's egress/ingress posture."),
            detail=f"namespace={ns} outcome=forbidden resource=network_policies",
            assessable=False,
            assessment_reason="RBAC denied listing NetworkPolicy resources",
            source_ref={"api": "networking.k8s.io/NetworkPolicy", "namespace": ns,
                        "outcome": "forbidden"},
        )]
    if outcome != "ok":
        return []          # absent: the NetworkPolicy API was not read at all — no claim to make
    ingress_dd = egress_dd = False
    for np in ctx.of_kind("k8s_networkpolicy"):
        if (np.raw or {}).get("namespace") != ns:
            continue
        ingress_dd = ingress_dd or bool((np.raw or {}).get("default_deny_ingress"))
        egress_dd = egress_dd or bool((np.raw or {}).get("default_deny_egress"))
    if ingress_dd and egress_dd:
        return []
    open_dirs = [d for d, covered in (("ingress", ingress_dd), ("egress", egress_dd))
                 if not covered]
    fully_open = len(open_dirs) == 2
    c = _cluster(ctx)
    cni_engine = bool((c.raw or {}).get("egress_crd_present")) if c else False
    cni_note = (" — note: a CNI-level policy engine (e.g. Cilium/Calico CRDs) is installed, so "
                "some of this may be governed outside core NetworkPolicy and is not visible to "
                "this scan" if cni_engine else "")
    return [Hit(
        observation=(f"namespace '{ns}' has no default-deny NetworkPolicy for "
                     f"{' and '.join(open_dirs)} traffic (podSelector: {{}} with empty rules) — "
                     f"pods accept connections from, and initiate connections to, any peer the "
                     f"CNI allows{cni_note}"),
        remediation=("Apply a default-deny NetworkPolicy selecting every pod, then add explicit "
                     "allow policies per workload:\n"
                     "  apiVersion: networking.k8s.io/v1\n  kind: NetworkPolicy\n"
                     f"  metadata: {{name: default-deny, namespace: {ns}}}\n"
                     "  spec: {podSelector: {}, policyTypes: [Ingress, Egress]}\n"
                     "Locking egress in particular contains data exfiltration and stops a "
                     "compromised pod from calling out to the metadata service or the internet."),
        detail=f"namespace={ns} open_directions={open_dirs} cni_engine={cni_engine}",
        severity=None if fully_open else "low",
        source_ref={"api": "networking.k8s.io/NetworkPolicy", "namespace": ns,
                    "field": "spec.podSelector/policyTypes"},
    )]


@detector(kinds=["k8s_networkpolicy"], rule_id="K8S.NETPOL.ALLOW_ALL", severity="medium",
          title="NetworkPolicy selects all pods but allows all traffic")
def netpol_allow_all(r, ctx) -> list:
    """A no-selector NetworkPolicy (podSelector: {}) whose rule is empty ({} / no `from`/`to` /
    no ports) matches every peer — it provides zero isolation and, because NetworkPolicies are
    additive, it re-opens any direction a sibling default-deny closed for the same pods."""
    raw = r.raw or {}
    if not raw.get("selects_all_pods"):
        return []
    dirs = [d for d, on in (("ingress", raw.get("allow_all_ingress")),
                            ("egress", raw.get("allow_all_egress"))) if on]
    if not dirs:
        return []
    return [Hit(
        observation=(f"NetworkPolicy '{raw.get('namespace')}/{raw.get('name')}' selects all pods "
                     f"(empty podSelector) and carries an empty {'/'.join(dirs)} rule, which "
                     f"allows all {' and '.join(dirs)} traffic — it grants no isolation and "
                     f"additively overrides any default-deny on these pods"),
        remediation=("Remove the empty rule or replace it with explicit peers "
                     "(`from`/`to` naming namespaceSelector / podSelector / ipBlock, plus "
                     "`ports`). An empty rule matches every source and destination; a "
                     "NetworkPolicy is meant to narrow reachability, not widen it."),
        detail=(f"selects_all_pods=true allow_all={dirs} "
                f"policy_types={raw.get('policy_types')}"),
        source_ref={"api": "networking.k8s.io/NetworkPolicy", "name": raw.get("name"),
                    "namespace": raw.get("namespace"), "field": "spec.ingress/egress"},
    )]


# ── PodSecurity admission ──────────────────────────────────────────────────────
@detector(kinds=["k8s_namespace"], rule_id="K8S.PSA.NO_ENFORCE", severity="medium",
          title="Namespace does not enforce a restrictive Pod Security Standard")
def psa_no_enforce(r, ctx) -> list:
    """PodSecurity admission is label-driven per namespace. With no
    `pod-security.kubernetes.io/enforce` label (or one set to `privileged`), the admission
    controller admits pods that run privileged, share host namespaces, or mount hostPath — the
    building blocks of a container escape. `baseline`/`restricted` is a pass."""
    raw = r.raw or {}
    enforce = raw.get("pss_enforce")
    ns = raw.get("name") or r.name
    if enforce in ("baseline", "restricted"):
        return []
    if enforce == "privileged":
        state = "pod-security.kubernetes.io/enforce=privileged"
        why = ("its Pod Security Standard enforce level is explicitly 'privileged', which admits "
               "pods using host namespaces, privileged containers, hostPath volumes and added "
               "capabilities")
    else:
        state = "pod-security.kubernetes.io/enforce=(unset)"
        why = ("it carries no pod-security.kubernetes.io/enforce label, so the built-in "
               "PodSecurity admission controller enforces no standard on it and pods may run "
               "privileged, share host namespaces, or mount hostPath volumes")
    return [Hit(
        observation=f"namespace '{ns}': {why}",
        remediation=("Label the namespace with a restrictive standard:\n"
                     f"  kubectl label ns {ns} "
                     "pod-security.kubernetes.io/enforce=restricted "
                     "pod-security.kubernetes.io/enforce-version=latest\n"
                     "Use 'baseline' only where 'restricted' breaks a workload, and pin an "
                     "enforce-version so a future policy release doesn't silently change what is "
                     "admitted."),
        detail=f"namespace={ns} {state}",
        source_ref={"api": "v1/Namespace", "namespace": ns,
                    "field": "metadata.labels[pod-security.kubernetes.io/enforce]"},
    )]


# ── Admission webhooks ─────────────────────────────────────────────────────────
@detector(kinds=["k8s_admission_webhook"], rule_id="K8S.ADMISSION.WEBHOOK_FAIL_OPEN",
          severity="medium", title="Admission webhook fails open (failurePolicy=Ignore)")
def webhook_fail_open(r, ctx) -> list:
    """failurePolicy=Ignore means that when the webhook backend is unreachable, times out, or
    errors, the API server admits the request unchecked — the policy is bypassable by knocking the
    webhook over. A validating (enforcement) webhook that fails open grades high; a mutating one
    (defaulting/injection) grades medium."""
    raw = r.raw or {}
    wtype = raw.get("webhook_type")
    hits = []
    for w in raw.get("webhooks") or []:
        if (w.get("failure_policy") or "Fail") != "Ignore":
            continue
        hits.append(Hit(
            observation=(f"{wtype} webhook '{w.get('name')}' in configuration "
                         f"'{raw.get('name')}' sets failurePolicy=Ignore — if its backend is "
                         f"unreachable, slow, or erroring, the API server admits the request "
                         f"unchecked, so the policy this gate enforces can be bypassed by making "
                         f"the webhook unavailable"),
            remediation=("Set `failurePolicy: Fail` so the gate closes when the webhook is down, "
                         "run the backend highly-available, and scope it with a "
                         "`namespaceSelector`/`objectSelector` so a failing webhook does not wedge "
                         "unrelated namespaces. Fail-open turns any webhook outage into a silent "
                         "policy bypass."),
            detail=(f"config={raw.get('name')} webhook={w.get('name')} "
                    f"failurePolicy=Ignore type={wtype}"),
            severity="high" if wtype == "validating" else None,
            source_ref={"api": f"admissionregistration.k8s.io/{wtype}",
                        "name": raw.get("name"), "webhook": w.get("name"),
                        "field": "webhooks[].failurePolicy"},
        ))
    return hits


@detector(kinds=["k8s_cluster"], rule_id="K8S.ADMISSION.NO_VALIDATING_WEBHOOK", severity="low",
          title="Cluster has no validating admission webhook")
def no_validating_webhook(r, ctx) -> list:
    """No ValidatingWebhookConfiguration means no admission-time policy engine (Kyverno, OPA
    Gatekeeper, a custom validating webhook) is rejecting non-compliant resources as they are
    created — the cluster relies entirely on RBAC and the built-in PodSecurity standards. Absence
    of the whole mechanism IS the finding; a 403 on the listing is not-assessable, not a pass."""
    raw = r.raw or {}
    outcome = (raw.get("outcomes") or {}).get("validating_webhooks")
    if outcome == "forbidden":
        return [Hit(
            observation=("the scanning credential was denied (HTTP 403) listing "
                         "admissionregistration.k8s.io/validatingwebhookconfigurations, so "
                         "whether any admission-time policy gate exists could not be determined"),
            remediation=("Grant the scanner get/list on admissionregistration.k8s.io "
                         "ValidatingWebhookConfiguration (the built-in `view` ClusterRole covers "
                         "it) and re-scan."),
            detail="outcome=forbidden resource=validating_webhooks",
            assessable=False,
            assessment_reason="RBAC denied listing ValidatingWebhookConfiguration",
            source_ref={"api": "admissionregistration.k8s.io", "outcome": "forbidden"},
        )]
    if outcome != "ok":
        return []          # absent: the webhook API was not read at all — no claim to make
    if any((w.raw or {}).get("webhook_type") == "validating"
           for w in ctx.of_kind("k8s_admission_webhook")):
        return []
    return [Hit(
        observation=("the cluster has no ValidatingWebhookConfiguration — no admission-time policy "
                     "engine (e.g. Kyverno, OPA Gatekeeper, or a custom validating webhook) is "
                     "validating or rejecting resources as they are created"),
        remediation=("Deploy a policy admission controller (Kyverno or OPA Gatekeeper) with "
                     "validating webhooks, or author ValidatingAdmissionPolicy (CEL, built-in "
                     "1.30+) rules, to enforce guardrails — image provenance, disallowed "
                     "capabilities, required labels — at admission time. PodSecurity admission "
                     "covers only the built-in pod standards, not custom policy."),
        detail="validating_webhooks=0",
        source_ref={"api": "admissionregistration.k8s.io/ValidatingWebhookConfiguration",
                    "field": "(none present)"},
    )]
