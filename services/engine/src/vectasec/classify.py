"""Data classification — a deterministic derivation pass over collected resources.

WHAT THIS IS. A middleware security tool has to answer "what sensitive data flows through
this?", because the same misconfiguration is a different risk on a `payments` topic than on
`heartbeat`. This pass tags data-carrying resources (topics, queues, routes, services, MCP
tools, Redis keyspaces, NATS subjects…) with the data classes their NAME and LABELS suggest,
so downstream detectors can escalate on sensitivity and the console can show a data-flow view.

WHY NAME-BASED, AND WHY THAT IS HONEST. VectaSec reads configuration, not payloads — it never
consumes a message or samples a row, by design (read-only, credentials-stay-local). So it
cannot *prove* what data a topic carries; it can only observe what the operators NAMED it.
That is a real signal (teams name `customer-pii` deliberately) and a limited one (a benign
name can carry regulated data). So every classification is:
  • recorded as a SIGNAL, not a fact — the evidence says "name 'payments' matched the PCI
    signal 'payment'", never "this topic contains cardholder data";
  • surfaced as a HINT the console labels as inferred-from-naming;
  • never on its own a finding — it escalates the severity of a real exposure finding, and
    seeds a low/info inventory finding, but "named like PII" is not itself a vulnerability.

This mirrors the Hit.assessable discipline (contracts.py): state what was read, not a
conclusion the evidence cannot carry.

STORAGE. Results go into `resource.labels` (jsonb), no schema change:
  data_classes      csv of matched classes, worst-first  ("pci,pii")
  data_sensitivity  high | medium | low | none
  data_signals      csv of "class:matched-word" for evidence ("pci:payment,pii:customer")
Only data-carrying kinds are classified; brokers, nodes, and the derived identity/credential/
grant kinds are skipped (a credential literally named "secret" must not read as PII).
"""
import re
from typing import Optional

from .contracts import Collected, Resource

# The kinds that actually carry or route data. Everything else (broker, node, user,
# permission, plugin, identity, credential, grant, mcp_server) is infrastructure, not a
# data payload, and is left unclassified on purpose.
DATA_KINDS = frozenset({
    "topic", "queue", "stream", "exchange", "subject",      # brokers
    "route", "service",                                      # gateways
    "mcp_tool",                                              # agent tools
    "keyspace", "channel",                                   # redis / pubsub
})

# class -> (sensitivity, [signal words]). Ordered by regulatory weight: a resource that
# matches several is filed under the worst. Words are matched as whole tokens against a
# normalized name, so "card" hits "credit-card" and "card_txns" but not "dashboard".
_SIGNALS: list[tuple[str, str, tuple[str, ...]]] = [
    ("pci", "high", (
        "payment", "payments", "card", "cards", "cardholder", "pan", "creditcard",
        "debit", "transaction", "transactions", "txn", "txns", "billing", "invoice",
        "invoices", "payout", "payouts", "settlement", "acquirer", "merchant", "charge",
        "charges", "refund", "refunds", "stripe", "paypal",
    )),
    ("phi", "high", (
        "patient", "patients", "health", "medical", "diagnosis", "clinical", "prescription",
        "phi", "hl7", "fhir", "ehr", "emr", "claim", "claims", "insurance", "lab", "labs",
    )),
    ("secrets", "high", (
        "secret", "secrets", "credential", "credentials", "token", "tokens", "apikey",
        "apikeys", "password", "passwords", "vault", "privatekey", "keystore", "certificate",
        "certs",
    )),
    ("pii", "medium", (
        "customer", "customers", "user", "users", "person", "people", "email", "emails",
        "phone", "phones", "address", "addresses", "ssn", "sin", "passport", "dob",
        "birthdate", "profile", "profiles", "contact", "contacts", "subscriber",
        "subscribers", "member", "members", "employee", "employees", "account", "accounts",
        "identity", "kyc", "gdpr", "personal",
    )),
    ("financial", "medium", (
        "ledger", "balance", "balances", "finance", "financial", "journal", "gl", "accounting",
        "wallet", "wallets", "bank", "iban", "swift", "ach",
    )),
    ("auth", "medium", (
        "auth", "authentication", "session", "sessions", "login", "logins", "oauth", "jwt",
        "sso", "saml", "mfa", "otp",
    )),
]

_SENS_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}

# Split a resource name/namespace into lowercase word tokens. Middleware names are dotted,
# hyphenated, underscored, slashed, or camelCase: `payments.v2`, `customer-pii`, `svcAccounts`.
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokens(*parts: Optional[str]) -> set[str]:
    words: set[str] = set()
    for p in parts:
        if not p:
            continue
        spaced = _CAMEL.sub(" ", p)
        for tok in re.split(r"[^A-Za-z0-9]+", spaced):
            if tok:
                words.add(tok.lower())
    return words


def classify_name(*parts: Optional[str]) -> dict:
    """The pure core: classify from name parts. Returns {classes, sensitivity, signals}.

    Unit-tested directly. `signals` is a list of (class, matched-word) so the caller can
    write honest evidence. A token must match a signal word EXACTLY (whole token), so
    'dashboard' does not match 'card' and 'metrics' does not match 'ric'."""
    toks = _tokens(*parts)
    classes: list[str] = []
    signals: list[tuple[str, str]] = []
    sensitivity = "none"
    for cls, sens, words in _SIGNALS:
        hit = next((w for w in words if w in toks), None)
        if hit:
            classes.append(cls)
            signals.append((cls, hit))
            if _SENS_RANK[sens] > _SENS_RANK[sensitivity]:
                sensitivity = sens
    return {"classes": classes, "sensitivity": sensitivity, "signals": signals}


def classify_resource(r: Resource) -> Optional[dict]:
    """Classify one resource if it is a data-carrying kind. Returns the classification dict
    or None. Considers the name, namespace, and any label VALUES (a topic labelled
    `dataset=cardholder` is a signal even when its name is opaque)."""
    if r.kind not in DATA_KINDS:
        return None
    label_values = [str(v) for v in (r.labels or {}).values()]
    result = classify_name(r.name, r.namespace, *label_values)
    return result if result["classes"] else None


def classify_resources(collected: Collected) -> Collected:
    """Tag every data-carrying resource in place with data_classes / data_sensitivity /
    data_signals labels. Returns the same Collected (mutated) for call-site chaining.

    Idempotent: re-running overwrites the same three labels with the same values, so a
    re-scan never accumulates or drifts."""
    for r in collected.resources:
        c = classify_resource(r)
        if not c:
            continue
        if r.labels is None:
            r.labels = {}
        r.labels["data_classes"] = ",".join(c["classes"])
        r.labels["data_sensitivity"] = c["sensitivity"]
        r.labels["data_signals"] = ",".join(f"{cls}:{word}" for cls, word in c["signals"])
    return collected
