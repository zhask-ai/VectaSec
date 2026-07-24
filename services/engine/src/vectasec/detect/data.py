"""Data-security detectors — the DSPM layer.

Two rules, both reading the data-classification labels that classify.py wrote:

  DATA.SENSITIVE.INVENTORY   a data-carrying resource named like regulated data (PCI/PHI/secrets)
                             — the sensitive-data inventory, surfaced as a low finding, never a
                             vulnerability on its own.
  DATA.EXPOSURE.SENSITIVE_PLAINTEXT   the toxic combination the research calls the differentiator:
                             sensitive data ON a broker that is unencrypted or unauthenticated.
                             This is what a flat scanner misses — the topic and the broker are each
                             only medium alone, but a `payments` topic on a PLAINTEXT no-authorizer
                             broker is a critical data-exposure path, and only a cross-resource rule
                             sees it.

Both are grounded: the observation quotes the naming signal that triggered the classification and
(for exposure) the exact broker config facts, never a conclusion the evidence can't carry. A
classification is a HINT inferred from naming (VectaSec reads config, not payloads), so the
inventory finding is deliberately low and says "named like", not "contains".
"""
from ..contracts import Hit
from ..registry import detector

_HIGH = {"pci", "phi", "secrets"}


def _classes(r) -> list:
    raw = (r.labels or {}).get("data_classes") or ""
    return [c for c in raw.split(",") if c]


def _signals(r) -> str:
    return (r.labels or {}).get("data_signals") or ""


# ── The sensitive-data inventory ──────────────────────────────────────────────
@detector(kinds=["topic", "queue", "stream", "exchange", "subject", "route", "service",
                 "mcp_tool", "keyspace", "channel"],
          rule_id="DATA.SENSITIVE.INVENTORY", severity="low",
          title="Resource is named like regulated or sensitive data")
def sensitive_inventory(r, ctx) -> list:
    """Surface data-carrying resources whose NAME matches a high-sensitivity signal (PCI/PHI/
    secrets). Low severity and worded as an inference — this is the data-flow map a security team
    needs ("where does regulated data move"), not an assertion about payloads we never read."""
    classes = _classes(r)
    high = [c for c in classes if c in _HIGH]
    if not high:
        return []
    sens = (r.labels or {}).get("data_sensitivity", "?")
    return [Hit(
        observation=(f"{r.kind} '{r.name}' is named like {', '.join(high)} data "
                     f"(matched {_signals(r)})"),
        remediation=("Confirm what data this actually carries and, if regulated, verify it is "
                     "encrypted in transit and at rest, access-controlled to least privilege, "
                     "and in scope for the relevant compliance program."),
        detail=f"data_classes={','.join(classes)} sensitivity={sens} signals={_signals(r)}",
        source_ref={"classification": "name-inferred", "classes": classes, "kind": r.kind},
    )]


# ── The toxic combination: sensitive data on an exposed broker ────────────────
def _cfg_value(cfg: dict, key: str):
    e = (cfg or {}).get(key)
    return e.get("value") if isinstance(e, dict) else e


def _kafka_exposure(ctx) -> dict:
    """Read the connection's Kafka brokers for the two exposure facts that turn a sensitive
    topic into a critical exposure: a plaintext client listener, and no authorizer. Returns
    {plaintext, no_authorizer, broker, evidence} or {} when no broker is exposed.

    Reads the same readable config the Kafka pack does (these keys are NOT among the ones the
    broker redacts), parsing `listener.security.protocol.map` directly rather than importing the
    Kafka detector's private listener machinery — this rule needs only the coarse "is any client
    listener PLAINTEXT" fact, not per-listener resolution."""
    for b in ctx.of_kind("broker"):
        cfg = (b.raw or {}).get("config") or {}
        authz = _cfg_value(cfg, "authorizer.class.name")
        no_authorizer = not (authz and str(authz).strip())

        controllers = {n.strip().lower() for n in
                       str(_cfg_value(cfg, "controller.listener.names") or "").split(",") if n.strip()}
        pmap = str(_cfg_value(cfg, "listener.security.protocol.map") or "")
        plaintext = False
        evidence_listener = ""
        for pair in pmap.split(","):
            if ":" not in pair:
                continue
            name, proto = pair.split(":", 1)
            if proto.strip().upper() == "PLAINTEXT" and name.strip().lower() not in controllers:
                plaintext = True
                evidence_listener = name.strip()
                break

        if plaintext or no_authorizer:
            ev = []
            if plaintext:
                ev.append(f"listener {evidence_listener} maps to PLAINTEXT")
            if no_authorizer:
                ev.append("authorizer.class.name is not set (no ACL enforcement)")
            return {"plaintext": plaintext, "no_authorizer": no_authorizer,
                    "broker": b.name, "evidence": "; ".join(ev)}
    return {}


@detector(kinds=["topic"], rule_id="DATA.EXPOSURE.SENSITIVE_PLAINTEXT", severity="high",
          title="Sensitive data carried on an unencrypted or unauthenticated broker")
def sensitive_plaintext_exposure(r, ctx) -> list:
    """The cross-resource money rule. Fires when THIS topic is classified sensitive AND the broker
    hosting it is plaintext and/or has no authorizer. Critical when regulated data (PCI/PHI/
    secrets) rides a listener that is BOTH unencrypted AND unauthenticated — cleartext on the wire
    with no access control is the worst case. The observation cites the naming signal and the exact
    broker config, so the AI triage and the auditor both see grounded evidence, not a verdict."""
    classes = _classes(r)
    if not classes:
        return []
    exposure = _kafka_exposure(ctx)
    if not exposure:
        return []

    high = [c for c in classes if c in _HIGH]
    worst = "critical" if (high and exposure["plaintext"] and exposure["no_authorizer"]) else "high"
    return [Hit(
        severity=worst,
        observation=(f"topic '{r.name}' is named like {', '.join(classes)} data "
                     f"(matched {_signals(r)}); its broker {exposure['broker']} is exposed: "
                     f"{exposure['evidence']}"),
        remediation=("Put this topic behind an encrypted (SSL/SASL_SSL) listener and enable an "
                     "authorizer with least-privilege ACLs. Sensitive data on a plaintext, "
                     "unauthenticated broker is readable by anyone who can reach the port."),
        detail=(f"data_classes={','.join(classes)} · plaintext={exposure['plaintext']} · "
                f"no_authorizer={exposure['no_authorizer']}"),
        source_ref={"toxic_combination": True, "classes": classes,
                    "broker": exposure["broker"]},
    )]
