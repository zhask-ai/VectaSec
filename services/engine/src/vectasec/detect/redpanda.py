"""Redpanda rulepack — read-only Admin API posture.

Redpanda's security switches live in cluster_config, not the Kafka protocol, so these rules run
on the DISTINCT `redpanda_cluster` kind. Redpanda ships permissive: SASL off, authorization off,
Admin API open. Every check is about what was NOT turned on, cited from what the Admin API
returned. When the config could not be read at all (Admin API required auth we did not have),
the rules answer not-assessable rather than inventing a clean pass.
"""
from ..contracts import Hit
from ..registry import detector


def _not_assessable(raw, rule_key, what):
    return [Hit(
        observation=(f"redpanda cluster {raw.get('base_url')}: /v1/cluster_config was not "
                     f"readable, so {what} could not be determined."),
        remediation=("Grant the scan a superuser (or an Admin API account) so cluster_config can "
                     "be read, or confirm the setting directly with `rpk cluster config get`."),
        detail="Coverage gap: the Admin API required authentication that was not supplied.",
        assessable=False,
        assessment_reason="/v1/cluster_config unreadable (Admin API auth required)",
        source_ref={"config": rule_key},
    )]


@detector(kinds=["redpanda_cluster"], rule_id="REDPANDA.AUTH.SASL_DISABLED", severity="critical",
          title="Redpanda SASL authentication is disabled — the Kafka API is unauthenticated")
def sasl_disabled(resource, ctx):
    raw = resource.raw or {}
    if not raw.get("config_readable"):
        return _not_assessable(raw, "enable_sasl", "whether SASL authentication is enabled")
    if raw.get("enable_sasl") is not False:
        return []
    return [Hit(
        observation=("redpanda cluster_config enable_sasl=false, so the Kafka API accepts "
                     "connections with no authentication — any client that can reach the broker "
                     "port has full produce/consume/admin access."),
        remediation=("Set enable_sasl=true (rpk cluster config set enable_sasl true), create "
                     "SASL/SCRAM users, and provision ACLs before enabling it so clients are not "
                     "locked out. Unauthenticated Redpanda is data and admin access to anyone who "
                     "can open the socket."),
        detail="enable_sasl=false",
        source_ref={"config": "enable_sasl"},
    )]


@detector(kinds=["redpanda_cluster"], rule_id="REDPANDA.AUTHZ.DISABLED", severity="high",
          title="Redpanda Kafka authorization (ACLs) is not enforced")
def authz_disabled(resource, ctx):
    raw = resource.raw or {}
    if not raw.get("config_readable"):
        return _not_assessable(raw, "kafka_enable_authorization",
                               "whether Kafka authorization is enforced")
    kea = raw.get("kafka_enable_authorization")
    sasl = raw.get("enable_sasl")
    # kafka_enable_authorization defaults to null: authorization is then governed by enable_sasl.
    # So authorization is OFF when it is explicitly false, OR when it is null AND SASL is off.
    enforced = kea is True or (kea is None and sasl is True)
    if enforced:
        return []
    reason = ("kafka_enable_authorization=false" if kea is False else
              "kafka_enable_authorization is unset (null) and enable_sasl is not enabled, so "
              "authorization is not in effect")
    return [Hit(
        observation=(f"redpanda cluster_config: {reason}. No ACLs are enforced on the Kafka API, "
                     f"so any principal that connects can read, write and administer every topic."),
        remediation=("Set kafka_enable_authorization=true (or enable_sasl=true, which enables "
                     "authorization when kafka_enable_authorization is null), define superusers, "
                     "and create ACLs for each client before enforcing. "),
        detail=f"kafka_enable_authorization={kea} enable_sasl={sasl}",
        source_ref={"config": "kafka_enable_authorization"},
    )]


@detector(kinds=["redpanda_cluster"], rule_id="REDPANDA.ADMIN_API.NO_AUTH", severity="high",
          title="Redpanda Admin API does not require authentication")
def admin_api_no_auth(resource, ctx):
    raw = resource.raw or {}
    require_auth = raw.get("admin_api_require_auth")
    anon = raw.get("anonymous_readable")
    # The strongest evidence is that we read cluster_config with no credentials. Fall back to the
    # config flag when we authenticated.
    if not (anon or require_auth is False):
        if not raw.get("config_readable"):
            return _not_assessable(raw, "admin_api_require_auth",
                                   "whether the Admin API requires authentication")
        return []
    return [Hit(
        observation=(
            f"redpanda Admin API at {raw.get('base_url')}: "
            + ("cluster_config was read with NO credentials, proving the Admin API is "
               "unauthenticated. " if anon else "admin_api_require_auth=false. ")
            + "The Admin API can list and create SASL users, read and change every cluster config "
              "value, and manage the cluster — all without authentication here."),
        remediation=("Set admin_api_require_auth=true and configure Admin API authentication "
                     "(basic auth backed by SASL/SCRAM superusers), and restrict the Admin API "
                     "port (default 9644) to trusted operators. An open Admin API is full cluster "
                     "control, including user creation, to anyone who can reach it."),
        detail=(f"admin_api_require_auth={require_auth} anonymous_readable={anon}"),
        severity="critical" if anon else "high",
        source_ref={"config": "admin_api_require_auth", "anonymous": bool(anon)},
    )]


@detector(kinds=["redpanda_cluster"], rule_id="REDPANDA.TLS.KAFKA_API_DISABLED", severity="medium",
          title="Redpanda Kafka API has no TLS listener")
def kafka_api_tls_disabled(resource, ctx):
    raw = resource.raw or {}
    tls = raw.get("kafka_api_tls_enabled")
    if tls is None:
        return [Hit(
            observation=(f"redpanda node {raw.get('base_url')}: the Kafka API TLS configuration "
                         f"(kafka_api_tls in node_config) was not readable, so whether the Kafka "
                         f"API offers TLS could not be determined."),
            remediation=("Confirm the Kafka API listener has a TLS endpoint configured, and grant "
                         "the scan Admin API access so node_config can be read."),
            detail="Coverage gap: node_config / kafka_api_tls unreadable.",
            assessable=False,
            assessment_reason="node_config kafka_api_tls not readable",
            source_ref={"config": "kafka_api_tls"},
        )]
    if tls:
        return []
    return [Hit(
        observation=("redpanda node_config shows the Kafka API listener has no TLS enabled, so "
                     "client traffic — including SASL/SCRAM credential exchange — crosses the "
                     "network in plaintext."),
        remediation=("Configure a TLS endpoint on the Kafka API listener (kafka_api_tls with a "
                     "server certificate) and require TLS from clients. Without it the SCRAM "
                     "handshake and all data are sniffable."),
        detail="kafka_api_tls_enabled=false",
        source_ref={"config": "kafka_api_tls"},
    )]
