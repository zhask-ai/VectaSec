"""Kafka Connect rulepack — read-only Connect REST posture.

Runs on the DISTINCT kafka_connect_cluster / kafka_connect_connector kinds (rule prefix
KAFKA_CONNECT.*, which never collides with the KAFKA.* broker pack). The headline check is the
unauthenticated REST endpoint — the classic hole that turns "reachable" into "arbitrary connector
creation → RCE" (CVE-2023-25194 via a JndiLoginModule sasl.jaas.config). Secondary checks read
connector configs for inline plaintext secrets and per-connector JAAS overrides — always by KEY
PRESENCE, never the value.
"""
from ..contracts import Hit
from ..registry import detector


@detector(kinds=["kafka_connect_cluster"], rule_id="KAFKA_CONNECT.REST.UNAUTHENTICATED",
          severity="critical",
          title="Kafka Connect REST API is reachable without authentication (connector-creation RCE)")
def rest_unauthenticated(resource, ctx):
    raw = resource.raw or {}
    if not raw.get("connectors_readable"):
        return [Hit(
            observation=(f"kafka connect at {raw.get('base_url')}: /connectors was not readable, "
                         f"so whether the REST API is unauthenticated could not be determined."),
            remediation=("Grant the scan access to /connectors, or confirm the REST API requires "
                         "authentication directly."),
            detail="Coverage gap: /connectors returned an error (auth required or unreachable).",
            assessable=False,
            assessment_reason="/connectors unreadable; unauthenticated exposure undetermined",
            source_ref={"endpoint": "/connectors"},
        )]
    if not raw.get("anonymous_readable"):
        return []
    return [Hit(
        observation=(
            f"kafka connect REST API at {raw.get('base_url')} (version {raw.get('version')!r}) "
            f"served /connectors to a client sending NO credentials. The Connect REST API has no "
            f"read-only mode: anyone who can reach it can also POST a connector config. Since "
            f"Kafka 2.3.0 a connector config may set an arbitrary client sasl.jaas.config, and the "
            f"JndiLoginModule path (CVE-2023-25194) turns that into remote code execution on the "
            f"Connect worker. An unauthenticated Connect REST endpoint is effectively "
            f"unauthenticated RCE."),
        remediation=(
            "Put the Connect REST API behind authentication and authorization: enable a REST "
            "extension (BasicAuthSecurityRestExtension or an OAuth/mTLS extension) via "
            "rest.extension.classes, or front it with an authenticating proxy, and restrict the "
            "port (default 8083) to trusted operators. Separately, run Kafka Connect 3.4.0+ where "
            "org.apache.kafka.disallowed.login.modules disables JndiLoginModule by default, and "
            "keep connector.client.config.override.policy restrictive."),
        detail=(
            "Read exposure is proven (an anonymous GET succeeded); the write/RCE path follows "
            "because the REST API is write-capable by design. The scan does not POST, so it does "
            "not itself create a connector — the RCE is the documented consequence of the open "
            "endpoint, not something this scan executed."),
        source_ref={"probe": "anonymous /connectors", "cve": "CVE-2023-25194"},
    )]


@detector(kinds=["kafka_connect_cluster"], rule_id="KAFKA_CONNECT.TLS.DISABLED", severity="medium",
          title="Kafka Connect REST API is served over plaintext HTTP")
def tls_disabled(resource, ctx):
    raw = resource.raw or {}
    if raw.get("over_tls"):
        return []
    return [Hit(
        observation=(
            f"kafka connect REST API at {raw.get('base_url')} is reached over plaintext HTTP, so "
            f"connector configs (which routinely carry database and cloud credentials) and any "
            f"Basic-auth header sent to the REST API cross the network unencrypted."),
        remediation=(
            "Configure the REST API for HTTPS (listeners=https://…, listeners.https.ssl.* "
            "keystore settings) and disable the plaintext listener. If a proxy terminates TLS, "
            "scan the HTTPS endpoint."),
        detail="Determined from the URL scheme; a TLS-terminating proxy is a possible exception.",
        source_ref={"scheme": "http"},
    )]


@detector(kinds=["kafka_connect_connector"], rule_id="KAFKA_CONNECT.CONNECTOR.PLAINTEXT_SECRET",
          severity="medium",
          title="Connector config stores a secret inline instead of via a ConfigProvider")
def connector_plaintext_secret(resource, ctx):
    raw = resource.raw or {}
    if raw.get("config_readable") is False:
        return [Hit(
            observation=(f"kafka connect connector {raw.get('connector_name')!r}: its config was "
                         f"not readable, so inline-secret storage could not be assessed."),
            remediation="Grant the scan read access to /connectors/{name} to assess secret storage.",
            detail="Coverage gap: connector config unreadable.",
            assessable=False,
            assessment_reason="connector config unreadable",
            source_ref={"connector": raw.get("connector_name")},
        )]
    inline = raw.get("inline_secret_keys") or []
    if not inline:
        return []
    return [Hit(
        observation=(
            f"kafka connect connector {raw.get('connector_name')!r} "
            f"(class {raw.get('connector_class')!r}) sets {len(inline)} secret-bearing config "
            f"key(s) as inline literals rather than externalized references: {', '.join(inline)}. "
            f"The values are stored in the Connect config topic and returned in plaintext by "
            f"GET /connectors/{raw.get('connector_name')} to anyone who can read the REST API. "
            f"(This scan records the key names only and never stores the values.)"),
        remediation=(
            "Externalize these values with a ConfigProvider — e.g. "
            "${file:/opt/secrets/creds.properties:db_password} via FileConfigProvider, or a "
            "Vault/AWS Secrets Manager provider — configured through config.providers on the "
            "worker. Rotate any secret that was stored inline, since it was retrievable via the "
            "REST API and persisted in the config topic."),
        detail=(
            "A value that is an externalized ${provider:...} reference is NOT flagged — only "
            "inline literals are. Whether the config topic and REST API are themselves access-"
            "controlled changes the exposure but not the recommendation to externalize secrets."),
        source_ref={"connector": raw.get("connector_name"), "inline_secret_keys": inline},
    )]


@detector(kinds=["kafka_connect_connector"], rule_id="KAFKA_CONNECT.CONNECTOR.JAAS_OVERRIDE",
          severity="high",
          title="Connector config uses a client sasl.jaas.config override (CVE-2023-25194 surface)")
def connector_jaas_override(resource, ctx):
    raw = resource.raw or {}
    keys = raw.get("jaas_override_keys") or []
    if not keys:
        return []
    return [Hit(
        observation=(
            f"kafka connect connector {raw.get('connector_name')!r} sets a client JAAS override "
            f"config key: {', '.join(keys)}. A per-connector sasl.jaas.config can name "
            f"com.sun.security.auth.module.JndiLoginModule to make the worker connect to an "
            f"attacker-controlled LDAP server and deserialize a gadget chain (CVE-2023-25194) — "
            f"remote code execution on the Connect worker. (Key presence only is recorded; the "
            f"JAAS value, which is a secret, is never stored or inspected for content.)"),
        remediation=(
            "Run Kafka Connect 3.4.0 or later, where JndiLoginModule (and other risky login "
            "modules) is disabled by default via org.apache.kafka.disallowed.login.modules — do "
            "not re-enable it. Restrict who can create/modify connectors "
            "(connector.client.config.override.policy=None or Principal, plus REST-API "
            "authentication), and review why this connector needs a JAAS override at all."),
        detail=(
            "The override key being present is the attack surface; whether it actually names "
            "JndiLoginModule cannot be confirmed read-only because the value is a secret. On a "
            "3.4.0+ worker with the default disallowed-login-modules list the RCE is blocked, so "
            "this is worker-version dependent — confirm the version and the override policy."),
        source_ref={"connector": raw.get("connector_name"), "jaas_override_keys": keys,
                    "cve": "CVE-2023-25194"},
    )]


@detector(kinds=["kafka_connect_cluster"], rule_id="KAFKA_CONNECT.PLUGINS.NOT_READABLE",
          severity="info",
          title="Installed connector-plugin inventory could not be read")
def plugins_not_readable(resource, ctx):
    """/connector-plugins is the RUNTIME plugin inventory — a build SBOM cannot enumerate what
    plugin.path holds, and every installed plugin is loadable code on the worker. An unreadable
    inventory must file a gap: silence here is byte-identical to 'no plugins installed'.

    `plugins_readable` is three-valued on purpose: None marks a resource collected before this
    inventory existed (unknown, not a refusal), and only an explicit False is the gap."""
    raw = resource.raw or {}
    if raw.get("plugins_readable") is not False:
        return []
    return [Hit(
        observation=(f"kafka connect at {raw.get('base_url')}: /connector-plugins was not "
                     f"readable, so the set of installed connector plugins — each of which is "
                     f"loadable code on the worker — could not be inventoried."),
        remediation=("Grant the scan read access to /connector-plugins so the installed-plugin "
                     "inventory (and its versions) can feed the estate SBOM."),
        detail=("Coverage gap: the plugin inventory endpoint returned an error. No claim is "
                "made about what is installed."),
        assessable=False,
        assessment_reason="/connector-plugins unreadable; installed-plugin set undetermined",
        source_ref={"endpoint": "/connector-plugins"},
    )]
