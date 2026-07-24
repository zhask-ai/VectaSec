"""ActiveMQ detectors — Classic and Artemis.

Two of these are load-bearing. The OpenWire RCE (CVE-2023-46604) is a CISA-KEV, actively
ransomware-exploited flaw whose only evidence is the broker version — and it is a *Classic*
flaw, so it runs on `activemq_broker` and deliberately never on `artemis_broker`. The rest are
config-evidence rules read from supplied broker configuration; when the relevant config was not
supplied to the connector they return an honest "not assessed" rather than a silent pass.
"""
from ..contracts import Hit
from ..registry import detector
from ..connect.activemq import openwire_rce_vulnerable

# Fixed release per 5.x series, for the remediation string (mirrors the connector's advisory map).
_OPENWIRE_FIX_TEXT = "5.15.16 / 5.16.7 / 5.17.6 / 5.18.3 (or 6.0.0+)"

# Guest/console roles that mean administrative reach if an anonymous client lands in them.
_ADMIN_ROLES = {"admin", "admins", "amq", "manager"}


# ── Classic ────────────────────────────────────────────────────────────────────
@detector(kinds=["activemq_broker"], rule_id="ACTIVEMQ.OPENWIRE.RCE_CVE_2023_46604",
          severity="critical",
          title="ActiveMQ Classic version is affected by the OpenWire RCE (CVE-2023-46604)")
def openwire_rce(r, ctx) -> list:
    version = (r.raw or {}).get("broker_version")
    vulnerable = openwire_rce_vulnerable(version)
    if vulnerable is False:
        return []
    if vulnerable is None:
        return [Hit(
            observation=(f"ActiveMQ Classic reports version '{version}'; it could not be placed "
                         f"against the CVE-2023-46604 advisory, so OpenWire RCE exposure was not "
                         f"determined"),
            remediation=(f"Confirm the running version and ensure it is at least "
                         f"{_OPENWIRE_FIX_TEXT}. CVE-2023-46604 is remotely exploitable, trivially, "
                         f"and is on CISA's Known Exploited Vulnerabilities list."),
            detail=f"broker_version={version}",
            assessable=False,
            assessment_reason="broker version string not resolvable to a CVE-2023-46604 series",
            source_ref={"jmx": "BrokerVersion", "cve": "CVE-2023-46604"},
        )]
    return [Hit(
        observation=(f"ActiveMQ Classic version {version} predates the CVE-2023-46604 fix — its "
                     f"OpenWire transport deserializes untrusted class types, allowing remote code "
                     f"execution"),
        remediation=(f"Upgrade to {_OPENWIRE_FIX_TEXT} immediately. CVE-2023-46604 (CVSS 9.8, "
                     f"CISA-KEV) is actively exploited to deploy ransomware and cryptominers; until "
                     f"patched, restrict OpenWire (:61616) to trusted hosts only."),
        detail=f"broker_version={version}",
        source_ref={"jmx": "BrokerVersion", "cve": "CVE-2023-46604"},
    )]


@detector(kinds=["activemq_broker"], rule_id="ACTIVEMQ.AUTH.NO_AUTHENTICATION_PLUGIN",
          severity="high", title="ActiveMQ Classic broker has no authentication plugin")
def classic_no_authn(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("xml_readable"):
        return [_xml_not_assessed(raw, "whether an authentication plugin is configured")]
    if raw.get("has_authentication_plugin"):
        return []
    return [Hit(
        observation=(f"ActiveMQ broker {raw.get('broker_name')} activemq.xml declares no "
                     f"authentication plugin (no simpleAuthenticationPlugin or "
                     f"jaasAuthenticationPlugin), so any client may connect without credentials"),
        remediation=("Add a jaasAuthenticationPlugin (or simpleAuthenticationPlugin) inside "
                     "<plugins> and disable anonymous access. Without an authentication plugin the "
                     "broker accepts every connection."),
        detail="has_authentication_plugin=False",
        source_ref={"config": "activemq.xml <plugins>"},
    )]


@detector(kinds=["activemq_broker"], rule_id="ACTIVEMQ.AUTH.ANONYMOUS_ACCESS",
          severity="high", title="ActiveMQ Classic allows anonymous access")
def classic_anonymous(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("xml_readable"):
        return []   # NO_AUTHENTICATION_PLUGIN already reports the not-assessed config
    if not raw.get("anonymous_access_allowed"):
        return []
    return [Hit(
        observation=(f"ActiveMQ broker {raw.get('broker_name')} has "
                     f"simpleAuthenticationPlugin anonymousAccessAllowed=\"true\", so clients that "
                     f"present no credentials are still admitted"),
        remediation=("Set anonymousAccessAllowed=\"false\" (or remove it) so every connection must "
                     "authenticate. Anonymous access bypasses the user table entirely."),
        detail="anonymous_access_allowed=True",
        source_ref={"config": "activemq.xml simpleAuthenticationPlugin"},
    )]


@detector(kinds=["activemq_broker"], rule_id="ACTIVEMQ.AUTHZ.NO_AUTHORIZATION_PLUGIN",
          severity="medium", title="ActiveMQ Classic broker has no authorization plugin")
def classic_no_authz(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("xml_readable"):
        return []   # the not-assessed signal is emitted once by NO_AUTHENTICATION_PLUGIN
    if raw.get("has_authorization_plugin"):
        return []
    return [Hit(
        observation=(f"ActiveMQ broker {raw.get('broker_name')} activemq.xml declares no "
                     f"authorizationPlugin, so authenticated users are not restricted per "
                     f"destination"),
        remediation=("Add an authorizationPlugin with authorizationEntries granting read/write/admin "
                     "per queue and topic. Without it, any authenticated user can access every "
                     "destination."),
        detail="has_authorization_plugin=False",
        source_ref={"config": "activemq.xml <plugins>"},
    )]


@detector(kinds=["activemq_broker"], rule_id="ACTIVEMQ.CONSOLE.DEFAULT_ADMIN",
          severity="high", title="ActiveMQ web console uses the default admin/admin credentials")
def classic_default_console(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("realm_readable"):
        return [Hit(
            observation=(f"ActiveMQ broker {raw.get('broker_name')} web-console realm "
                         f"(jetty-realm.properties) was not supplied, so use of the default "
                         f"admin/admin credential was not determined"),
            remediation=("Provide conf/jetty-realm.properties to the connector, or confirm manually "
                         "that the default 'admin: admin' entry has been changed."),
            detail="realm_readable=False",
            assessable=False,
            assessment_reason="jetty-realm.properties not supplied to the connector",
            source_ref={"config": "conf/jetty-realm.properties"},
        )]
    if not raw.get("realm_has_default_admin"):
        return []
    return [Hit(
        observation=(f"ActiveMQ broker {raw.get('broker_name')} web console still has the factory "
                     f"'admin: admin' entry in jetty-realm.properties"),
        remediation=("Change the admin password in conf/jetty-realm.properties (and prefer an "
                     "encrypted value). admin/admin is the documented default and is widely scanned "
                     "for."),
        detail="realm_has_default_admin=True",
        source_ref={"config": "conf/jetty-realm.properties"},
    )]


@detector(kinds=["activemq_broker"], rule_id="ACTIVEMQ.TLS.NO_SSL_CONNECTOR",
          severity="high", title="ActiveMQ Classic has no TLS transport connector")
def classic_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("connector_count"):
        return [Hit(
            observation=(f"ActiveMQ broker {raw.get('broker_name')} transport connectors could not "
                         f"be read over JMX, so TLS coverage of the transports was not determined"),
            remediation=("Ensure the connector can read the Broker MBean's TransportConnectors "
                         "attribute, or confirm an ssl:// connector exists manually."),
            detail="connector_count=0",
            assessable=False,
            assessment_reason="TransportConnectors attribute not readable over Jolokia",
            source_ref={"jmx": "TransportConnectors"},
        )]
    if raw.get("has_ssl_connector"):
        return []
    conns = ", ".join(sorted((raw.get("transport_connectors") or {}).keys())) or "(unnamed)"
    return [Hit(
        observation=(f"ActiveMQ broker {raw.get('broker_name')} has {raw.get('connector_count')} "
                     f"transport connector(s) [{conns}] and none use ssl:// — OpenWire and any "
                     f"credentials on it cross the network in plaintext"),
        remediation=("Add an ssl:// transport connector with a broker keystore and move clients onto "
                     "it. Plaintext tcp:// OpenWire exposes messages and passwords to anyone on the "
                     "network path."),
        detail=f"has_ssl_connector=False connectors={conns}",
        source_ref={"jmx": "TransportConnectors"},
    )]


# ── Artemis ─────────────────────────────────────────────────────────────────────
@detector(kinds=["artemis_broker"], rule_id="ARTEMIS.SECURITY.DISABLED",
          severity="critical", title="ActiveMQ Artemis has security disabled")
def artemis_security_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("broker_xml_readable"):
        return [Hit(
            observation=(f"Artemis broker {raw.get('broker_name')} broker.xml was not supplied, so "
                         f"whether security-enabled has been turned off was not determined"),
            remediation=("Provide broker.xml to the connector, or confirm <security-enabled> is not "
                         "set to false."),
            detail="broker_xml_readable=False",
            assessable=False,
            assessment_reason="broker.xml not supplied to the connector",
            source_ref={"config": "broker.xml <security-enabled>"},
        )]
    if raw.get("security_enabled"):
        return []
    return [Hit(
        observation=(f"Artemis broker {raw.get('broker_name')} broker.xml sets "
                     f"<security-enabled>false</security-enabled>, so authentication and "
                     f"authorization are turned off entirely"),
        remediation=("Set <security-enabled>true</security-enabled> and define security-settings "
                     "roles. With security disabled every client has full access to every address."),
        detail="security_enabled=False",
        source_ref={"config": "broker.xml <security-enabled>"},
    )]


@detector(kinds=["artemis_broker"], rule_id="ARTEMIS.AUTH.GUEST_LOGIN_ENABLED",
          severity="high", title="ActiveMQ Artemis GuestLoginModule admits unauthenticated clients")
def artemis_guest_login(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("login_config_readable"):
        return [Hit(
            observation=(f"Artemis broker {raw.get('broker_name')} JAAS login.config was not "
                         f"supplied, so whether a GuestLoginModule admits unauthenticated clients "
                         f"was not determined"),
            remediation=("Provide login.config to the connector, or confirm no GuestLoginModule is "
                         "present in the login chain."),
            detail="login_config_readable=False",
            assessable=False,
            assessment_reason="login.config not supplied to the connector",
            source_ref={"config": "login.config"},
        )]
    if not raw.get("guest_login_module"):
        return []
    role = raw.get("guest_role") or "guests"
    privileged = str(role).strip().lower() in _ADMIN_ROLES
    return [Hit(
        observation=(f"Artemis broker {raw.get('broker_name')} login.config enables a "
                     f"GuestLoginModule mapping unauthenticated (or invalid-credential) clients to "
                     f"user '{raw.get('guest_user') or 'guest'}' with role '{role}'"),
        remediation=("Remove the GuestLoginModule from the login chain, or scope its guest role to "
                     "the minimum with tight security-settings. It lets clients with no credentials "
                     "onto the broker."),
        detail=f"guest_login_module=True guest_role={role}",
        severity="critical" if privileged else "high",
        source_ref={"config": "login.config GuestLoginModule"},
    )]


@detector(kinds=["artemis_broker"], rule_id="ARTEMIS.CREDS.DEFAULT_USER",
          severity="high", title="ActiveMQ Artemis has a user with a default or plaintext password")
def artemis_default_user(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("users_readable"):
        return [Hit(
            observation=(f"Artemis broker {raw.get('broker_name')} artemis-users.properties was not "
                         f"supplied, so use of default or plaintext user passwords was not "
                         f"determined"),
            remediation=("Provide artemis-users.properties to the connector, or confirm no user has "
                         "a default or unmasked password."),
            detail="users_readable=False",
            assessable=False,
            assessment_reason="artemis-users.properties not supplied to the connector",
            source_ref={"config": "artemis-users.properties"},
        )]
    weak = [u.get("username") for u in raw.get("auth_users") or [] if u.get("looks_default")]
    if not weak:
        return []
    return [Hit(
        observation=(f"Artemis broker {raw.get('broker_name')} artemis-users.properties has "
                     f"user(s) {', '.join(weak)} with a plaintext, well-known-default password"),
        remediation=("Change these passwords to strong values and mask them with the Artemis ENC() "
                     "password masking. A default or plaintext broker password is a direct login."),
        detail=f"default_users={','.join(weak)}",
        source_ref={"config": "artemis-users.properties"},
    )]


@detector(kinds=["artemis_broker"], rule_id="ARTEMIS.TLS.NO_SSL_ACCEPTOR",
          severity="high", title="ActiveMQ Artemis has no TLS acceptor")
def artemis_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("broker_xml_readable") or not (raw.get("acceptors") or []):
        return [Hit(
            observation=(f"Artemis broker {raw.get('broker_name')} acceptors were not readable "
                         f"(broker.xml not supplied or no acceptors declared), so TLS coverage of "
                         f"the transports was not determined"),
            remediation=("Provide broker.xml with the acceptors, or confirm an acceptor with "
                         "sslEnabled=true exists."),
            detail=f"broker_xml_readable={raw.get('broker_xml_readable')} "
                   f"acceptors={len(raw.get('acceptors') or [])}",
            assessable=False,
            assessment_reason="broker.xml acceptors not available to assess TLS",
            source_ref={"config": "broker.xml <acceptors>"},
        )]
    if raw.get("has_ssl_acceptor"):
        return []
    names = ", ".join(a.get("name") or "(unnamed)" for a in raw.get("acceptors") or [])
    return [Hit(
        observation=(f"Artemis broker {raw.get('broker_name')} has acceptor(s) [{names}] and none "
                     f"set sslEnabled=true — client traffic and credentials cross the network in "
                     f"plaintext"),
        remediation=("Add sslEnabled=true (with keyStorePath/keyStorePassword) to the client-facing "
                     "acceptor and require it. Plaintext acceptors expose messages and passwords."),
        detail=f"has_ssl_acceptor=False acceptors={names}",
        source_ref={"config": "broker.xml <acceptors>"},
    )]


def _xml_not_assessed(raw: dict, what: str) -> Hit:
    return Hit(
        observation=(f"ActiveMQ broker {raw.get('broker_name')} activemq.xml was not supplied, so "
                     f"{what} was not determined"),
        remediation="Provide activemq.xml to the connector so authentication/authorization posture "
                    "can be assessed.",
        detail="xml_readable=False",
        assessable=False,
        assessment_reason="activemq.xml not supplied to the connector",
        source_ref={"config": "activemq.xml"},
    )
