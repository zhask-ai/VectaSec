"""MQTT rulepack — config/API-evidence detectors over the normalized mqtt_broker / mqtt_listener
kinds connect/mqtt.py emits for Mosquitto, EMQX and HiveMQ.

MQTT is anonymous-by-default and one of the most internet-exposed protocols there is, so the P0
checks are about what was NOT turned on: anonymous access, an absent ACL (default-allow topics),
plaintext listeners and bridges, an exposed admin console, the installer default admin, and a
management API that answers with no credential.

Three disciplines, same as the Redis/K8s packs:

  • Rules read NORMALIZED fields (`allow_anonymous`, `authz_default_allow`, `tls`…), so one rule
    covers all three broker families — a value read off mosquitto.conf and a value read off the
    EMQX API reach the same detector.
  • The `*_readable` flags gate the coverage-gap answer. A broker whose authn posture the
    connector could not read (every HiveMQ broker; a denied EMQX endpoint) yields a not-assessable
    finding via MQTT.POSTURE.NOT_ASSESSABLE — never a silent pass. A value that IS readable but
    genuinely unknown (Mosquitto `allow_anonymous` unset ⇒ version-dependent) yields a
    per-rule assessable=False Hit.
  • Every observation states a value read from the target. Nothing here concludes.
"""
from ..contracts import Hit
from ..registry import detector

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _api(raw) -> dict:
    return raw.get("admin_api") or {}


# ════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION
# ════════════════════════════════════════════════════════════════════════════
@detector(kinds=["mqtt_broker"], rule_id="MQTT.AUTH.ANONYMOUS_ENABLED", severity="critical",
          title="MQTT broker accepts anonymous (unauthenticated) connections")
def anonymous_enabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("authn_readable"):
        return []                                   # unreadable → MQTT.POSTURE.NOT_ASSESSABLE
    anon = raw.get("allow_anonymous")
    if anon is True:
        return [Hit(
            observation=(f"MQTT broker '{r.name}' ({raw.get('system')}) allows anonymous "
                         f"connections — {raw.get('allow_anonymous_source')}. Any client that can "
                         f"reach a listener connects with no credential."),
            remediation=("Require authentication: set `allow_anonymous false` and configure a "
                         "password_file / auth plugin (Mosquitto), or enable at least one "
                         "authenticator (EMQX). Anonymous MQTT is publish/subscribe access to "
                         "every topic for anyone who can open the socket."),
            detail=f"allow_anonymous={anon} system={raw.get('system')}",
            source_ref={"config": "allow_anonymous", "system": raw.get("system")},
        )]
    if anon is None:
        return [Hit(
            observation=(f"MQTT broker '{r.name}' ({raw.get('system')}) does not set "
                         f"allow_anonymous explicitly ({raw.get('allow_anonymous_source')}); the "
                         f"effective anonymous policy depends on the broker version (Mosquitto "
                         f"<2.0 defaults to allowing anonymous, >=2.0 to denying)."),
            remediation=("Set `allow_anonymous` explicitly to false and configure authentication, "
                         "so the anonymous policy does not silently depend on the packaged version."),
            detail=f"allow_anonymous=unset system={raw.get('system')}",
            assessable=False,
            assessment_reason="allow_anonymous unset — effective default is broker-version dependent",
            source_ref={"config": "allow_anonymous"},
        )]
    return []


@detector(kinds=["mqtt_broker"], rule_id="MQTT.AUTH.NO_CREDENTIAL_STORE", severity="high",
          title="MQTT broker has no credential backend configured")
def no_credential_store(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("authn_readable"):
        return []
    # A broker that already allows anonymous is reported by MQTT.AUTH.ANONYMOUS_ENABLED — this rule
    # covers the distinct case: no password_file / no enabled authenticator, so there is nothing to
    # authenticate against even when anonymous is not explicitly on.
    if raw.get("auth_backend_present") is not False or raw.get("allow_anonymous") is True:
        return []
    return [Hit(
        observation=(f"MQTT broker '{r.name}' ({raw.get('system')}) has no credential backend: "
                     f"no password_file / auth plugin (Mosquitto) or no enabled authenticator "
                     f"(EMQX). allow_anonymous={raw.get('allow_anonymous')}."),
        remediation=("Configure a credential store: a Mosquitto `password_file` (or auth plugin), "
                     "or an EMQX authenticator (built-in database, HTTP, JWT, LDAP). Without one "
                     "the broker cannot verify any client identity."),
        detail=f"auth_backend_present=False allow_anonymous={raw.get('allow_anonymous')}",
        source_ref={"config": "password_file / authenticators"},
    )]


# ════════════════════════════════════════════════════════════════════════════
# AUTHORIZATION
# ════════════════════════════════════════════════════════════════════════════
@detector(kinds=["mqtt_broker"], rule_id="MQTT.AUTHZ.DEFAULT_ALLOW", severity="high",
          title="MQTT broker authorizes every topic by default (no ACL / default-allow)")
def authz_default_allow(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("authz_readable"):
        return []
    da = raw.get("authz_default_allow")
    if da is True:
        return [Hit(
            observation=(f"MQTT broker '{r.name}' ({raw.get('system')}) applies a default-allow "
                         f"topic policy — {raw.get('authz_source')}. Every connected client may "
                         f"publish and subscribe to any topic, including $SYS and other clients' "
                         f"command topics."),
            remediation=("Define explicit authorization: a Mosquitto `acl_file` (unmatched topics "
                         "are then denied), or EMQX authorization sources with "
                         "`authorization.no_match = deny`. Default-allow means an authenticated "
                         "but unprivileged client still reads and writes everything."),
            detail=f"authz_default_allow=True source={raw.get('authz_source')}",
            source_ref={"config": "acl_file / authorization.no_match"},
        )]
    if da is None:
        return [Hit(
            observation=(f"MQTT broker '{r.name}' ({raw.get('system')}) topic authorization is "
                         f"handled by an opaque backend ({raw.get('authz_source')}); the "
                         f"default action for unmatched topics could not be determined."),
            remediation=("Confirm the authorization plugin denies unmatched topics by default, or "
                         "add an explicit acl_file so the policy is auditable."),
            detail=f"authz_source={raw.get('authz_source')}",
            assessable=False,
            assessment_reason="authorization delegated to a plugin whose default action is not readable",
            source_ref={"config": "authorization backend"},
        )]
    return []


# ════════════════════════════════════════════════════════════════════════════
# BRIDGES (Mosquitto `connection` blocks)
# ════════════════════════════════════════════════════════════════════════════
@detector(kinds=["mqtt_broker"], rule_id="MQTT.BRIDGE.PLAINTEXT", severity="high",
          title="MQTT bridge connects to a remote broker without TLS")
def bridge_plaintext(r, ctx) -> list:
    raw = r.raw or {}
    hits = []
    for b in raw.get("bridges") or []:
        if not b.get("address") or b.get("tls"):
            continue
        hits.append(Hit(
            observation=(f"MQTT bridge '{b.get('name')}' on broker '{r.name}' connects to "
                         f"{b.get('address')} with no bridge TLS (no bridge_cafile / bridge_capath "
                         f"/ bridge_certfile). Bridged traffic — including the remote credential — "
                         f"crosses the network in plaintext."),
            remediation=("Configure bridge TLS (`bridge_cafile` and, for mutual auth, "
                         "`bridge_certfile`/`bridge_keyfile`) and do not set `bridge_insecure "
                         "true`. A plaintext bridge exposes every replicated message and the "
                         "remote password to anyone on the path."),
            detail=f"bridge={b.get('name')} address={b.get('address')} tls=False",
            source_ref={"config": f"connection {b.get('name')}"},
        ))
    return hits


@detector(kinds=["mqtt_broker"], rule_id="MQTT.BRIDGE.UNAUTHENTICATED", severity="medium",
          title="MQTT bridge connects to a remote broker without credentials")
def bridge_unauthenticated(r, ctx) -> list:
    raw = r.raw or {}
    hits = []
    for b in raw.get("bridges") or []:
        if not b.get("address") or b.get("remote_auth"):
            continue
        hits.append(Hit(
            observation=(f"MQTT bridge '{b.get('name')}' on broker '{r.name}' connects to "
                         f"{b.get('address')} with no `remote_username` — the bridge authenticates "
                         f"to the remote broker anonymously."),
            remediation=("Set `remote_username`/`remote_password` (or client-certificate auth) on "
                         "the bridge so the remote broker can authenticate this connection."),
            detail=f"bridge={b.get('name')} remote_username=None",
            source_ref={"config": f"connection {b.get('name')}"},
        ))
    return hits


# ════════════════════════════════════════════════════════════════════════════
# ADMIN CONSOLE / API
# ════════════════════════════════════════════════════════════════════════════
def _bind_exposed(bind) -> bool | None:
    """Is a dashboard/control-center bind reachable off-host? None when the bind is unknown."""
    if bind is None:
        return None
    s = str(bind).strip()
    host = s
    if s.startswith("["):
        host = s[1:].split("]")[0]
    elif s.isdigit():
        host = ""                                   # bare port ⇒ all interfaces
    elif ":" in s and s.count(":") == 1:
        host = s.rsplit(":", 1)[0]
    host = host.strip("[]").lower()
    if host in _LOOPBACK or host == "127.0.0.1":
        return False
    return host in ("", "0.0.0.0", "*", "::")


@detector(kinds=["mqtt_broker"], rule_id="MQTT.DASHBOARD.EXPOSED", severity="high",
          title="MQTT admin console binds to all network interfaces")
def dashboard_exposed(r, ctx) -> list:
    raw = r.raw or {}
    dash = raw.get("dashboard") or {}
    if not raw.get("dashboard_readable") or dash.get("enabled") is not True:
        return []
    exposed = _bind_exposed(dash.get("bind"))
    if exposed is True:
        return [Hit(
            observation=(f"{dash.get('kind')} of MQTT broker '{r.name}' ({raw.get('system')}) "
                         f"binds to {dash.get('bind')} (all interfaces) with tls={dash.get('tls')}. "
                         f"The management console is reachable off-host."),
            remediation=("Bind the dashboard/control-center to a private/loopback interface behind "
                         "a VPN or reverse proxy, and serve it over TLS. An internet-exposed MQTT "
                         "admin console is a broker-takeover surface."),
            detail=f"bind={dash.get('bind')} tls={dash.get('tls')}",
            source_ref={"config": "dashboard.bind"},
        )]
    if exposed is None:
        return [Hit(
            observation=(f"{dash.get('kind')} of MQTT broker '{r.name}' is enabled but its bind "
                         f"address was not readable, so off-host reachability is undetermined."),
            remediation="Confirm the console binds to a private interface and is fronted by TLS.",
            detail="dashboard.bind=unknown",
            assessable=False,
            assessment_reason="dashboard enabled but bind address not readable",
            source_ref={"config": "dashboard.bind"},
        )]
    return []


@detector(kinds=["mqtt_broker"], rule_id="MQTT.DASHBOARD.DEFAULT_ADMIN", severity="high",
          title="MQTT admin console still has the installer default administrator account")
def dashboard_default_admin(r, ctx) -> list:
    raw = r.raw or {}
    da = raw.get("default_admin") or {}
    if da.get("present") is not True:
        return []
    return [Hit(
        observation=(f"MQTT broker '{r.name}' ({raw.get('system')}) admin console still has the "
                     f"installer default administrator account '{da.get('username')}'. The "
                     f"account name is the vendor default; its password is not readable via the "
                     f"API, so whether it was rotated could not be confirmed."),
        remediation=("Delete or rename the default administrator account and set a strong, unique "
                     "password (EMQX ships admin/public, HiveMQ admin/hivemq — both are published). "
                     "Prefer creating a named admin and removing the default."),
        detail=f"default_admin_username={da.get('username')}",
        source_ref={"api": "dashboard users", "credential_metadata": "default admin account"},
    )]


@detector(kinds=["mqtt_broker"], rule_id="MQTT.API.UNAUTHENTICATED", severity="critical",
          title="MQTT management API answers without authentication")
def api_unauthenticated(r, ctx) -> list:
    raw = r.raw or {}
    api = _api(raw)
    if api.get("unauthenticated_reachable") is not True:
        return []
    return [Hit(
        observation=(f"The {api.get('kind')} for MQTT broker '{r.name}' at {api.get('base_url')} "
                     f"returned a 2xx response to an unauthenticated GET — the management plane is "
                     f"world-readable to anyone who can reach it."),
        remediation=("Require authentication on the management API. EMQX: protect the Dashboard "
                     "API with API keys and never expose :18083 publicly. HiveMQ: the REST API's "
                     "own user authentication is disabled by default even once the API is enabled — "
                     "turn it on and restrict the listener. Restrict the port to a management network."),
        detail=f"unauthenticated_reachable=True base_url={api.get('base_url')}",
        source_ref={"api": api.get("base_url"), "probe": "unauthenticated GET"},
    )]


@detector(kinds=["mqtt_broker"], rule_id="MQTT.API.PLAINTEXT", severity="medium",
          title="MQTT management API is served over plaintext HTTP")
def api_plaintext(r, ctx) -> list:
    raw = r.raw or {}
    api = _api(raw)
    if not api:
        return []
    host = (api.get("host") or "").strip("[]").lower()
    if api.get("scheme") != "http" or host in _LOOPBACK or host == "127.0.0.1" or host == "":
        return []
    return [Hit(
        observation=(f"The {api.get('kind')} for MQTT broker '{r.name}' is served over plaintext "
                     f"HTTP at {api.get('base_url')} (host {host}). API keys / bearer tokens and "
                     f"every management response travel unencrypted."),
        remediation=("Serve the management API over HTTPS with a valid certificate, or restrict it "
                     "to a loopback/management interface fronted by a TLS-terminating proxy."),
        detail=f"scheme=http host={host}",
        source_ref={"api": api.get("base_url"), "config_key": "scheme"},
    )]


# ════════════════════════════════════════════════════════════════════════════
# TLS (broker-level roll-up)
# ════════════════════════════════════════════════════════════════════════════
@detector(kinds=["mqtt_broker"], rule_id="MQTT.TLS.NO_LISTENER", severity="medium",
          title="MQTT broker has no TLS listener")
def tls_no_listener(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("listeners_readable"):
        return []
    listeners = [x for x in ctx.of_kind("mqtt_listener")
                 if (x.raw or {}).get("broker_ext") == r.ext_id]
    if not listeners:
        return []
    reachable = [l for l in listeners if not (l.raw or {}).get("loopback")]
    if not reachable or any((l.raw or {}).get("tls") for l in reachable):
        return []
    return [Hit(
        observation=(f"MQTT broker '{r.name}' ({raw.get('system')}) exposes {len(reachable)} "
                     f"non-loopback listener(s) and none of them use TLS — all client and "
                     f"credential traffic is plaintext MQTT."),
        remediation=("Add a TLS listener (Mosquitto certfile/keyfile; EMQX ssl listener) and move "
                     "clients onto it. Without any encrypted entrypoint, MQTT usernames/passwords "
                     "are sniffable on the wire."),
        detail=f"non_loopback_listeners={len(reachable)} tls_listeners=0",
        source_ref={"config": "listeners"},
    )]


# ════════════════════════════════════════════════════════════════════════════
# LISTENERS (per-listener)
# ════════════════════════════════════════════════════════════════════════════
@detector(kinds=["mqtt_listener"], rule_id="MQTT.LISTENER.NO_TLS", severity="high",
          title="MQTT listener has no TLS")
def listener_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("tls") or raw.get("loopback"):
        return []
    where = raw.get("bind") or f"port {raw.get('port')}"
    return [Hit(
        observation=(f"MQTT listener {r.name} ({raw.get('system')}) on {where} is plaintext "
                     f"(protocol={raw.get('protocol')}, tls=False) and is not loopback-only, so "
                     f"MQTT credentials and payloads cross the network unencrypted."),
        remediation=("Terminate this listener over TLS (Mosquitto certfile/keyfile; EMQX ssl/wss "
                     "listener), or restrict it to loopback and front it with a TLS proxy. "
                     "Plaintext MQTT on a routable interface leaks the AUTH password."),
        detail=f"bind={raw.get('bind')} port={raw.get('port')} tls=False protocol={raw.get('protocol')}",
        source_ref={"config": f"listener {raw.get('port')}"},
    )]


@detector(kinds=["mqtt_listener"], rule_id="MQTT.LISTENER.ANON_ALLOWED", severity="high",
          title="MQTT listener overrides authentication to allow anonymous")
def listener_anon_allowed(r, ctx) -> list:
    raw = r.raw or {}
    # Per-listener allow_anonymous true (Mosquitto per_listener_settings) opens THIS listener even
    # when the broker default requires auth — a distinct, easily-missed exposure.
    if raw.get("allow_anonymous") is not True:
        return []
    where = raw.get("bind") or f"port {raw.get('port')}"
    return [Hit(
        observation=(f"MQTT listener {r.name} ({raw.get('system')}) on {where} sets "
                     f"`allow_anonymous true` at the listener level, permitting unauthenticated "
                     f"connections on this listener regardless of the broker default."),
        remediation=("Remove the per-listener `allow_anonymous true` override, or restrict this "
                     "listener to a trusted network. A single anonymous listener is enough to make "
                     "the whole broker reachable without credentials."),
        detail=f"listener_allow_anonymous=True bind={raw.get('bind')}",
        source_ref={"config": f"listener {raw.get('port')} allow_anonymous"},
    )]


# ════════════════════════════════════════════════════════════════════════════
# COVERAGE GAP (not-assessable)
# ════════════════════════════════════════════════════════════════════════════
@detector(kinds=["mqtt_broker"], rule_id="MQTT.POSTURE.NOT_ASSESSABLE", severity="info",
          title="MQTT broker security posture could not be read")
def posture_not_assessable(r, ctx) -> list:
    raw = r.raw or {}
    gaps = [aspect for aspect, flag in (
        ("authentication", raw.get("authn_readable")),
        ("authorization", raw.get("authz_readable")),
        ("listeners/TLS", raw.get("listeners_readable")),
    ) if not flag]
    if not gaps:
        return []
    return [Hit(
        observation=(f"MQTT broker '{r.name}' ({raw.get('system')}): the following posture "
                     f"aspects were not readable from the available interface: {', '.join(gaps)}. "
                     f"{raw.get('allow_anonymous_source')}."),
        remediation=("Read this broker's posture from an interface that exposes it: for HiveMQ the "
                     "REST API does not surface authentication/authorization/TLS config, so audit "
                     "those from the HiveMQ config file, the Enterprise Security Extension, or the "
                     "Control Center; for EMQX supply an API key with read access to the "
                     "authentication/authorization/listeners endpoints."),
        detail=f"unreadable_aspects={gaps} system={raw.get('system')}",
        assessable=False,
        assessment_reason=f"posture aspects not exposed by the available interface: {', '.join(gaps)}",
        source_ref={"system": raw.get("system"), "collection": raw.get("collection")},
    )]
