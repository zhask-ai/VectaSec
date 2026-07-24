"""Offline tests for the MQTT connector's parse layer, the MQTT rulepack, and NHI extraction.

No network, no live broker: the connector's parse functions (parse_mosquitto_config / parse_emqx /
parse_hivemq) are pure, so golden fixtures — a realistic mosquitto.conf and EMQX/HiveMQ admin-API
JSON — flow straight into the detectors, which are pure functions of (Resource, ScanContext).

Every detector gets a fires-on-bad and a does-not-fire-on-good case; the value-reading rules also
get a not-assessable case (the third honest outcome). The negative case carries the weight: a rule
that fires unconditionally is indistinguishable from one that works.
"""
import json
import pathlib

from vectasec.contracts import Collected, Resource, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS, validate_config
from vectasec.connect.mqtt import parse_mosquitto_config, parse_emqx, parse_hivemq
from vectasec.detect.mqtt import (
    anonymous_enabled, no_credential_store, authz_default_allow, bridge_plaintext,
    bridge_unauthenticated, dashboard_exposed, dashboard_default_admin, api_unauthenticated,
    api_plaintext, tls_no_listener, listener_no_tls, listener_anon_allowed, posture_not_assessable,
)

FIX = pathlib.Path(__file__).parent / "fixtures"


# ── fixture loaders ───────────────────────────────────────────────────────────
def mosq(name: str) -> Collected:
    return parse_mosquitto_config((FIX / f"mqtt_mosquitto_{name}.conf").read_text())


def emqx(name: str, base_url="http://emqx.example.com:18083") -> Collected:
    data = json.loads((FIX / f"mqtt_emqx_{name}.json").read_text())
    return parse_emqx(data, base_url=base_url)


def emqx_from(data: dict, base_url="http://emqx.example.com:18083") -> Collected:
    return parse_emqx(data, base_url=base_url)


def hivemq(base_url="http://hivemq.example.com:8888") -> Collected:
    data = json.loads((FIX / "mqtt_hivemq.json").read_text())
    return parse_hivemq(data, base_url=base_url)


def broker(col: Collected) -> Resource:
    return next(r for r in col.resources if r.kind == "mqtt_broker")


def listeners(col: Collected) -> list:
    return [r for r in col.resources if r.kind == "mqtt_listener"]


def ctx(*resources, **config) -> ScanContext:
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1",
                       resources=list(resources), config=config)


def cctx(col: Collected, **config) -> ScanContext:
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1",
                       resources=list(col.resources), config=config)


def one(hits):
    assert len(hits) == 1, f"expected exactly one hit, got {len(hits)}"
    return hits[0]


def kinds(resources) -> dict:
    out: dict = {}
    for r in resources:
        out[r.kind] = out.get(r.kind, 0) + 1
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Registration + connector surface
# ══════════════════════════════════════════════════════════════════════════════
def test_connector_registered():
    assert "mqtt" in CONNECTORS


def test_system_field_required():
    assert validate_config("mqtt", {}) == ["system is required (Broker system)"]
    assert validate_config("mqtt", {"system": "mosquitto"}) == []


def test_secret_fields_marked():
    secret = {f.key for f in CONNECTOR_FIELDS["mqtt"] if f.secret}
    assert secret == {"api_secret", "token"}


def test_only_mqtt_kinds_emitted():
    for col in (mosq("insecure"), mosq("hardened"), emqx("insecure"), emqx("hardened"), hivemq()):
        assert set(kinds(col.resources)) <= {"mqtt_broker", "mqtt_listener"}


def test_extractor_registered():
    assert "mqtt" in IDENTITY_EXTRACTORS


# ══════════════════════════════════════════════════════════════════════════════
# Mosquitto parse layer
# ══════════════════════════════════════════════════════════════════════════════
def test_mosquitto_parse_shape():
    col = mosq("insecure")
    b = broker(col)
    assert b.raw["system"] == "mosquitto"
    assert b.raw["allow_anonymous"] is True
    assert b.raw["auth_backend_present"] is False        # no password_file
    assert b.raw["authz_default_allow"] is True           # no acl_file
    assert len(listeners(col)) == 3
    # one TLS listener (8883), two plaintext (1883, 9001)
    assert sum(1 for l in listeners(col) if l.raw["tls"]) == 1
    # bridge captured, TLS/creds both absent
    assert b.raw["bridges"][0]["name"] == "cloud-bridge"
    assert b.raw["bridges"][0]["tls"] is False and b.raw["bridges"][0]["remote_auth"] is False


def test_mosquitto_default_listener_synthesized():
    # No `listener` line ⇒ a default listener from global port/bind + global TLS directives.
    col = parse_mosquitto_config("allow_anonymous true\ncertfile /c\nkeyfile /k\nport 1884\n")
    ls = listeners(col)
    assert len(ls) == 1 and ls[0].raw["port"] == "1884" and ls[0].raw["tls"] is True


def test_mosquitto_remote_password_never_stored():
    col = mosq("hardened")
    blob = json.dumps([r.raw for r in col.resources])
    assert "s3cr3t-not-stored" not in blob                # value dropped
    assert broker(col).raw["bridges"][0]["remote_password_present"] is True


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.AUTH.ANONYMOUS_ENABLED
# ══════════════════════════════════════════════════════════════════════════════
def test_anonymous_enabled_fires():
    b = broker(mosq("insecure"))
    h = one(anonymous_enabled(b, ctx(b)))
    assert h.severity is None and "anonymous" in h.observation.lower()


def test_anonymous_enabled_fires_emqx_no_authenticators():
    b = broker(emqx("insecure"))
    assert len(anonymous_enabled(b, ctx(b))) == 1


def test_anonymous_enabled_not_fire_when_denied():
    b = broker(mosq("hardened"))
    assert anonymous_enabled(b, ctx(b)) == []
    assert anonymous_enabled(broker(emqx("hardened")), ctx()) == []


def test_anonymous_enabled_not_assessable_when_unset():
    b = broker(parse_mosquitto_config("listener 1883 0.0.0.0\nprotocol mqtt\n"))
    h = one(anonymous_enabled(b, ctx(b)))
    assert h.assessable is False and "version" in h.assessment_reason.lower()


def test_anonymous_enabled_silent_when_unreadable():
    # HiveMQ authn is not readable ⇒ this rule stays silent (POSTURE.NOT_ASSESSABLE owns the gap).
    assert anonymous_enabled(broker(hivemq()), ctx()) == []


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.AUTH.NO_CREDENTIAL_STORE
# ══════════════════════════════════════════════════════════════════════════════
def test_no_credential_store_fires():
    b = broker(parse_mosquitto_config("listener 1883 0.0.0.0\n"))   # no pwd, anon unset
    assert len(no_credential_store(b, ctx(b))) == 1


def test_no_credential_store_not_fire_with_backend():
    assert no_credential_store(broker(mosq("hardened")), ctx()) == []


def test_no_credential_store_not_fire_when_anonymous_already_flagged():
    # allow_anonymous true is reported by ANONYMOUS_ENABLED — this rule must not double-report.
    assert no_credential_store(broker(mosq("insecure")), ctx()) == []


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.AUTHZ.DEFAULT_ALLOW
# ══════════════════════════════════════════════════════════════════════════════
def test_authz_default_allow_fires():
    b = broker(mosq("insecure"))
    assert len(authz_default_allow(b, ctx(b))) == 1


def test_authz_default_allow_fires_emqx_no_match_allow():
    assert len(authz_default_allow(broker(emqx("insecure")), ctx())) == 1


def test_authz_default_allow_not_fire_with_acl():
    assert authz_default_allow(broker(mosq("hardened")), ctx()) == []
    assert authz_default_allow(broker(emqx("hardened")), ctx()) == []


def test_authz_default_allow_not_assessable_with_plugin():
    b = broker(parse_mosquitto_config(
        "allow_anonymous false\npassword_file /x\nplugin /usr/lib/mosq_dynsec.so\n"))
    h = one(authz_default_allow(b, ctx(b)))
    assert h.assessable is False


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.BRIDGE.PLAINTEXT / UNAUTHENTICATED
# ══════════════════════════════════════════════════════════════════════════════
def test_bridge_plaintext_fires():
    h = one(bridge_plaintext(broker(mosq("insecure")), ctx()))
    assert "cloud-bridge" in h.observation


def test_bridge_plaintext_not_fire_with_tls():
    assert bridge_plaintext(broker(mosq("hardened")), ctx()) == []


def test_bridge_unauthenticated_fires():
    assert len(bridge_unauthenticated(broker(mosq("insecure")), ctx())) == 1


def test_bridge_unauthenticated_not_fire_with_credentials():
    assert bridge_unauthenticated(broker(mosq("hardened")), ctx()) == []


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.DASHBOARD.EXPOSED / DEFAULT_ADMIN
# ══════════════════════════════════════════════════════════════════════════════
def test_dashboard_exposed_fires():
    h = one(dashboard_exposed(broker(emqx("insecure")), ctx()))
    assert "0.0.0.0:18083" in h.observation


def test_dashboard_exposed_not_fire_on_loopback():
    assert dashboard_exposed(broker(emqx("hardened")), ctx()) == []


def test_dashboard_exposed_not_assessable_when_bind_unknown():
    data = json.loads((FIX / "mqtt_emqx_insecure.json").read_text())
    data["dashboard"] = {"outcome": "ok", "data": {"listeners": {"http": {"enable": True}}}}
    h = one(dashboard_exposed(broker(emqx_from(data)), ctx()))
    assert h.assessable is False


def test_dashboard_default_admin_fires():
    assert len(dashboard_default_admin(broker(emqx("insecure")), ctx())) == 1


def test_dashboard_default_admin_not_fire_when_rotated():
    assert dashboard_default_admin(broker(emqx("hardened")), ctx()) == []


def test_dashboard_default_admin_silent_when_unreadable():
    assert dashboard_default_admin(broker(hivemq()), ctx()) == []


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.API.UNAUTHENTICATED / PLAINTEXT
# ══════════════════════════════════════════════════════════════════════════════
def test_api_unauthenticated_fires_emqx():
    assert len(api_unauthenticated(broker(emqx("insecure")), ctx())) == 1


def test_api_unauthenticated_fires_hivemq():
    h = one(api_unauthenticated(broker(hivemq()), ctx()))
    assert "world-readable" in h.observation


def test_api_unauthenticated_not_fire_when_protected():
    assert api_unauthenticated(broker(emqx("hardened")), ctx()) == []


def test_api_plaintext_fires_on_http_remote():
    assert len(api_plaintext(broker(emqx("insecure")), ctx())) == 1


def test_api_plaintext_not_fire_on_https():
    b = broker(emqx("insecure", base_url="https://emqx.example.com:18083"))
    assert api_plaintext(b, ctx()) == []


def test_api_plaintext_not_fire_on_loopback():
    b = broker(emqx("insecure", base_url="http://127.0.0.1:18083"))
    assert api_plaintext(b, ctx()) == []


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.TLS.NO_LISTENER
# ══════════════════════════════════════════════════════════════════════════════
def test_tls_no_listener_fires_when_all_plaintext():
    col = emqx("insecure")
    h = one(tls_no_listener(broker(col), cctx(col)))
    assert "none of them use TLS" in h.observation


def test_tls_no_listener_not_fire_when_a_tls_listener_exists():
    col = mosq("insecure")            # has an 8883 TLS listener
    assert tls_no_listener(broker(col), cctx(col)) == []


def test_tls_no_listener_silent_for_hivemq():
    assert tls_no_listener(broker(hivemq()), ctx()) == []


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.LISTENER.NO_TLS / ANON_ALLOWED
# ══════════════════════════════════════════════════════════════════════════════
def test_listener_no_tls_fires_on_plaintext():
    plain = [l for l in listeners(mosq("insecure")) if not l.raw["tls"]]
    assert len(plain) == 2
    for l in plain:
        assert len(listener_no_tls(l, ctx())) == 1


def test_listener_no_tls_not_fire_on_tls_listener():
    tls = next(l for l in listeners(mosq("insecure")) if l.raw["tls"])
    assert listener_no_tls(tls, ctx()) == []


def test_listener_no_tls_not_fire_on_loopback():
    lp = next(l for l in listeners(parse_mosquitto_config("listener 1883 127.0.0.1\n")))
    assert listener_no_tls(lp, ctx()) == []


def test_listener_anon_allowed_fires():
    col = parse_mosquitto_config(
        "per_listener_settings true\nallow_anonymous false\n"
        "listener 1883 0.0.0.0\nallow_anonymous true\ncertfile /c\nkeyfile /k\n")
    l = listeners(col)[0]
    assert l.raw["allow_anonymous"] is True
    assert len(listener_anon_allowed(l, ctx())) == 1
    # TLS is configured here, so the plaintext rule stays quiet — the two rules are independent.
    assert listener_no_tls(l, ctx()) == []


def test_listener_anon_allowed_not_fire_without_override():
    for l in listeners(mosq("insecure")):
        assert listener_anon_allowed(l, ctx()) == []


# ══════════════════════════════════════════════════════════════════════════════
# MQTT.POSTURE.NOT_ASSESSABLE
# ══════════════════════════════════════════════════════════════════════════════
def test_posture_not_assessable_fires_for_hivemq():
    h = one(posture_not_assessable(broker(hivemq()), ctx()))
    assert h.assessable is False
    assert "authentication" in h.observation and "authorization" in h.observation


def test_posture_not_assessable_fires_on_denied_emqx_endpoint():
    data = json.loads((FIX / "mqtt_emqx_insecure.json").read_text())
    data["authentication"] = {"outcome": "denied", "data": None, "status": 401}
    h = one(posture_not_assessable(broker(emqx_from(data)), ctx()))
    assert h.assessable is False and "authentication" in h.observation


def test_posture_not_assessable_not_fire_when_all_readable():
    assert posture_not_assessable(broker(mosq("insecure")), ctx()) == []
    assert posture_not_assessable(broker(emqx("insecure")), ctx()) == []


# ══════════════════════════════════════════════════════════════════════════════
# NHI extraction
# ══════════════════════════════════════════════════════════════════════════════
def test_nhi_emqx_hardened_users_creds_grants():
    col = derive_identities("mqtt", emqx("hardened"))
    k = kinds(col.resources)
    # 1 dashboard admin + 2 built-in MQTT users
    assert k["identity"] == 3
    assert k["credential"] == 3
    assert k["grant"] == 2
    # the rotated dashboard admin is not flagged default; every credential is presence-only
    admin_cred = next(r for r in col.resources
                      if r.kind == "credential" and "ops-admin" in r.name)
    assert admin_cred.raw["is_default"] is False
    assert admin_cred.raw["plaintext"] is False
    # the built-in user grants attach to the existing device identities (no duplicate identity)
    principals = {r.raw["principal"] for r in col.resources if r.kind == "identity"}
    assert principals == {"emqx:dashboard:ops-admin", "emqx:mqtt:device-01", "emqx:mqtt:device-02"}


def test_nhi_emqx_default_admin_flagged():
    col = derive_identities("mqtt", emqx("insecure"))
    cred = next(r for r in col.resources if r.kind == "credential")
    assert cred.raw["is_default"] is True                # the installer 'admin' account


def test_nhi_mosquitto_bridge_identity():
    col = derive_identities("mqtt", mosq("hardened"))
    k = kinds(col.resources)
    assert k["identity"] == 1 and k["credential"] == 1 and k["grant"] == 1
    idr = next(r for r in col.resources if r.kind == "identity")
    assert idr.raw["external"] is True and "bridgeuser" in idr.raw["principal"]


def test_nhi_mosquitto_anonymous_bridge_no_identity():
    # cloud-bridge has no remote_username ⇒ no identity to derive.
    col = derive_identities("mqtt", mosq("insecure"))
    assert kinds(col.resources).get("identity") is None


def test_nhi_hivemq_contributes_nothing():
    col = derive_identities("mqtt", hivemq())
    assert kinds(col.resources).get("identity") is None
