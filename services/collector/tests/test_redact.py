"""The redaction boundary is the product's headline claim, so it is the part that gets tests.

Each test below is a way a credential has actually escaped a scanner in the wild: under an obvious
key, inside a URL, quoted into an error string, echoed by a careless rule.
"""
from collector.redact import REDACTED, is_cred_key, redact

PW = "sup3rs3cr3tpw"


def test_value_scrub_finds_the_secret_wherever_it_hides():
    payload = {
        "findings": [{"observation": f"connected as admin with password {PW}"}],
        "labels": {"note": f"amqp://admin:{PW}@rabbit.internal:5672"},
        "error": f"AuthError: rejected {PW}",
    }
    out = redact(payload, {PW})
    assert PW not in str(out)


def test_key_scrub_catches_secrets_we_do_not_hold():
    # The point of the key layer: a connector that reads a credential OFF the target hands us a
    # secret that is not in secret_values() and so cannot be value-scrubbed.
    out = redact({"redis_password": "discovered-on-the-target", "client_secret": "abc"}, set())
    assert out == {"redis_password": REDACTED, "client_secret": REDACTED}


def test_presence_is_preserved_but_value_is_not():
    # "ssl.keystore.password is configured" is a fact a rule may need; its value never is. And a
    # falsey value must stay falsey — marking it would invert "not set" into "set to something".
    out = redact({"ssl.keystore.password": "hunter2", "sasl.password": None,
                  "admin_token": "", "tls.enabled": False}, set())
    assert out["ssl.keystore.password"] == REDACTED
    assert out["sasl.password"] is None
    assert out["admin_token"] == ""
    assert out["tls.enabled"] is False


def test_url_userinfo_is_stripped_but_the_host_survives():
    # The host is the posture-relevant half and the console needs it; the userinfo is the secret.
    out = redact({"url": "https://admin:pw@kong.internal:8001/status"}, set())
    assert out["url"] == f"https://{REDACTED}@kong.internal:8001/status"


def test_pem_private_key_is_stripped():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    assert "MIIEow" not in str(redact({"detail": f"key was {pem}"}, set()))


def test_provenance_survives_redaction():
    # source_ref is why a finding exists. A greedy key regex matching bare `key` would eat
    # `config_key` and leave the evidence ledger unable to say what was read.
    src = {"config_key": "authorizer.class.name", "api": "describe_configs"}
    assert redact({"source_ref": src}, set())["source_ref"] == src


def test_short_credentials_are_not_value_scrubbed():
    # RabbitMQ's default login is guest/guest. Scrubbing it by value would gut the observation of
    # the rule that exists to report it — so the key/shape layers cover it instead.
    obs = "user `guest` has tag administrator and password `guest`"
    assert redact({"observation": obs}, {"guest"})["observation"] == obs


def test_longest_secret_scrubbed_first():
    # A short secret that is a substring of a long one would otherwise chop the long one into a
    # fragment that no longer matches, leaving most of it on the wire.
    out = redact({"s": "token=abcdefgh12345678"}, {"abcdefgh", "abcdefgh12345678"})
    assert "12345678" not in out["s"]


def test_walks_lists_and_leaves_non_strings_alone():
    out = redact({"n": [{"password": "x"}, 5, True, None]}, set())
    assert out["n"] == [{"password": REDACTED}, 5, True, None]


def test_cred_key_matching_is_precise():
    for k in ("password", "sasl.password", "admin_token", "ssl.keystore.password",
              "client_secret", "api_key", "authorization"):
        assert is_cred_key(k), k
    # Keys that merely resemble one. `authenticated`/`oauth_enabled` are posture, not secrets, and
    # dropping them would silently weaken findings rather than protect anything.
    for k in ("config_key", "authenticated", "oauth_enabled", "key_algorithm", "tenant_id"):
        assert not is_cred_key(k), k
