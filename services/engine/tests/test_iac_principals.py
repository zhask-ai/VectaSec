"""IaC principal NAME extraction — the "Also in git" column. Offline, from golden manifests fed
through the connector's own parse layer.

Two properties pinned hard:
  * a principal is a NAME (SASL user, Kong consumer, AWS access key id, client_id) and IS stored,
    on the workload and on the file, in raw["principals"] and labels["principals"];
  * the secret that sits beside it (SASL password, key-auth key, password_hash, AWS secret key)
    NEVER is — not in raw, not in labels, not in the principal list.
"""
from vectasec.connect.iac import _looks_like_iac, parse_iac

_COMPOSE = """
services:
  kafka-client:
    image: mycorp/consumer:1.0.0
    environment:
      KAFKA_SASL_USERNAME: orders-consumer
      KAFKA_SASL_PASSWORD: s3cr3t-sasl-pass
      KAFKA_SASL_JAAS_CONFIG: 'org.apache.kafka.common.security.scram.ScramLoginModule required username="jaas-svc" password="jaas-pw-123";'
      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
      AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      OIDC_CLIENT_ID: orders-api-client
      OIDC_CLIENT_SECRET: oidc-very-secret
      DB_USER: ${DB_USER}
      DB_URL: amqp://alice:pw@broker/
      DEBUG_USER: "true"
  rabbitmq:
    image: rabbitmq:3.13.7-management
    environment:
      RABBITMQ_DEFAULT_USER: app-user
      RABBITMQ_DEFAULT_PASS: app-pass-9
  gateway:
    image: kong:3.6
    environment:
      KONG_CONSUMER: billing-svc
"""

_RABBIT_DEFS = """
{"rabbit_version": "3.13.7",
 "users": [{"name": "svc-orders", "password_hash": "rabbit-hash-AAAA", "tags": []},
           {"name": "admin", "password_hash": "rabbit-hash-BBBB", "tags": ["administrator"]}],
 "vhosts": [{"name": "/"}],
 "permissions": [{"user": "svc-orders", "vhost": "/", "configure": ".*", "write": ".*", "read": ".*"}]}
"""

_KONG = """
_format_version: "3.0"
services:
  - name: orders
    url: http://orders:8080
consumers:
  - username: partner-a
    keyauth_credentials:
      - key: kong-key-partner-a-0123456789
  - username: partner-b
    basicauth_credentials:
      - username: partner-b-basic
        password: kong-basic-pw
keyauth_credentials:
  - consumer: partner-c
    key: kong-key-partner-c-9876543210
"""

_VALUES = """
image:
  repository: bitnami/kafka
auth:
  username: helm-sasl-user
  password: helm-sasl-pass
sasl:
  user: helm-sasl-user2
  password: helm-pass-2
replicaCount: 3
"""


def _workload(col, name):
    return next(r for r in col.resources if r.kind == "iac_workload" and r.raw["workload"] == name)


def _file(col):
    return next(r for r in col.resources if r.kind == "iac_file")


def _blob(col):
    return repr([r.raw for r in col.resources]) + repr([r.labels for r in col.resources])


# ── compose / env keys ────────────────────────────────────────────────────────
def test_env_principals_by_kind():
    col = parse_iac({"docker-compose.yml": _COMPOSE})
    kc = _workload(col, "kafka-client")
    by_name = {p["name"]: p for p in kc.raw["principals"]}
    assert by_name["orders-consumer"]["kind"] == "sasl_user"
    assert by_name["jaas-svc"]["kind"] == "sasl_user"           # from the JAAS string
    assert by_name["AKIAIOSFODNN7EXAMPLE"]["kind"] == "aws_access_key_id"
    assert by_name["orders-api-client"]["kind"] == "client_id"
    assert set(by_name) == {"orders-consumer", "jaas-svc", "AKIAIOSFODNN7EXAMPLE", "orders-api-client"}
    for p in by_name.values():
        assert p["file"] == "docker-compose.yml" and p["line"], "a principal points at a line"
    assert _workload(col, "rabbitmq").raw["principals"] == [
        {"name": "app-user", "kind": "amqp_user", "key": "RABBITMQ_DEFAULT_USER",
         "file": "docker-compose.yml", "line": 19}]
    assert _workload(col, "gateway").raw["principals"][0] == {
        "name": "billing-svc", "kind": "kong_consumer", "key": "KONG_CONSUMER",
        "file": "docker-compose.yml", "line": 24}


def test_references_urls_and_toggles_are_not_principals():
    kc = _workload(parse_iac({"docker-compose.yml": _COMPOSE}), "kafka-client")
    names = {p["name"] for p in kc.raw["principals"]}
    assert "${DB_USER}" not in names and not any("://" in n for n in names)
    assert "true" not in names


def test_secrets_beside_principals_never_stored():
    col = parse_iac({"docker-compose.yml": _COMPOSE})
    blob = _blob(col)
    for secret in ("s3cr3t-sasl-pass", "jaas-pw-123", "wJalrXUtnFEMI", "oidc-very-secret",
                   "app-pass-9", "alice:pw"):
        assert secret not in blob, secret
    kc = _workload(col, "kafka-client")
    secret_keys = {s["key"] for s in kc.raw["literal_secrets"]}
    # the paired secrets are still fingerprinted; the key ID is no longer mistaken for one
    assert {"KAFKA_SASL_PASSWORD", "KAFKA_SASL_JAAS_CONFIG", "AWS_SECRET_ACCESS_KEY",
            "OIDC_CLIENT_SECRET"} <= secret_keys
    assert "AWS_ACCESS_KEY_ID" not in secret_keys


def test_principals_label_is_sorted_unique_names_on_workload_and_file():
    col = parse_iac({"docker-compose.yml": _COMPOSE})
    kc = _workload(col, "kafka-client")
    assert kc.labels["principals"] == "AKIAIOSFODNN7EXAMPLE,jaas-svc,orders-api-client,orders-consumer"
    f = _file(col)
    assert f.labels["principals"] == ("AKIAIOSFODNN7EXAMPLE,app-user,billing-svc,jaas-svc,"
                                      "orders-api-client,orders-consumer")
    assert {p["name"] for p in f.raw["principals"]} == set(f.labels["principals"].split(","))


def test_label_is_capped_at_fifty_names():
    env = "\n".join(f"      SVC{i:03d}_USER: user-{i:03d}" for i in range(60))
    text = f"services:\n  app:\n    image: x:1\n    environment:\n{env}\n"
    w = _workload(parse_iac({"docker-compose.yml": text}), "app")
    assert len(w.raw["principals"]) == 60
    assert len(w.labels["principals"].split(",")) == 50


def test_workload_without_principals_has_no_label_and_empty_list():
    w = _workload(parse_iac({"docker-compose.yml": "services:\n  a:\n    image: x:1\n"}), "a")
    assert w.raw["principals"] == [] and "principals" not in w.labels


# ── RabbitMQ definitions.json ─────────────────────────────────────────────────
def test_rabbitmq_definitions_users_are_amqp_principals_and_hashes_are_fingerprinted():
    col = parse_iac({"definitions.json": _RABBIT_DEFS})
    f = _file(col)
    assert f.raw["format"] == "rabbitmq-definitions" and f.raw["parsed"] is True
    w = _workload(col, "rabbitmq-definitions")
    assert w.raw["source_format"] == "rabbitmq-definitions"
    assert {(p["name"], p["kind"]) for p in w.raw["principals"]} == {
        ("svc-orders", "amqp_user"), ("admin", "amqp_user")}
    assert w.labels["principals"] == "admin,svc-orders"
    assert {s["key"] for s in w.raw["literal_secrets"]} == {
        "users[svc-orders].password_hash", "users[admin].password_hash"}
    assert "rabbit-hash" not in _blob(col)


# ── Kong declarative ──────────────────────────────────────────────────────────
def test_kong_declarative_consumers_are_principals_and_keys_are_hashed():
    col = parse_iac({"kong.yaml": _KONG})
    f = _file(col)
    assert f.raw["format"] == "kong-declarative", "must not be mistaken for compose (it has services:)"
    w = _workload(col, "kong-declarative")
    assert {(p["name"], p["kind"]) for p in w.raw["principals"]} == {
        ("partner-a", "kong_consumer"), ("partner-b", "kong_consumer"),
        ("partner-b-basic", "kong_consumer"), ("partner-c", "kong_consumer")}
    keys = {s["key"] for s in w.raw["literal_secrets"]}
    assert keys == {"consumers[partner-a].keyauth_credentials[].key",
                    "consumers[partner-b].basicauth_credentials[].password",
                    "consumers[partner-c].keyauth_credentials[].key"}
    for s in w.raw["literal_secrets"]:
        assert len(s["fingerprint"]) == 12
    blob = _blob(col)
    assert "kong-key-partner" not in blob and "kong-basic-pw" not in blob


# ── Helm values ───────────────────────────────────────────────────────────────
def test_helm_values_username_paths_are_principals():
    col = parse_iac({"charts/kafka/values.yaml": _VALUES})
    assert _file(col).raw["format"] == "helm-values"
    w = _workload(col, "values")
    assert {(p["name"], p["kind"], p["key"]) for p in w.raw["principals"]} == {
        ("helm-sasl-user", "username", "auth.username"),
        ("helm-sasl-user2", "sasl_user", "sasl.user")}
    assert {s["key"] for s in w.raw["literal_secrets"]} == {"auth.password", "sasl.password"}
    assert "helm-sasl-pass" not in _blob(col) and "helm-pass-2" not in _blob(col)


# ── the walker picks the new formats up ──────────────────────────────────────
def test_walker_recognises_the_new_formats():
    assert _looks_like_iac("/repo/rabbit/definitions.json", _RABBIT_DEFS)
    assert _looks_like_iac("/repo/kong/kong.yaml", _KONG)
    assert _looks_like_iac("/repo/charts/kafka/values-prod.yaml", _VALUES)
    assert not _looks_like_iac("/repo/data/export.json", '{"rows": []}')


# ── existing behaviour is untouched ───────────────────────────────────────────
def test_existing_iac_rules_still_see_the_same_facts():
    from vectasec.registry import DETECTORS
    from vectasec.contracts import ScanContext
    import vectasec.detect.iac  # noqa: F401
    rules = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("SUPPLY.IAC.")}
    col = parse_iac({"docker-compose.yml": _COMPOSE})
    kc = _workload(col, "kafka-client")
    ctx = ScanContext(connection_id="c", tenant_id="t", resources=col.resources)
    hits = rules["SUPPLY.IAC.LITERAL_SECRET"].fn(kc, ctx)
    assert hits and "AKIAIOSFODNN7EXAMPLE" not in hits[0].observation
