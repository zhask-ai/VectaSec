"""The fix library: an exact, copy-paste remediation per rule, per system.

contracts.Hit.remediation is free prose — correct, but a sentence a human still has to turn
into a command. SMBs buy fixes, not sentences (docs/vectasec-smb-strategy-2026-10.md §3), so this
module pairs a rule with the vendor CLI / Terraform / console steps that close it, templated with
the resource specifics the detectors already record (labels/raw), and with a `verify_hint` that
says exactly what the rescan behind the console's Verify button will check.

Design rules:
  • PURE. No DB, no network, no imports from the scan loop. `fix_for` is a lookup plus string
    substitution, so it is safe to call from the API per request and from tests without setup.
  • Lookup is compliance/map.py::_lookup's rule verbatim: an exact rule_id key wins; otherwise
    the LONGEST key that ends in "." and prefixes the rule id. Keys must name a registered
    detector (exact) or prefix at least one (families) — tests/test_remediation.py enforces it,
    so a fix for a rule that does not exist cannot ship.
  • Placeholders ARE the template tokens. A snippet is written with `<QUEUE_URL>`-style markers;
    `fix_for` replaces each marker whose value it can read from the resource and leaves the
    rest standing, so an unfilled value is visibly a blank to fill, never a fabricated one.
  • Every Fix says what the rescan verifies. The Verify loop (scan.py::_settle_verifications)
    resolves a finding only when the detector no longer fires, so the hint describes that
    observation, not the command.
  • This is a READ-ONLY product: nothing here runs. `read_only_note` says so where a customer
    might reasonably expect a button to do the work.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal, Optional

SnippetKind = Literal["cli", "terraform", "helm", "console", "config", "sql"]

READ_ONLY = ("VectaSec never changes your systems. Run this yourself (or hand it to the owner), "
             "then press Verify: a rescan confirms the fix and closes the finding.")


@dataclass
class Snippet:
    kind: SnippetKind
    title: str
    body: str


@dataclass
class Fix:
    summary: str
    steps: list[str]
    snippets: list[Snippet]
    verify_hint: str
    read_only_note: Optional[str] = READ_ONLY

    def to_dict(self) -> dict:
        return asdict(self)


def _f(summary: str, steps: list[str], snippets: list[Snippet], verify: str,
       note: Optional[str] = READ_ONLY) -> Fix:
    return Fix(summary=summary, steps=steps, snippets=snippets, verify_hint=verify,
               read_only_note=note)


def _cli(title: str, body: str) -> Snippet:
    return Snippet("cli", title, body.strip("\n"))


def _tf(title: str, body: str) -> Snippet:
    return Snippet("terraform", title, body.strip("\n"))


def _cfg(title: str, body: str) -> Snippet:
    return Snippet("config", title, body.strip("\n"))


def _helm(title: str, body: str) -> Snippet:
    return Snippet("helm", title, body.strip("\n"))


def _console(title: str, body: str) -> Snippet:
    return Snippet("console", title, body.strip("\n"))


# ═══ Kafka ═════════════════════════════════════════════════════════════════
_KAFKA_CLIENT_CFG = _cfg("client.properties (admin credentials for kafka-acls.sh / kafka-configs.sh)", """
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-512
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required \\
  username="<ADMIN_USER>" password="<ADMIN_PASSWORD>";
""")

_KAFKA_FIXES: dict[str, Fix] = {
    "KAFKA.ACL.WILDCARD_PRINCIPAL": _f(
        "Replace the `User:*` ACL with per-principal grants, then remove the wildcard.",
        ["Grant each real client principal the exact operation it needs on the exact resource "
         "(add FIRST — removing the wildcard first breaks clients between the two commands).",
         "Remove the `User:*` binding. `--remove` needs the full resource specifier; quote "
         "'User:*' so the shell does not glob it.",
         "If a shared grant is truly needed, keep it but restrict the operation (DESCRIBE, "
         "not ALL/WRITE)."],
        [_cli("Add the scoped grant, then remove the wildcard", """
kafka-acls.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --add --allow-principal 'User:<PRINCIPAL>' --operation <OPERATION> \\
  --<RESTYPE> '<RESOURCE_NAME>' --resource-pattern-type <PATTERN>

kafka-acls.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --remove --allow-principal 'User:*' --operation <OPERATION> \\
  --<RESTYPE> '<RESOURCE_NAME>' --resource-pattern-type <PATTERN> --force
"""),
         _tf("Terraform (Mongey/kafka provider): one ACL per principal, no wildcard", """
resource "kafka_acl" "<PRINCIPAL>_<RESOURCE_NAME>" {
  resource_name       = "<RESOURCE_NAME>"
  resource_type       = "Topic"
  resource_pattern_type_filter = "Literal"
  acl_principal       = "User:<PRINCIPAL>"
  acl_host            = "*"
  acl_operation       = "<OPERATION>"
  acl_permission_type = "Allow"
}
"""), _KAFKA_CLIENT_CFG],
        "Rescan runs describe_acls on the cluster and passes when no ALLOW binding names "
        "principal `User:*`."),
    "KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS": _f(
        "Replace the ALL-on-`*` binding with per-resource grants listing the exact operations.",
        ["Enumerate what the principal actually does (READ/WRITE/DESCRIBE on which topics and "
         "groups) and add those LITERAL or tightly-scoped PREFIXED grants first.",
         "Remove the `*` LITERAL / ALL binding.",
         "Do NOT move the principal to super.users — that is strictly more privilege and is "
         "immune to DENY."],
        [_cli("Add scoped grants, then remove the wildcard-resource binding", """
kafka-acls.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --add --allow-principal 'User:<PRINCIPAL>' --operation Read --operation Describe \\
  --topic '<TOPIC>' --group '<CONSUMER_GROUP>'

kafka-acls.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --remove --allow-principal 'User:<PRINCIPAL>' --operation All \\
  --<RESTYPE> '*' --resource-pattern-type literal --force
"""),
         _tf("Terraform (Mongey/kafka provider)", """
resource "kafka_acl" "<PRINCIPAL>_read_<TOPIC>" {
  resource_name       = "<TOPIC>"
  resource_type       = "Topic"
  acl_principal       = "User:<PRINCIPAL>"
  acl_host            = "*"
  acl_operation       = "Read"
  acl_permission_type = "Allow"
}
"""), _KAFKA_CLIENT_CFG],
        "Rescan runs describe_acls and passes when no ALLOW binding grants ALL (or "
        "READ/WRITE/DELETE/ALTER) on the LITERAL resource `*` or ALL on the cluster."),
    "KAFKA.ACL.PREFIXED_OVERBROAD": _f(
        "Narrow the PREFIXED pattern to a single team/application namespace.",
        ["Pick a prefix that maps to one owner (e.g. `payments.`), add that grant.",
         "Remove the short/overbroad PREFIXED binding.",
         "Adopt a `<team>.<app>.<dataset>` topic naming convention so prefixes cannot leak."],
        [_cli("Replace the prefix", """
kafka-acls.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --add --allow-principal 'User:<PRINCIPAL>' --operation <OPERATION> \\
  --topic '<NARROW_PREFIX>' --resource-pattern-type prefixed

kafka-acls.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --remove --allow-principal 'User:<PRINCIPAL>' --operation <OPERATION> \\
  --topic '<RESOURCE_NAME>' --resource-pattern-type prefixed --force
"""), _KAFKA_CLIENT_CFG],
        "Rescan runs describe_acls and passes when no PREFIXED TOPIC grant has a prefix of one "
        "character or less, or matches more than half of the collected topics."),
    "KAFKA.ACL.ANONYMOUS_PRINCIPAL": _f(
        "Authenticate every listener, give the brokers a real principal, then drop the "
        "`User:ANONYMOUS` ACLs.",
        ["Move the inter-broker listener to SASL_SSL (or SSL with ssl.client.auth=required) and "
         "set security.inter.broker.protocol to match — on PLAINTEXT the brokers themselves "
         "are User:ANONYMOUS (KAFKA-3687), so the binding may be load-bearing.",
         "Grant the real broker principal ClusterAction/Describe on the cluster.",
         "Only then remove the ANONYMOUS bindings."],
        [_cli("Grant the broker principal, then remove ANONYMOUS", """
kafka-acls.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --add --allow-principal 'User:<BROKER_PRINCIPAL>' --operation ClusterAction \\
  --operation Describe --cluster

kafka-acls.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --remove --allow-principal 'User:ANONYMOUS' --operation <OPERATION> \\
  --<RESTYPE> '<RESOURCE_NAME>' --resource-pattern-type <PATTERN> --force
"""),
         _cfg("server.properties: authenticated inter-broker listener", """
listeners=SASL_SSL://0.0.0.0:9093,BROKER://0.0.0.0:9094
listener.security.protocol.map=SASL_SSL:SASL_SSL,BROKER:SASL_SSL
inter.broker.listener.name=BROKER
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-512
"""), _KAFKA_CLIENT_CFG],
        "Rescan runs describe_acls and passes when no ALLOW binding names `User:ANONYMOUS`."),
    "KAFKA.AUTHZ.NO_AUTHORIZER": _f(
        "Enable the broker authorizer and bootstrap an admin super user before ACLs go live.",
        ["Set authorizer.class.name (StandardAuthorizer on KRaft, AclAuthorizer on ZooKeeper).",
         "Name the admin and broker principals in super.users so you cannot lock yourself out.",
         "Keep allow.everyone.if.no.acl.found=false; rolling-restart the brokers."],
        [_cfg("server.properties (KRaft)", """
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer
super.users=User:admin;User:<BROKER_PRINCIPAL>
allow.everyone.if.no.acl.found=false
"""),
         _cfg("server.properties (ZooKeeper mode)", """
authorizer.class.name=kafka.security.authorizer.AclAuthorizer
super.users=User:admin;User:<BROKER_PRINCIPAL>
allow.everyone.if.no.acl.found=false
"""),
         _helm("Strimzi Kafka CR", """
spec:
  kafka:
    authorization:
      type: simple
      superUsers:
        - CN=admin
""")],
        "Rescan reads the broker config and passes when authorizer.class.name is set to a "
        "non-empty class."),
    "KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL": _f(
        "Turn off the allow-by-default fallback so a resource with no ACL is denied, not open.",
        ["Audit which clients rely on the fallback (they have no ACL at all) and grant them "
         "explicit ACLs first.",
         "Set allow.everyone.if.no.acl.found=false and rolling-restart."],
        [_cfg("server.properties", """
allow.everyone.if.no.acl.found=false
"""),
         _helm("Strimzi Kafka CR", """
spec:
  kafka:
    config:
      allow.everyone.if.no.acl.found: "false"
""")],
        "Rescan reads the broker config and passes when allow.everyone.if.no.acl.found is "
        "false or unset."),
    "KAFKA.LISTENER.PLAINTEXT": _f(
        "Replace the PLAINTEXT listener with SASL_SSL (TLS plus authentication).",
        ["Provision a keystore/truststore per broker.",
         "Add a SASL_SSL listener on a new port, migrate clients, then remove the PLAINTEXT one.",
         "If the listener is inter-broker, update inter.broker.listener.name in the same step."],
        [_cfg("server.properties", """
listeners=SASL_SSL://0.0.0.0:9093
advertised.listeners=SASL_SSL://<BROKER_HOST>:9093
listener.security.protocol.map=SASL_SSL:SASL_SSL
sasl.enabled.mechanisms=SCRAM-SHA-512
ssl.keystore.location=/etc/kafka/ssl/broker.keystore.p12
ssl.keystore.password=<KEYSTORE_PASSWORD>
ssl.truststore.location=/etc/kafka/ssl/truststore.p12
ssl.truststore.password=<TRUSTSTORE_PASSWORD>
"""),
         _helm("Strimzi Kafka CR listener", """
spec:
  kafka:
    listeners:
      - name: tls
        port: 9093
        type: internal
        tls: true
        authentication:
          type: scram-sha-512
""")],
        "Rescan reads listeners / listener.security.protocol.map and passes when no listener "
        "resolves to PLAINTEXT."),
    "KAFKA.LISTENER.SASL_PLAINTEXT": _f(
        "Upgrade the SASL_PLAINTEXT listener to SASL_SSL so credentials are not sent in clear.",
        ["Provision TLS material, add the SASL_SSL listener, migrate clients, retire "
         "SASL_PLAINTEXT. With PLAIN the password crosses the wire readable; with SCRAM the "
         "hash exchange is still replayable without TLS."],
        [_cfg("server.properties", """
listeners=SASL_SSL://0.0.0.0:9093
listener.security.protocol.map=SASL_SSL:SASL_SSL
ssl.keystore.location=/etc/kafka/ssl/broker.keystore.p12
ssl.keystore.password=<KEYSTORE_PASSWORD>
""")],
        "Rescan passes when no listener resolves to SASL_PLAINTEXT."),
    "KAFKA.TOPIC.AUTO_CREATE_ENABLED": _f(
        "Disable topic auto-creation; create topics deliberately with the right ACLs.",
        ["Set auto.create.topics.enable=false (static broker config: rolling restart).",
         "Create any topics producers relied on being auto-created."],
        [_cfg("server.properties", """
auto.create.topics.enable=false
"""),
         _cli("Create topics explicitly", """
kafka-topics.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --create --topic <TOPIC> --partitions 6 --replication-factor 3
"""),
         _helm("Strimzi Kafka CR", """
spec:
  kafka:
    config:
      auto.create.topics.enable: "false"
""")],
        "Rescan reads the broker config and passes when auto.create.topics.enable is false."),
    "KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED": _f(
        "Require client certificates on the SSL listener (or add SASL on top of it).",
        ["Set ssl.client.auth=required per listener (dynamic per-broker config) or globally.",
         "Issue client certificates to every client first, or switch the listener to SASL_SSL."],
        [_cli("Dynamic per-listener update (no restart)", """
kafka-configs.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --entity-type brokers --entity-name <BROKER_ID> --alter \\
  --add-config listener.name.<LISTENER_NAME>.ssl.client.auth=required
"""),
         _cfg("server.properties", """
ssl.client.auth=required
ssl.truststore.location=/etc/kafka/ssl/truststore.p12
ssl.truststore.password=<TRUSTSTORE_PASSWORD>
""")],
        "Rescan passes when every SSL listener has ssl.client.auth=required."),
}

# ═══ RabbitMQ ══════════════════════════════════════════════════════════════
_RMQ_FIXES: dict[str, Fix] = {
    "RABBITMQ.USER.DEFAULT_GUEST_PRESENT": _f(
        "Create a named administrator, then delete the `guest` account.",
        ["Add a real admin with a strong password and administrator tag.",
         "Grant it permissions on every vhost you manage.",
         "Delete guest. Nothing ships depending on it except local dev tooling."],
        [_cli("rabbitmqctl", """
rabbitmqctl add_user <ADMIN_USER> '<ADMIN_PASSWORD>'
rabbitmqctl set_user_tags <ADMIN_USER> administrator
rabbitmqctl set_permissions -p / <ADMIN_USER> '.*' '.*' '.*'
rabbitmqctl delete_user guest
"""),
         _cli("Management HTTP API", """
curl -u <ADMIN_USER>:<ADMIN_PASSWORD> -X DELETE <RABBITMQ_URL>/api/users/guest
"""),
         _tf("Terraform (cyrilgdn/rabbitmq)", """
resource "rabbitmq_user" "admin" {
  name     = "<ADMIN_USER>"
  password = var.admin_password
  tags     = ["administrator"]
}
# and remove any rabbitmq_user "guest" resource from state / code
""")],
        "Rescan lists /api/users and passes when no user named `guest` exists."),
    "RABBITMQ.USER.GUEST_DEFAULT_PASSWORD_REMOTE": _f(
        "Rotate (or delete) guest and confine it to loopback.",
        ["Change the guest password immediately, or delete the user.",
         "Restore the loopback restriction so guest can never log in remotely again."],
        [_cli("rabbitmqctl", """
rabbitmqctl change_password guest '<NEW_PASSWORD>'
# preferred:
rabbitmqctl delete_user guest
"""),
         _cfg("rabbitmq.conf", """
loopback_users.guest = true
""")],
        "Rescan probes /api/whoami as guest/guest from outside the broker and passes when the "
        "login is refused."),
    "RABBITMQ.USER.GUEST_REMOTE_LOGIN": _f(
        "Restore the loopback-only restriction for `guest`.",
        ["Set loopback_users.guest = true (the shipped default) and restart, or delete guest."],
        [_cfg("rabbitmq.conf", """
loopback_users.guest = true
"""),
         _helm("Bitnami / cluster-operator extraConfiguration", """
rabbitmq:
  additionalConfig: |
    loopback_users.guest = true
""")],
        "Rescan passes when guest cannot authenticate from a non-loopback address."),
    "RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED": _f(
        "Remove ANONYMOUS from the enabled SASL mechanisms.",
        ["List only PLAIN and AMQPLAIN (or EXTERNAL for mTLS) in auth_mechanisms.",
         "On RabbitMQ 4.x also set anonymous_login_user = none."],
        [_cfg("rabbitmq.conf", """
auth_mechanisms.1 = PLAIN
auth_mechanisms.2 = AMQPLAIN
anonymous_login_user = none
""")],
        "Rescan reads the node's auth_mechanisms and passes when ANONYMOUS is absent."),
    "RABBITMQ.LISTENER.AMQP_PLAINTEXT": _f(
        "Disable the plain AMQP listener (5672) and serve AMQPS (5671) only.",
        ["Install certificates, enable listeners.ssl, migrate clients to amqps://.",
         "Set listeners.tcp = none once no client needs 5672."],
        [_cfg("rabbitmq.conf", """
listeners.tcp = none
listeners.ssl.default = 5671
ssl_options.cacertfile = /etc/rabbitmq/ssl/ca.pem
ssl_options.certfile   = /etc/rabbitmq/ssl/server.pem
ssl_options.keyfile    = /etc/rabbitmq/ssl/server-key.pem
ssl_options.verify     = verify_peer
ssl_options.fail_if_no_peer_cert = false
""")],
        "Rescan reads /api/overview listeners and passes when no `amqp` (non-TLS) listener "
        "is bound."),
    "RABBITMQ.MGMT.HTTP_API_NO_TLS": _f(
        "Serve the management UI/API over HTTPS and keep plain HTTP off the network.",
        ["Enable management.ssl.* with the broker certificate.",
         "Bind the plain HTTP listener to loopback only (it cannot be fully disabled)."],
        [_cfg("rabbitmq.conf", """
management.ssl.port       = 15671
management.ssl.cacertfile = /etc/rabbitmq/ssl/ca.pem
management.ssl.certfile   = /etc/rabbitmq/ssl/server.pem
management.ssl.keyfile    = /etc/rabbitmq/ssl/server-key.pem
management.tcp.ip         = 127.0.0.1
""")],
        "Rescan passes when the management listener in /api/overview is `https` (or the only "
        "`http` one is bound to 127.0.0.1)."),
    "RABBITMQ.PERMISSION.": _f(
        "Replace the `.*` permission regexes with patterns scoped to the user's own objects.",
        ["Decide the naming prefix the user owns (queues/exchanges it declares).",
         "Set configure/write/read regexes to that prefix — configure is the most dangerous: "
         "it allows declaring and deleting."],
        [_cli("rabbitmqctl", """
rabbitmqctl set_permissions -p '<VHOST>' '<USER>' '^<USER>-.*$' '^<USER>-.*$' '^<USER>-.*$'
"""),
         _cli("Management HTTP API", """
curl -u <ADMIN_USER>:<ADMIN_PASSWORD> -X PUT <RABBITMQ_URL>/api/permissions/<VHOST_ENC>/<USER> \\
  -H 'content-type: application/json' \\
  -d '{"configure":"^<USER>-.*$","write":"^<USER>-.*$","read":"^<USER>-.*$"}'
"""),
         _tf("Terraform (cyrilgdn/rabbitmq)", """
resource "rabbitmq_permissions" "<USER>" {
  user  = "<USER>"
  vhost = "<VHOST>"
  permissions {
    configure = "^<USER>-.*$"
    write     = "^<USER>-.*$"
    read      = "^<USER>-.*$"
  }
}
""")],
        "Rescan reads /api/permissions and passes when this user/vhost pair no longer has a "
        "`.*` configure (or all-three-wildcard) regex."),
    "RABBITMQ.USER.ADMIN_TAG_SPRAWL": _f(
        "Downgrade accounts that do not administer the broker to `monitoring` or `management`.",
        ["Keep `administrator` for one or two break-glass/operator accounts.",
         "Set the rest to monitoring (dashboards) or management (own-vhost only)."],
        [_cli("rabbitmqctl", """
rabbitmqctl set_user_tags <USER> monitoring
"""),
         _tf("Terraform (cyrilgdn/rabbitmq)", """
resource "rabbitmq_user" "<USER>" {
  name     = "<USER>"
  password = var.password
  tags     = ["monitoring"]
}
""")],
        "Rescan lists /api/users and passes when the administrator-tagged set is small "
        "relative to the user count (threshold in detect/rabbitmq.py)."),
}

# ═══ Redis ═════════════════════════════════════════════════════════════════
_REDIS_FIXES: dict[str, Fix] = {
    "REDIS.AUTH.NO_PASSWORD": _f(
        "Require authentication: a default-user password (requirepass) or, better, ACL users.",
        ["Set requirepass (or `ACL SETUSER default ... >password`) and persist it.",
         "Update every client with the credential before restarting anything."],
        [_cli("redis-cli (live, then persisted)", """
redis-cli -h <HOST> CONFIG SET requirepass '<PASSWORD>'
redis-cli -h <HOST> -a '<PASSWORD>' CONFIG REWRITE
"""),
         _cfg("redis.conf", """
requirepass <PASSWORD>
"""),
         _helm("Bitnami redis chart values", """
auth:
  enabled: true
  existingSecret: redis-auth
  existingSecretPasswordKey: redis-password
""")],
        "Rescan connects without credentials and passes when the server answers NOAUTH."),
    "REDIS.TLS.DISABLED": _f(
        "Enable the TLS port and close the plaintext one.",
        ["Build Redis with TLS (default in 6+), install certificate/key/CA.",
         "Set tls-port and port 0; move clients to rediss://."],
        [_cfg("redis.conf", """
port 0
tls-port 6379
tls-cert-file /etc/redis/tls/redis.crt
tls-key-file  /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt
tls-auth-clients optional
"""),
         _helm("Bitnami redis chart values", """
tls:
  enabled: true
  authClients: false
  existingSecret: redis-tls
  certFilename: tls.crt
  certKeyFilename: tls.key
  certCAFilename: ca.crt
""")],
        "Rescan passes when the configured port negotiates TLS (plain connect is refused)."),
    "REDIS.USER.NOPASS": _f(
        "Give the ACL user a password (or disable it) — `nopass` is an open door.",
        ["Set a password with `>` and drop nopass via resetpass.",
         "Persist with ACL SAVE (aclfile) or CONFIG REWRITE (users in redis.conf)."],
        [_cli("redis-cli", """
redis-cli -h <HOST> -a '<ADMIN_PASSWORD>' ACL SETUSER <USER> resetpass '><PASSWORD>'
redis-cli -h <HOST> -a '<ADMIN_PASSWORD>' ACL SAVE
"""),
         _cfg("users.acl", """
user <USER> on ><PASSWORD> ~app:* &* -@all +@read +@write
""")],
        "Rescan runs ACL LIST and passes when user `<USER>` no longer carries the nopass flag."),
    "REDIS.NETWORK.BIND_ALL": _f(
        "Bind Redis to the interfaces that need it, not 0.0.0.0.",
        ["List the private IP(s) clients use plus loopback.",
         "Keep protected-mode yes and a password as well — binding is one layer."],
        [_cli("redis-cli", """
redis-cli -h <HOST> -a '<ADMIN_PASSWORD>' CONFIG SET bind '127.0.0.1 <PRIVATE_IP>'
redis-cli -h <HOST> -a '<ADMIN_PASSWORD>' CONFIG REWRITE
"""),
         _cfg("redis.conf", """
bind 127.0.0.1 -::1 <PRIVATE_IP>
""")],
        "Rescan reads CONFIG GET bind and passes when it no longer contains 0.0.0.0 / *."),
    "REDIS.NETWORK.PROTECTED_MODE_OFF": _f(
        "Turn protected mode back on.",
        ["Set protected-mode yes; if clients then fail, they were reaching an unauthenticated "
         "Redis over a non-loopback interface — fix that with auth, not by disabling the guard."],
        [_cli("redis-cli", """
redis-cli -h <HOST> -a '<ADMIN_PASSWORD>' CONFIG SET protected-mode yes
redis-cli -h <HOST> -a '<ADMIN_PASSWORD>' CONFIG REWRITE
"""),
         _cfg("redis.conf", """
protected-mode yes
""")],
        "Rescan reads CONFIG GET protected-mode and passes when it is `yes`."),
}

# ═══ Kong ══════════════════════════════════════════════════════════════════
_KONG_FIXES: dict[str, Fix] = {
    "KONG.ADMIN.UNAUTHENTICATED": _f(
        "Put the Admin API behind authentication: loopback-only, then expose it through Kong "
        "itself with key-auth (OSS) or enable RBAC (Enterprise).",
        ["Bind admin_listen to 127.0.0.1.",
         "Create a Service+Route that proxies to the loopback Admin API and attach key-auth "
         "(and an IP allowlist).",
         "Enterprise: set enforce_rbac = on and create an admin with a token."],
        [_cfg("kong.conf", """
admin_listen = 127.0.0.1:8001, 127.0.0.1:8444 ssl
# Enterprise:
# enforce_rbac = on
"""),
         _cli("Loopback proxy with key-auth (OSS)", """
curl -X POST http://127.0.0.1:8001/services --data name=admin-api --data url=http://127.0.0.1:8001
curl -X POST http://127.0.0.1:8001/services/admin-api/routes --data name=admin-api --data 'paths[]=/admin-api'
curl -X POST http://127.0.0.1:8001/services/admin-api/plugins --data name=key-auth
curl -X POST http://127.0.0.1:8001/consumers --data username=ops
curl -X POST http://127.0.0.1:8001/consumers/ops/key-auth
"""),
         _helm("Kong Helm values", """
admin:
  enabled: true
  http:
    enabled: false
  tls:
    enabled: true
  ingress:
    enabled: false
env:
  admin_listen: "127.0.0.1:8444 ssl"
""")],
        "Rescan requests the Admin API root without credentials and passes when it is refused "
        "(401/403) or unreachable."),
    "KONG.ADMIN.LISTEN_WILDCARD": _f(
        "Stop binding the Admin API to every interface.",
        ["Set admin_listen (or KONG_ADMIN_LISTEN) to loopback or a management-network IP.",
         "Reload Kong."],
        [_cfg("kong.conf", """
admin_listen = 127.0.0.1:8001, 127.0.0.1:8444 ssl
"""),
         _cli("Container / env", """
export KONG_ADMIN_LISTEN='127.0.0.1:8001, 127.0.0.1:8444 ssl'
kong reload
""")],
        "Rescan reads / (configuration.admin_listen) and passes when no admin listener binds "
        "0.0.0.0 or ::."),
    "KONG.ROUTE.NO_AUTH_PLUGIN": _f(
        "Attach an authentication plugin to the route (or its service).",
        ["Choose key-auth, jwt, oauth2, basic-auth or openid-connect.",
         "Create credentials for each consumer BEFORE enabling the plugin, or the route goes "
         "dark for them."],
        [_cli("Admin API", """
curl -X POST <KONG_ADMIN_URL>/routes/<ROUTE_ID>/plugins \\
  --data name=key-auth --data config.key_names=apikey --data config.hide_credentials=true
"""),
         _cfg("decK kong.yaml", """
routes:
  - name: <ROUTE_NAME>
    plugins:
      - name: key-auth
        config:
          key_names: [apikey]
          hide_credentials: true
"""),
         _tf("Terraform (kong/kong provider)", """
resource "kong_plugin" "<ROUTE_NAME>_key_auth" {
  name        = "key-auth"
  route_id    = "<ROUTE_ID>"
  config_json = jsonencode({ key_names = ["apikey"], hide_credentials = true })
}
""")],
        "Rescan reads /plugins for the route, its service and global scope, and passes when an "
        "enabled auth plugin applies to route <ROUTE_ID>."),
    "KONG.ROUTE.HTTP_PROTOCOL_ALLOWED": _f(
        "Restrict the route to https and redirect plaintext.",
        ["PATCH protocols to https only; set https_redirect_status_code so old links upgrade."],
        [_cli("Admin API", """
curl -X PATCH <KONG_ADMIN_URL>/routes/<ROUTE_ID> \\
  --data 'protocols[]=https' --data https_redirect_status_code=301
"""),
         _cfg("decK kong.yaml", """
routes:
  - name: <ROUTE_NAME>
    protocols: [https]
    https_redirect_status_code: 301
""")],
        "Rescan reads the route and passes when `protocols` contains no `http`."),
    "KONG.ROUTE.NO_RATE_LIMITING": _f(
        "Add rate-limiting to the route.",
        ["Start with a per-consumer (or per-IP) minute budget; use the redis policy on "
         "multi-node clusters."],
        [_cli("Admin API", """
curl -X POST <KONG_ADMIN_URL>/routes/<ROUTE_ID>/plugins \\
  --data name=rate-limiting --data config.minute=60 --data config.policy=local \\
  --data config.fault_tolerant=false
"""),
         _cfg("decK kong.yaml", """
routes:
  - name: <ROUTE_NAME>
    plugins:
      - name: rate-limiting
        config:
          minute: 60
          policy: local
          fault_tolerant: false
""")],
        "Rescan passes when an enabled rate-limiting (or rate-limiting-advanced) plugin applies "
        "to route <ROUTE_ID>."),
    "KONG.CONSUMER.NO_CREDENTIALS": _f(
        "Give the consumer a credential, or delete it.",
        ["A consumer without credentials cannot authenticate and is dead config — unless an "
         "`anonymous` plugin option points at it, in which case it is an unauthenticated path."],
        [_cli("Admin API", """
# issue a credential:
curl -X POST <KONG_ADMIN_URL>/consumers/<CONSUMER>/key-auth
# or remove the consumer:
curl -X DELETE <KONG_ADMIN_URL>/consumers/<CONSUMER>
""")],
        "Rescan lists the consumer's credential endpoints and passes when at least one "
        "credential exists, or the consumer is gone."),
}

# ═══ AWS ═══════════════════════════════════════════════════════════════════
_AWS_FIXES: dict[str, Fix] = {
    "AWS.SQS.QUEUE_POLICY_PUBLIC": _f(
        "Replace the `Principal: *` queue policy with one scoped to the producing account/service.",
        ["Write a policy naming the exact principal (account, role or service) and, for "
         "SNS/EventBridge producers, an aws:SourceArn condition.",
         "Apply it with set-queue-attributes (this REPLACES the whole policy)."],
        [_cli("AWS CLI", """
cat > policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ProducerOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:role/<PRODUCER_ROLE>"},
    "Action": ["sqs:SendMessage"],
    "Resource": "<QUEUE_ARN>"
  }]
}
EOF
aws sqs set-queue-attributes --region <REGION> --queue-url <QUEUE_URL> \\
  --attributes Policy="$(jq -c . policy.json)"
"""),
         _tf("Terraform", """
resource "aws_sqs_queue_policy" "scoped" {
  queue_url = "<QUEUE_URL>"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ProducerOnly"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::<ACCOUNT_ID>:role/<PRODUCER_ROLE>" }
      Action    = ["sqs:SendMessage"]
      Resource  = "<QUEUE_ARN>"
    }]
  })
}
""")],
        "Rescan reads the queue's Policy attribute and passes when no Allow statement has a "
        "wildcard principal without a restricting condition."),
    "AWS.SQS.POLICY_WILDCARD_ACTION": _f(
        "Enumerate the SQS actions the principal needs instead of `sqs:*`.",
        ["Producers need sqs:SendMessage; consumers need ReceiveMessage, DeleteMessage, "
         "GetQueueAttributes, ChangeMessageVisibility."],
        [_cli("AWS CLI", """
aws sqs set-queue-attributes --region <REGION> --queue-url <QUEUE_URL> \\
  --attributes Policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<ACCOUNT_ID>:role/<CONSUMER_ROLE>"},"Action":["sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes","sqs:ChangeMessageVisibility"],"Resource":"<QUEUE_ARN>"}]}'
"""),
         _tf("Terraform", """
resource "aws_sqs_queue_policy" "scoped" {
  queue_url = "<QUEUE_URL>"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::<ACCOUNT_ID>:role/<CONSUMER_ROLE>" }
      Action    = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility"]
      Resource  = "<QUEUE_ARN>"
    }]
  })
}
""")],
        "Rescan reads the queue policy and passes when no Allow statement lists `sqs:*` or `*`."),
    "AWS.SQS.ENCRYPTION_AT_REST_OFF": _f(
        "Turn on server-side encryption (SQS-managed or a KMS key).",
        ["SQS-managed SSE is free and needs no key policy; use a CMK when you need key-level "
         "access control or cross-account producers."],
        [_cli("AWS CLI", """
aws sqs set-queue-attributes --region <REGION> --queue-url <QUEUE_URL> \\
  --attributes SqsManagedSseEnabled=true
# or with a customer-managed key:
# aws sqs set-queue-attributes --region <REGION> --queue-url <QUEUE_URL> \\
#   --attributes KmsMasterKeyId=alias/<KEY_ALIAS>,KmsDataKeyReusePeriodSeconds=300
"""),
         _tf("Terraform", """
resource "aws_sqs_queue" "q" {
  name                    = "<NAME>"
  sqs_managed_sse_enabled = true
}
""")],
        "Rescan reads KmsMasterKeyId / SqsManagedSseEnabled and passes when either is set."),
    "AWS.SNS.TOPIC_POLICY_PUBLIC": _f(
        "Scope the topic policy to known publishers and subscribers.",
        ["Name the exact principals; add aws:SourceOwner / aws:SourceArn conditions for "
         "service publishers (S3, CloudWatch, EventBridge)."],
        [_cli("AWS CLI", """
cat > policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "OwnerOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::<ACCOUNT_ID>:root"},
    "Action": ["sns:Publish", "sns:Subscribe", "sns:Receive"],
    "Resource": "<TOPIC_ARN>",
    "Condition": {"StringEquals": {"aws:SourceOwner": "<ACCOUNT_ID>"}}
  }]
}
EOF
aws sns set-topic-attributes --region <REGION> --topic-arn <TOPIC_ARN> \\
  --attribute-name Policy --attribute-value file://policy.json
"""),
         _tf("Terraform", """
resource "aws_sns_topic_policy" "scoped" {
  arn = "<TOPIC_ARN>"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::<ACCOUNT_ID>:root" }
      Action    = ["sns:Publish", "sns:Subscribe", "sns:Receive"]
      Resource  = "<TOPIC_ARN>"
      Condition = { StringEquals = { "aws:SourceOwner" = "<ACCOUNT_ID>" } }
    }]
  })
}
""")],
        "Rescan reads the topic Policy attribute and passes when no Allow statement has an "
        "unconditioned wildcard principal."),
    "AWS.EVENTBRIDGE.BUS_POLICY_PUBLIC": _f(
        "Remove the open bus permission and grant PutEvents to specific accounts.",
        ["remove-permission drops the existing statements; put-permission adds a scoped one "
         "(or an organization condition)."],
        [_cli("AWS CLI", """
aws events remove-permission --region <REGION> --event-bus-name <BUS_NAME> --remove-all-permissions
aws events put-permission --region <REGION> --event-bus-name <BUS_NAME> \\
  --action events:PutEvents --principal <PRODUCER_ACCOUNT_ID> --statement-id AllowProducerAccount
"""),
         _tf("Terraform", """
resource "aws_cloudwatch_event_permission" "producer" {
  event_bus_name = "<BUS_NAME>"
  principal      = "<PRODUCER_ACCOUNT_ID>"
  statement_id   = "AllowProducerAccount"
  action         = "events:PutEvents"
}
""")],
        "Rescan reads the bus policy and passes when no statement allows `*` without a "
        "condition."),
    "AWS.MSK.CLIENT_PLAINTEXT_IN_TRANSIT": _f(
        "Require TLS between clients and brokers.",
        ["update-security needs the cluster's current version string (describe-cluster).",
         "Move clients to the TLS bootstrap string (port 9094 / 9096 / 9098) first."],
        [_cli("AWS CLI", """
VER=$(aws kafka describe-cluster --region <REGION> --cluster-arn <CLUSTER_ARN> --query ClusterInfo.CurrentVersion --output text)
aws kafka update-security --region <REGION> --cluster-arn <CLUSTER_ARN> --current-version "$VER" \\
  --encryption-info '{"EncryptionInTransit":{"ClientBroker":"TLS"}}'
"""),
         _tf("Terraform", """
resource "aws_msk_cluster" "c" {
  # ...
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}
""")],
        "Rescan reads EncryptionInfo.EncryptionInTransit.ClientBroker and passes when it is TLS."),
    "AWS.MSK.UNAUTHENTICATED_ACCESS": _f(
        "Disable unauthenticated access and enable IAM (or SASL/SCRAM) authentication.",
        ["Enable IAM auth first, migrate clients to the IAM bootstrap string (9098), then "
         "disable Unauthenticated."],
        [_cli("AWS CLI", """
VER=$(aws kafka describe-cluster --region <REGION> --cluster-arn <CLUSTER_ARN> --query ClusterInfo.CurrentVersion --output text)
aws kafka update-security --region <REGION> --cluster-arn <CLUSTER_ARN> --current-version "$VER" \\
  --client-authentication '{"Sasl":{"Iam":{"Enabled":true}},"Unauthenticated":{"Enabled":false}}'
"""),
         _tf("Terraform", """
resource "aws_msk_cluster" "c" {
  # ...
  client_authentication {
    sasl { iam = true }
    unauthenticated = false
  }
}
""")],
        "Rescan reads ClientAuthentication and passes when Unauthenticated.Enabled is false."),
    "AWS.MSK.PUBLIC_ACCESS_ENABLED": _f(
        "Turn off public access; reach the cluster over VPC peering, PrivateLink or a VPN.",
        ["update-connectivity with PublicAccess DISABLED; clients outside the VPC need a "
         "private path first."],
        [_cli("AWS CLI", """
VER=$(aws kafka describe-cluster --region <REGION> --cluster-arn <CLUSTER_ARN> --query ClusterInfo.CurrentVersion --output text)
aws kafka update-connectivity --region <REGION> --cluster-arn <CLUSTER_ARN> --current-version "$VER" \\
  --connectivity-info '{"PublicAccess":{"Type":"DISABLED"}}'
"""),
         _tf("Terraform", """
resource "aws_msk_cluster" "c" {
  # ...
  broker_node_group_info {
    connectivity_info {
      public_access { type = "DISABLED" }
    }
  }
}
""")],
        "Rescan reads BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess and passes when the "
        "type is DISABLED."),
    "AWS.APIGW.ROUTE_NO_AUTHORIZER": _f(
        "Attach an authorizer (JWT, Lambda or IAM) to every route/method that is not meant "
        "to be public.",
        ["HTTP API (v2): create a JWT authorizer and set it on the route.",
         "REST API (v1): set authorizationType on the method and redeploy the stage."],
        [_cli("HTTP API (v2)", """
AUTH=$(aws apigatewayv2 create-authorizer --region <REGION> --api-id <API_ID> --name jwt \\
  --authorizer-type JWT --identity-source '$request.header.Authorization' \\
  --jwt-configuration Audience=<AUDIENCE>,Issuer=<ISSUER_URL> --query AuthorizerId --output text)
aws apigatewayv2 update-route --region <REGION> --api-id <API_ID> --route-id <ROUTE_ID> \\
  --authorization-type JWT --authorizer-id "$AUTH"
"""),
         _cli("REST API (v1)", """
aws apigateway update-method --region <REGION> --rest-api-id <API_ID> --resource-id <RESOURCE_ID> \\
  --http-method <METHOD> --patch-operations op=replace,path=/authorizationType,value=AWS_IAM
aws apigateway create-deployment --region <REGION> --rest-api-id <API_ID> --stage-name <STAGE>
"""),
         _tf("Terraform (HTTP API)", """
resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = "<API_ID>"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "jwt"
  jwt_configuration {
    audience = ["<AUDIENCE>"]
    issuer   = "<ISSUER_URL>"
  }
}
resource "aws_apigatewayv2_route" "r" {
  api_id             = "<API_ID>"
  route_key          = "<ROUTE_KEY>"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}
""")],
        "Rescan lists the API's routes/methods and passes when none has authorizationType NONE."),
}

# ═══ Kubernetes ════════════════════════════════════════════════════════════
_K8S_FIXES: dict[str, Fix] = {
    "K8S.MESH.MTLS_NOT_STRICT": _f(
        "Set the PeerAuthentication mode to STRICT.",
        ["Confirm every workload in scope has a sidecar (PERMISSIVE existed to let legacy "
         "pods in).",
         "Apply STRICT at the namespace (or mesh) level; remove workload-level PERMISSIVE "
         "overrides."],
        [_helm("PeerAuthentication", """
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: <NAMESPACE>
spec:
  mtls:
    mode: STRICT
"""),
         _cli("kubectl", """
kubectl apply -n <NAMESPACE> -f peer-authentication.yaml
kubectl get peerauthentication -A
""")],
        "Rescan reads PeerAuthentication `<NAME>` in <NAMESPACE> and passes when mtls.mode is "
        "STRICT with no PERMISSIVE port overrides."),
    "K8S.MESH.AUTHZ_ALLOW_ALL": _f(
        "Replace the allow-all AuthorizationPolicy with explicit source principals.",
        ["Delete the policy with an empty `rules: [{}]` / no selector.",
         "Add a namespace default-deny and per-workload ALLOW rules naming principals."],
        [_helm("Default deny + scoped allow", """
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: <NAMESPACE>
spec: {}
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-frontend
  namespace: <NAMESPACE>
spec:
  selector:
    matchLabels:
      app: <WORKLOAD>
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/<NAMESPACE>/sa/<CALLER_SA>"]
"""),
         _cli("kubectl", """
kubectl delete authorizationpolicy <NAME> -n <NAMESPACE>
kubectl apply -n <NAMESPACE> -f authz.yaml
""")],
        "Rescan passes when AuthorizationPolicy `<NAME>` in <NAMESPACE> is gone or no longer "
        "has an unconditioned ALLOW rule."),
    "K8S.RBAC.SA_CLUSTER_ADMIN": _f(
        "Remove the ServiceAccount from cluster-admin and bind a least-privilege role instead.",
        ["List the verbs/resources the workload really uses (audit log or kubectl auth can-i).",
         "Create a Role/ClusterRole with just those; bind it; delete the cluster-admin binding."],
        [_cli("kubectl", """
kubectl delete clusterrolebinding <NAME>
"""),
         _helm("Scoped replacement", """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: <WORKLOAD>-role
  namespace: <NAMESPACE>
rules:
  - apiGroups: [""]
    resources: ["configmaps", "pods"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: <WORKLOAD>-binding
  namespace: <NAMESPACE>
subjects:
  - kind: ServiceAccount
    name: <SERVICE_ACCOUNT>
    namespace: <NAMESPACE>
roleRef:
  kind: Role
  name: <WORKLOAD>-role
  apiGroup: rbac.authorization.k8s.io
""")],
        "Rescan lists ClusterRoleBindings and passes when no binding to cluster-admin names a "
        "ServiceAccount subject."),
    "K8S.SA.DEFAULT_BOUND": _f(
        "Stop granting roles to the namespace `default` ServiceAccount; use a dedicated one.",
        ["Create a dedicated ServiceAccount for the workload and move the binding to it.",
         "Disable token automount on `default` so pods that forgot to set one get nothing."],
        [_cli("kubectl", """
kubectl create serviceaccount <WORKLOAD>-sa -n <NAMESPACE>
kubectl patch serviceaccount default -n <NAMESPACE> \\
  -p '{"automountServiceAccountToken": false}'
# then point the (Cluster)RoleBinding subject and the pod spec at <WORKLOAD>-sa
"""),
         _helm("Pod spec", """
spec:
  serviceAccountName: <WORKLOAD>-sa
  automountServiceAccountToken: true
""")],
        "Rescan passes when no RoleBinding/ClusterRoleBinding subject is `default` in "
        "<NAMESPACE>, or its automountServiceAccountToken is false."),
    "K8S.INGRESS.NO_TLS": _f(
        "Add a TLS block to the Ingress (cert-manager can issue the certificate).",
        ["Create or reference a TLS secret for each host.",
         "Enable HTTPS redirect on the ingress controller."],
        [_helm("Ingress", """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: <NAME>
  namespace: <NAMESPACE>
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts: ["<HOST>"]
      secretName: <NAME>-tls
  rules:
    - host: <HOST>
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: <SERVICE>
                port:
                  number: 80
"""),
         _cli("kubectl", """
kubectl apply -n <NAMESPACE> -f ingress.yaml
""")],
        "Rescan reads Ingress `<NAME>` in <NAMESPACE> and passes when spec.tls covers its hosts."),
    "K8S.NETPOL.NO_DEFAULT_DENY": _f(
        "Add a default-deny NetworkPolicy to the namespace, then allow what is needed.",
        ["Apply default-deny for ingress and egress (keep DNS egress).",
         "Add per-workload allow policies; watch for breakage in staging first."],
        [_helm("Default deny", """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: <NAMESPACE>
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: <NAMESPACE>
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
"""),
         _cli("kubectl", """
kubectl apply -n <NAMESPACE> -f netpol.yaml
""")],
        "Rescan lists NetworkPolicies in <NAMESPACE> and passes when one selects every pod "
        "(empty podSelector) with an Ingress policyType and no ingress rules."),
}

# ═══ MCP ═══════════════════════════════════════════════════════════════════
_MCP_FIXES: dict[str, Fix] = {
    "MCP.AUTH.UNAUTHENTICATED_ENDPOINT": _f(
        "Require a bearer token on the MCP endpoint and advertise the authorization server.",
        ["Put the server behind an authenticating proxy (or enable the SDK's auth middleware).",
         "Serve /.well-known/oauth-protected-resource so clients can discover the AS.",
         "Return 401 with WWW-Authenticate for unauthenticated requests."],
        [_cfg("nginx in front of the MCP server", """
location /mcp {
    auth_request /_validate;
    proxy_pass http://127.0.0.1:<MCP_PORT>;
}
location = /_validate {
    internal;
    proxy_pass http://127.0.0.1:<AUTH_PORT>/introspect;
    proxy_pass_request_body off;
    proxy_set_header Authorization $http_authorization;
}
location = /.well-known/oauth-protected-resource {
    default_type application/json;
    return 200 '{"resource":"<URL>","authorization_servers":["<ISSUER_URL>"]}';
}
"""),
         _cfg("Python MCP SDK (FastMCP) token verification", """
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("server", token_verifier=MyVerifier(),
              auth=AuthSettings(issuer_url="<ISSUER_URL>", resource_server_url="<URL>",
                                required_scopes=["mcp:tools"]))
""")],
        "Rescan sends an unauthenticated initialize to <URL> and passes when it is refused "
        "with 401/403."),
    "MCP.TRANSPORT.PLAINTEXT_HTTP": _f(
        "Serve the MCP endpoint over HTTPS only.",
        ["Terminate TLS at a proxy or load balancer; redirect http:// to https://.",
         "Update the client configuration (and any OAuth metadata URLs) to the https URL."],
        [_cfg("nginx", """
server {
    listen 80;
    server_name <HOST>;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    server_name <HOST>;
    ssl_certificate     /etc/ssl/<HOST>/fullchain.pem;
    ssl_certificate_key /etc/ssl/<HOST>/privkey.pem;
    location /mcp { proxy_pass http://127.0.0.1:<MCP_PORT>; }
}
"""),
         _cli("Caddy (automatic certificates)", """
cat > Caddyfile <<'EOF'
<HOST> {
    reverse_proxy 127.0.0.1:<MCP_PORT>
}
EOF
caddy run
""")],
        "Rescan passes when the connection's MCP URL (and the advertised OAuth URLs) use "
        "https and the TLS handshake succeeds."),
}

# ═══ n8n ═══════════════════════════════════════════════════════════════════
_N8N_FIXES: dict[str, Fix] = {
    "N8N.WORKFLOW.UNAUTHENTICATED_WEBHOOK": _f(
        "Require authentication on the Webhook trigger node.",
        ["Open workflow `<WORKFLOW_NAME>` (id <WORKFLOW_ID>) and each Webhook node flagged.",
         "Set Authentication to Header Auth, Basic Auth or JWT Auth and attach a credential.",
         "Rotate the webhook path too — the old one may be cached by callers and logs.",
         "Re-activate the workflow."],
        [_console("n8n editor", """
Workflow <WORKFLOW_NAME> (<WORKFLOW_ID>) -> Webhook node -> Authentication: Header Auth
  Credential: create "webhook-caller" with header X-Api-Key = <RANDOM_SECRET>
Save -> Activate
"""),
         _cli("Or via the public API (requires N8N_PUBLIC_API)", """
curl -s -H 'X-N8N-API-KEY: <N8N_API_KEY>' <N8N_URL>/api/v1/workflows/<WORKFLOW_ID> > wf.json
# edit nodes[].parameters.authentication to "headerAuth" and add credentials.httpHeaderAuth
curl -X PUT -H 'X-N8N-API-KEY: <N8N_API_KEY>' -H 'content-type: application/json' \\
  <N8N_URL>/api/v1/workflows/<WORKFLOW_ID> --data @wf.json
""")],
        "Rescan reads the workflow's webhook trigger nodes and passes when none has "
        "authentication=none while the workflow is active."),
    "N8N.CREDENTIAL.REACHABLE_VIA_UNAUTH_WEBHOOK": _f(
        "Authenticate the webhook(s) that lead to this credential, or move the credential out "
        "of those workflows.",
        ["Fix every N8N.WORKFLOW.UNAUTHENTICATED_WEBHOOK on the workflows that use this "
         "credential.",
         "Rotate the credential if the webhook was reachable from the internet."],
        [_console("n8n editor", """
Credentials -> <NAME> -> "Used in" lists the workflows; for each, set the Webhook node
Authentication to Header/Basic/JWT and re-activate.
""")],
        "Rescan passes when no active workflow using credential `<NAME>` has an unauthenticated "
        "webhook trigger."),
}

# ═══ Credential lifecycle (per-system branches) ════════════════════════════
_CRED_SYSTEM_SNIPPETS: dict[str, list[Snippet]] = {
    "aws": [_cli("AWS IAM access key: deactivate, confirm nothing breaks, delete", """
aws iam update-access-key --user-name <IAM_USER> --access-key-id <ACCESS_KEY_ID> --status Inactive
# wait one business cycle, watch CloudTrail for AccessDenied from this key id, then:
aws iam delete-access-key --user-name <IAM_USER> --access-key-id <ACCESS_KEY_ID>
"""),
            _cli("Rotate instead of delete", """
aws iam create-access-key --user-name <IAM_USER>
# deploy the new key, then deactivate + delete the old one as above
""")],
    "rabbitmq": [_cli("rabbitmqctl", """
rabbitmqctl change_password '<USER>' '<NEW_PASSWORD>'
# or, if the account is unused:
rabbitmqctl delete_user '<USER>'
""")],
    "kafka": [_cli("kafka-configs.sh (SCRAM credential)", """
# rotate:
kafka-configs.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --alter --entity-type users --entity-name '<USER>' \\
  --add-config 'SCRAM-SHA-512=[password=<NEW_PASSWORD>]'
# or delete an unused credential:
kafka-configs.sh --bootstrap-server <BOOTSTRAP> --command-config client.properties \\
  --alter --entity-type users --entity-name '<USER>' --delete-config 'SCRAM-SHA-512'
""")],
    "kong": [_cli("Kong Admin API", """
curl -s <KONG_ADMIN_URL>/consumers/<CONSUMER>/key-auth          # list credential ids
curl -X POST <KONG_ADMIN_URL>/consumers/<CONSUMER>/key-auth      # issue the replacement
curl -X DELETE <KONG_ADMIN_URL>/consumers/<CONSUMER>/key-auth/<CREDENTIAL_ID>
""")],
    "k8s": [_cli("kubectl (long-lived ServiceAccount token secret)", """
kubectl delete secret <SECRET> -n <NAMESPACE>
# workloads should use projected, time-bound tokens (automount) instead of a stored secret;
# if an external system needs one: kubectl create token <SERVICE_ACCOUNT> -n <NAMESPACE> --duration=1h
""")],
    "redis": [_cli("redis-cli", """
redis-cli -h <HOST> -a '<ADMIN_PASSWORD>' ACL SETUSER <USER> resetpass '><NEW_PASSWORD>'
redis-cli -h <HOST> -a '<ADMIN_PASSWORD>' ACL SAVE
""")],
}


def _cred_fix(summary: str, steps: list[str], verify: str) -> Fix:
    snippets = [s for group in _CRED_SYSTEM_SNIPPETS.values() for s in group]
    return _f(summary, steps, snippets, verify)


_CRED_FIXES: dict[str, Fix] = {
    "CREDENTIAL.LIFECYCLE.NEVER_USED": _cred_fix(
        "Remove a credential that has never authenticated — it is attack surface with no owner "
        "depending on it.",
        ["Confirm with the owner that nothing is about to start using it.",
         "Deactivate first where the system supports it (AWS), then delete."],
        "Rescan re-reads the credential inventory and passes when this credential is gone or "
        "now shows a last-used timestamp."),
    "CREDENTIAL.LIFECYCLE.ROTATION_STALE": _cred_fix(
        "Rotate the credential and retire the old one.",
        ["Issue the replacement, deploy it to every consumer, then deactivate and delete the "
         "old secret.",
         "Put a rotation schedule on it (90 days is the common policy threshold)."],
        "Rescan passes when the credential's created/rotated timestamp is within the rotation "
        "window, or the credential no longer exists."),
    "CREDENTIAL.LIFECYCLE.DEFAULT_ACTIVE": _cred_fix(
        "Change or delete the vendor-default credential.",
        ["Default credentials are the first thing every scanner tries; delete the account if "
         "nothing legitimate uses it, otherwise set a strong unique secret."],
        "Rescan passes when the default account is gone or no longer accepts its default "
        "secret / is no longer flagged default by the system."),
}


FIX_LIBRARY: dict[str, Fix] = {
    **_KAFKA_FIXES, **_RMQ_FIXES, **_REDIS_FIXES, **_KONG_FIXES, **_AWS_FIXES,
    **_K8S_FIXES, **_MCP_FIXES, **_N8N_FIXES, **_CRED_FIXES,
}


# ═══ Lookup and templating ═════════════════════════════════════════════════
def lookup(rule_id: str) -> Optional[tuple[str, Fix]]:
    """compliance/map.py::_lookup, verbatim: exact key, else the longest '.'-terminated prefix."""
    if rule_id in FIX_LIBRARY:
        return rule_id, FIX_LIBRARY[rule_id]
    best = None
    for key, value in FIX_LIBRARY.items():
        if key.endswith(".") and rule_id.startswith(key):
            if best is None or len(key) > len(best[0]):
                best = (key, value)
    return best


def _first(*vals) -> Optional[str]:
    for v in vals:
        if v not in (None, "", "?"):
            return str(v)
    return None


def _owner_principal(labels: dict, system: str) -> Optional[str]:
    """identity.py builds credential ext ids as cred:<system>:<slug(owner_ext)>:<type> and labels
    `owner` with the identity ext id identity:<system>:<slug(name)>. The slug is lossy, so it is
    offered only as a hint; raw.owner_label / raw.principal win when present."""
    owner = labels.get("owner") or ""
    prefix = f"identity:{system}:"
    if owner.startswith(prefix):
        return owner[len(prefix):] or None
    return None


def _context(rule_id: str, labels: dict, raw: dict, name: Optional[str], ext_id: Optional[str],
             namespace: Optional[str]) -> dict[str, str]:
    """Token -> value for the markers a snippet may carry. Only values the connectors and
    detectors actually record are read; everything else stays a visible placeholder."""
    ctx: dict[str, Optional[str]] = {}
    fam = rule_id.split(".", 1)[0]

    if fam == "KAFKA":
        host, port = labels.get("host"), labels.get("port")
        ctx["BOOTSTRAP"] = f"{host}:{port}" if host and port else None
        ctx["BROKER_HOST"] = host
        ctx["BROKER_ID"] = _first(raw.get("node_id"), raw.get("broker_id"), name)
    elif fam == "RABBITMQ":
        ctx["USER"] = _first(labels.get("user"), raw.get("name") if raw.get("role") != "cluster" else None,
                             name if rule_id.startswith(("RABBITMQ.USER.", "RABBITMQ.PERMISSION.")) else None)
        ctx["VHOST"] = _first(labels.get("vhost"), raw.get("vhost"))
        ctx["RABBITMQ_URL"] = _first(labels.get("url"))
        if ctx.get("VHOST"):
            ctx["VHOST_ENC"] = "%2F" if ctx["VHOST"] == "/" else ctx["VHOST"]
    elif fam == "REDIS":
        ctx["USER"] = _first(raw.get("user"), raw.get("name") if rule_id.startswith("REDIS.USER.") else None,
                             name if rule_id.startswith("REDIS.USER.") else None)
        ctx["HOST"] = _first(labels.get("host"), raw.get("host"))
    elif fam == "KONG":
        if ext_id and ext_id.startswith("kong-route-"):
            ctx["ROUTE_ID"] = ext_id[len("kong-route-"):]
        ctx["ROUTE_NAME"] = name if rule_id.startswith("KONG.ROUTE.") else None
        ctx["CONSUMER"] = name if rule_id.startswith("KONG.CONSUMER.") else None
    elif fam == "AWS":
        ctx["REGION"] = _first(labels.get("region"), raw.get("region"), namespace)
        ctx["ACCOUNT_ID"] = _first(raw.get("account"))
        ctx["QUEUE_URL"] = _first(raw.get("queue_url"))
        ctx["QUEUE_ARN"] = _first(raw.get("queue_arn"), ext_id if rule_id.startswith("AWS.SQS.") else None)
        ctx["TOPIC_ARN"] = ext_id if rule_id.startswith("AWS.SNS.") else None
        ctx["BUS_NAME"] = name if rule_id.startswith("AWS.EVENTBRIDGE.") else None
        ctx["CLUSTER_ARN"] = _first(raw.get("cluster_arn"), ext_id if rule_id.startswith("AWS.MSK.") else None)
        ctx["API_ID"] = _first(raw.get("api_id"))
        ctx["NAME"] = name
    elif fam == "K8S":
        ctx["NAMESPACE"] = _first(raw.get("namespace"), namespace,
                                  (raw.get("name") or name) if rule_id.startswith("K8S.NETPOL.") else None)
        ctx["NAME"] = _first(raw.get("name"), name)
    elif fam == "MCP":
        ctx["URL"] = _first(raw.get("url"))
        url = ctx.get("URL") or ""
        if "://" in url:
            ctx["HOST"] = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] or None
    elif fam == "N8N":
        ctx["WORKFLOW_ID"] = _first(raw.get("id"))
        ctx["WORKFLOW_NAME"] = _first(raw.get("name"), name)
        ctx["NAME"] = name
    elif fam == "CREDENTIAL":
        system = _first(labels.get("system"), raw.get("system")) or ""
        principal = _first(raw.get("owner_label"), raw.get("principal"), _owner_principal(labels, system))
        ctx["IAM_USER"] = principal if system == "aws" else None
        ctx["USER"] = principal if system in ("rabbitmq", "kafka", "redis") else None
        ctx["CONSUMER"] = principal if system == "kong" else None
        ctx["SERVICE_ACCOUNT"] = principal if system == "k8s" else None
        ctx["NAMESPACE"] = _first(raw.get("namespace"), namespace)
        ctx["SECRET"] = _first(raw.get("secret_name"))
        ctx["ACCESS_KEY_ID"] = _first(raw.get("access_key_id"))

    return {k: v for k, v in ctx.items() if v}


def _render(text: str, ctx: dict[str, str]) -> str:
    for token, value in ctx.items():
        text = text.replace(f"<{token}>", value)
    return text


def fix_for(rule_id: str, labels: Optional[dict] = None, raw: Optional[dict] = None, *,
            name: Optional[str] = None, ext_id: Optional[str] = None,
            namespace: Optional[str] = None) -> Optional[Fix]:
    """The Fix for a rule, templated with what is known about the resource it fired on.

    `labels`/`raw` are the resource's columns as the connector recorded them; `name`, `ext_id`
    and `namespace` are the sibling columns (keyword-only so the positional contract stays
    `fix_for(rule_id, labels, raw)`). Returns a NEW Fix each call; the library is never mutated.
    Unknown rule -> None, and the caller falls back to the finding's free-text remediation.
    """
    hit = lookup(rule_id)
    if hit is None:
        return None
    key, base = hit
    labels = labels or {}
    raw = raw or {}
    ctx = _context(rule_id, labels, raw, name, ext_id, namespace)

    snippets = list(base.snippets)
    if key.startswith("CREDENTIAL.LIFECYCLE."):
        system = _first(labels.get("system"), raw.get("system"))
        if system in _CRED_SYSTEM_SNIPPETS:
            snippets = list(_CRED_SYSTEM_SNIPPETS[system])

    return Fix(
        summary=_render(base.summary, ctx),
        steps=[_render(s, ctx) for s in base.steps],
        snippets=[Snippet(s.kind, _render(s.title, ctx), _render(s.body, ctx)) for s in snippets],
        verify_hint=_render(base.verify_hint, ctx),
        read_only_note=base.read_only_note,
    )


def coverage(detectors: Optional[list] = None) -> dict:
    """How much of the registered rulepack has an exact fix. Computed against the live
    registry so the number can never drift from what a scan can actually emit."""
    if detectors is None:
        from .registry import DETECTORS
        from . import detect as _detect  # noqa: F401 — auto-registration
        detectors = DETECTORS
    rules = {d.rule_id for d in detectors}
    return {"rules_with_fix": sum(1 for r in rules if lookup(r) is not None),
            "rules_total": len(rules)}


# Exposed so tests can prove every prefix key resolves to at least one detector.
PREFIX_KEYS: tuple[str, ...] = tuple(k for k in FIX_LIBRARY if k.endswith("."))
