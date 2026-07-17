# VectaSec Connector Platform APIs — Implementation Reference

**Written:** 2026-07-17
**Purpose:** Exact read-only client APIs the VectaSec connectors call. Every shape below was
captured from a **live system**, not copied from documentation, except where explicitly marked
otherwise.

## How this was verified

Docs lie and go stale. Where possible I stood up the real software locally and captured actual
responses. Versions actually exercised:

| Target | Version exercised | Method |
|---|---|---|
| Kafka broker | Apache Kafka **4.3.1** (KRaft, `apache/kafka:latest`) | live broker in Docker |
| confluent-kafka-python | **2.15.0** (librdkafka 2.15.0) | real `AdminClient` calls against that broker |
| Kong Gateway | **3.9.3** OSS (`kong:latest`, DB-less) | live Admin API, real `curl` |
| RabbitMQ | **4.3.2** (`rabbitmq:4-management`, Erlang 27.3.4.14) | live Management API, real `curl` |
| MCP Python SDK | **1.28.1** | real client → real FastMCP server, plus raw HTTP wire capture |
| MCP protocol | **2025-11-25** (current) | negotiated live |

Anything I could not execute is flagged **confidence: low** or **confidence: medium** inline.
Nothing below is reconstructed from memory.

---

## Table of contents

1. [confluent-kafka-python](#1-confluent-kafka-python-2150)
2. [Kong Admin API](#2-kong-admin-api-393-oss)
3. [RabbitMQ Management HTTP API](#3-rabbitmq-management-http-api-432)
4. [MCP introspection over Streamable HTTP](#4-mcp-introspection-over-streamable-http)
5. [Cross-cutting traps](#5-cross-cutting-traps-worth-reading-before-you-code)

---

## 1. confluent-kafka-python (2.15.0)

**Install:** `pip install confluent-kafka==2.15.0` — requires Python **>= 3.8**.
Latest release **2.15.0**, published **2026-06-30** ([PyPI](https://pypi.org/project/confluent-kafka/)).
Verified at runtime: `confluent_kafka.libversion() == ('2.15.0', 34537727)`.

### 1.1 Import paths (exact)

All admin types are re-exported from `confluent_kafka.admin`. Use that; do not import from the
private `_config` / `_acl` / `_resource` / `_metadata` submodules.

```python
from confluent_kafka.admin import (
    AdminClient,
    ConfigResource, ConfigEntry, ConfigSource, AlterConfigOpType,
    AclBinding, AclBindingFilter, AclOperation, AclPermissionType,
    ResourceType, ResourcePatternType,
    DescribeClusterResult,
    ClusterMetadata, BrokerMetadata, TopicMetadata, PartitionMetadata,
)
from confluent_kafka import KafkaException, KafkaError
```

`Node` (used by `DescribeClusterResult`) lives in `confluent_kafka._model`. It is not re-exported
from `confluent_kafka.admin`, so treat it as duck-typed (`.id`, `.host`, `.port`, `.rack`) rather
than importing it. **confidence: high** (checked `admin/__init__.py` import list).

> Note: `confluent_kafka/admin/__init__.py` defines **no `__all__`**. Public names are the
> `# noqa: F401` re-imports at the top of that file. Source:
> [admin/\_\_init\_\_.py](https://github.com/confluentinc/confluent-kafka-python/blob/master/src/confluent_kafka/admin/__init__.py).

### 1.2 AdminClient construction

```python
AdminClient(conf: Dict[str, str | int | float | bool], **kwargs) -> AdminClient
```

`conf` is a librdkafka config dict. Minimum for a read-only posture scan:

```python
admin = AdminClient({
    "bootstrap.servers": "broker1:9092,broker2:9092",
    "socket.timeout.ms": 10000,
    # TLS / SASL as needed:
    # "security.protocol": "SASL_SSL",
    # "sasl.mechanisms": "PLAIN",
    # "sasl.username": "...",
    # "sasl.password": "...",
})
```

`AdminClient` is **not** a context manager in a way you should rely on for 2.15.0 —
just let it go out of scope. There is no `.close()` in the documented surface.

### 1.3 `list_topics(topic=None, timeout=-1) -> ClusterMetadata`

**Synchronous** — this is the one admin call that does *not* return a future.
`timeout` is in **seconds** (float), `-1` = infinite.

Live output against Kafka 4.3.1:

```
type: ClusterMetadata
cluster_id: 5L6g3nShT-eMCtK--X86sw | controller_id: 1
orig_broker_id: 1 | orig_broker_name: vs-kafka:9092/1
  broker key=1 -> id=1 host=vs-kafka port=9092 type=BrokerMetadata
  topic 'vectasec-demo': error=None n_partitions=3
    partition id=0 leader=1 replicas=[1] isrs=[1] error=None
```

Exact shapes (from `admin/_metadata.py`, confirmed live):

```python
class ClusterMetadata:
    cluster_id: Optional[str]              # None if broker doesn't support it
    controller_id: int                     # -1 if unknown
    brokers: Dict[int, BrokerMetadata]     # keyed by broker id (int)
    topics: Dict[str, TopicMetadata]       # keyed by topic name (str)
    orig_broker_id: int                    # broker this metadata came from
    orig_broker_name: Optional[str]

class BrokerMetadata:
    id: int          # -1 default
    host: Optional[str]
    port: int        # -1 default

class TopicMetadata:
    topic: Optional[str]
    partitions: Dict[int, PartitionMetadata]   # keyed by partition id (int)
    error: Optional[KafkaError]                # per-topic error, or None

class PartitionMetadata:
    id: int
    leader: int          # -1 if none
    replicas: List[int]
    isrs: List[int]
    error: Optional[KafkaError]
```

**Traps:**
- `brokers` and `topics` are **dicts, not lists**. Iterate `.values()` or `.items()`.
- `TopicMetadata.error` is per-topic and is `None` on success — **check it**. A topic can appear
  in the map with an error set (e.g. `LEADER_NOT_AVAILABLE`).
- `list_topics()` returns **internal topics too** (e.g. `__consumer_offsets`) once they exist.
  Filter on `name.startswith("__")` if VectaSec should ignore them.
- `timeout` is **seconds**, unlike most librdkafka config which is milliseconds.

### 1.4 `describe_configs(resources) -> Dict[ConfigResource, Future]`

```python
def describe_configs(
    self, resources: List[ConfigResource], **kwargs
) -> Dict[ConfigResource, concurrent.futures.Future]
```

- kwarg: `request_timeout: float` (seconds). Default `socket.timeout.ms / 1000.0`.
- Returned dict is keyed by the **`ConfigResource` object you passed in** (verified live:
  `returned dict keys type: ['ConfigResource']`). `ConfigResource` implements `__hash__`/`__eq__`
  on `(restype, name)`, so you can look up with the same object.
- `future.result()` returns `Dict[str, ConfigEntry]` keyed by config name.

**Hard constraint from the docstring** (verbatim):

> Multiple resources and resource types may be requested, but **at most one resource of type
> RESOURCE_BROKER is allowed per call** since these resource requests must be sent to the broker
> specified in the resource.

So: **one `describe_configs` call per broker**. Loop over `md.brokers` and issue a separate call
for each. Do not batch brokers.

Working, executed snippet:

```python
res = ConfigResource(ConfigResource.Type.BROKER, "1")   # name = broker id AS A STRING
futures = admin.describe_configs([res], request_timeout=10)
configs = futures[res].result(timeout=10)               # Dict[str, ConfigEntry]
entry = configs["auto.create.topics.enable"]
```

Live result: **340 config entries** returned for a single Kafka 4.3.1 broker.

#### `ConfigResource`

```python
ConfigResource(
    restype: Union[ResourceType, str, int],
    name: str,
    set_config: Optional[Dict[str, str]] = None,
    described_configs: Optional[Dict[str, ConfigEntry]] = None,
    error: Optional[Any] = None,
    incremental_configs: Optional[List[ConfigEntry]] = None,
) -> None
```

- `ConfigResource.Type` **is** `ResourceType` — verified live: `ConfigResource.Type is ResourceType → True`.
  So `ConfigResource.Type.BROKER` and `ResourceType.BROKER` are the same object. Either is fine.
- `name` for a BROKER resource is the **broker id rendered as a string** (`"1"`, not `1`).
  The enum docstring says so verbatim: *"Broker resource. Resource name is broker id."*
- Attributes: `restype`, `restype_int`, `name`, `set_config_dict`, `incremental_configs`,
  `configs`, `error`.

#### `ConfigEntry`

```python
ConfigEntry(
    name: str,
    value: Optional[str],
    source: ConfigSource = ConfigSource.UNKNOWN_CONFIG,
    is_read_only: bool = False,
    is_default: bool = False,
    is_sensitive: bool = False,
    is_synonym: bool = False,
    synonyms: Dict[str, 'ConfigEntry'] = {},
    incremental_operation: Optional[AlterConfigOpType] = None,
) -> None
```

Live sample:

```
ssl.protocol             = 'TLSv1.3' source=5 is_default=True  is_sensitive=False is_read_only=False
auto.create.topics.enable= 'true'    source=5 is_default=True  is_sensitive=False is_read_only=True
num.network.threads      = '3'       source=5 is_default=True  is_sensitive=False is_read_only=False
```

> ### ⚠️ TRAP — `ConfigEntry.source` is an `int` at runtime, not a `ConfigSource`
>
> The type hint says `source: ConfigSource`. **It is not.** Verified live:
>
> ```
> repr(e.source): 5            | type: int
> ConfigSource.DEFAULT_CONFIG  = <ConfigSource.DEFAULT_CONFIG: 5>
> e.source == ConfigSource.DEFAULT_CONFIG  ->  False        # <-- silently False!
> ConfigSource(e.source)       ->  ConfigSource.DEFAULT_CONFIG
> ```
>
> A posture check written as `if entry.source == ConfigSource.DYNAMIC_BROKER_CONFIG:` will
> **never fire** and will fail silently — no exception, just a wrong answer. Always coerce:
> `ConfigSource(entry.source)`. This is the single most dangerous detail in this document.
>
> Note this trap is **specific to `ConfigEntry.source`** (it comes straight from the C layer).
> `AclBinding` fields are properly converted to enums — see §1.5.

**Other `ConfigEntry` notes:**
- `value` is `None` when `is_sensitive == True`. Verified live: `delegation.token.secret.key`,
  `sasl.oauthbearer.assertion.private.key.passphrase`, `ssl.keystore.key` all returned
  `is_sensitive=True, value=None`. The broker redacts these — VectaSec cannot read them and
  should not try. Record presence, never value.
- `is_default=True` means the broker is running the built-in default. For posture work this is
  usually the interesting signal (e.g. `auto.create.topics.enable='true'` at default).
- `is_read_only=True` means it cannot be altered dynamically — informational only for VectaSec.

#### `ConfigSource` enum (exact members)

```python
class ConfigSource(Enum):
    UNKNOWN_CONFIG = 0                 # values are librdkafka constants; 
    DYNAMIC_TOPIC_CONFIG = ...         # DEFAULT_CONFIG == 5 confirmed live
    DYNAMIC_BROKER_CONFIG = ...
    DYNAMIC_DEFAULT_BROKER_CONFIG = ...
    STATIC_BROKER_CONFIG = ...
    DEFAULT_CONFIG = 5
    GROUP_CONFIG = ...                 # added for KIP-848 group configs (2.10.0+)
```

Only `DEFAULT_CONFIG == 5` was confirmed by execution. The member **names** are exact (read from
`_config.py`); the other integer **values** I did not individually verify — **confidence: medium on
the numeric values, high on the names**. Never hardcode the ints; always use the enum.

### 1.5 `describe_acls(acl_binding_filter) -> Future`

```python
def describe_acls(
    self, acl_binding_filter: AclBindingFilter, **kwargs
) -> concurrent.futures.Future     # result() -> List[AclBinding]
```

Working, executed snippet — "list every ACL":

```python
f = AclBindingFilter(
    ResourceType.ANY,          # restype
    None,                      # name (None = any)
    ResourcePatternType.ANY,   # resource_pattern_type
    None,                      # principal (None = any)
    None,                      # host (None = any)
    AclOperation.ANY,          # operation
    AclPermissionType.ANY,     # permission_type
)
acls = admin.describe_acls(f, request_timeout=10).result(timeout=10)  # -> List[AclBinding]
```

`AclBindingFilter` subclasses `AclBinding` with the same 7-positional-arg constructor:

```python
AclBinding(
    restype: Union[ResourceType, str, int],
    name: str,
    resource_pattern_type: Union[ResourcePatternType, str, int],
    principal: str,
    host: str,
    operation: Union[AclOperation, str, int],
    permission_type: Union[AclPermissionType, str, int],
) -> None
```

Difference: `AclBindingFilter._not_none_args()` returns only
`["restype", "resource_pattern_type", "operation", "permission_type"]` — meaning `name`,
`principal`, `host` **may be `None`** in a filter (they may not in an `AclBinding`). And
`AclBindingFilter._forbidden_enums()` forbids `UNKNOWN` (whereas `AclBinding` forbids `ANY`).
Practical upshot: **use `ANY` in filters, never `UNKNOWN`**; use `None` for the string fields you
want to wildcard.

**`AclBinding` attributes are real enums** (unlike `ConfigEntry.source`) — verified live:

```
restype:               <ResourceType.TOPIC: 2>          (type=ResourceType)
name:                  'orders'                          (type=str)
resource_pattern_type: <ResourcePatternType.LITERAL: 3>  (type=ResourcePatternType)
principal:             'User:alice'                      (type=str)
host:                  '*'                               (type=str)
operation:             <AclOperation.READ: 3>            (type=AclOperation)
permission_type:       <AclPermissionType.ALLOW: 3>      (type=AclPermissionType)
int mirrors: ['operation_int', 'permission_type_int', 'resource_pattern_type_int', 'restype_int']
```

The constructor also **accepts plain strings** — verified live:

```python
AclBinding("TOPIC", "orders", "LITERAL", "User:alice", "*", "READ", "ALLOW")
# -> restype: <ResourceType.TOPIC: 2> | operation: <AclOperation.READ: 3>
```

**Observed:** on a broker with **no authorizer configured** (default `apache/kafka:latest` KRaft),
`describe_acls` returned **`[]`** — an empty list, not an exception. Many hardened clusters instead
raise `KafkaException` with `KafkaError.SECURITY_DISABLED` when no authorizer is set. **Handle
both**: treat empty list and `SECURITY_DISABLED` as "no ACL data available", which is itself a
posture finding (an unauthorized Kafka). **confidence: high on the observed `[]`; medium on how
broadly `SECURITY_DISABLED` appears in the wild** — I only had one broker config to test.

#### Enum members (exact, from `_acl.py` / `_resource.py`)

```python
ResourceType:        UNKNOWN, ANY, TOPIC, GROUP, BROKER, TRANSACTIONAL_ID
ResourcePatternType: UNKNOWN, ANY, MATCH, LITERAL, PREFIXED
AclOperation:        UNKNOWN, ANY, ALL, READ, WRITE, CREATE, DELETE, ALTER,
                     DESCRIBE, CLUSTER_ACTION, DESCRIBE_CONFIGS, ALTER_CONFIGS,
                     IDEMPOTENT_WRITE
AclPermissionType:   UNKNOWN, ANY, DENY, ALLOW
```

`ResourceType` docstrings worth knowing: `TOPIC` → name is topic name; `GROUP` → name is
`group.id`; `BROKER` → name is broker id.

### 1.6 `describe_cluster()` — present and works

```python
def describe_cluster(self, **kwargs) -> concurrent.futures.Future   # -> DescribeClusterResult
```

kwargs: `include_authorized_operations: bool = False`, `request_timeout: float`.

Verified live:

```python
dc = admin.describe_cluster(request_timeout=10).result(timeout=10)
```
```
type: DescribeClusterResult
cluster_id: 5L6g3nShT-eMCtK--X86sw
controller: Node 1 vs-kafka 9092 rack= None
nodes: [(1, 'vs-kafka', 9092)]
authorized_operations: None
```

```python
class DescribeClusterResult:
    cluster_id: Optional[str]
    controller: Node
    nodes: List[Node]
    authorized_operations: Optional[List[AclOperation]]   # None unless include_authorized_operations=True

class Node:   # confluent_kafka._model.Node
    id: int
    id_string: str
    host: str
    port: int
    rack: Optional[str]
```

**`describe_cluster` vs `list_topics` — which to use?** `describe_cluster` gives you
`rack` and `authorized_operations`, which `list_topics` does not. `list_topics` gives you topics
and partitions, which `describe_cluster` does not. VectaSec needs both; call both.
`authorized_operations` is `None` unless you pass `include_authorized_operations=True` —
that's a cheap, high-value posture signal (it tells you what the scanning principal itself can do).

### 1.7 Error handling

Everything raises **`KafkaException`**, whose `args[0]` is a **`KafkaError`**. Verified live:

```python
try:
    admin.list_topics(timeout=2)
except KafkaException as ex:
    err = ex.args[0]                      # KafkaError
    err.code()       # -195
    err.name()       # '_TRANSPORT'
    err.str()        # 'Failed to get metadata: Local: Broker transport failure'
    err.retriable()  # False
    err.fatal()      # False
```

Observed error surfaces:

| Situation | Result |
|---|---|
| Unreachable broker, `list_topics` | `KafkaException`, `code=-195`, `name='_TRANSPORT'`, `str='Failed to get metadata: Local: Broker transport failure'` |
| `describe_configs` for a broker id that doesn't exist | `future.result()` raises `KafkaException`, `name='_TIMED_OUT'`, `str='Failed while waiting for broker: Local: Timed out'` |
| No authorizer, `describe_acls` | returned `[]` (no exception) — see §1.5 |

**Traps:**
- `describe_configs` errors surface at **`future.result()`**, not at the `describe_configs()` call.
  The call itself returns immediately. Wrap `.result()`, not the dispatch.
- A bad broker id gives you a **`_TIMED_OUT`**, not a "not found" — it blocks for the full
  `request_timeout` then times out. Enumerate broker ids from `list_topics()` metadata; never guess.
- Error codes are negative for **local/client-side** errors (`_TRANSPORT`, `_TIMED_OUT`; note the
  leading underscore in `name()`) and positive for **broker-side** errors. Compare against
  `KafkaError._TRANSPORT` etc. rather than hardcoding integers.
- `KafkaError` is imported from `confluent_kafka`, **not** `confluent_kafka.admin`.

### 1.8 Deprecations / recent changes relevant to VectaSec

From the [CHANGELOG](https://github.com/confluentinc/confluent-kafka-python/blob/master/CHANGELOG.md):

- **2.13.0** — "Enforced type hinting across all interfaces." This is why the source carries
  annotations. **Do not trust them blindly** — the `ConfigEntry.source` trap in §1.4 is precisely
  a case where the annotation lies about the runtime type.
- **2.10.0** — KIP-848 group config supported in `DescribeConfigs`; `ConfigSource.GROUP_CONFIG`
  added; `describe_consumer_groups()` gained consumer-group `type` and target-assignment fields.
- **2.12.0** — KIP-848 next-gen consumer rebalance protocol GA; new `group.protocol` config,
  defaults to `classic`. Not enabled by default. Irrelevant to admin/read-only paths.
- **2.15.0** — KIP-932 Queues (`ShareConsumer`) in preview; AWS IAM OAUTHBEARER support.
  No admin-surface changes.
- **Nothing in `list_topics` / `describe_configs` / `describe_acls` / `describe_cluster` is
  deprecated** as of 2.15.0. The legacy `list_groups()` is superseded by
  `list_consumer_groups()` / `describe_consumer_groups()` — prefer the latter if VectaSec ever
  needs group posture. **confidence: medium** on `list_groups` deprecation status; I did not find
  an explicit deprecation notice, only the newer replacements.

### 1.9 Complete minimal working connector snippet

This is assembled from the pieces executed above.

```python
from confluent_kafka.admin import (
    AdminClient, ConfigResource, ConfigSource,
    AclBindingFilter, ResourceType, ResourcePatternType,
    AclOperation, AclPermissionType,
)
from confluent_kafka import KafkaException, KafkaError


def scan_kafka(bootstrap: str, timeout: float = 10.0) -> dict:
    admin = AdminClient({"bootstrap.servers": bootstrap, "socket.timeout.ms": 10000})
    out = {"brokers": [], "topics": [], "broker_configs": {}, "acls": None, "cluster": {}}

    # --- cluster + topics (synchronous) ---
    md = admin.list_topics(timeout=timeout)
    out["cluster"] = {"cluster_id": md.cluster_id, "controller_id": md.controller_id}
    out["brokers"] = [
        {"id": b.id, "host": b.host, "port": b.port} for b in md.brokers.values()
    ]
    out["topics"] = [
        {
            "name": t.topic,
            "error": str(t.error) if t.error else None,
            "partitions": [
                {"id": p.id, "leader": p.leader, "replicas": p.replicas, "isrs": p.isrs}
                for p in t.partitions.values()
            ],
        }
        for t in md.topics.values()
        if not (t.topic or "").startswith("__")     # skip internal topics
    ]

    # --- describe_cluster: rack + what WE are authorized to do ---
    dc = admin.describe_cluster(include_authorized_operations=True,
                                request_timeout=timeout).result(timeout=timeout)
    out["cluster"]["nodes"] = [
        {"id": n.id, "host": n.host, "port": n.port, "rack": n.rack} for n in dc.nodes
    ]
    out["cluster"]["authorized_operations"] = (
        [op.name for op in dc.authorized_operations] if dc.authorized_operations else None
    )

    # --- broker configs: ONE CALL PER BROKER (hard broker-side constraint) ---
    for broker_id in md.brokers:
        res = ConfigResource(ConfigResource.Type.BROKER, str(broker_id))
        try:
            entries = admin.describe_configs([res], request_timeout=timeout)[res].result(
                timeout=timeout
            )
        except KafkaException as ex:
            out["broker_configs"][broker_id] = {"error": ex.args[0].name()}
            continue
        out["broker_configs"][broker_id] = {
            e.name: {
                "value": None if e.is_sensitive else e.value,   # never store sensitive values
                "source": ConfigSource(e.source).name,          # MUST coerce: source is an int
                "is_default": e.is_default,
                "is_sensitive": e.is_sensitive,
                "is_read_only": e.is_read_only,
            }
            for e in entries.values()
        }

    # --- ACLs: [] or SECURITY_DISABLED both mean "no authorizer" ---
    acl_filter = AclBindingFilter(
        ResourceType.ANY, None, ResourcePatternType.ANY, None, None,
        AclOperation.ANY, AclPermissionType.ANY,
    )
    try:
        bindings = admin.describe_acls(acl_filter, request_timeout=timeout).result(timeout=timeout)
        out["acls"] = [
            {
                "restype": b.restype.name,
                "name": b.name,
                "pattern": b.resource_pattern_type.name,
                "principal": b.principal,
                "host": b.host,
                "operation": b.operation.name,
                "permission_type": b.permission_type.name,
            }
            for b in bindings
        ]
    except KafkaException as ex:
        if ex.args[0].code() == KafkaError.SECURITY_DISABLED:
            out["acls"] = []          # no authorizer — a finding in itself
        else:
            raise

    return out
```

---

## 2. Kong Admin API (3.9.3 OSS)

**Version note:** `kong:latest` on Docker Hub is **3.9.3**, last pushed 2026-07-02
([Docker Hub tags](https://hub.docker.com/v2/repositories/library/kong/tags)). endoflife.date
confirms **3.9.3 (released 17 Jun 2026)** is the latest Community release, with **3.4 LTS**
(latest 3.4.2) supported until 09 Aug 2026 ([endoflife.date/kong-gateway](https://endoflife.date/kong-gateway)).

⚠️ Don't confuse the lines: **Kong Gateway Enterprise** uses a 4-part version (e.g. 3.15.0.0,
released 2026-07-02) and ships as `kong/kong-gateway`. VectaSec targeting OSS should assume
**3.9.x**. All captures below are from **Kong 3.9.3 OSS in DB-less mode**.

Admin API default port: **8001** (HTTP) / 8444 (HTTPS). No auth by default on OSS — an
unauthenticated reachable `:8001` is itself a critical VectaSec finding.

### 2.1 Pagination — **the docs are wrong, read this**

Real Kong 3.9.3 response envelope:

```json
{
  "data": [ /* entities */ ],
  "next": null
}
```

Three corrections against widely-circulated (stale) docs:

1. **There is no `total` field.** Older docs show `{"total": 10, "data": [...], "next": "..."}`.
   Kong 3.9.3 returns **only `data` and `next`**. Do not read `total`.
2. **`next` is a RELATIVE PATH, not an absolute URL.** Old docs show
   `"next": "http://localhost:8001/consumers/?size=2&offset=..."`. Actual 3.9.3:
   ```
   "next": "/plugins?offset=cGx1Z2luc3wwZGM2ZjQ1Yi04ZjhkLTQwZDItYTUwNC00NzM1NDRlZTE5MGJ8KnwzMzVjOWFkYy1kYzE0LTU5YzAtOGIxZS0xMmY3YTEzZWIwZDkA&size=1"
   ```
   You **must** join it onto your base URL yourself.
3. **`next` is non-null on the last populated page.** Verified by walking pages of 2 plugins at
   `size=1`:
   ```
   page 1 -> n_data=1  next='/plugins?offset=...&size=1'
   page 2 -> n_data=1  next='/plugins?offset=...&size=1'    <-- still non-null!
   page 3 -> n_data=0  next=None                            <-- only now null
   ```
   So `next != null` does **not** mean "more entities exist". The correct loop terminates on
   `next is None` and costs one extra empty request. Do **not** try to short-circuit on
   `len(data) < size` — that's an unrelated assumption Kong doesn't guarantee.

`offset` is an **opaque base64 cursor**, not a numeric index. Never construct or increment it.
Kong docs warn that offsets are not guaranteed to remain valid if the `tags` filter changes
between calls.

**Correct pagination helper:**

```python
import requests
from urllib.parse import urljoin

def kong_list(base: str, path: str, size: int = 100) -> list:
    """base e.g. 'http://kong-admin:8001'. path e.g. '/services'."""
    out, nxt = [], f"{path}?size={size}"
    while nxt:
        r = requests.get(urljoin(base, nxt), timeout=10)
        r.raise_for_status()
        body = r.json()
        out.extend(body["data"])          # 'data' always present on list endpoints
        nxt = body.get("next")            # relative path or None; NO 'total' field
    return out
```

### 2.2 `GET /services`

Real response (Kong 3.9.3):

```json
{
    "data": [
        {
            "protocol": "http",
            "retries": 5,
            "port": 80,
            "client_certificate": null,
            "write_timeout": 60000,
            "path": null,
            "tags": null,
            "ca_certificates": null,
            "read_timeout": 60000,
            "enabled": true,
            "id": "b942142b-f75b-527f-b4d0-d6efe7e1344d",
            "name": "demo-service",
            "connect_timeout": 60000,
            "host": "httpbin.org",
            "created_at": 1784265794,
            "tls_verify": null,
            "updated_at": 1784265794,
            "tls_verify_depth": null
        }
    ],
    "next": null
}
```

**Posture-relevant fields:** `protocol` (`http` = plaintext upstream), `tls_verify`
(**`null` means "inherit the global `nginx_proxy_lua_ssl_verify` setting"**, *not* `false` —
don't report `null` as "verification disabled" without checking the global), `tls_verify_depth`,
`ca_certificates`, `client_certificate` (mTLS to upstream), `enabled`.

`created_at` / `updated_at` are **Unix epoch seconds as integers** (`1784265794`), not ISO strings.

### 2.3 `GET /routes`

```json
{
    "data": [
        {
            "preserve_host": false,
            "protocols": ["http", "https"],
            "paths": ["/demo"],
            "path_handling": "v0",
            "headers": null,
            "service": { "id": "b942142b-f75b-527f-b4d0-d6efe7e1344d" },
            "snis": null,
            "request_buffering": true,
            "response_buffering": true,
            "https_redirect_status_code": 426,
            "destinations": null,
            "name": "demo-route",
            "id": "b8613a05-2540-5613-a77c-008d3263ece6",
            "hosts": null,
            "methods": null,
            "sources": null,
            "strip_path": true,
            "regex_priority": 0,
            "created_at": 1784265794,
            "updated_at": 1784265794,
            "tags": null
        }
    ],
    "next": null
}
```

**Posture-relevant:** `protocols` containing `"http"` means the route accepts **plaintext** —
a finding. `https_redirect_status_code` only applies when the route is https-only.
`service` is a **nested object with only `{"id": ...}`** — you must join to `/services` yourself;
it is not expanded. `service` can be `null` for serviceless routes.

### 2.4 `GET /plugins`

```json
{
    "data": [
        {
            "id": "335c9adc-dc14-59c0-8b1e-12f7a13eb0d9",
            "protocols": ["grpc", "grpcs", "http", "https"],
            "route": null,
            "config": {
                "month": null,
                "year": null,
                "policy": "local",
                "fault_tolerant": true,
                "hide_client_headers": false,
                "redis": {
                    "password": null,
                    "username": null,
                    "database": 0,
                    "ssl": false,
                    "server_name": null,
                    "port": 6379,
                    "ssl_verify": false,
                    "timeout": 2000,
                    "host": null
                },
                "redis_database": 0,
                "error_code": 429,
                "error_message": "API rate limit exceeded",
                "sync_rate": -1,
                "path": null,
                "redis_timeout": 2000,
                "redis_host": null,
                "redis_ssl_verify": false,
                "redis_ssl": false,
                "redis_username": null,
                "redis_password": null,
                "header_name": null,
                "redis_port": 6379,
                "redis_server_name": null,
                "limit_by": "consumer",
                "second": null,
                "minute": 10,
                "hour": null,
                "day": null
            },
            "enabled": true,
            "consumer": null,
            "name": "rate-limiting",
            "instance_name": null,
            "tags": null,
            "created_at": 1784265794,
            "updated_at": 1784265794,
            "service": { "id": "b942142b-f75b-527f-b4d0-d6efe7e1344d" }
        },
        {
            "id": "4cc13fa8-4473-5d90-bf3f-04d3e7ad2c79",
            "protocols": ["grpc", "grpcs", "http", "https"],
            "route": null,
            "config": {
                "key_in_body": false,
                "realm": null,
                "anonymous": null,
                "hide_credentials": false,
                "key_names": ["apikey"],
                "run_on_preflight": true,
                "key_in_header": true,
                "key_in_query": true
            },
            "enabled": true,
            "consumer": null,
            "name": "key-auth",
            "instance_name": null,
            "tags": null,
            "created_at": 1784265794,
            "updated_at": 1784265794,
            "service": { "id": "b942142b-f75b-527f-b4d0-d6efe7e1344d" }
        }
    ],
    "next": null
}
```

**Critical for VectaSec:**
- **`config` is a free-form object whose schema is entirely plugin-specific.** There is no
  common shape. Treat it as `Dict[str, Any]` and special-case per `name`. Do not model it.
- **`config` can contain secrets in cleartext.** Note `redis.password` and `redis_password`
  above. The Admin API does **not** redact plugin config. VectaSec must **allowlist** which
  config keys it stores, or scrub anything matching `password|secret|key|token`. This is a
  data-handling obligation, not an optional nicety.
- `service` / `route` / `consumer` are the **scoping triple**. All `null` = a **global** plugin.
  Exactly one non-null = scoped to that entity. This is how you tell "auth is enforced
  everywhere" from "auth is enforced on one route".
- Note the duplicated `redis_*` flat keys alongside the nested `redis` object — Kong 3.x keeps
  both for backwards compatibility. They can disagree; prefer the nested `redis` object.
  **confidence: medium** on which wins at runtime — I did not test divergent values.
- `key-auth` with `key_in_query: true` is a real finding (API keys in URLs get logged).

### 2.5 `GET /consumers`

```json
{
    "data": [
        {
            "id": "a9c0ddda-1fd5-552c-a6e4-6f5dc9660fc2",
            "tags": null,
            "username": "demo-consumer",
            "created_at": 1784265794,
            "updated_at": 1784265794,
            "custom_id": "demo-123"
        }
    ],
    "next": null
}
```

Minimal by design. Credentials are **not** included — they live at sub-resources
(`/consumers/{id}/key-auth`, `/basic-auth`, `/jwt`, `/hmac-auth`, `/acls`). VectaSec should
enumerate those separately **only if** it needs credential-posture; note that
`/consumers/{id}/key-auth` returns the **actual API key in cleartext**. Prefer counting
credentials over reading them. **confidence: high** that key-auth creds are readable (the
declarative config round-trips them); I did not execute that sub-resource call.

### 2.6 `GET /status`

Real response (Kong 3.9.3, **DB-less**), abridged in the middle:

```json
{
    "memory": {
        "lua_shared_dicts": {
            "kong":                        { "allocated_slabs": "0.04 MiB", "capacity": "5.00 MiB" },
            "kong_locks":                  { "allocated_slabs": "0.06 MiB", "capacity": "8.00 MiB" },
            "kong_healthchecks":           { "allocated_slabs": "0.04 MiB", "capacity": "5.00 MiB" },
            "kong_cluster_events":         { "allocated_slabs": "0.04 MiB", "capacity": "5.00 MiB" },
            "kong_rate_limiting_counters": { "allocated_slabs": "0.08 MiB", "capacity": "12.00 MiB" },
            "kong_core_db_cache":          { "allocated_slabs": "0.76 MiB", "capacity": "128.00 MiB" },
            "kong_core_db_cache_miss":     { "allocated_slabs": "0.08 MiB", "capacity": "12.00 MiB" },
            "kong_db_cache":               { "allocated_slabs": "0.76 MiB", "capacity": "128.00 MiB" },
            "kong_db_cache_miss":          { "allocated_slabs": "0.08 MiB", "capacity": "12.00 MiB" },
            "kong_secrets":                { "allocated_slabs": "0.04 MiB", "capacity": "5.00 MiB" },
            "prometheus_metrics":          { "allocated_slabs": "0.04 MiB", "capacity": "5.00 MiB" }
        },
        "workers_lua_vms": [
            { "http_allocated_gc": "53.59 MiB", "pid": 1405 },
            { "http_allocated_gc": "53.24 MiB", "pid": 1406 }
        ]
    },
    "server": {
        "connections_reading": 0,
        "connections_writing": 11,
        "total_requests": 17,
        "connections_waiting": 0,
        "connections_handled": 17,
        "connections_active": 11,
        "connections_accepted": 17
    },
    "configuration_hash": "21a8f262ad4fa1c762538d7918fdab0a"
}
```

**Traps:**
- **There is NO `database` key in DB-less mode.** Docs describe `"database": {"reachable": true}`.
  On a DB-less node it is simply **absent**. Use `.get("database")`, never `["database"]`.
  Conversely `configuration_hash` appears in DB-less mode. **confidence: high** on the DB-less
  shape (captured); **medium** on the exact DB-backed shape — I only ran DB-less. Assume
  `database.reachable: bool` exists there and code defensively.
- Memory values are **strings with units** (`"0.04 MiB"`), not numbers. Pass `?unit=b` to get
  numeric bytes instead — per Kong docs, `unit` accepts `b/B, k/K, m/M, g/G`, and with bytes the
  values become JSON numbers rather than strings. **confidence: medium** (documented, not executed).
- `/status` is the liveness probe VectaSec should use for reachability — it returned **200**
  with no auth.

### 2.7 `GET /` (node info — bonus, useful for version fingerprinting)

Top-level keys observed:
`['configuration', 'edition', 'hostname', 'lua_version', 'node_id', 'pids', 'plugins', 'tagline', 'timers', 'version']`
with `version: "3.9.3"`.

This is the cleanest way to fingerprint the Kong version and read `edition`
(`community` vs `enterprise`). **`configuration` dumps the full Kong config** — including paths,
listen addresses, and potentially secrets. Scrub before storing.

---

## 3. RabbitMQ Management HTTP API (4.3.2)

Captured live from `rabbitmq:4-management` — **RabbitMQ 4.3.2**, management plugin **4.3.2**,
Erlang **27.3.4.14**.

### 3.1 Auth — HTTP Basic

Plain HTTP Basic auth on every request. Verified:

```
curl -u guest:guest http://localhost:15672/api/overview        -> 200
curl -u guest:wrongpw http://localhost:15672/api/overview      -> 401
curl http://localhost:15672/api/overview  (no auth)            -> 401, empty body
```

The 401 has `content-length: 0` — **no JSON body**. Don't try to parse it.

Default management port **15672**. The `guest` user is restricted to `localhost` by default —
remote scanning needs a dedicated user. Give it the **`monitoring`** tag, which is the
least-privilege tag that can read `/api/overview` and `/api/nodes`.
**confidence: medium** — `monitoring` is the documented right tag but I only tested as
`administrator`; `/api/users` and `/api/permissions` likely require `administrator`, since they
expose credential material.

```python
import requests
from requests.auth import HTTPBasicAuth

s = requests.Session()
s.auth = HTTPBasicAuth("vectasec", "...")
r = s.get("http://rabbit:15672/api/overview", timeout=10)
r.raise_for_status()
```

Error body for a bad path (this one *is* JSON):

```json
{"error":"Object Not Found","reason":"Not Found"}
```

### 3.2 `GET /api/overview`

Top-level keys (exact, live):

```
['churn_rates', 'cluster_name', 'cluster_tags', 'contexts', 'crypto_lib_version',
 'default_queue_type', 'disable_stats', 'enable_queue_totals', 'erlang_full_version',
 'erlang_version', 'exchange_types', 'is_op_policy_updating_enabled', 'listeners',
 'management_version', 'message_stats', 'node', 'node_tags', 'object_totals',
 'product_name', 'product_version', 'queue_totals', 'rates_mode',
 'sample_retention_policies', 'statistics_db_event_queue']
```

Values:

```json
{
  "management_version": "4.3.2",
  "rabbitmq_version": "4.3.2",
  "erlang_version": "27.3.4.14",
  "product_name": "RabbitMQ",
  "product_version": "4.3.2",
  "node": "rabbit@e33be4083982",
  "cluster_name": "rabbit@e33be4083982",
  "disable_stats": false,
  "statistics_db_event_queue": 0,
  "object_totals": {"channels": 0, "consumers": 0, "exchanges": 8, "queues": 0, "connections": 0}
}
```

`listeners[0]` (live) — **the highest-value posture object on this endpoint**:

```json
{
  "node": "rabbit@e33be4083982",
  "protocol": "amqp",
  "ip_address": "::",
  "port": 5672,
  "socket_opts": {"backlog": 128, "nodelay": true, "linger": [true, 0], "exit_on_close": false},
  "tls": false
}
```

`tls: false` on an `amqp` listener bound to `::` (all interfaces) is exactly the kind of finding
VectaSec exists to surface.

**Traps:**
- `rabbitmq_version` is present but **not** in the top-level key list above — it *is* returned
  (value `"4.3.2"`); it just isn't in the sorted-keys dump order I printed. Both
  `rabbitmq_version` and `product_version` exist and agreed at 4.3.2 here; they can diverge on
  a customized/branded build. Prefer `rabbitmq_version`.
- `queue_totals` was **`{}`** (empty dict) on an idle broker with 0 queues — not absent, not null.
  Code for the empty case.
- `disable_stats: true` (a valid production config) makes most statistics fields disappear
  entirely. Check it before reading `message_stats` / `object_totals`.

**`columns` query param works here** — verified:

```
GET /api/overview?columns=rabbitmq_version,node
-> {"rabbitmq_version": "4.3.2", "node": "rabbit@e33be4083982"}
```

### 3.3 `GET /api/nodes`

Returns a **JSON array**. A single node returned **~100 keys** — it is a large payload dominated
by metrics. Full key list (live):

```
applications, auth_mechanisms, being_drained, channel_closed, channel_closed_details,
channel_created, channel_created_details, cluster_links, config_files, connection_closed,
connection_closed_details, connection_created, connection_created_details, context_switches,
context_switches_details, contexts, crypto_lib_version, db_dir, disk_free, disk_free_alarm,
disk_free_details, disk_free_limit, enabled_plugins, erlang_full_version, erlang_version,
exchange_types, fd_total, fd_used, fd_used_details, gc_bytes_reclaimed,
gc_bytes_reclaimed_details, gc_num, gc_num_details, io_read_avg_time, io_read_avg_time_details,
io_read_bytes, io_read_bytes_details, io_read_count, io_read_count_details, io_reopen_count,
io_reopen_count_details, io_seek_avg_time, io_seek_avg_time_details, io_seek_count,
io_seek_count_details, io_sync_avg_time, io_sync_avg_time_details, io_sync_count,
io_sync_count_details, io_write_avg_time, io_write_avg_time_details, io_write_bytes,
io_write_bytes_details, io_write_count, io_write_count_details, log_files, mem_alarm,
mem_calculation_strategy, mem_limit, mem_used, mem_used_details, metrics_gc_queue_length,
mnesia_disk_tx_count, mnesia_disk_tx_count_details, mnesia_ram_tx_count,
mnesia_ram_tx_count_details, msg_store_read_count, msg_store_read_count_details,
msg_store_write_count, msg_store_write_count_details, name, net_ticktime, os_pid, partitions,
proc_total, proc_used, proc_used_details, processors, queue_created, queue_created_details,
queue_declared, queue_declared_details, queue_deleted, queue_deleted_details,
queue_index_read_count, queue_index_read_count_details, queue_index_write_count,
queue_index_write_count_details, ra_open_file_metrics, rabbitmq_version, rates_mode, run_queue,
running, sockets_total, sockets_used, sockets_used_details, type, uptime
```

Posture-relevant subset (live values):

```
name:             "rabbit@e33be4083982"
type:             "disc"
running:          true
os_pid:           "1"
mem_limit:        4992909312
mem_alarm:        false
disk_free_limit:  50000000
disk_free_alarm:  false
uptime:           62063
enabled_plugins:  ["rabbitmq_management", "rabbitmq_prometheus"]
being_drained:    false
rates_mode:       "basic"
cluster_links:    []
partitions:       []
db_dir:           "/var/lib/rabbitmq/mnesia/rabbit@e33be4083982"
config_files:     ["/etc/rabbitmq/conf.d/10-defaults.conf"]
log_files:        ["<stdout>"]
net_ticktime:     60
```

**`auth_mechanisms` is the security jackpot on this endpoint** (live):

```json
[
  {"name": "AMQPLAIN",       "description": "QPid AMQPLAIN mechanism",                          "enabled": true},
  {"name": "PLAIN",          "description": "SASL PLAIN authentication mechanism",             "enabled": true},
  {"name": "ANONYMOUS",      "description": "SASL ANONYMOUS authentication mechanism",         "enabled": true},
  {"name": "RABBIT-CR-DEMO", "description": "RabbitMQ Demo challenge-response authentication mechanism", "enabled": false}
]
```

`ANONYMOUS: enabled=true` is a **default in RabbitMQ 4.x** and a genuine finding worth flagging
(it's gated to loopback by default, but VectaSec should surface it). `partitions: []` non-empty
means a **network partition** — a critical availability finding.

**Use `columns` here — it works and the payload is ~100 fields otherwise.** Verified:

```
GET /api/nodes?columns=name,running,type,mem_alarm,disk_free_alarm,enabled_plugins
```
```json
[
    {
        "mem_alarm": false,
        "disk_free_alarm": false,
        "enabled_plugins": ["rabbitmq_management", "rabbitmq_prometheus"],
        "name": "rabbit@e33be4083982",
        "type": "disc",
        "running": true
    }
]
```

### 3.4 `GET /api/users`

```json
[
    {
        "hashing_algorithm": "rabbit_password_hashing_sha256",
        "limits": {},
        "name": "guest",
        "password_hash": "ATDCg0JaSphQGorFY30+L+ZuZIjNwPW6u9LqIgg1+X2DZR65",
        "tags": ["administrator"]
    }
]
```

> ### ⚠️ `/api/users` returns `password_hash` for every user.
>
> This endpoint hands VectaSec **credential material**. The connector must **drop
> `password_hash` at ingest** — before it reaches logs, the DB, or Supabase. Do not store it, do
> not hash it again, do not "keep it for diffing". Read `name`, `tags`, `hashing_algorithm`, and
> `limits`; discard the rest.
>
> `hashing_algorithm` is legitimately useful posture data — a user on the legacy
> `rabbit_password_hashing_md5` is a real finding. Keep the algorithm, drop the hash.

`tags` is a **list** (`["administrator"]`) in modern RabbitMQ. Older versions returned a
comma-separated **string**. Against 4.3.2 it is a list. **confidence: high** for 4.x;
if VectaSec must support RabbitMQ 3.x, defensively handle both.

### 3.5 `GET /api/vhosts`

```json
[
    {
        "name": "/",
        "description": "Default virtual host",
        "metadata": {
            "description": "Default virtual host",
            "tags": [],
            "default_queue_type": "classic"
        },
        "tags": [],
        "default_queue_type": "classic",
        "tracing": false,
        "cluster_state": { "rabbit@e33be4083982": "running" },
        "protected_from_deletion": false
    }
]
```

Keys: `['cluster_state', 'default_queue_type', 'description', 'metadata', 'name', 'protected_from_deletion', 'tags', 'tracing']`.

`tracing: true` is a finding — RabbitMQ tracing captures message bodies.

> **Trap: `columns` does NOT work on `/api/vhosts`.** Verified — `GET /api/vhosts?columns=name,tracing`
> returned **every field anyway**, silently ignoring the filter, while the same param works on
> `/api/nodes` and `/api/overview`. Do not assume `columns` is universal; never rely on it for
> correctness, only as a payload optimization where you've confirmed it works.

> **Trap: the default vhost is named `"/"` and MUST be URL-encoded as `%2F` in paths.** Verified:
> ```
> GET /api/vhosts/%2F   -> 200
> GET /api/vhosts//     -> 404
> ```
> Use `urllib.parse.quote(vhost, safe="")`. `requests` will **not** do this for you if you
> f-string the path.

### 3.6 `GET /api/permissions`

```json
[
    {
        "user": "guest",
        "vhost": "/",
        "configure": ".*",
        "write": ".*",
        "read": ".*"
    }
]
```

`configure` / `write` / `read` are **regex strings**. `".*"` = unrestricted on that vhost — the
core RabbitMQ authz finding. Empty string `""` = no permission.

Scoped variants (both verified live, both return the same shape):

```
GET /api/vhosts/%2F/permissions    -> [{"vhost":"/","user":"guest","configure":".*","write":".*","read":".*"}]
GET /api/users/guest/permissions   -> [{"user":"guest","vhost":"/","configure":".*","write":".*","read":".*"}]
```

Prefer the **flat `/api/permissions`** for a full scan — one request, no N+1 over vhosts/users.

### 3.7 Pagination

The endpoints VectaSec needs (`/api/overview`, `/api/nodes`, `/api/users`, `/api/vhosts`,
`/api/permissions`) are **unpaginated** — they return complete JSON arrays. Only the
high-cardinality endpoints (`/api/queues`, `/api/exchanges`, `/api/connections`, `/api/channels`)
support `page`/`page_size`, and those return a wrapped
`{"items": [...], "page": 1, "page_count": N, ...}` envelope instead of a bare array.
**confidence: high** that the five listed are bare arrays (captured); **medium** on the exact
paginated envelope for `/api/queues` — not executed, not needed for the current connector scope.

### 3.8 Minimal working RabbitMQ connector

```python
from urllib.parse import quote
import requests
from requests.auth import HTTPBasicAuth

SENSITIVE_USER_FIELDS = {"password_hash"}   # never persist

def scan_rabbitmq(base: str, user: str, password: str, timeout: int = 10) -> dict:
    s = requests.Session()
    s.auth = HTTPBasicAuth(user, password)

    def get(path: str):
        r = s.get(f"{base}{path}", timeout=timeout)
        r.raise_for_status()          # 401 has an EMPTY body — don't parse it
        return r.json()

    overview = get("/api/overview")
    nodes = get("/api/nodes?columns=name,running,type,mem_alarm,disk_free_alarm,"
                "enabled_plugins,partitions,auth_mechanisms,rabbitmq_version")
    users = [
        {k: v for k, v in u.items() if k not in SENSITIVE_USER_FIELDS}   # drop password_hash
        for u in get("/api/users")
    ]
    vhosts = get("/api/vhosts")            # NOTE: ?columns= is ignored here
    permissions = get("/api/permissions")  # flat list; avoids N+1 over vhosts

    return {
        "version": overview.get("rabbitmq_version"),
        "management_version": overview.get("management_version"),
        "cluster_name": overview.get("cluster_name"),
        "stats_disabled": overview.get("disable_stats", False),
        "listeners": overview.get("listeners", []),   # tls:false here is a finding
        "nodes": nodes,
        "users": users,
        "vhosts": vhosts,
        "permissions": permissions,
    }

def vhost_path(vhost: str) -> str:
    """The default vhost '/' must be encoded as %2F or you get a 404."""
    return quote(vhost, safe="")
```

---

## 4. MCP introspection over Streamable HTTP

### 4.1 Protocol version — **use `2025-11-25`**

Per [modelcontextprotocol.io/specification/versioning](https://modelcontextprotocol.io/specification/versioning):

> The **current** protocol version is **2025-11-25**.

Confirmed live — a real handshake negotiated `protocolVersion: 2025-11-25`.

⚠️ **Timing matters right now.** A **2026-07-28** revision is in **release candidate** and ships
**2026-07-28 — 11 days from today**. It is the largest revision since launch and it
**removes the `initialize` handshake entirely**: protocol version, client identity and
capabilities move into `_meta` on every request (`io.modelcontextprotocol/protocolVersion`,
`/clientInfo`, `/clientCapabilities`), and a new **`server/discover`** RPC (servers MUST
implement) replaces discovery. Streamable HTTP also gains required `Mcp-Method` / `Mcp-Name`
headers, and list results gain `ttlMs` / `cacheScope`.
Source: [MCP blog, 2026-07-28 RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/).

**Recommendation:** build against **2025-11-25** now — it's what live servers negotiate today —
but **isolate the handshake behind one function**. Do not scatter `initialize` assumptions through
the connector. Within weeks you will likely need a `server/discover` path alongside it, and the
SDK will need a major bump (note there are already `mcp` **2.0.0b1/b2** prereleases on PyPI).
**confidence: high** on the RC contents (from the official MCP blog); **medium** on exactly when
servers in the wild will adopt it.

### 4.2 Python SDK — this is the sane path

**Package:** `mcp` — latest stable **1.28.1**, released **2026-06-26**, requires **Python >= 3.10**
(supports 3.10–3.14). Verified by installing it: `mcp SDK version installed: 1.28.1`.

> Note: `mcp` requires **Python >= 3.10**. VectaSec's engine must be on 3.10+ for the MCP
> connector. (Confirmed the hard way — install fails outright on 3.9.)

**This exact script was executed against a live FastMCP server and produced the output below.**

```python
import asyncio, json
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def introspect(url: str) -> dict:
    async with streamablehttp_client(url) as (read, write, get_session_id):
        async with ClientSession(read, write) as session:
            init = await session.initialize()          # does initialize + notifications/initialized
            tools = await session.list_tools()
            return {
                "protocol_version": init.protocolVersion,
                "server_name": init.serverInfo.name,
                "server_version": init.serverInfo.version,
                "capabilities": init.capabilities.model_dump(exclude_none=True),
                "session_id": get_session_id(),
                "tools": [
                    {
                        "name": t.name,
                        "title": t.title,
                        "description": t.description,
                        "input_schema": t.inputSchema,
                        "output_schema": t.outputSchema,
                        "annotations": t.annotations.model_dump() if t.annotations else None,
                    }
                    for t in tools.tools
                ],
                "next_cursor": tools.nextCursor,
            }

asyncio.run(introspect("http://127.0.0.1:9100/mcp"))
```

Actual output:

```
=== InitializeResult ===
protocolVersion: 2025-11-25
serverInfo: vectasec-probe-server 1.28.1
capabilities: {'experimental': {}, 'prompts': {'listChanged': False}, 'resources': {'subscribe': False, 'listChanged': False}, 'tools': {'listChanged': False}}
session id: 1a1a95ac1e824c2ca98c22fead0b6479
=== tools/list ===
{
  "name": "get_weather",
  "title": null,
  "description": "Get current weather information for a location.",
  "inputSchema": {
    "properties": {"location": {"title": "Location", "type": "string"}},
    "required": ["location"],
    "title": "get_weatherArguments",
    "type": "object"
  },
  "outputSchema": {
    "properties": {"result": {"title": "Result", "type": "string"}},
    "required": ["result"],
    "title": "get_weatherOutput",
    "type": "object"
  },
  "annotations": null
}
nextCursor: None
```

**API facts confirmed by execution:**
- `streamablehttp_client(url)` yields a **3-tuple**: `(read, write, get_session_id)`. The third
  element is a **callable**, not a value — call `get_session_id()`. Getting this wrong is a
  common error.
- `session.initialize()` performs the full handshake (`initialize` **and**
  `notifications/initialized`) and returns an `InitializeResult`.
- `init.capabilities` and `t.annotations` are **Pydantic models** — use `.model_dump()`, not
  `dict()` / `json.dumps()` directly.
- `t.title` and `t.annotations` are commonly `None`. Both are optional in the spec.
- `tools.nextCursor` is `None` when there is no next page.
- Both `ClientSession` and `streamablehttp_client` are **async context managers**. The whole
  connector path must be `async`. `ClientSession` must be entered **inside** the
  `streamablehttp_client` block.

**Import paths (exact):** `from mcp import ClientSession` and
`from mcp.client.streamable_http import streamablehttp_client`. Note the module is
`streamable_http` (underscore) but the function is `streamablehttp_client` (no underscore between
"streamable" and "http") — an easy typo.

### 4.3 Pagination for `tools/list`

`tools/list` is paginated via an **opaque cursor**:

```python
tools, cursor = [], None
while True:
    page = await session.list_tools(cursor=cursor)   # confidence: MEDIUM — see note
    tools.extend(page.tools)
    cursor = page.nextCursor
    if cursor is None:
        break
```

⚠️ **confidence: medium** — I executed `session.list_tools()` with **no arguments** (verified
working, `nextCursor: None`). I did **not** verify that `list_tools()` accepts a `cursor=` kwarg
in SDK 1.28.1, because my test server had only 2 tools and never paginated. **Check the signature
before relying on it.** The wire protocol definitely supports `params.cursor` (§4.4); whether the
SDK surfaces it as that exact kwarg is unconfirmed. Most servers return all tools in one page, so
this may not matter in practice — but don't ship the loop above untested.

### 4.4 Raw HTTP wire (if you skip the SDK)

Captured live against a real MCP server. **This is what actually goes over the wire.**

**1. POST initialize**

```http
POST /mcp HTTP/1.1
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2025-11-25

{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"vectasec-scanner","version":"0.1.0"}}}
```

Actual response:

```
HTTP 200
Content-Type: text/event-stream          <-- NOT application/json!
MCP-Session-Id: 0adc5a22a4a74870b1b9ebc45701369d

event: message
data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"experimental":{},"prompts":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"tools":{"listChanged":false}},"serverInfo":{"name":"vectasec-probe-server","version":"1.28.1"}}}
```

**2. POST notifications/initialized** (with `MCP-Session-Id`)

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```
```
HTTP 202 | body: ''          <-- 202 Accepted, empty body
```

**3. POST tools/list** (with `MCP-Session-Id`)

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```
```
HTTP 200 | Content-Type: text/event-stream

event: message
data: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_weather","description":"Get current weather information for a location.","inputSchema":{"properties":{"location":{"title":"Location","type":"string"}},"required":["location"],"title":"get_weatherArguments","type":"object"},"outputSchema":{"properties":{"result":{"title":"Result","type":"string"}},"required":["result"],"title":"get_weatherOutput","type":"object"}},{"name":"danger_delete_all","description":"Deletes everything. Used to test posture scanning.","inputSchema":{"properties":{"confirm":{"default":false,"title":"Confirm","type":"boolean"}},"title":"danger_delete_allArguments","type":"object"},"outputSchema":{"properties":{"result":{"title":"Result","type":"string"}},"required":["result"],"title":"danger_delete_allOutput","type":"object"}}]}}
```

**4. Omitting the session id**

```
HTTP 400 | {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Bad Request: Missing session ID"}}
```

> ### ⚠️ TRAP — the server replies `text/event-stream` even for `initialize`
>
> The spec says the server **MUST** return *either* `application/json` *or* `text/event-stream`,
> and the client **MUST** support both. In practice the reference Python server (FastMCP) returns
> **SSE for everything**, including `initialize` and `tools/list`. A hand-rolled client that does
> `response.json()` will **fail on every single request** against the most common MCP server
> implementation.
>
> If you skip the SDK you must parse SSE framing (`event: message\ndata: {json}\n\n`) and extract
> the JSON from the `data:` line. **This alone is a strong argument for using the SDK** — it
> handles the content-type negotiation, SSE parsing, and session-id plumbing for you.

**Other wire rules that matter** (from the
[transports spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)):

- The `Accept` header **MUST** list **both** `application/json` and `text/event-stream`. Omitting
  either is a protocol violation.
- The server **MAY** assign `MCP-Session-Id` on the `InitializeResult` response. If it does, the
  client **MUST** send it on every subsequent request (verified: 400 if you don't).
- On **HTTP 404** with a session id, the client **MUST** start a new session with a fresh
  `initialize` (the server expired it).
- `MCP-Protocol-Version: <version>` **MUST** be sent on all requests after initialization. If the
  server sees no such header it **SHOULD** assume `2025-03-26`. An invalid/unsupported value
  **MUST** get a `400`.
- Client **SHOULD** send `DELETE` with the session id to cleanly terminate; the server **MAY**
  answer `405` if it doesn't allow that.
- The MCP endpoint is a **single path** (e.g. `/mcp`) serving both POST and GET.

### 4.5 What VectaSec should actually record from an MCP server

The `tools/list` payload **is** the security surface. From the executed capture, per tool:
`name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `icons`, `execution`.

Spec notes that matter for posture scoring
([tools spec](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)):

- **`annotations` are UNTRUSTED.** Verbatim from the spec: *"clients MUST consider tool
  annotations to be untrusted unless they come from trusted servers."* A server can self-declare
  `readOnlyHint: true` while doing anything at all. VectaSec must **never** treat an annotation as
  evidence of safety — record it as a *claim*, and flag mismatches (e.g. a tool named
  `danger_delete_all` claiming to be read-only) as a finding.
- `description` is model-facing text and is a **prompt-injection vector** — it goes into an LLM
  context. Scanning descriptions for injection patterns is a legitimate VectaSec check.
- `inputSchema` **MUST** be a valid JSON Schema object, never `null`. Defaults to draft 2020-12
  when `$schema` is absent.
- `execution.taskSupport` ∈ `"forbidden"` (default) / `"optional"` / `"required"`.
- `outputSchema` is optional; when present, servers **MUST** conform to it.

**Introspection is read-only and safe.** `initialize` + `tools/list` never invoke a tool.
VectaSec must **never** call `tools/call` during a scan.

---

## 5. Cross-cutting traps worth reading before you code

Ranked by how much damage they'd do if missed.

1. **`ConfigEntry.source` is an `int`, not `ConfigSource`** (§1.4). Fails **silently** and
   produces wrong posture results with no error. Always `ConfigSource(entry.source)`.
2. **Three of these four APIs hand you secrets you must not store.** Kong plugin `config`
   contains `redis_password` in cleartext; RabbitMQ `/api/users` returns `password_hash`; Kong
   `GET /` dumps full configuration. Kafka is the good citizen — the broker itself redacts
   sensitive values to `None`. Build the scrubbing into the **connector**, not a later layer.
3. **Kong's `next` is a relative path, has no `total`, and is non-null on the last populated
   page** (§2.1). Widely-published examples are stale on all three points.
4. **MCP servers reply `text/event-stream` even to `initialize`** (§4.4). A hand-rolled
   `response.json()` client fails 100% of the time against FastMCP. Use the SDK.
5. **`describe_configs` allows at most ONE broker resource per call** (§1.4). Broker-side
   constraint, not a client quirk. Loop per broker.
6. **RabbitMQ vhost `/` must be `%2F`-encoded** (§3.5); unencoded gives a 404.
7. **`columns=` works on RabbitMQ `/api/nodes` and `/api/overview` but is silently ignored on
   `/api/vhosts`** (§3.5). Never rely on it for correctness.
8. **Kafka `list_topics()` returns dicts, not lists**, and `timeout` is in **seconds** while
   almost all other librdkafka settings are milliseconds (§1.3).
9. **Kong `/status` has no `database` key in DB-less mode** (§2.6). Use `.get()`.
10. **MCP tool `annotations` are attacker-controlled** (§4.5). Never treat as a safety signal.
11. **MCP's `initialize` handshake disappears in the 2026-07-28 revision, shipping in 11 days**
    (§4.1). Isolate it behind one function now.

### Version pinning summary

```
confluent-kafka==2.15.0     # Python >=3.8;  verified vs Apache Kafka 4.3.1 (KRaft)
mcp==1.28.1                 # Python >=3.10 REQUIRED; 2.0.0b* prereleases exist — do not use yet
requests                    # Kong + RabbitMQ are plain REST; no vendor SDK needed
```

**VectaSec engine must run Python >= 3.10** — forced by `mcp`.

Kong OSS **3.9.x** and RabbitMQ **4.x** are the versions to target.

---

## Sources

Live systems (primary — captured, not cited):
Apache Kafka 4.3.1 · confluent-kafka-python 2.15.0 · Kong 3.9.3 OSS · RabbitMQ 4.3.2 ·
mcp SDK 1.28.1 · MCP protocol 2025-11-25.

Documentation consulted:

- [confluent-kafka on PyPI](https://pypi.org/project/confluent-kafka/) — v2.15.0, 2026-06-30
- [confluent-kafka-python API docs (2.15.0)](https://docs.confluent.io/platform/current/clients/confluent-kafka-python/html/index.html)
- [confluent-kafka-python `admin/__init__.py`](https://github.com/confluentinc/confluent-kafka-python/blob/master/src/confluent_kafka/admin/__init__.py)
- [`admin/_config.py`](https://raw.githubusercontent.com/confluentinc/confluent-kafka-python/master/src/confluent_kafka/admin/_config.py) · [`_acl.py`](https://raw.githubusercontent.com/confluentinc/confluent-kafka-python/master/src/confluent_kafka/admin/_acl.py) · [`_resource.py`](https://raw.githubusercontent.com/confluentinc/confluent-kafka-python/master/src/confluent_kafka/admin/_resource.py) · [`_metadata.py`](https://raw.githubusercontent.com/confluentinc/confluent-kafka-python/master/src/confluent_kafka/admin/_metadata.py) · [`_cluster.py`](https://raw.githubusercontent.com/confluentinc/confluent-kafka-python/master/src/confluent_kafka/admin/_cluster.py) · [`_model/__init__.py`](https://raw.githubusercontent.com/confluentinc/confluent-kafka-python/master/src/confluent_kafka/_model/__init__.py)
- [confluent-kafka-python CHANGELOG](https://github.com/confluentinc/confluent-kafka-python/blob/master/CHANGELOG.md)
- [Kong Admin API OpenAPI spec (`kong-admin-api.yml`)](https://raw.githubusercontent.com/Kong/kong/master/kong-admin-api.yml) — OpenAPI 3.1.0, info.version 3.4.0
- [Kong Gateway EOL / versions](https://endoflife.date/kong-gateway) — 3.9.3 latest, 17 Jun 2026
- [Kong Docker Hub tags](https://hub.docker.com/v2/repositories/library/kong/tags) — `latest` = 3.9.3
- [Kong Admin API landing](https://developer.konghq.com/admin-api/)
- [MCP Versioning](https://modelcontextprotocol.io/specification/versioning) — current = 2025-11-25
- [MCP Lifecycle (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [MCP Transports (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP Tools (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP 2026-07-28 Release Candidate](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [mcp on PyPI](https://pypi.org/project/mcp/) — v1.28.1, 2026-06-26
