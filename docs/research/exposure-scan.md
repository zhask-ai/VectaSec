# Free external exposure scan

The top-of-funnel product from the SMB strategy (§2 "Free entry", §4 item 5): enter a domain or
IP range, prove you own it, get a public-safe report of the middleware the internet can reach —
brokers, gateways, admin UIs — with CVE and end-of-life facts attached. No credentials, ever.

Code: `services/engine/src/vectasec/exposure.py` (pure logic), `api/exposure.py` (router),
migration `20261017000003_exposure_scans.sql`.

## What is probed

The same pre-auth fingerprints the `discovery` connector uses (`discover/probes.py`,
`discover/http_probes.py`): open a TCP connection, send what a normal client sends *before*
authenticating, read one bounded reply, hang up. Ports are the connector's `DEFAULT_PORTS`
middleware set (MQTT, ZooKeeper, etcd, NATS, AMQP, Redis, Pulsar, Kong admin, 8080/9000 admin
surfaces, ActiveMQ console, Vault, Consul, Kafka, Elasticsearch, Memcached, RabbitMQ management,
OpenWire). The do-not-contact list (`EXCLUDED_PORTS`: raw print, IBM MQ, LPD/IPP) applies
unchanged. Nothing authenticates, writes, or follows a redirect out of scope.

A domain expands to the A/AAAA records of the apex plus the common middleware hostnames
(`kafka`, `broker`, `mq`, `rabbitmq`, `redis`, `api`, `gateway`, `kong`, `n8n`, `mcp`, `admin`,
`queue`, `events`), capped at 32 addresses. A CIDR expands to its hosts and must be /24 or
smaller. Private, loopback, link-local and reserved space is rejected at submission: the scan
runs from the internet and only reports what the internet can reach.

Each identified service gets CVEs from the curated `cve_data` set (affected-range match on the
version actually read; top five by CVSS) and a lifecycle verdict from `lifecycle.support_status`
(`eol` / `approaching` / `supported` / `unknown`). A version the wire did not reveal gets no CVE
attached — we never assert a vulnerability against a version we did not read.

## The ownership gate

`POST /exposure/targets` issues a 32-byte URL-safe token. The engine will not probe until one of:

* **Domain** — the exact string `vectasec-verify=<token>` is published as a TXT record on the
  apex or on `_vectasec.<domain>` (`POST /exposure/targets/{id}/verify`, method `dns_txt`).
* **IP / CIDR** — every address either reverse-resolves (PTR) to an already-verified domain, or
  appears in a verified domain's A/AAAA records (apex or middleware hostname). One unowned
  address fails the whole range (`ptr` / `a_record`).

`POST /exposure/targets/{id}/scan` returns 403 for an unverified target. This is the whole
point: the discovery guardrail refuses public address space by default, and the exposure scan
is the one caller allowed past it, only after this check. DNS lookups use a stdlib resolver
(`/etc/resolv.conf`, overridable with `VECTASEC_DNS_SERVER`); dnspython was not added.

## What the report deliberately omits

The report is designed to be forwarded to a stranger's CTO. Per service it carries host, port,
product, version (+ `version_inferred`), transport, `auth_observed` (`none` / `required` /
`unknown`), at most six evidence strings each cut to 120 characters, CVE ids with CVSS and a
one-line summary, and the EOL verdict. It never carries: full banners, raw probe payloads,
anything matching a credential pattern (`password=`, `token=`, `secret:`, …), connection
configs, or the verification token. The row is readable by the tenant's members under RLS and
by nobody else; all writes go through the engine.

## Abuse limits

* Ownership gate before any packet leaves (above).
* One running scan per tenant; ten scans per tenant per rolling day (429 otherwise).
* 32 hosts per domain, /24 per range, the middleware port set only — not a port scanner.
* A hard 60 s wall-clock budget per scan: the per-probe timeout is scaled to fit and an
  overrunning sweep is cut off and reported as `partial` with a refusal line, never silently.
* Every target creation, verification attempt and scan start is an `audit_log` row.
* Managed cloud messaging (MSK, Amazon MQ, SQS, …) is outside AWS's pre-authorised scanning
  list; the discovery connector's warning applies here too — use the cloud connectors for those.
