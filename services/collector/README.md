# VectaSec Collector

The Collector runs **inside your network**, next to the systems it scans. It holds the credentials
for your Kafka / Kong / RabbitMQ **locally**, reaches us **outbound only**, and sends us
**findings, not configuration**.

This document is written for the person who has to approve it. It describes what the software
actually does today, and says plainly where the claims stop.

---

## The claim, in one paragraph

You give the Collector a read-only credential for your broker. It uses that credential to talk to
your broker over a socket that never leaves your network, runs our detection rules **locally**
against what it reads, and pushes the *conclusions* out to our control plane over a single TLS
connection that **it** opens. We never receive the credential. We never receive your broker's
configuration. We cannot connect to you — there is no port to connect to. If you shut off egress,
the Collector goes quiet; it does not fall back to anything.

## Why it exists

There is no cloud API that returns a Kafka topic ACL or a Kong plugin config. These are data-plane
systems inside private networks, so the only way to assess them is to speak their admin protocols
from *inside*. That forces a customer-side component — so we made the necessity the guarantee.

---

## Data flow

```
   YOUR NETWORK                                        │       VECTASEC
                                                       │
   ┌──────────────┐   admin API, read-only             │
   │  Kafka       │◀──────────────┐                    │
   │  Kong        │               │  credential used   │
   │  RabbitMQ    │               │  HERE, only here   │
   └──────────────┘               │                    │
                          ┌───────┴────────┐           │
   ┌──────────────┐       │   Collector    │           │    ┌──────────────────┐
   │ K8s Secret / │──────▶│  connect →     │═══════════╪═══▶│  control plane   │
   │ Vault / file │ creds │  detect →      │  outbound │    │  (Supabase)      │
   └──────────────┘       │  redact → push │   TLS 443 │    └──────────────────┘
                          └────────────────┘  ▲        │
                                              │        │
                                    NO INBOUND PORT ───┘
```

The Collector opens the connection. The control plane parks the request (long-poll) until a scan
job exists, then answers on that same connection. Job dispatch therefore rides an outbound flow
your egress policy already permits.

---

## What leaves your network, and what does not

| Leaves | Never leaves |
|---|---|
| Findings: rule id, severity, title, remediation text | Any credential you configured (broker password, admin token, SASL secret) |
| The **observation** behind each finding — the specific fact a rule read | `Resource.raw` — the broker/gateway/topic config blob a rule ran against |
| Resource metadata: kind, name, ext_id, namespace, labels | Message contents, payloads, keys, topic data — we never read them at all |
| Connection config **with credential-shaped keys redacted** (host, port, TLS flags) | The enrollment token after enrollment; the service token, ever, to disk |
| Target **names** and **types**, on each heartbeat | Target hostnames, on the heartbeat |
| Collector version, status, timestamps | |

### Two disclosures we want you to see before you ask

**1. Resource labels contain internal hostnames.** A Kafka broker resource is labelled with its
host and port. The console cannot show you "broker-3 at kafka-3.prod.internal:9093 has no
authorizer" without them. If your threat model treats internal hostnames as sensitive, this is the
line to look at — `resources` in the payload — and `preview` (below) prints it for you.

**2. Findings quote the specific config values a rule read.** "Raw configs never leave" means the
*blob* never leaves. It does not mean no configuration value ever appears: an observation is
required by our own contract to state a fact read from the target, including the observed value —
`config authorizer.class.name is empty`, `security.inter.broker.protocol=PLAINTEXT`. That is the
evidence for the finding, and a finding without it is a rumour. So: **the values our rules read and
cite, you send us. The configuration wholesale, you do not.** Anyone who tells you a scanner
reports issues while transmitting *nothing* about your config is selling you something.

---

## Where credentials live

Credentials are read in [`src/collector/config.py`](src/collector/config.py) and go exactly one
place: into the connector that dials your system.

- **At rest:** wherever you put them — a K8s Secret, a Vault agent file, a cloud secrets manager.
  The Collector reads them; it never writes them anywhere.
- **In transit:** from your secret store to this process, and from this process to your broker.
  Never to us.
- **On disk (ours):** the state file holds a collector id and `sha256(enrollment token)`. Nothing
  in it can authenticate to anything. The short-lived tenant token is **memory-only** — it is never
  written, so it cannot be recovered from a volume snapshot or a backup.
- **Prefer the `_FILE` form.** `VECTASEC_ENROLL_TOKEN_FILE` beats `VECTASEC_ENROLL_TOKEN`: an env
  var is readable via `/proc/<pid>/environ`, `docker inspect`, `kubectl describe pod`, and most
  crash reporters. A mounted Secret is not. Both work; only one is a good idea.
- **The targets file holds no secrets.** `${ENV_VAR}` is interpolated at load, so the file itself
  can live in git or a ConfigMap while the credential arrives from a Secret at runtime.

## The redaction boundary

Structurally, a credential cannot reach a payload: payloads are built out of credential-free
parts and `Target.config` is never serialised. But "we were careful" is not an argument that
survives a security review, and the person who adds the seventh connector will not have read that
code. So every payload passes through `redact()`
([`src/collector/redact.py`](src/collector/redact.py)) as it leaves — one small file, deliberately
dependency-free so you can read it in five minutes. Three layers:

1. **Value** — every credential we hold, byte for byte, wherever it appears. Shape-independent:
   it does not matter which field a secret leaked into.
2. **Key** — every credential-shaped key, whatever its value. This catches secrets we *don't*
   hold: ones a connector read off your target. The key survives with its value replaced, because
   "`ssl.keystore.password` is configured" is posture and only the value is secret.
3. **Shape** — URL userinfo (`amqp://user:pw@host`) and PEM private keys, which hide in a value
   position under an innocent key like `url`.

Log records go through the same scrub, because your log shipper probably does leave your network.

### Honest limits of redaction

- **Credentials shorter than 8 characters are not value-scrubbed.** This is deliberate. RabbitMQ's
  default login is `guest`/`guest`; blanking every occurrence of "guest" would gut the observation
  of the rule that exists to *report* it. Short credentials remain covered by the key and shape
  layers — and a credential that guessable is already a finding, not a secret worth protecting.
- **Redaction is a backstop, not the mechanism.** If you are evaluating this, evaluate the
  structure (what `run_job()` builds), not just the filter.
- **A determined connector could still encode a secret past it** — base64, a hash, a substring.
  Nothing in-process can prevent that. What protects you is that the connectors are open source and
  you can read them.

## The control plane cannot tell the Collector where to connect

A job is a **reference to a locally configured target** — `{"target": "prod-kafka"}` — never a
connection config. Config-shaped fields on an incoming job are ignored by construction; we never
read one.

This matters more than it looks. If the control plane could hand the Collector a host and a
credential, then anyone who compromised *us* could aim your Collector at any address inside your
network, or at a broker they own, and it would dial out holding your credentials. It can't. The
worst a compromised control plane can do is ask you to scan a system you already configured, and
read the findings you were already sending. Test covering this:
`tests/test_payload.py::test_job_cannot_tell_the_collector_where_to_connect`.

## Network posture

- **No inbound port.** No `bind()`, no `listen()`, no web framework, no `EXPOSE`. Verify:
  `ss -ltnp` inside the container lists nothing.
- **One outbound destination:** your `VECTASEC_CONTROL_PLANE_URL`, TLS on 443. Plus whatever
  targets you configured, inside your own network.
- **HTTPS is enforced** for the control plane. Downgrade requires
  `VECTASEC_ALLOW_INSECURE_CONTROL_PLANE=1`, which is named that way so it cannot be set by
  accident, and is for local development only.
- **Egress-proxy friendly:** `VECTASEC_CA_BUNDLE` points at your CA bundle if your proxy
  terminates TLS.
- **Backoff:** jittered exponential, capped. A control plane outage doesn't turn a fleet of
  Collectors into a retry storm against you or us.
- **Read-only:** connectors issue only reads. The Collector never writes to a customer system.

## Verify the claims yourself

Do not take our word for any of the above.

```bash
# 1. Print exactly what WOULD be sent — against your real broker, with your real credentials.
#    Enrolls nothing, sends nothing, opens no connection to us. Read the JSON.
vectasec-collector preview

# 2. Validate config and show the redacted view of every target.
vectasec-collector check

# 3. Watch the wire.
tcpdump -i any -n host <control-plane-ip>

# 4. Prove it needs no ingress: deny all inbound to the pod. Nothing changes.
# 5. Prove it can't phone anywhere else: allow egress only to the control plane. Nothing changes.
# 6. Read the boundary. It is one file, ~90 lines: src/collector/redact.py
```

`preview` exists specifically so this conversation ends with you reading real output rather than
reading our marketing.

---

## Implemented vs stubbed

Straight answers. Do not deploy this to production on the strength of this README alone — it is
early software and the list below is the honest state of it.

### Implemented and tested

| | |
|---|---|
| Enroll → short-lived tenant token → heartbeat → long-poll → local scan → redact → push | the whole loop closes — driven end to end against a fake control plane in `tests/test_control_plane.py` |
| Credentials local; never in any outbound payload | `tests/test_payload.py`, `tests/test_redact.py`, and asserted on the pushed body in `tests/test_control_plane.py` |
| `Resource.raw` never leaves | by construction — the payload builder never assembles it. Also asserted on the pushed body. |
| Job cannot carry a connection config | tested |
| Outbound-only, no listener | no bind/listen anywhere in the source |
| `sha256(enrollment token)` stored; raw token and service token never on disk | tested (`test_neither_token_reaches_the_disk`, which also asserts mode 0600) |
| Log records scrubbed, including exception objects and tracebacks | `tests/test_log_filter.py` |
| TLS verification cannot be turned off by an unparseable flag value | `tests/test_config.py` |
| Same connectors + detectors as the cloud engine (73 rules), same fingerprints | imported from the engine, not forked |
| `preview` / `check` for offline review | |
| Non-root container, no shell, no package manager | |
| TLS verification, custom CA bundle, jittered backoff, SIGTERM shutdown | |

### Stubbed, missing, or not what you might assume

| Thing | Status |
|---|---|
| **mTLS to the control plane** | **Not implemented.** The plan says mTLS; today it is server-side TLS plus a bearer token. Client auth is a token, not a certificate. |
| **Signed images / SBOM / provenance** | **Not implemented.** No cosign signature, no attestation. "A single signed container" is a plan, not a fact. Build from source and verify it yourself. |
| **The control-plane endpoints** | **Not built.** The Collector implements the client side of `/collector/{enroll,heartbeat,jobs,results}`. The Edge Functions that serve them do not exist yet. This code is written against a contract, and the client is tested against a fake server (`httpx.MockTransport`, `tests/test_control_plane.py`) — never a real one. A fake server agrees with the contract by construction; it cannot tell us the contract is right. |
| **State file is write-only** | The Collector writes `state.json` (collector id + `sha256(enrollment token)`) and never reads it back. It is a record for you to inspect, not state the Collector resumes from: every restart re-enrolls and takes a fresh server-assigned collector id. Nothing detects a rotated enrollment token in advance — a rotated token simply fails enrollment with a 401 and the process exits saying so. |
| **Per-target rate limiting (token bucket)** | **Not implemented.** The plan promises we never overload your production broker. Today a scan calls your admin API as fast as the connector does. Believe this claim when you see the code. |
| **Result durability** | Push is one POST with in-memory retry. If the control plane is down long enough, that scan's results are dropped and the next scan supersedes them. No on-disk spool. |
| **Large payloads** | Sent in one request; no chunking. A very large estate will need it. |
| **Self-update / pinned channel** | **Not implemented.** You pin the image tag; nothing auto-updates. (We think this is the right default anyway.) |
| **Kafka SASL/TLS** | The engine's Kafka connector builds its admin client with `bootstrap.servers` only — it does not yet pass SASL or TLS settings through. A SASL-authenticated cluster is not scannable today. This is an engine gap, not a Collector one, but it is the Collector you would notice it in. |
| **Fingerprint trust** | The Collector computes finding fingerprints locally so triage history survives a topology change. The control plane must **recompute** them rather than trust the client — every input is in the payload. That is a control-plane obligation and it is not written yet. |
| **Image size** | The Collector installs the engine, so it currently carries the engine's full dependency set — `psycopg`, `fastapi`, `uvicorn`, `anthropic` — none of which the Collector uses. That is unnecessary attack surface. Splitting the engine's control-plane deps behind an optional extra is the fix. |

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `VECTASEC_CONTROL_PLANE_URL` | — | **Required.** Must be `https://`. |
| `VECTASEC_ENROLL_TOKEN_FILE` | — | **Preferred.** Path to the enrollment token. |
| `VECTASEC_ENROLL_TOKEN` | — | Fallback. Weaker — env vars leak. |
| `VECTASEC_TARGETS_FILE` | `/etc/vectasec/targets.json` | Supports `${ENV_VAR}`. |
| `VECTASEC_STATE_DIR` | `/var/lib/vectasec` | Holds collector id + token hash only. |
| `VECTASEC_COLLECTOR_NAME` | hostname | Shown in the console. |
| `VECTASEC_CA_BUNDLE` | — | For TLS-terminating egress proxies. |
| `VECTASEC_VERIFY_TLS` | `true` | Leave it alone. Accepts `1/true/yes/on` or `0/false/no/off`; anything else is a boot error, not a silent `false`. |
| `VECTASEC_TIMEOUT_S` / `_POLL_WAIT_S` / `_POLL_INTERVAL_S` / `_HEARTBEAT_INTERVAL_S` / `_MAX_BACKOFF_S` | `30` / `25` / `5` / `60` / `300` | |
| `VECTASEC_LOG_LEVEL` | `INFO` | |
| `VECTASEC_ALLOW_INSECURE_CONTROL_PLANE` | unset | Local dev only. Same strict boolean parsing. |

### `targets.json`

The credential is `${...}` here, not a literal — so this file can live in git.

```json
{
  "targets": [
    { "name": "prod-kafka",  "type": "kafka",
      "config": { "bootstrap": "kafka-1.internal:9092" } },

    { "name": "prod-kong",   "type": "kong",
      "config": { "url": "http://kong.internal:8001", "admin_token": "${KONG_ADMIN_TOKEN}" } },

    { "name": "prod-rabbit", "type": "rabbitmq",
      "config": { "url": "https://rabbit.internal:15672",
                  "username": "vectasec-ro", "password": "${RABBIT_PASSWORD}" } }
  ]
}
```

Target `name` is what a scan job addresses; it must be unique, and it is the only part of this file
we ever see.

## Running

```bash
# Build (context is services/ — the image installs the engine from a sibling path)
docker build -f services/collector/Dockerfile -t vectasec/collector:0.0.1 services/

docker run --rm \
  -e VECTASEC_CONTROL_PLANE_URL=https://app.vectasec.com \
  -e VECTASEC_ENROLL_TOKEN_FILE=/run/secrets/enroll \
  -v /path/to/enroll.token:/run/secrets/enroll:ro \
  -v /path/to/targets.json:/etc/vectasec/targets.json:ro \
  -v vectasec-state:/var/lib/vectasec \
  vectasec/collector:0.0.1
```

The container runs as uid 10001, has **no shell and no package manager** (they are deleted from the
final layer), and exposes no ports. `docker exec … sh` will not work — that is the point. Use
`preview`, `check`, and the logs.

Recommended hardening on your side: `--read-only`, `--cap-drop=ALL`, `--security-opt
no-new-privileges`, and an egress policy allowing only the control plane and your targets.

## Development

```bash
cd services/collector
uv venv && uv pip install -e ../engine -e . pytest
.venv/bin/python -m pytest tests/ -q
```
