# VectaSec — self-hosted (on-prem)

For customers who will not accept any external processing. Same codebase as the SaaS path, two
topologies. Nothing here phones home; the AI layer is off unless you supply a key, and with no
key the engine runs its deterministic rule-based triage locally.

**Read [Not production-ready](#what-is-not-production-ready-yet) before you deploy this to
anything that matters.** There are three things in it that will surprise you, and one of them is
a cross-tenant hole.

---

## What is in the stack

| Service    | Image                          | Why it is here |
|------------|--------------------------------|----------------|
| `db`       | `supabase/postgres:15.8.1.060` | Postgres + `pgcrypto`, `pgmq`, `pg_cron` and the `anon`/`authenticated`/`service_role` roles the migrations need. |
| `migrate`  | `supabase/postgres:15.8.1.060` | One-shot. Applies `supabase/migrations/*.sql` in filename order, then exits. |
| `auth`     | `supabase/gotrue:v2.174.0`     | Login. The console calls `supabase.auth.getClaims()`. |
| `rest`     | `postgrest/postgrest:v12.2.12` | The console's read path. **This is the tenant-isolation boundary** — it connects as `authenticator` (NOBYPASSRLS) so RLS applies. |
| `realtime` | `supabase/realtime:v2.34.47`   | `LiveFindings.tsx` subscribes to a private channel on `findings`. |
| `engine`   | built here                     | The scan/action API (FastAPI). Holds a **BYPASSRLS** connection. |
| `worker`   | built here                     | **Disabled.** See below — there is nothing for it to do yet. |
| `web`      | built here                     | The Next.js console. |
| `caddy`    | `caddy:2.8-alpine`             | TLS + one origin for all of the above. |

**Not run, deliberately:**

- **storage-api** — nothing uploads or reads a file. In a security product an unused container
  is attack surface you have to defend. Add it when a report export lands.
- **Kong** — upstream Supabase fronts these with Kong; Caddy does the same routing and we
  already need Caddy for TLS. Kong's `key-auth` was never the boundary anyway: PostgREST and
  Realtime verify the JWT themselves against `JWT_SECRET`.

**Routing** (all one origin, which is why the console needs no CORS):

```
https://host/            → web
https://host/auth/v1/*   → auth
https://host/rest/v1/*   → rest
https://host/realtime/v1 → realtime
https://host/api/*       → engine      ← IP-gated. Read the security note.
```

**Ports.** Only Caddy is published (`8080`/`8443` by default); Postgres is on `127.0.0.1:55432`
for `psql` and dumps; everything else is internal-only. The defaults avoid what this dev host
already runs: `80`/`443` (the sibling `kaveo` stack), `9092`/`9093` (the deliberately
misconfigured Kafka in `deploy/dev`), `3000`/`8000` (`next dev`, engine dev), `5432`. On a
dedicated host, set `80`/`443` — and then ACME can actually work.

---

## Prerequisites

- Docker Engine 24+ with Compose v2 (`docker compose version`).
- 4 vCPU / 8 GB RAM / 20 GB disk for a small deployment. The `web` image is the memory hog.
- `openssl` for generating secrets.
- x86_64 or arm64. All images publish both.
- **No outbound internet required at runtime.** You need it once to pull base images and build,
  unless you mirror (see [Air-gap](#air-gap)).

## Install

```bash
cd deploy/onprem
cp .env.example .env
```

Fill the five required secrets in `.env` — compose refuses to start without them rather than
booting something subtly wrong:

```bash
openssl rand -hex 32     # POSTGRES_PASSWORD
openssl rand -hex 32     # JWT_SECRET
openssl rand -hex 8      # REALTIME_DB_ENC_KEY       (exactly 16 chars — realtime won't boot otherwise)
openssl rand -base64 48  # REALTIME_SECRET_KEY_BASE  (64+ chars)
```

`ANON_KEY` is the fifth: an HS256 JWT with payload `{"role":"anon","iss":"supabase"}` signed
with your `JWT_SECRET`. There is no in-repo generator yet — use any offline HS256 signer or the
[Supabase self-hosting docs](https://supabase.com/docs/guides/self-hosting#api-keys). A mismatch
with `JWT_SECRET` presents as a console that loads and then 401s on every query.

Set `VECTASEC_PUBLIC_URL` to the URL operators will actually type. **Then:**

```bash
docker compose -f deploy/onprem/docker-compose.yml up -d --build
```

`--build` is not optional: no registry publishes these images yet.

Check it:

```bash
docker compose -f deploy/onprem/docker-compose.yml ps
curl -sk https://localhost:8443/api/health | jq
# {"status":"ok","db":true,"detectors":N,"connectors":["kafka","kong","mcp","rabbitmq"]}
```

`"db": true` is the bit that matters — `/health` returns 200 even when Postgres is down (by
design: a health check that refuses to answer can't tell you which half is broken), so the
status code alone proves nothing.

With `VECTASEC_TLS=internal` (the default) your browser will warn until you trust Caddy's root:

```bash
docker compose -f deploy/onprem/docker-compose.yml cp \
  caddy:/data/caddy/pki/authorities/local/root.crt ./vectasec-root.crt
```

### First operator account

`GOTRUE_DISABLE_SIGNUP=true` by default — correct for an internal security console. Create the
first account with signup temporarily open, or insert via gotrue's admin API using a
`service_role` JWT. **There is no bootstrap-admin command yet**; this is a rough edge.

## TLS

`VECTASEC_TLS` is passed straight to Caddy's `tls` directive:

| Value | Meaning |
|---|---|
| `internal` | Caddy's own CA. **The default**, because ACME cannot work on `:8443` — HTTP-01 needs public `:80`. |
| `you@example.com` | Let's Encrypt. Needs `VECTASEC_HTTP_PORT=80`, `VECTASEC_HTTPS_PORT=443`, a public DNS name, and egress. Usually wrong for an air-gapped site. |
| `/certs/site.pem /certs/site.key` | Your own cert. **The honest choice for most on-prem** and the only one that works air-gapped with a chain clients already trust. Mount them into the `caddy` service yourself. |

## Migrations

Applied by the `migrate` service on every `up`, in filename order, with `ON_ERROR_STOP=1`.
`auth`, `rest`, `realtime` and `engine` all wait on `service_completed_successfully`, so nothing
talks to a half-migrated schema.

**There is no version ledger.** Every migration re-runs on every boot. That is safe *today* only
because both existing migrations are written idempotently (`create ... if not exists`, `add
column if not exists`). **A new migration that is not idempotent will break restart.** This is
the stack's sharpest edge and the first thing to fix if you add migrations — this directory does
not own `supabase/migrations/`, so the fix belongs there (adopt the Supabase CLI's
`schema_migrations` ledger, or gate each file).

Apply them by hand against an external Postgres:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f supabase/migrations/20260717000001_core_schema.sql \
  -f supabase/migrations/20260717000002_platform_schema.sql
```

## Upgrade

```bash
git pull
docker compose -f deploy/onprem/docker-compose.yml up -d --build
```

Compose recreates changed containers only; `migrate` re-runs first. Rollback is `git checkout
<prev> && up -d --build` — **but only if the migrations in between were additive.** Nothing here
generates down-migrations, so a schema change that drops or rewrites a column is a one-way door.
Back up first, always:

```bash
docker compose -f deploy/onprem/docker-compose.yml exec db \
  pg_dump -U postgres --format=custom postgres > vectasec-$(date +%F).dump
```

Back up the `caddy-data` volume too if you use `tls internal` — it holds the CA, and losing it
means every client re-trusts a new root.

## Kubernetes (Helm)

`helm/` deploys the three VectaSec workloads **only**. It does not bring Postgres or the
Supabase components — see `Chart.yaml` for why (short version: this database holds the evidence
ledger, and a convenience Postgres with a default password is the wrong default in exactly the
deployments this chart exists for).

```bash
helm install vectasec ./deploy/onprem/helm \
  --namespace vectasec --create-namespace \
  --set publicUrl=https://vectasec.example.com \
  --set ingress.host=vectasec.example.com \
  --set database.existingSecret=vectasec-db \
  --set supabase.url=https://vectasec.example.com \
  --set supabase.anonKey=eyJ... \
  --set web.image.repository=registry.internal/vectasec/web \
  --set web.image.tag=0.1.0-example-com
```

Every pod is `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, drops
all capabilities, and has requests/limits. Engine probes hit `/health`; **web probes hit `/`**,
because the console has no health route — a 307 to `/login` counts as a pass, which proves Next
is serving and nothing more.

The chart does **not** apply migrations and does **not** deploy an ingress path for Supabase.
`NOTES.txt` says both out loud on every install.

---

## What is not production-ready yet

Nothing below is speculative. Each one is a fact about the code in this repo today.

### 1. The engine API authenticates nobody — this is a cross-tenant hole

`api/main.py`'s `principal()` reads the tenant from an `X-VectaSec-Tenant` header and **believes
it**. Its own comment says so:

> `TODO(auth): a real deployment MUST verify a Supabase JWT here ... As written they are
> self-asserted: any caller can name any tenant and any actor.`

That process holds a **BYPASSRLS** connection. So anything that can reach `/api/` can read and
modify **every tenant's** findings, evidence and suppressions by typing a different UUID in a
header. The code defends itself by binding to `127.0.0.1`; containerising it necessarily
overrides that (`ENGINE_HOST=0.0.0.0`).

The Caddy CIDR gate (`VECTASEC_ENGINE_ALLOWED_CIDRS`) is a **network stopgap standing in for
authentication that does not exist**. It authenticates no one — a single compromised host inside
an allowed range has full cross-tenant access. Do not read that config as "auth done". On
Kubernetes there is no equivalent default at all; you must set a source-range annotation
yourself.

**Single-tenant on-prem reduces the blast radius but does not close the hole**: the actor on
every audit row is still self-asserted, so the audit trail is unattributable.

### 2. There is no worker

Disabled in both compose (`profiles: ["worker"]`) and Helm (`worker.enabled: false`), because
there is nothing to run:

- **Nothing consumes the pgmq queue `vectasec_scans`.** `POST /scans` without `inline: true`
  enqueues a job that stays `queued` forever. `api/main.py` states this itself: *"no worker
  consumes the queue yet"*.
- **The collector cannot stand in.** It polls `/collector/enroll`, `/collector/heartbeat`,
  `/collector/jobs` and `/collector/results` — the engine implements **none of the four**.
  Enabled today it 404s on enroll and CrashLoops.

The service definitions ship as reviewable wiring, not as working components. **Scans work
today only via `inline: true`** (which runs in the API request) or the `vectasec scan` CLI.

### 3. The console image is not a universal artifact

Next.js inlines `NEXT_PUBLIC_*` into the browser bundle **at build time**. So `vectasec/web` is
bound to one hostname and one anon key, and **"same image, two topologies" holds for the engine
but not for the console**. You cannot repoint a built console by editing `.env` and restarting.

Compose hides this by building locally. **Helm cannot** — you must build and push a per-hostname
image (`Dockerfile.web` takes the build args). Fixing it properly means a runtime-config shim in
the app, which is outside this directory's remit.

### 4. Offline licensing — does not exist

No license check, no entitlement, no seat count, no expiry. Nothing stops a customer running
this forever on any number of hosts. If on-prem is a commercial tier, this is the gap.

### 5. Air-gap — partial

The **runtime** is genuinely offline: no telemetry, no calls out, and a blank `ANTHROPIC_API_KEY`
keeps triage local. What is missing is the **delivery**: no bundle target (`docker save` tarball
+ checksums), no mirrored base images, no offline install path. Today you need internet once, to
pull and build. `VECTASEC_*_IMAGE` and `image.registry` exist so you can point at your own
mirror, but nothing produces that mirror for you.

### 6. Signed images — no

No signing, no provenance, no SBOM, no published digests. Tags are pinned by version, which
protects against drift but **not against a registry compromise** — a tag can be repointed.
Verify digests yourself and pin by `@sha256:` if that is in your threat model. For a security
vendor shipping into regulated environments this needs to become Cosign + SLSA provenance + an
SBOM per image.

### 7. Smaller, real

- **`web` image is fat.** `next.config.ts` does not set `output: 'standalone'`, so the runtime
  layer carries the full `node_modules` tree and pnpm. Roughly an order of magnitude larger than
  it needs to be. (Fix belongs in `apps/web`, not here.)
- **No `/health` on the console.** Probes use `/`.
- **No healthcheck on `rest`.** The PostgREST image has no shell, curl or wget, so any test
  would be a lie that always passes or always fails.
- **No HA.** Single Postgres, no replica, no PgBouncer. `db-data` is a local volume.
- **No backup automation.** The `pg_dump` above is manual.
- **No first-admin bootstrap.** See above.
- **Realtime needs the `findings` table in the `supabase_realtime` publication** and an RLS
  policy on `realtime.messages` (`LiveFindings.tsx` documents both). Neither is applied here —
  the live panel renders nothing until they are.
- **Secrets are env vars and Kubernetes Secrets** (base64, not encryption). Anyone with `get
  secret` in the namespace reads a BYPASSRLS DSN. Use `database.existingSecret` with a real
  secret store.
- **`--profile worker` mounts `./targets.json` and `./enroll_token`**, which do not exist; Docker
  would silently create directories. Moot while the worker cannot work.

---

## Validation status

What was actually run against this directory, not what should pass:

```bash
docker compose -f deploy/onprem/docker-compose.yml config          # ✅ valid
docker compose -f deploy/onprem/docker-compose.yml --profile worker config  # ✅ valid
docker run --rm caddy:2.8-alpine caddy validate --config …/Caddyfile        # ✅ Valid configuration
helm lint deploy/onprem/helm                                       # ✅ 0 failed
helm template … | kubeconform -strict -kubernetes-version 1.29.0   # ✅ 11/11 valid
```

Also verified: required secrets fail fast with a named error; the worker is excluded by default
and included under `--profile worker`; resolved ports are `8080`/`8443`/`55432` with no collision.

**The stack has never been started.** Ports would clash with the running `kaveo` stack and dev
Kafka on this host. So: syntax, schema and policy are verified; **runtime is not**. Nothing above
proves an image builds, a migration applies, or a container reaches its neighbour. First real
boot on a clean host should be treated as the actual test.
