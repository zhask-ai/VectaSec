"""Integration-as-code connector — static analysis of the manifests that DEPLOY the estate.

This is the last unbuilt half of the Supply-chain capability. Every other connector in this
product reads a system that is already running; this one reads the files that will bring one
into existence, which buys two things a live scan cannot:

  * TIME. A plaintext Kafka listener found in a compose file is a review comment. The same
    listener found by the Kafka connector is an incident with traffic already on it.
  * REACH. A literal password committed into a manifest is invisible to every live connector —
    the broker only ever sees the resolved value, and a running RabbitMQ cannot tell you that
    its credential is also sitting in a git repository. Only the file knows.

DELIBERATELY NARROW. This is *integration*-as-code, not cloud IaC: it reads the manifests that
stand up brokers, gateways and MCP servers (docker-compose, Kubernetes workloads, Kafka Connect
connector JSON). It does not attempt Terraform/CloudFormation cloud-posture analysis — that is a
different product's job, the rules would be thousands deep, and claiming it on the strength of a
handful of checks is exactly the coverage dishonesty this codebase refuses everywhere else.

ALSO READ (sprint 1 of the SMB strategy, "Also in git"): principal NAMES. A SASL username, a
RabbitMQ definitions user, a Kong consumer, an AWS access key ID or an OAuth client_id in a
manifest is an identity, not a secret — the live connectors report the same names from the
running system, and matching the two answers "is this credential also committed to a repo?".
Names are recorded on each workload (raw["principals"], labels["principals"]) and on the file.
To carry them the parser also reads RabbitMQ definitions.json exports, Kong declarative config
(`_format_version`) and Helm values files, as one synthetic workload per file. Values that sit
next to those names (password_hash, key-auth keys) stay on the secret path: fingerprinted,
never stored.

WHAT IT NEVER DOES. It never resolves a secret. When a literal credential is found, the value
is hashed to a short fingerprint and DROPPED — findings carry the key, the file, the line and
the fingerprint, never the secret. That is the same discipline connect/rabbitmq.py applies to a
password hash, for the same reason: a security product that copies your secrets into its own
database has moved the problem, not solved it.

Kinds are DISTINCT (`iac_file`, `iac_workload`, `iac_finding_site`) so no live-system rulepack
ever runs against a file.

Split for offline testing:
  collect(config)   walks a path / accepts pasted text
  parse_iac(files)  pure: {filename: text} -> Collected (the whole rulepack is tested on this)
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from ..contracts import Collected, Edge, Resource
from ..registry import ConnectorField, connector

# Files worth reading. Anything else in a repo is not integration-as-code and reading it would
# be both slow and none of our business.
_COMPOSE_NAMES = re.compile(r"(^|/)(docker-)?compose(\.\w+)?\.ya?ml$", re.I)
_K8S_HINT = re.compile(r"\b(apiVersion|kind)\s*:", re.I)
_CONNECT_HINT = re.compile(r'"connector\.class"', re.I)

# Env keys whose VALUE is a credential. Matched on the key, never on the value's shape: a
# value-shaped regex ("looks like base64") is the classic secret-scanner false-positive engine,
# and this product would rather report fewer, certain things.
#
# `_PASS\b` is separate from PASSWORD on purpose — RABBITMQ_DEFAULT_PASS is the single most
# common hardcoded broker credential in the wild and does not contain the word "password". The
# \b is what keeps it off BYPASS_* and *_PASSTHROUGH.
_SECRET_KEY = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|"
    r"SASL_JAAS_CONFIG|_PWD|_PASS\b)", re.I)

# A boolean is never a credential. Without this, every ALLOW_EMPTY_PASSWORD=yes toggle matches
# the key regex above (it contains "PASSWORD") and gets reported as a hardcoded secret — a
# false positive on the very line that is already, correctly, an ANONYMOUS_ACCESS finding.
# Reporting one misconfiguration twice under two names is how a rulepack loses trust.
_BOOLEANISH = {"true", "false", "yes", "no", "on", "off", "0", "1", "enabled", "disabled"}

# A value that is a REFERENCE, not a secret: ${VAR}, $VAR, {{ .Values.x }}, vault:..., or an
# empty string. These are the correct pattern and must never be reported.
_REFERENCE = re.compile(
    r"^\s*($|\$\{|\$[A-Za-z_]|\{\{|vault:|secretKeyRef|valueFrom|sm://|aws:|gcp:|azure:)")

# Credentials shipped by the vendor. Present in a manifest means the deployment will come up
# with them — the single most common way an integration estate is born insecure.
_DEFAULT_CREDENTIALS = {
    "guest", "admin", "password", "changeme", "redis", "kafka", "rabbitmq", "postgres",
    "root", "secret", "test", "12345", "123456", "admin123", "letmein",
}

# Settings that disable authentication outright, by the name each ecosystem uses.
_ANON_KEYS = {
    "ALLOW_ANONYMOUS_LOGIN": "Bitnami/Zookeeper anonymous login",
    "ALLOW_EMPTY_PASSWORD": "Bitnami empty-password mode",
    "KAFKA_ALLOW_EVERYONE_IF_NO_ACL_FOUND": "Kafka allow-everyone-if-no-ACL",
    "ALLOW_ANONYMOUS": "Mosquitto anonymous access",
    "REDIS_ALLOW_EMPTY_PASSWORD": "Redis empty-password mode",
    "DISABLE_AUTH": "authentication disabled",
    "AUTH_ENABLED": "authentication toggle",
}

# Env keys whose VALUE is a principal NAME — an identity, not a secret. Suffix-matched on the
# key (RABBITMQ_DEFAULT_USER, KAFKA_SASL_USERNAME, connection.user, auth.username …), first match
# wins, so the specific kinds come before the generic USERNAME/USER. The value IS stored: it is a
# name, and the Access page matches it against identity names from the live connectors to answer
# the "Also in git" column. An AWS access key ID (AKIA…/ASIA…) is a principal name too — the
# paired AWS_SECRET_ACCESS_KEY stays on the secret path above and is never stored.
_PRINCIPAL_KEYS = (
    ("AWS_ACCESS_KEY_ID", "aws_access_key_id"),
    ("SASL_USERNAME", "sasl_user"), ("SASL_USER", "sasl_user"), ("SASL.USER", "sasl_user"),
    ("SASL.USERNAME", "sasl_user"), ("KAFKA_USER", "sasl_user"), ("KAFKA_USERNAME", "sasl_user"),
    ("RABBITMQ_DEFAULT_USER", "amqp_user"), ("RABBITMQ_USER", "amqp_user"),
    ("RABBITMQ_USERNAME", "amqp_user"), ("AMQP_USER", "amqp_user"), ("AMQP_USERNAME", "amqp_user"),
    ("KONG_CONSUMER", "kong_consumer"),
    ("CLIENT_ID", "client_id"),
    ("USERNAME", "username"), ("USER", "username"),
)
# Kafka JAAS: `... required username="alice" password="…";` — the username is a SASL principal,
# the password beside it is the secret the key-regex already fingerprints and drops.
_JAAS_USERNAME = re.compile(r"username\s*=\s*[\"']([^\"']+)[\"']", re.I)
_MAX_PRINCIPALS_LABEL = 50
_MAX_PRINCIPAL_LEN = 128

# File-level formats that carry principals but are not compose/k8s workloads.
_RABBIT_HINT = re.compile(r'"(rabbit_version|rabbitmq_version|vhosts)"')
_KONG_HINT = re.compile(r"^_format_version\s*:", re.M)
_VALUES_NAMES = re.compile(r"(^|/)values(-[\w.]+)?\.ya?ml$", re.I)

# Images whose presence marks this workload as part of the integration layer. Used only to
# decide whether a workload is IN SCOPE — never to conclude anything about its security.
_INTEGRATION_IMAGES = re.compile(
    r"(kafka|rabbitmq|redis|nats|pulsar|activemq|artemis|kong|nginx|envoy|traefik|zookeeper|"
    r"etcd|consul|elasticsearch|opensearch|solr|memcached|pgbouncer|mosquitto|emqx|hivemq|"
    r"vault|keycloak|schema-registry|connect|flink|airflow|n8n|mcp|solace|ibmmq|redpanda)", re.I)


def _fingerprint(value: str) -> str:
    """A short, stable, NON-REVERSIBLE handle for a literal secret.

    Its only jobs are (a) letting a reader confirm two findings point at the same value and
    (b) letting a rotation be verified — the fingerprint changes when the secret does. It is
    truncated to 12 hex chars precisely so it is useless for cracking and useful for matching.
    """
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def _is_reference(value) -> bool:
    return bool(_REFERENCE.match(str(value or "")))


def _line_of(text: str, needle: str) -> int | None:
    """1-indexed line a key appears on, so a finding can point at a place a human can open.
    Best-effort: a key that appears twice reports the first, which is still a correct anchor."""
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return None


def _principal_kind(key: str) -> str | None:
    up = str(key or "").upper()
    for suffix, kind in _PRINCIPAL_KEYS:
        if up == suffix or up.endswith("_" + suffix) or up.endswith("." + suffix):
            return kind
    return None


def _principals_from_env(env, *, filename: str, text: str) -> list[dict]:
    """Principal NAMES in env/config pairs: [{name, kind, key, file, line}]. Never a value whose
    key matched the secret regex (AWS_ACCESS_KEY_ID excepted — it is an id, not a secret), never a
    reference (${VAR}), never a URL (a connection URL can embed a password)."""
    out: list[dict] = []
    for key, value in env:
        sval = str(value if value is not None else "").strip()
        if not sval or _is_reference(sval) or sval.lower() in _BOOLEANISH:
            continue
        kind = _principal_kind(key)
        if kind and (kind == "aws_access_key_id" or not _SECRET_KEY.search(key)):
            if "://" not in sval and len(sval) <= _MAX_PRINCIPAL_LEN:
                out.append({"name": sval, "kind": kind, "key": key, "file": filename,
                            "line": _line_of(text, key)})
        if "jaas" in key.lower() or "loginmodule" in sval.lower():
            for m in _JAAS_USERNAME.finditer(sval):
                out.append({"name": m.group(1), "kind": "sasl_user", "key": key,
                            "file": filename, "line": _line_of(text, key)})
    return _dedupe_principals(out)


def _dedupe_principals(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for p in items:
        k = (p.get("name"), p.get("kind"))
        if p.get("name") and k not in seen:
            seen.add(k)
            out.append(p)
    return out


def _principals_label(principals: list[dict]) -> str:
    names = sorted({p["name"] for p in principals})[:_MAX_PRINCIPALS_LABEL]
    return ",".join(names)


def _flatten(d: dict, prefix: str = "", _out=None, _budget=None) -> list[tuple[str, object]]:
    """Nested Helm values → dotted (key, scalar) pairs, so `auth.username` / `auth.password`
    flow through the same key-based principal/secret matching as an env block."""
    out = [] if _out is None else _out
    budget = [2000] if _budget is None else _budget
    for k, v in (d or {}).items():
        if budget[0] <= 0:
            break
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            _flatten(v, key + ".", out, budget)
        elif isinstance(v, (str, int, float)) and not isinstance(v, bool):
            out.append((key, v))
            budget[0] -= 1
    return out


def _parse_image(image: str) -> dict:
    """`registry/name:tag@sha256:...` → its parts, plus the two supply-chain facts that matter:
    whether the tag is mutable and whether the content is pinned by digest."""
    image = str(image or "").strip()
    digest = None
    if "@" in image:
        image, digest = image.split("@", 1)
    tag = None
    # Split on the LAST colon, but only when it is not part of a registry:port prefix.
    if ":" in image:
        head, maybe_tag = image.rsplit(":", 1)
        if "/" not in maybe_tag:
            image, tag = head, maybe_tag
    return {
        "repository": image,
        "tag": tag,
        "digest": digest,
        # No tag at all means :latest by default — the same mutability problem, less visible.
        "mutable_tag": tag in (None, "latest", "main", "master", "stable", "edge"),
        "digest_pinned": digest is not None,
    }


def _env_pairs(env) -> list[tuple[str, object]]:
    """Compose/k8s env in any of its three shapes → [(key, value)].

      dict            {"KAFKA_X": "y"}
      list of "K=V"   ["KAFKA_X=y"]
      list of dicts   [{"name": "KAFKA_X", "value": "y"}]   (k8s)
    """
    out: list[tuple[str, object]] = []
    if isinstance(env, dict):
        return [(str(k), v) for k, v in env.items()]
    if isinstance(env, list):
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                out.append((k.strip(), v))
            elif isinstance(item, dict):
                name = item.get("name")
                if name is None:
                    continue
                if "value" in item:
                    out.append((str(name), item.get("value")))
                else:
                    # valueFrom / secretKeyRef — the CORRECT pattern. Recorded as a reference so
                    # the secret rule stays silent and the workload is not mistaken for one
                    # with no credentials at all.
                    out.append((str(name), "valueFrom"))
    return out


def _ports_of(spec: dict) -> list[dict]:
    """Published ports, normalised. Compose `"0.0.0.0:9092:9092"` and k8s hostPort both mean
    'reachable from outside the pod/host network', which is the fact the rule needs."""
    out = []
    for p in spec.get("ports") or []:
        if isinstance(p, str):
            parts = p.split(":")
            host_ip = parts[0] if len(parts) >= 3 else None
            published = parts[-2] if len(parts) >= 2 else None
            out.append({"published": published, "host_ip": host_ip,
                        "public": host_ip in (None, "", "0.0.0.0", "::")})
        elif isinstance(p, dict):
            # compose long syntax, or a k8s containerPort
            published = p.get("published") or p.get("hostPort")
            host_ip = p.get("host_ip")
            if published is not None:
                out.append({"published": str(published), "host_ip": host_ip,
                            "public": host_ip in (None, "", "0.0.0.0", "::")})
    return out


def _workload_from(name: str, spec: dict, *, source: str, filename: str, text: str,
                   extra_principals: list | None = None,
                   extra_secrets: list | None = None) -> Resource:
    """One deployable unit (a compose service or a k8s container) → an `iac_workload`. The
    file-level formats (RabbitMQ definitions, Kong declarative config, Helm values) come through
    here too, as one synthetic workload per file with their principals/secrets pre-extracted."""
    image = _parse_image(spec.get("image") or "")
    # Kubernetes calls it `env`; compose and a Kafka Connect config block both use the
    # `environment` shape. Selecting on "is it compose" alone silently read nothing for Connect
    # configs, so every secret in a connector JSON went unreported.
    env = _env_pairs(spec.get("env") if source == "kubernetes" else spec.get("environment"))

    secrets, defaults, anon = list(extra_secrets or []), [], []
    for key, value in env:
        sval = str(value if value is not None else "")
        is_toggle = (sval.strip().lower() in _BOOLEANISH
                     or any(key.upper().endswith(a) for a in _ANON_KEYS))
        # An AWS access key ID is a principal name (recorded below), not a secret.
        is_principal_id = _principal_kind(key) == "aws_access_key_id"
        if (_SECRET_KEY.search(key) and not _is_reference(sval) and not is_toggle
                and not is_principal_id):
            secrets.append({"key": key, "fingerprint": _fingerprint(sval),
                            "length": len(sval), "line": _line_of(text, key)})
            if sval.strip().lower() in _DEFAULT_CREDENTIALS:
                defaults.append({"key": key, "line": _line_of(text, key)})
        upper = key.upper()
        for anon_key, why in _ANON_KEYS.items():
            if upper.endswith(anon_key):
                truthy = sval.strip().lower() in ("yes", "true", "1", "on")
                falsy = sval.strip().lower() in ("no", "false", "0", "off")
                # AUTH_ENABLED is the inverted one: enabled=false is the finding.
                enabled_anon = falsy if anon_key == "AUTH_ENABLED" else truthy
                if enabled_anon:
                    anon.append({"key": key, "why": why, "value": sval,
                                 "line": _line_of(text, key)})

    listeners = [str(v) for k, v in env if "LISTENER" in k.upper() or "ADVERTISED" in k.upper()]
    plaintext_listeners = [l for l in listeners if "PLAINTEXT://" in l.upper()]
    principals = _dedupe_principals(
        list(extra_principals or []) + _principals_from_env(env, filename=filename, text=text))

    ext = f"iac-{filename}-{name}"
    labels = {"image": image["repository"] or "?", "source": source,
              "integration": "true" if _INTEGRATION_IMAGES.search(
                  image["repository"] or name) else "false"}
    if principals:
        # Names only (never a secret), comma-joined and capped, so the Access page can match
        # identity names against repos without reading `raw`.
        labels["principals"] = _principals_label(principals)
    return Resource(
        kind="iac_workload",
        name=name,
        ext_id=ext,
        namespace=filename,
        labels=labels,
        raw={
            "workload": name,
            "file": filename,
            "source_format": source,
            "image": image,
            "is_integration_component": bool(
                _INTEGRATION_IMAGES.search(image["repository"] or name)),
            "privileged": bool(spec.get("privileged")
                               or (spec.get("securityContext") or {}).get("privileged")),
            "ports": _ports_of(spec),
            "env_key_count": len(env),
            # VALUES NEVER TRAVEL. Only keys, fingerprints and lengths.
            "literal_secrets": secrets,
            "default_credentials": defaults,
            "anonymous_access": anon,
            "plaintext_listeners": plaintext_listeners,
            "listener_count": len(listeners),
            # Principal NAMES declared here — identities, not secrets. Each is a name a live
            # connector could also report (a SASL user, a Kong consumer, an AWS key id), which is
            # how "this credential is also in git" gets answered.
            "principals": principals,
        },
    )


# ── file-level formats: principals and secrets out of a whole document ─────────
def _rabbitmq_definitions(doc: dict, *, filename: str, text: str) -> tuple[list, list]:
    """RabbitMQ definitions export: users[].name are AMQP principals; users[].password_hash is a
    credential and is fingerprinted, never kept."""
    principals, secrets = [], []
    for u in doc.get("users") or []:
        if not isinstance(u, dict) or not u.get("name"):
            continue
        name = str(u["name"])
        principals.append({"name": name, "kind": "amqp_user", "key": "users[].name",
                           "file": filename, "line": _line_of(text, f'"{name}"')})
        ph = u.get("password_hash")
        if ph and not _is_reference(str(ph)):
            secrets.append({"key": f"users[{name}].password_hash",
                            "fingerprint": _fingerprint(str(ph)),
                            "length": len(str(ph)), "line": _line_of(text, str(ph))})
    return principals, secrets


_KONG_CRED_FIELDS = {"keyauth_credentials": "key", "basicauth_credentials": "password",
                     "jwt_secrets": "secret", "hmac_auth_credentials": "secret",
                     "oauth2_credentials": "client_secret"}


def _kong_declarative(doc: dict, *, filename: str, text: str) -> tuple[list, list]:
    """Kong declarative (deck / DB-less) config: consumers[].username are API consumers;
    key-auth keys, basic-auth passwords, jwt / hmac / oauth2 secrets are credentials —
    fingerprinted only. Credentials may be nested under a consumer or listed top-level."""
    principals, secrets = [], []

    def _creds(owner: str, block: dict):
        for coll, field in _KONG_CRED_FIELDS.items():
            for c in block.get(coll) or []:
                if not isinstance(c, dict):
                    continue
                val = c.get(field)
                if val and not _is_reference(str(val)):
                    secrets.append({"key": f"consumers[{owner}].{coll}[].{field}",
                                    "fingerprint": _fingerprint(str(val)), "length": len(str(val)),
                                    "line": _line_of(text, str(val))})
                for pk in ("username", "client_id"):
                    if c.get(pk):
                        principals.append({"name": str(c[pk]), "kind": "kong_consumer",
                                           "key": f"{coll}[].{pk}", "file": filename,
                                           "line": _line_of(text, str(c[pk]))})

    for c in doc.get("consumers") or []:
        if not isinstance(c, dict):
            continue
        uname = c.get("username") or c.get("custom_id")
        if uname:
            principals.append({"name": str(uname), "kind": "kong_consumer",
                               "key": "consumers[].username", "file": filename,
                               "line": _line_of(text, str(uname))})
        _creds(str(uname or "?"), c)
    for coll in _KONG_CRED_FIELDS:
        for c in doc.get(coll) or []:
            if isinstance(c, dict):
                owner = c.get("consumer")
                owner = (owner.get("username") or owner.get("id")) if isinstance(owner, dict) else owner
                if owner:
                    principals.append({"name": str(owner), "kind": "kong_consumer",
                                       "key": f"{coll}[].consumer", "file": filename,
                                       "line": _line_of(text, str(owner))})
                _creds(str(owner or "?"), {coll: [c]})
    return principals, secrets


def parse_iac(files: dict, *, unreadable: dict | None = None) -> Collected:
    """PURE: {filename: text} → Collected. No filesystem, no yaml import cost for the caller.

    Every file becomes an `iac_file` (so a file we could not parse is VISIBLE rather than
    silently skipped — an unparsed manifest is a coverage gap, and coverage gaps are findings
    in this product), plus one `iac_workload` per deployable unit inside it.
    """
    import yaml

    resources: list[Resource] = []
    edges: list[Edge] = []

    for filename, text in sorted((files or {}).items()):
        parsed_ok, parse_error, kind_guess = True, None, "unknown"
        workloads: list[tuple[str, dict, str]] = []

        extras: dict[str, tuple[list, list]] = {}      # workload name → (principals, secrets)
        from .mcp_client import looks_like_mcp_client_config, parse_mcp_client_config
        mcp_servers: list = []
        try:
            if looks_like_mcp_client_config(filename, (text or "")[:4096]):
                kind_guess = "mcp-client-config"
                mcp_servers, err = parse_mcp_client_config(filename, text or "")
                if err:
                    parsed_ok, parse_error = False, err
            elif _CONNECT_HINT.search(text or ""):
                kind_guess = "kafka-connect"
                doc = json.loads(text)
                cfg = doc.get("config") if isinstance(doc.get("config"), dict) else doc
                workloads.append((str(doc.get("name") or "connector"),
                                  {"environment": cfg}, "kafka-connect"))
            elif _RABBIT_HINT.search(text or "") and (text or "").lstrip().startswith("{"):
                kind_guess = "rabbitmq-definitions"
                doc = json.loads(text)
                if isinstance(doc.get("users"), list):
                    wname = "rabbitmq-definitions"
                    extras[wname] = _rabbitmq_definitions(doc, filename=filename, text=text)
                    workloads.append((wname, {}, "rabbitmq-definitions"))
                else:
                    parsed_ok, parse_error = False, "no users[] in definitions document"
            else:
                docs = [d for d in yaml.safe_load_all(text or "") if isinstance(d, dict)]
                if not docs:
                    parsed_ok, parse_error = False, "no YAML document found"
                for doc in docs:
                    if "_format_version" in doc:
                        # Kong declarative config also has a `services:` list — test before compose.
                        kind_guess = "kong-declarative"
                        wname = "kong-declarative"
                        extras[wname] = _kong_declarative(doc, filename=filename, text=text)
                        workloads.append((wname, {}, "kong-declarative"))
                    elif (_VALUES_NAMES.search(filename) and "services" not in doc
                          and not doc.get("kind")):
                        kind_guess = "helm-values"
                        wname = os.path.splitext(os.path.basename(filename))[0]
                        workloads.append((wname, {"environment": dict(_flatten(doc))},
                                          "helm-values"))
                    elif _COMPOSE_NAMES.search(filename) or "services" in doc:
                        kind_guess = "compose"
                        for svc_name, svc in (doc.get("services") or {}).items():
                            if isinstance(svc, dict):
                                workloads.append((str(svc_name), svc, "compose"))
                    elif doc.get("kind"):
                        kind_guess = "kubernetes"
                        pod = (((doc.get("spec") or {}).get("template") or {}).get("spec")
                               or doc.get("spec") or {})
                        for c in (pod.get("containers") or []):
                            if isinstance(c, dict):
                                merged = dict(c)
                                # hostNetwork lifts every containerPort onto the node.
                                if pod.get("hostNetwork"):
                                    merged["ports"] = [
                                        {**p, "hostPort": p.get("hostPort") or p.get("containerPort")}
                                        for p in (c.get("ports") or []) if isinstance(p, dict)]
                                workloads.append(
                                    (f"{doc.get('metadata', {}).get('name') or doc['kind']}"
                                     f"/{c.get('name') or 'container'}", merged, "kubernetes"))
        except (yaml.YAMLError, ValueError, AttributeError, TypeError) as e:
            parsed_ok, parse_error = False, f"{type(e).__name__}: {e}"

        file_ext = f"iac-file-{filename}"
        resources.append(Resource(
            kind="iac_file",
            name=filename,
            ext_id=file_ext,
            labels={"format": kind_guess, "parsed": str(parsed_ok).lower()},
            raw={
                "file": filename,
                "format": kind_guess,
                "parsed": parsed_ok,
                "parse_error": parse_error,
                "workload_count": len(workloads),
                "bytes": len(text or ""),
            },
        ))

        file_res = resources[-1]
        file_res.raw["workload_count"] += len(mcp_servers)
        for m in mcp_servers:
            resources.append(m)
            edges.append(Edge(src_ext_id=file_ext, dst_ext_id=m.ext_id, kind="declares"))
        file_principals: list[dict] = []
        for wname, spec, source in workloads:
            ep, es = extras.get(wname, ([], []))
            r = _workload_from(wname, spec, source=source, filename=filename, text=text or "",
                               extra_principals=ep, extra_secrets=es)
            resources.append(r)
            edges.append(Edge(src_ext_id=file_ext, dst_ext_id=r.ext_id, kind="declares"))
            file_principals.extend(r.raw.get("principals") or [])
        # The manifest resource carries the union of its workloads' principals, so a repo-level
        # match ("is this SASL user in this file?") needs only the file row.
        file_principals = _dedupe_principals(file_principals)
        file_res.raw["principals"] = file_principals
        if file_principals:
            file_res.labels["principals"] = _principals_label(file_principals)

    # Files we were asked for but could not open at all (permissions, vanished mid-walk). Named
    # so the console can show that the requested scope was not fully covered.
    for filename, why in (unreadable or {}).items():
        resources.append(Resource(
            kind="iac_file",
            name=filename,
            ext_id=f"iac-file-{filename}",
            labels={"format": "unreadable", "parsed": "false"},
            raw={"file": filename, "format": "unknown", "parsed": False,
                 "parse_error": why, "workload_count": 0, "bytes": 0},
        ))

    return Collected(resources=resources, edges=edges)


# ── collection (filesystem walk / pasted text) ───────────────────────────────
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
              ".next", "target", ".terraform"}
# A manifest is small. Anything larger is a data file that happens to end in .yaml, and
# reading it would cost time and memory for no finding.
_MAX_BYTES = 512 * 1024
_MAX_FILES = 500


def _looks_like_iac(path: str, head: str) -> bool:
    from .mcp_client import looks_like_mcp_client_config
    if looks_like_mcp_client_config(path, head):
        return True
    base = os.path.basename(path)
    if _COMPOSE_NAMES.search(path):
        return True
    if base.endswith((".yaml", ".yml")) and _K8S_HINT.search(head):
        return True
    if base.endswith(".json") and (_CONNECT_HINT.search(head) or _RABBIT_HINT.search(head)):
        return True
    if base.endswith((".yaml", ".yml")) and (_KONG_HINT.search(head) or _VALUES_NAMES.search(path)):
        return True
    return False


def _walk(root: str) -> tuple[dict, dict]:
    files: dict[str, str] = {}
    unreadable: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        from .mcp_client import MCP_CONFIG_DIRS
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS
                       and (not d.startswith(".") or d in MCP_CONFIG_DIRS)]
        for fn in filenames:
            if len(files) >= _MAX_FILES:
                return files, unreadable
            if not fn.endswith((".yaml", ".yml", ".json")):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                if os.path.getsize(full) > _MAX_BYTES:
                    continue
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as e:
                unreadable[rel] = f"{type(e).__name__}: {e}"
                continue
            if _looks_like_iac(full, text[:4096]):
                files[rel] = text
    return files, unreadable


@connector("iac", fields=[
    ConnectorField("source_path", "Manifest path", placeholder="/srv/deploy",
                   help="A directory or single file the engine can read. Walked read-only for "
                        "docker-compose files, Kubernetes workload manifests and Kafka Connect "
                        "connector JSON. Nothing is written and no repository is cloned."),
    ConnectorField("source_text", "Manifest text",
                   help="Paste a manifest instead of giving a path — useful for CI, or when the "
                        "repository is not on a filesystem the engine can reach."),
    ConnectorField("source_name", "Manifest name", placeholder="docker-compose.yml",
                   help="Filename to attribute pasted text to, so findings point somewhere a "
                        "human can open. Defaults to docker-compose.yml."),
])
def collect(config: dict) -> Collected:
    text = config.get("source_text")
    if text and str(text).strip():
        name = (config.get("source_name") or "docker-compose.yml").strip()
        return parse_iac({name: str(text)})

    path = (config.get("source_path") or "").strip()
    if not path:
        raise SystemExit("iac connector requires config['source_path'] or config['source_text']")
    path = os.path.expanduser(path)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return parse_iac({os.path.basename(path): fh.read()})
        except OSError as e:
            return parse_iac({}, unreadable={os.path.basename(path): f"{type(e).__name__}: {e}"})
    if not os.path.isdir(path):
        raise SystemExit(f"iac connector: {path!r} is neither a file nor a directory")

    files, unreadable = _walk(path)
    return parse_iac(files, unreadable=unreadable)
