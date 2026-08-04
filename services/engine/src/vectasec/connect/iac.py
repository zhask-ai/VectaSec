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


def _workload_from(name: str, spec: dict, *, source: str, filename: str, text: str) -> Resource:
    """One deployable unit (a compose service or a k8s container) → an `iac_workload`."""
    image = _parse_image(spec.get("image") or "")
    # Kubernetes calls it `env`; compose and a Kafka Connect config block both use the
    # `environment` shape. Selecting on "is it compose" alone silently read nothing for Connect
    # configs, so every secret in a connector JSON went unreported.
    env = _env_pairs(spec.get("env") if source == "kubernetes" else spec.get("environment"))

    secrets, defaults, anon = [], [], []
    for key, value in env:
        sval = str(value if value is not None else "")
        is_toggle = (sval.strip().lower() in _BOOLEANISH
                     or any(key.upper().endswith(a) for a in _ANON_KEYS))
        if _SECRET_KEY.search(key) and not _is_reference(sval) and not is_toggle:
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

    ext = f"iac-{filename}-{name}"
    return Resource(
        kind="iac_workload",
        name=name,
        ext_id=ext,
        namespace=filename,
        labels={"image": image["repository"] or "?", "source": source,
                "integration": "true" if _INTEGRATION_IMAGES.search(
                    image["repository"] or name) else "false"},
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
        },
    )


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

        try:
            if _CONNECT_HINT.search(text or ""):
                kind_guess = "kafka-connect"
                doc = json.loads(text)
                cfg = doc.get("config") if isinstance(doc.get("config"), dict) else doc
                workloads.append((str(doc.get("name") or "connector"),
                                  {"environment": cfg}, "kafka-connect"))
            else:
                docs = [d for d in yaml.safe_load_all(text or "") if isinstance(d, dict)]
                if not docs:
                    parsed_ok, parse_error = False, "no YAML document found"
                for doc in docs:
                    if _COMPOSE_NAMES.search(filename) or "services" in doc:
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

        for wname, spec, source in workloads:
            r = _workload_from(wname, spec, source=source, filename=filename, text=text or "")
            resources.append(r)
            edges.append(Edge(src_ext_id=file_ext, dst_ext_id=r.ext_id, kind="declares"))

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
    base = os.path.basename(path)
    if _COMPOSE_NAMES.search(path):
        return True
    if base.endswith((".yaml", ".yml")) and _K8S_HINT.search(head):
        return True
    if base.endswith(".json") and _CONNECT_HINT.search(head):
        return True
    return False


def _walk(root: str) -> tuple[dict, dict]:
    files: dict[str, str] = {}
    unreadable: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
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
