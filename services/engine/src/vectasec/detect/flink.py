"""Flink rulepack — read-only Apache Flink REST posture.

Runs on the DISTINCT `flink_cluster` kind. Flink has no built-in REST authentication and its
dashboard accepts job submission by default, so an exposed endpoint is a documented RCE surface;
two path-traversal CVEs (CVE-2020-17518 file write, CVE-2020-17519 file read) live on the same
REST API for 1.11.0–1.11.2. Findings cite what /overview and /jobmanager/config returned; the
version-gated CVE check answers not-assessable when the version string is unreadable.
"""
from ..contracts import Hit
from ..registry import detector

# CVE-2020-17518 / CVE-2020-17519: unauthenticated REST path traversal (arbitrary file
# write/read). Affected 1.11.0–1.11.2, fixed in 1.11.3. Verified via NVD / Apache Flink advisory.
_TRAVERSAL_MIN = (1, 11, 0)
_TRAVERSAL_MAX = (1, 11, 2)


def _parse_version(v):
    if not v:
        return None
    head = str(v).strip().split("-")[0]   # drop -SNAPSHOT / -rc suffixes
    try:
        parts = [int(x) for x in head.split(".")[:3]]
    except ValueError:
        return None
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


@detector(kinds=["flink_cluster"], rule_id="FLINK.REST.UNAUTHENTICATED", severity="critical",
          title="Flink REST API / dashboard is reachable without authentication (job-submission RCE)")
def rest_unauthenticated(resource, ctx):
    raw = resource.raw or {}
    if not raw.get("anonymous_readable"):
        return []
    submit = raw.get("web_submit_enabled")
    return [Hit(
        observation=(
            f"apache flink REST API at {raw.get('base_url')} (version {raw.get('version')!r}) "
            f"served /overview to a client sending NO credentials. Flink has no built-in "
            f"authentication, and the REST API accepts job submission (JAR upload + run), so an "
            f"unauthenticated client can submit a job that executes arbitrary code in the cluster. "
            f"web.submit.enable is {submit!r}."),
        remediation=(
            "Do not expose the Flink REST/dashboard port (default 8081) on an untrusted network: "
            "bind it to localhost or a private interface and front it with an authenticating, "
            "TLS-terminating reverse proxy. Set web.submit.enable=false and web.cancel.enable=false "
            "on production clusters that do not need interactive submission, and enable "
            "security.ssl.rest.enabled with mutual TLS between components."),
        detail=(
            "Read exposure is proven (an anonymous GET succeeded); the RCE follows from Flink's "
            "job-submission design, not from anything this scan executed (it never submits a job). "
            "A network policy or proxy not visible to the scan could restrict reachability."),
        source_ref={"probe": "anonymous /overview", "web_submit_enable": submit},
    )]


@detector(kinds=["flink_cluster"], rule_id="FLINK.WEB.SUBMIT_ENABLED", severity="medium",
          title="Flink web dashboard job submission is enabled")
def web_submit_enabled(resource, ctx):
    raw = resource.raw or {}
    if not raw.get("config_readable"):
        return [Hit(
            observation=(f"apache flink at {raw.get('base_url')}: /jobmanager/config was not "
                         f"readable, so whether web job submission is enabled could not be "
                         f"determined."),
            remediation=("Grant the scan read access to /jobmanager/config, or confirm "
                         "web.submit.enable directly."),
            detail="Coverage gap: /jobmanager/config unreadable.",
            assessable=False,
            assessment_reason="/jobmanager/config unreadable; web.submit.enable undetermined",
            source_ref={"config_key": "web.submit.enable"},
        )]
    if raw.get("web_submit_enabled") is not True:
        return []
    anon = raw.get("anonymous_readable")
    return [Hit(
        observation=(
            f"apache flink at {raw.get('base_url')}: web.submit.enable=true, so the dashboard "
            f"accepts JAR uploads and job submission. Combined with Flink's lack of built-in "
            f"authentication, this is the arbitrary-code-execution surface — the endpoint "
            f"{'was reachable anonymously in this scan' if anon else 'must be network-restricted'}."),
        remediation=(
            "Set web.submit.enable=false (and web.cancel.enable=false) on clusters that do not "
            "need interactive submission, and always require authentication in front of the "
            "dashboard. Deploy applications via the CLI/operator rather than the web UI."),
        detail=("Job submission is a legitimate feature; the risk is it being reachable without "
                "authentication. Severity is escalated when the endpoint was also anonymously "
                "reachable in this scan."),
        severity="high" if anon else "medium",
        source_ref={"config_key": "web.submit.enable", "anonymous": bool(anon)},
    )]


@detector(kinds=["flink_cluster"], rule_id="FLINK.TLS.DISABLED", severity="medium",
          title="Flink REST API is served over plaintext HTTP")
def tls_disabled(resource, ctx):
    raw = resource.raw or {}
    # security.ssl.rest.enabled=true means TLS even if we reached an http scheme via a proxy.
    if raw.get("over_tls") or raw.get("ssl_rest_enabled") is True:
        return []
    return [Hit(
        observation=(
            f"apache flink at {raw.get('base_url')} is reached over plaintext HTTP and "
            f"security.ssl.rest.enabled is {raw.get('ssl_rest_enabled')!r}, so REST traffic — "
            f"including submitted job artifacts and any credentials — crosses the network "
            f"unencrypted."),
        remediation=(
            "Enable security.ssl.rest.enabled with a keystore/truststore for mutual REST TLS, or "
            "front the dashboard with a TLS-terminating authenticating proxy and scan the HTTPS "
            "endpoint."),
        detail="Determined from the URL scheme and security.ssl.rest.enabled.",
        source_ref={"scheme": "http", "config_key": "security.ssl.rest.enabled"},
    )]


@detector(kinds=["flink_cluster"], rule_id="FLINK.VERSION.PATH_TRAVERSAL_CVE", severity="high",
          title="Flink version affected by unauthenticated REST path traversal "
                "(CVE-2020-17518 / CVE-2020-17519)")
def version_path_traversal_cve(resource, ctx):
    raw = resource.raw or {}
    version = raw.get("version")
    parsed = _parse_version(version)
    if parsed is None:
        return [Hit(
            observation=(f"apache flink at {raw.get('base_url')}: the version string "
                         f"{version!r} could not be parsed, so exposure to CVE-2020-17518 / "
                         f"CVE-2020-17519 (unauthenticated REST path traversal, affecting "
                         f"1.11.0–1.11.2) was not determined."),
            remediation=("Confirm the running Flink version and ensure it is 1.11.3 or later "
                         "(both CVEs are fixed there)."),
            detail="Coverage gap: version string unreadable/unparseable.",
            assessable=False,
            assessment_reason="Flink version string not parseable to a known release",
            source_ref={"info": "flink-version"},
        )]
    if not (_TRAVERSAL_MIN <= parsed <= _TRAVERSAL_MAX):
        return []
    return [Hit(
        observation=(
            f"apache flink version {version} is in the 1.11.0–1.11.2 range affected by "
            f"CVE-2020-17518 (arbitrary file WRITE via the REST upload handler) and "
            f"CVE-2020-17519 (arbitrary file READ), both unauthenticated directory-traversal "
            f"flaws on the JobManager REST interface."),
        remediation=(
            "Upgrade to Apache Flink 1.11.3 or later, where both CVEs are fixed. As an interim "
            "control, restrict network access to the JobManager REST port so it is not reachable "
            "by untrusted clients."),
        detail=("Version-gated and exact for the 1.11.x line. Deployments already on 1.11.3+ or "
                "on a different minor line are not affected."),
        source_ref={"info": "flink-version", "cve": "CVE-2020-17518,CVE-2020-17519"},
    )]
