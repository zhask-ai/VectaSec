"""MCP client configurations committed to repositories (connect/mcp_client.py).

Each rule cites the file and line, so the fix is "open this file". None of them contacts the
server the config points at.
"""
from ..contracts import Hit
from ..registry import detector


def _where(raw: dict) -> str:
    return f"{raw.get('file')}" + (f":{raw.get('line')}" if raw.get("line") else "")


@detector(kinds=["mcp_client_server"], rule_id="MCP.CLIENTCONFIG.LITERAL_SECRET", severity="critical",
          title="MCP client config contains a literal credential")
def literal_secret(r, ctx) -> list:
    raw = r.raw or {}
    hits = []
    for s in raw.get("secrets") or []:
        hits.append(Hit(
            observation=f"MCP server '{raw.get('server')}' in {raw.get('file')}"
                        + (f" line {s.get('line')}" if s.get("line") else "")
                        + f": {s.get('where')} `{s.get('key')}` holds a literal "
                        + ("token-shaped value" if s.get("shape") == "token" else "secret")
                        + f" (fingerprint {s.get('fingerprint')})",
            remediation="Rotate the credential now: anyone with read access to the repository has it. "
                        "Then replace the value with an environment reference (for example "
                        "\"${GITHUB_TOKEN}\"), keep the real value in the developer's own environment or "
                        "a secret manager, and add the file to secret scanning.",
            detail=f"fingerprint={s.get('fingerprint')} key={s.get('key')}",
            source_ref={"file": raw.get("file"), "line": s.get("line"), "key": s.get("key")},
        ))
    return hits


@detector(kinds=["mcp_client_server"], rule_id="MCP.CLIENTCONFIG.BROAD_FILESYSTEM", severity="high",
          title="MCP file server is given the whole home directory or disk")
def broad_filesystem(r, ctx) -> list:
    raw = r.raw or {}
    broad = raw.get("broad_filesystem_roots") or []
    if not broad:
        return []
    return [Hit(
        observation=f"MCP server '{raw.get('server')}' ({_where(raw)}) starts a filesystem server "
                    f"rooted at {', '.join(broad)}: the AI agent can read SSH keys, cloud credentials "
                    "and every other file under it",
        remediation="Point the filesystem server at the project directory only (for example the "
                    "repository path), never at / or a home directory.",
        source_ref={"file": raw.get("file"), "line": raw.get("line")},
    )]


@detector(kinds=["mcp_client_server"], rule_id="MCP.CLIENTCONFIG.DATABASE_DIRECT", severity="medium",
          title="MCP server connects an AI agent straight to a database")
def database_direct(r, ctx) -> list:
    raw = r.raw or {}
    dbs = raw.get("databases") or []
    if not dbs:
        return []
    prod = [d for d in dbs if d.get("production_like")]
    target = ", ".join(f"{d['scheme']}://{d['host']}/{d['database']}" for d in dbs[:3])
    return [Hit(
        observation=f"MCP server '{raw.get('server')}' ({_where(raw)}) is configured with database "
                    f"connection {target}"
                    + (" whose name looks like production" if prod else "")
                    + (" and the connection string carries a password" if any(d.get("has_password") for d in dbs) else ""),
        remediation="Give AI agents a read-only user on a non-production copy, scoped to the tables "
                    "they need. Never commit the connection string; reference it from the environment.",
        severity="high" if prod else None,
        source_ref={"file": raw.get("file"), "line": raw.get("line")},
    )]


@detector(kinds=["mcp_client_server"], rule_id="MCP.CLIENTCONFIG.UNPINNED_PACKAGE", severity="medium",
          title="MCP server is launched from an unpinned package")
def unpinned_package(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("pinned") is not False or not raw.get("package"):
        return []
    return [Hit(
        observation=f"MCP server '{raw.get('server')}' ({_where(raw)}) runs `{raw.get('command')} "
                    f"{raw.get('package')}` with no version, so every launch installs whatever was "
                    "published last",
        remediation="Pin an exact version (for example package@1.4.2, or ==1.4.2 for Python), and "
                    "update it deliberately. Malicious updates to automation and AI packages were "
                    "published to npm and PyPI in 2026.",
        source_ref={"file": raw.get("file"), "line": raw.get("line"), "package": raw.get("package")},
    )]


@detector(kinds=["mcp_client_server"], rule_id="MCP.CLIENTCONFIG.PLAINTEXT_REMOTE", severity="high",
          title="Remote MCP server is reached over plain HTTP")
def plaintext_remote(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("plaintext_remote"):
        return []
    return [Hit(
        observation=f"MCP server '{raw.get('server')}' ({_where(raw)}) is reached at {raw.get('url')} "
                    "over plain HTTP, so tool calls, results and any token header cross the network unencrypted",
        remediation="Use the server's https:// address.",
        source_ref={"file": raw.get("file"), "line": raw.get("line")},
    )]
