"""MCP client configuration files: what AI coding tools are told to connect to.

Operators' own words (research_notes/Middleware engine AI upgrade research/
forum_voice_of_operators.md): a reviewer found "half the team had copied an MCP config with a
prod read replica, a wide scope PAT and home directory access". These configs live in
repositories (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) and in
`claude_desktop_config.json`, and they are copied from person to person. Nothing inventories
them, because they are not servers: they are instructions to an AI client to START or CALL
servers, with credentials inline.

This parser turns one such file into one `mcp_client_server` resource per configured server.
It is called by the IaC connector's file walk, so any repository VectaSec already reads for
manifests is also read for these.

What is stored, and what is not:
  * command, package name and whether its version is pinned; remote URL (with any userinfo
    removed); environment variable NAMES; filesystem roots handed to file servers; database
    URLs reduced to scheme + host + database name.
  * A literal secret is never stored: only its key, a 12-character fingerprint (iac._fingerprint)
    and the line it is on. Values that are references (${VAR}, $VAR) are not secrets.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional
from urllib.parse import urlsplit

from ..contracts import Resource

__all__ = ["looks_like_mcp_client_config", "parse_mcp_client_config", "MCP_CONFIG_DIRS"]

# Dot-directories the file walk must enter for these files (it skips dot-dirs otherwise).
MCP_CONFIG_DIRS = {".cursor", ".vscode", ".claude", ".gemini", ".windsurf", ".roo", ".kiro"}
_NAMES = re.compile(
    r"(^|/)(\.mcp\.json|mcp\.json|mcp_config\.json|claude_desktop_config\.json|"
    r"\.cursor/mcp\.json|\.vscode/mcp\.json|\.gemini/settings\.json|\.claude/settings(\.local)?\.json)$",
    re.I)

_SECRET_KEY = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|"
                         r"CREDENTIAL|AUTHORIZATION|_PAT\b|^PAT$|_PWD|_PASS\b|BEARER)", re.I)
_REFERENCE = re.compile(r"^\s*($|\$\{|\$[A-Za-z_]|\{\{|\$env:|input:)", re.I)
# Value shapes that are credentials whatever the key is called.
_TOKEN_SHAPES = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|"
    r"xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{16,}|"
    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})")
_DB_URL = re.compile(r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql|sqlserver)://[^\s\"']+", re.I)
_PROD_WORDS = re.compile(r"(^|[.\-_])(prod|production|prd|live|primary|replica|master)([.\-_]|$)", re.I)
_FS_PACKAGES = re.compile(r"(server-filesystem|filesystem-server|mcp-server-filesystem|@modelcontextprotocol/server-filesystem)", re.I)
_BROAD_ROOTS = {"/", "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "C:\\", "C:/", "/Users", "/home", "/root"}


def looks_like_mcp_client_config(path: str, head: str) -> bool:
    if _NAMES.search(path.replace(os.sep, "/")):
        return True
    return path.endswith(".json") and ('"mcpServers"' in head or '"mcp_servers"' in head)


def _client_of(path: str) -> str:
    p = path.replace(os.sep, "/").lower()
    for marker, client in ((".cursor/", "cursor"), (".vscode/", "vscode"), ("claude_desktop", "claude-desktop"),
                           (".claude/", "claude-code"), (".gemini/", "gemini-cli"), (".windsurf/", "windsurf")):
        if marker in p:
            return client
    return "claude-code" if p.endswith(".mcp.json") else "generic"


def _fingerprint(value: str) -> str:
    from .iac import _fingerprint as fp
    return fp(value)


def _line_of(text: str, needle: str) -> Optional[int]:
    for i, line in enumerate(text.splitlines(), 1):
        if needle and needle in line:
            return i
    return None


def _package(command: str, args: list[str]) -> tuple[Optional[str], Optional[bool]]:
    """(package, pinned) for npx / uvx / pipx / bunx / docker launches."""
    cmd = os.path.basename(command or "").lower()
    rest = [a for a in args if not a.startswith("-")]
    if cmd in ("npx", "bunx", "pnpx") or (cmd in ("pnpm", "yarn", "npm") and args[:1] in (["dlx"], ["exec"])):
        if cmd in ("pnpm", "yarn", "npm"):
            rest = rest[1:]
        if not rest:
            return None, None
        pkg = rest[0]
        name = pkg[1:] if pkg.startswith("@") else pkg
        return pkg, "@" in name
    if cmd in ("uvx", "pipx") or (cmd == "uv" and args[:1] == ["tool"]):
        if not rest:
            return None, None
        pkg = rest[-1] if cmd == "uv" else rest[0]
        return pkg, bool(re.search(r"(==|@)\d", pkg))
    if cmd in ("docker", "podman"):
        img = next((a for a in rest if a not in ("run",) and ("/" in a or ":" in a)), None)
        return img, (img is not None and (":" in img.split("/")[-1] and not img.endswith(":latest")) or "@sha256:" in (img or ""))
    return None, None


def _safe_url(url: str) -> str:
    try:
        u = urlsplit(url)
        host = u.hostname or ""
        port = f":{u.port}" if u.port else ""
        return f"{u.scheme}://{host}{port}{u.path}"
    except ValueError:
        return "(unparseable URL)"


def _db_targets(text: str) -> list[dict]:
    out = []
    for m in _DB_URL.finditer(text or ""):
        try:
            u = urlsplit(m.group(0))
            host = u.hostname or ""
        except ValueError:
            continue
        out.append({"scheme": u.scheme, "host": host, "database": (u.path or "/").lstrip("/").split("?")[0],
                    "production_like": bool(_PROD_WORDS.search(host) or _PROD_WORDS.search(u.path or "")),
                    "has_password": bool(u.password)})
    return out


def parse_mcp_client_config(filename: str, text: str) -> tuple[list[Resource], Optional[str]]:
    """{file} → (resources, parse_error). One `mcp_client_server` per configured server."""
    try:
        doc = json.loads(text or "")
    except ValueError as e:
        return [], f"JSON: {e}"
    if not isinstance(doc, dict):
        return [], "not a JSON object"
    servers = doc.get("mcpServers") or doc.get("mcp_servers") or doc.get("servers")
    if servers is None and isinstance(doc.get("mcp"), dict):
        servers = doc["mcp"].get("servers")
    if not isinstance(servers, dict):
        return [], None
    client = _client_of(filename)
    out: list[Resource] = []
    for name, spec in sorted(servers.items()):
        if not isinstance(spec, dict):
            continue
        command = str(spec.get("command") or "")
        args = [str(a) for a in (spec.get("args") or []) if isinstance(a, (str, int, float))]
        env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
        headers = spec.get("headers") if isinstance(spec.get("headers"), dict) else {}
        url = str(spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or "")
        transport = "http" if url else "stdio"

        secrets = []
        def consider(where: str, key: str, value) -> None:
            v = str(value or "")
            # "Bearer ${TOKEN}" is a reference behind a scheme word, not a secret.
            bare = re.sub(r"^(bearer|basic|token)\s+", "", v.strip(), flags=re.I)
            if not v or _REFERENCE.match(v) or _REFERENCE.match(bare) or v.lower() in ("true", "false"):
                return
            shaped = _TOKEN_SHAPES.search(v)
            if _SECRET_KEY.search(key) or shaped:
                literal = shaped.group(0) if shaped else v
                secrets.append({"where": where, "key": key, "fingerprint": _fingerprint(literal),
                                "line": _line_of(text, literal[:24]) or _line_of(text, f'"{key}"'),
                                "shape": "token" if shaped else "keyword"})
        for k, v in env.items():
            consider("env", str(k), v)
        for k, v in headers.items():
            consider("headers", str(k), v)
        for i, a in enumerate(args):
            if _TOKEN_SHAPES.search(a):
                consider("args", f"args[{i}]", a)
            elif "=" in a and a.startswith("--"):
                k, _, v = a[2:].partition("=")
                consider("args", k, v)

        package, pinned = _package(command, args)
        fs_roots = []
        if _FS_PACKAGES.search(" ".join([command, *args])):
            pkg_idx = next((i for i, a in enumerate(args) if _FS_PACKAGES.search(a)), -1)
            fs_roots = [a for a in args[pkg_idx + 1:] if not a.startswith("-")]
        broad = [r for r in fs_roots if r.rstrip("/\\") in {b.rstrip("/\\") for b in _BROAD_ROOTS} or r in _BROAD_ROOTS
                 or re.match(r"^(/Users|/home)/[^/]+/?$", r) or re.match(r"^[A-Za-z]:\\Users\\[^\\]+\\?$", r)]
        all_text = " ".join([command, *args, *[str(v) for v in env.values()], url])
        dbs = _db_targets(all_text)
        remote = _safe_url(url) if url else ""
        plaintext_remote = bool(url) and url.lower().startswith("http://") and \
            (urlsplit(url).hostname or "") not in ("localhost", "127.0.0.1", "::1")

        line = _line_of(text, f'"{name}"')
        out.append(Resource(
            kind="mcp_client_server",
            name=f"{name} ({filename})",
            ext_id=f"mcp-client-{filename}#{name}",
            labels={"client": client, "transport": transport, "file": filename,
                    "secrets": str(len(secrets)), "pinned": "unknown" if pinned is None else str(pinned).lower()},
            raw={"server": name, "file": filename, "line": line, "client": client,
                 "transport": transport, "command": os.path.basename(command) if command else "",
                 "package": package, "pinned": pinned, "url": remote,
                 "plaintext_remote": plaintext_remote,
                 "env_keys": sorted(str(k) for k in env), "secrets": secrets,
                 "filesystem_roots": fs_roots, "broad_filesystem_roots": broad,
                 "databases": dbs},
        ))
    return out, None
