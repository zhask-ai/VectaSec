"""MCP client configs in repositories (connect/mcp_client.py, detect/mcp_client.py)."""
import json

from vectasec.connect.iac import _looks_like_iac, parse_iac
from vectasec.connect.mcp_client import looks_like_mcp_client_config, parse_mcp_client_config
from vectasec import detect as _detect  # noqa: F401
from vectasec.registry import DETECTORS

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("MCP.CLIENTCONFIG.")}

CONFIG = json.dumps({"mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}},
    "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.0", "/Users/sam"]},
    "db": {"command": "uvx", "args": ["mcp-server-postgres==0.6.1", "postgresql://app:hunter2@prod-replica.db.internal:5432/orders"]},
    "safe": {"command": "npx", "args": ["-y", "some-mcp@2.0.1"], "env": {"API_KEY": "${API_KEY}"}},
    "remote": {"url": "http://mcp.example.com/sse", "headers": {"Authorization": "Bearer ${TOKEN}"}},
    "local": {"url": "http://localhost:3000/mcp"},
}}, indent=2)


def servers(text=CONFIG, name=".cursor/mcp.json"):
    res, err = parse_mcp_client_config(name, text)
    assert err is None
    return {r.raw["server"]: r for r in res}


def test_file_detection():
    for p in (".mcp.json", "repo/.cursor/mcp.json", ".vscode/mcp.json", "claude_desktop_config.json"):
        assert looks_like_mcp_client_config(p, "{}"), p
    assert looks_like_mcp_client_config("tools/agents.json", '{"mcpServers": {}}')
    assert not looks_like_mcp_client_config("package.json", '{"name": "x"}')
    assert _looks_like_iac(".mcp.json", "{}")


def test_parse_never_stores_a_secret_value():
    s = servers()
    assert set(s) == {"github", "files", "db", "safe", "remote", "local"}
    gh = s["github"].raw
    assert gh["secrets"] and gh["secrets"][0]["shape"] == "token" and gh["pinned"] is False
    assert "ghp_" not in json.dumps([r.raw for r in s.values()]) and "hunter2" not in json.dumps([r.raw for r in s.values()])
    assert s["safe"].raw["secrets"] == [] and s["safe"].raw["pinned"] is True
    assert s["db"].raw["databases"] == [{"scheme": "postgresql", "host": "prod-replica.db.internal",
                                         "database": "orders", "production_like": True, "has_password": True}]
    assert s["files"].raw["broad_filesystem_roots"] == ["/Users/sam"]
    assert s["remote"].raw["plaintext_remote"] and not s["local"].raw["plaintext_remote"]
    assert s["remote"].raw["secrets"] == [], "a ${VAR} reference is not a secret"


def test_detectors():
    s = servers()

    class Ctx:
        resources = []

    def fired(rule, name):
        return RULES[rule].fn(s[name], Ctx)
    assert fired("MCP.CLIENTCONFIG.LITERAL_SECRET", "github") and not fired("MCP.CLIENTCONFIG.LITERAL_SECRET", "safe")
    assert fired("MCP.CLIENTCONFIG.BROAD_FILESYSTEM", "files")
    db = fired("MCP.CLIENTCONFIG.DATABASE_DIRECT", "db")
    assert db and db[0].severity == "high" and "carries a password" in db[0].observation
    assert fired("MCP.CLIENTCONFIG.UNPINNED_PACKAGE", "github") and not fired("MCP.CLIENTCONFIG.UNPINNED_PACKAGE", "files")
    assert fired("MCP.CLIENTCONFIG.PLAINTEXT_REMOTE", "remote") and not fired("MCP.CLIENTCONFIG.PLAINTEXT_REMOTE", "local")


def test_vscode_shape_and_bad_json():
    s = servers(json.dumps({"servers": {"x": {"type": "http", "url": "https://api.example.com/mcp"}}}), ".vscode/mcp.json")
    assert s["x"].raw["transport"] == "http" and s["x"].labels["client"] == "vscode"
    assert parse_mcp_client_config(".mcp.json", "{not json")[1].startswith("JSON")


def test_through_the_iac_parser():
    c = parse_iac({".cursor/mcp.json": CONFIG, "docker-compose.yml": "services: {}"})
    kinds = [r.kind for r in c.resources]
    assert kinds.count("mcp_client_server") == 6 and kinds.count("iac_file") == 2
    f = next(r for r in c.resources if r.kind == "iac_file" and r.name == ".cursor/mcp.json")
    assert f.labels["format"] == "mcp-client-config" and f.raw["workload_count"] == 6
    assert len([e for e in c.edges if e.kind == "declares"]) == 6


def test_bearer_literal_is_a_secret_but_bearer_reference_is_not():
    s = servers(json.dumps({"mcpServers": {
        "a": {"url": "https://x.example.com/mcp", "headers": {"Authorization": "Bearer abc123def456ghi789"}},
        "b": {"url": "https://x.example.com/mcp", "headers": {"Authorization": "Bearer ${env:TOKEN}"}}}}))
    assert s["a"].raw["secrets"] and s["b"].raw["secrets"] == []
