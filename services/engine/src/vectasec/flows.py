"""Data and agents: where sensitive data can leave, and what AI agents can reach.

Three joins over stored scan results. No system is contacted.

  toxic_flows()   automations that connect a sensitive or anonymous source to an external
                  destination: "anyone with the URL can write to the CRM", "CRM records go to
                  an LLM", "an unauthenticated webhook runs code".
  agent_reach()   per MCP server: what its tools can do (read / write / execute) and which of
                  YOUR systems and resources they name.
  data_map()      sensitive topics, queues, routes and keyspaces, and how many identities can
                  reach each one, external ones called out.

HONESTY — this module is mostly inference, and every row carries its `basis`:
  * Zapier steps are read from the API with their order, so trigger → action is `declared`.
  * n8n is read as credential types and trigger settings, not the node graph, so an n8n row
    says what the workflow HOLDS and how it is triggered, never "data flows from A to B".
  * An MCP server does not publish what it connects to. Reach is inferred from tool names,
    descriptions and declared annotations, and each edge says so.
  * Data classes come from names (classify.py). A topic called `orders` is not proven to hold
    card numbers; the console draws inferred classes with the dashed border.
"""
from __future__ import annotations

import re
from typing import Iterable

from .classify import classify_name

__all__ = ["toxic_flows", "agent_reach", "data_map", "load", "build"]

# App keys / credential types, lower-cased, matched as whole tokens.
SENSITIVE_APPS = frozenset({
    "salesforce", "hubspot", "pipedrive", "zoho", "stripe", "paypal", "quickbooks", "xero",
    "netsuite", "workday", "bamboohr", "gusto", "zendesk", "intercom", "freshdesk", "postgres",
    "postgresql", "mysql", "mssql", "mongodb", "snowflake", "bigquery", "redshift", "shopify",
    "docusign", "okta", "auth0", "github", "gitlab", "jira", "aws", "s3", "gmail", "outlook",
    "office365", "googledrive", "onedrive", "dropbox", "box", "sharepoint",
})
EXTERNAL_SINKS = frozenset({
    "webhook", "webhooks", "http", "httprequest", "email", "smtp", "sendgrid", "mailgun",
    "discord", "telegram", "twilio", "pastebin", "airtable", "googlesheets", "sheets",
    "notion", "slack", "ftp", "sftp",
})
LLM_APPS = frozenset({"openai", "chatgpt", "anthropic", "claude", "gemini", "googleai", "mistral",
                      "cohere", "perplexity", "huggingface", "groq", "ollama", "azureopenai",
                      "langchain", "lmchatopenai", "lmchatanthropic", "agent"})
_WRITE = frozenset({"write", "create", "update", "search_or_write"})
_SEV = {"critical": 0, "high": 1, "medium": 2}

_READ_WORDS = frozenset({"get", "list", "read", "query", "search", "fetch", "describe", "find",
                         "show", "view", "select", "consume", "subscribe", "peek"})
_WRITE_WORDS = frozenset({"create", "update", "delete", "write", "send", "publish", "post", "put",
                          "patch", "drop", "remove", "insert", "upsert", "produce", "set", "add",
                          "purge", "revoke", "grant", "deploy", "merge", "push"})
_EXEC_WORDS = frozenset({"exec", "execute", "run", "shell", "bash", "eval", "command", "script",
                         "terminal", "sql"})
# System words a tool may name → the connector types that would cover it.
SYSTEM_WORDS: dict[str, tuple[str, ...]] = {
    "kafka": ("kafka", "msk", "confluent", "redpanda"), "topic": ("kafka", "msk", "confluent", "redpanda", "pulsar"),
    "rabbitmq": ("rabbitmq",), "amqp": ("rabbitmq",), "queue": ("rabbitmq", "aws", "azure"),
    "redis": ("redis",), "nats": ("nats",), "kong": ("kong",), "gateway": ("kong", "aws", "azure", "gcp"),
    "n8n": ("n8n",), "zapier": ("zapier",), "vault": ("vault",), "keycloak": ("keycloak",),
    "elasticsearch": ("elasticsearch",), "opensearch": ("elasticsearch",),
    "sqs": ("aws",), "sns": ("aws",), "s3": ("aws",), "lambda": ("aws",), "aws": ("aws",),
    "pubsub": ("gcp",), "gcp": ("gcp",), "azure": ("azure",), "servicebus": ("azure",),
    "kubernetes": ("k8s",), "k8s": ("k8s",), "postgres": ("pgbouncer",), "postgresql": ("pgbouncer",),
    "airflow": ("airflow",), "mqtt": ("mqtt",),
}


def _toks(*parts) -> set[str]:
    out: set[str] = set()
    for p in parts:
        spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(p or ""))
        out.update(t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t)
        # Also the un-split words: "RabbitMQ" and "OpenSearch" are one name, not two.
        out.update(t.lower() for t in re.split(r"[^A-Za-z0-9]+", str(p or "")) if t)
    return out


def _appkey(v) -> str:
    return re.sub(r"[^a-z0-9]", "", str(v or "").lower().replace("cli-api", "").replace("api", ""))


def _is(app: str, family: frozenset) -> bool:
    k = _appkey(app)
    return bool(k) and (k in family or any(f in k for f in family if len(f) >= 5))


def toxic_flows(resources: Iterable[dict], connections: dict) -> list[dict]:
    flows: list[dict] = []

    def add(r, pattern, severity, source, sink, why, basis):
        labels = r.get("labels") or {}
        enabled = str(labels.get("enabled", labels.get("active", "true"))).lower() != "false"
        c = connections.get(str(r.get("connection_id") or ""), {})
        flows.append({"resource_id": r.get("id"), "workflow": r.get("name"), "system": c.get("type") or "",
                      "connection": c.get("name") or "", "pattern": pattern, "severity": severity,
                      "source": source, "sink": sink, "why": why, "basis": basis, "enabled": enabled,
                      "owner": str(labels.get("owner") or "")})

    for r in resources:
        raw, labels = r.get("raw") or {}, r.get("labels") or {}
        if r.get("kind") == "zapier_zap":
            trig = raw.get("trigger") or {}
            tapp = str(((trig.get("app") or {}).get("key") or (trig.get("app") or {}).get("title") or "")
                       if isinstance(trig.get("app"), dict) else trig.get("app") or "")
            actions = [a for a in (raw.get("actions") or []) if isinstance(a, dict)]
            anonymous = str(labels.get("anonymous_trigger")) == "true"
            title_sens = classify_name(r.get("name"))["sensitivity"] in ("high", "restricted", "confidential")
            src_sensitive = _is(tapp, SENSITIVE_APPS) or title_sens
            basis = "declared: trigger and action steps read from the Zapier API"
            for a in actions:
                app = str(a.get("app") or "")
                writes = str(a.get("action_type") or "").lower() in _WRITE
                if anonymous and writes and _is(app, SENSITIVE_APPS):
                    add(r, "anonymous_to_system", "critical", f"{tapp or 'webhook'} (no authentication)", app,
                        "Anyone who has the trigger address can write to this system.", basis)
                if src_sensitive and _is(app, LLM_APPS):
                    add(r, "sensitive_to_llm", "high", tapp or "this workflow", app,
                        "Records from a business system are sent to an AI model provider.", basis)
                elif src_sensitive and _is(app, EXTERNAL_SINKS) and not _is(app, SENSITIVE_APPS):
                    add(r, "sensitive_to_external", "high", tapp or "this workflow", app,
                        "Records from a business system are sent to a destination outside it.", basis)
        elif r.get("kind") == "n8n_workflow":
            types = sorted({str((ref or {}).get("type") or "") for ref in (raw.get("credential_refs") or [])
                            if isinstance(ref, dict)} - {""})
            sens = [t for t in types if _is(t, SENSITIVE_APPS)]
            llm = [t for t in types if _is(t, LLM_APPS)]
            basis = "inferred: credential types and trigger settings; step order is not read"
            if raw.get("has_unauthenticated_webhook") and raw.get("execution_node_types"):
                add(r, "anonymous_to_code", "critical", "webhook (no authentication)",
                    ", ".join(raw["execution_node_types"][:3]),
                    "An unauthenticated webhook starts a workflow that can run code or commands.", basis)
            if raw.get("has_unauthenticated_webhook") and sens:
                add(r, "anonymous_to_system", "high", "webhook (no authentication)", ", ".join(sens[:4]),
                    "An unauthenticated webhook starts a workflow that holds credentials for these systems.", basis)
            if sens and llm:
                add(r, "sensitive_to_llm", "medium", ", ".join(sens[:3]), ", ".join(llm[:3]),
                    "The workflow holds credentials for a business system and for an AI model provider.", basis)
    flows.sort(key=lambda f: (not f["enabled"], _SEV.get(f["severity"], 9), str(f["workflow"])))
    return flows


def agent_reach(resources: Iterable[dict], connections: dict, open_findings: dict) -> list[dict]:
    """open_findings: resource_id -> count of open findings."""
    resources = list(resources)
    connected_types = {c.get("type") for c in connections.values()}
    named = {str(r.get("name")).lower(): r for r in resources
             if r.get("kind") in ("topic", "queue", "exchange", "stream", "subject", "route", "service")
             and len(str(r.get("name") or "")) >= 5}
    servers = {str(r.get("ext_id")): r for r in resources if r.get("kind") == "mcp_server"}
    out: dict[str, dict] = {}
    for ext, s in servers.items():
        labels = s.get("labels") or {}
        out[ext] = {"resource_id": s.get("id"), "server": s.get("name"),
                    "endpoint": str((s.get("raw") or {}).get("endpoint") or s.get("namespace") or ""),
                    "public": str(labels.get("ip_class") or "").lower() == "public",
                    "plaintext": str(labels.get("scheme") or "").lower() == "http",
                    "open_findings": int(open_findings.get(str(s.get("id")), 0)),
                    "tools": 0, "write_tools": 0, "exec_tools": 0, "reaches": {}, "sensitive_tools": []}
    for t in resources:
        if t.get("kind") != "mcp_tool":
            continue
        entry = out.get(str((t.get("labels") or {}).get("server") or ""))
        if entry is None:
            continue
        tool = (t.get("raw") or {}).get("tool") or {}
        name, desc = str(tool.get("name") or t.get("name") or ""), str(tool.get("description") or "")[:2000]
        ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
        toks, name_toks = _toks(name, desc), _toks(name)
        declared = "readOnlyHint" in ann or "destructiveHint" in ann
        if declared:
            access = "read" if ann.get("readOnlyHint") else "write"
        else:
            access = ("execute" if name_toks & _EXEC_WORDS else "write" if name_toks & _WRITE_WORDS
                      else "read" if name_toks & _READ_WORDS else "unknown")
        entry["tools"] += 1
        entry["write_tools"] += access == "write"
        entry["exec_tools"] += access == "execute"
        entry["open_findings"] += int(open_findings.get(str(t.get("id")), 0))
        cls = classify_name(name, desc)
        if cls["classes"] and len(entry["sensitive_tools"]) < 10:
            entry["sensitive_tools"].append({"tool": name, "classes": cls["classes"]})
        basis = ("access declared by the server's annotations; target inferred from the tool text"
                 if declared else "inferred from the tool's name and description")
        hits: dict[str, dict] = {}
        for word, types in SYSTEM_WORDS.items():
            if word in toks:
                hits.setdefault(word, {"target": word, "kind": "system",
                                       "connected": bool(connected_types & set(types))})
        for rname, res in named.items():
            if rname in toks or rname in desc.lower() or rname in name.lower():
                hits[f"res:{rname}"] = {"target": res.get("name"), "kind": res.get("kind"),
                                        "connected": True, "resource_id": res.get("id"),
                                        "sensitivity": (res.get("labels") or {}).get("data_sensitivity") or ""}
        for key, h in hits.items():
            cur = entry["reaches"].setdefault(key, {**h, "tools": [], "access": access, "basis": basis})
            if name not in cur["tools"] and len(cur["tools"]) < 8:
                cur["tools"].append(name)
            order = {"unknown": 0, "read": 1, "write": 2, "execute": 3}
            if order[access] > order[cur["access"]]:
                cur["access"] = access
    rows = []
    for e in out.values():
        e["reaches"] = sorted(e["reaches"].values(),
                              key=lambda r: (r["kind"] == "system", str(r["target"])))
        rows.append(e)
    rows.sort(key=lambda e: (not e["public"], -(e["exec_tools"] * 3 + e["write_tools"]), str(e["server"])))
    return rows


def data_map(resources: Iterable[dict], connections: dict) -> list[dict]:
    resources = list(resources)
    identities = {str(r.get("ext_id")): r for r in resources if r.get("kind") == "identity"}
    grants_by_conn: dict[str, list] = {}
    for g in resources:
        if g.get("kind") == "grant" and str((g.get("labels") or {}).get("permission", "allow")).lower() != "deny":
            grants_by_conn.setdefault(str(g.get("connection_id") or ""), []).append(g.get("labels") or {})
    rows = []
    for r in resources:
        labels = r.get("labels") or {}
        classes = [c for c in str(labels.get("data_classes") or "").split(",") if c]
        if not classes:
            continue
        cid, name = str(r.get("connection_id") or ""), str(r.get("name") or "")
        direct, wildcard, external = set(), set(), set()
        for gl in grants_by_conn.get(cid, []):
            holder = str(gl.get("identity") or "")
            if str(gl.get("wildcard")) == "true":
                wildcard.add(holder)
            elif str(gl.get("target") or "") == name:
                direct.add(holder)
            else:
                continue
            ident = identities.get(holder)
            if ident and str((ident.get("labels") or {}).get("external")) == "true":
                external.add(holder)
        c = connections.get(cid, {})
        rows.append({"resource_id": r.get("id"), "name": name, "kind": r.get("kind"),
                     "system": c.get("type") or "", "connection": c.get("name") or "",
                     "classes": classes, "sensitivity": labels.get("data_sensitivity") or "",
                     "signals": labels.get("data_signals") or "",
                     "direct_readers": len(direct), "wildcard_readers": len(wildcard - direct),
                     "external_readers": len(external)})
    rank = {"restricted": 0, "high": 0, "confidential": 1, "medium": 1, "internal": 2, "low": 2}
    rows.sort(key=lambda x: (rank.get(str(x["sensitivity"]).lower(), 3), -x["external_readers"],
                             -(x["direct_readers"] + x["wildcard_readers"]), x["name"]))
    return rows


def build(resources: list, connections: dict, open_findings: dict) -> dict:
    flows = toxic_flows(resources, connections)
    return {
        "toxic_flows": flows[:500], "toxic_total": len(flows),
        "agents": agent_reach(resources, connections, open_findings)[:200],
        "data_map": data_map(resources, connections)[:500],
        "coverage": {
            "automation_systems": sorted({connections.get(str(r.get("connection_id") or ""), {}).get("type")
                                          for r in resources if r.get("kind") in ("zapier_zap", "n8n_workflow")} - {None}),
            "mcp_servers": sum(1 for r in resources if r.get("kind") == "mcp_server"),
        },
        "scope_note": "Built from stored scan results. Flow direction is read from the API only "
                      "for Zapier; n8n rows say what a workflow holds, not which way data moves. "
                      "Agent reach and data classes are inferred from names and descriptions.",
    }


def load(cur, tenant_id: str) -> dict:
    cur.execute("select id::text, name, type from connections where tenant_id = %s", (tenant_id,))
    connections = {r[0]: {"name": r[1], "type": r[2]} for r in cur.fetchall() or []}
    cur.execute(
        """select id::text, kind, name, ext_id, namespace, labels, raw, connection_id::text
             from resources
            where tenant_id = %s and not stale
              and (kind = any(%s) or labels ? 'data_classes')
            limit 50000""",
        (tenant_id, ["zapier_zap", "n8n_workflow", "mcp_server", "mcp_tool", "identity", "grant",
                     "topic", "queue", "exchange", "stream", "subject", "route", "service"]))
    resources = [{"id": r[0], "kind": r[1], "name": r[2], "ext_id": r[3], "namespace": r[4],
                  "labels": r[5] or {}, "raw": r[6] or {}, "connection_id": r[7]}
                 for r in cur.fetchall() or []]
    cur.execute(
        """select f.resource_id::text, count(*) from findings f join resources r on r.id = f.resource_id
            where f.tenant_id = %s and f.status = 'open' and r.kind in ('mcp_server', 'mcp_tool')
            group by f.resource_id""", (tenant_id,))
    open_findings = {r[0]: int(r[1]) for r in cur.fetchall() or []}
    return build(resources, connections, open_findings)
