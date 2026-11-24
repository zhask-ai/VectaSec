"""Data and agents (flows.py). Pinned: Zapier flows are declared and directional; n8n rows are
inferred and never claim a direction; an authenticated trigger is not 'anonymous'; a write to a
non-sensitive app is not a toxic flow; disabled workflows sort last; MCP access prefers the
server's declared annotations over the name; reach names connected systems and real resource
names; the data map counts direct, wildcard and external readers and ignores deny grants."""
from vectasec import flows

CONNS = {"z": {"name": "zapier", "type": "zapier"}, "n": {"name": "n8n", "type": "n8n"},
         "k": {"name": "kafka prod", "type": "kafka"}, "m": {"name": "mcp", "type": "mcp"}}


def zap(name, trigger_app, actions, anonymous=False, enabled=True):
    return {"id": name, "kind": "zapier_zap", "name": name, "connection_id": "z",
            "labels": {"anonymous_trigger": "true" if anonymous else "false", "enabled": "true" if enabled else "false"},
            "raw": {"trigger": {"app": {"key": trigger_app}},
                    "actions": [{"app": a, "action_type": t} for a, t in actions]}}


def n8n(name, cred_types, unauth=False, exec_nodes=()):
    return {"id": name, "kind": "n8n_workflow", "name": name, "connection_id": "n", "labels": {"active": "true"},
            "raw": {"credential_refs": [{"type": t} for t in cred_types],
                    "has_unauthenticated_webhook": unauth, "execution_node_types": list(exec_nodes)}}


def test_zapier_patterns_are_declared_and_directional():
    fl = flows.toxic_flows([
        zap("Web form to CRM", "webhook", [("salesforce", "write")], anonymous=True),
        zap("CRM to GPT", "SalesforceCLIAPI", [("openai", "write")]),
        zap("CRM to sheet", "hubspot", [("GoogleSheets", "write")]),
        zap("Authenticated to CRM", "typeform", [("salesforce", "write")], anonymous=False),
        zap("Webhook to chat", "webhook", [("discord", "write")], anonymous=True),
        zap("Old", "webhook", [("stripe", "write")], anonymous=True, enabled=False),
    ], CONNS)
    by = {(f["workflow"], f["pattern"]) for f in fl}
    assert by == {("Web form to CRM", "anonymous_to_system"), ("CRM to GPT", "sensitive_to_llm"),
                  ("CRM to sheet", "sensitive_to_external"), ("Old", "anonymous_to_system")}
    assert all(f["basis"].startswith("declared") for f in fl)
    assert fl[-1]["workflow"] == "Old" and fl[-1]["enabled"] is False
    assert fl[0]["severity"] == "critical"


def test_n8n_rows_are_inferred_and_never_directional():
    fl = flows.toxic_flows([
        n8n("hook runs code", [], unauth=True, exec_nodes=["n8n-nodes-base.executeCommand"]),
        n8n("hook with crm", ["salesforceOAuth2Api"], unauth=True),
        n8n("crm and llm", ["hubspotApi", "openAiApi"]),
        n8n("harmless", ["slackApi"]),
    ], CONNS)
    assert {(f["workflow"], f["pattern"]) for f in fl} == {
        ("hook runs code", "anonymous_to_code"), ("hook with crm", "anonymous_to_system"), ("crm and llm", "sensitive_to_llm")}
    assert all(f["basis"].startswith("inferred") for f in fl)
    assert "holds credentials" in next(f for f in fl if f["workflow"] == "crm and llm")["why"]


def tool(name, desc="", ann=None, server="srv"):
    t = {"name": name, "description": desc}
    if ann is not None:
        t["annotations"] = ann
    return {"id": f"t-{name}", "kind": "mcp_tool", "name": name, "connection_id": "m",
            "labels": {"server": server}, "raw": {"tool": t}}


SERVER = {"id": "s1", "kind": "mcp_server", "name": "ops-mcp", "ext_id": "srv", "connection_id": "m",
          "labels": {"ip_class": "public", "scheme": "https"}, "raw": {"endpoint": "https://mcp.corp.io"}}
TOPIC = {"id": "tp", "kind": "topic", "name": "payments-events", "connection_id": "k",
         "labels": {"data_sensitivity": "high", "data_classes": "financial"}}


def test_agent_reach():
    rows = flows.agent_reach([
        SERVER, TOPIC,
        tool("publish_kafka_message", "Publish a message to a Kafka topic such as payments-events"),
        tool("list_queues", "List RabbitMQ queues"),
        tool("delete_everything", "Looks destructive by name", ann={"readOnlyHint": True}),
        tool("run_shell", "Run a shell command"),
        tool("orphan", server="nope"),
    ], CONNS, {"s1": 2, "t-run_shell": 1})
    assert len(rows) == 1
    e = rows[0]
    assert (e["tools"], e["write_tools"], e["exec_tools"], e["public"], e["open_findings"]) == (4, 1, 1, True, 3)
    reach = {r["target"]: r for r in e["reaches"]}
    assert reach["kafka"]["connected"] is True and reach["kafka"]["access"] == "write"
    assert reach["rabbitmq"]["connected"] is False, "named, but VectaSec is not connected to it"
    assert reach["payments-events"]["resource_id"] == "tp" and reach["payments-events"]["sensitivity"] == "high"
    assert all("inferred" in r["basis"] or "declared" in r["basis"] for r in e["reaches"])


def test_declared_annotation_beats_the_name():
    rows = flows.agent_reach([SERVER, tool("delete_kafka_topic", "kafka", ann={"readOnlyHint": True})], CONNS, {})
    assert rows[0]["write_tools"] == 0 and rows[0]["reaches"][0]["access"] == "read"
    assert rows[0]["reaches"][0]["basis"].startswith("access declared")


def test_data_map_counts_readers():
    def ident(name, external=False):
        return {"id": name, "kind": "identity", "ext_id": f"identity:kafka:{name}", "name": name, "connection_id": "k",
                "labels": {"external": "true" if external else "false"}}

    def grant(holder, target, wildcard=False, permission="allow", cid="k"):
        return {"id": f"g-{holder}-{target}", "kind": "grant", "connection_id": cid,
                "labels": {"identity": f"identity:kafka:{holder}", "target": target,
                           "wildcard": "true" if wildcard else "false", "permission": permission}}
    rows = flows.data_map([
        TOPIC, {"id": "x", "kind": "topic", "name": "logs", "connection_id": "k", "labels": {}},
        ident("svc"), ident("partner", external=True), ident("admin"),
        grant("svc", "payments-events"), grant("partner", "payments-events"), grant("admin", "*", wildcard=True),
        grant("blocked", "payments-events", permission="deny"), grant("elsewhere", "payments-events", cid="z"),
    ], CONNS)
    assert len(rows) == 1
    r = rows[0]
    assert (r["direct_readers"], r["wildcard_readers"], r["external_readers"]) == (2, 1, 1)
    assert r["classes"] == ["financial"] and r["system"] == "kafka"
