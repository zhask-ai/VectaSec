"""RabbitMQ enabled-plugin inventory (connect/rabbitmq.py::plugin_resources).

The management API has always reported `enabled_plugins` per node and the connector has always
collected it — these tests pin the derivation of that data into inventory resources. The
honesty constraint under test: the API states plugin NAMES only, so a plugin resource must
carry NO version (a community .ez plugin does not travel with the broker's version, and
stamping it on would be a fabricated fact feeding CVE matching).
"""
from vectasec.connect.rabbitmq import plugin_resources
from vectasec.sbom import component_for


def _node(name, plugins):
    return {"name": name, "enabled_plugins": plugins}


def test_one_resource_per_distinct_plugin_with_its_nodes():
    out = plugin_resources([
        _node("rabbit@a", ["rabbitmq_management", "rabbitmq_shovel"]),
        _node("rabbit@b", ["rabbitmq_management"]),
    ])
    assert [(r.kind, r.name) for r in out] == [
        ("rabbitmq_plugin", "rabbitmq_management"),
        ("rabbitmq_plugin", "rabbitmq_shovel"),
    ]
    mgmt = out[0]
    assert mgmt.ext_id == "plugin-rabbitmq_management"
    assert mgmt.raw["enabled_on_nodes"] == ["rabbit@a", "rabbit@b"]
    assert out[1].raw["enabled_on_nodes"] == ["rabbit@a"]


def test_a_plugin_claims_no_version_and_is_not_an_sbom_component():
    (r,) = plugin_resources([_node("rabbit@a", ["rabbitmq_delayed_message_exchange"])])
    assert "version" not in r.labels and "version" not in r.raw
    assert component_for({"kind": r.kind, "name": r.name, "ext_id": r.ext_id,
                          "labels": r.labels, "raw": r.raw}) is None


def test_garbage_shapes_are_dropped():
    assert plugin_resources(None) == []
    assert plugin_resources(["x", {}, {"name": "n", "enabled_plugins": None}]) == []
    assert plugin_resources([{"enabled_plugins": ["p"]}])[0].raw["enabled_on_nodes"] == [""]
