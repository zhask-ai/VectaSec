"""The Leaver report (leaver.py). Pinned: exact (never fuzzy) matching, owner fields in labels
and raw and as lists / dicts, accounts vs owned, the "keeps running" join through uses_* edges
and that it excludes the person's own things, stale resources ignored, systems that expose no
owner are named, and an empty result does not claim the person owns nothing."""
from vectasec import leaver

CONNS = [{"id": "c1", "name": "zapier prod", "type": "zapier"}, {"id": "c2", "name": "n8n prod", "type": "n8n"},
         {"id": "c3", "name": "kafka", "type": "kafka"}]


def r(id_, kind, name, cid, labels=None, raw=None, stale=False):
    return {"id": id_, "kind": kind, "name": name, "labels": labels or {}, "raw": raw or {},
            "connection_id": cid, "stale": stale}


RES = [
    r("a", "zapier_connection", "Salesforce (Sam)", "c1", {"owner": "Sam@Corp.io", "app": "salesforce"}),
    r("b", "zapier_zap", "Lead sync", "c1", {"owner": "pat@corp.io"}),
    r("c", "zapier_zap", "Sam's own zap", "c1", {"owner": "sam@corp.io"}),
    r("d", "n8n_user", "sam@corp.io", "c2", {"role": "admin"}),
    r("e", "n8n_workflow", "Invoices", "c2", raw={"created_by": {"email": "sam@corp.io"}}),
    r("f", "airflow_dag", "etl", "c2", raw={"owners": ["sam@corp.io", "data@corp.io"]}),
    r("g", "zapier_zap", "Old", "c1", {"owner": "sam@corp.io"}, stale=True),
    r("h", "topic", "orders", "c3"),
    r("i", "zapier_zap", "samantha thing", "c1", {"owner": "samantha@corp.io"}),
    r("j", "identity", "etl-bot", "c3", {"identity_type": "service_account", "owner_label": "sam@corp.io"}),
]
EDGES = [{"src": "b", "dst": "a", "kind": "uses_connection"},     # Pat's zap uses Sam's connection
         {"src": "c", "dst": "a", "kind": "uses_connection"},     # Sam's own zap: not a "break"
         {"src": "h", "dst": "a", "kind": "contains"}]            # not a dependency edge


def test_owner_values_from_labels_raw_lists_and_dicts():
    assert leaver.owners_of(RES[0]) == {"sam@corp.io"}
    assert leaver.owners_of(RES[4]) == {"sam@corp.io"}
    assert leaver.owners_of(RES[5]) == {"sam@corp.io", "data@corp.io"}
    assert leaver.owners_of(r("x", "t", "n", "c1", {"owner": "?"})) == set()


def test_report_sections():
    rep = leaver.build_report(" SAM@corp.io ", RES, EDGES, CONNS)
    assert [x["name"] for x in rep["accounts"]] == ["sam@corp.io"]
    assert sorted(x["name"] for x in rep["owns"]) == ["Invoices", "Salesforce (Sam)", "Sam's own zap", "etl", "etl-bot"]
    assert [x["name"] for x in rep["breaks"]] == ["Lead sync"]
    assert rep["breaks"][0]["because"] == ["Salesforce (Sam)"] and rep["breaks"][0]["other_owners"] == ["pat@corp.io"]
    assert rep["systems_without_owner_data"] == [], "kafka has an owner-labelled identity"
    assert "Deleting the person's connection before this stops them" in rep["checklist"][0]


def test_matching_is_exact_not_fuzzy():
    rep = leaver.build_report("sam", RES, EDGES, CONNS)
    assert rep["owns"] == [] and rep["accounts"] == []
    assert "by hand" in rep["checklist"][0] and "not proof" in rep["scope_note"]
    rep = leaver.build_report("samantha@corp.io", RES, EDGES, CONNS)
    assert [x["name"] for x in rep["owns"]] == ["samantha thing"]


def test_people_list_and_stale():
    people = {p["person"]: p for p in leaver.list_people(RES)}
    assert people["sam@corp.io"] == {"person": "sam@corp.io", "owns": 5, "accounts": 1}
    assert "etl-bot" not in people, "a service account is not a person"
    assert leaver.list_people(RES)[0]["person"] == "sam@corp.io"


def test_systems_without_owner_data_named():
    rep = leaver.build_report("sam@corp.io", [RES[0], RES[7]], [], CONNS)
    assert rep["systems_without_owner_data"] == ["kafka", "n8n"]


def test_markdown():
    md = leaver.to_markdown(leaver.build_report("sam@corp.io", RES, EDGES, CONNS), "2026-11-23T10:00:00+00:00")
    assert "# Leaver report: sam@corp.io" in md and "| Lead sync |" in md and "Nothing was changed." in md


def test_service_logins_and_identity_references_are_not_people():
    res = [r("g", "identity", "guest", "c3", {"identity_type": "user"}),
           r("u", "rabbitmq_user", "guest", "c3"),
           r("c", "credential", "guest:password", "c3", {"owner": "identity:rabbitmq:guest"}),
           r("h", "identity", "ana@corp.io", "c3", {"identity_type": "admin"})]
    assert [p["person"] for p in leaver.list_people(res)] == ["ana@corp.io"]
    assert leaver.owners_of(res[2]) == set()


def test_confirmed_owner_counts_as_ownership():
    r = {"id": "x", "kind": "identity", "name": "etl-bot", "connection_id": "c3",
         "labels": {"identity_type": "service_account", "owner_confirmed": "Data Team"}, "raw": {}}
    assert leaver.owners_of(r) == {"data team"}
    assert [x["name"] for x in leaver.build_report("data team", [r], [], CONNS)["owns"]] == ["etl-bot"]
