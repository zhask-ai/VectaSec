"""Vanta / Drata evidence push (notify.send_vanta / send_drata) and the INTEGRATION_FIELDS
contract the console mirrors. HTTP through httpx.MockTransport; no network."""
import json

import httpx
import pytest

from vectasec import notify
from vectasec.notify import (
    INTEGRATION_FIELDS,
    INTEGRATION_REQUIRED,
    INTEGRATION_SECRET_KEYS,
    INTEGRATION_TYPES,
    NotifyError,
    deliver,
    evidence_payload,
    send_drata,
    send_vanta,
    split_integration_config,
    validate_integration_config,
)

TENANT = "00000000-0000-0000-0000-000000000001"
SCAN = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def finding(**over):
    f = {"id": "f-1", "rule_id": "KAFKA.TOPIC.PUBLIC", "title": "Topic world-readable",
         "severity": "high", "detail": "anyone can read payments",
         "resource_name": "payments", "resource_kind": "topic", "resource_ext_id": "topic-payments"}
    f.update(over)
    return f


def event(**over):
    e = {"kind": "new_findings", "tenant_id": TENANT, "scan_id": SCAN,
         "connection": {"type": "kafka", "name": "prod"}, "findings": [finding()], "error": None}
    e.update(over)
    return e


def capture_client(status_code=200):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(status_code, json={"id": "1", "success": True})

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def multipart_parts(request):
    """{field_name: (filename|None, bytes)} out of a multipart body — enough to assert on."""
    ctype = request.headers["content-type"]
    boundary = ctype.split("boundary=")[1].encode()
    out = {}
    for chunk in request.content.split(b"--" + boundary)[1:-1]:
        head, _, body = chunk.lstrip(b"\r\n").partition(b"\r\n\r\n")
        disp = head.split(b"\r\n")[0].decode()
        name = disp.split('name="')[1].split('"')[0]
        filename = disp.split('filename="')[1].split('"')[0] if 'filename="' in disp else None
        out[name] = (filename, body.rstrip(b"\r\n"))
    return out


# ── contracts ──────────────────────────────────────────────────────────────
def test_vanta_and_drata_are_registered_types_with_declared_secrets():
    assert "vanta" in INTEGRATION_TYPES and "drata" in INTEGRATION_TYPES
    assert INTEGRATION_SECRET_KEYS["vanta"] == ("api_token",)
    assert INTEGRATION_SECRET_KEYS["drata"] == ("api_key",)
    assert "vanta" in notify.SENDERS and "drata" in notify.SENDERS


def test_validate_integration_config_for_vanta_and_drata():
    assert validate_integration_config("vanta", {}) == [
        "api_token is required for a vanta integration",
        "document_id is required for a vanta integration"]
    assert validate_integration_config("vanta", {"api_token": "t", "document_id": "d"}) == []
    # an update may leave the vaulted token blank
    assert validate_integration_config("vanta", {"document_id": "d"}, stored_secret_keys=("api_token",)) == []
    assert validate_integration_config("drata", {"api_key": "k"}) == ["control_id is required for a drata integration"]
    assert validate_integration_config("drata", {"api_key": "k", "control_id": "42"}) == []


def test_split_keeps_only_the_declared_secrets_out_of_public_config():
    public, secrets = split_integration_config(
        "vanta", {"api_token": "vat_x", "document_id": "d", "region": "us"})
    assert public == {"document_id": "d", "region": "us"} and secrets == {"api_token": "vat_x"}
    public, secrets = split_integration_config("drata", {"api_key": "k", "control_id": "42"})
    assert public == {"control_id": "42"} and secrets == {"api_key": "k"}


def test_integration_fields_cover_every_type_and_match_secret_and_required_keys():
    assert set(INTEGRATION_FIELDS) == set(INTEGRATION_TYPES)
    for type_ in INTEGRATION_TYPES:
        fields = INTEGRATION_FIELDS[type_]
        keys = [f["key"] for f in fields]
        assert len(keys) == len(set(keys)), type_
        for f in fields:
            assert set(f) == {"key", "label", "secret", "required", "help"}, (type_, f)
            assert isinstance(f["secret"], bool) and isinstance(f["required"], bool)
            assert f["label"]
        assert {f["key"] for f in fields if f["secret"]} == set(INTEGRATION_SECRET_KEYS[type_]), type_
        assert {f["key"] for f in fields if f["required"]} == set(INTEGRATION_REQUIRED[type_]), type_
        # every required key is a declared field, so the console can render what validation demands
        assert set(INTEGRATION_REQUIRED[type_]) <= set(keys), type_


# ── evidence payload ───────────────────────────────────────────────────────
def test_evidence_payload_for_a_scan_event_lists_findings_and_points_at_the_register():
    p = evidence_payload(event())
    assert p["source"] == "vectasec" and p["event"] == "new_findings" and p["scan_id"] == SCAN
    assert p["findings"] == [{"rule": "KAFKA.TOPIC.PUBLIC", "severity": "high", "resource": "payments",
                              "resource_kind": "topic", "observation": "anyone can read payments",
                              "status": "open", "title": "Topic world-readable"}]
    assert p["access_register"]["endpoint"] == "/reports/access-register?format=csv"


def test_evidence_payload_for_a_digest_event_is_the_digest_summary():
    p = evidence_payload({"kind": "weekly_digest", "tenant_id": TENANT, "digest": {"scans": {"total": 3}}})
    assert p["digest"] == {"scans": {"total": 3}} and "findings" not in p


def test_evidence_payload_for_control_evaluated():
    p = evidence_payload({"kind": "control_evaluated", "tenant_id": TENANT,
                          "control": {"framework": "SOC2_TSC_2017", "control_id": "CC6.1", "status": "fail"}})
    assert p["control"]["control_id"] == "CC6.1"
    assert "control_evaluated" in notify.EVENT_KINDS


# ── Vanta ──────────────────────────────────────────────────────────────────
def test_vanta_uploads_the_evidence_file_to_the_document():
    client, seen = capture_client()
    send_vanta({"api_token": "vat_secret", "document_id": "doc-7"}, event(), client=client)
    assert len(seen) == 1
    req = seen[0]
    assert req.method == "POST"
    assert str(req.url) == "https://api.vanta.com/v1/documents/doc-7/uploads"
    assert req.headers["authorization"] == "Bearer vat_secret"
    assert req.headers["content-type"].startswith("multipart/form-data")
    parts = multipart_parts(req)
    assert parts["description"][1] == b"VectaSec scan evidence: kafka/prod (1 finding(s))"
    filename, body = parts["file"]
    assert filename.endswith(".json")
    payload = json.loads(body)
    assert payload["findings"][0]["rule"] == "KAFKA.TOPIC.PUBLIC"
    assert payload["tenant_id"] == TENANT


def test_vanta_gov_region_and_custom_resource_sync():
    client, seen = capture_client()
    send_vanta({"api_token": "t", "document_id": "d", "region": "gov", "resource_id": "res-1",
                "register_url": "https://console.example/access-register"}, event(), client=client)
    assert [str(r.url) for r in seen] == [
        "https://api.vanta-gov.com/v1/documents/d/uploads",
        "https://api.vanta-gov.com/v1/resources/custom_resource"]
    assert seen[1].method == "PUT"
    body = json.loads(seen[1].content)
    assert body == {"resourceId": "res-1", "resources": [{
        "displayName": "KAFKA.TOPIC.PUBLIC on payments", "uniqueId": "f-1",
        "externalUrl": "https://console.example/access-register"}]}
    # the register link is cited in the evidence file too
    assert json.loads(multipart_parts(seen[0])["file"][1])["access_register"]["url"] == \
        "https://console.example/access-register"


def test_vanta_digest_event_skips_the_resource_sync():
    client, seen = capture_client()
    send_vanta({"api_token": "t", "document_id": "d", "resource_id": "r"},
               {"kind": "weekly_digest", "tenant_id": TENANT, "digest": {"period_start": "2026-10-10",
                                                                          "period_end": "2026-10-17"}},
               client=client)
    assert len(seen) == 1
    assert multipart_parts(seen[0])["description"][1] == b"VectaSec weekly digest 2026-10-10 to 2026-10-17"


def test_vanta_missing_config_and_bad_region_and_http_error():
    with pytest.raises(NotifyError):
        send_vanta({"api_token": "t"}, event(), client=capture_client()[0])
    with pytest.raises(NotifyError) as e:
        send_vanta({"api_token": "t", "document_id": "d", "region": "mars"}, event(), client=capture_client()[0])
    assert "region" in str(e.value)
    client, _ = capture_client(401)
    with pytest.raises(NotifyError) as e:
        send_vanta({"api_token": "t", "document_id": "d"}, event(), client=client)
    assert "vanta" in str(e.value) and "401" in str(e.value)


# ── Drata ──────────────────────────────────────────────────────────────────
def test_drata_uploads_external_evidence_to_the_control():
    client, seen = capture_client()
    send_drata({"api_key": "dk_secret", "control_id": "42"}, event(), client=client)
    assert len(seen) == 1
    req = seen[0]
    assert req.method == "POST"
    assert str(req.url) == "https://public-api.drata.com/public/controls/42/external-evidence"
    assert req.headers["authorization"] == "Bearer dk_secret"
    parts = multipart_parts(req)
    assert parts["description"][1] == b"VectaSec scan evidence: kafka/prod (1 finding(s))"
    assert parts["filename"][1].endswith(b".json")
    assert "renewalScheduleType" not in parts and "workspaceId" not in parts
    payload = json.loads(parts["file"][1])
    assert payload["findings"][0]["status"] == "open"


def test_drata_optional_fields_and_base_url():
    client, seen = capture_client()
    send_drata({"api_key": "k", "control_id": "7", "base_url": "https://public-api.eu.drata.com/",
                "workspace_id": "ws-1", "renewal_schedule_type": "QUARTERLY",
                "register_url": "https://console.example/access-register"},
               {"kind": "weekly_digest", "tenant_id": TENANT,
                "digest": {"period_start": "2026-10-10T00:00:00+00:00", "period_end": "2026-10-17T00:00:00+00:00"}},
               client=client)
    assert str(seen[0].url) == "https://public-api.eu.drata.com/public/controls/7/external-evidence"
    parts = multipart_parts(seen[0])
    assert parts["workspaceId"][1] == b"ws-1"
    assert parts["renewalScheduleType"][1] == b"QUARTERLY"
    assert parts["url"][1] == b"https://console.example/access-register"
    assert parts["creationDate"][1] == b"2026-10-17T00:00:00+00:00"


def test_drata_missing_config_and_http_error():
    with pytest.raises(NotifyError):
        send_drata({"api_key": "k"}, event(), client=capture_client()[0])
    client, _ = capture_client(412)
    with pytest.raises(NotifyError) as e:
        send_drata({"api_key": "k", "control_id": "1"}, event(), client=client)
    assert "drata" in str(e.value) and "412" in str(e.value)


# ── guard_url applies when no client is injected ──────────────────────────
def test_guard_url_refuses_a_metadata_address_for_drata_and_vanta(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, *a, **k: [(None, None, None, None, ("169.254.169.254", 0))])
    with pytest.raises(NotifyError) as e:
        send_drata({"api_key": "k", "control_id": "1", "base_url": "http://metadata.internal"}, event())
    assert "link-local" in str(e.value)
    # vanta's host is fixed, but the guard still runs on it (resolution is monkeypatched here)
    with pytest.raises(NotifyError) as e:
        send_vanta({"api_token": "t", "document_id": "d"}, event())
    assert "link-local" in str(e.value)


def test_deliver_dispatches_to_the_new_senders():
    client, seen = capture_client()
    deliver("drata", {"api_key": "k", "control_id": "1"}, event(), client=client)
    deliver("vanta", {"api_token": "t", "document_id": "d"}, event(), client=client)
    assert [str(r.url) for r in seen] == [
        "https://public-api.drata.com/public/controls/1/external-evidence",
        "https://api.vanta.com/v1/documents/d/uploads"]
