"""The OpenAI leg of grounded triage. Offline: _openai_post is stubbed — nothing here touches
the network (test_ai.py's rule, held to here).

Same thesis as test_ai_gemini.py: a provider is swappable, the grounding contract is not.
These tests pin (1) OpenAI output passing through the SAME _grounded_triage gate, (2) OpenAI's
own refusal/truncation shapes (the `refusal` field, finish_reason length/content_filter) being
treated as refusals rather than crashes, and (3) the provider chain placing OpenAI after
Anthropic and before Gemini, assembled from which keys are set.
"""
import json

import pytest

import vectasec.ai as ai
from vectasec.ai import (
    GEMINI_MODELS, MODELS, OPENAI_MODELS, TRIAGE_SCHEMA, ModelHTTPError, UncitedOutput,
    _call_openai, _openai_schema, _provider_chain, _triage_via_models,
)
from test_ai import FINDING, OBS, payload


def openai_response(body: str, finish: str = "stop", refusal: str | None = None) -> dict:
    """A chat.completions response body, shaped like the API actually replies."""
    return {"choices": [{"message": {"content": body, "refusal": refusal},
                         "finish_reason": finish}]}


@pytest.fixture
def openai(monkeypatch):
    """Installs a fake _openai_post. Returns a handle whose .calls records (url, body), so a
    test can assert the API was never reached at all."""
    class Handle:
        resp = None
        exc = None
        seq = None          # optional per-call script of (dict | Exception), consumed in order
        calls: list = []

    h = Handle()
    h.calls = []

    def fake_post(url, api_key, body):
        h.calls.append({"url": url, "api_key": api_key, "body": body})
        if h.seq is not None:
            i = len(h.calls) - 1
            item = h.seq[i] if i < len(h.seq) else h.seq[-1]
            if isinstance(item, BaseException):
                raise item
            return item
        if h.exc:
            raise h.exc
        return h.resp

    monkeypatch.setattr(ai, "_openai_post", fake_post)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-test-not-a-real-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    return h


# ═══ the schema OpenAI receives still carries the contract ═════════════════
def test_openai_schema_strips_only_what_strict_mode_rejects():
    s = _openai_schema(TRIAGE_SCHEMA)
    assert "minItems" not in json.dumps(s)
    # strict mode REQUIRES additionalProperties:false — it must survive the strip.
    assert s["additionalProperties"] is False
    assert s["required"] == TRIAGE_SCHEMA["required"]
    assert s["properties"]["priority"]["enum"] == ["P0", "P1", "P2", "P3"]
    # and the original was not mutated
    assert TRIAGE_SCHEMA["properties"]["citations"]["minItems"] == 1


# ═══ the accepting path ════════════════════════════════════════════════════
def test_valid_openai_output_is_grounded_floored_and_attributed(openai):
    openai.resp = openai_response(payload(citations=[1, 2]))
    t = _call_openai(FINDING, OBS)
    assert t.cited_observation_ids == [OBS[0]["id"], OBS[1]["id"]]
    assert t.grounded is True and t.model == OPENAI_MODELS[0]
    # payload() says P1, FINDING is critical (floor P0) — the same clamp as every other leg.
    assert t.priority == "P0" and t.model_priority == "P1" and t.priority_floor_applied is True
    # request shape: strict structured outputs, system+user messages, the stripped schema
    body = openai.calls[0]["body"]
    fmt = body["response_format"]["json_schema"]
    assert fmt["strict"] is True and "minItems" not in json.dumps(fmt["schema"])
    assert body["messages"][0]["role"] == "system"
    assert openai.calls[0]["url"].endswith("/chat/completions")


# ═══ the same grounding gate, enforced on OpenAI output ════════════════════
def test_openai_citations_out_of_range_are_discarded(openai):
    openai.resp = openai_response(payload(citations=[99]))
    with pytest.raises(UncitedOutput):
        _call_openai(FINDING, OBS)


def test_openai_zero_citations_is_not_an_output(openai):
    openai.resp = openai_response(payload(citations=[]))
    with pytest.raises(UncitedOutput) as e:
        _call_openai(FINDING, OBS)
    assert "no citations" in str(e.value)


# ═══ OpenAI's refusal and truncation shapes ════════════════════════════════
def test_the_refusal_field_is_a_refusal_not_a_crash(openai):
    openai.resp = openai_response("", refusal="I can't help with exploit guidance.")
    with pytest.raises(UncitedOutput) as e:
        _call_openai(FINDING, OBS)
    assert "declined" in str(e.value)


def test_truncated_output_is_discarded(openai):
    openai.resp = openai_response('{"summary": "cut off', finish="length")
    with pytest.raises(UncitedOutput) as e:
        _call_openai(FINDING, OBS)
    assert "truncated" in str(e.value)


def test_a_content_filter_stop_is_a_refusal_not_a_crash(openai):
    openai.resp = openai_response(payload(citations=[1]), finish="content_filter")
    with pytest.raises(UncitedOutput) as e:
        _call_openai(FINDING, OBS)
    assert "declined" in str(e.value)


def test_an_empty_choice_list_is_not_an_output(openai):
    openai.resp = {"choices": []}
    with pytest.raises(UncitedOutput):
        _call_openai(FINDING, OBS)


# ═══ ModelHTTPError carries what _is_retryable needs ═══════════════════════
def test_a_429_walks_the_openai_chain_a_400_does_not(openai):
    openai.seq = [ModelHTTPError(429, "quota"), openai_response(payload(citations=[1]))]
    t = _triage_via_models(FINDING, OBS, 0)
    assert t.model == OPENAI_MODELS[1]
    assert len(openai.calls) == 2

    openai.calls.clear()
    openai.seq = [ModelHTTPError(400, "bad request"), openai_response(payload(citations=[1]))]
    with pytest.raises(ModelHTTPError):
        _triage_via_models(FINDING, OBS, 0)
    assert len(openai.calls) == 1       # recurs identically — the second model is never asked


# ═══ the provider chain is built from which keys are set ═══════════════════
def test_openai_only_deployment_gets_an_openai_chain(openai):
    assert _provider_chain() == [("openai", m) for m in OPENAI_MODELS]


def test_all_three_keys_order_anthropic_openai_gemini(openai, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-a-real-key")
    monkeypatch.setenv("GEMINI_API_KEY", "gm-test-not-a-real-key")
    assert _provider_chain() == ([("anthropic", m) for m in MODELS]
                                 + [("openai", m) for m in OPENAI_MODELS]
                                 + [("gemini", m) for m in GEMINI_MODELS])


def test_a_dead_anthropic_key_does_not_condemn_the_openai_leg(openai, monkeypatch):
    """The user-shaped scenario: a revoked/dead key on a provider EARLIER in the chain alongside
    a working key behind it. The dead provider 401s once, is skipped as a provider (not walked
    through both its models), and the working leg still produces the grounded triage."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-revoked")

    calls = []

    def anthropic_always_401(finding, observations, n_total=0, model=None):
        calls.append(model)
        raise ModelHTTPError(401, "invalid x-api-key")

    monkeypatch.setitem(ai._PROVIDER_CALLS, "anthropic", anthropic_always_401)
    openai.resp = openai_response(payload(citations=[1]))
    t = _triage_via_models(FINDING, OBS, 0)
    assert t.model == OPENAI_MODELS[0] and t.grounded is True
    assert calls == [MODELS[0]]         # 401 on the head — the rest of the provider is skipped
    assert len(openai.calls) == 1
