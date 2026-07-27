"""The Gemini leg of grounded triage. Offline: _gemini_post is stubbed — nothing here touches
the network (test_ai.py's rule, held to here).

The product claim does not change per provider: *every AI claim cites a stored observation, or
the output is discarded.* These tests pin the three things a second provider could quietly
break: (1) Gemini output passes through the SAME _grounded_triage gate as Anthropic output,
(2) the provider chain is assembled from which keys are set — Gemini-only, Anthropic-first when
dual-keyed, and an Anthropic auth failure never condemns the Gemini leg — and (3) the schema
sent to Gemini still demands at least one citation after the fields its API rejects are
stripped.
"""
import json

import pytest

import vectasec.ai as ai
from vectasec.ai import (
    GEMINI_MODELS, MODELS, TRIAGE_SCHEMA, ModelHTTPError, UncitedOutput,
    _call_gemini, _gemini_schema, _provider_chain, _triage_via_models,
)
from test_ai import FINDING, OBS, payload


def gemini_response(body: str, finish: str = "STOP", thought: str | None = None) -> dict:
    """A generateContent response body. `thought` prepends a thought-flagged part, which the
    parser must skip — thought summaries are prose about the answer, not the answer."""
    parts = []
    if thought is not None:
        parts.append({"text": thought, "thought": True})
    parts.append({"text": body})
    return {"candidates": [{"content": {"parts": parts}, "finishReason": finish}]}


@pytest.fixture
def gemini(monkeypatch):
    """Installs a fake _gemini_post. Returns a handle whose .calls records (url, body), so a
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

    monkeypatch.setattr(ai, "_gemini_post", fake_post)
    monkeypatch.setenv("GEMINI_API_KEY", "gm-test-not-a-real-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    return h


# ═══ the schema Gemini receives still carries the contract ═════════════════
def test_gemini_schema_strips_only_what_the_api_rejects():
    s = _gemini_schema(TRIAGE_SCHEMA)
    assert "additionalProperties" not in json.dumps(s)
    assert s["required"] == TRIAGE_SCHEMA["required"]
    assert s["properties"]["citations"]["minItems"] == 1
    assert s["properties"]["priority"]["enum"] == ["P0", "P1", "P2", "P3"]
    # and the original was not mutated
    assert TRIAGE_SCHEMA["additionalProperties"] is False


# ═══ the accepting path ════════════════════════════════════════════════════
def test_valid_gemini_output_is_grounded_floored_and_attributed(gemini):
    gemini.resp = gemini_response(payload(citations=[1, 2]))
    t = _call_gemini(FINDING, OBS)
    assert t.cited_observation_ids == [OBS[0]["id"], OBS[1]["id"]]
    assert t.grounded is True and t.model == GEMINI_MODELS[0]
    # payload() says P1, FINDING is critical (floor P0) — the same clamp as the Anthropic path.
    assert t.priority == "P0" and t.model_priority == "P1" and t.priority_floor_applied is True
    # request shape: system instruction, JSON response mode, the stripped schema
    body = gemini.calls[0]["body"]
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert "additionalProperties" not in json.dumps(body["generationConfig"]["responseSchema"])
    assert GEMINI_MODELS[0] in gemini.calls[0]["url"]


def test_thought_parts_are_not_the_answer(gemini):
    gemini.resp = gemini_response(payload(citations=[1]), thought="Let me think about PLAINTEXT…")
    t = _call_gemini(FINDING, OBS)
    assert t.cited_observation_ids == [OBS[0]["id"]]


# ═══ the same grounding gate, enforced on Gemini output ════════════════════
def test_gemini_citations_out_of_range_are_discarded(gemini):
    gemini.resp = gemini_response(payload(citations=[99]))
    with pytest.raises(UncitedOutput):
        _call_gemini(FINDING, OBS)


def test_gemini_zero_citations_is_not_an_output(gemini):
    gemini.resp = gemini_response(payload(citations=[]))
    with pytest.raises(UncitedOutput) as e:
        _call_gemini(FINDING, OBS)
    assert "no citations" in str(e.value)


# ═══ Gemini's refusal and truncation shapes ════════════════════════════════
def test_a_blocked_prompt_is_a_refusal_not_a_crash(gemini):
    gemini.resp = {"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}, "candidates": []}
    with pytest.raises(UncitedOutput) as e:
        _call_gemini(FINDING, OBS)
    assert "declined" in str(e.value)


def test_a_safety_stop_is_a_refusal_not_a_crash(gemini):
    gemini.resp = gemini_response(payload(citations=[1]), finish="SAFETY")
    with pytest.raises(UncitedOutput) as e:
        _call_gemini(FINDING, OBS)
    assert "declined" in str(e.value)


def test_truncated_output_is_discarded(gemini):
    gemini.resp = gemini_response('{"summary": "cut off', finish="MAX_TOKENS")
    with pytest.raises(UncitedOutput) as e:
        _call_gemini(FINDING, OBS)
    assert "truncated" in str(e.value)


def test_an_empty_candidate_list_is_not_an_output(gemini):
    gemini.resp = {"candidates": []}
    with pytest.raises(UncitedOutput):
        _call_gemini(FINDING, OBS)


# ═══ ModelHTTPError carries what _is_retryable needs ═══════════════════════
def test_a_429_walks_the_gemini_chain_a_400_does_not(gemini):
    gemini.seq = [ModelHTTPError(429, "quota"), gemini_response(payload(citations=[1]))]
    t = _triage_via_models(FINDING, OBS, 0)
    assert t.model == GEMINI_MODELS[1]
    assert len(gemini.calls) == 2

    gemini.calls.clear()
    gemini.seq = [ModelHTTPError(400, "bad request"), gemini_response(payload(citations=[1]))]
    with pytest.raises(ModelHTTPError):
        _triage_via_models(FINDING, OBS, 0)
    assert len(gemini.calls) == 1       # recurs identically — the second model is never asked


# ═══ the provider chain is built from which keys are set ═══════════════════
def test_gemini_only_deployment_gets_a_gemini_chain(gemini):
    assert _provider_chain() == [("gemini", m) for m in GEMINI_MODELS]


def test_dual_keyed_deployment_tries_anthropic_first(gemini, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-a-real-key")
    chain = _provider_chain()
    assert chain[: len(MODELS)] == [("anthropic", m) for m in MODELS]
    assert chain[len(MODELS):] == [("gemini", m) for m in GEMINI_MODELS]


def test_no_keys_means_an_empty_chain(gemini, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    assert _provider_chain() == []


def test_an_anthropic_auth_error_does_not_condemn_the_gemini_leg(gemini, monkeypatch):
    """The reason non-retryable errors skip a PROVIDER rather than abort the CHAIN: the other
    provider's key and endpoint are independent. Anthropic 401s twice-over -> Gemini still
    produces the grounded triage."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-revoked")

    class _Auth(Exception):
        status_code = 401

    calls = []

    def anthropic_always_401(finding, observations, n_total=0, model=None):
        calls.append(model)
        raise _Auth("invalid x-api-key")

    monkeypatch.setitem(ai._PROVIDER_CALLS, "anthropic", anthropic_always_401)
    gemini.resp = gemini_response(payload(citations=[1]))
    t = _triage_via_models(FINDING, OBS, 0)
    assert t.model == GEMINI_MODELS[0] and t.grounded is True
    assert calls == [MODELS[0]]         # 401 on the head — the rest of the provider is skipped
    assert len(gemini.calls) == 1
