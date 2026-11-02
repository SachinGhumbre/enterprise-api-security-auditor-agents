"""Unit tests for the central model router.

All transports are fakes; no network or credentials are touched.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, router  # noqa: E402


def _router(**kwargs):
    kwargs.setdefault("max_retries", 1)
    kwargs.setdefault("backoff_base_s", 0)
    kwargs.setdefault("fallback_order", [])
    return router.Router(**kwargs)


def _ok_transport(seen=None, usage=None):
    def transport(provider, model, messages, max_tokens, route):
        (seen if seen is not None else []).append((provider, model))
        return '{"ok": true}', usage or {"prompt_tokens": 10,
                                         "completion_tokens": 5,
                                         "total_tokens": 15}
    return transport


# --- selection ---------------------------------------------------------------------

def test_explicit_model_selection(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    seen = []
    response = _router(transport=_ok_transport(seen)).run(
        router.SECURITY_INVESTIGATION, [{"role": "user", "content": "hi"}])
    assert seen == [("meta", "muse-spark-1.3")]
    assert (response.provider, response.model) == ("meta", "muse-spark-1.3")
    assert response.parsed == {"ok": True}


def test_unknown_task_is_rejected():
    with pytest.raises(router.RouterError, match="Unknown task"):
        _router(transport=_ok_transport()).run(
            "nope", [{"role": "user", "content": "hi"}])


def test_empty_model_id_raises_instead_of_defaulting(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "")
    with pytest.raises(router.RouterError, match="refusing to rely"):
        _router(transport=_ok_transport()).run(
            router.SECURITY_INVESTIGATION, [{"role": "user", "content": "hi"}])


# --- retries -------------------------------------------------------------------------

def test_retryable_error_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    calls = []

    def flaky(provider, model, messages, max_tokens, route):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("503 Service Unavailable")
        return '{"ok": true}', None

    response = _router(transport=flaky).run(
        router.THREAT_MODELLING, [{"role": "user", "content": "hi"}])
    assert response.retries == 1
    assert response.fallback_used is False
    assert len(calls) == 2


def test_auth_error_never_retries_or_falls_back(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    monkeypatch.setattr(config, "META_ONLY", False)
    monkeypatch.setattr(config, "AZURE_OPENAI_DEPLOYMENT_NAME", "dep")
    calls = []

    def denied(provider, model, messages, max_tokens, route):
        calls.append(provider)
        raise RuntimeError("401 Unauthorized: invalid api key")

    with pytest.raises(router.RouterError, match="auth"):
        _router(transport=denied, fallback_order=["azure"]).run(
            router.RISK_REASONING, [{"role": "user", "content": "hi"}])
    assert calls == ["meta"]


def test_unknown_model_never_falls_back(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-9.9")
    monkeypatch.setattr(config, "META_ONLY", False)
    monkeypatch.setattr(config, "AZURE_OPENAI_DEPLOYMENT_NAME", "dep")
    calls = []

    def missing(provider, model, messages, max_tokens, route):
        calls.append(provider)
        raise RuntimeError("model_not_found")

    with pytest.raises(router.RouterError, match="not_found"):
        _router(transport=missing, fallback_order=["azure"]).run(
            router.REMEDIATION_PLANNING, [{"role": "user", "content": "hi"}])
    assert calls == ["meta"]


# --- fallback ----------------------------------------------------------------------------

def test_retryable_exhaustion_falls_back(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    monkeypatch.setattr(config, "META_ONLY", False)
    monkeypatch.setattr(config, "AZURE_OPENAI_DEPLOYMENT_NAME", "dep")
    calls = []

    def failover(provider, model, messages, max_tokens, route):
        calls.append(provider)
        if provider == "meta":
            raise RuntimeError("503 Service Unavailable")
        return '{"ok": true}', None

    response = _router(transport=failover, fallback_order=["azure"]).run(
        router.EXECUTIVE_EXPLANATION, [{"role": "user", "content": "hi"}])
    assert response.provider == "azure"
    assert response.fallback_used is True
    assert "503" in response.fallback_reason
    assert calls[0] == "meta" and calls[-1] == "azure"


def test_no_fallback_configured_raises_exhausted(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")

    def down(provider, model, messages, max_tokens, route):
        raise RuntimeError("503 Service Unavailable")

    with pytest.raises(router.RouterError, match="All model candidates failed"):
        _router(transport=down, fallback_order=[]).run(
            router.EVIDENCE_CORRELATION, [{"role": "user", "content": "hi"}])


def test_meta_only_blocks_fallback_observably(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    monkeypatch.setattr(config, "META_ONLY", True)
    monkeypatch.setattr(config, "AZURE_OPENAI_DEPLOYMENT_NAME", "dep")

    def down(provider, model, messages, max_tokens, route):
        raise RuntimeError("503 Service Unavailable")

    instance = _router(transport=down, fallback_order=["azure"])
    with pytest.raises(router.RouterError):
        instance.run(router.SECURITY_INVESTIGATION,
                     [{"role": "user", "content": "hi"}])
    (entry,) = instance.get_call_log()
    assert {"provider": "azure", "reason": "blocked by META_ONLY=true"} in entry["skipped"]


# --- circuit breaker -----------------------------------------------------------------------

def test_circuit_opens_and_fails_fast(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    calls = []

    def down(provider, model, messages, max_tokens, route):
        calls.append(1)
        raise RuntimeError("503 Service Unavailable")

    instance = _router(transport=down, max_retries=0, circuit_threshold=2,
                       circuit_cooldown_s=60)
    messages = [{"role": "user", "content": "hi"}]
    with pytest.raises(router.RouterError):
        instance.run(router.RISK_REASONING, messages)
    with pytest.raises(router.RouterError):
        instance.run(router.RISK_REASONING, messages)
    assert instance.breaker.state("meta:muse-spark-1.3") == "open"
    with pytest.raises(router.RouterError, match="All model candidates failed"):
        instance.run(router.RISK_REASONING, messages)
    assert len(calls) == 2  # third run failed fast without a transport call


def test_circuit_half_open_probe_recovers():
    breaker = router.CircuitBreaker(threshold=2, cooldown_s=60)
    breaker.record_failure("k")
    breaker.record_failure("k")
    assert breaker.allow("k") is False
    breaker._opened_at["k"] -= 61  # cooldown elapsed
    assert breaker.allow("k") is True  # one probe
    breaker.record_success("k")
    assert breaker.state("k") == "closed"
    assert breaker.allow("k") is True


# --- recording and redaction -------------------------------------------------------------------

def test_call_log_records_without_bodies(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    instance = _router(transport=_ok_transport())
    instance.run(router.SECURITY_INVESTIGATION,
                 [{"role": "user", "content": "secret-content-marker"}])
    (entry,) = instance.get_call_log()
    assert entry["model"] == "muse-spark-1.3"
    assert entry["task"] == router.SECURITY_INVESTIGATION
    assert entry["usage"] == {"prompt_tokens": 10, "completion_tokens": 5,
                              "total_tokens": 15}
    assert entry["latency_ms"] >= 0
    assert "secret-content-marker" not in str(entry)


def test_error_text_is_redacted_in_log(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")

    def denied(provider, model, messages, max_tokens, route):
        raise RuntimeError("401 with Authorization: Bearer [REDACTED]")

    instance = _router(transport=denied)
    with pytest.raises(router.RouterError):
        instance.run(router.RISK_REASONING, [{"role": "user", "content": "hi"}])
    (entry,) = instance.get_call_log()
    assert "supersecret-token" not in entry["error"]
    assert "[REDACTED]" in entry["error"]


def test_redact_scrubs_credential_shapes():
    assert router.redact("key sk-abc123456789 end") == "key [REDACTED] end"
    assert "kpat_" not in router.redact("tok kpat_xyz123")
    assert router.redact('api-key: "hunter2"') == 'api-key: "[REDACTED]"'


# --- streaming and parsing ----------------------------------------------------------------------

def test_stream_yields_deltas_then_response(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")

    def stream(provider, model, messages, max_tokens, route):
        assert (provider, model) == ("meta", "muse-spark-1.3")
        yield from ("a", "b")

    events = list(_router(stream_transport=stream).run_stream(
        router.EXECUTIVE_EXPLANATION, [{"role": "user", "content": "hi"}]))
    assert events[0] == {"delta": "a"}
    assert events[1] == {"delta": "b"}
    assert events[2]["response"]["model"] == "muse-spark-1.3"
    assert events[2]["response"]["response_chars"] == 2


def test_stream_refusal_is_recorded(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    instance = _router(circuit_threshold=1, circuit_cooldown_s=60)
    instance.breaker.record_failure("meta:muse-spark-1.3")
    with pytest.raises(router.RouterError, match="Circuit open"):
        list(instance.run_stream(router.RISK_REASONING,
                                 [{"role": "user", "content": "hi"}]))


def test_unparsable_json_keeps_text_with_parsed_none(monkeypatch):
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")

    def prose(provider, model, messages, max_tokens, route):
        return "not json at all", None

    response = _router(transport=prose).run(
        router.SECURITY_INVESTIGATION, [{"role": "user", "content": "hi"}],
        expect="object")
    assert response.text == "not json at all"
    assert response.parsed is None
