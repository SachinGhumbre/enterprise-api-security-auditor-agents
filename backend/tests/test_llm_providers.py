"""Tests for the LLM provider layer.

Focus is the Meta Model API path used for the Meta Global AI Developer Hackathon:
provider resolution, that the configured Muse Spark model id is actually sent,
and the OpenAI-compatible parameter handling. The SDK client is stubbed, so no
network access or API key is needed.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, llm  # noqa: E402


class FakeMessage:
    def __init__(self, content):
        self.content = content


class FakeChoice:
    def __init__(self, content):
        self.message = FakeMessage(content)


class FakeCompletion:
    def __init__(self, content):
        self.choices = [FakeChoice(content)]


class FakeCompletions:
    """Records the kwargs the agent sends, and can simulate parameter rejection."""

    def __init__(self, content='{"ok": true}', reject=None):
        self.content = content
        self.reject = reject
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.reject and len(self.calls) == 1:
            raise RuntimeError(self.reject)
        return FakeCompletion(self.content)


class FakeClient:
    def __init__(self, completions):
        self.chat = type("Chat", (), {"completions": completions})()


@pytest.fixture
def meta_mode(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "meta")
    monkeypatch.setattr(config, "META_API_KEY", "meta_test_key")
    monkeypatch.setattr(config, "META_MODEL", "muse-spark-1.3")
    monkeypatch.setattr(config, "META_BASE_URL", "https://api.meta.ai/v1")


# --- provider resolution ------------------------------------------------------

def test_meta_is_preferred_when_key_present(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "auto")
    monkeypatch.setattr(config, "META_API_KEY", "meta_test_key")
    assert config.resolve_llm_provider() == "meta"


def test_falls_back_to_azure_without_meta_key(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "auto")
    monkeypatch.setattr(config, "META_API_KEY", None)
    monkeypatch.setattr(config, "KONG_AI_PROXY_HOSTNAME", None)
    monkeypatch.setattr(config, "KONG_API_KEY", None)
    assert config.resolve_llm_provider() == "azure"


def test_explicit_provider_overrides_auto_detection(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "azure")
    monkeypatch.setattr(config, "META_API_KEY", "meta_test_key")
    assert config.resolve_llm_provider() == "azure"


def test_active_model_reports_muse_spark(meta_mode):
    assert config.active_model() == "muse-spark-1.3"
    assert llm.model_name() == "muse-spark-1.3"


# --- configuration validation ---------------------------------------------------

def test_missing_meta_key_is_reported(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "meta")
    monkeypatch.setattr(config, "META_API_KEY", None)
    problems = llm.check_config()
    assert problems and "META_API_KEY" in problems[0]


def test_meta_config_is_clean_when_key_present(meta_mode):
    assert llm.check_config() == []


# --- chat() against Meta ----------------------------------------------------------

def test_chat_sends_configured_meta_model(meta_mode, monkeypatch):
    completions = FakeCompletions('{"ok": true}')
    monkeypatch.setattr(llm, "_get_meta_client", lambda: FakeClient(completions))

    result = llm.chat([{"role": "user", "content": "hi"}], max_tokens=1234)

    assert result == '{"ok": true}'
    sent = completions.calls[0]
    assert sent["model"] == "muse-spark-1.3"
    # Meta Model API is OpenAI-compatible and takes max_tokens.
    assert sent["max_tokens"] == 1234
    assert "max_completion_tokens" not in sent


def test_chat_retries_with_max_completion_tokens(meta_mode, monkeypatch):
    completions = FakeCompletions(
        '{"ok": true}',
        reject="Unsupported parameter: 'max_tokens'. Use 'max_completion_tokens' instead.",
    )
    monkeypatch.setattr(llm, "_get_meta_client", lambda: FakeClient(completions))

    assert llm.chat([{"role": "user", "content": "hi"}]) == '{"ok": true}'
    assert len(completions.calls) == 2
    assert "max_completion_tokens" in completions.calls[1]


def test_chat_drops_unsupported_temperature(meta_mode, monkeypatch):
    completions = FakeCompletions(
        "done", reject="Unsupported value: 'temperature' is not supported."
    )
    monkeypatch.setattr(llm, "_get_meta_client", lambda: FakeClient(completions))

    assert llm.chat([{"role": "user", "content": "hi"}], temperature=0.2) == "done"
    assert "temperature" in completions.calls[0]
    assert "temperature" not in completions.calls[1]


def test_chat_wraps_meta_failures_with_context(meta_mode, monkeypatch):
    completions = FakeCompletions(reject="503 upstream unavailable")
    # reject fires only on the first call, so force it to always raise.
    def always_raise(**kwargs):
        raise RuntimeError("503 upstream unavailable")
    completions.create = always_raise
    monkeypatch.setattr(llm, "_get_meta_client", lambda: FakeClient(completions))

    with pytest.raises(RuntimeError, match="Meta Model API call failed"):
        llm.chat([{"role": "user", "content": "hi"}])


def test_chat_json_parses_fenced_meta_response(meta_mode, monkeypatch):
    """Models commonly wrap JSON in markdown fences; that must still parse."""
    fenced = '```json\n[{"serviceName": "svc", "severity": "Critical"}]\n```'
    completions = FakeCompletions(fenced)
    monkeypatch.setattr(llm, "_get_meta_client", lambda: FakeClient(completions))

    parsed, raw = llm.chat_json([{"role": "user", "content": "x"}], expect="array")
    assert parsed == [{"serviceName": "svc", "severity": "Critical"}]
    assert raw == fenced


def test_chat_json_extracts_json_embedded_in_prose(meta_mode, monkeypatch):
    noisy = 'Here is the audit:\n{"serviceName": "svc", "policies": []}\nHope that helps!'
    completions = FakeCompletions(noisy)
    monkeypatch.setattr(llm, "_get_meta_client", lambda: FakeClient(completions))

    parsed, _ = llm.chat_json([{"role": "user", "content": "x"}], expect="object")
    assert parsed == {"serviceName": "svc", "policies": []}


# --- agents run on whichever provider is active ------------------------------------

def test_audit_agent_runs_on_meta_provider(meta_mode, monkeypatch, tmp_path):
    """End-to-end graph run with Meta as the provider and the SDK stubbed."""
    from agents import auditor_agent
    from common import vector_store

    monkeypatch.setattr(auditor_agent, "AUDIT_REPORT_FILE", str(tmp_path / "audit.json"))
    monkeypatch.setattr(vector_store, "ping", lambda: False)  # skip RAG for this test

    audit_json = (
        '{"serviceName": "PaymentService", "policies": [{"policy_name": '
        '"Authentication Policy", "comply": false, "missing_plugins": ["jwt"], '
        '"details": "jwt missing"}]}'
    )
    completions = FakeCompletions(audit_json)
    monkeypatch.setattr(llm, "_get_meta_client", lambda: FakeClient(completions))

    result = auditor_agent.audit_app.invoke({
        "kong_data": [{"service_name": "PaymentService", "service_id": "s1",
                       "service_plugins": ["key-auth"]}],
        "selected_standards": ["OWASP API Top 10"],
    })

    assert result["summary"]["llm_provider"] == "meta"
    assert result["summary"]["non_compliant"] == 1
    assert completions.calls[0]["model"] == "muse-spark-1.3"
