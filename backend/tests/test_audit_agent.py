"""Unit tests for the Audit Agent nodes.

The LLM, Kong Admin API and Redis are all stubbed, so these run offline and
without credentials.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import auditor_agent  # noqa: E402
from common import llm, vector_store  # noqa: E402


KONG_DATA = [
    {
        "service_name": "HealthService",
        "service_id": "svc-1",
        "service_plugins": ["key-auth", "request-transformer"],
    }
]

AUDIT_JSON = {
    "serviceName": "HealthService",
    "policies": [
        {
            "policy_name": "Authentication Policy",
            "comply": False,
            "missing_plugins": ["jwt"],
            "details": "jwt is required but not enabled.",
        },
        {
            "policy_name": "Rate Limiting Policy",
            "comply": True,
            "missing_plugins": [],
            "details": "",
        },
    ],
}


@pytest.fixture(autouse=True)
def isolate_artifacts(tmp_path, monkeypatch):
    """Write audit artifacts into a temp dir instead of the repo."""
    monkeypatch.setattr(auditor_agent, "AUDIT_REPORT_FILE",
                        str(tmp_path / "langgraph_audit_report.json"))
    monkeypatch.setattr(auditor_agent, "KONG_DATA_FILE",
                        str(tmp_path / "filtered_kong_data.json"))
    return tmp_path


@pytest.fixture
def stub_rag(monkeypatch):
    monkeypatch.setattr(vector_store, "ping", lambda: True)
    monkeypatch.setattr(vector_store, "index_exists", lambda *a, **k: True)
    monkeypatch.setattr(vector_store, "search", lambda query, top_k=5: [
        {
            "id": "embedding:test-1",
            "content": "Authentication Policy: services must enable key-auth, jwt or oauth2.",
            "source": "01_authentication_policy.txt",
            "metadata": {},
            "score": 0.91,
        }
    ])


def test_perceive_uses_request_payload():
    """An inventory supplied in the request must bypass the Kong Admin API."""
    state = auditor_agent.perceive_kong({"kong_data": KONG_DATA})
    assert state["kong_source"] == "request"
    assert state["kong_data"] == KONG_DATA


def test_perceive_falls_back_when_kong_unreachable(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(auditor_agent, "collect_kong_inventory", boom)

    state = auditor_agent.perceive_kong({})
    assert state["kong_source"] in ("cached_file", "none")
    assert "Kong Admin API unreachable" in state["kong_warning"]


def test_retrieve_policies_attaches_context(stub_rag):
    state = auditor_agent.retrieve_policies({"kong_data": KONG_DATA})
    assert state["retrieved_chunks"] == 1
    assert "HealthService" in state["policy_context"]


def test_retrieve_policies_warns_when_store_empty(monkeypatch):
    monkeypatch.setattr(vector_store, "ping", lambda: False)
    state = auditor_agent.retrieve_policies({"kong_data": KONG_DATA})
    assert "rag_warning" in state
    assert state["policy_context"] == {}


def test_reason_audit_parses_model_json(monkeypatch, stub_rag):
    monkeypatch.setattr(llm, "chat_json",
                        lambda *a, **k: (AUDIT_JSON, json.dumps(AUDIT_JSON)))

    state = auditor_agent.retrieve_policies({"kong_data": KONG_DATA})
    state = auditor_agent.reason_audit(state)

    entry = state["audit_report"]["HealthService:policy:HealthService"]
    assert entry["serviceName"] == "HealthService"
    assert len(entry["policies"]) == 2
    assert entry["policy_sources"] == ["01_authentication_policy.txt"]


def test_reason_audit_records_unparsable_response(monkeypatch, stub_rag):
    """A non-JSON reply must be reported, not raise UnboundLocalError."""
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: (None, "I cannot help with that."))

    state = auditor_agent.retrieve_policies({"kong_data": KONG_DATA})
    state = auditor_agent.reason_audit(state)

    entry = state["audit_report"]["HealthService:policy:HealthService"]
    assert entry["policies"] == []
    assert "did not return parsable JSON" in entry["error"]


def test_reason_audit_records_call_failure(monkeypatch, stub_rag):
    def boom(*args, **kwargs):
        raise RuntimeError("gateway timeout")

    monkeypatch.setattr(llm, "chat_json", boom)

    state = auditor_agent.retrieve_policies({"kong_data": KONG_DATA})
    state = auditor_agent.reason_audit(state)

    entry = state["audit_report"]["HealthService:policy:HealthService"]
    assert "gateway timeout" in entry["error"]


def test_plan_audit_builds_summary():
    state = auditor_agent.plan_audit({
        "audit_report": {"HealthService:policy:HealthService": AUDIT_JSON},
        "kong_source": "request",
    })
    summary = state["summary"]
    assert summary["services_audited"] == 1
    assert summary["policies_evaluated"] == 2
    assert summary["compliant"] == 1
    assert summary["non_compliant"] == 1
    assert summary["compliance_rate"] == 50.0


def test_action_audit_writes_report(isolate_artifacts):
    state = auditor_agent.action_audit({"audit_report": {"a": AUDIT_JSON}})
    assert os.path.exists(auditor_agent.AUDIT_REPORT_FILE)
    with open(auditor_agent.AUDIT_REPORT_FILE, encoding="utf-8") as handle:
        assert json.load(handle) == {"a": AUDIT_JSON}
    assert state["audit_report"]


def test_audit_graph_runs_end_to_end(monkeypatch, stub_rag, isolate_artifacts):
    """The compiled graph must terminate - it needs an explicit END edge."""
    monkeypatch.setattr(llm, "chat_json",
                        lambda *a, **k: (AUDIT_JSON, json.dumps(AUDIT_JSON)))

    result = auditor_agent.audit_app.invoke({
        "kong_data": KONG_DATA,
        "selected_standards": ["OWASP API Top 10"],
    })

    assert result["summary"]["services_audited"] == 1
    assert os.path.exists(auditor_agent.AUDIT_REPORT_FILE)
