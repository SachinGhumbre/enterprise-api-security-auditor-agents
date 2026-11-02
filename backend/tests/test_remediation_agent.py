"""Unit tests for the Remediation Agent nodes.

The LLM and Redis are stubbed, so these run offline and without credentials.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import auditor_agent  # noqa: E402
from common import llm, router, vector_store  # noqa: E402

def _routed(parsed, raw=""):
    return router.ModelResponse(provider="meta", model="muse-spark-1.3",
                                task="test", text=raw, parsed=parsed)



AUDIT_REPORT = {
    "HealthService:policy:HealthService": {
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
}

PLAN = [
    {
        "serviceName": "HealthService",
        "policyName": "Authentication Policy",
        "issue": "jwt plugin missing",
        "missingPlugin": "jwt",
        "recommendedAction": "Enable the jwt plugin.",
        "severity": "Critical",
        "owner": "API Gateway Team",
        "estimatedEffort": "2 hours",
        "impact": "Unauthenticated access is possible.",
        "securityStandardReference": "OWASP API2:2023",
    }
]


@pytest.fixture(autouse=True)
def isolate_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(auditor_agent, "REMEDIATION_PLAN_FILE",
                        str(tmp_path / "langgraph_remediation_plan.json"))
    return tmp_path


@pytest.fixture
def stub_rag(monkeypatch):
    monkeypatch.setattr(vector_store, "ping", lambda: True)
    monkeypatch.setattr(vector_store, "index_exists", lambda *a, **k: True)
    monkeypatch.setattr(vector_store, "search", lambda query, top_k=5, **k: [
        {
            "id": "embedding:test-1",
            "content": "Authentication Policy: enable key-auth, jwt or oauth2.",
            "source": "01_authentication_policy.txt",
            "metadata": {},
            "score": 0.88,
        }
    ])


def test_perceive_extracts_only_non_compliant():
    state = auditor_agent.perceive_issues({"audit_report": AUDIT_REPORT})
    assert len(state["findings"]) == 1
    finding = state["findings"][0]
    assert finding["policyName"] == "Authentication Policy"
    assert finding["missingPlugins"] == ["jwt"]
    # "Authentication" maps to Critical in SEVERITY_MAP.
    assert finding["severity"] == "Critical"


def test_perceive_handles_empty_report():
    state = auditor_agent.perceive_issues({"audit_report": {}})
    assert state["findings"] == []


def test_retrieve_remediation_context(stub_rag):
    state = auditor_agent.perceive_issues({"audit_report": AUDIT_REPORT})
    state = auditor_agent.retrieve_remediation_context(state)
    assert len(state["remediation_context"]) == 1


def test_reason_remediation_returns_plan(monkeypatch, stub_rag):
    monkeypatch.setattr(router, "run", lambda *a, **k: _routed(PLAN, json.dumps(PLAN)))

    state = auditor_agent.perceive_issues({"audit_report": AUDIT_REPORT})
    state = auditor_agent.retrieve_remediation_context(state)
    state = auditor_agent.reason_remediation(state)

    assert state["remediation_plan"] == PLAN


def test_reason_remediation_unwraps_object_response(monkeypatch, stub_rag):
    """Models sometimes wrap the array in {"remediation_plan": [...]}."""
    monkeypatch.setattr(router, "run",
                        lambda *a, **k: _routed({"remediation_plan": PLAN}, json.dumps(PLAN)))

    state = auditor_agent.perceive_issues({"audit_report": AUDIT_REPORT})
    state = auditor_agent.retrieve_remediation_context(state)
    state = auditor_agent.reason_remediation(state)

    assert state["remediation_plan"] == PLAN


def test_reason_remediation_skips_llm_when_compliant(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("LLM must not be called when there are no findings")

    monkeypatch.setattr(router, "run", boom)

    state = auditor_agent.reason_remediation({"findings": []})
    assert state["remediation_plan"] == []
    assert "No non-compliant findings" in state["remediation_note"]


def test_reason_remediation_records_failure(monkeypatch, stub_rag):
    def boom(*args, **kwargs):
        raise RuntimeError("gateway timeout")

    monkeypatch.setattr(router, "run", boom)

    state = auditor_agent.perceive_issues({"audit_report": AUDIT_REPORT})
    state = auditor_agent.reason_remediation(state)

    assert state["remediation_plan"] == []
    assert "gateway timeout" in state["remediation_error"]


def _many_findings(count):
    return [
        {
            "serviceName": f"svc-{i}",
            "policyName": "Authentication Policy",
            "details": "missing jwt",
            "missingPlugins": ["jwt"],
            "severity": "Critical",
        }
        for i in range(count)
    ]


def test_reason_remediation_batches_large_finding_sets(monkeypatch, stub_rag):
    """16 findings must be split into bounded calls, not one oversized request.

    A single call grows with the estate and silently truncates past the token
    cap, producing invalid JSON and losing the whole plan.
    """
    calls = []

    def fake_chat_json(task, messages, **kwargs):
        body = messages[-1]["content"]
        sent = json.loads(body.split("Audit findings:\n", 1)[1].split("\n\nOrganization", 1)[0])
        calls.append(len(sent))
        return _routed([dict(PLAN[0], serviceName=f["serviceName"]) for f in sent], "[]")

    monkeypatch.setattr(router, "run", fake_chat_json)

    state = auditor_agent.reason_remediation({
        "findings": _many_findings(16),
        "remediation_context": [],
        "batch_size": 5,
    })

    assert calls == [5, 5, 5, 1]
    assert state["remediation_batches"] == 4
    assert len(state["remediation_plan"]) == 16
    assert "remediation_error" not in state


def test_reason_remediation_retries_failed_batch_individually(monkeypatch, stub_rag):
    """One unparsable batch must not discard its findings."""
    def fake_chat_json(task, messages, **kwargs):
        body = messages[-1]["content"]
        sent = json.loads(body.split("Audit findings:\n", 1)[1].split("\n\nOrganization", 1)[0])
        if len(sent) > 1:
            return _routed(None, "Sorry, I cannot do that.")  # whole-batch failure
        return _routed([dict(PLAN[0], serviceName=sent[0]["serviceName"])], "[]")

    monkeypatch.setattr(router, "run", fake_chat_json)

    state = auditor_agent.reason_remediation({
        "findings": _many_findings(3),
        "remediation_context": [],
        "batch_size": 3,
    })

    # Recovered all three via the per-finding retry path.
    assert len(state["remediation_plan"]) == 3


def test_reason_remediation_reports_incomplete_coverage(monkeypatch, stub_rag):
    monkeypatch.setattr(router, "run", lambda *a, **k: _routed([], "[]"))

    state = auditor_agent.reason_remediation({
        "findings": _many_findings(4),
        "remediation_context": [],
        "batch_size": 2,
    })

    assert state["remediation_plan"] == []
    assert "were not covered" in state["remediation_error"]


def test_plan_remediation_sorts_by_severity():
    plan = [
        {"severity": "Low", "serviceName": "a"},
        {"severity": "Critical", "serviceName": "b"},
        {"severity": "Medium", "serviceName": "c"},
        {"severity": "High", "serviceName": "d"},
    ]
    state = auditor_agent.plan_remediation({"remediation_plan": plan})
    assert [i["severity"] for i in state["remediation_plan"]] == [
        "Critical", "High", "Medium", "Low",
    ]
    assert state["summary"]["total_actions"] == 4


def test_action_remediation_writes_plan():
    auditor_agent.action_remediation({"remediation_plan": PLAN})
    assert os.path.exists(auditor_agent.REMEDIATION_PLAN_FILE)
    with open(auditor_agent.REMEDIATION_PLAN_FILE, encoding="utf-8") as handle:
        assert json.load(handle) == PLAN


def test_remediation_graph_runs_end_to_end(monkeypatch, stub_rag):
    """The compiled graph must terminate - it needs an explicit END edge."""
    monkeypatch.setattr(router, "run", lambda *a, **k: _routed(PLAN, json.dumps(PLAN)))

    result = auditor_agent.rem_app.invoke({"audit_report": AUDIT_REPORT})

    assert result["summary"]["total_actions"] == 1
    assert result["remediation_plan"][0]["severity"] == "Critical"
    assert os.path.exists(auditor_agent.REMEDIATION_PLAN_FILE)
