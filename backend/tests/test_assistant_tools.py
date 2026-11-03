"""Unit tests for the real assistant tool implementations.

Snapshots, inventory and the vector store are stubbed at their seams;
the tool code itself (filtering, provenance, fallbacks, task spawn)
runs for real.
"""

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import tools  # noqa: E402

VALUES = {
    "assessment_id": "asm-x",
    "status": "complete",
    "objective": "review payments",
    "depth": "standard",
    "kong_source": "kong_admin_api",
    "kong_live": True,
    "kong_stale": False,
    "kong_snapshot_at": "2026-01-01T00:00:00+00:00",
    "kong_data": [{"service_name": "SvcB"}],
    "enriched_findings": [{"finding_id": "SA-SvcB-0"}],
    "recovered_findings": [],
    "policy_findings": [],
    "threats": [{"threat_id": "TM-SvcB-spoof", "service": "SvcB",
                 "title": "Spoofing", "category": "Spoofing",
                 "severity_hint": "High", "owasp_ref": "OWASP-API2",
                 "preconditions": ["no auth"], "evidence_refs": ["r1"],
                 "recommended_tests": ["t1"], "attack_path": [],
                 "objective": "", "model_explanation": "x"}],
    "quarantined": [],
    "risk": {"register": [{
        "entry_id": "R-SvcB-authentication", "title": "Authentication gap",
        "service": "SvcB", "level": "Critical", "score": 9.1,
        "severity": "Critical", "confidence": "high", "verified": True,
        "state": "open", "capability": "payments", "sources": [],
        "evidence": [], "linked_controls": []}],
        "summary": {"by_level": {"Critical": 1}}},
    "remediation_plan": [{}, {}],
    "change_proposals": [{"change_id": "CH-1"}],
    "validation": {"passed": True},
    "approval": {"decision": "approve"},
    "budgets": {"llm_calls_used": 7},
    "degraded_reasons": [],
    "assessment_summary": {"services": 1},
}


@pytest.fixture
def snapshot(monkeypatch):
    monkeypatch.setattr(
        tools, "_assistant_snapshot",
        lambda _id: (types.SimpleNamespace(tasks=[]), dict(VALUES)))


def test_unknown_assessment_raises(monkeypatch):
    def missing(assessment_id):
        raise tools.ToolError(f"No assessment '{assessment_id}' found.")

    monkeypatch.setattr(tools, "_assistant_snapshot", missing)
    with pytest.raises(tools.ToolError, match="No assessment"):
        tools.TOOL_DEFS["assistant_read_assessment"]["fn"]("asm-nope")


def test_read_assessment_shapes_snapshot(snapshot):
    result = tools.TOOL_DEFS["assistant_read_assessment"]["fn"]("asm-x")
    assert result["status"] == "complete"
    assert result["counts"]["findings"] == 1
    assert result["counts"]["change_proposals"] == 1
    assert result["risk_by_level"] == {"Critical": 1}
    assert result["kong"]["services"] == 1


def test_read_findings_filters_by_level_and_service(snapshot):
    fn = tools.TOOL_DEFS["assistant_read_findings"]["fn"]
    assert fn("asm-x", level="critical")["total"] == 1
    assert fn("asm-x", level="low")["total"] == 0
    assert fn("asm-x", service="SvcB")["total"] == 1
    assert fn("asm-x", service="Nobody")["total"] == 0
    with pytest.raises(tools.ToolError, match="level must be"):
        fn("asm-x", level="urgent")


def test_read_threats_filters_by_service(snapshot):
    fn = tools.TOOL_DEFS["assistant_read_threats"]["fn"]
    assert fn("asm-x")["total"] == 1
    assert fn("asm-x", service="SvcB")["threats"][0][
        "threat_id"] == "TM-SvcB-spoof"
    assert fn("asm-x", service="Nobody")["total"] == 0


def test_executive_brief_is_deterministic(snapshot):
    result = tools.TOOL_DEFS["assistant_executive_brief"]["fn"]("asm-x")
    assert result["by_level"] == {"Critical": 1}
    assert result["top_entries"][0]["entry_id"] == "R-SvcB-authentication"
    assert result["approval"] == "approve"


def test_compare_diffs_two_assessments(monkeypatch):
    older = dict(VALUES, assessment_id="asm-a",
                 risk={"register": [], "summary": {"by_level": {}}})
    newer = dict(VALUES, assessment_id="asm-b")

    def by_id(assessment_id):
        return (types.SimpleNamespace(tasks=[]),
                older if assessment_id == "asm-a" else newer)

    monkeypatch.setattr(tools, "_assistant_snapshot", by_id)
    result = tools.TOOL_DEFS["assistant_compare"]["fn"]("asm-a", "asm-b")
    assert result["delta_by_level"] == {"Critical": 1}
    assert result["before"]["assessment_id"] == "asm-a"


def test_search_policies_needs_an_index(monkeypatch):
    from common import vector_store
    monkeypatch.setattr(vector_store, "ping", lambda: False)
    with pytest.raises(tools.ToolError, match="not ingested"):
        tools.TOOL_DEFS["assistant_search_policies"]["fn"]("auth")
    monkeypatch.setattr(vector_store, "ping", lambda: True)
    monkeypatch.setattr(vector_store, "index_exists", lambda: True)
    monkeypatch.setattr(vector_store, "search",
                        lambda q, top_k=4: [{"id": "c1"}])
    assert tools.TOOL_DEFS["assistant_search_policies"]["fn"](
        "auth") == [{"id": "c1"}]


def test_inventory_prefers_live_then_snapshot_then_file(monkeypatch):
    from common import kong_inventory
    fn = tools.TOOL_DEFS["assistant_inventory"]["fn"]
    live = [{"service_name": "SvcA", "service_plugins": ["jwt"],
             "service_routes": []}]

    monkeypatch.setattr(kong_inventory, "collect_report",
                        lambda **k: {"inventory": live, "gaps": []})
    monkeypatch.setattr(kong_inventory, "save_snapshot",
                        lambda *a, **k: {"captured_at": "now", "count": 1})
    result = fn()
    assert result["live"] is True and result["count"] == 1

    def down(**kwargs):
        raise RuntimeError("gateway down")

    monkeypatch.setattr(kong_inventory, "collect_report", down)
    monkeypatch.setattr(kong_inventory, "load_snapshot",
                        lambda: ({"inventory": live,
                                  "captured_at": "earlier", "gaps": []},
                                 {"stale": True}))
    result = fn()
    assert result["source"] == "redis_snapshot"
    assert result["live"] is False and result["stale"] is True

    monkeypatch.setattr(kong_inventory, "load_snapshot",
                        lambda: (None, None))
    result = fn()  # ships with the repo as the last resort
    assert result["source"] == "cached_file"
    assert result["count"] > 0

    filtered = fn(service_name="no-such-service")
    assert filtered["count"] == 0


def test_start_assessment_spawns_and_tracks(monkeypatch):
    import time as _time
    from agents import orchestrator
    calls = []

    class FakeApp:
        def get_state(self, _config):
            return types.SimpleNamespace(values={}, tasks=[])

        def invoke(self, state, _config):
            calls.append(state)
            return {"status": "awaiting_approval"}

    monkeypatch.setattr(orchestrator, "get_assessment_app",
                        lambda: FakeApp())
    result = tools.TOOL_DEFS["assistant_start_assessment"]["fn"](
        objective="chat audit", depth="quick")
    assert result["status"] == "running"
    assert result["assessment_id"].startswith("asm-")
    try:
        for _ in range(100):
            if calls:
                break
            _time.sleep(0.05)
        assert calls and calls[0]["depth"] == "quick"
        assert calls[0]["objective"] == "chat audit"
        status = tools.get_assistant_task(result["task_id"])
        assert status["assessment_id"] == result["assessment_id"]
    finally:
        tools._ASSISTANT_TASKS.pop(result["task_id"], None)
        tools._ASSISTANT_ERRORS.pop(result["task_id"], None)


def test_start_assessment_validates_depth():
    with pytest.raises(tools.ToolError, match="depth"):
        tools.TOOL_DEFS["assistant_start_assessment"]["fn"](depth="turbo")


def test_unknown_task_is_not_found():
    with pytest.raises(tools.ToolError, match="No assistant task"):
        tools.get_assistant_task("task-nope")
