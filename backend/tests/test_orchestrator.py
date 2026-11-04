"""Tests for the supervisor-led multi-agent workflow.

The LLM, Kong Admin API and Redis are stubbed throughout; the suite runs
offline with no credentials.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import tools  # noqa: E402
from common import policy  # noqa: E402


def _gateway(agent="discovery", llm_used=0, llm_max=10):
    state = {"budgets": {"llm_calls_used": llm_used, "max_llm_calls": llm_max}}
    record = {"agent": agent, "tool_calls": []}
    return tools.ToolGateway(state, record), state, record


# --- tool gateway ----------------------------------------------------------------

def test_unknown_tool_is_rejected():
    gateway, _, _ = _gateway()
    with pytest.raises(tools.ToolNotPermitted, match="Unknown tool"):
        gateway.call("no_such_tool")


def test_agent_cannot_use_unlisted_tool():
    gateway, _, _ = _gateway(agent="risk")
    with pytest.raises(tools.ToolNotPermitted, match="not permitted"):
        gateway.call("kong_inventory")


def test_permitted_tool_call_is_recorded(monkeypatch):
    monkeypatch.setitem(tools.TOOL_DEFS, "vector_search",
                        {"fn": lambda **k: [{"id": "c1"}], "uses_llm": False})
    gateway, _, record = _gateway(agent="discovery")
    assert gateway.call("vector_search", query="q", top_k=1) == [{"id": "c1"}]
    (entry,) = record["tool_calls"]
    assert entry["tool"] == "vector_search" and entry["ok"] is True
    assert entry["ms"] >= 0


def test_llm_budget_is_enforced(monkeypatch):
    monkeypatch.setitem(tools.TOOL_DEFS, "llm_threat_elaborate",
                        {"fn": lambda **k: [], "uses_llm": True})
    gateway, state, _ = _gateway(agent="threat_model", llm_used=2, llm_max=2)
    with pytest.raises(tools.ToolBudgetExceeded, match="budget exhausted"):
        gateway.call("llm_threat_elaborate", scenarios=[], relations=[],
                     business_context="")
    assert state["budgets"]["llm_calls_used"] == 2


def test_tool_failure_raises_tool_error(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("down")

    monkeypatch.setitem(tools.TOOL_DEFS, "kong_inventory",
                        {"fn": boom, "uses_llm": False})
    gateway, _, record = _gateway(agent="discovery")
    with pytest.raises(tools.ToolError, match="kong_inventory.*down"):
        gateway.call("kong_inventory")
    assert record["tool_calls"][0]["ok"] is False


from agents import orchestrator  # noqa: E402


CHUNK = {
    "id": "embedding:chunk-1",
    "content": "Authentication Policy v1.0: services must enable jwt, oauth2 or key-auth.",
    "source": "01_authentication_policy.txt",
    "metadata": {},
    "score": 0.91,
}

INVENTORY = [
    {"service_name": "SvcA", "service_id": "a",
     "service_plugins": ["key-auth", "rate-limiting"]},
    {"service_name": "SvcB", "service_id": "b", "service_plugins": []},
]

VERDICT = {
    "serviceName": "SvcA",
    "policies": [
        {"policy_name": "Authentication Policy", "comply": False,
         "missing_plugins": ["jwt"], "details": "jwt is required but not enabled."},
        {"policy_name": "Rate Limiting Policy", "comply": True,
         "missing_plugins": [], "details": ""},
    ],
}


def _no_snapshot(**kwargs):
    raise RuntimeError("No cached Kong snapshot in Redis.")


@pytest.fixture
def stub_env(monkeypatch):
    from common import config as _config
    monkeypatch.setattr(_config, "REMEDIATION_BATCH_SIZE", 5)
    monkeypatch.setitem(tools.TOOL_DEFS, "kong_inventory",
                        {"fn": lambda **k: {
                            "inventory": [dict(s) for s in INVENTORY],
                            "gaps": [], "collections": {"services": 2}},
                         "uses_llm": False})
    monkeypatch.setitem(tools.TOOL_DEFS, "kong_snapshot_save",
                        {"fn": lambda **k: {"captured_at": "2026-01-01T00:00:00+00:00",
                                            "count": len(k["inventory"])},
                         "uses_llm": False})
    monkeypatch.setitem(tools.TOOL_DEFS, "kong_snapshot_load",
                        {"fn": _no_snapshot, "uses_llm": False})
    monkeypatch.setitem(tools.TOOL_DEFS, "kong_snapshot_diff",
                        {"fn": lambda **k: None, "uses_llm": False})
    monkeypatch.setitem(tools.TOOL_DEFS, "vector_search",
                        {"fn": lambda **k: [dict(CHUNK)], "uses_llm": False})
    monkeypatch.setitem(
        tools.TOOL_DEFS, "llm_audit_verdict",
        {"fn": lambda **k: {**VERDICT, "serviceName": k["service_name"]},
         "uses_llm": True})
    monkeypatch.setitem(tools.TOOL_DEFS, "llm_explain",
                        {"fn": lambda **k: "Top risk: unauthenticated access.",
                         "uses_llm": True})

    def plan_items(**kwargs):
        return [{
            "serviceName": f["serviceName"],
            "policyName": f["policyName"],
            "issue": f["details"],
            "missingPlugin": ", ".join(f["missingPlugins"]),
            "recommendedAction": "Enable the missing plugin.",
            "severity": f["severity"],
            "owner": "API Gateway Team",
            "estimatedEffort": "2 hours",
            "impact": "Non-compliance.",
            "securityStandardReference": "OWASP API Top 10",
        } for f in kwargs["findings"]]

    monkeypatch.setitem(tools.TOOL_DEFS, "llm_remediation_batch",
                        {"fn": plan_items, "uses_llm": True})
    monkeypatch.setitem(tools.TOOL_DEFS, "llm_correlate",
                        {"fn": lambda **k: "correlated.", "uses_llm": True})
    monkeypatch.setitem(tools.TOOL_DEFS, "kong_consumers",
                        {"fn": lambda **k: [], "uses_llm": False})
    monkeypatch.setitem(tools.TOOL_DEFS, "llm_threat_elaborate",
                        {"fn": lambda **k: [], "uses_llm": True})
    monkeypatch.setitem(tools.TOOL_DEFS, "llm_risk_explain",
                        {"fn": lambda **k: "Top risk: unauthenticated access.",
                         "uses_llm": True})

    def change_prose(**kwargs):
        return [{
            "finding_id": item["finding_id"],
            "rationale": f"Enable {item['plugin']} on {item['service']}.",
            "preconditions": ["maintenance window agreed"],
            "consumer_impact": "clients must authenticate.",
            "breaking_changes": ["unauthenticated calls will fail"],
            "validation_plan": ["call the API with credentials"],
        } for item in kwargs["items"]]

    monkeypatch.setitem(tools.TOOL_DEFS, "llm_change_prose_batch",
                        {"fn": change_prose, "uses_llm": True})

    saved = {}

    def fake_persist(**kwargs):
        saved[kwargs["name"]] = kwargs["payload"]
        return {"path": f"mem:{kwargs['name']}",
                "filename": f"{kwargs['assessment_id']}_{kwargs['name']}.json"}

    monkeypatch.setitem(tools.TOOL_DEFS, "persist_artifact",
                        {"fn": fake_persist, "uses_llm": False})
    return monkeypatch


def _run_graph(input_state):
    """Run the full workflow to completion, auto-approving the governance gate."""
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command
    app = orchestrator.build_assessment_graph(checkpointer=MemorySaver())
    config = {"configurable": {"thread_id": "test-thread"}}
    result = app.invoke(input_state, config)
    while isinstance(result, dict) and "__interrupt__" in result:
        result = app.invoke(
            Command(resume={"decision": "approve", "reviewer": "test"}), config)
    return result


def test_graph_runs_end_to_end(stub_env):
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"],
    })
    assert result["assessment_id"].startswith("asm-")
    assert result["kong_source"] == "kong_admin_api"
    assert len(result["enriched_findings"]) == 4  # 2 services x 2 policies
    assert result["controls"]  # 2 services x 7 controls
    assert any(t["category"] == "Spoofing" for t in result["threats"])
    for name in ("supervisor", "discovery", "security_analysis", "compliance",
                 "threat_model", "aggregate"):
        assert result["agents"][name]["status"] in ("ok", "degraded"), name
    # 2 verdicts + 1 elaboration + 1 remediation batch + 1 correlation
    # + 1 risk explanation + 1 change-prose batch.
    assert result["budgets"]["llm_calls_used"] == 7
    assert result["correlation"] == {"analysis": "correlated."}


def test_investigators_run_in_parallel(stub_env):
    import time as _time
    from datetime import datetime as _dt

    def slow_verdict(**kwargs):
        _time.sleep(0.5)
        return {**VERDICT, "serviceName": kwargs["service_name"]}

    def slow_elaboration(**kwargs):
        _time.sleep(0.5)
        return []

    stub_env.setitem(tools.TOOL_DEFS, "llm_audit_verdict",
                     {"fn": slow_verdict, "uses_llm": True})
    stub_env.setitem(tools.TOOL_DEFS, "llm_threat_elaborate",
                     {"fn": slow_elaboration, "uses_llm": True})

    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"],
    })
    starts, ends = [], []
    for name in ("security_analysis", "threat_model"):
        record = result["agents"][name]
        assert record["status"] == "ok"
        starts.append(_dt.fromisoformat(record["started_at"]))
        ends.append(_dt.fromisoformat(record["finished_at"]))
    # Overlapping wall-clock windows prove parallel branch execution:
    # sequential runs could never start the second before the first finishes.
    assert max(starts) < min(ends)


def test_missing_evidence_quarantines_findings(stub_env):
    stub_env.setitem(tools.TOOL_DEFS, "vector_search",
                     {"fn": lambda **k: [], "uses_llm": False})
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"],
    })
    assert result["enriched_findings"] == []
    assert len(result["quarantined"]) == 4
    assert result["agents"]["discovery"]["status"] == "degraded"
    assert any("quarantined" in r for r in result["degraded_reasons"])


def test_inventory_contradiction_raises_conflict(stub_env):
    stub_env.setitem(
        tools.TOOL_DEFS, "llm_audit_verdict",
        {"fn": lambda **k: {"serviceName": k["service_name"], "policies": [
            {"policy_name": "Authentication Policy", "comply": False,
             "missing_plugins": ["key-auth"], "details": "claims key-auth missing."}]},
         "uses_llm": True})
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"],
    })
    contradictions = [c for c in result["conflicts"]
                      if c["type"] == "inventory_contradiction"]
    assert contradictions  # SvcA enables key-auth, so the claim is disproven
    assert all(c["resolved"] is False for c in contradictions)


def test_compliance_control_outcomes_are_deterministic():
    updates = orchestrator.compliance({
        "kong_data": INVENTORY,
        "budgets": {},
        "max_retries": 0,
    })
    by_service = {}
    for record in updates["controls"]:
        by_service.setdefault(record["service"], {})[record["control"]] = record
    assert by_service["SvcA"]["authentication"]["outcome"] == "partial"
    assert by_service["SvcA"]["rate_limiting"]["outcome"] == "satisfied"
    assert by_service["SvcB"]["authentication"]["outcome"] == "unsatisfied"
    assert updates["agents"]["compliance"]["status"] == "ok"


def test_agent_failure_is_contained(stub_env):
    def boom(**kwargs):
        raise RuntimeError("model down")

    stub_env.setitem(tools.TOOL_DEFS, "llm_audit_verdict",
                     {"fn": boom, "uses_llm": True})
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"], "max_retries": 0,
    })
    assert result["agents"]["security_analysis"]["status"] == "failed"
    # The workflow still completes aggregation with the surviving agents.
    assert result["agents"]["aggregate"]["status"] in ("ok", "degraded")
    assert result["controls"] and result["threats"]
    assert any(e["agent"] == "security_analysis" for e in result["errors"])


def _stub_remediation(monkeypatch):
    def plan_items(**kwargs):
        return [{
            "serviceName": f["serviceName"],
            "policyName": f["policyName"],
            "issue": f["details"],
            "missingPlugin": ", ".join(f["missingPlugins"]),
            "recommendedAction": "Enable the missing plugin.",
            "severity": f["severity"],
            "owner": "API Gateway Team",
            "estimatedEffort": "2 hours",
            "impact": "Non-compliance.",
            "securityStandardReference": "OWASP API Top 10",
        } for f in kwargs["findings"]]

    monkeypatch.setitem(tools.TOOL_DEFS, "llm_remediation_batch",
                        {"fn": plan_items, "uses_llm": True})


def test_pipeline_runs_through_validation(stub_env):
    _stub_remediation(stub_env)
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"],
    })
    register = result["risk"]["register"]
    assert register  # deduplicated entries, highest risk first
    scores = [e["score"] for e in register]
    assert scores == sorted(scores, reverse=True)
    for entry in register:
        assert set(entry["factors"]) == {
            "severity", "exploitability", "exposure",
            "sensitivity", "criticality", "confidence"}
        assert all(f["rationale"] for f in entry["factors"].values())
        assert entry["scoring_model"] == "1.0.0"
        assert entry["state"] == "open"
        assert entry["sources"]
    by_id = {e["entry_id"]: e for e in register}
    assert (by_id["R-SvcB-authentication"]["score"] >
            by_id["R-SvcA-authentication"]["score"])
    assert sum(result["risk"]["by_level"].values()) == len(register)
    assert result["agents"]["risk"]["status"] == "ok"
    assert "unauthenticated" in result["risk"]["explanation"]
    assert len(result["remediation_plan"]) == 2
    assert result["validation"]["passed"] is True
    assert result["agents"]["validation"]["status"] == "ok"


def test_followup_recovers_quarantined_findings(stub_env):
    def selective_search(**kwargs):
        # Discovery finds nothing; the refined followup query succeeds.
        if "Mandatory Kong plugins" in kwargs.get("query", ""):
            return [dict(CHUNK)]
        return []

    stub_env.setitem(tools.TOOL_DEFS, "vector_search",
                     {"fn": selective_search, "uses_llm": False})
    _stub_remediation(stub_env)
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"],
    })
    assert len(result["recovered_findings"]) == 4
    assert result["followups_used"] == 1
    assert result["agents"]["validation"]["status"] == "ok"
    assert result["validation"]["passed"] is True


def test_followup_loop_is_bounded(stub_env):
    stub_env.setitem(tools.TOOL_DEFS, "vector_search",
                     {"fn": lambda **k: [], "uses_llm": False})
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"],
    })
    assert result["followups_used"] == 2  # max_rounds 3 = initial + 2
    assert "followup" in result["agents"]
    assert result["agents"]["validation"]["status"] in ("ok", "degraded")


def test_retry_exhaustion_marks_agent_failed(stub_env):
    def boom(**kwargs):
        raise RuntimeError("model down")

    stub_env.setitem(tools.TOOL_DEFS, "llm_audit_verdict",
                     {"fn": boom, "uses_llm": True})
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"], "max_retries": 2,
    })
    record = result["agents"]["security_analysis"]
    assert record["status"] == "failed"
    assert record["retries"] == 2
    assert "model down" in record["error"]


def test_contradictory_finding_excluded_from_plan(stub_env):
    stub_env.setitem(
        tools.TOOL_DEFS, "llm_audit_verdict",
        {"fn": lambda **k: {"serviceName": k["service_name"], "policies": [
            {"policy_name": "Authentication Policy", "comply": False,
             "missing_plugins": ["key-auth"], "details": "claims key-auth missing."}]},
         "uses_llm": True})
    _stub_remediation(stub_env)
    result = _run_graph({
        "selected_standards": ["OWASP API Top 10"],
    })
    # SvcA enables key-auth (contradicted, excluded); SvcB lacks it (planned).
    assert [e["finding_id"] for e in result["excluded"]] == ["SA-SvcA-0"]
    assert [p["serviceName"] for p in result["remediation_plan"]] == ["SvcB"]
    assert result["validation"]["passed"] is True


def test_agent_timeout_is_recorded():
    import time as _time

    def slow(state, gateway, record):
        _time.sleep(5)
        return {}

    updates = orchestrator.run_agent(
        {"budgets": {}, "max_retries": 0}, "risk", slow, timeout_s=0.05)
    record = updates["agents"]["risk"]
    assert record["timed_out"] is True
    assert record["status"] == "failed"


def _checkpointed_app():
    from langgraph.checkpoint.memory import MemorySaver
    app = orchestrator.build_assessment_graph(checkpointer=MemorySaver())
    return app, {"configurable": {"thread_id": "approval-thread"}}


def test_full_workflow_success_with_approval(stub_env):
    from langgraph.types import Command
    app, config = _checkpointed_app()
    paused = app.invoke({"selected_standards": ["OWASP API Top 10"],
                         "assessment_id": "asm-test-1"}, config)
    (pending,) = paused["__interrupt__"]
    assert pending.value["actions"] == 2
    assert pending.value["assessment_id"] == "asm-test-1"

    final = app.invoke(Command(resume={"decision": "approve",
                                       "reviewer": "sec-lead"}), config)
    assert final["status"] == "complete"
    assert final["approval"]["decision"] == "approve"
    assert final["approval"]["reviewer"] == "sec-lead"
    assert final["assessment_id"] == "asm-test-1"
    for name in ("supervisor", "discovery", "security_analysis", "compliance",
                 "threat_model", "aggregate", "risk", "remediation",
                 "validation", "governance", "finalize"):
        assert final["agents"][name]["status"] in ("ok", "degraded"), name
    assert final["assessment_summary"]["plan_actions"] == 2


def test_approval_rejection_is_recorded(stub_env):
    from langgraph.types import Command
    app, config = _checkpointed_app()
    paused = app.invoke({"selected_standards": ["OWASP API Top 10"]}, config)
    assert "__interrupt__" in paused
    final = app.invoke(Command(resume={"decision": "reject",
                                       "reviewer": "sec-lead",
                                       "note": "Needs stronger auth."}), config)
    assert final["status"] == "complete"
    assert final["approval"]["decision"] == "reject"
    assert final["approval"]["note"] == "Needs stronger auth."
    assert final["assessment_summary"]["approval"] == "reject"


def test_async_assess_completes_via_polling(stub_env):
    import time as _time
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    started = client.post("/api/v1/ai-agents/assess?async=true", json={
        "assessment_id": "api-async-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    assert started.get_json()["status"] == "running"
    body = {}
    for _ in range(100):
        status = client.get("/api/v1/ai-agents/assess/api-async-1")
        assert status.status_code == 200
        body = status.get_json()
        if body["status"] in ("awaiting_approval", "complete", "failed"):
            break
        _time.sleep(0.2)
    assert body["status"] == "awaiting_approval"
    assert body["approval_request"]["actions"] == 2
    resumed = client.post("/api/v1/ai-agents/assess/api-async-1/resume",
                          json={"decision": "approve"})
    assert resumed.status_code == 200
    assert resumed.get_json()["status"] == "complete"


def test_async_failure_is_reported(monkeypatch):
    from agents import init_auditor, orchestrator

    def boom():
        raise RuntimeError("kaput")

    monkeypatch.setattr(orchestrator, "get_assessment_app", boom)
    init_auditor._run_assessment_async(
        "asm-boom", {}, {"configurable": {"thread_id": "x"}})
    assert "asm-boom" not in init_auditor._ASYNC_THREADS
    response = init_auditor.app.test_client().get(
        "/api/v1/ai-agents/assess/asm-boom")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "failed"
    assert "kaput" in body["error"]


def test_resume_while_running_is_rejected(stub_env, monkeypatch):
    import types
    from agents import init_auditor
    monkeypatch.setitem(init_auditor._ASYNC_THREADS, "api-busy-1",
                        types.SimpleNamespace(is_alive=lambda: True))
    response = init_auditor.app.test_client().post(
        "/api/v1/ai-agents/assess/api-busy-1/resume",
        json={"decision": "approve"})
    assert response.status_code == 409


def test_list_and_details_endpoints(stub_env):
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-list-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    listed = client.get("/api/v1/ai-agents/assess")
    assert listed.status_code == 200
    ids = [a["assessment_id"] for a in listed.get_json()["assessments"]]
    assert "api-list-1" in ids
    details = client.get("/api/v1/ai-agents/assess/api-list-1/details")
    assert details.status_code == 200
    state = details.get_json()["state"]
    assert state["agents"]["supervisor"]["status"] == "ok"
    assert state["plan"]["dispatched"]
    missing = client.get("/api/v1/ai-agents/assess/nope/details")
    assert missing.status_code == 404


def test_llm_policy_endpoint():
    from agents.init_auditor import app as flask_app
    response = flask_app.test_client().get("/api/v1/ai-agents/llm/policy")
    assert response.status_code == 200
    body = response.get_json()
    assert body["tasks"]["security_investigation"]["provider"] == "meta"
    assert body["model"]


def test_eval_retrieval_endpoint():
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    response = client.get("/api/v1/ai-agents/eval/retrieval?store=fake")
    assert response.status_code == 200
    body = response.get_json()
    assert body["hit_rate"] == 1.0
    assert body["tasks"] == 10
    bad = client.get("/api/v1/ai-agents/eval/retrieval?store=nope")
    assert bad.status_code == 400


def test_invalid_approval_answer_is_reject(stub_env):
    from langgraph.types import Command
    app, config = _checkpointed_app()
    paused = app.invoke({"selected_standards": ["OWASP API Top 10"]}, config)
    assert "__interrupt__" in paused
    final = app.invoke(Command(resume={"decision": "maybe-later"}), config)
    assert final["approval"]["decision"] == "reject"
    decisions = final["agents"]["governance"]["decisions"]
    assert any(d.get("decision") == "invalid_answer_treated_as_reject"
               for d in decisions)


def test_security_events_reach_audit_log(stub_env, monkeypatch, tmp_path):
    from common import audit_log
    from agents.init_auditor import app as flask_app
    log = str(tmp_path / "audit.log.jsonl")
    monkeypatch.setattr(audit_log, "AUDIT_LOG_FILE", log)
    client = flask_app.test_client()
    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-audit-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    resumed = client.post("/api/v1/ai-agents/assess/api-audit-1/resume",
                          json={"decision": "approve", "reviewer": "lead"})
    assert resumed.status_code == 200
    changes = client.get("/api/v1/ai-agents/assess/api-audit-1/changes")
    change_id = changes.get_json()["change_proposals"][0]["change_id"]
    approved = client.post(
        f"/api/v1/ai-agents/assess/api-audit-1/changes/{change_id}/approve",
        json={"reviewer": "lead"})
    assert approved.status_code == 200
    simulated = client.post(
        f"/api/v1/ai-agents/assess/api-audit-1/changes/{change_id}/execute",
        json={"mode": "simulate"})
    assert simulated.status_code == 200
    events = [json.loads(line)["event"] for line in
              open(log, encoding="utf-8")]
    assert events == ["assessment.started", "assessment.resumed",
                      "change.approved", "change.simulated"]
    assert audit_log.verify()["ok"] is True


def test_refused_execution_is_audited(stub_env, monkeypatch, tmp_path):
    from common import audit_log
    from agents.init_auditor import app as flask_app
    log = str(tmp_path / "audit.log.jsonl")
    monkeypatch.setattr(audit_log, "AUDIT_LOG_FILE", log)
    client = flask_app.test_client()
    client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-audit-2",
        "selected_standards": ["OWASP API Top 10"],
    })
    client.post("/api/v1/ai-agents/assess/api-audit-2/resume",
                json={"decision": "approve"})
    changes = client.get("/api/v1/ai-agents/assess/api-audit-2/changes")
    change_id = changes.get_json()["change_proposals"][0]["change_id"]
    denied = client.post(
        f"/api/v1/ai-agents/assess/api-audit-2/changes/{change_id}/execute",
        json={"mode": "live"})
    assert denied.status_code in (403, 409)  # unapproved and/or disabled
    entries = [json.loads(line) for line in open(log, encoding="utf-8")]
    refused = [e for e in entries if e["event"] == "change.execution_refused"]
    assert len(refused) == 1
    assert refused[0]["details"]["change_id"] == change_id


def test_workflow_resume_preserves_state(stub_env):
    from langgraph.types import Command
    app, config = _checkpointed_app()
    app.invoke({"selected_standards": ["OWASP API Top 10"],
                "assessment_id": "asm-test-2"}, config)
    snapshot = app.get_state(config)
    assert snapshot.values["assessment_id"] == "asm-test-2"
    assert len(snapshot.values["enriched_findings"]) == 4
    final = app.invoke(Command(resume={"decision": "approve"}), config)
    assert final["assessment_id"] == "asm-test-2"
    assert final["status"] == "complete"
    assert len(final["enriched_findings"]) == 4


def test_governance_skips_interrupt_when_plan_empty(stub_env):
    stub_env.setitem(
        tools.TOOL_DEFS, "llm_audit_verdict",
        {"fn": lambda **k: {"serviceName": k["service_name"], "policies": [
            {"policy_name": "Rate Limiting Policy", "comply": True,
             "missing_plugins": [], "details": ""}]},
         "uses_llm": True})
    from langgraph.checkpoint.memory import MemorySaver
    app = orchestrator.build_assessment_graph(checkpointer=MemorySaver())
    result = app.invoke({"selected_standards": ["OWASP API Top 10"]},
                        {"configurable": {"thread_id": "empty-thread"}})
    assert "__interrupt__" not in result
    assert result["approval"]["decision"] == "nothing_to_approve"
    assert result["status"] == "complete"


def test_assess_api_pauses_and_resumes(stub_env):
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()

    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-test-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    assert started.get_json()["approval_request"]["actions"] == 2

    status = client.get("/api/v1/ai-agents/assess/api-test-1")
    assert status.get_json()["status"] == "awaiting_approval"

    resumed = client.post("/api/v1/ai-agents/assess/api-test-1/resume", json={
        "decision": "approve", "reviewer": "sec-lead"})
    assert resumed.status_code == 200
    body = resumed.get_json()
    assert body["status"] == "complete"
    assert body["summary"]["plan_actions"] == 2


def test_assess_status_unknown_id_returns_404(stub_env):
    from agents.init_auditor import app as flask_app
    response = flask_app.test_client().get(
        "/api/v1/ai-agents/assess/does-not-exist")
    assert response.status_code == 404


def test_remediation_builds_simulated_change_proposals(stub_env):
    entry = {"entry_id": "R-Svc-authentication", "service": "Svc",
             "severity": "High", "confidence": "high",
             "sources": [{"finding_id": "F-high", "stream": "llm"}]}
    updates = orchestrator.remediation({
        "assessment_id": "asm-1",
        "enriched_findings": [{
            "finding_id": "F-high", "service": "Svc",
            "policy_name": "Authentication Policy", "comply": False,
            "missing_plugins": ["jwt"], "details": "jwt missing.",
            "evidence_ids": ["c1"], "tier": "suspected",
            "verification": {"status": "verified", "confidence": "high"}}],
        "recovered_findings": [],
        "risk": {"register": [entry]},
        "policy_context": {},
        "kong_data": [{"service_name": "Svc", "service_id": "s",
                       "service_plugins": ["key-auth"], "service_routes": []}],
        "plan": {"evidence_requirements": {"min_confidence_for_action": "high"}},
        "budgets": {},
        "max_retries": 0,
    })
    (proposal,) = updates["change_proposals"]
    assert proposal["change_id"] == "CH-svc-enable_plugin-jwt"
    assert proposal["target"] == {"kind": "service", "service": "Svc"}
    assert proposal["diff"][0]["added"] == ["jwt"]
    assert proposal["rationale"].startswith("Enable jwt on Svc.")
    assert proposal["rollback"]["op"] == "remove_plugin"
    assert proposal["simulation"]["mode"] == "simulate"
    assert (proposal["residual_risk"]["after"] <
            proposal["residual_risk"]["before"])
    assert updates["agents"]["remediation"]["status"] == "ok"


def test_change_prose_failure_keeps_plan(stub_env):
    def boom(**kwargs):
        raise RuntimeError("model down")

    stub_env.setitem(tools.TOOL_DEFS, "llm_change_prose_batch",
                     {"fn": boom, "uses_llm": True})
    updates = orchestrator.remediation({
        "enriched_findings": [{
            "finding_id": "F-high", "service": "Svc",
            "policy_name": "Authentication Policy", "comply": False,
            "missing_plugins": ["jwt"], "details": "jwt missing.",
            "evidence_ids": ["c1"], "tier": "suspected",
            "verification": {"status": "verified", "confidence": "high"}}],
        "recovered_findings": [],
        "risk": {"register": []},
        "policy_context": {},
        "kong_data": [{"service_name": "Svc", "service_plugins": []}],
        "plan": {"evidence_requirements": {"min_confidence_for_action": "high"}},
        "budgets": {},
        "max_retries": 0,
    })
    assert len(updates["remediation_plan"]) == 1  # plan survives
    assert updates["change_proposals"] == []
    assert any("change prose failed" in e["error"]
               for e in updates["errors"])
    assert updates["agents"]["remediation"]["status"] == "degraded"


def test_change_approval_and_execute_endpoints(stub_env, monkeypatch):
    from common import config as _config
    from agents.init_auditor import app as flask_app
    monkeypatch.setattr(_config, "KONG_WRITE_ENABLED", False)
    client = flask_app.test_client()
    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-change-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    resumed = client.post("/api/v1/ai-agents/assess/api-change-1/resume",
                          json={"decision": "approve"})
    assert resumed.status_code == 200

    listed = client.get("/api/v1/ai-agents/assess/api-change-1/changes")
    assert listed.status_code == 200
    proposals = listed.get_json()["change_proposals"]
    assert len(proposals) == 2
    first, second = proposals[0]["change_id"], proposals[1]["change_id"]

    simulated = client.post(
        f"/api/v1/ai-agents/assess/api-change-1/changes/{first}/execute",
        json={"mode": "simulate"})
    assert simulated.status_code == 200
    body = simulated.get_json()
    assert body["simulation"]["mode"] == "simulate"
    assert "no live gateway resources" in body["simulation"]["note"]

    denied = client.post(
        f"/api/v1/ai-agents/assess/api-change-1/changes/{second}/execute",
        json={"mode": "live"})
    assert denied.status_code == 403  # no approval recorded
    assert denied.get_json()["proposal"]["status"] == "failed"

    anonymous = client.post(
        f"/api/v1/ai-agents/assess/api-change-1/changes/{first}/approve",
        json={})
    assert anonymous.status_code == 400  # reviewer required

    approved = client.post(
        f"/api/v1/ai-agents/assess/api-change-1/changes/{first}/approve",
        json={"reviewer": "sec-lead"})
    assert approved.status_code == 200
    assert approved.get_json()["proposal"]["status"] == "approved"

    disabled = client.post(
        f"/api/v1/ai-agents/assess/api-change-1/changes/{first}/execute",
        json={"mode": "live"})
    assert disabled.status_code == 409  # writes not enabled
    assert "KONG_WRITE_ENABLED" in disabled.get_json()["error"]

    missing = client.get("/api/v1/ai-agents/assess/nope/changes")
    assert missing.status_code == 404


def test_risk_transition_endpoint_moves_entry_lifecycle(stub_env):
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-risk-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    resumed = client.post("/api/v1/ai-agents/assess/api-risk-1/resume",
                          json={"decision": "approve"})
    assert resumed.status_code == 200

    status = client.get("/api/v1/ai-agents/assess/api-risk-1")
    register = status.get_json()["risk_register"]
    assert register["scoring_model"] == "1.0.0"
    entry_id = register["entries"][0]["entry_id"]
    assert register["entries"][0]["state"] == "open"

    moved = client.post(
        f"/api/v1/ai-agents/assess/api-risk-1/risk/{entry_id}/transition",
        json={"to_state": "accepted", "actor": "ciso", "note": "accepted Q4"})
    assert moved.status_code == 200
    body = moved.get_json()
    assert body["entry"]["state"] == "accepted"
    assert body["entry"]["state_history"][0]["actor"] == "ciso"
    assert body["summary"]["by_state"]["accepted"] == 1

    again = client.get("/api/v1/ai-agents/assess/api-risk-1")
    states = {e["entry_id"]: e["state"]
              for e in again.get_json()["risk_register"]["entries"]}
    assert states[entry_id] == "accepted"  # persisted via checkpointer

    illegal = client.post(
        f"/api/v1/ai-agents/assess/api-risk-1/risk/{entry_id}/transition",
        json={"to_state": "accepted"})
    assert illegal.status_code == 400  # accepted -> accepted is not allowed

    missing = client.post(
        "/api/v1/ai-agents/assess/api-risk-1/risk/R-nope/transition",
        json={"to_state": "accepted"})
    assert missing.status_code == 404
    unknown = client.post(
        "/api/v1/ai-agents/assess/nope/risk/R-nope/transition",
        json={"to_state": "accepted"})
    assert unknown.status_code == 404


def test_assessment_id_is_sanitized_for_paths():
    assert tools.safe_assessment_id("../../etc/x") == "etcx"
    assert tools.safe_assessment_id("asm-ok_1") == "asm-ok_1"
    assert tools.safe_assessment_id("!!!") == "assessment"
    assert len(tools.safe_assessment_id("a" * 100)) == 64


def test_least_privilege_tool_contracts():
    for agent in ("supervisor", "compliance", "risk"):
        gateway, _, _ = _gateway(agent=agent)
        with pytest.raises(tools.ToolNotPermitted):
            gateway.call("vector_search", query="q")
    gateway, _, _ = _gateway(agent="security_analysis")
    with pytest.raises(tools.ToolNotPermitted, match="not permitted"):
        gateway.call("llm_explain", system_prompt="s", user_prompt="u")


def test_followup_correlates_unresolved_conflicts(stub_env):
    calls = []
    stub_env.setitem(tools.TOOL_DEFS, "llm_correlate",
                     {"fn": lambda **k: calls.append(k) or "analysis text",
                      "uses_llm": True})
    updates = orchestrator.followup({
        "conflicts": [{"conflict_id": "CF-1", "type": "verdict_disagreement",
                       "finding_id": "F-1", "service": "Svc",
                       "detail": "disagree", "resolved": False}],
        "conflict_resolutions": [],
        "quarantined": [],
        "policy_context": {},
        "selected_standards": [],
        "budgets": {},
        "max_retries": 0,
    })
    assert updates["correlation"] == {"analysis": "analysis text"}
    assert len(calls) == 1
    assert updates["agents"]["followup"]["status"] == "ok"


def test_followup_skips_correlation_when_resolved(stub_env):
    calls = []
    stub_env.setitem(tools.TOOL_DEFS, "llm_correlate",
                     {"fn": lambda **k: calls.append(k) or "x",
                      "uses_llm": True})
    updates = orchestrator.followup({
        "conflicts": [{"conflict_id": "CF-1",
                       "type": "inventory_contradiction",
                       "finding_id": "F-1", "service": "Svc",
                       "detail": "disproven", "resolved": False}],
        "conflict_resolutions": [],
        "quarantined": [],
        "policy_context": {},
        "selected_standards": [],
        "budgets": {},
        "max_retries": 0,
    })
    assert updates["correlation"] == {"analysis": ""}
    assert calls == []


def test_executive_summary_endpoint(stub_env, monkeypatch):
    from common import router as model_router
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-exec-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    resumed = client.post("/api/v1/ai-agents/assess/api-exec-1/resume",
                          json={"decision": "approve"})
    assert resumed.status_code == 200

    def fake_run(task, messages, **kwargs):
        return model_router.ModelResponse(
            provider="meta", model="muse-spark-1.3", task=task,
            text=f"{task} narrative.")

    monkeypatch.setattr(model_router, "run", fake_run)
    response = client.post("/api/v1/ai-agents/assess/api-exec-1/executive-summary")
    assert response.status_code == 200
    body = response.get_json()
    assert body["risk_narrative"] == "risk_reasoning narrative."
    assert body["executive_summary"] == "executive_explanation narrative."
    assert [c["task"] for c in body["calls"]] == ["risk_reasoning",
                                                 "executive_explanation"]
    assert all(c["model"] == "muse-spark-1.3" for c in body["calls"])


def test_executive_summary_requires_completed_assessment(stub_env):
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    missing = client.post("/api/v1/ai-agents/assess/nope/executive-summary")
    assert missing.status_code == 404
    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-exec-pending",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202  # paused at the gate, not complete
    pending = client.post(
        "/api/v1/ai-agents/assess/api-exec-pending/executive-summary")
    assert pending.status_code == 409


def test_llm_calls_endpoint_lists_records(stub_env, monkeypatch):
    from common import router as model_router
    from agents.init_auditor import app as flask_app
    model_router.clear_call_log()
    monkeypatch.setattr(
        model_router.get_router(), "transport",
        lambda *a, **k: ('{"ok": true}', {"total_tokens": 7}))
    model_router.run(model_router.RISK_REASONING,
                     [{"role": "user", "content": "hi"}])
    response = flask_app.test_client().get("/api/v1/ai-agents/llm/calls?limit=10")
    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] >= 1
    assert body["calls"][-1]["task"] == "risk_reasoning"
    assert body["calls"][-1]["usage"] == {"total_tokens": 7}


def test_validation_flags_tampered_verification():
    finding = {
        "finding_id": "SA-Svc-0",
        "service": "Svc",
        "service_plugins": ["jwt"],
        "policy_name": "Authentication Policy",
        "comply": False,
        "missing_plugins": ["jwt"],
        "details": "claims jwt missing",
        "evidence_ids": ["c1"],
        # Tampered: jwt is enabled, so the true status is contradictory.
        "verification": {"status": "verified", "confidence": "high"},
    }
    updates = orchestrator.validation({
        "enriched_findings": [finding],
        "recovered_findings": [],
        "remediation_plan": [],
        "excluded": [],
        "policy_context": {"Svc": []},
        "selected_standards": [],
        "budgets": {},
        "max_retries": 0,
    })
    assert updates["validation"]["passed"] is False
    assert len(updates["validation"]["mismatches"]) == 1


def test_threat_objective_dispatches_threat_only(stub_env):
    result = _run_graph({"objective": "threat model the estate for STRIDE attacks"})
    assert result["plan"]["investigators"] == ["threat_model"]
    assert "threat_model" in result["agents"]
    assert "compliance" not in result["agents"]
    assert "security_analysis" not in result["agents"]
    assert result["status"] == "complete"


def test_compliance_objective_dispatches_compliance_only(stub_env):
    result = _run_graph({"objective": "check GDPR compliance controls"})
    assert result["plan"]["investigators"] == ["compliance"]
    assert "compliance" in result["agents"]
    assert "threat_model" not in result["agents"]
    assert "security_analysis" not in result["agents"]


def test_compound_objective_dispatches_subset(stub_env):
    result = _run_graph(
        {"objective": "review authentication findings and assess the threat of abuse"})
    assert result["plan"]["investigators"] == ["security_analysis", "threat_model"]
    assert "compliance" not in result["agents"]


def test_unstated_objective_runs_full_coverage(stub_env):
    result = _run_graph({"selected_standards": ["OWASP API Top 10"]})
    assert result["plan"]["investigators"] == ["security_analysis", "compliance",
                                              "threat_model"]
    assert "no specific focus" in " ".join(result["plan"]["rationale"])


def test_depth_preset_applies_budgets():
    quick = orchestrator.supervisor_plan({"depth": "quick"})
    assert quick["budgets"]["max_rounds"] == 1
    assert quick["budgets"]["max_llm_calls"] == 20
    assert quick["plan"]["depth"] == "quick"
    deep = orchestrator.supervisor_plan({"depth": "deep"})
    assert deep["budgets"]["max_rounds"] == 5
    invalid = orchestrator.supervisor_plan({"depth": "turbo"})
    assert invalid["plan"]["depth"] == "standard"
    assert invalid["budgets"]["max_rounds"] == 3


def test_empty_inventory_skips_investigators(stub_env):
    stub_env.setitem(tools.TOOL_DEFS, "kong_inventory",
                     {"fn": lambda **k: {"inventory": [], "gaps": [],
                                         "collections": {}},
                      "uses_llm": False})
    result = _run_graph({"selected_standards": ["OWASP API Top 10"]})
    assert result["plan"]["dispatched"] == []
    assert "security_analysis" not in result["agents"]
    assert "aggregate" in result["agents"]
    assert result["status"] == "complete"


def test_tiers_distinguish_evidence_strength(stub_env):
    result = _run_graph({"selected_standards": ["OWASP API Top 10"]})
    tiers = result["tiers"]
    # SvcB: grounded verdict + unsatisfied auth control -> confirmed gap.
    assert "SA-SvcB-0" in [f["finding_id"] for f in tiers["confirmed"]]
    # SvcA: grounded verdict, but key-auth weakens the control signal.
    suspected_ids = [f["finding_id"] for f in tiers["suspected"]]
    assert "SA-SvcA-0" in suspected_ids
    assert any("-PF-" in fid for fid in suspected_ids)  # policy findings join in
    assert len(tiers["informational"]) == 2  # the comply verdicts
    assert tiers["unverified"] == []


def test_ungrounded_claim_never_leaves_unverified():
    updates = orchestrator.aggregate({
        "findings": [{
            "finding_id": "SA-X-0", "service": "SvcX",
            "service_plugins": ["key-auth"],
            "policy_name": "Authentication Policy", "comply": False,
            "missing_plugins": ["jwt"],  # truly absent from the inventory
            "details": "jwt missing.", "evidence_ids": [],
        }],
        "controls": [],
        "threats": [],
        "policy_context": {},
        "selected_standards": [],
        "budgets": {},
        "agents": {},
        "max_retries": 0,
    })
    assert updates["enriched_findings"] == []
    assert len(updates["quarantined"]) == 1
    assert "evidence" in updates["quarantined"][0]["quarantine_reason"]


def test_remediation_min_confidence_gate(stub_env):
    def finding(fid, tier, confidence):
        return {"finding_id": fid, "service": "Svc", "tier": tier,
                "service_plugins": ["key-auth"],
                "policy_name": "Authentication Policy", "comply": False,
                "missing_plugins": ["jwt"], "details": "jwt missing.",
                "verification": {"status": "verified", "confidence": confidence}}

    updates = orchestrator.remediation({
        "enriched_findings": [finding("F-high", "suspected", "high"),
                              finding("F-med", "suspected", "medium"),
                              finding("F-unv", "unverified", "low")],
        "recovered_findings": [],
        "risk": {"register": []},
        "policy_context": {},
        "plan": {"evidence_requirements": {"min_confidence_for_action": "high"}},
        "budgets": {},
        "max_retries": 0,
    })
    assert len(updates["remediation_plan"]) == 1  # F-high only
    assert updates["agents"]["remediation"]["status"] == "ok"
    reasons = {e["finding_id"]: e["reason"] for e in updates["excluded"]}
    assert "below the minimum" in reasons["F-med"]
    assert "not actionable" in reasons["F-unv"]
    assert "F-high" not in reasons


def test_risk_priority_boost(monkeypatch):
    monkeypatch.setitem(tools.TOOL_DEFS, "llm_risk_explain",
                        {"fn": lambda **k: "priority service is riskiest.",
                         "uses_llm": True})
    updates = orchestrator.risk({
        "enriched_findings": [{
            "finding_id": "F-1", "service": "SvcP",
            "policy_name": "Rate Limiting Policy", "comply": False,
            "missing_plugins": ["rate-limiting"], "details": "no limits.",
            "evidence_ids": ["c1"], "severity": "High",
            "tier": "suspected",
            "verification": {"status": "verified", "confidence": "high"}}],
        "recovered_findings": [],
        "policy_findings": [],
        "kong_data": [{"service_name": "SvcP", "service_plugins": [],
                       "service_routes": [{"paths": ["/pay"], "methods": ["POST"]}]}],
        "controls": [],
        "priority_services": ["SvcP"],
        "budgets": {},
        "max_retries": 0,
    })
    (entry,) = updates["risk"]["register"]
    # base .3*7.5 + .2*9 + .15*8 + .15*8 + .2*9 = 8.25, blend .92
    assert entry["score"] == 7.6
    assert entry["level"] == "High"
    assert entry["factors"]["criticality"] == {
        "score": 9.0, "rationale": "priority service"}
    assert updates["risk"]["explanation"] == "priority service is riskiest."
    assert updates["agents"]["risk"]["status"] == "ok"


def test_risk_accepts_scoring_overrides(monkeypatch):
    monkeypatch.setitem(tools.TOOL_DEFS, "llm_risk_explain",
                        {"fn": lambda **k: "ok.", "uses_llm": True})
    base = {
        "enriched_findings": [{
            "finding_id": "F-1", "service": "SvcP",
            "policy_name": "Rate Limiting Policy", "comply": False,
            "missing_plugins": ["rate-limiting"], "details": "no limits.",
            "evidence_ids": ["c1"], "severity": "High",
            "tier": "suspected",
            "verification": {"status": "verified", "confidence": "high"}}],
        "recovered_findings": [],
        "policy_findings": [],
        "kong_data": [{"service_name": "SvcP", "service_plugins": []}],
        "controls": [],
        "budgets": {},
        "max_retries": 0,
    }
    default = orchestrator.risk(dict(base))["risk"]["register"][0]["score"]
    tuned = orchestrator.risk({**base, "risk_scoring": {
        "weights": {"severity": 1.0, "exploitability": 0.0,
                    "exposure": 0.0, "sensitivity": 0.0,
                    "criticality": 0.0}}})["risk"]["register"][0]["score"]
    assert tuned != default
    assert tuned == round(7.5 * 0.92, 1)


def test_risk_explanation_failure_degrades_gracefully(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("model down")

    monkeypatch.setitem(tools.TOOL_DEFS, "llm_risk_explain",
                        {"fn": boom, "uses_llm": True})
    updates = orchestrator.risk({
        "enriched_findings": [{
            "finding_id": "F-1", "service": "SvcP",
            "policy_name": "Rate Limiting Policy", "comply": False,
            "missing_plugins": ["rate-limiting"], "details": "no limits.",
            "evidence_ids": ["c1"], "severity": "High",
            "tier": "suspected",
            "verification": {"status": "verified", "confidence": "high"}}],
        "recovered_findings": [],
        "policy_findings": [],
        "kong_data": [{"service_name": "SvcP", "service_plugins": []}],
        "controls": [],
        "budgets": {},
        "max_retries": 0,
    })
    assert len(updates["risk"]["register"]) == 1  # register survives
    assert updates["risk"]["explanation"] is None
    assert updates["agents"]["risk"]["status"] == "degraded"


def test_risk_merges_cross_stream_duplicates(monkeypatch):
    monkeypatch.setitem(tools.TOOL_DEFS, "llm_risk_explain",
                        {"fn": lambda **k: "auth gap.", "uses_llm": True})
    updates = orchestrator.risk({
        "enriched_findings": [{
            "finding_id": "SA-SvcA-0", "service": "SvcA",
            "policy_name": "Authentication Policy", "comply": False,
            "missing_plugins": ["jwt"], "details": "jwt missing.",
            "evidence_ids": ["c1"], "severity": "High",
            "tier": "suspected",
            "verification": {"status": "verified", "confidence": "high"}}],
        "recovered_findings": [],
        "policy_findings": [{
            "finding_id": "PF-1",
            "affected_api": {"api": "SvcA"},
            "category": "owasp", "severity": "Critical",
            "confidence": "high", "evidence": [],
            "applicable_standard": {"standard": "OWASP",
                                    "control": "OWASP-API2 v1.0",
                                    "catalog_version": "1.0.0"},
            "tier": "suspected"}],
        "kong_data": [{"service_name": "SvcA",
                       "service_plugins": ["key-auth"]}],
        "controls": [],
        "budgets": {},
        "max_retries": 0,
    })
    (entry,) = updates["risk"]["register"]
    assert sorted(s["stream"] for s in entry["sources"]) == ["llm", "policy"]
    assert entry["severity"] == "Critical"  # highest wins, conflict noted
    assert entry["severity_conflicts"]


def _stopping_state(**overrides):
    state = {
        "followups_used": 0,
        "budgets": {"max_rounds": 3, "max_llm_calls": 60, "llm_calls_used": 2,
                    "max_tool_calls": 200, "tool_calls_used": 5,
                    "max_duration_s": 600},
        "started_at": "2999-01-01T00:00:00+00:00",
        "conflicts": [{"conflict_id": "CF-1"}],
        "conflict_resolutions": [],
        "quarantined": [],
        "recovered_findings": [],
        "policy_context": {"Svc": [{"id": "c1"}]},
        "plan": {"evidence_requirements": {"min_chunks_per_service": 1}},
    }
    state.update(overrides)
    return state


def test_evaluate_continues_on_gaps_within_budget():
    decision, assessment = orchestrator.evaluate_stopping(_stopping_state())
    assert decision == "followup"
    assert assessment["gaps"]["open_conflicts"] == ["CF-1"]
    assert assessment["rounds_used"] == 1


def test_evaluate_stops_on_max_rounds():
    decision, assessment = orchestrator.evaluate_stopping(
        _stopping_state(followups_used=2))
    assert decision == "risk"
    assert any("max_rounds" in r for r in assessment["reasons"])


def test_evaluate_stops_on_duration():
    decision, assessment = orchestrator.evaluate_stopping(
        _stopping_state(started_at="2000-01-01T00:00:00+00:00"))
    assert decision == "risk"
    assert any("max_duration_s" in r for r in assessment["reasons"])


def test_evaluate_stops_on_tool_budget():
    state = _stopping_state()
    state["budgets"]["tool_calls_used"] = 200
    decision, assessment = orchestrator.evaluate_stopping(state)
    assert decision == "risk"
    assert any("max_tool_calls" in r for r in assessment["reasons"])


def test_evaluate_proceeds_when_no_gaps():
    decision, assessment = orchestrator.evaluate_stopping(_stopping_state(
        conflicts=[], quarantined=[]))
    assert decision == "risk"
    assert assessment["reasons"] == ["no gaps; evidence sufficient"]


def test_tool_budget_is_enforced():
    gateway, _, _ = _gateway(agent="discovery")
    gateway.state["budgets"] = {"max_tool_calls": 1, "tool_calls_used": 1,
                                "max_llm_calls": 10, "llm_calls_used": 0}
    with pytest.raises(tools.ToolBudgetExceeded, match="Tool budget exhausted"):
        gateway.call("kong_fallback")


def test_consolidated_summary_explains_assessment(stub_env):
    result = _run_graph({"objective": "audit authentication findings",
                         "selected_standards": ["OWASP API Top 10"]})
    summary = result["assessment_summary"]
    assert summary["objective"] == "audit authentication findings"
    assert summary["depth"] == "standard"
    assert summary["plan_rationale"]
    assert summary["tiers"]["confirmed"] == 1
    assert summary["tiers"]["informational"] == 2
    assert summary["tiers"]["unverified"] == 0
    assert summary["tiers"]["suspected"] >= 2  # LLM + policy findings
    assert summary["stopping"]["decision"] == "risk"
    assert summary["stopping"]["rounds_used"] >= 1


def test_compliance_produces_policy_findings(stub_env):
    updates = orchestrator.compliance({
        "kong_data": INVENTORY,
        "policy_context": {"SvcA": [dict(CHUNK)], "SvcB": [dict(CHUNK)]},
        "evidence_retrieved_at": "2026-01-01T00:00:00+00:00",
        "assessment_id": "asm-x",
        "budgets": {},
        "max_retries": 0,
    })
    assert len(updates["control_results"]) == 2 * 27
    assert updates["coverage"]["catalog_version"] == "1.0.0"
    assert updates["coverage"]["totals"]["total"] == 54
    not_evaluable = [g for g in updates["coverage"]["gaps"]
                     if g["outcome"] == "not_evaluable"]
    assert any(g["control_id"] == "TLS-01" for g in not_evaluable)
    assert all("Required evidence" in g["reason"] for g in not_evaluable)
    findings = updates["policy_findings"]
    assert findings
    assert all(set(policy.FINDING_REQUIRED) <= set(f) for f in findings)
    assert all(f["finding_id"].startswith("asm-x-PF-") for f in findings)
    assert all(f["tier"] == "suspected" for f in findings)


def test_graph_reports_coverage_and_gaps(stub_env):
    result = _run_graph({"selected_standards": ["OWASP API Top 10"]})
    summary = result["assessment_summary"]
    assert summary["coverage"]["totals"]["total"] == 54
    assert summary["coverage"]["gaps"]
    assert summary["policy_findings"] == len(result["policy_findings"])
    assert summary["policy_findings"] > 0
    finding = result["policy_findings"][0]
    assert set(policy.FINDING_REQUIRED) <= set(finding)
    assert finding["evidence_freshness"]["stale"] is False


def test_discovery_collects_consumers(stub_env):
    stub_env.setitem(tools.TOOL_DEFS, "kong_consumers",
                     {"fn": lambda **k: [{"id": "c1", "username": "app"}],
                      "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_consumers"] == [{"id": "c1", "username": "app"}]
    assert updates["agents"]["discovery"]["status"] == "ok"


def test_assess_rejects_id_reuse(stub_env):
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    first = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-reuse-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert first.status_code == 202
    again = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-reuse-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert again.status_code == 409


def test_resume_and_approve_cap_free_text(stub_env):
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-cap-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    long_resume = client.post(
        "/api/v1/ai-agents/assess/api-cap-1/resume",
        json={"decision": "approve", "note": "x" * 2001})
    assert long_resume.status_code == 400
    resumed = client.post("/api/v1/ai-agents/assess/api-cap-1/resume",
                          json={"decision": "approve"})
    assert resumed.status_code == 200
    changes = client.get("/api/v1/ai-agents/assess/api-cap-1/changes")
    change_id = changes.get_json()["change_proposals"][0]["change_id"]
    long_review = client.post(
        f"/api/v1/ai-agents/assess/api-cap-1/changes/{change_id}/approve",
        json={"reviewer": "r" * 129})
    assert long_review.status_code == 400


def test_discovery_flags_insufficient_retrieval(stub_env):
    stub_env.setitem(tools.TOOL_DEFS, "vector_search",
                     {"fn": lambda **k: [], "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert any("Retrieval insufficient for SvcA" in w
               for w in updates["warnings"])
    decisions = updates["agents"]["discovery"]["decisions"]
    assert any(d.get("decision") == "retrieval_insufficient"
               for d in decisions)


def test_discovery_marks_live_provenance(stub_env):
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_source"] == "kong_admin_api"
    assert updates["kong_live"] is True
    assert updates["kong_stale"] is False
    assert updates["kong_snapshot_at"] == "2026-01-01T00:00:00+00:00"
    assert updates["kong_gaps"] == []
    assert updates["kong_capabilities"] == {
        "services": True, "routes": True, "plugins": True,
        "consumers": True}
    assert updates["agents"]["discovery"]["status"] == "ok"


def test_discovery_uses_redis_snapshot_on_outage(stub_env):
    def boom(**kwargs):
        raise RuntimeError("connection refused")

    stub_env.setitem(tools.TOOL_DEFS, "kong_inventory",
                     {"fn": boom, "uses_llm": False})
    snapshot = {"captured_at": "2026-01-01T00:00:00+00:00",
                "inventory": [dict(s) for s in INVENTORY], "gaps": []}
    stub_env.setitem(tools.TOOL_DEFS, "kong_snapshot_load",
                     {"fn": lambda **k: {"snapshot": snapshot,
                                         "freshness": {"stale": False}},
                      "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_source"] == "redis_snapshot"
    assert updates["kong_live"] is False
    assert updates["kong_stale"] is False
    assert len(updates["kong_data"]) == 2
    assert updates["agents"]["discovery"]["status"] == "degraded"
    assert any("not a live assessment" in r
               for r in updates.get("degraded_reasons", []))


def test_discovery_flags_stale_snapshot(stub_env):
    def boom(**kwargs):
        raise RuntimeError("connection refused")

    stub_env.setitem(tools.TOOL_DEFS, "kong_inventory",
                     {"fn": boom, "uses_llm": False})
    snapshot = {"captured_at": "2000-01-01T00:00:00+00:00",
                "inventory": [dict(s) for s in INVENTORY], "gaps": []}
    stub_env.setitem(tools.TOOL_DEFS, "kong_snapshot_load",
                     {"fn": lambda **k: {"snapshot": snapshot,
                                         "freshness": {"stale": True}},
                      "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_stale"] is True
    assert any("stale: True" in w for w in updates["warnings"])


def test_discovery_falls_back_to_file_without_snapshot(stub_env, monkeypatch):
    from common import config as _config
    monkeypatch.setattr(_config, "KONG_ADMIN_API", "https://kong.example")
    monkeypatch.setattr(_config, "KONG_ADMIN_TOKEN", "tok")

    def boom(**kwargs):
        raise RuntimeError("connection refused")

    stub_env.setitem(tools.TOOL_DEFS, "kong_inventory",
                     {"fn": boom, "uses_llm": False})
    stub_env.setitem(tools.TOOL_DEFS, "kong_fallback",
                     {"fn": lambda **k: [dict(s) for s in INVENTORY],
                      "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_source"] == "cached_file"
    assert updates["kong_live"] is False
    assert updates["kong_stale"] is True  # unknown age: never fresh
    assert any("unknown age" in w for w in updates["warnings"])


def test_discovery_reports_partial_collection_gaps(stub_env):
    stub_env.setitem(tools.TOOL_DEFS, "kong_inventory",
                     {"fn": lambda **k: {
                         "inventory": [dict(s) for s in INVENTORY],
                         "gaps": [{"collection": "routes",
                                   "error": "HTTP 500"}],
                         "collections": {"services": 2}},
                      "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_live"] is True
    assert updates["kong_gaps"] == [{"collection": "routes",
                                     "error": "HTTP 500"}]
    assert updates["kong_capabilities"]["routes"] is False
    assert any("partial" in w for w in updates["warnings"])


def test_discovery_records_capabilities_and_changes(stub_env):
    def boom(**kwargs):
        raise RuntimeError("no consumers here")

    stub_env.setitem(tools.TOOL_DEFS, "kong_consumers",
                     {"fn": boom, "uses_llm": False})
    stub_env.setitem(tools.TOOL_DEFS, "kong_snapshot_diff",
                     {"fn": lambda **k: {"services_added": ["svc-new"],
                                         "services_removed": [],
                                         "changed": [], "unchanged": False},
                      "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_capabilities"]["consumers"] is False
    assert updates["kong_changes"]["services_added"] == ["svc-new"]


def test_finalize_preserves_inventory_snapshot(stub_env):
    from agents.init_auditor import app as flask_app
    client = flask_app.test_client()
    started = client.post("/api/v1/ai-agents/assess", json={
        "assessment_id": "api-kong-1",
        "selected_standards": ["OWASP API Top 10"],
    })
    assert started.status_code == 202
    resumed = client.post("/api/v1/ai-agents/assess/api-kong-1/resume",
                          json={"decision": "approve"})
    assert resumed.status_code == 200
    status = client.get("/api/v1/ai-agents/assess/api-kong-1")
    body = status.get_json()
    assert body["kong"]["source"] == "kong_admin_api"
    assert body["kong"]["live"] is True
    assert body["kong"]["stale"] is False
    assert body["kong"]["services"] == 2
    assert body["summary"]["kong_live"] is True


def test_finalize_writes_inventory_artifact(stub_env):
    saved = {}

    def fake_persist(**kwargs):
        saved[kwargs["name"]] = kwargs["payload"]
        return {"path": "mem", "filename": kwargs["name"]}

    stub_env.setitem(tools.TOOL_DEFS, "persist_artifact",
                     {"fn": fake_persist, "uses_llm": False})
    updates = orchestrator.finalize({
        "assessment_id": "asm-inv",
        "kong_source": "redis_snapshot", "kong_live": False,
        "kong_stale": True, "kong_snapshot_at": "2000-01-01T00:00:00+00:00",
        "kong_gaps": [{"collection": "routes", "error": "HTTP 500"}],
        "kong_data": [dict(s) for s in INVENTORY],
        "budgets": {}, "agents": {},
    })
    assert updates["status"] == "complete"
    inventory = saved["inventory"]
    assert inventory["kong_source"] == "redis_snapshot"
    assert inventory["kong_live"] is False
    assert inventory["kong_stale"] is True
    assert len(inventory["inventory"]) == 2
    assert updates["assessment_summary"]["kong_stale"] is True


def test_discovery_survives_consumer_outage(stub_env):
    def boom(**kwargs):
        raise RuntimeError("no consumers here")

    stub_env.setitem(tools.TOOL_DEFS, "kong_consumers",
                     {"fn": boom, "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_consumers"] == []
    assert any("Consumer inventory" in w for w in updates["warnings"])
    assert updates["agents"]["discovery"]["status"] == "ok"


def test_quick_depth_skips_followup(stub_env):
    result = _run_graph({"selected_standards": ["OWASP API Top 10"],
                         "depth": "quick"})
    assert result["followups_used"] == 0
    assert result["stopping"]["decision"] == "risk"
    assert "evaluate" in result["agents"]
    assert result["status"] == "complete"


SHOP_INV = [
    {"service_name": "shop-api", "service_id": "s1", "service_plugins": [],
     "service_routes": [
         {"id": "r1", "name": "get-user", "paths": ["/api/v1/users/{id}"],
          "methods": ["GET"], "plugin_names": []},
         {"id": "r2", "name": "pay", "paths": ["/api/v1/payment"],
          "methods": ["POST"], "plugin_names": []},
     ]},
    {"service_name": "shop-admin", "service_id": "s2",
     "service_plugins": ["key-auth"],
     "service_routes": [
         {"id": "r3", "name": "admin", "paths": ["/api/v1/admin/users"],
          "methods": ["GET"], "plugin_names": []},
     ]},
]


def test_threat_model_structured_output_synthetic(stub_env):
    def elaborate(**kwargs):
        assert len(kwargs["relations"]) == 1  # shared /api/v1 prefix
        return [{
            "scenario_ref": "shop-api:bola",
            "explanation": "Attackers may enumerate user ids.",
            "attack_path": ["shop-api", "shop-admin", "ghost-api"],
            "objective": "Steal user data.",
            "assets": ["user records"],
            "business_impact": "Breach of customer trust.",
        }]

    stub_env.setitem(tools.TOOL_DEFS, "llm_threat_elaborate",
                     {"fn": elaborate, "uses_llm": True})
    updates = orchestrator.threat_model({
        "kong_data": [dict(s) for s in SHOP_INV],
        "priority_services": ["shop-api"],
        "selected_standards": ["OWASP API Top 10"],
        "budgets": {}, "max_retries": 0,
    })
    threats = updates["threats"]
    assert len(threats) == 12  # 11 scenarios + 1 assessment limitation
    for threat in threats:
        assert threat["hypothesis"] is True
        assert threat["preconditions"] and threat["evidence_refs"]
        assert threat["recommended_tests"]
        assert threat["owasp_ref"].startswith("OWASP API")
    bola = next(t for t in threats if t["threat_id"] == "TM-shop-api-bola")
    assert bola["attack_path"] == ["shop-api", "shop-admin"]  # ghost pruned
    assert bola["objective"] == "Steal user data."
    assert bola["assets"] == ["user records"]
    assert bola["business_impact"] == "Breach of customer trust."
    assert "enumerate user ids" in bola["model_explanation"]
    assert any(t["threat_id"] == "TM-assessment-unsafe_consumption"
               for t in threats)
    assert updates["agents"]["threat_model"]["status"] == "ok"


def test_threat_model_survives_elaboration_failure(stub_env):
    def boom(**kwargs):
        raise RuntimeError("model down")

    stub_env.setitem(tools.TOOL_DEFS, "llm_threat_elaborate",
                     {"fn": boom, "uses_llm": True})
    updates = orchestrator.threat_model({
        "kong_data": [dict(s) for s in SHOP_INV],
        "priority_services": [],
        "selected_standards": [],
        "budgets": {}, "max_retries": 0,
    })
    assert len(updates["threats"]) == 12  # deterministic output retained
    assert all(t["model_explanation"] == "" for t in updates["threats"])
    decisions = updates["agents"]["threat_model"]["decisions"]
    assert any(d["decision"] == "elaboration_skipped" for d in decisions)
    assert updates["agents"]["threat_model"]["status"] == "ok"

def test_discovery_sample_note_when_kong_unconfigured(stub_env, monkeypatch):
    from common import config as _config
    monkeypatch.setattr(_config, "KONG_ADMIN_API", None)
    monkeypatch.setattr(_config, "KONG_ADMIN_TOKEN", None)

    def boom(**kwargs):
        raise RuntimeError("KONG_ADMIN_API is not set")

    def no_snapshot(**kwargs):
        raise RuntimeError("no snapshot")

    stub_env.setitem(tools.TOOL_DEFS, "kong_inventory",
                     {"fn": boom, "uses_llm": False})
    stub_env.setitem(tools.TOOL_DEFS, "kong_snapshot_load",
                     {"fn": no_snapshot, "uses_llm": False})
    stub_env.setitem(tools.TOOL_DEFS, "kong_fallback",
                     {"fn": lambda **k: [dict(s) for s in INVENTORY],
                      "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_source"] == "cached_file"
    assert any(w.startswith("Sample inventory:") for w in updates["warnings"])
    assert not any("unreachable" in w for w in updates["warnings"])


def test_discovery_saved_snapshot_note_when_kong_unconfigured(stub_env, monkeypatch):
    from common import config as _config
    monkeypatch.setattr(_config, "KONG_ADMIN_API", None)
    monkeypatch.setattr(_config, "KONG_ADMIN_TOKEN", None)

    def boom(**kwargs):
        raise RuntimeError("KONG_ADMIN_API is not set")

    snapshot = {"captured_at": "2026-01-01T00:00:00+00:00",
                "inventory": [dict(s) for s in INVENTORY], "gaps": []}
    stub_env.setitem(tools.TOOL_DEFS, "kong_inventory",
                     {"fn": boom, "uses_llm": False})
    stub_env.setitem(tools.TOOL_DEFS, "kong_snapshot_load",
                     {"fn": lambda **k: {"snapshot": snapshot,
                                         "freshness": {"stale": True}},
                      "uses_llm": False})
    updates = orchestrator.discovery({"service_names": None, "top_k": 4,
                                      "budgets": {}, "max_retries": 0})
    assert updates["kong_source"] == "redis_snapshot"
    assert any(w.startswith("Saved snapshot:") for w in updates["warnings"])
