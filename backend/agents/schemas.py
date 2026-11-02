"""
===============================================================================
 File Name   : agents/schemas.py
 Description : Typed shared state and structured records for the supervisor-led
               multi-agent assessment workflow. Every record is JSON-serializable
               so checkpoints, artifacts and API responses share one shape.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import operator
from typing import Annotated, Any, Dict, List, TypedDict


def _merge_dict(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(left or {})
    merged.update(right or {})
    return merged


def _merge_budgets(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Merge concurrent budget snapshots, keeping the highest usage count.

    Parallel investigators each snapshot the live counter; the merge keeps the
    max so no recorded usage is lost, and the fan-in reconciles the exact
    total from the per-agent tool records afterwards.
    """
    left, right = (left or {}), (right or {})
    merged = dict(left)
    merged.update(right)
    merged["llm_calls_used"] = max(
        int(left.get("llm_calls_used", 0) or 0),
        int(right.get("llm_calls_used", 0) or 0))
    return merged


class AgentRecord(TypedDict, total=False):
    """Structured account of one agent's execution within an assessment."""

    agent: str
    status: str  # ok | degraded | failed | skipped
    started_at: str
    finished_at: str
    duration_ms: float
    model: str
    retries: int
    timeout_s: float
    timed_out: bool
    input_summary: Dict[str, Any]
    output_summary: Dict[str, Any]
    decisions: List[Dict[str, Any]]
    tool_calls: List[Dict[str, Any]]
    evidence_ids: List[str]
    error: str


class AssessmentState(TypedDict, total=False):
    """Shared supervisor state. Threaded through every node of the graph."""

    assessment_id: str
    run_id: str
    selected_standards: List[str]
    service_names: List[str]
    top_k: int
    objective: str
    priority_services: List[str]
    depth: str
    risk_scoring: Dict[str, Any]
    plan: Dict[str, Any]
    tiers: Dict[str, List[Dict[str, Any]]]
    stopping: Dict[str, Any]
    max_retries: int
    agent_timeout_s: float
    budgets: Annotated[Dict[str, Any], _merge_budgets]
    started_at: str

    kong_data: List[Dict[str, Any]]
    kong_consumers: List[Dict[str, Any]]
    kong_source: str
    kong_live: bool
    kong_stale: bool
    kong_snapshot_at: str
    kong_gaps: List[Dict[str, Any]]
    kong_capabilities: Dict[str, Any]
    kong_changes: Dict[str, Any]
    warnings: Annotated[List[str], operator.add]
    policy_context: Dict[str, List[Dict[str, Any]]]

    agents: Annotated[Dict[str, AgentRecord], _merge_dict]
    findings: Annotated[List[Dict[str, Any]], operator.add]
    enriched_findings: List[Dict[str, Any]]
    control_results: Annotated[List[Dict[str, Any]], operator.add]
    policy_findings: Annotated[List[Dict[str, Any]], operator.add]
    coverage: Dict[str, Any]
    evidence_retrieved_at: str
    controls: Annotated[List[Dict[str, Any]], operator.add]
    threats: Annotated[List[Dict[str, Any]], operator.add]
    quarantined: Annotated[List[Dict[str, Any]], operator.add]
    recovered_findings: Annotated[List[Dict[str, Any]], operator.add]
    conflicts: Annotated[List[Dict[str, Any]], operator.add]
    conflict_resolutions: Annotated[List[Dict[str, Any]], operator.add]
    correlation: Dict[str, Any]
    risk: Dict[str, Any]
    assessment_summary: Dict[str, Any]
    remediation_plan: List[Dict[str, Any]]
    excluded: List[Dict[str, Any]]
    change_proposals: List[Dict[str, Any]]
    validation: Dict[str, Any]
    approval: Dict[str, Any]

    followups_used: int
    degraded: bool
    degraded_reasons: Annotated[List[str], operator.add]
    errors: Annotated[List[Dict[str, Any]], operator.add]
    trace: Annotated[List[Dict[str, Any]], operator.add]
    status: str  # running | awaiting_approval | complete | failed
