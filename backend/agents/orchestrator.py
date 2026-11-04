"""
===============================================================================
 File Name   : agents/orchestrator.py
 Description : Supervisor-controlled multi-agent assessment workflow.

               Nine logical agents with explicit responsibilities, input/output
               schemas and tool allowlists (see tools.AGENT_TOOLS):

                 supervisor         plans the assessment, owns routing/budgets.
                 discovery          Kong inventory (read-only) + policy retrieval.
                 security_analysis  LLM verdicts per service (Muse Spark).
                 compliance         deterministic control-coverage checks.
                 threat_model       OWASP scenarios + path elaboration.
                 risk               explainable risk scoring (deterministic).
                 remediation        prioritised fix plan (Muse Spark, batched).
                 validation         deterministic finding/plan verification.
                 governance         human approval gate (interrupt; no execution).

               Independent investigators (security_analysis, compliance,
               threat_model) run in parallel and fan in to the aggregator.
               Deterministic checks live in common/rules.py; the LLM reasons
               and explains but no finding survives without evidence.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone
from typing import Any, Callable, Dict

from langgraph.errors import GraphInterrupt
from langgraph.graph import END, StateGraph
from langgraph.types import interrupt

from agents.schemas import AssessmentState
from agents.tools import ToolBudgetExceeded, ToolError, ToolGateway
from common import config, policy, rules, vector_store
from common import validation as input_validation
from common import threats as threat_engine

DEFAULT_AGENT_TIMEOUT_S = 180.0
DEFAULT_MAX_RETRIES = 1
DEFAULT_MAX_LLM_CALLS = 60


def _now():
    return datetime.now(timezone.utc).isoformat()


def _trace(state, agent, event, detail=None):
    return {"at": _now(), "agent": agent, "event": event,
            "detail": detail or {}}


# --- agent runtime ---------------------------------------------------------------

def run_agent(state: Dict[str, Any], agent_name: str,
              fn: Callable[[Dict, ToolGateway, Dict], Dict[str, Any]],
              timeout_s=None, max_retries=None,
              threaded=True) -> Dict[str, Any]:
    """Execute one agent with timeout, retries, budgets and full recording.

    `fn` receives (state, gateway, record) and returns node updates. It may
    include a "_degraded" string to report partial success. Failures after all
    retries return an error-carrying update so the workflow can continue in a
    degraded state instead of aborting the whole assessment.

    `threaded=False` runs the agent inline (no timeout enforcement). Required
    for nodes that use human-in-the-loop interrupts, which must execute on the
    graph's own thread to reach the checkpointer. Interrupts always propagate
    and are never retried or recorded as failures.
    """
    timeout_s = state.get("agent_timeout_s") or timeout_s or DEFAULT_AGENT_TIMEOUT_S
    if max_retries is None:
        max_retries = int(state.get("max_retries", DEFAULT_MAX_RETRIES))
    record: Dict[str, Any] = {
        "agent": agent_name,
        "status": "failed",
        "started_at": _now(),
        "retries": 0,
        "timeout_s": float(timeout_s),
        "timed_out": False,
        "decisions": [],
        "tool_calls": [],
        "evidence_ids": [],
        "error": "",
    }
    gateway = ToolGateway(state, record)
    started = time.monotonic()
    last_error: BaseException = RuntimeError("agent produced no result")
    updates: Dict[str, Any] = {}

    for attempt in range(int(max_retries) + 1):
        record["retries"] = attempt
        try:
            if threaded:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(fn, state, gateway, record)
                    updates = future.result(timeout=float(timeout_s)) or {}
            else:
                updates = fn(state, gateway, record) or {}
            last_error = None  # type: ignore[assignment]
            break
        except GraphInterrupt:
            raise
        except (TimeoutError, FuturesTimeoutError) as exc:
            last_error = exc
            record["timed_out"] = True
        except ToolBudgetExceeded as exc:
            # Retrying cannot help: the budget is spent.
            last_error = exc
            break
        except Exception as exc:  # noqa: BLE001 - recorded, then degraded/failed
            last_error = exc

    record["finished_at"] = _now()
    record["duration_ms"] = round((time.monotonic() - started) * 1000, 1)

    if last_error is None:
        degraded_reason = updates.pop("_degraded", None)
        if degraded_reason:
            record["status"] = "degraded"
            record["error"] = str(degraded_reason)
        else:
            record["status"] = "ok"
    else:
        record["status"] = "failed"
        record["error"] = f"{type(last_error).__name__}: {last_error}"
        updates = {}

    merged = dict(updates)
    merged["agents"] = {agent_name: record}
    # Snapshot the live budgets into the update: in-place mutations are
    # invisible to the checkpointer, so without this a resume would restore
    # stale counters. Single (non-parallel) nodes later reconcile the exact
    # total from the per-agent tool records.
    if "budgets" in state:
        merged["budgets"] = dict(state["budgets"])
    merged_trace = list(merged.get("trace", []))
    merged_trace.append(_trace(
        state, agent_name, f"agent_{record['status']}",
        {"retries": record["retries"], "ms": record["duration_ms"],
         "error": record["error"] or None}))
    merged["trace"] = merged_trace
    if record["status"] == "failed":
        merged["errors"] = [{
            "agent": agent_name, "error": record["error"],
            "timed_out": record["timed_out"], "at": record["finished_at"],
        }]
        merged["degraded_reasons"] = [f"{agent_name} failed: {record['error']}"]
    elif record["status"] == "degraded":
        merged["degraded_reasons"] = [f"{agent_name} degraded: {record['error']}"]
    return merged


def reconcile_budgets(state: Dict[str, Any]) -> Dict[str, Any]:
    """Recompute budget counters from per-agent tool records.

    Parallel nodes share the live counter in memory, but each returns its own
    snapshot and the channel keeps only the last writer. The tool records,
    merged per agent without loss, are the source of truth: count successful
    LLM tool calls across all recorded agents.
    """
    from agents.tools import TOOL_DEFS
    llm_total = 0
    tool_total = 0
    for record in (state.get("agents") or {}).values():
        for call in (record or {}).get("tool_calls", []):
            # Every attempt consumes budget, failed or not.
            tool_total += 1
            if TOOL_DEFS.get(call.get("tool", ""), {}).get("uses_llm"):
                llm_total += 1
    budgets = dict(state.get("budgets") or {})
    budgets["llm_calls_used"] = max(int(budgets.get("llm_calls_used", 0)), llm_total)
    budgets["tool_calls_used"] = max(int(budgets.get("tool_calls_used", 0)), tool_total)
    return budgets


# --- supervisor -------------------------------------------------------------------
# Responsibility: initialise the assessment, own ids/budgets/status.
# Input:  selected_standards?, service_names?, top_k?, assessment_id?
# Output: ids, budgets, status=running.
# Tools:  none (pure routing/planning).

DEPTH_PRESETS = {
    "quick": {"max_rounds": 1, "max_llm_calls": 20, "max_tool_calls": 60,
              "max_duration_s": 180},
    "standard": {"max_rounds": 3, "max_llm_calls": 60, "max_tool_calls": 200,
                 "max_duration_s": 600},
    "deep": {"max_rounds": 5, "max_llm_calls": 150, "max_tool_calls": 500,
             "max_duration_s": 1800},
}

THREAT_WORDS = ("threat", "stride", "attack", "abuse", "adversary", "malicious")
COMPLIANCE_WORDS = ("complian", "gdpr", "hipaa", "pci", "iso 27001", "soc 2",
                    "soc2", "nist", "audit", "control", "policy", "regulation")
INVESTIGATION_WORDS = ("audit", "assess", "vulnerab", "finding", "investigat",
                       "posture", "review", "scan", "pentest", "gap")


def detect_focus(objective):
    """Map the assessment objective to focus areas with explicit rationale.

    Deterministic and auditable by design: every selected focus cites the
    objective phrase that triggered it.
    """
    lowered = str(objective or "").lower()
    focus, rationale = [], []
    for area, words in (("threat", THREAT_WORDS),
                        ("compliance", COMPLIANCE_WORDS),
                        ("investigation", INVESTIGATION_WORDS)):
        hit = next((w for w in words if w in lowered), None)
        if hit:
            focus.append(area)
            rationale.append(f"objective mentions '{hit}' -> {area} focus")
    return focus, rationale


def select_investigators(focus):
    """Choose the relevant specialist agents for the detected focus."""
    if not focus:
        return (["security_analysis", "compliance", "threat_model"],
                "no specific focus detected; running full coverage")
    selected = []
    if "investigation" in focus:
        selected.append("security_analysis")
    if "compliance" in focus:
        selected.append("compliance")
    if "threat" in focus:
        selected.append("threat_model")
    return selected or ["security_analysis", "compliance", "threat_model"], (
        f"selected [{', '.join(selected)}] for focus [{', '.join(focus)}]"
        if selected else "fallback to full coverage")


def build_plan(objective, depth, budgets):
    """Structured investigation plan: scope, agents, evidence requirements,
    stopping limits and the rationale behind every choice."""
    focus, rationale = detect_focus(objective)
    investigators, selection_note = select_investigators(focus)
    rationale.append(selection_note)
    return {
        "objective": objective,
        "depth": depth,
        "focus_areas": focus,
        "investigators": investigators,
        "evidence_requirements": {
            "min_chunks_per_service": 1,
            "min_confidence_for_action": "medium",
        },
        "stopping": {
            "max_rounds": budgets.get("max_rounds"),
            "max_llm_calls": budgets.get("max_llm_calls"),
            "max_tool_calls": budgets.get("max_tool_calls"),
            "max_duration_s": budgets.get("max_duration_s"),
        },
        "rationale": rationale,
    }


def supervisor_plan(state: Dict[str, Any]) -> Dict[str, Any]:
    assessment_id = state.get("assessment_id") or f"asm-{uuid.uuid4().hex[:12]}"
    depth = str(state.get("depth") or "standard").lower()
    if depth not in DEPTH_PRESETS:
        depth = "standard"
    preset = DEPTH_PRESETS[depth]
    budgets = dict(state.get("budgets") or {})
    budgets.setdefault("max_llm_calls", preset["max_llm_calls"])
    budgets.setdefault("llm_calls_used", 0)
    budgets.setdefault("max_rounds", preset["max_rounds"])
    budgets.setdefault("max_tool_calls", preset["max_tool_calls"])
    budgets.setdefault("tool_calls_used", 0)
    budgets.setdefault("max_duration_s", preset["max_duration_s"])
    raw_objective = state.get("objective") or ""
    objective = raw_objective or "Full API security assessment"
    priority_services = [str(s) for s in (state.get("priority_services") or [])]
    # Focus is detected from the stated objective only: an unstated objective
    # means full coverage, never an accidental keyword subset.
    plan = build_plan(raw_objective, depth, budgets)
    plan["objective"] = objective
    record = {
        "agent": "supervisor",
        "status": "ok",
        "started_at": _now(),
        "finished_at": _now(),
        "duration_ms": 0.0,
        "retries": 0,
        "decisions": [{
            "decision": "assessment_planned",
            "objective": objective,
            "depth": depth,
            "investigators": plan["investigators"],
            "rationale": plan["rationale"],
            "routes": ["discovery", "dispatch", "aggregate", "risk",
                       "remediation", "validation", "governance", "finalize"],
        }],
        "tool_calls": [],
        "evidence_ids": [],
        "error": "",
    }
    return {
        "assessment_id": assessment_id,
        "run_id": f"run-{uuid.uuid4().hex[:8]}",
        "selected_standards": state.get("selected_standards") or ["All Security Standards"],
        "service_names": state.get("service_names"),
        "top_k": int(state.get("top_k") or 4),
        "objective": objective,
        "priority_services": priority_services,
        "depth": depth,
        "plan": plan,
        "budgets": budgets,
        "started_at": _now(),
        "followups_used": 0,
        "degraded": False,
        "status": "running",
        "agents": {"supervisor": record},
        "trace": [_trace(state, "supervisor", "assessment_planned",
                         {"assessment_id": assessment_id})],
    }


# --- discovery --------------------------------------------------------------------
# Responsibility: read-only Kong inventory + per-service policy retrieval.
# Inventory resolves live -> Redis snapshot -> cached file, and the provenance
# (source, live flag, staleness, capture time, gaps, capabilities, changes)
# travels with the assessment so cached data is never presented as live.
# Input:  service_names?, top_k.
# Output: kong_data, kong_source, kong_live, kong_stale, kong_snapshot_at,
#         kong_gaps, kong_capabilities, kong_changes, policy_context, warnings?.
# Tools:  kong_inventory, kong_consumers, kong_fallback, kong_snapshot_save,
#         kong_snapshot_load, kong_snapshot_diff, vector_search.

def _discovery_fn(state, gateway: ToolGateway, record):
    service_names = state.get("service_names")
    top_k = int(state.get("top_k") or 4)
    record["input_summary"] = {"service_names": service_names, "top_k": top_k}
    warnings = []
    gaps: List[Dict[str, str]] = []
    changes = None
    try:
        live = gateway.call("kong_inventory", service_names=service_names)
        kong_data = live["inventory"]
        gaps = list(live.get("gaps", []))
        kong_source = "kong_admin_api"
        kong_live, kong_stale = True, False
        snapshot_at = _now()
        record["decisions"].append({"decision": "inventory_source",
                                    "source": kong_source,
                                    "gaps": [g["collection"] for g in gaps]})
        for gap in gaps:
            warnings.append(f"Collection '{gap['collection']}' failed "
                            f"({gap['error']}); inventory is partial.")
        try:
            saved = gateway.call("kong_snapshot_save", inventory=kong_data,
                                 source=kong_source, gaps=gaps)
            snapshot_at = saved.get("captured_at", snapshot_at)
        except ToolError as exc:
            warnings.append(f"Snapshot cache write failed: {exc}")
        try:
            changes = gateway.call("kong_snapshot_diff", inventory=kong_data)
        except ToolError as exc:
            warnings.append(f"Change detection unavailable: {exc}")
    except ToolError as exc:
        try:
            cached = gateway.call("kong_snapshot_load")
            snapshot = cached["snapshot"]
            kong_data = snapshot["inventory"]
            gaps = list(snapshot.get("gaps", []))
            kong_source = "redis_snapshot"
            kong_live = False
            kong_stale = bool((cached.get("freshness") or {}).get("stale",
                                                                  True))
            snapshot_at = snapshot.get("captured_at")
            if config.kong_configured():
                warnings.append(
                    f"Kong Admin API unreachable ({exc}); used Redis snapshot "
                    f"captured at {snapshot_at} (stale: {kong_stale}).")
            else:
                warnings.append(
                    config.saved_snapshot_note(snapshot_at, kong_stale))
        except ToolError:
            kong_data = gateway.call("kong_fallback")
            kong_source = "cached_file"
            kong_live, kong_stale = False, True
            snapshot_at = None
            if config.kong_configured():
                warnings.append(f"Kong Admin API unreachable ({exc}); no Redis "
                                "snapshot; used cached file inventory of unknown "
                                "age (treated as stale).")
            else:
                warnings.append(
                    config.sample_inventory_note(len(kong_data)))
        record["decisions"].append({"decision": "inventory_source",
                                    "source": kong_source, "live": kong_live,
                                    "stale": kong_stale,
                                    "reason": str(exc)[:200]})
    if service_names:
        wanted = {n.lower() for n in service_names}
        kong_data = [s for s in kong_data
                     if str(s.get("service_name", "")).lower() in wanted]

    capabilities: Dict[str, Any] = {
        "services": True,
        "routes": "routes" not in {g["collection"] for g in gaps},
        "plugins": "plugins" not in {g["collection"] for g in gaps},
    }
    try:
        kong_consumers = gateway.call("kong_consumers")
        capabilities["consumers"] = True
        record["decisions"].append({"decision": "consumers_inventoried",
                                    "count": len(kong_consumers)})
    except ToolError as exc:
        if config.kong_configured():
            warnings.append(f"Consumer inventory unavailable: {exc}")
        else:
            warnings.append("Consumer inventory skipped: no Kong Admin API "
                            "configured (the sample inventory has no consumers).")
        record["decisions"].append({"decision": "consumers_skipped",
                                    "reason": str(exc)[:200]})
        capabilities["consumers"] = False
        kong_consumers = []

    policy_context: Dict[str, Any] = {}
    retrieved = 0
    for service in kong_data:
        name = service.get("service_name", "unknown")
        plugins = ", ".join(service.get("service_plugins", []))
        try:
            chunks = gateway.call(
                "vector_search",
                query=(f"Security policy requirements and mandatory Kong plugins for "
                       f"service {name} with plugins {plugins}"),
                top_k=top_k,
            )
        except ToolError as exc:
            warnings.append(f"Retrieval failed for {name}: {exc}")
            chunks = []
        policy_context[name] = chunks
        assessment = vector_store.assess_retrieval(chunks)
        if not assessment["sufficient"]:
            warnings.append(f"Retrieval insufficient for {name}: "
                            f"{'; '.join(assessment['reasons'])}")
            record["decisions"].append({"decision": "retrieval_insufficient",
                                        "service": name,
                                        "reasons": assessment["reasons"]})
        retrieved += len(chunks)
        record.setdefault("evidence_ids", []).extend(
            [c.get("id") for c in chunks if isinstance(c, dict) and c.get("id")])

    record["output_summary"] = {"services": len(kong_data), "source": kong_source,
                                "live": kong_live, "stale": kong_stale,
                                "consumers": len(kong_consumers),
                                "retrieved_chunks": retrieved}
    updates: Dict[str, Any] = {
        "kong_data": kong_data,
        "kong_consumers": kong_consumers,
        "kong_source": kong_source,
        "kong_live": kong_live,
        "kong_stale": kong_stale,
        "kong_snapshot_at": snapshot_at,
        "kong_gaps": gaps,
        "kong_capabilities": capabilities,
        "kong_changes": changes,
        "policy_context": policy_context,
        "warnings": warnings,
        "evidence_retrieved_at": _now(),
    }
    if not kong_data:
        updates["_degraded"] = "Discovery found no services to assess."
    elif not kong_live:
        if kong_source == "cached_file" and not config.kong_configured():
            updates["_degraded"] = (
                "Inventory source is cached_file; auditing the bundled sample "
                "APIs \u2014 this is not a live assessment.")
        else:
            updates["_degraded"] = (
                f"Inventory source is {kong_source} (stale: {kong_stale}); "
                "this is not a live assessment.")
    elif retrieved == 0:
        updates["_degraded"] = "No policy evidence retrieved; findings will be quarantined."
    return updates


def discovery(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "discovery", _discovery_fn)


# --- dispatch (supervisor sub-routine) ----------------------------------------------------------
# Responsibility: finalize the investigator selection against the discovered
# inventory and hand the supervisor's plan to the conditional fan-out.
# Input:  plan, kong_data. Output: plan (with dispatched[] + inventory count).
# Tools:  none.

def _dispatch_fn(state, gateway, record):
    plan = dict(state.get("plan") or {})
    wanted = list(plan.get("investigators") or
                  ["security_analysis", "compliance", "threat_model"])
    kong_data = state.get("kong_data", [])
    record["input_summary"] = {"planned": wanted, "services": len(kong_data)}
    if not kong_data:
        dispatched = []
        record["decisions"].append({"decision": "no_inventory_no_dispatch"})
    else:
        dispatched = wanted
        record["decisions"].append({"decision": "investigators_dispatched",
                                    "agents": dispatched})
    plan["dispatched"] = dispatched
    plan["inventory_services"] = len(kong_data)
    record["output_summary"] = {"dispatched": dispatched}
    return {"plan": plan}


def dispatch(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "dispatch", _dispatch_fn)


def route_investigators(state: Dict[str, Any]):
    """Fan out to the planned investigators (a list means parallel dispatch)."""
    plan = state.get("plan") or {}
    selected = plan.get("dispatched", plan.get("investigators"))
    if not selected:
        return ["aggregate"]
    known = [name for name in selected
             if name in ("security_analysis", "compliance", "threat_model")]
    return known or ["aggregate"]


# --- security analysis --------------------------------------------------------------
# Responsibility: LLM verdicts (comply/missing/plugins) per service.
# Input:  kong_data, policy_context, selected_standards.
# Output: findings[] (each with evidence_ids from retrieved chunks).
# Tools:  llm_audit_verdict.

def _analysis_fn(state, gateway: ToolGateway, record):
    kong_data = state.get("kong_data", [])
    context = state.get("policy_context", {})
    scope = state.get("selected_standards", [])
    record["input_summary"] = {"services": len(kong_data), "scope": scope}
    findings = []
    failed_services = []
    for index, service in enumerate(kong_data):
        name = service.get("service_name", "unknown")
        chunks = context.get(name, [])
        excerpts = vector_store.format_excerpts(
            chunks, empty_text="No policy excerpts retrieved; rely on standard "
            "API security practice.")
        try:
            verdict = gateway.call(
                "llm_audit_verdict",
                service_name=name,
                service_plugins=service.get("service_plugins", []),
                excerpts=excerpts,
                standards=scope,
            )
        except (ToolError, ToolBudgetExceeded) as exc:
            failed_services.append({"service": name, "error": str(exc)[:300]})
            continue
        evidence_ids = [c.get("id") for c in chunks
                        if isinstance(c, dict) and c.get("id")]
        record["evidence_ids"].extend(evidence_ids)
        for position, policy in enumerate(verdict.get("policies", [])):
            findings.append({
                "finding_id": f"SA-{name}-{position}",
                "agent": "security_analysis",
                "service": name,
                "service_plugins": service.get("service_plugins", []),
                "policy_name": policy.get("policy_name", "Unknown Policy"),
                "comply": bool(policy.get("comply", policy.get("comply_status", False))),
                "missing_plugins": policy.get("missing_plugins", []) or [],
                "details": policy.get("details", ""),
                "evidence_ids": list(evidence_ids),
            })
    record["output_summary"] = {"findings": len(findings),
                                "failed_services": len(failed_services)}
    record["decisions"].append({"decision": "verdicts_produced",
                                "count": len(findings)})
    updates: Dict[str, Any] = {"findings": findings}
    if failed_services:
        updates["errors"] = [{"agent": "security_analysis", **item, "at": _now()}
                             for item in failed_services]
        if not findings:
            raise ToolError(
                f"All {len(failed_services)} service verdict(s) failed: "
                f"{failed_services[0]['error']}")
        updates["_degraded"] = (
            f"{len(failed_services)} service(s) produced no verdict.")
    return updates


def security_analysis(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "security_analysis", _analysis_fn)


# --- compliance ----------------------------------------------------------------------
# Responsibility: deterministic control-coverage checks per service, plus the
# versioned policy catalog evaluation with coverage and common-schema findings.
# Input:  kong_data, policy_context.
# Output: controls[], control_results[], policy_findings[], coverage.
# Tools:  none (purely deterministic over discovered evidence).

# Control -> Kong plugins that satisfy it. Derived from
# backend/knowledge_base/kong_api_security_mapping.md.
CONTROL_CHECKS = {
    "authentication": {
        "satisfies": ["jwt", "oauth2", "openid-connect", "mtls-auth"],
        "weak": ["key-auth", "basic-auth"],
    },
    "authorization": {"satisfies": ["acl"], "weak": []},
    "rate_limiting": {"satisfies": ["rate-limiting"], "weak": []},
    "input_validation": {"satisfies": ["request-validator"], "weak": []},
    "logging_audit": {"satisfies": ["file-log", "http-log", "tcp-log", "syslog"],
                      "weak": []},
    "data_protection": {"satisfies": ["response-transformer", "exit-transformer"],
                        "weak": []},
    "network_restriction": {"satisfies": ["ip-restriction"], "weak": []},
}


def _compliance_fn(state, gateway: ToolGateway, record):
    kong_data = state.get("kong_data", [])
    record["input_summary"] = {"services": len(kong_data)}
    controls = []
    for service in kong_data:
        name = service.get("service_name", "unknown")
        enabled = {rules.normalize_plugin(p)["canonical"]
                   for p in service.get("service_plugins", [])}
        enabled.discard(None)
        for control, spec in CONTROL_CHECKS.items():
            strong = sorted(set(spec["satisfies"]) & enabled)
            weak = sorted(set(spec.get("weak", [])) & enabled)
            if strong:
                outcome, basis = "satisfied", strong
            elif weak:
                outcome, basis = "partial", weak
            else:
                outcome, basis = "unsatisfied", []
            controls.append({
                "control_id": f"CC-{name}-{control}",
                "agent": "compliance",
                "service": name,
                "control": control,
                "outcome": outcome,
                "basis_plugins": basis,
            })
    # Versioned policy engine over the same inventory evidence, plus the
    # retrieved excerpts for control grounding.
    context = state.get("policy_context", {})
    retrieved_at = state.get("evidence_retrieved_at")
    assessment_id = state.get("assessment_id", "asm")
    control_results = []
    policy_findings = []
    results_by_service = {}
    for service in kong_data:
        name = service.get("service_name", "unknown")
        evidence = policy.build_service_evidence(service, context.get(name, []))
        results = policy.evaluate_all(evidence)
        control_results.extend({**r, "service": name} for r in results)
        results_by_service[name] = results
        for result in results:
            finding = policy.control_result_to_finding(
                result, service,
                f"{assessment_id}-PF-{name}-{result['control_id']}",
                retrieved_at)
            if finding:
                policy_findings.append(finding)
    coverage = policy.compute_coverage(results_by_service)
    record["output_summary"] = {
        "controls_evaluated": len(controls),
        "policy_controls": len(control_results),
        "policy_findings": len(policy_findings),
        "coverage_totals": coverage["totals"],
    }
    record["decisions"].append({"decision": "controls_evaluated",
                                "count": len(controls)})
    record["decisions"].append({"decision": "policy_catalog_evaluated",
                                "version": policy.CATALOG_VERSION,
                                "findings": len(policy_findings)})
    return {"controls": controls, "control_results": control_results,
            "policy_findings": policy_findings, "coverage": coverage}


def compliance(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "compliance", _compliance_fn)


# --- threat modelling ------------------------------------------------------------------
# Responsibility: OWASP-shaped threat scenarios from route/method/plugin
# evidence, with bounded LLM elaboration of attack paths and impact.
# Input:  kong_data, priority_services, selected_standards.
# Output: threats[] (structured suspected-only hypotheses with preconditions,
#         evidence refs and non-destructive test recommendations).
# Tools:  llm_threat_elaborate (one call per assessment at most).

MAX_ELABORATION_SCENARIOS = 12


def _apply_elaborations(model_threats, elaborations, relations, record):
    """Merge model explanations, keeping only attack paths that traverse
    evidenced service relationships. Ungrounded path hops are pruned."""
    adjacency: Dict[str, set] = {}
    for relation in relations or []:
        pair = (relation or {}).get("services") or []
        if len(pair) == 2:
            adjacency.setdefault(pair[0], set()).add(pair[1])
            adjacency.setdefault(pair[1], set()).add(pair[0])
    by_ref = {f"{t.get('service')}:{t.get('scenario_id')}": t
              for t in model_threats if t.get("scenario_id")}
    pruned, applied = 0, 0
    for item in elaborations or []:
        if not isinstance(item, dict):
            continue
        target = by_ref.get(item.get("scenario_ref"))
        if target is None:
            continue
        allowed = {target.get("service")} | adjacency.get(
            target.get("service"), set())
        path = [s for s in (item.get("attack_path") or []) if s in allowed]
        pruned += len(item.get("attack_path") or []) - len(path)
        target["attack_path"] = path
        target["objective"] = str(item.get("objective", ""))[:500]
        target["assets"] = [str(a)[:200] for a in (item.get("assets") or [])[:10]]
        if item.get("business_impact"):
            target["business_impact"] = str(item.get("business_impact"))[:500]
        target["model_explanation"] = str(item.get("explanation", ""))[:2000]
        applied += 1
    if pruned:
        record["decisions"].append({"decision": "ungrounded_path_pruned",
                                    "hops": pruned})
    return applied


def _threat_fn(state, gateway: ToolGateway, record):
    kong_data = state.get("kong_data", [])
    priority = state.get("priority_services", [])
    scope = state.get("selected_standards", [])
    record["input_summary"] = {"services": len(kong_data),
                               "priority_services": priority}
    record["decisions"].append({
        "decision": "api_specs_unavailable",
        "note": ("No API specifications are inventoried; spec-dependent "
                 "checks are skipped, route/config evidence only.")})
    estate = threat_engine.analyze_estate(kong_data, priority)
    model_threats = []
    for service_name, scenarios in estate["scenarios_by_service"].items():
        for scenario in scenarios:
            model_threats.append({
                "threat_id": f"TM-{service_name}-{scenario['scenario_id']}",
                "agent": "threat_model",
                "service": service_name,
                "control": scenario["scenario_id"],
                "category": scenario["stride"],
                "title": scenario["title"],
                "severity_hint": scenario["severity_hint"],
                "basis": "; ".join(scenario["preconditions"]),
                "scenario_id": scenario["scenario_id"],
                "owasp_ref": scenario["owasp_ref"],
                "hypothesis": True,
                "preconditions": scenario["preconditions"],
                "evidence_refs": scenario["evidence_refs"],
                "attack_path": [],
                "objective": "",
                "assets": [],
                "business_impact": ("Priority service; treat impact as high."
                                    if service_name in (priority or []) else ""),
                "recommended_tests": scenario["recommended_tests"],
                "model_explanation": "",
            })
    if estate["limitation"]:
        limitation = estate["limitation"]
        model_threats.append({
            "threat_id": "TM-assessment-unsafe_consumption",
            "agent": "threat_model",
            "service": "*",
            "control": limitation["scenario_id"],
            "category": limitation["stride"],
            "title": limitation["title"],
            "severity_hint": limitation["severity_hint"],
            "basis": "; ".join(limitation["preconditions"]),
            "scenario_id": limitation["scenario_id"],
            "owasp_ref": limitation["owasp_ref"],
            "hypothesis": True,
            "preconditions": limitation["preconditions"],
            "evidence_refs": limitation["evidence_refs"],
            "attack_path": [],
            "objective": "",
            "assets": [],
            "business_impact": "",
            "recommended_tests": limitation["recommended_tests"],
            "model_explanation": "",
        })
    elaborated = 0
    if model_threats:
        payload = [{
            "scenario_ref": f"{t['service']}:{t['scenario_id']}",
            "title": t["title"],
            "severity_hint": t["severity_hint"],
            "preconditions": t["preconditions"],
            "evidence_refs": t["evidence_refs"],
        } for t in model_threats[:MAX_ELABORATION_SCENARIOS]]
        try:
            elaborations = gateway.call(
                "llm_threat_elaborate",
                scenarios=payload,
                relations=estate["relations"],
                business_context=(
                    f"priority_services={input_validation.sanitize_for_prompt(priority, max_len=1000)}; "  # noqa: E501
                    f"standards={input_validation.sanitize_for_prompt(scope, max_len=1000)}"))
            elaborated = _apply_elaborations(
                model_threats, elaborations, estate["relations"], record)
            record["decisions"].append({"decision": "scenarios_elaborated",
                                        "count": elaborated})
        except (ToolError, ToolBudgetExceeded) as exc:
            record["decisions"].append({"decision": "elaboration_skipped",
                                        "reason": str(exc)[:200]})
    record["output_summary"] = {"threats": len(model_threats),
                                "elaborated": elaborated,
                                "relations": len(estate["relations"])}
    return {"threats": model_threats}


def threat_model(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "threat_model", _threat_fn)


# --- aggregate (fan-in) ------------------------------------------------------------------
# Responsibility: correlate findings with controls, enforce the evidence rule,
# verify claims deterministically, surface conflicts. No finding without
# evidence survives aggregation: ungrounded findings are quarantined with an
# explicit reason, never silently dropped and never planned against.

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def _control_for_plugin(canonical):
    for control, spec in CONTROL_CHECKS.items():
        if canonical in (spec.get("satisfies") or []):
            return control
    return None


def assign_tier(finding, control_index):
    """Assign confirmed/suspected/informational/unverified with a reason.

    confirmed = multi-path corroboration: a grounded, high-confidence LLM
    verdict agrees with an independent deterministic control gap. It is still
    a configuration gap, never a proven-exploitable vulnerability. A lone
    config indicator can never yield better than suspected, and an
    ungrounded claim never leaves unverified.
    """
    verification = finding.get("verification") or {}
    status = verification.get("status")
    confidence = verification.get("confidence", "low")
    grounded = (verification.get("evidence") or {}).get("grounded", False)
    if finding.get("comply"):
        return "informational", "Verdict claims compliance."
    if status != "verified" or not grounded:
        return "unverified", (
            f"status={status}, grounded={grounded}; insufficient support.")
    service = finding.get("service")
    corroborated = sorted({
        str(plugin) for plugin in (finding.get("missing_plugins") or [])
        if control_index.get((service, _control_for_plugin(
            rules.normalize_plugin(plugin)["canonical"]))) == "unsatisfied"
    })
    if confidence == "high" and corroborated:
        return "confirmed", (
            "Grounded verdict corroborated by unsatisfied control(s) for "
            f"{', '.join(corroborated)}.")
    return "suspected", (
        "Grounded configuration indicator; requires human confirmation.")


def _aggregate_fn(state, gateway: ToolGateway, record):
    findings = state.get("findings", [])
    controls = state.get("controls", [])
    threats = state.get("threats", [])
    context = state.get("policy_context", {})
    scope = state.get("selected_standards", [])
    record["input_summary"] = {"findings": len(findings),
                               "controls": len(controls),
                               "threats": len(threats)}
    known_chunk_ids = {c.get("id") for chunks in context.values()
                       for c in chunks if isinstance(c, dict)}

    control_index = {(c.get("service"), c.get("control")): c.get("outcome")
                     for c in controls if isinstance(c, dict)}
    verified_findings = []
    quarantined = []
    conflicts = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        service = finding.get("service", "")
        evidence_ids = [e for e in (finding.get("evidence_ids") or [])
                        if e in known_chunk_ids]
        if not evidence_ids:
            quarantined.append({**finding, "quarantine_reason": (
                "No retrieved policy evidence references this finding; "
                "security findings require evidence.")})
            continue
        policy = {"policy_name": finding.get("policy_name"),
                  "comply": finding.get("comply"),
                  "missing_plugins": finding.get("missing_plugins"),
                  "details": finding.get("details")}
        verification = rules.verify_policy_finding(
            policy, finding.get("service_plugins", []),
            context.get(service, []), scope)
        enriched = {**finding, "evidence_ids": evidence_ids,
                    "verification": verification}
        tier, tier_reason = assign_tier(enriched, control_index)
        enriched["tier"] = tier
        enriched["tier_reason"] = tier_reason
        verified_findings.append(enriched)
        for claim in verification.get("claims", []):
            if claim.get("result") == "contradicted":
                conflicts.append({
                    "conflict_id": f"CF-{finding.get('finding_id')}",
                    "type": "inventory_contradiction",
                    "finding_id": finding.get("finding_id"),
                    "service": service,
                    "detail": claim.get("note"),
                    "resolved": False,
                })
        if finding.get("comply") and control_index.get((service, "authentication")) == "unsatisfied":
            conflicts.append({
                "conflict_id": f"CF-{finding.get('finding_id')}-auth",
                "type": "verdict_disagreement",
                "finding_id": finding.get("finding_id"),
                "service": service,
                "detail": ("Verdict claims compliance but no authentication "
                           "plugin is enabled."),
                "resolved": False,
            })
    record["output_summary"] = {"verified": len(verified_findings),
                                "quarantined": len(quarantined),
                                "conflicts": len(conflicts)}
    record["decisions"].append({"decision": "evidence_rule_enforced",
                                "quarantined": len(quarantined)})
    # Raw investigator findings stay on `findings` for traceability; the
    # verified, evidence-enforced set carries forward on `enriched_findings`.
    updates: Dict[str, Any] = {
        "enriched_findings": verified_findings,
        "quarantined": quarantined,
        "conflicts": conflicts,
        "budgets": reconcile_budgets(state),
    }
    if quarantined:
        updates["_degraded"] = (
            f"{len(quarantined)} finding(s) quarantined for missing evidence.")
    return updates


def aggregate(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "aggregate", _aggregate_fn)


# --- followup (bounded investigation loop) ---------------------------------------------------
# Responsibility: resolve conflicts and recover quarantined findings with one
# targeted re-investigation per pass. Bounded by the plan's max_rounds.
# Input:  conflicts, quarantined, kong_data, policy_context.
# Output: recovered_findings[], conflict_resolutions[], correlation?,
#         followups_used+1.
# Tools:  vector_search, llm_correlate (once per pass, only when conflicts
#         remain unresolved after the deterministic pass).


def _followup_fn(state, gateway: ToolGateway, record):
    conflicts = [c for c in state.get("conflicts", []) if isinstance(c, dict)]
    resolved_ids = {r.get("conflict_id") for r in state.get("conflict_resolutions", [])}
    quarantined = state.get("quarantined", [])
    context = state.get("policy_context", {})
    scope = state.get("selected_standards", [])
    record["input_summary"] = {"conflicts": len(conflicts),
                               "quarantined": len(quarantined)}
    control_index = {(c.get("service"), c.get("control")): c.get("outcome")
                     for c in state.get("controls", [])
                     if isinstance(c, dict)}
    resolutions = []
    for conflict in conflicts:
        if conflict.get("conflict_id") in resolved_ids:
            continue
        # Deterministic re-check settles inventory contradictions: the claim is
        # disproven, so the finding is excluded from planning downstream.
        resolutions.append({
            "conflict_id": conflict.get("conflict_id"),
            "resolved": conflict.get("type") == "inventory_contradiction",
            "resolution": (
                "Deterministic re-check confirms the missing-plugin claim is "
                "disproven by the inventory; finding excluded from the plan."
                if conflict.get("type") == "inventory_contradiction"
                else "Disagreement persists after re-check; escalated to validation."),
        })
    recovered = []
    already = {f.get("finding_id") for f in state.get("recovered_findings", [])
               if isinstance(f, dict)}
    merged_context = dict(context)
    services = sorted({q.get("service") for q in quarantined if isinstance(q, dict)})
    for service in services:
        try:
            chunks = gateway.call(
                "vector_search",
                query=(f"Mandatory Kong plugins and security requirements for "
                       f"service {service}; authentication authorization rate "
                       f"limiting logging"),
                top_k=int(state.get("top_k") or 4),
            )
        except ToolError as exc:
            record["decisions"].append({"decision": "recovery_failed",
                                        "service": service,
                                        "reason": str(exc)[:200]})
            continue
        if not chunks:
            continue
        merged_context[service] = chunks
        known = {c.get("id") for c in chunks if isinstance(c, dict)}
        for item in quarantined:
            if not isinstance(item, dict) or item.get("service") != service:
                continue
            if item.get("finding_id") in already:
                continue
            policy = {"policy_name": item.get("policy_name"),
                      "comply": item.get("comply"),
                      "missing_plugins": item.get("missing_plugins"),
                      "details": item.get("details")}
            verification = rules.verify_policy_finding(
                policy, item.get("service_plugins", []), chunks, scope)
            recovered_item = {**item, "evidence_ids": sorted(known),
                              "verification": verification,
                              "recovered_by": "followup"}
            tier, tier_reason = assign_tier(recovered_item, control_index)
            recovered_item["tier"] = tier
            recovered_item["tier_reason"] = tier_reason
            recovered.append(recovered_item)
    correlation = ""
    pending = [r for r in resolutions if not r.get("resolved")]
    if pending:
        brief = "; ".join(
            f"{c.get('service')}: {c.get('detail')}" for c in conflicts[:10])
        try:
            correlation = gateway.call(
                "llm_correlate", conflicts=conflicts, findings_brief=brief)
            record["decisions"].append({"decision": "correlation_produced"})
        except (ToolError, ToolBudgetExceeded) as exc:
            record["decisions"].append({"decision": "correlation_skipped",
                                        "reason": str(exc)[:200]})
    record["output_summary"] = {"recovered": len(recovered),
                                "resolutions": len(resolutions),
                                "correlated": bool(correlation)}
    return {
        "recovered_findings": recovered,
        "conflict_resolutions": resolutions,
        "correlation": {"analysis": correlation},
        "policy_context": merged_context,
        "followups_used": int(state.get("followups_used", 0)) + 1,
    }


def followup(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "followup", _followup_fn)


def _elapsed_s(state):
    try:
        started = datetime.fromisoformat(state.get("started_at") or "")
        return max(0.0, (datetime.now(timezone.utc) - started).total_seconds())
    except (ValueError, TypeError):
        return 0.0


def evaluate_stopping(state: Dict[str, Any]):
    """Decide followup vs risk from explicit stopping criteria.

    Hard stops (any one ends the loop): max rounds, max model calls, max tool
    calls, max duration. Soft gaps (continue while budget remains): open
    conflicts, quarantined findings, services below the evidence minimum.
    Returns (decision, assessment).
    """
    budgets = state.get("budgets", {})
    rounds_used = 1 + int(state.get("followups_used", 0))
    max_rounds = int(budgets.get("max_rounds", 3))
    llm_used = int(budgets.get("llm_calls_used", 0))
    llm_max = int(budgets.get("max_llm_calls", DEFAULT_MAX_LLM_CALLS))
    tool_used = int(budgets.get("tool_calls_used", 0))
    tool_max = int(budgets.get("max_tool_calls", 10 ** 9))
    elapsed = _elapsed_s(state)
    max_duration = int(budgets.get("max_duration_s", 10 ** 9))

    resolved_ids = {r.get("conflict_id") for r in state.get("conflict_resolutions", [])}
    open_conflicts = [c.get("conflict_id") for c in state.get("conflicts", [])
                      if c.get("conflict_id") not in resolved_ids]
    recovered_services = {f.get("service") for f in state.get("recovered_findings", [])}
    open_quarantine = [q.get("finding_id") for q in state.get("quarantined", [])
                       if q.get("service") not in recovered_services]
    requirements = (state.get("plan") or {}).get("evidence_requirements") or {}
    min_chunks = int(requirements.get("min_chunks_per_service", 1) or 1)
    thin_services = sorted(
        name for name, chunks in (state.get("policy_context") or {}).items()
        if len(chunks or []) < min_chunks)

    criteria = [
        {"name": "max_rounds", "limit": max_rounds, "used": rounds_used,
         "exceeded": rounds_used >= max_rounds},
        {"name": "max_llm_calls", "limit": llm_max, "used": llm_used,
         "exceeded": llm_used >= llm_max},
        {"name": "max_tool_calls", "limit": tool_max, "used": tool_used,
         "exceeded": tool_used >= tool_max},
        {"name": "max_duration_s", "limit": max_duration,
         "used": round(elapsed, 1), "exceeded": elapsed >= max_duration},
    ]
    gaps = {"open_conflicts": open_conflicts, "open_quarantine": open_quarantine,
            "thin_services": thin_services}
    stopped = [c["name"] for c in criteria if c["exceeded"]]
    has_gaps = bool(open_conflicts or open_quarantine or thin_services)
    if stopped:
        decision = "risk"
        reasons = [f"{name} reached; stopping investigation" for name in stopped]
    elif has_gaps:
        decision = "followup"
        reasons = [r for r in (
            f"{len(open_conflicts)} open conflict(s)",
            f"{len(open_quarantine)} quarantined finding(s)",
            f"{len(thin_services)} service(s) below evidence minimum")
            if not r.startswith("0 ")]
    else:
        decision = "risk"
        reasons = ["no gaps; evidence sufficient"]
    assessment = {"rounds_used": rounds_used, "criteria": criteria, "gaps": gaps,
                  "decision": decision, "reasons": reasons}
    return decision, assessment


def route_after_evidence(state: Dict[str, Any]) -> str:
    """Supervisor routing: re-investigate gaps while the budget allows."""
    decision, _ = evaluate_stopping(state)
    return decision


# --- evaluate (supervisor sub-routine) -------------------------------------------------------------------
# Responsibility: record the stopping-criteria assessment behind each
# followup/risk routing decision. Pure observation; the conditional edge acts.
# Input:  whole evidence state. Output: stopping {criteria, gaps, decision}.
# Tools:  none.

def _evaluate_fn(state, gateway, record):
    decision, assessment = evaluate_stopping(state)
    record["input_summary"] = {
        "conflicts": len(state.get("conflicts", [])),
        "quarantined": len(state.get("quarantined", [])),
        "followups_used": state.get("followups_used", 0),
    }
    record["decisions"].append({"decision": decision,
                                "reasons": assessment["reasons"]})
    record["output_summary"] = {"decision": decision,
                                "rounds_used": assessment["rounds_used"]}
    return {"stopping": assessment}


def evaluate(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "evaluate", _evaluate_fn)


# --- risk intelligence -----------------------------------------------------------------
# Responsibility: build the deduplicated enterprise risk register from every
# finding stream (LLM security, policy, threat context) and score each entry
# with the versioned deterministic model in common/risks.py. The register is
# the technical risk record; Muse Spark only explains the ranking, never
# scores, verifies or upgrades entries.
# Input:  enriched_findings, recovered_findings, policy_findings, kong_data,
#         controls, priority_services, risk_scoring (optional config).
# Output: risk {register[], summary, by_level, formula, scoring_model,
#         explanation}, tiers.
# Tools:  llm_risk_explain.


def _risk_fn(state, gateway: ToolGateway, record):
    from common import risks
    findings = [f for f in list(state.get("enriched_findings", [])) +
                list(state.get("recovered_findings", []))
                if isinstance(f, dict) and not f.get("comply")]
    policy_findings = [f for f in state.get("policy_findings", [])
                       if isinstance(f, dict)]
    lookup = {}
    for service in state.get("kong_data", []):
        if not isinstance(service, dict):
            continue
        name = service.get("service_name", "?")
        lookup[name] = {
            "service_plugins": service.get("service_plugins", []),
            "service_routes": service.get("service_routes", []),
            "_priority": name in (state.get("priority_services") or []),
        }
    scoring = state.get("risk_scoring")
    scoring_config = (risks.RiskScoringConfig.from_dict(scoring)
                      if isinstance(scoring, dict)
                      else risks.RiskScoringConfig())
    record["input_summary"] = {"findings": len(findings),
                               "policy_findings": len(policy_findings),
                               "scoring_model": scoring_config.version}
    entries = risks.build_register(findings, policy_findings, lookup,
                                   state.get("controls", []), scoring_config)
    summary = risks.summarize_register(entries)
    explanation = None
    degraded_note = None
    if entries:
        brief = "\n".join(
            f"- {input_validation.sanitize_for_prompt(e['entry_id'])} "
            f"[{e['level']}, score {e['score']}]: "
            f"{input_validation.sanitize_for_prompt(e['title'])}; "
            f"severity {e['severity']}, confidence "
            f"{e['confidence']}, verified {e['verified']}; " + "; ".join(
                f"{name} {f['score']} "
                f"({input_validation.sanitize_for_prompt(f['rationale'])})"
                for name, f in e["factors"].items())
            for e in entries[:8])
        try:
            explanation = gateway.call("llm_risk_explain", entries_brief=brief)
        except (ToolError, ToolBudgetExceeded) as exc:
            degraded_note = f"Risk explanation unavailable: {exc}"
    tiers: Dict[str, list] = {"confirmed": [], "suspected": [],
                               "informational": [], "unverified": []}
    for finding in list(state.get("enriched_findings", [])) + \
            list(state.get("recovered_findings", [])):
        if isinstance(finding, dict):
            tiers.get(finding.get("tier", "unverified"),
                      tiers["unverified"]).append(finding)
    tiers["unverified"].extend(q for q in state.get("quarantined", [])
                               if isinstance(q, dict))
    for finding in policy_findings:
        tiers.get(finding.get("tier", "unverified"),
                  tiers["unverified"]).append(finding)
    record["output_summary"] = {"entries": len(entries),
                                "by_level": summary["by_level"],
                                "tiers": {k: len(v) for k, v in tiers.items()}}
    record["decisions"].append({"decision": "register_built",
                                "entries": len(entries),
                                "scoring_model": scoring_config.version})
    updates: Dict[str, Any] = {
        "risk": {"register": entries, "summary": summary,
                 "by_level": summary["by_level"],
                 "formula": risks.SCORING_FORMULA,
                 "scoring_model": scoring_config.version,
                 "explanation": explanation},
        "tiers": tiers,
    }
    if degraded_note:
        updates["_degraded"] = degraded_note
    return updates


def risk(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "risk", _risk_fn)


# --- remediation --------------------------------------------------------------------------
# Responsibility: prioritised fix plan for sufficiently supported findings
# (Muse Spark, batched) plus structured change proposals for the same
# eligible findings. Only confirmed/suspected findings at or above the
# plan's minimum confidence are eligible; everything else is excluded with an
# explicit reason. Proposals are deterministic shells (exact target,
# retrieved config, patch, diff, rollback) with model-drafted prose that is
# validated field-by-field; each proposal is simulated and rescored before
# it lands. Nothing here executes against live Kong.
# Input:  enriched_findings, recovered_findings, risk, policy_context,
#         kong_data, service_names.
# Output: remediation_plan[], excluded[], change_proposals[].
# Tools:  llm_remediation_batch, llm_change_prose_batch.

def _remediation_fn(state, gateway: ToolGateway, record):
    from agents import auditor_agent
    findings = [f for f in list(state.get("enriched_findings", [])) +
                list(state.get("recovered_findings", []))
                if isinstance(f, dict) and not f.get("comply")]
    context = state.get("policy_context", {})
    record["input_summary"] = {"candidate_findings": len(findings)}
    requirements = (state.get("plan") or {}).get("evidence_requirements") or {}
    min_conf = str(requirements.get("min_confidence_for_action", "medium")).lower()
    min_rank = CONFIDENCE_RANK.get(min_conf, 2)
    eligible, excluded = [], []
    for finding in findings:
        fid = finding.get("finding_id")
        status = (finding.get("verification") or {}).get("status")
        if status == "contradictory":
            excluded.append({"finding_id": fid,
                             "reason": "Claim disproven by the inventory."})
            continue
        tier = finding.get("tier", "unverified")
        if tier not in ("confirmed", "suspected"):
            excluded.append({
                "finding_id": fid,
                "reason": (f"Tier '{tier}' is not actionable; remediation "
                           "requires confirmed or suspected findings.")})
            continue
        confidence = str((finding.get("verification") or {}).get(
            "confidence", "low")).lower()
        if CONFIDENCE_RANK.get(confidence, 1) < min_rank:
            excluded.append({
                "finding_id": fid,
                "reason": (f"Confidence '{confidence}' is below the minimum "
                           f"'{min_conf}' for action.")})
            continue
        eligible.append(finding)
    register = state.get("risk", {}).get("register", [])
    entry_scores: Dict[str, float] = {}
    for entry in register:
        if not isinstance(entry, dict):
            continue
        for source in entry.get("sources", []):
            fid = source.get("finding_id")
            if fid:
                entry_scores[fid] = max(entry_scores.get(fid, 0.0),
                                        entry.get("score", 0.0))
    eligible.sort(key=lambda f: entry_scores.get(f.get("finding_id"), 0.0),
                  reverse=True)

    excerpts = vector_store.format_excerpts(
        [c for chunks in context.values() for c in chunks])
    batch_size = max(1, config.REMEDIATION_BATCH_SIZE)
    plan: list = []
    errors: list = []
    for index in range(0, len(eligible), batch_size):
        batch = eligible[index:index + batch_size]
        payload = [{
            "serviceName": f.get("service"),
            "policyName": f.get("policy_name"),
            "details": f.get("details", ""),
            "missingPlugins": f.get("missing_plugins", []),
            "severity": auditor_agent.SEVERITY_MAP.get(
                str(f.get("policy_name", "")).split(" ")[0], "Medium"),
        } for f in batch]
        try:
            items = gateway.call("llm_remediation_batch", findings=payload,
                                 excerpts=excerpts,
                                 batch_label=f"batch {index // batch_size + 1}")
            plan.extend(items)
        except (ToolError, ToolBudgetExceeded) as exc:
            errors.append({"agent": "remediation", "error": str(exc)[:300],
                           "at": _now()})
    proposals = _build_change_proposals(state, eligible, excerpts, gateway,
                                      record, errors)
    record["output_summary"] = {"actions": len(plan), "excluded": len(excluded),
                                "change_proposals": len(proposals)}
    updates: Dict[str, Any] = {"remediation_plan": plan, "excluded": excluded,
                               "change_proposals": proposals}
    if errors:
        updates["errors"] = errors
        if not plan and eligible:
            raise ToolError(errors[0]["error"])
        updates["_degraded"] = f"{len(errors)} remediation batch(es) failed."
    return updates


def _build_change_proposals(state, eligible, excerpts, gateway, record,
                              errors):
    """Deterministic proposal shells + validated model prose + simulation.

    Findings without an exact, unambiguous target are skipped with a
    recorded reason; prose or validation failures land in errors without
    affecting the remediation plan.
    """
    from common import changes as change_engine
    from common import kong_adapter
    kong_data = [s for s in state.get("kong_data", []) if isinstance(s, dict)]
    scope = list(state.get("service_names") or
                 [s.get("service_name") for s in kong_data
                  if s.get("service_name")])
    entry_by_finding: Dict[str, Dict[str, Any]] = {}
    for entry in state.get("risk", {}).get("register", []):
        if not isinstance(entry, dict):
            continue
        for source in entry.get("sources", []):
            fid = (source or {}).get("finding_id")
            if fid and fid not in entry_by_finding:
                entry_by_finding[fid] = entry
    shells = []
    skipped = 0
    for finding in eligible:
        proposal, error = change_engine.build_proposal(
            finding, kong_data, scope,
            assessment_id=state.get("assessment_id", "?"),
            entry=entry_by_finding.get(finding.get("finding_id", "")))
        if error:
            skipped += 1
            record["decisions"].append(
                {"decision": "change_skipped",
                 "finding_id": finding.get("finding_id"), "reason": error})
            continue
        shells.append((finding, proposal))
    if not shells:
        return []
    brief = [{
        "finding_id": input_validation.sanitize_for_prompt(f.get("finding_id")),
        "service": input_validation.sanitize_for_prompt(p["target"]["service"]),
        "plugin": input_validation.sanitize_for_prompt(p["plugin"]),
        "policy_name": input_validation.sanitize_for_prompt(f.get("policy_name")),
        "details": input_validation.sanitize_for_prompt(
            f.get("details", ""), max_len=1000),
        "current_plugins": p["current"]["service_plugins"],
    } for f, p in shells]
    try:
        prose_items = gateway.call("llm_change_prose_batch", items=brief,
                                   excerpts=excerpts, batch_label="changes")
    except (ToolError, ToolBudgetExceeded) as exc:
        errors.append({"agent": "remediation",
                       "error": f"change prose failed: {exc}"[:300],
                       "at": _now()})
        return []
    prose_by_id = {p.get("finding_id"): p for p in (prose_items or [])
                   if isinstance(p, dict)}
    proposals = []
    for finding, proposal in shells:
        fid = finding.get("finding_id")
        try:
            prose = prose_by_id.get(fid)
            if prose is None:
                raise ValueError("model returned no prose for this finding")
            prose = {k: v for k, v in prose.items() if k != "finding_id"}
            change_engine.attach_proposal_prose(proposal, prose)
            ok, reasons = change_engine.validate_proposal(proposal, scope)
            if not ok:
                raise ValueError("; ".join(reasons))
            report = kong_adapter.simulate(
                proposal, kong_data, entry_by_finding.get(fid or ""))
            proposal["residual_risk"] = report["residual_risk"]
            proposals.append(proposal)
        except ValueError as exc:
            errors.append({"agent": "remediation",
                           "error": f"{proposal['change_id']}: {exc}"[:300],
                           "at": _now()})
    record["decisions"].append({"decision": "changes_proposed",
                                "count": len(proposals), "skipped": skipped})
    return proposals


def remediation(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "remediation", _remediation_fn)


# --- validation ------------------------------------------------------------------------------
# Responsibility: deterministic finding/plan verification and coverage checks.
# Input:  enriched_findings, recovered_findings, remediation_plan, excluded.
# Output: validation {passed, checks[], orphans[], gaps[], mismatches[],
#          excluded[]}.
# Tools:  verify_finding.

def _validation_fn(state, gateway: ToolGateway, record):
    findings = [f for f in list(state.get("enriched_findings", [])) +
                list(state.get("recovered_findings", []))
                if isinstance(f, dict)]
    plan = state.get("remediation_plan", [])
    scope = state.get("selected_standards", [])
    context = state.get("policy_context", {})
    record["input_summary"] = {"findings": len(findings),
                               "actions": len(plan)}
    checks, orphans, gaps, mismatches = [], [], [], []
    planned = {(p.get("serviceName"), p.get("policyName")) for p in plan
               if isinstance(p, dict)}
    finding_keys = {(f.get("service"), f.get("policy_name")) for f in findings}
    for item in plan:
        if not isinstance(item, dict):
            continue
        key = (item.get("serviceName"), item.get("policyName"))
        if key not in finding_keys:
            orphans.append({"service": key[0], "policy": key[1],
                            "reason": "Plan item matches no aggregated finding."})
    checks.append({"check": "no_orphan_actions", "passed": not orphans,
                   "detail": f"{len(orphans)} orphan(s)"})
    for finding in findings:
        if finding.get("comply"):
            continue
        status = (finding.get("verification") or {}).get("status")
        key = (finding.get("service"), finding.get("policy_name"))
        if status == "contradictory":
            if key in planned:
                gaps.append({"finding_id": finding.get("finding_id"),
                             "reason": "Contradictory finding must not be planned."})
        elif key not in planned:
            gaps.append({"finding_id": finding.get("finding_id"),
                         "reason": "Verified finding has no remediation action."})
        # Independent re-verification: the attached record must reproduce
        # from the inventory and retrieved context.
        recheck = gateway.call(
            "verify_finding",
            policy={"policy_name": finding.get("policy_name"),
                    "comply": finding.get("comply"),
                    "missing_plugins": finding.get("missing_plugins"),
                    "details": finding.get("details")},
            service_plugins=finding.get("service_plugins", []),
            evidence_chunks=context.get(finding.get("service"), []),
            scope=scope,
        )
        if recheck["status"] != status:
            mismatches.append({
                "finding_id": finding.get("finding_id"),
                "reason": (f"Attached verification says '{status}' but an "
                           f"independent re-check says '{recheck['status']}'."),
            })
    checks.append({"check": "plan_coverage", "passed": not gaps,
                   "detail": f"{len(gaps)} gap(s)"})
    checks.append({"check": "verification_reproduces", "passed": not mismatches,
                   "detail": f"{len(mismatches)} mismatch(es)"})
    excluded = list(state.get("excluded", []))
    passed = not orphans and not gaps and not mismatches
    record["output_summary"] = {"passed": passed, "checks": len(checks)}
    record["decisions"].append({"decision": "plan_validated", "passed": passed})
    updates: Dict[str, Any] = {"validation": {
        "passed": passed, "checks": checks, "orphans": orphans, "gaps": gaps,
        "mismatches": mismatches, "excluded": excluded,
    }}
    if not passed:
        updates["_degraded"] = "Validation found orphans or coverage gaps."
    return updates


def validation(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "validation", _validation_fn)


# --- governance and approval -------------------------------------------------------------------
# Responsibility: human approval gate for the remediation plan. Nothing is
# executed against Kong: approval authorises export of the plan only.
# Input:  remediation_plan, risk, validation, degraded_reasons.
# Output: approval {request, decision, reviewer, note, decided_at}.
# Tools:  persist_artifact (audit trail of the approval request).

def _governance_fn(state, gateway: ToolGateway, record):
    plan = state.get("remediation_plan", [])
    assessment_id = state.get("assessment_id", "?")
    record["input_summary"] = {"actions": len(plan),
                               "validation_passed": state.get("validation", {}).get("passed")}
    if not plan:
        record["decisions"].append({"decision": "nothing_to_approve"})
        return {"approval": {
            "request": None,
            "decision": "nothing_to_approve",
            "reviewer": None,
            "note": "No remediation actions; approval not required.",
            "decided_at": _now(),
        }}
    by_severity: Dict[str, int] = {}
    for item in plan:
        key = str(item.get("severity", "Medium")).title()
        by_severity[key] = by_severity.get(key, 0) + 1
    request = {
        "assessment_id": assessment_id,
        "actions": len(plan),
        "by_severity": by_severity,
        "risk": state.get("risk", {}).get("by_level", {}),
        "validation_passed": state.get("validation", {}).get("passed"),
        "change_proposals": len(state.get("change_proposals", [])),
        "excluded": state.get("excluded", []),
        "degraded_reasons": list(state.get("degraded_reasons", [])),
        "objective": state.get("objective"),
        "tiers": {k: len(v) for k, v in (state.get("tiers") or {}).items()},
        "coverage_totals": (state.get("coverage") or {}).get("totals", {}),
        "note": ("Approval authorises export of this plan. Nothing is applied "
                 "to Kong by this workflow."),
    }
    gateway.call("persist_artifact", assessment_id=assessment_id,
                 name="approval_request", payload=request)
    record["decisions"].append({"decision": "approval_requested",
                                "actions": len(plan)})
    # Human-in-the-loop: execution pauses here until resumed with
    # Command(resume={"decision": "approve"|"reject", ...}).
    answer = interrupt(request)
    decision = str((answer or {}).get("decision", "")).lower()
    if decision not in ("approve", "reject"):
        record["decisions"].append({"decision": "invalid_answer_treated_as_reject",
                                    "received": answer})
        decision = "reject"
        note = f"Unrecognized approval answer {answer!r}; treated as reject."
    else:
        note = str((answer or {}).get("note", ""))
    record["output_summary"] = {"decision": decision}
    return {"approval": {
        "request": request,
        "decision": decision,
        "reviewer": (answer or {}).get("reviewer"),
        "note": note,
        "decided_at": _now(),
    }}


def governance(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "governance", _governance_fn, threaded=False)


# --- finalize -----------------------------------------------------------------------------------
# Responsibility: close the assessment, persist the full record, set status.
# Input:  whole state. Output: status=complete, artifact reference.
# Tools:  persist_artifact.

def _finalize_fn(state, gateway: ToolGateway, record):
    assessment_id = state.get("assessment_id", "?")
    degraded = bool(state.get("degraded_reasons") or state.get("errors"))
    summary = {
        "assessment_id": assessment_id,
        "run_id": state.get("run_id"),
        "status": "complete",
        "degraded": degraded,
        "degraded_reasons": list(state.get("degraded_reasons", [])),
        "selected_standards": state.get("selected_standards", []),
        "kong_source": state.get("kong_source"),
        "kong_live": state.get("kong_live"),
        "kong_stale": state.get("kong_stale"),
        "kong_snapshot_at": state.get("kong_snapshot_at"),
        "services": len(state.get("kong_data", [])),
        "findings": len(state.get("enriched_findings", [])),
        "recovered": len(state.get("recovered_findings", [])),
        "quarantined": len(state.get("quarantined", [])),
        "policy_findings": len(state.get("policy_findings", [])),
        "coverage": state.get("coverage", {}),
        "conflicts": len(state.get("conflicts", [])),
        "risk": state.get("risk", {}).get("by_level", {}),
        "plan_actions": len(state.get("remediation_plan", [])),
        "change_proposals": len(state.get("change_proposals", [])),
        "validation_passed": state.get("validation", {}).get("passed"),
        "approval": state.get("approval", {}).get("decision"),
        "budgets": state.get("budgets", {}),
        "objective": state.get("objective"),
        "depth": state.get("depth"),
        "plan_rationale": (state.get("plan") or {}).get("rationale", []),
        "tiers": {k: len(v) for k, v in (state.get("tiers") or {}).items()},
        "stopping": {
            "decision": (state.get("stopping") or {}).get("decision"),
            "rounds_used": (state.get("stopping") or {}).get("rounds_used"),
            "reasons": (state.get("stopping") or {}).get("reasons", []),
        },
        "agents": {name: {"status": rec.get("status"),
                          "ms": rec.get("duration_ms"),
                          "model": rec.get("model"),
                          "retries": rec.get("retries"),
                          "error": rec.get("error") or None}
                   for name, rec in state.get("agents", {}).items()},
    }
    saved = gateway.call("persist_artifact", assessment_id=assessment_id,
                         name="assessment", payload={
                             "summary": summary,
                             "trace": list(state.get("trace", [])),
                         })
    gateway.call("persist_artifact", assessment_id=assessment_id,
                 name="inventory", payload={
                     "assessment_id": assessment_id,
                     "kong_source": state.get("kong_source"),
                     "kong_live": state.get("kong_live"),
                     "kong_stale": state.get("kong_stale"),
                     "kong_snapshot_at": state.get("kong_snapshot_at"),
                     "kong_gaps": state.get("kong_gaps", []),
                     "inventory": state.get("kong_data", []),
                 })
    record["output_summary"] = {"artifact": saved["filename"], "degraded": degraded}
    summary["budgets"] = reconcile_budgets(state)
    return {"status": "complete", "degraded": degraded,
            "budgets": summary["budgets"],
            "assessment_summary": summary}


def finalize(state: Dict[str, Any]) -> Dict[str, Any]:
    return run_agent(state, "finalize", _finalize_fn)


def build_assessment_graph(checkpointer=None):
    """Compile the full supervisor-led assessment workflow."""
    graph = StateGraph(AssessmentState)
    graph.add_node("supervisor", supervisor_plan)
    graph.add_node("discovery", discovery)
    graph.add_node("dispatch", dispatch)
    graph.add_node("security_analysis", security_analysis)
    graph.add_node("compliance", compliance)
    graph.add_node("threat_model", threat_model)
    graph.add_node("aggregate", aggregate)
    graph.add_node("followup", followup)
    graph.add_node("evaluate", evaluate)
    graph.add_node("risk", risk)
    graph.add_node("remediation", remediation)
    graph.add_node("validation", validation)
    graph.add_node("governance", governance)
    graph.add_node("finalize", finalize)
    graph.set_entry_point("supervisor")
    graph.add_edge("supervisor", "discovery")
    graph.add_edge("discovery", "dispatch")
    graph.add_conditional_edges(
        "dispatch", route_investigators,
        {"security_analysis": "security_analysis",
         "compliance": "compliance",
         "threat_model": "threat_model",
         "aggregate": "aggregate"})
    graph.add_edge("security_analysis", "aggregate")
    graph.add_edge("compliance", "aggregate")
    graph.add_edge("threat_model", "aggregate")
    graph.add_edge("aggregate", "evaluate")
    graph.add_edge("followup", "evaluate")
    graph.add_conditional_edges(
        "evaluate", route_after_evidence,
        {"followup": "followup", "risk": "risk"})
    graph.add_edge("risk", "remediation")
    graph.add_edge("remediation", "validation")
    graph.add_edge("validation", "governance")
    graph.add_edge("governance", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile(checkpointer=checkpointer)


_ASSESSMENT_APP = None


def get_assessment_app():
    """Shared compiled workflow for the HTTP API, with an in-process
    checkpointer keyed by assessment_id (thread_id)."""
    global _ASSESSMENT_APP
    if _ASSESSMENT_APP is None:
        from langgraph.checkpoint.memory import MemorySaver
        _ASSESSMENT_APP = build_assessment_graph(checkpointer=MemorySaver())
    return _ASSESSMENT_APP
