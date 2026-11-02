"""
===============================================================================
 File Name   : init_auditor.py
 Description : Enterprise API Security Auditor API. Exposes the Audit and
               Remediate LangGraph agents over HTTP, plus health and artifact
               endpoints used by the React dashboard.
 Author      : Sachin Ghumbre
 Created On  : 2025-09-26
 Version     : v1.0.0
 License     : Proprietary
 Tags        : kong, konnect, genai, audit, langgraph, agentic ai
===============================================================================
"""

import json
import os
import sys
import uuid

from flask import Flask, jsonify, request
from flask_cors import CORS

# Allow `python agents/init_auditor.py` from any working directory. The original
# `from auditor_agent import ...` only resolved when the process was started from
# inside backend/agents/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, llm, vector_store  # noqa: E402
from agents import auditor_agent  # noqa: E402

API_PREFIX = "/api/v1/ai-agents"
AUDIT_ROUTE = f"{API_PREFIX}/audit"
REMEDIATE_ROUTE = f"{API_PREFIX}/remediate"
SERVICE_PORT = config.get_int("AGENTS_PORT", 5000)

app = Flask(__name__)
# Reject payload bombs before JSON parsing (Flask answers 413).
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
CORS(app, origins=config.ALLOWED_ORIGINS or "*")


# Role-based access: viewer reads, operator runs/approves/simulates,
# admin additionally executes live changes. Open when no API keys are
# configured (single-user default).
AUTH_RULES = [
    ({"GET"}, f"{API_PREFIX}/health", None),
    ({"POST"}, f"{API_PREFIX}/assess", "operator"),
    ({"POST"}, f"{API_PREFIX}/audit", "operator"),
    ({"POST"}, f"{API_PREFIX}/remediate", "operator"),
    ({"GET"}, API_PREFIX, "viewer"),
    ({"POST"}, API_PREFIX, "operator"),
]


@app.before_request
def _enforce_auth():
    from common import auth as auth_mod
    from flask import request as flask_request
    return auth_mod.guard(flask_request, AUTH_RULES)


def _load_artifact(path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


@app.route(f"{API_PREFIX}/health", methods=["GET"])
def health():
    """Readiness probe. Reports which dependencies are degraded but still
    returns 200 when the agents can run, since Kong and the vector store both
    have documented fallbacks."""
    problems = llm.check_config()
    warnings = []

    redis_ok = vector_store.ping()
    index_ok = redis_ok and vector_store.index_exists()
    if not redis_ok:
        warnings.append(
            f"Redis unreachable at {config.REDIS_HOST}:{config.REDIS_PORT}; "
            "the audit will run without policy grounding."
        )
    elif not index_ok:
        warnings.append(
            "Policy vector index missing; run POST /api/v1/knowledge/ingest on port 5001."
        )

    kong_ok = False
    kong_services = 0
    if config.KONG_ADMIN_API:
        try:
            kong_services = len(auditor_agent.fetch_kong_data("services"))
            kong_ok = True
        except Exception as exc:
            warnings.append(
                f"Kong {config.resolve_kong_mode()} Admin API unreachable ({str(exc)[:200]}); "
                "the audit will fall back to the cached inventory in "
                "agents/filtered_kong_data.json."
            )
    else:
        warnings.append("KONG_ADMIN_API is not set; cached inventory will be used.")

    return jsonify({
        "service": "ai-agents",
        "status": "ok" if not problems else "degraded",
        "problems": problems,
        "warnings": warnings,
        "dependencies": {
            "llm_provider": llm.provider(),
            "llm_model": llm.model_name(),
            "redis_reachable": redis_ok,
            "policy_index": index_ok,
            "policy_chunks": vector_store.count_chunks() if redis_ok else 0,
            "kong_admin_reachable": kong_ok,
            "kong_mode": config.resolve_kong_mode(),
            "kong_services": kong_services,
        },
        "config": config.summary(),
    }), (200 if not problems else 503)


@app.route(f"{API_PREFIX}/models", methods=["GET"])
def list_models():
    """Model ids the configured Meta API key can use.

    Use this to resolve a `model_not_found` error: META_MODEL must be one of the
    ids returned here.
    """
    try:
        models = llm.list_models()
        return jsonify({
            "provider": llm.provider(),
            "base_url": config.META_BASE_URL,
            "configured_model": config.META_MODEL,
            "configured_model_available": config.META_MODEL in models,
            "count": len(models),
            "models": models,
        }), 200
    except Exception as exc:
        return jsonify({
            "error": str(exc),
            "provider": llm.provider(),
            "configured_model": config.META_MODEL,
        }), 502


@app.route(f"{API_PREFIX}/kong/services", methods=["GET"])
def kong_services():
    """Kong inventory the audit will run against, with its provenance.

    Resolves live -> Redis snapshot -> cached file. The `live`/`stale`
    flags and `snapshot_at` state exactly what the data is; cached data is
    never presented as a live assessment.
    """
    from common import kong_inventory
    try:
        report = kong_inventory.collect_report()
        try:
            saved = kong_inventory.save_snapshot(
                report["inventory"], "kong_admin_api",
                gaps=report["gaps"])
            snapshot_at = saved["captured_at"]
        except kong_inventory.KongSnapshotError:
            snapshot_at = None
        return jsonify({
            "source": f"kong_{config.resolve_kong_mode()}",
            "kong_mode": config.resolve_kong_mode(),
            "live": True,
            "stale": False,
            "snapshot_at": snapshot_at,
            "gaps": report["gaps"],
            "count": len(report["inventory"]),
            "services": report["inventory"],
        }), 200
    except Exception as exc:
        snapshot, freshness = kong_inventory.load_snapshot()
        if snapshot is not None:
            return jsonify({
                "source": "redis_snapshot",
                "kong_mode": config.resolve_kong_mode(),
                "live": False,
                "stale": bool((freshness or {}).get("stale", True)),
                "snapshot_at": snapshot.get("captured_at"),
                "gaps": snapshot.get("gaps", []),
                "warning": f"Kong Admin API unreachable ({exc}); served the "
                           "Redis snapshot instead of live data.",
                "count": len(snapshot["inventory"]),
                "services": snapshot["inventory"],
            }), 200
        cached = _load_artifact(auditor_agent.FALLBACK_KONG_DATA, [])
        return jsonify({
            "source": "cached_file",
            "live": False,
            "stale": True,
            "snapshot_at": None,
            "gaps": [],
            "warning": f"Kong Admin API unreachable: {exc}",
            "count": len(cached),
            "services": cached,
        }), 200


@app.route(AUDIT_ROUTE, methods=["POST"])
def run_audit():
    """Invoke the Audit Agent.

    Body (all optional):
        selected_standards : list of standards to audit against
        kong_data          : inventory override, skips the Kong Admin API
        service_names      : audit only these Kong services
        top_k              : policy chunks to retrieve per service
    """
    from common import validation
    payload = request.get_json(silent=True) or {}

    try:
        standards = validation.coerce_name_list(
            payload.get("selected_standards"), "selected_standards")
        service_names = validation.coerce_name_list(
            payload.get("service_names"), "service_names")
        top_k = (validation.coerce_top_k(payload.get("top_k"))
                 if payload.get("top_k") is not None else None)
        kong_data = payload.get("kong_data")
        if kong_data is not None and not isinstance(kong_data, list):
            raise ValueError("'kong_data' must be a list.")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    state = {"selected_standards": standards or ["All Security Standards"]}
    if kong_data:
        state["kong_data"] = kong_data
    if service_names:
        state["service_names"] = service_names
    if top_k is not None:
        state["top_k"] = top_k

    try:
        result = auditor_agent.audit_app.invoke(state)
        return jsonify({
            "audit_report": result.get("audit_report", {}),
            "summary": result.get("summary", {}),
            "selected_standards": standards,
            "kong_source": result.get("kong_source"),
            "provenance": auditor_agent.build_audit_provenance(result),
            "warnings": [w for w in (result.get("kong_warning"), result.get("rag_warning")) if w],
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route(REMEDIATE_ROUTE, methods=["POST"])
def run_remediation():
    """Invoke the Remediation Agent with an audit report.

    Accepts {"audit_report": {...}}. When omitted, falls back to the last audit
    report written to disk so the endpoint is usable standalone.
    """
    payload = request.get_json(silent=True) or {}
    audit_report = payload.get("audit_report")

    if not audit_report:
        audit_report = _load_artifact(auditor_agent.AUDIT_REPORT_FILE, None)
        if not audit_report:
            return jsonify({
                "error": "Missing 'audit_report' in request body and no saved report found. "
                         f"Run POST {AUDIT_ROUTE} first."
            }), 400

    try:
        result = auditor_agent.rem_app.invoke({"audit_report": audit_report})
        plan = result.get("remediation_plan", [])

        # The dashboard renders the array directly; ?envelope=true returns the
        # richer object with summary and error detail.
        if request.args.get("envelope", "false").lower() == "true":
            return jsonify({
                "remediation_plan": plan,
                "summary": result.get("summary", {}),
                "findings_count": len(result.get("findings", [])),
                "note": result.get("remediation_note"),
                "error": result.get("remediation_error"),
            }), 200
        return jsonify(plan), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route(f"{API_PREFIX}/audit/report", methods=["GET"])
def last_audit_report():
    """Most recent audit report written by the Audit Agent."""
    report = _load_artifact(auditor_agent.AUDIT_REPORT_FILE, None)
    if report is None:
        return jsonify({"error": "No audit report found. Run the audit first."}), 404
    summary = _load_artifact(auditor_agent.AUDIT_SUMMARY_FILE, None)
    payload = {"audit_report": report}
    if isinstance(summary, dict):
        # Additive only: old clients keep reading audit_report as before.
        payload["summary"] = summary.get("summary")
        payload["provenance"] = summary.get("provenance")
    return jsonify(payload), 200


@app.route(f"{API_PREFIX}/remediate/plan", methods=["GET"])
def last_remediation_plan():
    """Most recent remediation plan written by the Remediation Agent."""
    plan = _load_artifact(auditor_agent.REMEDIATION_PLAN_FILE, None)
    if plan is None:
        return jsonify({"error": "No remediation plan found. Run remediation first."}), 404
    return jsonify(plan), 200


def _assessment_config(assessment_id):
    return {"configurable": {"thread_id": f"assessment-{assessment_id}"}}


def _assessment_response(assessment_id, result):
    """Shape a workflow result for HTTP. Pending approval -> 202, else 200."""
    pending = (result.get("__interrupt__") or [None])[0]
    body = {"assessment_id": assessment_id,
            "status": result.get("status", "running")}
    if pending is not None:
        body["status"] = "awaiting_approval"
        body["approval_request"] = pending.value
        return jsonify(body), 202
    if result.get("assessment_summary"):
        body["summary"] = result["assessment_summary"]
    return jsonify(body), 200


_ASYNC_THREADS = {}
_ASYNC_ERRORS = {}
_ASSESSMENT_INDEX = {}


def _utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _run_assessment_async(assessment_id, state, invoke_config):
    """Background invoke for ?async=true starts. Failures land in
    _ASYNC_ERRORS so status polling can report them."""
    from agents import orchestrator
    try:
        orchestrator.get_assessment_app().invoke(state, invoke_config)
    except Exception as exc:  # noqa: BLE001 - captured for polling
        _ASYNC_ERRORS[assessment_id] = {"error": str(exc)[:500],
                                        "at": _utcnow()}
    finally:
        _ASYNC_THREADS.pop(assessment_id, None)


def _register_assessment(assessment_id):
    _ASSESSMENT_INDEX[assessment_id] = {
        "assessment_id": assessment_id,
        "started_at": _utcnow(),
    }
    while len(_ASSESSMENT_INDEX) > 100:
        _ASSESSMENT_INDEX.pop(next(iter(_ASSESSMENT_INDEX)))


@app.route(f"{API_PREFIX}/assess", methods=["POST"])
def start_assessment():
    """Run the supervisor-led multi-agent assessment.

    Body (all optional): selected_standards, service_names, top_k,
    objective, priority_services, depth (quick|standard|deep),
    risk_scoring (weights/blend/threshold overrides for the versioned model),
    assessment_id (generated when omitted; reused as the resume thread).
    Pauses with 202 + approval_request at the governance gate.
    With ?async=true the run starts on a background thread and this returns
    immediately with {"status": "running"}; poll GET assess/<id> (and
    /details) until it pauses or completes.
    """
    from agents import orchestrator
    from agents.tools import safe_assessment_id
    from common import validation
    payload = request.get_json(silent=True) or {}
    try:
        assessment_id = safe_assessment_id(
            payload.get("assessment_id") or f"asm-{uuid.uuid4().hex[:12]}")
        state = {"assessment_id": assessment_id}
        standards = validation.coerce_name_list(
            payload.get("selected_standards"), "selected_standards")
        if standards:
            state["selected_standards"] = standards
        names = validation.coerce_name_list(
            payload.get("service_names"), "service_names")
        if names:
            state["service_names"] = names
        if payload.get("top_k") is not None:
            state["top_k"] = validation.coerce_top_k(payload.get("top_k"))
        if payload.get("objective") is not None:
            state["objective"] = validation.coerce_text(
                payload.get("objective"), "objective",
                max_len=validation.MAX_OBJECTIVE_CHARS)
        priority = validation.coerce_name_list(
            payload.get("priority_services"), "priority_services")
        if priority:
            state["priority_services"] = priority
        if payload.get("depth") is not None:
            state["depth"] = validation.coerce_depth(payload.get("depth"))
        scoring = validation.coerce_scoring(payload.get("risk_scoring"))
        if scoring is not None:
            state["risk_scoring"] = scoring
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        existing = orchestrator.get_assessment_app().get_state(
            _assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    if existing.values:
        from common import audit_log
        audit_log.record("assessment.rejected", assessment_id=assessment_id,
                         details={"reason": "id_reuse"})
        return jsonify({"error": f"Assessment '{assessment_id}' already "
                                 "exists; resume it or start a new id."}), 409
    from common import audit_log
    _register_assessment(assessment_id)
    if request.args.get("async") == "true":
        import threading
        thread = threading.Thread(
            target=_run_assessment_async,
            args=(assessment_id, state,
                  _assessment_config(assessment_id)),
            daemon=True)
        _ASYNC_THREADS[assessment_id] = thread
        thread.start()
        audit_log.record(
            "assessment.started", assessment_id=assessment_id,
            details={"standards": state.get("selected_standards", []),
                     "depth": state.get("depth", "standard"),
                     "mode": "async"})
        return jsonify({"assessment_id": assessment_id,
                        "status": "running"}), 202
    try:
        result = orchestrator.get_assessment_app().invoke(
            state, _assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    audit_log.record("assessment.started", assessment_id=assessment_id,
                     details={"standards": state.get("selected_standards", []),
                              "depth": state.get("depth", "standard"),
                              "mode": "sync"})
    return _assessment_response(assessment_id, result)


@app.route(f"{API_PREFIX}/assess/<assessment_id>", methods=["GET"])
def assessment_status(assessment_id):
    """Current snapshot of an assessment, including any pending approval."""
    from agents import orchestrator
    try:
        snapshot = orchestrator.get_assessment_app().get_state(
            _assessment_config(assessment_id))
    except Exception as exc:
        if assessment_id in _ASYNC_ERRORS:
            return jsonify({"assessment_id": assessment_id,
                            "status": "failed",
                            "error": _ASYNC_ERRORS[assessment_id]["error"]}), 200
        return jsonify({"error": str(exc)}), 500
    values = snapshot.values or {}
    if not values and assessment_id not in _ASYNC_ERRORS:
        if assessment_id in _ASSESSMENT_INDEX:
            return jsonify({"assessment_id": assessment_id,
                            "status": "running"}), 200
        return jsonify({"error": f"No assessment '{assessment_id}' found."}), 404
    if assessment_id in _ASYNC_ERRORS and not values.get("status"):
        return jsonify({"assessment_id": assessment_id, "status": "failed",
                        "error": _ASYNC_ERRORS[assessment_id]["error"]}), 200
    body = {
        "assessment_id": assessment_id,
        "status": values.get("status", "running"),
        "agents": {name: {"status": (rec or {}).get("status")}
                   for name, rec in (values.get("agents") or {}).items()},
        "budgets": values.get("budgets", {}),
        "kong": {
            "source": values.get("kong_source"),
            "live": values.get("kong_live"),
            "stale": values.get("kong_stale"),
            "snapshot_at": values.get("kong_snapshot_at"),
            "services": len(values.get("kong_data", []) or []),
        },
    }
    for task in snapshot.tasks or []:
        interrupts = getattr(task, "interrupts", None) or []
        if interrupts:
            body["status"] = "awaiting_approval"
            body["approval_request"] = interrupts[0].value
    if values.get("assessment_summary"):
        body["summary"] = values["assessment_summary"]
    risk = values.get("risk") or {}
    if risk.get("register"):
        body["risk_register"] = {
            "scoring_model": risk.get("scoring_model"),
            "by_state": (risk.get("summary") or {}).get("by_state", {}),
            "entries": [{"entry_id": e.get("entry_id"),
                         "level": e.get("level"), "score": e.get("score"),
                         "state": e.get("state")}
                        for e in risk["register"]],
        }
    return jsonify(body), 200


@app.route(f"{API_PREFIX}/assess/<assessment_id>/resume", methods=["POST"])
def resume_assessment(assessment_id):
    """Answer the governance gate: {"decision": "approve"|"reject",
    "reviewer"?, "note"?}. Approval authorises plan export only."""
    from langgraph.types import Command
    from agents import orchestrator
    from common import validation
    payload = request.get_json(silent=True) or {}
    try:
        reviewer = validation.coerce_text(
            payload.get("reviewer"), "reviewer",
            max_len=validation.MAX_REVIEWER_CHARS)
        note = validation.coerce_text(payload.get("note"), "note")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    running = _ASYNC_THREADS.get(assessment_id)
    if running is not None and running.is_alive():
        return jsonify({"error": f"Assessment '{assessment_id}' is still "
                                 "running; resume once it pauses for "
                                 "approval."}), 409
    try:
        result = orchestrator.get_assessment_app().invoke(
            Command(resume={"decision": payload.get("decision"),
                            "reviewer": reviewer or None,
                            "note": note or None}),
            _assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    from common import audit_log
    audit_log.record("assessment.resumed", assessment_id=assessment_id,
                     details={"decision": payload.get("decision"),
                              "reviewer": reviewer or None})
    return _assessment_response(assessment_id, result)


@app.route(f"{API_PREFIX}/assess/<assessment_id>/risk/<entry_id>/transition",
           methods=["POST"])
def transition_risk_entry(assessment_id, entry_id):
    """Move a risk register entry through its lifecycle.

    Body: {"to_state": "accepted"|"mitigated"|"remediated"|"open",
    "actor"?, "note"?}. Invalid transitions return 400 naming the allowed
    next states. The register is rewritten through the workflow
    checkpointer so snapshots and resume stay consistent.
    """
    import copy
    from common import risks
    from agents import orchestrator
    from common import validation
    payload = request.get_json(silent=True) or {}
    to_state = str(payload.get("to_state", ""))
    try:
        actor = validation.coerce_text(
            payload.get("actor"), "actor",
            max_len=validation.MAX_REVIEWER_CHARS)
        note = validation.coerce_text(payload.get("note"), "note")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        workflow = orchestrator.get_assessment_app()
        snapshot = workflow.get_state(_assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    values = snapshot.values or {}
    if not values:
        return jsonify({"error": f"No assessment '{assessment_id}' found."}), 404
    risk = values.get("risk") or {}
    register = [copy.deepcopy(e) for e in risk.get("register", [])]
    entry = next((e for e in register if e.get("entry_id") == entry_id), None)
    if entry is None:
        return jsonify({"error": f"No register entry '{entry_id}'."}), 404
    try:
        risks.transition(entry, to_state, actor=actor or None,
                         note=note)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    updated = {**risk, "register": register,
               "summary": risks.summarize_register(register)}
    try:
        workflow.update_state(_assessment_config(assessment_id),
                              {"risk": updated})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    from common import audit_log
    audit_log.record("risk.transition", assessment_id=assessment_id,
                     details={"entry_id": entry_id,
                              "to_state": entry.get("state")})
    return jsonify({"assessment_id": assessment_id, "entry": entry,
                    "summary": updated["summary"]}), 200


@app.route(f"{API_PREFIX}/assess/<assessment_id>/changes", methods=["GET"])
def list_changes(assessment_id):
    """Structured change proposals for an assessment (simulated, unexecuted)."""
    from agents import orchestrator
    try:
        snapshot = orchestrator.get_assessment_app().get_state(
            _assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    values = snapshot.values or {}
    if not values:
        return jsonify({"error": f"No assessment '{assessment_id}' found."}), 404
    return jsonify({"assessment_id": assessment_id,
                    "change_proposals": values.get("change_proposals", [])}), 200


@app.route(f"{API_PREFIX}/assess/<assessment_id>/changes/<change_id>/approve",
           methods=["POST"])
def approve_change(assessment_id, change_id):
    """Record a human approval for one change proposal.

    Body: {"reviewer" (required), "note"?}. Only proposed changes can be
    approved; approval authorises execution, it does not execute.
    """
    import copy
    from common import changes as change_engine
    from agents import orchestrator
    from common import validation
    payload = request.get_json(silent=True) or {}
    try:
        reviewer = validation.coerce_text(
            payload.get("reviewer"), "reviewer",
            max_len=validation.MAX_REVIEWER_CHARS)
        note = validation.coerce_text(payload.get("note"), "note")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        workflow = orchestrator.get_assessment_app()
        snapshot = workflow.get_state(_assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    values = snapshot.values or {}
    if not values:
        return jsonify({"error": f"No assessment '{assessment_id}' found."}), 404
    proposals = [copy.deepcopy(p)
                 for p in values.get("change_proposals", [])]
    proposal = next((p for p in proposals
                     if p.get("change_id") == change_id), None)
    if proposal is None:
        return jsonify({"error": f"No change '{change_id}'."}), 404
    try:
        change_engine.approve(proposal, reviewer, note=note)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        workflow.update_state(_assessment_config(assessment_id),
                              {"change_proposals": proposals})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    from common import audit_log
    audit_log.record("change.approved", assessment_id=assessment_id,
                     details={"change_id": change_id,
                              "reviewer": reviewer or None})
    return jsonify({"assessment_id": assessment_id,
                    "proposal": proposal}), 200


@app.route(f"{API_PREFIX}/assess/<assessment_id>/changes/<change_id>/execute",
           methods=["POST"])
def execute_change(assessment_id, change_id):
    """Simulate (default) or live-execute one change proposal.

    Body: {"mode": "simulate"|"live"}. Simulation never touches the gateway.
    Live execution requires a recorded approval and KONG_WRITE_ENABLED=true;
    every refusal and failure is persisted on the proposal before responding.
    """
    import copy
    from common import audit_log, kong_adapter
    from agents import orchestrator
    payload = request.get_json(silent=True) or {}
    mode = str(payload.get("mode", "simulate")).lower()
    if mode not in ("simulate", "live"):
        return jsonify({"error": "mode must be 'simulate' or 'live'."}), 400
    from common import auth as auth_mod
    if not auth_mod.live_execution_permitted(mode):
        return jsonify({"error": "Live execution requires the admin role."}), 403
    try:
        workflow = orchestrator.get_assessment_app()
        snapshot = workflow.get_state(_assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    values = snapshot.values or {}
    if not values:
        return jsonify({"error": f"No assessment '{assessment_id}' found."}), 404
    proposals = [copy.deepcopy(p)
                 for p in values.get("change_proposals", [])]
    proposal = next((p for p in proposals
                     if p.get("change_id") == change_id), None)
    if proposal is None:
        return jsonify({"error": f"No change '{change_id}'."}), 404
    kong_data = values.get("kong_data", [])

    def _persist():
        workflow.update_state(_assessment_config(assessment_id),
                              {"change_proposals": proposals})

    if mode == "simulate":
        entry = None
        wanted = set(proposal.get("entry_ids", []))
        for candidate in (values.get("risk", {}) or {}).get("register", []):
            if isinstance(candidate, dict) and candidate.get("entry_id") in wanted:
                entry = candidate
                break
        report = kong_adapter.simulate(proposal, kong_data, entry)
        proposal["residual_risk"] = report["residual_risk"]
        try:
            _persist()
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        audit_log.record("change.simulated", assessment_id=assessment_id,
                         details={"change_id": change_id,
                                  "ok": report.get("ok")})
        return jsonify({"assessment_id": assessment_id,
                        "simulation": report}), 200
    scope = list(values.get("service_names") or
                 [s.get("service_name") for s in kong_data
                  if isinstance(s, dict) and s.get("service_name")])
    def _refused(reason):
        audit_log.record("change.execution_refused",
                         assessment_id=assessment_id,
                         details={"change_id": change_id, "reason": reason})

    try:
        kong_adapter.execute(proposal, scope)
    except kong_adapter.KongNotApproved as exc:
        _persist()
        _refused("not_approved")
        return jsonify({"error": str(exc), "proposal": proposal}), 403
    except kong_adapter.KongWritesDisabled as exc:
        _persist()
        _refused("writes_disabled")
        return jsonify({"error": str(exc), "proposal": proposal}), 409
    except kong_adapter.KongOutOfScope as exc:
        _persist()
        _refused("out_of_scope")
        return jsonify({"error": str(exc), "proposal": proposal}), 400
    except kong_adapter.KongInvalid as exc:
        _persist()
        _refused("invalid")
        return jsonify({"error": str(exc), "proposal": proposal}), 400
    except kong_adapter.KongAdapterError as exc:
        _persist()
        _refused("gateway_error")
        return jsonify({"error": str(exc), "proposal": proposal}), 502
    try:
        _persist()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    audit_log.record("change.executed", assessment_id=assessment_id,
                     details={"change_id": change_id,
                              "status": proposal.get("status")})
    return jsonify({"assessment_id": assessment_id,
                    "proposal": proposal}), 200


@app.route(f"{API_PREFIX}/assess", methods=["GET"])
def list_assessments():
    """Recent assessments, newest first (in-memory index, capped at 100)."""
    from agents import orchestrator
    items = []
    for assessment_id, meta in reversed(list(_ASSESSMENT_INDEX.items())):
        try:
            snapshot = orchestrator.get_assessment_app().get_state(
                _assessment_config(assessment_id))
            values = snapshot.values or {}
            status = values.get("status", "running")
            for task in snapshot.tasks or []:
                if getattr(task, "interrupts", None):
                    status = "awaiting_approval"
        except Exception:
            status = "unknown"
        items.append({"assessment_id": assessment_id,
                      "started_at": meta.get("started_at"),
                      "status": status})
    return jsonify({"assessments": items[:50]}), 200


@app.route(f"{API_PREFIX}/assess/<assessment_id>/details", methods=["GET"])
def assessment_details(assessment_id):
    """Full execution snapshot for the investigation dashboard: agent
    records, plan, stopping decision, tiers, findings, threats, trace."""
    from agents import orchestrator
    try:
        snapshot = orchestrator.get_assessment_app().get_state(
            _assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    values = snapshot.values or {}
    if not values:
        return jsonify({"error": f"No assessment '{assessment_id}' found."}), 404
    pending = []
    for task in snapshot.tasks or []:
        for interrupt in getattr(task, "interrupts", None) or []:
            pending.append(interrupt.value)
    return jsonify({"assessment_id": assessment_id,
                    "pending_interrupts": pending,
                    "state": values}), 200


@app.route(f"{API_PREFIX}/llm/policy", methods=["GET"])
def llm_policy():
    """Model-routing policy: task -> provider/model/fallback, as enforced."""
    from common import router
    return jsonify({
        "provider": config.resolve_llm_provider(),
        "model": llm.model_name(),
        "meta_only_enforced": config.META_ONLY,
        "tasks": router.TASK_POLICY,
    }), 200


@app.route(f"{API_PREFIX}/eval/retrieval", methods=["GET"])
def eval_retrieval():
    """Run retrieval relevance eval (?store=fake|redis, default fake).

    Fake store is offline and deterministic; redis scores the live index
    (ingest first). No LLM involved: hit@k and MRR only.
    """
    from eval import run_retrieval_eval
    store = (request.args.get("store") or "fake").lower()
    if store not in ("fake", "redis"):
        return jsonify({"error": "store must be 'fake' or 'redis'."}), 400
    try:
        with open(run_retrieval_eval.TASKS_PATH, encoding="utf-8") as handle:
            import json as _json
            tasks = _json.load(handle)
        backend_store = (run_retrieval_eval.RedisStore()
                         if store == "redis"
                         else run_retrieval_eval.FakeStore())
        summary = run_retrieval_eval.run(tasks, backend_store)
    except Exception as exc:
        return jsonify({"error": str(exc)[:500]}), 500
    summary["store"] = store
    return jsonify(summary), 200


@app.route(f"{API_PREFIX}/llm/calls", methods=["GET"])
def llm_calls():
    """Recent model-router call records: model, task, latency, token usage,
    retries and fallback events. Prompt/response bodies are never logged."""
    from common import router as model_router
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        return jsonify({"error": "'limit' must be an integer."}), 400
    calls = model_router.get_call_log(limit if limit > 0 else None)
    return jsonify({"count": len(calls), "calls": calls}), 200


@app.route(f"{API_PREFIX}/assess/<assessment_id>/executive-summary", methods=["POST"])
def executive_summary(assessment_id):
    """On-demand board-ready summary for a completed assessment.

    Makes two budgeted router calls (risk reasoning, then executive
    explanation) over verified findings only. The register and the plan
    stay deterministic; the model only explains them.
    """
    from common import router as model_router
    from agents import orchestrator
    try:
        snapshot = orchestrator.get_assessment_app().get_state(
            _assessment_config(assessment_id))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    values = snapshot.values or {}
    if not values:
        return jsonify({"error": f"No assessment '{assessment_id}' found."}), 404
    if values.get("status") != "complete":
        return jsonify({"error": "Assessment is not complete.",
                        "status": values.get("status")}), 409

    summary = values.get("assessment_summary", {})
    from common import validation
    entries = (values.get("risk", {}) or {}).get("register", [])[:10]
    risk_lines = "\n".join(
        f"- {validation.sanitize_for_prompt(e.get('entry_id'))}: "
        f"{validation.sanitize_for_prompt(e.get('title'))} "
        f"[{e.get('level')}, score {e.get('score')}] "
        f"(severity {e.get('severity')}, confidence {e.get('confidence')}, "
        f"verified {e.get('verified')})" for e in entries
    ) or "(no register entries)"
    context = (
        f"Services: {summary.get('services')}, findings: {summary.get('findings')}, "
        f"quarantined: {summary.get('quarantined')}, "
        f"plan actions: {summary.get('plan_actions')}, "
        f"validation passed: {summary.get('validation_passed')}, "
        f"degraded: {summary.get('degraded')}"
    )
    try:
        risk_response = model_router.run(
            model_router.RISK_REASONING,
            [{"role": "system", "content": (
                "You explain API security risk to a security lead. Use only "
                "the findings given; do not invent new ones. Plain text.")},
             {"role": "user", "content": (
                f"Explain why these are the top risks:\n{risk_lines}")}],
            expect="text", max_tokens=800)
        exec_response = model_router.run(
            model_router.EXECUTIVE_EXPLANATION,
            [{"role": "system", "content": (
                "You write board-ready security summaries. Three short "
                "paragraphs: posture, top risks, recommended next step. Use "
                "only the evidence given. Plain text.")},
             {"role": "user", "content": (
                f"Assessment: {context}\n\nRisk analysis:\n{risk_response.text}")}],
            expect="text", max_tokens=1200)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502
    return jsonify({
        "assessment_id": assessment_id,
        "risk_narrative": risk_response.text,
        "executive_summary": exec_response.text,
        "calls": [risk_response.to_dict(), exec_response.to_dict()],
    }), 200


if __name__ == "__main__":
    print(f"[ai-agents] env       : {config.ENV_PATH}")
    print(f"[ai-agents] llm       : {llm.provider()} -> {llm.model_name()}")
    print(f"[ai-agents] kong      : {config.resolve_kong_mode()} -> {config.KONG_ADMIN_API}")
    print(f"[ai-agents] artifacts : {config.ARTIFACT_DIR}")
    print(f"[ai-agents] listening : http://localhost:{SERVICE_PORT}{API_PREFIX}")
    app.run(host="0.0.0.0", port=SERVICE_PORT, debug=False)
