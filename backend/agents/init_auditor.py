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
CORS(app)


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
    """Kong inventory the audit will run against, with its provenance."""
    try:
        inventory = auditor_agent.collect_kong_inventory()
        return jsonify({
            "source": f"kong_{config.resolve_kong_mode()}",
            "kong_mode": config.resolve_kong_mode(),
            "count": len(inventory),
            "services": inventory,
        }), 200
    except Exception as exc:
        cached = _load_artifact(auditor_agent.FALLBACK_KONG_DATA, [])
        return jsonify({
            "source": "cached_file",
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
    payload = request.get_json(silent=True) or {}

    standards = payload.get("selected_standards") or ["All Security Standards"]
    if isinstance(standards, str):
        standards = [standards]

    service_names = payload.get("service_names")
    if isinstance(service_names, str):
        service_names = [service_names]

    state = {"selected_standards": standards}
    if payload.get("kong_data"):
        state["kong_data"] = payload["kong_data"]
    if service_names:
        state["service_names"] = service_names
    if payload.get("top_k"):
        state["top_k"] = payload["top_k"]

    try:
        result = auditor_agent.audit_app.invoke(state)
        return jsonify({
            "audit_report": result.get("audit_report", {}),
            "summary": result.get("summary", {}),
            "selected_standards": standards,
            "kong_source": result.get("kong_source"),
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
    return jsonify({"audit_report": report}), 200


@app.route(f"{API_PREFIX}/remediate/plan", methods=["GET"])
def last_remediation_plan():
    """Most recent remediation plan written by the Remediation Agent."""
    plan = _load_artifact(auditor_agent.REMEDIATION_PLAN_FILE, None)
    if plan is None:
        return jsonify({"error": "No remediation plan found. Run remediation first."}), 404
    return jsonify(plan), 200


if __name__ == "__main__":
    print(f"[ai-agents] env       : {config.ENV_PATH}")
    print(f"[ai-agents] llm       : {llm.provider()} -> {llm.model_name()}")
    print(f"[ai-agents] kong      : {config.resolve_kong_mode()} -> {config.KONG_ADMIN_API}")
    print(f"[ai-agents] artifacts : {config.ARTIFACT_DIR}")
    print(f"[ai-agents] listening : http://localhost:{SERVICE_PORT}{API_PREFIX}")
    app.run(host="0.0.0.0", port=SERVICE_PORT, debug=False)
