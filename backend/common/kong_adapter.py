"""
===============================================================================
 File Name   : common/kong_adapter.py
 Description : Restricted Kong write adapter for approved remediation changes.
               The ONLY code path that may mutate gateway configuration, and it
               refuses unless every gate holds: the proposal validates, the
               target is in scope, a human approval is recorded, and
               KONG_WRITE_ENABLED=true. Only allowlisted plugin operations on
               explicit service/route targets are possible; there is no shell,
               no arbitrary HTTP and no delete of services, routes or
               consumers. simulate() shows the expected effect of a proposal
               against an inventory copy without touching live resources.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from common import changes, config


class KongAdapterError(RuntimeError):
    """Base for all adapter refusals and failures."""


class KongNotApproved(KongAdapterError):
    """Execution attempted without a recorded human approval."""


class KongOutOfScope(KongAdapterError):
    """Target is outside the assessment scope."""


class KongInvalid(KongAdapterError):
    """Proposal failed deterministic validation."""


class KongWritesDisabled(KongAdapterError):
    """Live execution attempted while KONG_WRITE_ENABLED is not true."""


class KongOpFailed(KongAdapterError):
    """The gateway call failed; the execution record carries the detail."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _default_http(method, url, headers, payload):
    """Minimal requests wrapper. Only POST/GET/DELETE to adapter-built URLs."""
    import requests
    if method not in ("POST", "GET", "DELETE"):
        raise KongAdapterError(f"HTTP method {method!r} is not allowlisted")
    response = requests.request(
        method, url, headers=headers, json=payload,
        verify=config.KONG_ADMIN_VERIFY_SSL,
        timeout=config.KONG_HTTP_TIMEOUT)
    return response.status_code, _safe_json(response)


def _safe_json(response):
    try:
        return response.json()
    except Exception:
        return {}


def _plugins_url(plugin_id=None):
    if not config.KONG_ADMIN_API:
        raise KongAdapterError("KONG_ADMIN_API is not set")
    base = f"{config.KONG_ADMIN_API}/{config.kong_entity_path('plugins')}"
    if plugin_id:
        if "/" in str(plugin_id) or str(plugin_id).startswith("."):
            raise KongAdapterError("refusing suspicious plugin id in URL")
        return f"{base}/{plugin_id}"
    return base


def check_gates(proposal, scope, allow_rollback=False):
    """Enforce every execution gate. Returns the approval record.

    Raises KongInvalid / KongOutOfScope / KongNotApproved / KongWritesDisabled.
    """
    op = (proposal or {}).get("op")
    if op not in changes.ALLOWED_OPS:
        if op in changes.ROLLBACK_OPS and allow_rollback:
            pass
        elif op in changes.ROLLBACK_OPS:
            raise KongInvalid(f"op {op!r} is rollback-only")
        else:
            raise KongInvalid(f"op {op!r} is not allowlisted")
    service = ((proposal or {}).get("target") or {}).get("service")
    if service not in (scope or []):
        raise KongOutOfScope(
            f"service {service!r} is outside the assessment scope")
    ok, reasons = changes.validate_proposal(proposal, scope)
    if not ok:
        if allow_rollback and op in changes.ROLLBACK_OPS:
            reasons = [r for r in reasons if "allowlisted" not in r]
        if reasons:
            raise KongInvalid(f"proposal rejected: {'; '.join(reasons)}")
    approvals = (proposal or {}).get("approvals") or []
    if (proposal or {}).get("status") != "approved" or not approvals:
        raise KongNotApproved(
            "change has no recorded human approval; refusing to execute")
    if not config.KONG_WRITE_ENABLED:
        raise KongWritesDisabled(
            "live execution is disabled; set KONG_WRITE_ENABLED=true to "
            "allow approved writes, or use simulate() for a dry run")
    return approvals[-1]


def _enable_plugin(proposal, http):
    target = proposal.get("target") or {}
    service_id = (proposal.get("current") or {}).get("service_id")
    body = {"name": proposal.get("plugin"), "config": {},
            "service": {"id": service_id or target.get("service")}}
    if target.get("kind") == "route" and target.get("route_id"):
        body["route"] = {"id": target["route_id"]}
    status, payload = http("POST", _plugins_url(),
                           config.kong_auth_headers(), body)
    if status not in (200, 201):
        raise KongOpFailed(
            f"enable_plugin returned HTTP {status}: {str(payload)[:200]}")
    return {"op": "enable_plugin", "http_status": status,
            "plugin_id": (payload or {}).get("id")}


def _remove_plugin(proposal, http, plugin_id):
    if not plugin_id:
        raise KongOpFailed("rollback needs the enabled plugin id; refusing "
                           "a blind delete")
    status, payload = http("DELETE", _plugins_url(plugin_id),
                           config.kong_auth_headers(), None)
    if status not in (200, 204):
        raise KongOpFailed(
            f"remove_plugin returned HTTP {status}: {str(payload)[:200]}")
    return {"op": "remove_plugin", "http_status": status,
            "plugin_id": plugin_id}


def _post_validate(proposal, http, plugin_id):
    """Re-read the plugin and confirm it matches the proposal."""
    checks: List[Dict[str, Any]] = []
    if not plugin_id:
        return {"passed": False, "at": _now(), "checks": [{
            "check": "plugin_readback",
            "passed": False,
            "detail": "no plugin id returned; cannot confirm the change"}]}
    status, payload = http("GET", _plugins_url(plugin_id),
                           config.kong_auth_headers(), None)
    ok_status = status == 200
    checks.append({"check": "plugin_readback", "passed": ok_status,
                   "detail": f"GET plugin returned HTTP {status}"})
    name_ok = (payload or {}).get("name") == proposal.get("plugin")
    checks.append({"check": "plugin_name_matches", "passed": name_ok,
                   "detail": f"name is {(payload or {}).get('name')!r}"})
    return {"passed": all(c["passed"] for c in checks), "at": _now(),
            "checks": checks}


def execute(proposal, scope, http=None, allow_rollback=False):
    """Execute one approved change through the allowlisted adapter.

    Gates, operation, post-change validation and bookkeeping happen here so
    no caller can skip a step. Returns the mutated proposal. Raises a
    KongAdapterError subclass; the proposal is marked failed with the
    recorded error before the exception propagates.
    """
    http = http or _default_http
    record: Dict[str, Any] = {
        "change_id": (proposal or {}).get("change_id", "?"),
        "mode": "live",
        "started_at": _now(),
        "finished_at": None,
        "approver": None,
        "ops": [],
        "error": None,
    }
    try:
        approval = check_gates(proposal, scope, allow_rollback=allow_rollback)
        record["approver"] = approval.get("reviewer")
        record["approved_at"] = approval.get("at")
        op = proposal.get("op")
        if op == "enable_plugin":
            result = _enable_plugin(proposal, http)
            record["ops"].append(result)
            post = _post_validate(proposal, http, result.get("plugin_id"))
        elif op == "remove_plugin" and allow_rollback:
            result = _remove_plugin(
                proposal, http,
                (proposal.get("rollback_of") or {}).get("plugin_id"))
            record["ops"].append(result)
            post = {"passed": result["http_status"] in (200, 204),
                    "at": _now(),
                    "checks": [{"check": "plugin_removed", "passed": True,
                                "detail": f"DELETE returned "
                                          f"{result['http_status']}"}]}
        else:
            raise KongInvalid(f"op {op!r} is not executable")
        record["finished_at"] = _now()
        changes.mark_executed(proposal, record)
        changes.mark_validated(proposal, post)
        return proposal
    except KongAdapterError as exc:
        record["finished_at"] = _now()
        record["error"] = f"{type(exc).__name__}: {exc}"
        changes.mark_executed(proposal, record)
        raise


def simulate(proposal, inventory, entry=None, scoring=None):
    """Security Fix Simulator: expected effect without touching live Kong.

    Applies the proposal to an inventory copy, diffs the target service,
    rescores the linked risk entry and stages the validation plan as
    pending-live steps. Pure function of its inputs.
    """
    updated, applied = changes.simulate_apply(inventory, proposal)
    report: Dict[str, Any] = {
        "change_id": (proposal or {}).get("change_id", "?"),
        "mode": "simulate",
        "at": _now(),
        "ok": applied.get("ok", False),
        "effect": applied.get("effect") or applied.get("error"),
        "diff": changes.diff_proposal(proposal or {}),
        "residual_risk": None,
        "validation_plan": list((proposal or {}).get("validation_plan", [])),
        "note": "simulation only; no live gateway resources were modified",
    }
    if applied.get("ok"):
        target = (proposal or {}).get("target") or {}
        before = next((s for s in inventory or []
                       if isinstance(s, dict)
                       and s.get("service_name") == target.get("service")),
                      {})
        after = next((s for s in updated
                      if isinstance(s, dict)
                      and s.get("service_name") == target.get("service")),
                     {})
        report["residual_risk"] = changes.residual_risk(
            entry or {}, before, after, scoring)
    proposal["simulation"] = report
    return report
