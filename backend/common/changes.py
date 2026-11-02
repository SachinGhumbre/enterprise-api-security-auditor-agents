"""
===============================================================================
 File Name   : common/changes.py
 Description : Controlled remediation change engine. Validated findings become
               structured change proposals: exact target, retrieved current
               configuration, proposed patch, rationale, preconditions, consumer
               impact, breaking changes, validation plan, current-vs-proposed
               diff, residual risk and rollback plan. Every safety decision is
               deterministic: the operation allowlist, scope enforcement,
               proposal validation, simulation and residual-risk scoring run in
               code. The LLM only drafts explanatory prose and a patch skeleton,
               which is validated field-by-field before it can attach.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from common import risks, rules

CHANGE_SCHEMA_VERSION = "1.0.0"

# v1 executes a single operation class. enable_plugin applies Kong's own
# plugin defaults (empty config), so no configuration field values are
# invented here. remove_plugin exists only as the deterministic inverse for
# rollback of a change this engine enabled.
ALLOWED_OPS = ("enable_plugin",)
ROLLBACK_OPS = ("remove_plugin",)

VALID_STATUSES = ("proposed", "approved", "executed", "failed",
                  "validated", "rolled_back")


def _now():
    return datetime.now(timezone.utc).isoformat()


def change_id_for(target_service, op, plugin):
    safe = "".join(c for c in
                   f"{target_service}-{op}-{plugin}".lower()
                   if c.isalnum() or c in ("-", "_"))[:80]
    return f"CH-{safe or 'change'}"


def snapshot_target(inventory, target):
    """Retrieve the current configuration for a target from inventory.

    The inventory carries effective plugin names and route bindings, not
    full plugin documents; the snapshot states exactly that, so a proposal
    never claims configuration detail it was not given.
    """
    service_name = (target or {}).get("service", "?")
    service = next((s for s in inventory or []
                    if isinstance(s, dict)
                    and s.get("service_name") == service_name), None)
    if service is None:
        return {"service": service_name, "found": False,
                "service_plugins": [], "service_routes": []}
    snapshot = {"service": service_name, "found": True,
                "service_id": service.get("service_id"),
                "service_plugins": list(service.get("service_plugins", [])),
                "service_routes": copy.deepcopy(
                    service.get("service_routes", []))}
    route_id = (target or {}).get("route_id")
    if route_id:
        route = next((r for r in snapshot["service_routes"]
                      if isinstance(r, dict) and r.get("id") == route_id),
                     None)
        snapshot["route"] = route
        if route is None:
            snapshot["route_found"] = False
    return snapshot


def build_proposal(finding, inventory, scope, assessment_id="?",
                   entry=None):
    """Deterministic proposal shell from one validated finding.

    The finding must name the missing plugin (LLM verdicts) or map to one
    (policy findings via CONTROL_TOPICS). Returns (proposal, error); error
    is set when no exact, unambiguous target+plugin can be derived.
    """
    if not isinstance(finding, dict):
        return None, "finding is not an object"
    service = finding.get("service")
    if not service and isinstance(finding.get("affected_api"), dict):
        service = finding["affected_api"].get("api")
    if not service:
        return None, "finding names no affected service"
    missing = list(finding.get("missing_plugins") or [])
    if not missing and finding.get("applicable_standard"):
        control = str((finding.get("applicable_standard") or {})
                      .get("control", ""))
        for token in control.split():
            topic = risks.CONTROL_TOPICS.get(token)
            if topic and topic[1]:
                missing = [topic[1][0]]
                break
    if len(missing) != 1:
        return None, (f"expected exactly one missing plugin, "
                      f"got {missing or 'none'}")
    normalized = rules.normalize_plugin(missing[0])
    if not normalized.get("known") or normalized.get("ambiguous"):
        return None, f"plugin {missing[0]!r} is not a known Kong plugin"
    plugin = normalized["canonical"]
    target = {"kind": "service", "service": service}
    current = snapshot_target(inventory, target)
    if not current.get("found"):
        return None, f"service {service!r} not in retrieved inventory"
    if plugin in {rules.normalize_plugin(p)["canonical"]
                  for p in current["service_plugins"]}:
        return None, (f"plugin {plugin!r} already enabled on "
                      f"{service!r}; nothing to change")
    proposal = {
        "change_id": change_id_for(service, "enable_plugin", plugin),
        "schema_version": CHANGE_SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "finding_ids": [finding.get("finding_id", "?")],
        "entry_ids": [entry.get("entry_id")] if isinstance(entry, dict)
        and entry.get("entry_id") else [],
        "target": target,
        "op": "enable_plugin",
        "plugin": plugin,
        "patch": {"config": {}},
        "current": current,
        "scope": sorted(scope or []),
        "rationale": "",
        "preconditions": [],
        "consumer_impact": "",
        "breaking_changes": [],
        "validation_plan": [],
        "diff": [],
        "residual_risk": None,
        "rollback": {"op": "remove_plugin", "plugin": plugin,
                     "target": dict(target),
                     "note": ("Remove the plugin this change enabled, "
                              "restoring the retrieved prior state.")},
        "status": "proposed",
        "approvals": [],
        "execution": None,
        "post_validation": None,
    }
    proposal["diff"] = diff_proposal(proposal)
    return proposal, None


def attach_proposal_prose(proposal, prose):
    """Attach LLM-drafted prose after strict validation. Unknown keys and
    non-string list items are rejected; the patch is never taken from the
    model (v1 fixes it to Kong defaults)."""
    if not isinstance(prose, dict):
        raise ValueError("proposal prose must be an object")
    allowed = {"rationale", "preconditions", "consumer_impact",
               "breaking_changes", "validation_plan"}
    unknown = sorted(set(prose) - allowed)
    if unknown:
        raise ValueError(f"unexpected prose keys: {unknown}")
    for key in ("rationale", "consumer_impact"):
        value = prose.get(key, "")
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"prose.{key} must be a non-empty string")
        proposal[key] = value.strip()
    for key in ("preconditions", "breaking_changes", "validation_plan"):
        value = prose.get(key, [])
        if not isinstance(value, list) or not value or not all(
                isinstance(v, str) and v.strip() for v in value):
            raise ValueError(
                f"prose.{key} must be a non-empty list of strings")
        proposal[key] = [v.strip() for v in value]
    return proposal


def validate_proposal(proposal, scope):
    """Deterministic acceptance check. Returns (ok, reasons)."""
    reasons = []
    if not isinstance(proposal, dict):
        return False, ["proposal is not an object"]
    if proposal.get("schema_version") != CHANGE_SCHEMA_VERSION:
        reasons.append("unsupported schema_version")
    if proposal.get("op") not in ALLOWED_OPS:
        reasons.append(f"op {proposal.get('op')!r} is not allowlisted")
    normalized = rules.normalize_plugin(proposal.get("plugin", ""))
    if (not normalized.get("known") or normalized.get("ambiguous")
            or normalized.get("canonical") != proposal.get("plugin")):
        reasons.append(f"plugin {proposal.get('plugin')!r} is not a known "
                       "canonical Kong plugin")
    target = proposal.get("target") or {}
    if target.get("kind") not in ("service", "route"):
        reasons.append("target.kind must be 'service' or 'route'")
    service = target.get("service", "")
    effective_scope = scope if scope is not None else proposal.get("scope", [])
    if service not in (effective_scope or []):
        reasons.append(f"service {service!r} is outside the assessment scope")
    if proposal.get("patch") != {"config": {}}:
        reasons.append("v1 proposals must use Kong default config "
                       "({'config': {}}); field-level config is rejected")
    current = proposal.get("current") or {}
    if not current.get("found"):
        reasons.append("no retrieved current configuration for the target")
    if not proposal.get("rationale"):
        reasons.append("rationale is empty")
    for key in ("preconditions", "validation_plan"):
        if not proposal.get(key):
            reasons.append(f"{key} is empty")
    return (not reasons), reasons


def diff_proposal(proposal):
    """Current-vs-proposed field diff for an enable_plugin change."""
    current = (proposal.get("current") or {}).get("service_plugins", [])
    plugin = proposal.get("plugin", "?")
    proposed = sorted(set(current) | {plugin})
    return [{
        "field": "service_plugins",
        "before": sorted(current),
        "after": proposed,
        "added": [plugin],
        "removed": [],
    }]


def simulate_apply(inventory, proposal):
    """Apply a proposal to an in-memory inventory copy. No I/O, no writes.

    Returns (new_inventory, report). Precondition failures (target gone,
    plugin already present) are errors in the report, never silent.
    """
    working = copy.deepcopy(inventory or [])
    target = proposal.get("target") or {}
    plugin = proposal.get("plugin", "")
    service = next((s for s in working
                    if isinstance(s, dict)
                    and s.get("service_name") == target.get("service")), None)
    if service is None:
        return working, {"ok": False,
                         "error": f"service {target.get('service')!r} missing "
                                  "from simulation inventory"}
    present = {rules.normalize_plugin(p)["canonical"]
               for p in service.get("service_plugins", [])}
    if plugin in present:
        return working, {"ok": False,
                         "error": f"plugin {plugin!r} already enabled; "
                                  "simulation refuses a no-op change"}
    service["service_plugins"] = sorted(
        set(service.get("service_plugins", [])) | {plugin})
    return working, {"ok": True,
                     "effect": f"{plugin} enabled on {service['service_name']}",
                     "service_plugins": list(service["service_plugins"])}


def residual_risk(entry, service_before, service_after, config=None):
    """Rescore a register entry against simulated post-change inventory.

    Returns {"before", "after", "level_before", "level_after"} or an
    {"error"} dict when the entry cannot be rescored (never a guess).
    """
    if not isinstance(entry, dict) or not entry.get("severity"):
        return {"error": "entry lacks severity; cannot rescore"}
    service_name = entry.get("service", "?")
    try:
        before = risks.score_entry(risks.score_factors(
            service_name, {service_name: service_before or {}}, entry,
            config))
        after = risks.score_entry(risks.score_factors(
            service_name, {service_name: service_after or {}}, entry,
            config))
    except Exception as exc:
        return {"error": f"rescoring failed: {exc}"}
    return {"before": before[0], "level_before": before[1],
            "after": after[0], "level_after": after[1]}


def approve(proposal, reviewer, note=""):
    """Record a human approval. Only proposed changes can be approved."""
    if proposal.get("status") != "proposed":
        raise ValueError(f"change is {proposal.get('status')!r}, not "
                         "'proposed'; cannot approve")
    if not (reviewer or "").strip():
        raise ValueError("reviewer is required")
    proposal.setdefault("approvals", []).append({
        "reviewer": reviewer.strip(), "note": note or "", "at": _now()})
    proposal["status"] = "approved"
    return proposal


def mark_executed(proposal, execution):
    proposal["execution"] = execution or {}
    proposal["status"] = ("failed" if (execution or {}).get("error")
                          else "executed")
    return proposal


def mark_validated(proposal, post_validation):
    proposal["post_validation"] = post_validation or {}
    if proposal.get("status") == "executed" and (post_validation or {}).get(
            "passed"):
        proposal["status"] = "validated"
    return proposal
