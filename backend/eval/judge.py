"""
===============================================================================
 File Name   : eval/judge.py
 Description : Deterministic judges for the model evaluation suite. Every
               check is plain Python over the response text - no LLM-as-judge,
               so scores are reproducible offline.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

from common import llm, rules

REMEDIATION_KEYS = (
    "serviceName", "policyName", "issue", "missingPlugin",
    "recommendedAction", "severity", "owner", "estimatedEffort",
    "impact", "securityStandardReference",
)

SEVERITIES = ("Critical", "High", "Medium", "Low")


def _finding_policy(policies, needle):
    needle = str(needle or "").lower()
    for policy in policies:
        if isinstance(policy, dict) and needle in str(policy.get("policy_name", "")).lower():
            return policy
    return None


def score_verdict(text, task):
    """Score an audit-verdict response against expected policies."""
    checks = {}
    parsed = llm.extract_json(text, expect="object")
    checks["valid_json"] = isinstance(parsed, dict)
    policies = parsed.get("policies", []) if checks["valid_json"] else []
    checks["has_policies"] = isinstance(policies, list) and bool(policies)
    enabled = {rules.normalize_plugin(p)["canonical"]
               for p in task["service"]["service_plugins"]}
    enabled.discard(None)
    for expected in task["expected"]["policies"]:
        tag = expected["policy_name_contains"]
        policy = _finding_policy(policies, tag) or {}
        checks[f"{tag}:verdict"] = (
            bool(policy.get("comply", policy.get("comply_status", False)))
            == bool(expected["comply"]))
        claimed = {rules.normalize_plugin(p)["canonical"]
                   for p in (policy.get("missing_plugins") or [])}
        claimed.discard(None)
        checks[f"{tag}:recall"] = all(
            rules.normalize_plugin(m)["canonical"] in claimed
            for m in expected.get("missing_any_of", []))
        checks[f"{tag}:no_contradiction"] = not (claimed & enabled)
    passed = all(checks.values())
    return {"checks": checks, "passed": passed,
            "score": round(sum(checks.values()) / len(checks), 3) if checks else 0.0}


def score_remediation(text, task):
    """Score a remediation plan against required shape and coverage."""
    from agents.auditor_agent import _coerce_plan_array
    checks = {}
    parsed = llm.extract_json(text, expect="array")
    items = _coerce_plan_array(parsed)
    checks["valid_json_array"] = isinstance(items, list)
    items = items if checks["valid_json_array"] else []
    expected = task["expected"]
    checks["item_count"] = len(items) == int(expected["item_count"])
    checks["all_keys"] = all(
        isinstance(item, dict) and all(k in item for k in REMEDIATION_KEYS)
        for item in items) if items else False
    checks["severity_enum"] = all(
        isinstance(item, dict) and item.get("severity") in SEVERITIES
        for item in items) if items else False
    if "service_names" in expected:
        got = sorted(i.get("serviceName") for i in items if isinstance(i, dict))
        checks["service_match"] = got == sorted(expected["service_names"])
    if "severities" in expected:
        got = sorted(i.get("severity") for i in items if isinstance(i, dict))
        checks["severity_match"] = got == sorted(expected["severities"])
    passed = all(checks.values())
    return {"checks": checks, "passed": passed,
            "score": round(sum(checks.values()) / len(checks), 3) if checks else 0.0}


def score_explanation(text, task):
    """Score an explanation for grounding: required terms present, forbidden
    terms absent. Deterministic by design, not a quality judgement."""
    checks = {}
    body = str(text or "")
    checks["non_empty"] = bool(body.strip())
    expected = task["expected"]
    checks["required_terms"] = all(
        term in body for term in expected.get("required_terms", []))
    checks["forbidden_terms"] = not any(
        term in body for term in expected.get("forbidden_terms", []))
    passed = all(checks.values())
    return {"checks": checks, "passed": passed,
            "score": round(sum(checks.values()) / len(checks), 3) if checks else 0.0}


def score(task, text):
    kind = task["kind"]
    if kind == "verdict":
        return score_verdict(text, task)
    if kind == "remediation":
        return score_remediation(text, task)
    if kind == "explanation":
        return score_explanation(text, task)
    raise ValueError(f"Unknown eval task kind '{kind}'.")
