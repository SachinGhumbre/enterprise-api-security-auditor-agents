"""
===============================================================================
 File Name   : common/risks.py
 Description : Enterprise risk register engine. Deduplicates security,
               compliance and policy findings into single issues, correlates
               them by API and business capability, links technical gaps to
               compliance controls, and scores them with a configurable,
               versioned deterministic model. Severity and confidence stay
               separate inputs; unverified findings can never become verified
               entries; lifecycle states track acceptance and remediation.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from common import rules
from common.policy import LOG_PLUGINS, STRONG_AUTH, WEAK_AUTH

SCORING_MODEL_VERSION = "1.0.0"
SCORING_FORMULA = ("score = weighted_mean(severity, exploitability, exposure, "
                   "sensitivity, criticality) * (blend_base + blend_scale * "
                   "confidence / 10)")

SEVERITY_SCORES = {"Critical": 10.0, "High": 7.5, "Medium": 5.0, "Low": 2.5}
CONFIDENCE_SCORES = {"high": 8.0, "medium": 5.0, "low": 2.0}
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

AUTH_PLUGINS = tuple(STRONG_AUTH) + tuple(WEAK_AUTH)

# Policy control -> (topic, related plugins) for cross-stream deduplication.
CONTROL_TOPICS = {
    "OWASP-API2": ("authentication", ("jwt", "oauth2", "openid-connect", "mtls-auth")),
    "ISMS-A8.5": ("authentication", ("jwt", "oauth2", "openid-connect", "mtls-auth")),
    "AUTH-01": ("authentication", ("jwt", "oauth2", "openid-connect", "mtls-auth")),
    "AUTH-02": ("authentication", ("mtls-auth",)),
    "AUTHZ-01": ("authorisation", ("acl",)),
    "OWASP-API4": ("rate_limiting", ("rate-limiting",)),
    "RL-01": ("rate_limiting", ("rate-limiting",)),
    "RL-02": ("abuse_protection", ("bot-detection",)),
    "RL-03": ("abuse_protection", ("request-size-limiting",)),
    "OWASP-API9": ("inventory", ()),
    "ISMS-A8.16": ("logging", LOG_PLUGINS),
    "GDPR-05": ("logging", LOG_PLUGINS),
    "LOG-01": ("logging", LOG_PLUGINS),
    "LOG-02": ("logging", ("prometheus", "statsd", "opentelemetry")),
    "LOG-03": ("logging", ("zipkin", "opentelemetry")),
    "GDPR-25": ("data_protection", ("response-transformer", "exit-transformer")),
    "EXP-01": ("exposure", ("ip-restriction",)),
}

TOPIC_LABELS = {
    "authentication": "Authentication gap",
    "authorisation": "Authorisation gap",
    "rate_limiting": "Rate limiting gap",
    "abuse_protection": "Abuse protection gap",
    "inventory": "Inventory gap",
    "logging": "Logging gap",
    "data_protection": "Data protection gap",
    "exposure": "Exposure gap",
}

VALID_TRANSITIONS = {
    "open": ("accepted", "mitigated", "remediated"),
    "accepted": ("open", "mitigated", "remediated"),
    "mitigated": ("open", "remediated"),
    "remediated": ("open",),
}


@dataclass
class RiskScoringConfig:
    version: str = SCORING_MODEL_VERSION
    weights: Dict[str, float] = field(default_factory=lambda: {
        "severity": 0.30, "exploitability": 0.20, "exposure": 0.15,
        "sensitivity": 0.15, "criticality": 0.20,
    })
    blend_base: float = 0.6
    blend_scale: float = 0.4
    thresholds: List[tuple] = field(default_factory=lambda: [
        (8.0, "Critical"), (6.0, "High"), (4.0, "Medium"), (0.0, "Low")])

    @classmethod
    def from_dict(cls, values):
        merged = {"weights": dict(cls().weights)}
        for key, value in (values or {}).items():
            if key == "weights":
                merged["weights"].update(value)
            elif hasattr(cls(), key):
                merged[key] = value
        return cls(**merged)

    def level_for(self, score):
        for threshold, level in sorted(self.thresholds, reverse=True):
            if score >= threshold:
                return level
        return "Low"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _canonical(plugin):
    return rules.normalize_plugin(plugin)["canonical"]


def _service_of(finding):
    if isinstance(finding.get("affected_api"), dict):
        return finding["affected_api"].get("api", "unknown")
    return finding.get("service", "unknown")


def _topic_for_plugins(canonicals):
    auth = {"jwt", "oauth2", "openid-connect", "mtls-auth", "key-auth", "basic-auth"}
    if set(canonicals) & auth:
        return "authentication"
    if "rate-limiting" in canonicals:
        return "rate_limiting"
    if set(canonicals) & set(LOG_PLUGINS):
        return "logging"
    if "acl" in canonicals:
        return "authorisation"
    if set(canonicals) & {"response-transformer", "exit-transformer"}:
        return "data_protection"
    if "ip-restriction" in canonicals:
        return "exposure"
    return ""


def dedup_key(finding, stream):
    """Identity of the underlying issue: service + topic."""
    service = _service_of(finding)
    if stream == "policy":
        control_id = ""
        standard = finding.get("applicable_standard") or {}
        for token in str(standard.get("control", "")).split():
            if token in CONTROL_TOPICS:
                control_id = token
                break
        topic = CONTROL_TOPICS.get(control_id, ("general", ()))[0]
        return (service, topic)
    missing = sorted({_canonical(p) for p in (finding.get("missing_plugins") or [])})
    missing = [m for m in missing if m]
    topic = _topic_for_plugins(missing)
    if not topic:
        stem = str(finding.get("policy_name", "general")).split(" ")[0].lower()
        return (service, f"general:{stem}")
    return (service, topic)


def merge_group(key, sources):
    """Merge duplicate findings into one register entry shell. Severity takes
    the max with conflicts noted; confidence takes the best-supported claim."""
    service, topic = key
    severities = [(s.get("severity") or "Medium") for _, s in sources]
    top_severity = max(severities, key=lambda s: SEVERITY_RANK.get(s, 2))
    conflicts = []
    if len(set(severities)) > 1:
        conflicts.append(f"severity conflict {sorted(set(severities))}; "
                         f"kept highest ({top_severity})")
    confidences = [((s.get("verification") or {}).get("confidence") or "low")
                   if "verification" in s else (s.get("confidence") or "low")
                   for _, s in sources]
    top_confidence = max(confidences, key=lambda c: CONFIDENCE_RANK.get(c, 1))
    tiers = [s.get("tier", "unverified") for _, s in sources]
    verified = "confirmed" in tiers
    evidence = []
    for stream, source in sources:
        if stream == "policy":
            evidence.extend(source.get("evidence", []))
        else:
            for chunk_id in source.get("evidence_ids", []):
                evidence.append({"kind": "policy_excerpt", "ref": str(chunk_id),
                                 "detail": "retrieved policy chunk"})
            evidence.append({
                "kind": "inventory",
                "ref": f"service:{service}",
                "detail": f"missing: {source.get('missing_plugins', [])}"})
    label = TOPIC_LABELS.get(topic.split(":")[0], "Security gap")
    return {
        "entry_id": f"R-{service}-{topic}".replace(":", "-").replace(" ", "_"),
        "service": service,
        "title": f"{label} on {service}",
        "policy_name": next(
            (s.get("policy_name") or (s.get("applicable_standard") or {})
             .get("control", topic) for _, s in sources), topic),
        "severity": top_severity,
        "confidence": top_confidence,
        "verified": verified,
        "tier": "confirmed" if verified else (
            "suspected" if "suspected" in tiers else "unverified"),
        "sources": [{
            "stream": stream,
            "finding_id": s.get("finding_id", "?"),
            "severity": s.get("severity", "Medium"),
            "confidence": ((s.get("verification") or {})
                           .get("confidence", s.get("confidence", "low"))),
            "tier": s.get("tier", "unverified"),
        } for stream, s in sources],
        "severity_conflicts": conflicts,
        "evidence": evidence,
    }


def score_factors(entry_service, service_lookup, entry, config=None):  # noqa: C901
    """Score the six risk factors with a rationale each. Every default is
    stated in its rationale; nothing is silently assumed."""
    service = service_lookup.get(entry_service, {})
    plugins = {_canonical(p) for p in (service.get("service_plugins") or [])}
    plugins.discard(None)
    routes = service.get("service_routes") or []
    priority = service.get("_priority", False)
    sensitive_paths = any(
        any(word in str(p).lower() for word in
            ("payment", "order", "transfer", "payout", "admin", "user",
             "account", "invoice"))
        for route in routes for p in ((route or {}).get("paths") or []))

    severity = entry.get("severity", "Medium")
    factors = {
        "severity": {
            "score": SEVERITY_SCORES.get(severity, 5.0),
            "rationale": f"finding severity {severity}",
        },
    }
    if plugins & set(STRONG_AUTH):
        factors["exploitability"] = {
            "score": 3.0, "rationale": "strong authentication enforced"}
    elif plugins & set(WEAK_AUTH):
        factors["exploitability"] = {
            "score": 6.0, "rationale": "weak-only authentication"}
    elif service:
        factors["exploitability"] = {
            "score": 9.0, "rationale": "no authentication detected"}
    else:
        factors["exploitability"] = {
            "score": 5.0, "rationale": "service unknown; assumed moderate"}
    if not routes:
        factors["exposure"] = {"score": 1.0,
                               "rationale": "no routes inventoried"}
    elif "ip-restriction" in plugins:
        factors["exposure"] = {"score": 4.0,
                               "rationale": "routes restricted by network"}
    else:
        factors["exposure"] = {
            "score": 8.0,
            "rationale": f"{len(routes)} route(s), no network restriction"}
    if priority:
        factors["sensitivity"] = {"score": 8.0,
                                  "rationale": "priority service"}
    elif sensitive_paths:
        factors["sensitivity"] = {"score": 7.0,
                                  "rationale": "sensitive paths detected"}
    else:
        factors["sensitivity"] = {
            "score": 5.0,
            "rationale": "unlabelled data; assumed moderate"}
    factors["criticality"] = (
        {"score": 9.0, "rationale": "priority service"}
        if priority else
        {"score": 4.0, "rationale": "not listed as priority; assumed standard"})
    confidence = entry.get("confidence", "low")
    factors["confidence"] = {
        "score": CONFIDENCE_SCORES.get(confidence, 2.0),
        "rationale": f"evidence confidence {confidence}",
    }
    return factors


def score_entry(entry_factors, config=None):
    """Apply the versioned formula. Returns (score, level)."""
    config = config or RiskScoringConfig()
    base = sum(entry_factors[name]["score"] * config.weights.get(name, 0.0)
               for name in ("severity", "exploitability", "exposure",
                            "sensitivity", "criticality"))
    confidence = entry_factors["confidence"]["score"]
    score = round(base * (config.blend_base + config.blend_scale
                          * confidence / 10.0), 1)
    return score, config.level_for(score)


def build_register(llm_findings, policy_findings, service_lookup,
                   control_results=None, config=None):
    """Deduplicate, correlate and score every finding into register entries."""
    config = config or RiskScoringConfig()
    groups: Dict[tuple, list] = {}
    for finding in llm_findings or []:
        if not isinstance(finding, dict) or finding.get("comply"):
            continue
        key = dedup_key(finding, "llm")
        groups.setdefault(key, []).append(("llm", finding))
    for finding in policy_findings or []:
        if not isinstance(finding, dict):
            continue
        key = dedup_key(finding, "policy")
        groups.setdefault(key, []).append(("policy", finding))

    controls_by_service: Dict[str, list] = {}
    for result in control_results or []:
        if isinstance(result, dict):
            controls_by_service.setdefault(
                result.get("service", "?"), []).append(result)

    entries = []
    for key, sources in groups.items():
        service, topic = key
        entry = merge_group(key, sources)
        factors = score_factors(service, service_lookup, entry, config)
        score, level = score_entry(factors, config)
        linked = sorted({
            r.get("control_id") for r in controls_by_service.get(service, [])
            if r.get("control_id") in CONTROL_TOPICS
            and CONTROL_TOPICS[r["control_id"]][0] == topic.split(":")[0]})
        entries.append({
            **entry,
            "factors": factors,
            "score": score,
            "level": level,
            "linked_controls": linked,
            "correlated_entries": [],
            "capability": service,
            "state": "open",
            "state_history": [],
            "scoring_model": config.version,
            "formula": SCORING_FORMULA,
        })
    _correlate(entries)
    entries.sort(key=lambda e: e["score"], reverse=True)
    return entries


def _capability_of(entry):
    return str(entry.get("service", "?")).split("-")[0].split("_")[0] or "?"


def _correlate(entries):
    """Group entries by business capability (service-name family) and link
    technical entries to their compliance controls (already attached)."""
    by_capability: Dict[str, list] = {}
    for entry in entries:
        capability = _capability_of(entry)
        entry["capability"] = capability
        by_capability.setdefault(capability, []).append(entry["entry_id"])
    for entry in entries:
        peers = [e for e in by_capability[entry["capability"]]
                 if e != entry["entry_id"]]
        entry["correlated_entries"] = sorted(peers)


def transition(entry, to_state, actor=None, note=""):
    """Move a register entry through its lifecycle with a history record."""
    current = entry.get("state", "open")
    allowed = VALID_TRANSITIONS.get(current, ())
    if to_state not in allowed:
        raise ValueError(
            f"Invalid transition {current} -> {to_state}; "
            f"allowed: {list(allowed) or 'none'}.")
    entry["state"] = to_state
    entry.setdefault("state_history", []).append({
        "from": current, "to": to_state, "actor": actor or "unknown",
        "note": note or "", "at": _now(),
    })
    return entry


def summarize_register(entries):
    """Deterministic executive rollup: counts plus the top entries."""
    by_level: Dict[str, int] = {}
    by_state: Dict[str, int] = {}
    for entry in entries or []:
        by_level[entry.get("level", "?")] = by_level.get(
            entry.get("level", "?"), 0) + 1
        by_state[entry.get("state", "?")] = by_state.get(
            entry.get("state", "?"), 0) + 1
    top = [{
        "entry_id": e.get("entry_id"), "title": e.get("title"),
        "score": e.get("score"), "level": e.get("level"),
        "severity": e.get("severity"), "confidence": e.get("confidence"),
        "verified": e.get("verified"),
    } for e in (entries or [])[:5]]
    return {"total": len(entries or []), "by_level": by_level,
            "by_state": by_state, "top": top}
