"""
===============================================================================
 File Name   : common/rules.py
 Description : Deterministic verification of LLM-generated audit verdicts.

               The LLM (Muse Spark) performs contextual analysis and explains
               findings. This module checks the *factual* part of every verdict
               - "plugin X is missing from service Y" - against the actual Kong
               inventory using plain Python, with no model calls. Deterministic
               checks live here, separate from LLM reasoning.

               Finding statuses:
                 verified      every missing-plugin claim is confirmed absent
                               from the inventory (and comply=true claims list
                               nothing missing).
                 unverified    a claim cannot be confirmed: unknown plugin
                               identifier, ambiguous display name, non-compliance
                               claimed without naming a plugin, or the service
                               produced no policies at all. Missing evidence is
                               reported, never treated as proof.
                 contradictory a claim is disproven by the inventory (the plugin
                               IS enabled) or the verdict contradicts itself
                               (comply=true while listing missing plugins).

               Confidence is a fixed rule table over (status, grounded), where
               grounded means at least one policy chunk was retrieved for the
               service. It is explainable by construction, not model-estimated:
                 contradictory         -> low
                 unverified            -> low
                 verified + grounded   -> high
                 verified + ungrounded -> medium (absence confirmed in the
                                          inventory, but no policy excerpt was
                                          retrieved to ground the requirement)
 Project     : Enterprise API Security Auditor
===============================================================================
"""

from typing import Any, Dict, List, Optional

# Display names the policy corpus and the LLM use, mapped to canonical Kong
# plugin ids. Sourced from backend/knowledge_base/kong_api_security_mapping.md
# and the policy files - never guessed. A tuple value means the display name is
# genuinely ambiguous between several plugins.
PLUGIN_ALIASES = {
    "jwt authentication": "jwt",
    "oauth2": "oauth2",
    "oauth2 / openid connect": ("oauth2", "openid-connect"),
    "oauth2/openid connect": ("oauth2", "openid-connect"),
    "openid connect": "openid-connect",
    "mutual tls authentication": "mtls-auth",
    "basic authentication": "basic-auth",
    "key authentication": "key-auth",
    "acl (access control list)": "acl",
    "acl": "acl",
    "ip restriction": "ip-restriction",
    "rate limiting": "rate-limiting",
    "request size limiting": "request-size-limiting",
    "bot detection": "bot-detection",
    "request validator": "request-validator",
    "cors": "cors",
    "response transformer": "response-transformer",
    "exit transformer": "exit-transformer",
    "logging plugins (tcp/http)": ("tcp-log", "http-log", "file-log"),
    "aws guardrails (ai plugin)": "ai-aws-guardrails",
    "azure content safety plugin": "ai-azure-content-safety",
}

# Canonical Kong Gateway plugin ids. Used ONLY to distinguish "known plugin,
# confirmed absent" from "unrecognized identifier". The contradiction check
# (claimed plugin is actually enabled) never depends on this set: it compares
# normalized names directly, so newly released plugins still verify.
KNOWN_PLUGINS = frozenset({
    # Authentication
    "jwt", "oauth2", "openid-connect", "mtls-auth", "key-auth", "basic-auth",
    "hmac-auth", "ldap-auth", "session",
    # Authorization / access control
    "acl", "cors", "ip-restriction",
    # Threat protection / traffic control
    "rate-limiting", "response-ratelimiting", "request-size-limiting",
    "bot-detection", "request-validator",
    # Transformation
    "response-transformer", "request-transformer", "exit-transformer",
    "correlation-id",
    # Logging / observability
    "file-log", "http-log", "tcp-log", "syslog", "statsd", "prometheus",
    "zipkin", "opentelemetry",
    # AI Gateway plugins (referenced by backend/kong_config/)
    "ai-proxy", "ai-proxy-advanced", "ai-prompt-decorator", "ai-prompt-template",
    "ai-prompt-guard", "ai-response-transformer", "ai-request-transformer",
    "ai-rag-injector", "ai-aws-guardrails", "ai-azure-content-safety",
    "ai-mcp-proxy",
    # Misc official
    "acme", "graphql-proxy-cache",
})

MAX_EXCERPT_CHARS = 280


def _clean_name(name: Any) -> str:
    return " ".join(str(name or "").strip().lower().split())


def normalize_plugin(name: Any) -> Dict[str, Any]:
    """Map a plugin name or display label to canonical Kong plugin id(s).

    Returns {"input", "canonical", "candidates", "ambiguous", "known"}.
    Unknown identifiers pass through in normalized string form with
    known=False - they are reported as unverifiable, never guessed.
    """
    cleaned = _clean_name(name)
    alias = PLUGIN_ALIASES.get(cleaned)
    if isinstance(alias, tuple):
        return {
            "input": name,
            "canonical": None,
            "candidates": list(alias),
            "ambiguous": True,
            "known": True,
        }
    if isinstance(alias, str):
        return {
            "input": name,
            "canonical": alias,
            "candidates": [alias],
            "ambiguous": False,
            "known": True,
        }
    canonical = cleaned.replace(" ", "-").replace("_", "-")
    return {
        "input": name,
        "canonical": canonical,
        "candidates": [canonical] if canonical else [],
        "ambiguous": False,
        "known": bool(canonical) and canonical in KNOWN_PLUGINS,
    }


def _enabled_set(service_plugins: Any) -> set:
    return {
        normalize_plugin(p)["canonical"]
        for p in (service_plugins or [])
        if normalize_plugin(p)["canonical"]
    }


def verify_missing_claims(
    service_plugins: Any, missing_plugins: Any
) -> List[Dict[str, Any]]:
    """Check each claimed-missing plugin against the enabled inventory.

    Per-claim result is one of:
      verified_missing     known plugin, confirmed absent from the service.
      contradicted         the plugin (or an alias of it) IS enabled.
      unverified_ambiguous display name maps to several plugins and at least
                           one candidate is enabled - cannot confirm or deny.
      unknown_plugin       identifier matches no known Kong plugin.
    """
    enabled = _enabled_set(service_plugins)
    results = []
    for claimed in missing_plugins or []:
        norm = normalize_plugin(claimed)
        if norm["ambiguous"]:
            hit = [c for c in norm["candidates"] if c in enabled]
            if hit:
                results.append({
                    "claimed": claimed,
                    "candidates": norm["candidates"],
                    "enabled_candidates": hit,
                    "result": "unverified_ambiguous",
                    "note": (
                        f"'{claimed}' is ambiguous between "
                        f"{', '.join(norm['candidates'])} and "
                        f"{', '.join(hit)} is enabled; cannot confirm the claim."
                    ),
                })
            else:
                results.append({
                    "claimed": claimed,
                    "candidates": norm["candidates"],
                    "enabled_candidates": [],
                    "result": "verified_missing",
                    "note": (
                        f"None of {', '.join(norm['candidates'])} "
                        f"('{claimed}') is enabled."
                    ),
                })
            continue
        canonical = norm["canonical"]
        if canonical in enabled:
            results.append({
                "claimed": claimed,
                "canonical": canonical,
                "result": "contradicted",
                "note": f"'{canonical}' is enabled on the service, not missing.",
            })
        elif norm["known"]:
            results.append({
                "claimed": claimed,
                "canonical": canonical,
                "result": "verified_missing",
                "note": f"'{canonical}' is not enabled on the service.",
            })
        else:
            results.append({
                "claimed": claimed,
                "canonical": canonical,
                "result": "unknown_plugin",
                "note": (
                    f"'{claimed}' matches no known Kong plugin id; "
                    "the claim cannot be verified."
                ),
            })
    return results


def build_service_evidence(chunks: Any) -> Dict[str, Any]:
    """Preserve the retrieval evidence that grounded a service's verdict."""
    items = []
    for chunk in chunks or []:
        if not isinstance(chunk, dict):
            continue
        content = str(chunk.get("content") or "")
        excerpt = content[:MAX_EXCERPT_CHARS]
        items.append({
            "id": chunk.get("id"),
            "source": chunk.get("source"),
            "score": chunk.get("score"),
            "excerpt": excerpt,
            "truncated": len(content) > MAX_EXCERPT_CHARS,
        })
    return {
        "grounded": bool(items),
        "chunk_count": len(items),
        "chunks": items,
    }


def verify_policy_finding(
    policy: Dict[str, Any],
    service_plugins: Any,
    evidence_chunks: Any,
    scope: Any = None,
) -> Dict[str, Any]:
    """Deterministically verify one LLM-generated policy verdict.

    Returns the finding-level verification record. Never raises on malformed
    input: anything unexpected degrades to unverified with an explanatory note.
    """
    scope = list(scope or [])
    try:
        comply = bool(policy.get("comply", policy.get("comply_status", False)))
        missing = policy.get("missing_plugins", []) or []
    except AttributeError:
        return {
            "status": "unverified",
            "confidence": "low",
            "confidence_basis": "Finding is malformed; nothing could be checked.",
            "claims": [],
            "notes": ["Finding is not a policy object."],
        }

    claims = verify_missing_claims(service_plugins, missing)
    evidence = build_service_evidence(evidence_chunks)
    notes: List[str] = []

    if comply and missing:
        status = "contradictory"
        notes.append(
            "Verdict claims compliance while listing missing plugins."
        )
    elif comply:
        status = "verified"
        notes.append("Compliant verdict claims nothing missing.")
    elif not missing:
        # Non-compliance with no named plugin: surfaced, not suppressed, and
        # explicitly NOT treated as proof of anything.
        status = "unverified"
        notes.append(
            "Non-compliance claimed without naming a missing plugin; "
            "there is nothing deterministic to confirm."
        )
    elif any(c["result"] == "contradicted" for c in claims):
        status = "contradictory"
    elif any(c["result"] in ("unknown_plugin", "unverified_ambiguous")
             for c in claims):
        status = "unverified"
    else:
        status = "verified"

    if status == "contradictory":
        confidence, basis = "low", "At least one claim is disproven by the inventory."
    elif status == "unverified":
        confidence, basis = "low", "At least one claim could not be confirmed."
    elif evidence["grounded"]:
        confidence, basis = "high", (
            f"All claims confirmed absent from the inventory and grounded in "
            f"{evidence['chunk_count']} retrieved policy chunk(s)."
        )
    else:
        confidence, basis = "medium", (
            "Plugin absence confirmed in the inventory, but no policy excerpt "
            "was retrieved to ground the requirement."
        )

    return {
        "status": status,
        "confidence": confidence,
        "confidence_basis": basis,
        "claims": claims,
        "evidence": {
            "grounded": evidence["grounded"],
            "chunk_count": evidence["chunk_count"],
            "chunk_ids": [c["id"] for c in evidence["chunks"]],
            "sources": sorted({str(c["source"]) for c in evidence["chunks"]
                               if c.get("source")}),
            "standards_in_scope": scope,
        },
        "notes": notes,
    }


def summarize_verification(audit_report: Any) -> Dict[str, int]:
    """Count finding-level verification statuses across a report."""
    counts = {"verified": 0, "unverified": 0, "contradictory": 0}
    for service in (audit_report or {}).values():
        if not isinstance(service, dict):
            continue
        if service.get("error") and not service.get("policies"):
            counts["unverified"] += 1
            continue
        for policy in service.get("policies", []):
            status = (policy.get("verification") or {}).get("status")
            if status in counts:
                counts[status] += 1
            else:
                # Policies that predate verification (e.g. replayed old
                # reports) count as unverified, never as verified.
                counts["unverified"] += 1
    return counts
