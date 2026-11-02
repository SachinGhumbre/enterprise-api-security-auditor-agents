"""
===============================================================================
 File Name   : common/policy.py
 Description : Versioned policy assessment catalog and deterministic engine.

               Twenty-seven controls across eight policy groups (OWASP API
               Top 10, ISMS, authentication/authorisation, privacy, TLS, rate
               limiting, logging, exposure). Each control declares the evidence its check
               needs; checks return satisfied/partial/unsatisfied, or
               not_evaluable with an explicit reason when the inventoried
               evidence cannot support a verdict. Not-evaluable controls are
               reported as gaps, never as findings, so the engine cannot make
               unsupported compliance claims.

               Violations map to the common finding schema via
               control_result_to_finding(). Muse Spark reasons over verdicts
               and writes narratives elsewhere; this module only evaluates
               configuration evidence deterministically.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from common import rules

CATALOG_VERSION = "1.0.0"

SEVERITIES = ("Critical", "High", "Medium", "Low")
CONFIDENCES = ("high", "medium", "low")
OUTCOMES = ("satisfied", "partial", "unsatisfied", "not_evaluable")

STRONG_AUTH = ("jwt", "oauth2", "openid-connect", "mtls-auth")
WEAK_AUTH = ("key-auth", "basic-auth")
LOG_PLUGINS = ("file-log", "http-log", "tcp-log", "syslog")


@dataclass
class Control:
    id: str
    domain: str
    title: str
    version: str
    severity: str
    standards: List[str]
    source_doc: str
    check: str
    keywords: List[str] = field(default_factory=list)
    evidence_required: List[str] = field(default_factory=list)
    impact: str = ""
    scenario: str = ""
    action: str = ""
    validation: str = ""


def _plugins(evidence):
    return {rules.normalize_plugin(p)["canonical"]
            for p in (evidence.get("plugins") or [])}


def check_strong_auth(evidence):
    """Strong token auth present, weak-only, or none."""
    enabled = _plugins(evidence)
    strong = sorted(set(STRONG_AUTH) & enabled)
    weak = sorted(set(WEAK_AUTH) & enabled)
    if strong:
        return "satisfied", strong, f"Strong auth enabled: {', '.join(strong)}."
    if weak:
        return "partial", weak, (f"Only weak auth enabled ({', '.join(weak)}); "
                                 "no token-based mechanism.")
    return "unsatisfied", [], "No authentication plugin enabled."


def check_plugin_present(name):
    def check(evidence, _name=name):
        enabled = _plugins(evidence)
        if _name in enabled:
            return "satisfied", [_name], f"'{_name}' is enabled."
        return "unsatisfied", [], f"'{_name}' is not enabled."
    return check


def check_any_plugin(*names):
    def check(evidence, _names=names):
        enabled = _plugins(evidence)
        hit = sorted(set(_names) & enabled)
        if hit:
            return "satisfied", hit, f"Enabled: {', '.join(hit)}."
        return "unsatisfied", [], f"None of {', '.join(_names)} is enabled."
    return check


def check_has_routes(evidence):
    routes = evidence.get("routes") or []
    if routes:
        return "satisfied", [], f"{len(routes)} route(s) inventoried."
    return "unsatisfied", [], "Service has no routes; possible orphan API."


def check_not_evaluable(reason, evidence_needed):
    def check(evidence, _reason=reason, _needed=evidence_needed):
        return ("not_evaluable", [],
                f"{_reason} Required evidence: {', '.join(_needed)}.")
    return check


CHECKS = {
    "strong_auth": check_strong_auth,
    "acl": check_plugin_present("acl"),
    "rate_limiting": check_plugin_present("rate-limiting"),
    "bot_detection": check_plugin_present("bot-detection"),
    "request_size_limiting": check_plugin_present("request-size-limiting"),
    "logging": check_any_plugin(*LOG_PLUGINS),
    "metrics": check_any_plugin("prometheus", "statsd", "opentelemetry"),
    "tracing": check_any_plugin("zipkin", "opentelemetry"),
    "response_filtering": check_any_plugin("response-transformer", "exit-transformer"),
    "ip_restriction": check_plugin_present("ip-restriction"),
    "has_routes": check_has_routes,
    "bola": check_not_evaluable(
        "Object-level authorisation needs application logic review.",
        ["API access-control matrix", "object-ownership tests"]),
    "bfla": check_not_evaluable(
        "Function-level authorisation needs role-to-endpoint mapping.",
        ["role matrix", "route role annotations"]),
    "misconfig_review": check_not_evaluable(
        "Misconfiguration review needs plugin configuration values.",
        ["plugin configs (CORS origins, timeouts, secrets)"]),
    "config_management": check_not_evaluable(
        "Configuration management needs process evidence.",
        ["change records", "config baselines"]),
    "pii_logging": check_not_evaluable(
        "Log PII minimisation needs log samples and schemas.",
        ["log samples", "field schemas"]),
    "encryption_at_rest": check_not_evaluable(
        "Processing security needs storage and TLS evidence.",
        ["datastore encryption proof", "TLS termination proof"]),
    "tls_transport": check_not_evaluable(
        "Transport encryption needs listener and route protocol data.",
        ["route protocols", "certificate inventory"]),
    "security_headers": check_not_evaluable(
        "Security headers need response configuration.",
        ["response header policy", "HSTS proof"]),
    "mtls_topology": check_not_evaluable(
        "Service-to-service mTLS needs caller topology.",
        ["service mesh graph", "client certificate inventory"]),
    "cors_policy": check_not_evaluable(
        "CORS policy needs plugin configuration values.",
        ["cors origins, methods and credentials settings"]),
    "data_labels": check_not_evaluable(
        "Data classification needs service labels.",
        ["data classification tags per service/route"]),
}


def _c(control_id, domain, title, severity, standards, source_doc, check,
       keywords=(), evidence_required=(), impact="", scenario="",
       action="", validation=""):
    return Control(
        id=control_id, domain=domain, title=title, version="1.0",
        severity=severity, standards=list(standards), source_doc=source_doc,
        check=check, keywords=list(keywords),
        evidence_required=list(evidence_required), impact=impact,
        scenario=scenario, action=action, validation=validation)


CONTROLS = [
    # OWASP API Security Top 10 2023 -------------------------------------------
    _c("OWASP-API2", "owasp", "Broken Authentication", "Critical",
       ["OWASP API Security Top 10 2023: API2"], "01_authentication_policy.txt",
       "strong_auth", ["jwt", "oauth2", "authentication"],
       ["service plugin names"],
       "Unauthenticated callers can invoke the API.",
       "Attacker calls endpoints without credentials and reads or mutates data.",
       "Enable jwt or oauth2 on the service.",
       "inventory"),
    _c("OWASP-API4", "owasp", "Unrestricted Resource Consumption", "High",
       ["OWASP API Security Top 10 2023: API4"], "03_rate_limiting.txt",
       "rate_limiting", ["rate", "throttl", "quota"],
       ["service plugin names"],
       "Unthrottled callers can exhaust the service.",
       "Attacker floods the API until legitimate traffic degrades.",
       "Enable rate-limiting with sensible quotas.",
       "inventory"),
    _c("OWASP-API9", "owasp", "Improper Inventory Management", "Low",
       ["OWASP API Security Top 10 2023: API9"], "kong_api_security_mapping.md",
       "has_routes", ["route", "inventory"],
       ["service route list"],
       "Orphan services escape review and patching.",
       "Attacker discovers an unmaintained service and exploits old flaws.",
       "Remove the service or attach reviewed routes.",
       "inventory"),
    _c("OWASP-API1", "owasp", "Broken Object Level Authorisation", "High",
       ["OWASP API Security Top 10 2023: API1"], "kong_api_security_mapping.md",
       "bola", ["authori", "object", "bola"],
       ["API access-control matrix", "object-ownership tests"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Review object-level checks in application code.",
       "manual"),
    _c("OWASP-API5", "owasp", "Broken Function Level Authorisation", "High",
       ["OWASP API Security Top 10 2023: API5"], "kong_api_security_mapping.md",
       "bfla", ["authori", "role", "function"],
       ["role matrix", "route role annotations"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Map roles to endpoints and enforce with acl.",
       "manual"),
    _c("OWASP-API8", "owasp", "Security Misconfiguration", "Medium",
       ["OWASP API Security Top 10 2023: API8"], "kong_api_security_mapping.md",
       "misconfig_review", ["misconfig", "cors", "header"],
       ["plugin configs (CORS origins, timeouts, secrets)"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Review plugin configurations against hardening baseline.",
       "manual"),
    # ISMS (ISO/IEC 27001:2022 Annex A) ------------------------------------------
    _c("ISMS-A8.5", "isms", "Secure Authentication", "Critical",
       ["ISO/IEC 27001:2022 A.8.5"], "01_authentication_policy.txt",
       "strong_auth", ["authenticat", "log-on", "credential"],
       ["service plugin names"],
       "Weak log-on exposes information systems.",
       "Attacker authenticates with stolen or guessed weak credentials.",
       "Enforce token-based authentication (jwt, oauth2).",
       "inventory"),
    _c("ISMS-A8.16", "isms", "Monitoring Activities", "Medium",
       ["ISO/IEC 27001:2022 A.8.16"], "05_logging_audit.txt",
       "logging", ["log", "audit", "monitor"],
       ["service plugin names"],
       "Unmonitored activity hides intrusions.",
       "Attacker operates unnoticed; no trail exists for response.",
       "Enable http-log, tcp-log, file-log or syslog.",
       "inventory"),
    _c("ISMS-A8.9", "isms", "Configuration Management", "Medium",
       ["ISO/IEC 27001:2022 A.8.9"], "kong_api_security_mapping.md",
       "config_management", ["baseline", "change", "configuration"],
       ["change records", "config baselines"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Establish configuration baselines and change review.",
       "manual"),
    # Authentication / authorisation ----------------------------------------------
    _c("AUTH-01", "authentication", "Strong Customer Authentication", "Critical",
       ["Internal API AuthN Standard v2"], "01_authentication_policy.txt",
       "strong_auth", ["jwt", "oauth2", "openid", "mtls"],
       ["service plugin names"],
       "Customer data exposed to unauthenticated access.",
       "Attacker replays or forges weak credentials.",
       "Enable jwt, oauth2, openid-connect or mtls-auth.",
       "inventory"),
    _c("AUTH-02", "authentication", "Service-to-Service mTLS", "High",
       ["Internal API AuthN Standard v2"], "kong_api_security_mapping.md",
       "mtls_topology", ["mtls", "service-to-service", "zero trust"],
       ["service mesh graph", "client certificate inventory"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Map east-west callers and enforce mtls-auth.",
       "manual"),
    _c("AUTHZ-01", "authorisation", "Authorisation Enforced", "High",
       ["Internal API AuthZ Standard v2"], "02_authorization_policy.txt",
       "acl", ["acl", "allowlist", "group"],
       ["service plugin names"],
       "Any authenticated caller can reach every endpoint.",
       "Low-privilege caller invokes admin endpoints.",
       "Enforce access lists with the acl plugin.",
       "inventory"),
    # Privacy / GDPR -----------------------------------------------------------------
    _c("GDPR-05", "privacy", "Accountability Audit Trail", "High",
       ["GDPR Art. 5(2)"], "05_logging_audit.txt",
       "logging", ["accountab", "audit trail", "article 5"],
       ["service plugin names"],
       "Processing cannot be demonstrated to regulators.",
       "Breach occurs with no record of who accessed personal data.",
       "Enable durable API access logging.",
       "inventory"),
    _c("GDPR-25", "privacy", "Response Data Minimisation", "Medium",
       ["GDPR Art. 25"], "06_gdpr_privacy.txt",
       "response_filtering", ["minimi", "pii", "redact", "transform"],
       ["service plugin names"],
       "Excessive personal data leaves the API.",
       "Attacker harvests over-exposed fields from responses.",
       "Filter responses with response-transformer.",
       "inventory"),
    _c("GDPR-32", "privacy", "Security of Processing", "High",
       ["GDPR Art. 32"], "06_gdpr_privacy.txt",
       "encryption_at_rest", ["encrypt", "at rest", "article 32"],
       ["datastore encryption proof", "TLS termination proof"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Evidence datastore encryption and TLS termination.",
       "manual"),
    _c("GDPR-LOG", "privacy", "PII Minimisation in Logs", "Medium",
       ["GDPR Art. 5(1)(c)"], "06_gdpr_privacy.txt",
       "pii_logging", ["pii", "log", "minimi"],
       ["log samples", "field schemas"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Sample logs and prove PII is minimised.",
       "manual"),
    # Encryption / TLS -----------------------------------------------------------------
    _c("TLS-01", "encryption", "Transport Encryption", "Critical",
       ["Internal Encryption & TLS Policy v3"], "kong_api_security_mapping.md",
       "tls_transport", ["tls", "https", "certificate"],
       ["route protocols", "certificate inventory"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Terminate TLS and inventory certificates.",
       "manual"),
    _c("TLS-02", "encryption", "Security Headers", "Medium",
       ["Internal Encryption & TLS Policy v3"], "kong_api_security_mapping.md",
       "security_headers", ["hsts", "header", "tls"],
       ["response header policy", "HSTS proof"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Emit HSTS and baseline security headers.",
       "manual"),
    # Rate limiting / abuse ---------------------------------------------------------------
    _c("RL-01", "rate_limiting", "Rate Limiting", "High",
       ["Internal API Abuse Protection v1"], "03_rate_limiting.txt",
       "rate_limiting", ["rate", "limit", "quota"],
       ["service plugin names"],
       "Service vulnerable to flooding and credential stuffing.",
       "Attacker automates high-volume requests unchecked.",
       "Enable rate-limiting with abuse-tuned quotas.",
       "inventory"),
    _c("RL-02", "rate_limiting", "Bot Protection", "Medium",
       ["Internal API Abuse Protection v1"], "kong_api_security_mapping.md",
       "bot_detection", ["bot", "scrap", "abuse"],
       ["service plugin names"],
       "Bots scrape or abuse the API freely.",
       "Botnet harvests data at machine speed.",
       "Enable bot-detection.",
       "inventory"),
    _c("RL-03", "rate_limiting", "Payload Limits", "Medium",
       ["Internal API Abuse Protection v1"], "04_input_validation.txt",
       "request_size_limiting", ["payload", "size", "limit"],
       ["service plugin names"],
       "Oversized payloads can destabilise backends.",
       "Attacker posts huge bodies to exhaust parsers.",
       "Enable request-size-limiting.",
       "inventory"),
    # Logging / monitoring / audit --------------------------------------------------------------
    _c("LOG-01", "logging", "Audit Logging", "High",
       ["Internal Logging Standard v4"], "05_logging_audit.txt",
       "logging", ["audit", "log trail"],
       ["service plugin names"],
       "Security events leave no trail.",
       "Incident occurs with nothing to investigate.",
       "Enable http-log, tcp-log, file-log or syslog.",
       "inventory"),
    _c("LOG-02", "logging", "Security Metrics", "Low",
       ["Internal Logging Standard v4"], "05_logging_audit.txt",
       "metrics", ["metric", "prometheus", "dashboard"],
       ["service plugin names"],
       "Anomalies go unmeasured.",
       "Slow attack blends into unmeasured traffic.",
       "Export prometheus or statsd metrics.",
       "inventory"),
    _c("LOG-03", "logging", "Distributed Tracing", "Low",
       ["Internal Logging Standard v4"], "kong_api_security_mapping.md",
       "tracing", ["trace", "span", "zipkin"],
       ["service plugin names"],
       "Cross-service attacks cannot be reconstructed.",
       "Attacker pivots across services invisibly.",
       "Enable zipkin or opentelemetry tracing.",
       "inventory"),
    # Exposure / classification --------------------------------------------------------------------
    _c("EXP-01", "exposure", "Network Restriction", "Medium",
       ["Internal API Exposure Policy v1"], "kong_api_security_mapping.md",
       "ip_restriction", ["allowlist", "ip", "network", "cidr"],
       ["service plugin names"],
       "API reachable from untrusted networks.",
       "Attacker probes the API from anywhere.",
       "Restrict callers with ip-restriction.",
       "inventory"),
    _c("EXP-02", "exposure", "CORS Policy", "Medium",
       ["Internal API Exposure Policy v1"], "kong_api_security_mapping.md",
       "cors_policy", ["cors", "origin", "browser"],
       ["cors origins, methods and credentials settings"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Review CORS origins, methods and credentials.",
       "manual"),
    _c("EXP-03", "exposure", "Data Classification Labels", "Low",
       ["Internal Data Classification v1"], "06_gdpr_privacy.txt",
       "data_labels", ["classif", "label", "sensitive", "tag"],
       ["data classification tags per service/route"],
       "Undetermined from gateway configuration.",
       "Undetermined from gateway configuration.",
       "Label services and routes by data sensitivity.",
       "manual"),
]


def build_service_evidence(service, chunks):
    """Evidence bundle for one service: inventory facts + retrieved excerpts."""
    return {
        "service_name": service.get("service_name", "unknown"),
        "service_id": service.get("service_id", ""),
        "plugins": list(service.get("service_plugins", []) or []),
        "routes": list(service.get("service_routes", []) or []),
        "chunks": [c for c in (chunks or []) if isinstance(c, dict)],
    }


def grounding(control, evidence):
    """Keyword grounding of a control in retrieved excerpts.

    Returns (grounded, chunk_ids). Deterministic substring match only; the
    model never decides what counts as referenced.
    """
    text = " ".join(str(c.get("content", "")) for c in evidence.get("chunks", []))
    lowered = text.lower()
    if not any(keyword in lowered for keyword in control.keywords):
        return False, []
    matched = [c.get("id") for c in evidence.get("chunks", [])
               if c.get("id") and any(k in str(c.get("content", "")).lower()
                                      for k in control.keywords)]
    return True, matched


def evaluate_control(control, evidence):
    """Run one control check. Never raises: unexpected input yields
    not_evaluable with a reason instead of a guessed verdict."""
    try:
        check = CHECKS.get(control.check)
        if check is None:
            raise KeyError(f"unknown check '{control.check}'")
        outcome, basis, reason = check(evidence)
        if outcome not in OUTCOMES:
            raise ValueError(f"check returned '{outcome}'")
    except Exception as exc:  # noqa: BLE001 - honesty over precision
        return {
            "control_id": control.id,
            "domain": control.domain,
            "title": control.title,
            "version": control.version,
            "catalog_version": CATALOG_VERSION,
            "severity": control.severity,
            "standards": list(control.standards),
            "source_doc": control.source_doc,
            "outcome": "not_evaluable",
            "basis": [],
            "reason": f"Check failed openly ({exc}); no verdict claimed.",
            "grounded": False,
            "chunk_ids": [],
        }
    grounded, chunk_ids = grounding(control, evidence)
    return {
        "control_id": control.id,
        "domain": control.domain,
        "title": control.title,
        "version": control.version,
        "catalog_version": CATALOG_VERSION,
        "severity": control.severity,
        "standards": list(control.standards),
        "source_doc": control.source_doc,
        "outcome": outcome,
        "basis": list(basis),
        "reason": reason,
        "grounded": grounded,
        "chunk_ids": chunk_ids,
    }


def evaluate_all(evidence, controls=None):
    return [evaluate_control(c, evidence) for c in (controls or CONTROLS)]


def compute_coverage(results_by_service):
    """Coverage and gaps across services. Gaps list every unsatisfied,
    partial and not-evaluable control with its reason."""
    by_domain: Dict[str, Dict[str, int]] = {}
    totals = {"total": 0, "satisfied": 0, "partial": 0, "unsatisfied": 0,
              "not_evaluable": 0}
    gaps = []
    for service_name, results in (results_by_service or {}).items():
        for result in results or []:
            outcome = result.get("outcome", "not_evaluable")
            domain = result.get("domain", "unknown")
            bucket = by_domain.setdefault(
                domain, {"total": 0, "satisfied": 0, "partial": 0,
                         "unsatisfied": 0, "not_evaluable": 0})
            bucket["total"] += 1
            bucket[outcome if outcome in bucket else "not_evaluable"] += 1
            totals["total"] += 1
            totals[outcome if outcome in totals else "not_evaluable"] += 1
            if outcome != "satisfied":
                gaps.append({
                    "service": service_name,
                    "control_id": result.get("control_id"),
                    "title": result.get("title"),
                    "outcome": outcome,
                    "severity": result.get("severity"),
                    "reason": result.get("reason"),
                })
    return {"catalog_version": CATALOG_VERSION, "by_domain": by_domain,
            "totals": totals, "gaps": gaps}


FINDING_REQUIRED = (
    "finding_id", "affected_api", "category", "severity", "confidence",
    "evidence", "applicable_standard", "business_impact", "attack_scenario",
    "recommended_action", "validation_method", "assessed_at",
    "evidence_freshness",
)

MAX_FRESHNESS_S = 86400


def build_finding(**fields):
    """Validate and freeze the common finding schema (13 fields)."""
    missing = [k for k in FINDING_REQUIRED if k not in fields]
    if missing:
        raise ValueError(f"Finding missing required fields: {missing}")
    if fields["severity"] not in SEVERITIES:
        raise ValueError(f"Invalid severity '{fields['severity']}'.")
    if fields["confidence"] not in CONFIDENCES:
        raise ValueError(f"Invalid confidence '{fields['confidence']}'.")
    return {key: fields[key] for key in FINDING_REQUIRED}


def freshness(retrieved_at, assessed_at=None, max_age_s=MAX_FRESHNESS_S):
    """Evidence freshness from retrieval timestamps. Unparseable input is
    reported stale rather than assumed fresh."""
    assessed_at = assessed_at or datetime.now(timezone.utc).isoformat()
    try:
        retrieved = datetime.fromisoformat(str(retrieved_at or ""))
        assessed = datetime.fromisoformat(str(assessed_at))
        age_s = max(0.0, (assessed - retrieved).total_seconds())
    except (ValueError, TypeError):
        return {"retrieved_at": retrieved_at, "assessed_at": assessed_at,
                "age_s": None, "stale": True}
    return {"retrieved_at": retrieved_at, "assessed_at": assessed_at,
            "age_s": round(age_s, 1), "stale": age_s > max_age_s}


def control_result_to_finding(result, service, finding_id, retrieved_at,
                              assessed_at=None):
    """Map a violating control result to the common finding schema.

    Satisfied and not-evaluable controls return None: the former needs no
    finding, the latter must not become an unsupported claim.
    """
    if result.get("outcome") not in ("partial", "unsatisfied"):
        return None
    control = next((c for c in CONTROLS if c.id == result.get("control_id")), None)
    grounded = bool(result.get("grounded"))
    if result.get("outcome") == "unsatisfied":
        confidence = "high" if grounded else "medium"
        tier, tier_note = "suspected", "Deterministic configuration gap."
    else:
        confidence = "medium" if grounded else "low"
        tier, tier_note = "suspected", "Partial control coverage."
    evidence = [{
        "kind": "inventory",
        "ref": f"service:{service.get('service_name', 'unknown')}",
        "detail": result.get("reason", ""),
    }]
    for chunk_id in result.get("chunk_ids", []):
        evidence.append({"kind": "policy_excerpt", "ref": str(chunk_id),
                         "detail": f"Control referenced in {result.get('source_doc')}"})
    return {
        **build_finding(
            finding_id=finding_id,
            affected_api={
                "api": service.get("service_name", "unknown"),
                "gateway_resource": {
                    "kind": "service",
                    "name": service.get("service_name", "unknown"),
                    "id": service.get("service_id", ""),
                },
            },
            category=result.get("domain", "unknown"),
            severity=result.get("severity", "Medium"),
            confidence=confidence,
            evidence=evidence,
            applicable_standard={
                "standard": "; ".join(result.get("standards", [])),
                "control": (f"{result.get('control_id')} "
                            f"v{result.get('version')}"),
                "catalog_version": result.get("catalog_version"),
            },
            business_impact=(control.impact if control else ""),
            attack_scenario=(control.scenario if control else ""),
            recommended_action=(control.action if control else ""),
            validation_method=(control.validation if control else "manual"),
            assessed_at=assessed_at or datetime.now(timezone.utc).isoformat(),
            evidence_freshness=freshness(retrieved_at, assessed_at),
        ),
        "tier": tier,
        "tier_reason": tier_note,
    }
