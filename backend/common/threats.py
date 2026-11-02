"""
===============================================================================
 File Name   : common/threats.py
 Description : Deterministic API threat-scenario engine.

               Detects OWASP-shaped threat scenarios from gateway evidence
               (routes, methods, plugins, consumers) and emits structured,
               suspected-only hypotheses with preconditions, evidence
               references and non-destructive test recommendations. A scenario
               fires only when its preconditions are present in the evidence;
               speculation beyond the evidence is left to the bounded LLM
               elaboration step, which may only explain listed scenarios.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import re
from typing import Any, Dict, List

from common import rules
from common.policy import LOG_PLUGINS, STRONG_AUTH, WEAK_AUTH

ID_PARAM_RE = re.compile(r"\{[^}]+\}|:[a-zA-Z_][a-zA-Z0-9_]*")
STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")
SENSITIVE_WORDS = ("admin", "payment", "order", "transfer", "payout",
                   "account", "user", "invoice", "auth", "login")
DEBUG_WORDS = ("debug", "internal", "actuator")
AUTH_PLUGINS = tuple(STRONG_AUTH) + tuple(WEAK_AUTH)

TEST_PREFIX = "Authorized testing only: "


def _canonical_plugins(service):
    return {rules.normalize_plugin(p)["canonical"]
            for p in (service.get("service_plugins") or [])}


def route_signals(service):
    """Derived per-service facts over routes, methods and plugins."""
    routes = service.get("service_routes") or []
    enabled = _canonical_plugins(service)
    service_auth = sorted(set(AUTH_PLUGINS) & enabled)
    id_param_routes, sensitive_routes, debug_routes = [], [], []
    state_changing, get_routes = [], []
    unauthenticated = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        name = route.get("name") or route.get("id") or "?"
        paths = [str(p) for p in (route.get("paths") or [])]
        methods = [str(m).upper() for m in (route.get("methods") or [])]
        blob = " ".join(paths).lower()
        route_auth = sorted(
            {rules.normalize_plugin(p)["canonical"]
             for p in (route.get("plugin_names") or [])} & set(AUTH_PLUGINS))
        if ID_PARAM_RE.search(blob):
            id_param_routes.append(name)
        if any(w in blob for w in SENSITIVE_WORDS):
            sensitive_routes.append(name)
        if any(w in blob for w in DEBUG_WORDS):
            debug_routes.append(name)
        if any(m in STATE_CHANGING for m in methods) or not methods:
            state_changing.append(name)
        if "GET" in methods or not methods:
            get_routes.append(name)
        if not route_auth and not service_auth:
            unauthenticated.append(name)
    return {
        "route_count": len(routes),
        "service_auth": service_auth,
        "has_validator": "request-validator" in enabled,
        "has_rate_limiting": "rate-limiting" in enabled,
        "has_acl": "acl" in enabled,
        "has_logging": bool(set(LOG_PLUGINS) & enabled),
        "has_response_filtering": bool(
            {"response-transformer", "exit-transformer"} & enabled),
        "id_param_routes": id_param_routes,
        "sensitive_routes": sensitive_routes,
        "debug_routes": debug_routes,
        "state_changing_routes": state_changing,
        "get_routes": get_routes,
        "unauthenticated_routes": unauthenticated,
    }


def _ref(kind, ref, detail):
    return {"kind": kind, "ref": ref, "detail": detail}


def detect_scenarios(service, priority_services=()):
    """Run the ten scenario detectors over one service's evidence."""
    name = service.get("service_name", "unknown")
    signals = route_signals(service)
    priority = name in (priority_services or [])
    scenarios = []

    def add(scenario_id, owasp_ref, stride, title, severity_hint,
            preconditions, evidence_refs, recommended_tests):
        scenarios.append({
            "scenario_id": scenario_id,
            "owasp_ref": owasp_ref,
            "stride": stride,
            "title": title,
            "severity_hint": ("Critical" if priority and severity_hint == "High"
                              else severity_hint),
            "hypothesis": True,
            "preconditions": list(preconditions),
            "evidence_refs": list(evidence_refs),
            "recommended_tests": [TEST_PREFIX + t for t in recommended_tests],
        })

    auth = signals["service_auth"]
    if signals["id_param_routes"]:
        add("bola", "OWASP API1:2023", "Elevation of privilege",
            "Broken Object Level Authorization", "High",
            [f"id-parameter routes: {', '.join(signals['id_param_routes'])}",
             "no object-level authorisation is provable from gateway config"],
            [_ref("route", r, "id parameter in path")
             for r in signals["id_param_routes"]],
            ["horizontal access test with two test accounts over read-only "
             "objects on staging"])
    if not auth:
        add("broken_auth", "OWASP API2:2023", "Spoofing",
            "Broken Authentication", "Critical",
            ["no authentication plugin on the service or its routes"],
            [_ref("inventory", f"service:{name}",
                  f"enabled plugins: {sorted(_canonical_plugins(service)) or 'none'}")],
            ["unauthenticated request test against staging"])
    if signals["state_changing_routes"] and not signals["has_validator"]:
        add("bopla", "OWASP API3:2023", "Tampering",
            "Broken Object Property Level Authorisation", "High",
            [f"state-changing routes without validation: "
             f"{', '.join(signals['state_changing_routes'])}"],
            [_ref("route", r, "state-changing method")
             for r in signals["state_changing_routes"]],
            ["mass-assignment probe with read-only fields on staging"])
    if not signals["has_rate_limiting"]:
        add("consumption", "OWASP API4:2023", "Denial of service",
            "Unrestricted Resource Consumption", "Medium",
            ["no rate-limiting plugin detected"],
            [_ref("inventory", f"service:{name}", "rate-limiting absent")],
            ["rate-limit verification burst within agreed limits on staging"])
    if signals["sensitive_routes"] and not signals["has_acl"]:
        add("bfla", "OWASP API5:2023", "Elevation of privilege",
            "Broken Function Level Authorisation", "High",
            [f"sensitive routes without acl: "
             f"{', '.join(signals['sensitive_routes'])}"],
            [_ref("route", r, "sensitive path")
             for r in signals["sensitive_routes"]],
            ["role matrix test: low-privilege role attempts admin routes"])
    if signals["debug_routes"]:
        add("misconfig", "OWASP API8:2023", "Information disclosure",
            "Security Misconfiguration", "Medium",
            [f"debug/internal routes exposed: "
             f"{', '.join(signals['debug_routes'])}"],
            [_ref("route", r, "debug/internal path")
             for r in signals["debug_routes"]],
            ["config review of debug routes; response header scan"])
    if signals["route_count"] == 0:
        add("inventory", "OWASP API9:2023", "Information disclosure",
            "Improper Inventory Management", "Low",
            ["service has no routes; possible shadow API"],
            [_ref("inventory", f"service:{name}", "route_count is 0")],
            ["confirm ownership; remove or document the service"])
    if signals["get_routes"] and not signals["has_response_filtering"]:
        add("excessive_exposure", "OWASP API3:2023", "Information disclosure",
            "Excessive Data Exposure", "Medium",
            [f"read routes without response filtering: "
             f"{', '.join(signals['get_routes'])}"],
            [_ref("route", r, "unfiltered read route")
             for r in signals["get_routes"]],
            ["response review: compare returned fields to need"])
    business_routes = []
    for route in service.get("service_routes") or []:
        blob = " ".join(str(p) for p in ((route or {}).get("paths") or [])).lower()
        if any(w in blob for w in
               ("payment", "order", "transfer", "payout", "admin")):
            business_routes.append((route or {}).get("name")
                                   or (route or {}).get("id") or "?")
    if business_routes and (not auth or not signals["has_rate_limiting"]):
        add("sensitive_ops_abuse", "OWASP API5:2023", "Elevation of privilege",
            "Abuse of Sensitive Business Operations", "High",
            [f"sensitive operations: {', '.join(business_routes)}",
             f"auth={'none' if not auth else ','.join(auth)}, "
             f"rate_limiting={'off' if not signals['has_rate_limiting'] else 'on'}"],
            [_ref("route", r, "sensitive operation")
             for r in business_routes],
            ["business-logic walkthrough with the product owner on staging"])
    return scenarios


def unsafe_consumption_limitation(services_with_routes):
    """Assessment-level limitation: upstream consumption safety cannot be
    judged from gateway configuration. Returned once, not per service."""
    if not services_with_routes:
        return None
    return {
        "scenario_id": "unsafe_consumption",
        "owasp_ref": "OWASP API10:2023",
        "stride": "Tampering",
        "title": "Unsafe Consumption of APIs (unevaluable)",
        "severity_hint": "Medium",
        "hypothesis": True,
        "preconditions": ["upstream validation unknown from gateway config"],
        "evidence_refs": [_ref("limitation", "no-upstream-inventory",
                               "no timeout/schema/max-size evidence available")],
        "recommended_tests": [TEST_PREFIX + "dependency review of upstream "
                              "timeouts, schemas and size limits (no live test)"],
    }


def _path_prefix(paths):
    for path in paths or []:
        parts = [p for p in str(path).split("/") if p and "{" not in p
                 and not p.startswith(":")]
        if len(parts) >= 2:
            return "/" + "/".join(parts[:2])
    return ""


def related_services(kong_data):
    """Evidenced service relationships: shared auth plugin or shared path
    prefix. Attack paths may only traverse these links."""
    services = [s for s in (kong_data or []) if isinstance(s, dict)]
    relations = []
    for i, left in enumerate(services):
        for right in services[i + 1:]:
            left_auth = ({rules.normalize_plugin(p)["canonical"]
                          for p in (left.get("service_plugins") or [])}
                         & set(AUTH_PLUGINS))
            right_auth = ({rules.normalize_plugin(p)["canonical"]
                           for p in (right.get("service_plugins") or [])}
                          & set(AUTH_PLUGINS))
            shared_auth = sorted(left_auth & right_auth)
            prefixes = set()
            for route in (left.get("service_routes") or []):
                prefix = _path_prefix((route or {}).get("paths"))
                if prefix:
                    prefixes.add(prefix)
            shared_prefix = next(
                (prefix for route in (right.get("service_routes") or [])
                 for prefix in [_path_prefix((route or {}).get("paths"))]
                 if prefix and prefix in prefixes), "")
            if shared_auth or shared_prefix:
                via = []
                if shared_auth:
                    via.append("shared_auth:" + ",".join(shared_auth))
                if shared_prefix:
                    via.append("shared_path_prefix:" + shared_prefix)
                relations.append({
                    "services": sorted([left.get("service_name", "?"),
                                        right.get("service_name", "?")]),
                    "via": via,
                    "strength": "moderate" if shared_prefix else "weak",
                })
    return relations


def analyze_estate(kong_data, priority_services=()):
    """Deterministic estate analysis: per-service scenarios, relations and
    the assessment-level unsafe-consumption limitation."""
    scenarios_by_service: Dict[str, List[Dict[str, Any]]] = {}
    for service in kong_data or []:
        if not isinstance(service, dict):
            continue
        name = service.get("service_name", "unknown")
        scenarios_by_service[name] = detect_scenarios(service, priority_services)
    limitation = unsafe_consumption_limitation(
        [s for s in (kong_data or [])
         if isinstance(s, dict) and (s.get("service_routes") or [])])
    return {
        "scenarios_by_service": scenarios_by_service,
        "relations": related_services(kong_data),
        "limitation": limitation,
    }
