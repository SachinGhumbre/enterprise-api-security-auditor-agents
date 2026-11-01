"""
===============================================================================
 File Name   : auditor_agent.py
 Description : Enterprise API Security Auditor - LangGraph definitions for the two
               agents, Audit and Remediate, over Kong Konnect configuration.

               Both graphs follow a Perceive -> Retrieve -> Reason -> Plan ->
               Act loop. Retrieval is backed by the Redis vector store, so the
               LLM is grounded in the organization's own policy corpus.
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
from typing import Any, Dict, List

import requests
import urllib3
from langgraph.graph import END, StateGraph

# Allow `python agents/init_auditor.py` from any working directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, llm, vector_store  # noqa: E402

# The Kong Admin API is typically fronted by a self-signed cert in a lab setup.
# verify=False without this prints a warning per request.
if not config.KONG_ADMIN_VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUDIT_REPORT_FILE = os.path.join(config.ARTIFACT_DIR, "langgraph_audit_report.json")
REMEDIATION_PLAN_FILE = os.path.join(config.ARTIFACT_DIR, "langgraph_remediation_plan.json")
KONG_DATA_FILE = os.path.join(config.ARTIFACT_DIR, "filtered_kong_data.json")

# Shipped with the repo; used when the Kong Admin API cannot be reached.
FALLBACK_KONG_DATA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "filtered_kong_data.json"
)

SEVERITY_MAP = {
    "Authentication": "Critical",
    "Authorization": "Critical",
    "Data": "Critical",
    "Rate": "High",
    "API": "High",
    "Request": "Medium",
    "Input": "Medium",
    "Logging": "Medium",
    "IP": "Low",
}


def _write_artifact(path: str, payload: Any) -> None:
    """Persist to an absolute path.

    The original code used bare relative filenames, so the same report landed in
    backend/ or backend/agents/ depending on where the server happened to be
    started from.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


# === Kong Admin API ==========================================================

def fetch_kong_data(endpoint: str) -> List[Dict[str, Any]]:
    """GET a collection from the Kong Admin API, following pagination.

    Works against both Kong Konnect (Bearer PAT, /core-entities/ paths) and a
    self-managed Admin API (kong-admin-token, bare paths); see
    common.config.kong_auth_headers / kong_entity_path.
    """
    if not config.KONG_ADMIN_API:
        raise RuntimeError("KONG_ADMIN_API is not set in backend/.env")
    if not config.KONG_ADMIN_TOKEN:
        raise RuntimeError("KONG_ADMIN_TOKEN is not set in backend/.env")

    url = f"{config.KONG_ADMIN_API}/{config.kong_entity_path(endpoint)}"
    headers = config.kong_auth_headers()
    params = {"size": config.KONG_PAGE_SIZE}
    collected: List[Dict[str, Any]] = []

    # Konnect caps page size and returns `next`/`offset` for the remainder.
    # Without this loop a large estate is silently truncated to one page.
    for _ in range(50):
        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=config.KONG_ADMIN_VERIFY_SSL,
                timeout=config.KONG_HTTP_TIMEOUT,
            )
        except requests.exceptions.SSLError as exc:
            raise RuntimeError(
                f"TLS verification failed for {url}: {str(exc)[:160]}. This usually means a "
                "corporate TLS-inspection proxy signs traffic with a root CA that is in the OS "
                "trust store but not in certifi's bundle. Install `truststore` "
                "(pip install truststore) to use the OS store, or set "
                "KONG_ADMIN_VERIFY_SSL=false in backend/.env to skip verification."
            ) from exc
        if response.status_code == 401:
            raise RuntimeError(
                f"Kong returned 401 Unauthorized for {url}. In "
                f"{config.resolve_kong_mode()} mode the token is sent as "
                f"'{'Authorization: Bearer' if config.kong_is_konnect() else 'kong-admin-token'}'. "
                "Check KONG_ADMIN_TOKEN and KONG_ADMIN_MODE in backend/.env."
            )
        if response.status_code == 404:
            raise RuntimeError(
                f"Kong returned 404 for {url}. For Konnect, KONG_ADMIN_API must include "
                "/v2/control-planes/<control-plane-id>."
            )
        response.raise_for_status()

        payload = response.json()
        collected.extend(payload.get("data", []) or [])

        offset = payload.get("offset")
        next_link = payload.get("next")
        if offset:
            params = {"size": config.KONG_PAGE_SIZE, "offset": offset}
        elif next_link:
            url = next_link if next_link.startswith("http") else (
                f"{config.KONG_ADMIN_API}/{next_link.lstrip('/')}"
            )
            params = {}
        else:
            break

    return collected


def collect_kong_inventory(service_names=None) -> List[Dict[str, Any]]:
    """Build the service -> effective-plugins inventory from live Kong.

    Fetches services, routes and plugins once each and joins them in memory.
    Walking routes and plugins per service instead costs roughly
    1 + 2*len(services) requests, which is slow against Konnect and needless:
    every plugin already carries its service/route reference.
    """
    services = fetch_kong_data("services")
    routes = fetch_kong_data("routes")
    plugins = fetch_kong_data("plugins")

    # route id -> owning service id
    route_to_service: Dict[str, str] = {}
    for route in routes:
        service_ref = route.get("service") or {}
        if route.get("id") and service_ref.get("id"):
            route_to_service[route["id"]] = service_ref["id"]

    service_plugins: Dict[str, set] = {}
    global_plugins: set = set()

    for plugin in plugins:
        name = plugin.get("name")
        if not name:
            continue
        service_ref = plugin.get("service") or {}
        route_ref = plugin.get("route") or {}

        if service_ref.get("id"):
            service_plugins.setdefault(service_ref["id"], set()).add(name)
        elif route_ref.get("id"):
            # Most Konnect estates bind plugins at the route level. A plugin on
            # any route of a service still protects traffic to that service, so
            # attribute it upward.
            owner = route_to_service.get(route_ref["id"])
            if owner:
                service_plugins.setdefault(owner, set()).add(name)
        elif not plugin.get("consumer"):
            # Bound to neither service, route nor consumer => gateway-wide.
            global_plugins.add(name)

    wanted = {n.lower() for n in service_names} if service_names else None

    inventory = []
    for service in services:
        service_id = service.get("id")
        name = service.get("name") or service_id
        if wanted and name.lower() not in wanted:
            continue
        inventory.append({
            "service_name": name,
            "service_id": service_id,
            "service_plugins": sorted(service_plugins.get(service_id, set()) | global_plugins),
            "route_count": sum(1 for r, s in route_to_service.items() if s == service_id),
        })
    return inventory


# === Audit agent nodes =======================================================

def perceive_kong(state: Dict[str, Any]) -> Dict[str, Any]:
    """Source the Kong inventory: request payload > live Kong > cached file."""
    print("[AuditAgent] Perceive: collecting Kong configuration...")

    if state.get("kong_data"):
        state["kong_source"] = "request"
        print(f"[AuditAgent] Perceive: using {len(state['kong_data'])} services from request")
        return state

    try:
        inventory = collect_kong_inventory(service_names=state.get("service_names"))
        if not inventory:
            raise RuntimeError(
                "Kong returned no services"
                + (" matching the requested service_names" if state.get("service_names") else "")
            )
        state["kong_data"] = inventory
        state["kong_source"] = f"kong_{config.resolve_kong_mode()}"
        _write_artifact(KONG_DATA_FILE, inventory)
    except Exception as exc:
        print(f"[AuditAgent] Perceive: Kong Admin API unavailable ({exc}); using cached inventory")
        state["kong_warning"] = (
            f"Kong Admin API unreachable ({exc}). Audited the cached inventory from "
            f"{os.path.basename(FALLBACK_KONG_DATA)} instead of live configuration."
        )
        try:
            with open(FALLBACK_KONG_DATA, "r", encoding="utf-8") as handle:
                state["kong_data"] = json.load(handle)
            state["kong_source"] = "cached_file"
        except Exception as inner:
            state["kong_data"] = []
            state["kong_source"] = "none"
            state["kong_warning"] += f" Cached inventory also unavailable ({inner})."

    return state


def retrieve_policies(state: Dict[str, Any]) -> Dict[str, Any]:
    """RAG step: pull the policy chunks relevant to each service from Redis.

    The original pipeline ingested the policy corpus into Redis but never read
    it back, so the vector database had no effect on the audit.
    """
    print("[AuditAgent] Retrieve: querying policy vector store...")
    top_k = int(state.get("top_k") or 4)
    standards = state.get("selected_standards") or []
    context: Dict[str, List[Dict[str, Any]]] = {}

    if not vector_store.ping() or not vector_store.index_exists():
        state["rag_warning"] = (
            "Policy vector store unavailable or not ingested; the audit ran on model "
            "knowledge alone. Run POST /api/v1/knowledge/ingest on port 5001 to ground it."
        )
        state["policy_context"] = context
        return state

    for service in state.get("kong_data", []):
        name = service.get("service_name", "unknown")
        plugins = ", ".join(service.get("service_plugins", []))
        query = (
            f"Security policy requirements and mandatory Kong plugins for service "
            f"{name} with plugins {plugins}. Standards: {', '.join(standards) or 'all'}"
        )
        try:
            context[name] = vector_store.search(query, top_k=top_k)
        except Exception as exc:
            print(f"[AuditAgent] Retrieve: search failed for {name}: {exc}")
            context[name] = []

    retrieved = sum(len(v) for v in context.values())
    print(f"[AuditAgent] Retrieve: {retrieved} policy chunks across {len(context)} services")
    state["policy_context"] = context
    state["retrieved_chunks"] = retrieved
    return state


AUDIT_SYSTEM_PROMPT = (
    "You are an autonomous API security auditor for Kong Gateway. Decide whether a "
    "Kong service complies with the organization's security policies, judging only "
    "from the service's enabled plugins and the policy excerpts provided.\n"
    "Respond with STRICT JSON and nothing else, in exactly this shape:\n"
    '{"serviceName": "<name>", "policies": [{"policy_name": "<policy>", '
    '"comply": true|false, "missing_plugins": ["<plugin>"], "details": "<why>"}]}\n'
    "Rules: cite only plugins that genuinely satisfy or violate a policy; set "
    "missing_plugins to [] and details to \"\" when comply is true; evaluate every "
    "policy present in the excerpts that applies to the requested standards."
)


def reason_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    """Ask the LLM to judge each service against the retrieved policy context."""
    print("[AuditAgent] Reason: evaluating policy compliance...")

    standards = state.get("selected_standards") or ["All Security Standards"]
    if isinstance(standards, str):
        standards = [standards]

    audit_report: Dict[str, Any] = {}
    policy_context = state.get("policy_context", {})

    for service in state.get("kong_data", []):
        service_name = service.get("service_name", "unknown_service")
        service_plugins = service.get("service_plugins", [])
        report_key = f"{service_name}:policy:{service_name}"

        print(f"[AuditAgent] Reason: auditing {service_name} -> {service_plugins}")

        chunks = policy_context.get(service_name, [])
        excerpts = "\n\n".join(
            f"--- {c['source']} (similarity {c['score']}) ---\n{c['content']}" for c in chunks
        ) or "No policy excerpts retrieved; rely on standard API security practice."

        user_prompt = (
            f"Kong service name: {service_name}\n"
            f"Enabled Kong plugins: {service_plugins or 'none'}\n"
            f"Security standards in scope: {', '.join(standards)}\n\n"
            f"Organization security policy excerpts:\n{excerpts}\n\n"
            "Audit this service and return the JSON object described in your instructions."
        )

        try:
            parsed, raw = llm.chat_json(
                [
                    {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                route="/api/v1/agents/auditor",
                expect="object",
            )

            if isinstance(parsed, dict) and parsed.get("policies") is not None:
                parsed.setdefault("serviceName", service_name)
                parsed["service_plugins"] = service_plugins
                parsed["policy_sources"] = sorted({c["source"] for c in chunks})
                audit_report[report_key] = parsed
            else:
                # report_key is assigned before the try block; the original
                # version only set it on success, so this handler raised
                # UnboundLocalError instead of reporting the real failure.
                audit_report[report_key] = {
                    "serviceName": service_name,
                    "service_plugins": service_plugins,
                    "policies": [],
                    "error": "Model did not return parsable JSON.",
                    "raw_response": (raw or "")[:1000],
                }
        except Exception as exc:
            audit_report[report_key] = {
                "serviceName": service_name,
                "service_plugins": service_plugins,
                "policies": [],
                "error": f"Audit call failed: {exc}",
            }

    state["audit_report"] = audit_report
    return state


def plan_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    """Summarise the findings so the UI does not have to recompute them."""
    print("[AuditAgent] Plan: summarising audit report...")

    total = compliant = non_compliant = 0
    for service_data in state.get("audit_report", {}).values():
        for policy in service_data.get("policies", []):
            total += 1
            if policy.get("comply", policy.get("comply_status", False)):
                compliant += 1
            else:
                non_compliant += 1

    services = state.get("audit_report", {})
    state["summary"] = {
        "services_audited": len(services),
        "policies_evaluated": total,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "compliance_rate": round((compliant / total) * 100, 1) if total else 0.0,
        "services_with_errors": sum(1 for s in services.values() if s.get("error")),
        "kong_source": state.get("kong_source"),
        "retrieved_policy_chunks": state.get("retrieved_chunks", 0),
        "llm_provider": llm.provider(),
        "llm_model": llm.model_name(),
    }
    return state


def action_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    print("[AuditAgent] Act: saving audit report...")
    _write_artifact(AUDIT_REPORT_FILE, state.get("audit_report", {}))
    return state


# === Remediation agent nodes =================================================

def perceive_issues(state: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the audit report down to the non-compliant findings."""
    print("[RemediationAgent] Perceive: reading audit report...")

    findings = []
    for service_key, service_data in (state.get("audit_report") or {}).items():
        if not isinstance(service_data, dict):
            continue
        service_name = service_data.get("serviceName", service_key)
        for policy in service_data.get("policies", []):
            comply = policy.get("comply", policy.get("comply_status", True))
            if comply:
                continue
            policy_name = policy.get("policy_name", "Unknown Policy")
            findings.append({
                "serviceName": service_name,
                "policyName": policy_name,
                "details": policy.get("details", "Non-compliance detected."),
                "missingPlugins": policy.get("missing_plugins", []),
                "severity": SEVERITY_MAP.get(policy_name.split()[0], "Medium"),
            })

    print(f"[RemediationAgent] Perceive: {len(findings)} non-compliant findings")
    state["findings"] = findings
    return state


def retrieve_remediation_context(state: Dict[str, Any]) -> Dict[str, Any]:
    """Ground remediation advice in the same policy corpus."""
    print("[RemediationAgent] Retrieve: querying policy vector store...")
    chunks = []
    findings = state.get("findings", [])

    if findings and vector_store.ping() and vector_store.index_exists():
        seen = set()
        for finding in findings:
            query = (
                f"{finding['policyName']} remediation, required Kong plugins "
                f"{', '.join(finding['missingPlugins']) or 'unknown'}"
            )
            try:
                for hit in vector_store.search(query, top_k=3):
                    if hit["id"] not in seen:
                        seen.add(hit["id"])
                        chunks.append(hit)
            except Exception as exc:
                print(f"[RemediationAgent] Retrieve: search failed: {exc}")

    state["remediation_context"] = chunks
    print(f"[RemediationAgent] Retrieve: {len(chunks)} supporting chunks")
    return state


REMEDIATION_SYSTEM_PROMPT = (
    "You are an API security remediation expert for Kong Gateway. Turn audit "
    "findings into a concrete remediation plan.\n"
    "Respond with STRICT JSON only: an array of objects, each with exactly these "
    "keys: serviceName, policyName, issue, missingPlugin, recommendedAction, "
    "severity, owner, estimatedEffort, impact, securityStandardReference.\n"
    "severity must be one of Critical, High, Medium, Low. "
    "securityStandardReference should cite a real control (OWASP API Top 10, "
    "GDPR, NIST 800-53, ISO 27001, PCI-DSS). Return [] if there are no findings."
)


def _coerce_plan_array(parsed):
    """Normalise a model response into a list of remediation items."""
    if isinstance(parsed, dict):
        # Models sometimes wrap the array in {"remediation_plan": [...]}.
        for value in parsed.values():
            if isinstance(value, list):
                return value
        return None
    return parsed if isinstance(parsed, list) else None


def _remediate_batch(findings, excerpts, batch_label):
    """One LLM call for a bounded group of findings. Returns (items, error)."""
    user_prompt = (
        f"Audit findings:\n{json.dumps(findings, indent=2)}\n\n"
        f"Organization security policy excerpts:\n{excerpts}\n\n"
        f"Produce exactly one remediation item per finding ({len(findings)} total) "
        "as a JSON array. Do not add commentary."
    )
    messages = [
        {"role": "system", "content": REMEDIATION_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    try:
        parsed, raw = llm.chat_json(
            messages, route="/api/v1/agents/remediate", expect="array"
        )
        items = _coerce_plan_array(parsed)
        if items is not None:
            return items, None
        return [], (
            f"{batch_label}: model did not return a parsable JSON array "
            f"(raw starts: {(raw or '')[:120]!r})"
        )
    except Exception as exc:
        return [], f"{batch_label}: remediation call failed: {exc}"


def reason_remediation(state: Dict[str, Any]) -> Dict[str, Any]:
    """Ask the LLM for a remediation plan covering every finding.

    Findings are sent in bounded batches. A single call for the whole set grows
    with the size of the Kong estate and silently truncates once the response
    exceeds max_completion_tokens, which yields invalid JSON and loses the entire
    plan. Batching keeps each response well inside the cap no matter how many
    services were audited.
    """
    print("[RemediationAgent] Reason: generating remediation plan...")

    findings = state.get("findings", [])
    if not findings:
        state["remediation_plan"] = []
        state["remediation_note"] = "No non-compliant findings in the audit report."
        return state

    excerpts = "\n\n".join(
        f"--- {c['source']} ---\n{c['content']}" for c in state.get("remediation_context", [])
    ) or "No policy excerpts retrieved."

    batch_size = max(1, int(state.get("batch_size") or config.REMEDIATION_BATCH_SIZE))
    batches = [findings[i:i + batch_size] for i in range(0, len(findings), batch_size)]

    plan: List[Dict[str, Any]] = []
    errors: List[str] = []

    for index, batch in enumerate(batches, start=1):
        label = f"batch {index}/{len(batches)}"
        print(f"[RemediationAgent] Reason: {label} ({len(batch)} findings)")
        items, error = _remediate_batch(batch, excerpts, label)

        if error and not items and len(batch) > 1:
            # Retry the batch one finding at a time so a single bad response
            # cannot discard the whole group.
            print(f"[RemediationAgent] Reason: {label} failed, retrying individually")
            recovered, retry_errors = [], []
            for single in batch:
                one, one_error = _remediate_batch([single], excerpts, f"{label} (single)")
                if one:
                    recovered.extend(one)
                elif one_error:
                    retry_errors.append(one_error)
            if recovered:
                items, error = recovered, None
                errors.extend(retry_errors)

        plan.extend(items)
        if error:
            errors.append(error)

    state["remediation_plan"] = plan
    state["remediation_batches"] = len(batches)

    if len(plan) < len(findings):
        errors.append(
            f"Produced {len(plan)} action(s) for {len(findings)} finding(s); "
            "some findings were not covered."
        )
    if errors:
        state["remediation_error"] = " | ".join(errors[:4])

    return state


def plan_remediation(state: Dict[str, Any]) -> Dict[str, Any]:
    print("[RemediationAgent] Plan: structuring remediation steps...")
    plan = state.get("remediation_plan", [])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    if isinstance(plan, list):
        state["remediation_plan"] = sorted(
            plan, key=lambda item: order.get(str(item.get("severity", "Medium")).title(), 2)
        )
        counts: Dict[str, int] = {}
        for item in state["remediation_plan"]:
            key = str(item.get("severity", "Medium")).title()
            counts[key] = counts.get(key, 0) + 1
        state["summary"] = {
            "total_actions": len(state["remediation_plan"]),
            "by_severity": counts,
            "llm_provider": llm.provider(),
            "llm_model": llm.model_name(),
        }
    return state


def action_remediation(state: Dict[str, Any]) -> Dict[str, Any]:
    print("[RemediationAgent] Act: saving remediation plan...")
    _write_artifact(REMEDIATION_PLAN_FILE, state.get("remediation_plan", []))
    return state


# === Graph construction ======================================================
# Nothing is invoked here. The original module ran a full audit AND remediation
# at import time, so simply importing it fired live Kong and LLM calls and the
# Flask app could not start without them.

def build_audit_graph():
    graph = StateGraph(dict)
    graph.add_node("perceive", perceive_kong)
    graph.add_node("retrieve", retrieve_policies)
    graph.add_node("reason", reason_audit)
    graph.add_node("plan", plan_audit)
    graph.add_node("act", action_audit)
    graph.set_entry_point("perceive")
    graph.add_edge("perceive", "retrieve")
    graph.add_edge("retrieve", "reason")
    graph.add_edge("reason", "plan")
    graph.add_edge("plan", "act")
    graph.add_edge("act", END)  # without an END edge the graph has no finish point
    return graph.compile()


def build_remediation_graph():
    graph = StateGraph(dict)
    graph.add_node("perceive", perceive_issues)
    graph.add_node("retrieve", retrieve_remediation_context)
    graph.add_node("reason", reason_remediation)
    graph.add_node("plan", plan_remediation)
    graph.add_node("act", action_remediation)
    graph.set_entry_point("perceive")
    graph.add_edge("perceive", "retrieve")
    graph.add_edge("retrieve", "reason")
    graph.add_edge("reason", "plan")
    graph.add_edge("plan", "act")
    graph.add_edge("act", END)
    return graph.compile()


audit_app = build_audit_graph()
rem_app = build_remediation_graph()


if __name__ == "__main__":
    # Manual one-shot run: python agents/auditor_agent.py
    audit_state = audit_app.invoke({"selected_standards": ["All Security Standards"]})
    print(json.dumps(audit_state.get("summary", {}), indent=2))
    rem_state = rem_app.invoke({"audit_report": audit_state.get("audit_report", {})})
    print(json.dumps(rem_state.get("summary", {}), indent=2))
    print("Audit and remediation completed.")
