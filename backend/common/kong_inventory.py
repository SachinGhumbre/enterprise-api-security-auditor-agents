"""
===============================================================================
 File Name   : common/kong_inventory.py
 Description : Enterprise Kong inventory discovery. Normalises services,
               routes, plugins and consumers from any supported Kong flavour
               into one internal representation, tolerates partial collection
               failures with explicit gaps, caches the last successful snapshot
               in Redis with capture metadata, diffs snapshots for
               configuration-change detection, and probes optional collections
               so no environment is assumed to expose identical APIs.
               Read-only: every gateway call here is a GET.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import copy
import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from common import config, policy

SNAPSHOT_VERSION = "1.0.0"
MAX_DIFF_ENTRIES = 50


class KongInventoryError(RuntimeError):
    """Inventory discovery failed (services collection unreachable)."""


class KongSnapshotError(RuntimeError):
    """The Redis snapshot cache could not be written."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _snapshot_keys():
    base = config.KONG_SNAPSHOT_KEY
    return base, f"{base}:previous"


def join_inventory(services, routes, plugins, service_names=None):
    """Normalise raw Kong collections into the internal inventory shape.

    Route-level plugins attribute upward to their owning service; plugins
    bound to nothing are gateway-wide; consumer-only bindings are ignored
    (consumers are inventoried separately). routes/plugins may be None when
    their collection failed; the join degrades honestly instead of guessing.
    """
    services = services or []
    routes = routes or []
    plugins = plugins or []

    route_to_service: Dict[str, str] = {}
    for route in routes:
        service_ref = route.get("service") or {}
        if route.get("id") and service_ref.get("id"):
            route_to_service[route["id"]] = service_ref["id"]

    routes_by_id = {r.get("id"): r for r in routes if r.get("id")}
    route_plugins: Dict[str, set] = {}
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
            owner = route_to_service.get(route_ref["id"])
            if owner:
                service_plugins.setdefault(owner, set()).add(name)
                route_plugins.setdefault(route_ref["id"], set()).add(name)
        elif not plugin.get("consumer"):
            global_plugins.add(name)

    wanted = {n.lower() for n in service_names} if service_names else None

    inventory = []
    for service in services:
        service_id = service.get("id")
        name = service.get("name") or service_id
        if wanted and str(name).lower() not in wanted:
            continue
        service_routes = []
        for route_id, owner_id in route_to_service.items():
            if owner_id != service_id:
                continue
            route = routes_by_id.get(route_id, {})
            service_routes.append({
                "id": route_id,
                "name": route.get("name") or route_id,
                "paths": route.get("paths") or [],
                "methods": route.get("methods") or [],
                "plugin_names": sorted(route_plugins.get(route_id, set())),
            })
        inventory.append({
            "service_name": name,
            "service_id": service_id,
            "service_plugins": sorted(service_plugins.get(service_id, set()) | global_plugins),
            "route_count": sum(1 for r, s in route_to_service.items() if s == service_id),
            "service_routes": service_routes,
        })
    return inventory


def collect_report(service_names=None, fetch=None):
    """Fetch each collection separately so one failure degrades, not aborts.

    Returns {"inventory", "gaps", "collections"}. A services failure is
    fatal (nothing to join); routes/plugins failures produce explicit gaps.
    """
    from agents import auditor_agent
    fetch = fetch or auditor_agent.fetch_kong_data
    data: Dict[str, list] = {}
    gaps: List[Dict[str, str]] = []
    for endpoint in ("services", "routes", "plugins"):
        try:
            data[endpoint] = fetch(endpoint) or []
        except Exception as exc:
            gaps.append({"collection": endpoint, "error": str(exc)[:300]})
    if "services" not in data:
        raise KongInventoryError(
            "services collection failed: "
            f"{next(g['error'] for g in gaps if g['collection'] == 'services')}")
    inventory = join_inventory(data["services"], data.get("routes"),
                               data.get("plugins"), service_names)
    return {"inventory": inventory, "gaps": gaps,
            "collections": {k: len(v) for k, v in data.items()}}


def probe_collection(endpoint, fetch=None):
    """Best-effort capability probe for one optional collection.

    Environments differ; a missing collection is reported unsupported, never
    fatal. Returns {"collection", "supported", "count"?, "error"?}.
    """
    from agents import auditor_agent
    fetch = fetch or auditor_agent.fetch_kong_data
    try:
        items = fetch(endpoint) or []
    except Exception as exc:
        return {"collection": endpoint, "supported": False,
                "error": str(exc)[:300]}
    return {"collection": endpoint, "supported": True, "count": len(items)}


def save_snapshot(inventory, source, environment=None, gaps=None):
    """Cache the last successful snapshot in Redis, keeping the previous one
    for change detection. Raises KongSnapshotError when Redis is unusable."""
    from common import vector_store
    snapshot = {
        "version": SNAPSHOT_VERSION,
        "captured_at": _now(),
        "source": source,
        "environment": environment or config.resolve_kong_mode(),
        "count": len(inventory or []),
        "inventory": copy.deepcopy(inventory or []),
        "gaps": list(gaps or []),
    }
    try:
        client = vector_store.get_client()
        latest_key, previous_key = _snapshot_keys()
        previous = client.get(latest_key)
        if previous:
            client.set(previous_key, previous)
        client.set(latest_key, json.dumps(snapshot).encode("utf-8"))
    except Exception as exc:
        raise KongSnapshotError(f"snapshot cache write failed: {exc}")
    return snapshot


def _read_snapshot(key):
    from common import vector_store
    raw = vector_store.get_client().get(key)
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    loaded = json.loads(raw)
    return loaded if isinstance(loaded, dict) else None


def load_snapshot(max_age_s=None):
    """Load the cached snapshot with its freshness. Never raises: missing,
    corrupt or unreachable cache returns (None, None)."""
    try:
        snapshot = _read_snapshot(_snapshot_keys()[0])
    except Exception:
        return None, None
    if not snapshot or not isinstance(snapshot.get("inventory"), list):
        return None, None
    freshness = policy.freshness(
        snapshot.get("captured_at"),
        max_age_s=(max_age_s if max_age_s is not None
                   else config.KONG_SNAPSHOT_STALE_S))
    return snapshot, freshness


def load_previous():
    """Load the pre-last snapshot for change detection. Never raises."""
    try:
        return _read_snapshot(_snapshot_keys()[1])
    except Exception:
        return None


def _capped(items):
    items = sorted(items)
    return items[:MAX_DIFF_ENTRIES], max(0, len(items) - MAX_DIFF_ENTRIES)


def diff_snapshots(old_inventory, new_inventory):
    """Detect configuration changes between two snapshots.

    Compares service membership, effective plugins and route bindings.
    Lists cap at MAX_DIFF_ENTRIES with overflow counts, so large estates
    stay readable.
    """
    old_by_name = {s.get("service_name"): s for s in old_inventory or []
                   if isinstance(s, dict)}
    new_by_name = {s.get("service_name"): s for s in new_inventory or []
                   if isinstance(s, dict)}
    added, added_overflow = _capped(set(new_by_name) - set(old_by_name))
    removed, removed_overflow = _capped(set(old_by_name) - set(new_by_name))
    changed = []
    changed_overflow = 0
    for name in sorted(set(old_by_name) & set(new_by_name)):
        old_service, new_service = old_by_name[name], new_by_name[name]
        plugins_added = sorted(set(new_service.get("service_plugins", []))
                               - set(old_service.get("service_plugins", [])))
        plugins_removed = sorted(set(old_service.get("service_plugins", []))
                                 - set(new_service.get("service_plugins", [])))
        old_routes = {r.get("id") for r in old_service.get("service_routes", [])
                      if isinstance(r, dict)}
        new_routes = {r.get("id") for r in new_service.get("service_routes", [])
                      if isinstance(r, dict)}
        if not (plugins_added or plugins_removed or old_routes != new_routes):
            continue
        if len(changed) >= MAX_DIFF_ENTRIES:
            changed_overflow += 1
            continue
        changed.append({
            "service": name,
            "plugins_added": plugins_added[:MAX_DIFF_ENTRIES],
            "plugins_removed": plugins_removed[:MAX_DIFF_ENTRIES],
            "routes_added": sorted(new_routes - old_routes)[:MAX_DIFF_ENTRIES],
            "routes_removed": sorted(old_routes - new_routes)[:MAX_DIFF_ENTRIES],
        })
    return {"services_added": added, "services_added_overflow": added_overflow,
            "services_removed": removed,
            "services_removed_overflow": removed_overflow,
            "changed": changed, "changed_overflow": changed_overflow,
            "unchanged": not (added or removed or changed)}
