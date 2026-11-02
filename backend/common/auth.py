"""
===============================================================================
 File Name   : common/auth.py
 Description : API-key authentication with role-based authorization for the
               Flask apps. Three roles: viewer (read-only), operator (run
               assessments, approve and simulate changes) and admin (ingest,
               index management, deletes, live execution). Disabled when no
               keys are configured (single-user default); enforced otherwise.
               Keys compare in constant time and never appear in logs - audit
               records carry only a key fingerprint.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import hashlib
import hmac

ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}


def auth_enabled():
    """True when at least one API key is configured in any role."""
    from common import config
    return bool(config.ADMIN_API_KEYS or config.OPERATOR_API_KEYS
                or config.VIEWER_API_KEYS)


def _role_keys():
    from common import config
    return (("admin", config.ADMIN_API_KEYS),
            ("operator", config.OPERATOR_API_KEYS),
            ("viewer", config.VIEWER_API_KEYS))


def fingerprint(key):
    """Short non-reversible key id for audit records."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def identify(headers):
    """Map request headers to (role, fingerprint) or (None, None).

    Accepts `Authorization: Bearer <key>` or `X-API-Key: <key>`.
    """
    presented = ""
    authorization = headers.get("Authorization", "") if headers else ""
    if authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    elif headers and headers.get("X-API-Key"):
        presented = str(headers.get("X-API-Key")).strip()
    if not presented:
        return None, None
    for role, keys in _role_keys():
        for candidate in keys or []:
            if candidate and hmac.compare_digest(presented, candidate):
                return role, fingerprint(candidate)
    return None, None


def guard(request, rules):
    """Flask before_request guard. Returns None to allow, else a response.

    `rules` is [(methods, prefix, min_role)] first-match-wins; min_role None
    means open. Paths outside /api/ and unmatched paths are allowed (the
    apps serve API routes only; Flask still 404s unknown paths).
    """
    from flask import g, jsonify
    if not auth_enabled():
        g.api_role = None
        g.api_key_fp = None
        return None
    path = request.path or ""
    method = (request.method or "GET").upper()
    if not path.startswith("/api/"):
        return None
    required = None
    matched = False
    for methods, prefix, min_role in rules or []:
        if path.startswith(prefix) and (methods is None or method in methods):
            required, matched = min_role, True
            break
    if not matched or required is None:
        g.api_role = "open"
        g.api_key_fp = None
        return None
    role, key_fp = identify(request.headers)
    if role is None:
        return jsonify({"error": "Authentication required. Provide a valid "
                                 "API key via Authorization: Bearer or "
                                 "X-API-Key."}), 401
    if ROLE_RANK.get(role, 0) < ROLE_RANK.get(required, 99):
        return jsonify({"error": f"Role '{role}' is not permitted; "
                                 f"'{required}' or higher required."}), 403
    g.api_role = role
    g.api_key_fp = key_fp
    return None


def current_role():
    """Role of the current request, or None when auth is disabled/open."""
    from flask import g, has_request_context
    if not has_request_context():
        return None
    role = getattr(g, "api_role", None)
    return None if role in (None, "open") else role


def live_execution_permitted(mode):
    """True when an execution of `mode` may proceed under the current role.

    Simulation is operator-level (checked by the route guard); live
    execution additionally requires the admin role when auth is enabled.
    """
    if mode != "live":
        return True
    if not auth_enabled():
        return True
    return current_role() == "admin"
