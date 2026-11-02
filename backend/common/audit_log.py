"""
===============================================================================
 File Name   : common/audit_log.py
 Description : Append-only hash-chained audit log for security-relevant
               events: assessment lifecycle, approvals, risk transitions,
               change executions (including refusals) and knowledge mutations.
               Each entry hashes the previous entry's hash, so modification is
               detectable via verify(). Tail truncation is not self-detectable;
               ship lines to a central sink with an external counter when that
               matters. Single-process design:
               concurrent writers append atomically per line, but a
               multi-worker deployment should ship these lines to a central
               sink instead of a local file.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from common import config

AUDIT_LOG_FILE = os.path.join(config.ARTIFACT_DIR, "audit.log.jsonl")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _canonical(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


def _entry_hash(body):
    return hashlib.sha256(_canonical(body)).hexdigest()


def _read_entries(path):
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except FileNotFoundError:
        pass
    return entries


def actor_from_context():
    """Best-effort actor label. Never includes key material."""
    try:
        from flask import g, has_request_context
        if has_request_context():
            role = getattr(g, "api_role", None)
            key_fp = getattr(g, "api_key_fp", None)
            if role and role != "open":
                return f"{role}:{key_fp}" if key_fp else str(role)
            if role == "open":
                return "anonymous"
    except Exception:
        pass
    return "system"


def record(event, assessment_id=None, details=None, actor=None, path=None):
    """Append one entry and return it. Never raises on logging failure."""
    path = path or AUDIT_LOG_FILE
    entry = {
        "at": _now(),
        "event": str(event),
        "actor": actor or actor_from_context(),
        "assessment_id": assessment_id,
        "details": details if isinstance(details, dict) else {},
        "prev": "",
    }
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        entries = _read_entries(path)
        entry["seq"] = len(entries) + 1
        if entries:
            entry["prev"] = entries[-1].get("hash", "")
        body = {key: entry[key] for key in
                ("seq", "at", "event", "actor", "assessment_id",
                 "details", "prev")}
        entry["hash"] = _entry_hash(body)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except Exception:
        entry["log_error"] = True
    return entry


def verify(path=None):
    """Verify chain integrity. Returns {"ok", "entries", "error"?}."""
    path = path or AUDIT_LOG_FILE
    try:
        entries = _read_entries(path)
    except Exception as exc:
        return {"ok": False, "entries": 0, "error": str(exc)}
    previous = ""
    for position, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            return {"ok": False, "entries": len(entries),
                    "error": f"entry {position} is not an object"}
        if entry.get("seq") != position or entry.get("prev") != previous:
            return {"ok": False, "entries": len(entries),
                    "error": f"chain broken at entry {position}"}
        body = {key: entry.get(key) for key in
                ("seq", "at", "event", "actor", "assessment_id",
                 "details", "prev")}
        if entry.get("hash") != _entry_hash(body):
            return {"ok": False, "entries": len(entries),
                    "error": f"entry {position} was modified"}
        previous = entry.get("hash", "")
    return {"ok": True, "entries": len(entries)}
