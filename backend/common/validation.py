"""
===============================================================================
 File Name   : common/validation.py
 Description : Request input validation and prompt-safe text handling. Every
               HTTP payload that reaches agents, tools or prompts passes
               through here first: shapes, enums, bounds and lengths are
               enforced with ValueError (mapped to 400), and untrusted
               gateway-derived strings are flattened before prompt use so a
               hostile service name cannot reshape an instruction.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import math
import os
import unicodedata

MAX_NAME_CHARS = 256
MAX_LIST_ITEMS = 200
MAX_OBJECTIVE_CHARS = 2000
MAX_NOTE_CHARS = 2000
MAX_REVIEWER_CHARS = 128
TOP_K_MIN = 1
TOP_K_MAX = 20
SEARCH_TOP_K_MAX = 50
DEPTHS = ("quick", "standard", "deep")
RISK_LEVELS = ("Critical", "High", "Medium", "Low")
PROMPT_TEXT_MAX = 200
MAX_CHAT_MESSAGE_CHARS = 4000
MAX_CONVERSATION_TITLE_CHARS = 120


def coerce_text(value, field, max_len=MAX_NOTE_CHARS, required=False):
    """Plain string with a length cap. Rejects non-string scalars."""
    if value is None:
        if required:
            raise ValueError(f"'{field}' is required.")
        return ""
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError(f"'{field}' must be a string.")
    if len(value) > max_len:
        raise ValueError(f"'{field}' exceeds {max_len} characters.")
    return value


def coerce_name_list(value, field):
    """Single name or list of names, stripped, capped, deduplicated."""
    if value is None:
        return []
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list):
        raise ValueError(f"'{field}' must be a string or list of strings.")
    if len(items) > MAX_LIST_ITEMS:
        raise ValueError(f"'{field}' exceeds {MAX_LIST_ITEMS} entries.")
    cleaned = []
    for item in items:
        if isinstance(item, bool) or not isinstance(item, str):
            raise ValueError(f"'{field}' must contain only strings.")
        item = item.strip()
        if not item:
            continue
        if len(item) > MAX_NAME_CHARS:
            raise ValueError(f"'{field}' entry exceeds {MAX_NAME_CHARS} "
                             "characters.")
        if item not in cleaned:
            cleaned.append(item)
    return cleaned


def coerce_top_k(value, default=4, upper=TOP_K_MAX, field="top_k"):
    try:
        top_k = int(value) if value is not None else default
    except (TypeError, ValueError):
        raise ValueError(f"'{field}' must be an integer.")
    if isinstance(value, bool) or not (TOP_K_MIN <= top_k <= upper):
        raise ValueError(f"'{field}' must be between {TOP_K_MIN} and {upper}.")
    return top_k


def coerce_depth(value):
    depth = str(value or "standard").lower()
    if depth not in DEPTHS:
        raise ValueError(f"'depth' must be one of {list(DEPTHS)}.")
    return depth


def _finite_number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"'{field}' must be a number.")
    if not math.isfinite(value):
        raise ValueError(f"'{field}' must be finite.")
    return float(value)


def coerce_scoring(value):
    """Validate a risk_scoring override dict (None passes through)."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("'risk_scoring' must be an object.")
    cleaned = {}
    if "version" in value:
        cleaned["version"] = coerce_text(value["version"], "version",
                                         max_len=32)
    if "weights" in value:
        weights = value["weights"]
        if not isinstance(weights, dict):
            raise ValueError("'risk_scoring.weights' must be an object.")
        cleaned["weights"] = {
            str(name): _finite_number(score, f"weights.{name}")
            for name, score in weights.items()}
    for key in ("blend_base", "blend_scale"):
        if key in value:
            cleaned[key] = _finite_number(value[key], f"risk_scoring.{key}")
    if "thresholds" in value:
        thresholds = value["thresholds"]
        if not isinstance(thresholds, list) or not thresholds:
            raise ValueError("'risk_scoring.thresholds' must be a "
                             "non-empty list.")
        cleaned_pairs = []
        for pair in thresholds:
            if (not isinstance(pair, (list, tuple)) or len(pair) != 2
                    or pair[1] not in RISK_LEVELS):
                raise ValueError("Each threshold must be [number, level] "
                                 f"with level in {list(RISK_LEVELS)}.")
            cleaned_pairs.append((_finite_number(pair[0], "threshold"),
                                  pair[1]))
        cleaned["thresholds"] = cleaned_pairs
    return cleaned


def safe_knowledge_dir(value, default):
    """Resolve an ingest root. Rejects escapes and empty values.

    The ingest endpoint is admin-only; this guard makes traversal explicit
    rather than relying on that alone.
    """
    candidate = str(value or default or "")
    segments = candidate.replace("\\", "/").split("/")
    if not candidate or ".." in segments:
        raise ValueError("Invalid 'knowledge_dir'.")
    return candidate


def coerce_chat_message(value, field="message",
                        max_len=MAX_CHAT_MESSAGE_CHARS, required=True):
    """Chat message text: required non-empty string with a length cap."""
    if value is None:
        if required:
            raise ValueError(f"'{field}' is required.")
        return ""
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError(f"'{field}' must be a string.")
    text = value.strip()
    if required and not text:
        raise ValueError(f"'{field}' must not be empty.")
    if len(value) > max_len:
        raise ValueError(f"'{field}' exceeds {max_len} characters.")
    return text


def sanitize_for_prompt(value, max_len=PROMPT_TEXT_MAX):
    """Flatten untrusted text to one safe prompt line.

    Control characters and line breaks become spaces, runs collapse, and
    the result truncates. Gateway-derived names/paths pass through this
    before prompt interpolation.
    """
    flat = "".join(" " if unicodedata.category(char).startswith("C") else char
                   for char in str(value or ""))
    flat = " ".join(flat.split())
    if len(flat) > max_len:
        flat = flat[:max_len].rstrip()
    return flat
