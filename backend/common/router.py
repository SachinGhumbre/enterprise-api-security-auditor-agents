"""
===============================================================================
 File Name   : common/router.py
 Description : Central model router. Every reasoning call in the application
               goes through here with an explicit task type; the router selects
               Muse Spark 1.3 for complex reasoning, applies bounded retries,
               per-model circuit breakers and a configured, observable fallback
               chain, and normalises all responses into ModelResponse.

               Rules:
               - The model id is always passed explicitly; an empty id raises
                 instead of relying on any CLI or API default.
               - Only retryable errors (timeout, connection, 5xx, 429) retry
                 and fall back. Auth failures, malformed requests, unknown
                 models and unclassified errors raise immediately with no
                 silent fallback.
               - The call log records model, task, latency, usage, retries and
                 fallback events. Prompt/response bodies are never logged, and
                 recorded error text is passed through redact().
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from common import config, llm

# --- task types -----------------------------------------------------------------
# Every reasoning call declares one of these; selection policy lives in
# TASK_POLICY, not inside individual agents.

SECURITY_INVESTIGATION = "security_investigation"
EVIDENCE_CORRELATION = "evidence_correlation"
THREAT_MODELLING = "threat_modelling"
RISK_REASONING = "risk_reasoning"
REMEDIATION_PLANNING = "remediation_planning"
EXECUTIVE_EXPLANATION = "executive_explanation"
ASSISTANT_INTENT = "assistant_intent"
ASSISTANT_QA = "assistant_qa"
ASSISTANT_SYNTHESIS = "assistant_synthesis"

TASK_POLICY = {
    SECURITY_INVESTIGATION: {
        "complexity": "high",
        "provider": "meta",
        "reason": ("Per-service compliance judgement needs strong "
                   "instruction-following and strict structured output."),
    },
    EVIDENCE_CORRELATION: {
        "complexity": "high",
        "provider": "meta",
        "reason": ("Correlating conflicting findings across agents needs "
                   "contextual reasoning over evidence."),
    },
    THREAT_MODELLING: {
        "complexity": "high",
        "provider": "meta",
        "reason": ("Threat narratives need domain reasoning grounded in the "
                   "deterministic control catalog."),
    },
    RISK_REASONING: {
        "complexity": "high",
        "provider": "meta",
        "reason": ("Explaining why findings are risky needs contextual "
                   "reasoning; numeric scoring stays deterministic."),
    },
    REMEDIATION_PLANNING: {
        "complexity": "high",
        "provider": "meta",
        "reason": ("Fix plans need a strict ten-field schema with real "
                   "standard citations."),
    },
    EXECUTIVE_EXPLANATION: {
        "complexity": "medium",
        "provider": "meta",
        "reason": ("Board-ready summaries need faithful abstraction over "
                   "verified findings without inventing new claims."),
    },
    ASSISTANT_INTENT: {
        "complexity": "medium",
        "provider": "meta",
        "reason": ("Ambiguous chat messages need instruction-following "
                   "classification into a strict intent JSON schema."),
    },
    ASSISTANT_QA: {
        "complexity": "high",
        "provider": "meta",
        "reason": ("Security explanations must reason over retrieved policy "
                   "evidence and inventory facts without inventing claims."),
    },
    ASSISTANT_SYNTHESIS: {
        "complexity": "high",
        "provider": "meta",
        "reason": ("Cross-agent results need faithful synthesis with "
                   "evidence citations and no invented execution claims."),
    },
}


class RouterError(RuntimeError):
    """The router could not produce a response (all candidates failed)."""


@dataclass
class ModelResponse:
    """Common internal contract for every model call."""

    provider: str
    model: str
    task: str
    text: str
    parsed: Any = None
    latency_ms: float = 0.0
    retries: int = 0
    fallback_used: bool = False
    fallback_reason: str = ""
    skipped: List[Dict[str, str]] = field(default_factory=list)
    usage: Optional[Dict[str, int]] = None
    prompt_chars: int = 0
    response_chars: int = 0
    timestamp: str = ""

    def to_dict(self):
        return {
            "provider": self.provider,
            "model": self.model,
            "task": self.task,
            "latency_ms": self.latency_ms,
            "retries": self.retries,
            "fallback_used": self.fallback_used,
            "fallback_reason": self.fallback_reason,
            "skipped": self.skipped,
            "usage": self.usage,
            "prompt_chars": self.prompt_chars,
            "response_chars": self.response_chars,
            "parsed_ok": self.parsed is not None,
            "timestamp": self.timestamp,
        }


# --- redaction --------------------------------------------------------------------

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/=]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api[-_ ]?key['\"\s:=]+)[^'\"\s,}]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password['\"\s:=]+)[^'\"\s,}]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token['\"\s:=]+)[A-Za-z0-9\-._~+/=]+"), r"\1[REDACTED]"),
    (re.compile(r"\b(sk-[A-Za-z0-9\-_]{8,})"), "[REDACTED]"),
    (re.compile(r"\bkpat_[A-Za-z0-9\-_]+"), "[REDACTED]"),
]


def redact(text):
    """Scrub credential-shaped substrings from text bound for logs."""
    out = str(text or "")
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


# --- error classification -----------------------------------------------------------

_RETRYABLE_TYPES = {
    "RateLimitError", "APIConnectionError", "APITimeoutError",
    "InternalServerError", "ServiceUnavailableError", "ConnectionError",
    "ConnectTimeout", "ReadTimeout", "Timeout",
}

_RETRYABLE_MARKS = (" 429", " 500", " 502", " 503", " 504", "timeout",
                    "timed out", "temporarily", "overloaded", "try again")


def classify_error(exc) -> str:
    """Return auth | bad_request | not_found | retryable | unknown."""
    name = type(exc).__name__
    message = f" {str(exc).lower()} "
    if (name in ("AuthenticationError",) or " 401" in message
            or " 403" in message or "unauthorized" in message
            or "forbidden" in message or "invalid api key" in message
            or "incorrect api key" in message):
        return "auth"
    if "model_not_found" in message or "model was not found" in message:
        return "not_found"
    if name in ("BadRequestError",) or " 400" in message or "invalid_request" in message:
        return "bad_request"
    if name in ("NotFoundError",) or " 404" in message:
        return "not_found"
    if name in _RETRYABLE_TYPES or any(m in message for m in _RETRYABLE_MARKS):
        return "retryable"
    return "unknown"


# --- circuit breaker ------------------------------------------------------------------

class CircuitBreaker:
    """Per-model breaker: opens after `threshold` consecutive retryable
    failures, allows one half-open probe after `cooldown_s`."""

    def __init__(self, threshold=5, cooldown_s=60):
        self.threshold = max(1, int(threshold))
        self.cooldown_s = max(1, int(cooldown_s))
        self._lock = threading.Lock()
        self._failures: Dict[str, int] = {}
        self._opened_at: Dict[str, float] = {}

    def allow(self, key):
        with self._lock:
            opened = self._opened_at.get(key)
            if opened is None:
                return True
            if time.monotonic() - opened >= self.cooldown_s:
                # Half-open: one probe, re-decided by its outcome.
                del self._opened_at[key]
                self._failures[key] = self.threshold - 1
                return True
            return False

    def record_success(self, key):
        with self._lock:
            self._failures.pop(key, None)
            self._opened_at.pop(key, None)

    def record_failure(self, key):
        with self._lock:
            count = self._failures.get(key, 0) + 1
            self._failures[key] = count
            if count >= self.threshold:
                self._opened_at[key] = time.monotonic()

    def state(self, key):
        with self._lock:
            if key in self._opened_at:
                return "open"
            return "closed"


# --- transports -------------------------------------------------------------------------

def default_transport(provider, model, messages, max_tokens, route):
    """Raw provider call. Returns (text, usage|None)."""
    if provider == "meta":
        return llm.complete_meta(model, messages, max_tokens)
    if provider == "azure":
        return llm.complete_azure(model, messages, max_tokens)
    if provider == "kong":
        return llm.complete_kong(messages, route, max_tokens)
    raise RouterError(f"Unknown provider '{provider}'.")


def default_stream_transport(provider, model, messages, max_tokens, route):
    """Raw streaming call. Returns an iterator of text deltas."""
    if provider == "meta":
        return llm.stream_meta(model, messages, max_tokens)
    if provider == "azure":
        return llm.stream_azure(model, messages, max_tokens)
    raise RouterError(
        f"Streaming is not supported for provider '{provider}'.")


# --- router -------------------------------------------------------------------------------

class Router:
    def __init__(self, transport=None, stream_transport=None, max_retries=None,
                 backoff_base_s=0.2, fallback_order=None, circuit_threshold=None,
                 circuit_cooldown_s=None, log_size=200):
        self.transport = transport or default_transport
        self.stream_transport = stream_transport or default_stream_transport
        self.max_retries = (config.ROUTER_MAX_RETRIES if max_retries is None
                            else int(max_retries))
        self.backoff_base_s = float(backoff_base_s)
        self.fallback_order = (list(config.LLM_FALLBACK_ORDER)
                               if fallback_order is None else list(fallback_order))
        self.breaker = CircuitBreaker(
            threshold=(config.CIRCUIT_THRESHOLD if circuit_threshold is None
                       else circuit_threshold),
            cooldown_s=(config.CIRCUIT_COOLDOWN_S if circuit_cooldown_s is None
                        else circuit_cooldown_s))
        self._log: deque = deque(maxlen=max(1, int(log_size)))
        self._log_lock = threading.Lock()

    # -- selection ------------------------------------------------------------
    def candidates(self, task):
        """Ordered [(provider, model)] with skip records for unusable entries."""
        if task not in TASK_POLICY:
            raise RouterError(
                f"Unknown task '{task}'. Known tasks: {sorted(TASK_POLICY)}.")
        policy = TASK_POLICY[task]
        selected, skipped = [], []
        model = (config.META_MODEL or "").strip() if policy["provider"] == "meta" else ""
        if not model:
            raise RouterError(
                "META_MODEL is empty; refusing to rely on any model default. "
                "Set META_MODEL in backend/.env (e.g. muse-spark-1.3).")
        selected.append(("meta", model))
        for provider in self.fallback_order:
            if config.META_ONLY:
                skipped.append({"provider": provider,
                                "reason": "blocked by META_ONLY=true"})
                continue
            if provider == "azure":
                deployment = config.AZURE_OPENAI_DEPLOYMENT_NAME or ""
                if not deployment:
                    skipped.append({"provider": provider,
                                    "reason": "AZURE_OPENAI_DEPLOYMENT_NAME unset"})
                    continue
                selected.append((provider, deployment))
            elif provider == "kong":
                if not (config.KONG_AI_PROXY_HOSTNAME and config.KONG_API_KEY):
                    skipped.append({"provider": provider,
                                    "reason": "Kong AI Gateway not configured"})
                    continue
                selected.append((provider, config.KONG_AI_PROXY_HOSTNAME))
        return selected, skipped

    # -- logging ---------------------------------------------------------------
    def _record(self, entry):
        entry = dict(entry)
        for key in ("error", "fallback_reason"):
            if entry.get(key):
                entry[key] = redact(str(entry[key])[:500])
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        with self._log_lock:
            self._log.append(entry)

    def get_call_log(self, limit=None):
        with self._log_lock:
            entries = list(self._log)
        return entries[-int(limit):] if limit else entries

    def clear_call_log(self):
        with self._log_lock:
            self._log.clear()

    # -- execution --------------------------------------------------------------
    def run(self, task, messages, expect="any", max_tokens=None, route=None):
        """Run one reasoning call and return a normalised ModelResponse."""
        started = time.monotonic()
        prompt_chars = sum(len(str(m.get("content", ""))) for m in messages)
        selected, skipped = self.candidates(task)
        retries = 0
        fallback_used = False
        fallback_reason = ""
        last_error: Optional[BaseException] = None

        for index, (provider, model) in enumerate(selected):
            key = f"{provider}:{model}"
            if not self.breaker.allow(key):
                skipped.append({"provider": provider, "model": model,
                                "reason": "circuit_open"})
                continue
            if index > 0:
                fallback_used = True
                fallback_reason = redact(str(last_error))[:300]
            for attempt in range(self.max_retries + 1):
                try:
                    text, usage = self.transport(
                        provider, model, messages, max_tokens, route)
                    self.breaker.record_success(key)
                    latency_ms = round((time.monotonic() - started) * 1000, 1)
                    parsed = (llm.extract_json(text, expect=expect)
                              if expect in ("any", "object", "array") else None)
                    response = ModelResponse(
                        provider=provider, model=model, task=task, text=text,
                        parsed=parsed, latency_ms=latency_ms, retries=retries,
                        fallback_used=fallback_used,
                        fallback_reason=fallback_reason, skipped=skipped,
                        usage=usage, prompt_chars=prompt_chars,
                        response_chars=len(str(text or "")),
                        timestamp=datetime.now(timezone.utc).isoformat())
                    self._record({**response.to_dict(), "error": ""})
                    return response
                except Exception as exc:  # noqa: BLE001 - classified below
                    kind = classify_error(exc)
                    if kind == "retryable":
                        self.breaker.record_failure(key)
                        last_error = exc
                        if attempt < self.max_retries:
                            retries += 1
                            time.sleep(self.backoff_base_s * (2 ** attempt))
                            continue
                        break  # retries exhausted -> next candidate
                    # Auth, malformed, unknown-model and unclassified errors
                    # never retry and never fall back.
                    self._record({
                        "provider": provider, "model": model, "task": task,
                        "latency_ms": round((time.monotonic() - started) * 1000, 1),
                        "retries": retries, "fallback_used": False,
                        "fallback_reason": "", "skipped": skipped, "usage": None,
                        "prompt_chars": prompt_chars, "response_chars": 0,
                        "parsed_ok": False,
                        "error": f"{kind}: {exc}",
                    })
                    raise RouterError(
                        f"Model call failed without fallback ({kind}): {exc}"
                    ) from exc

        self._record({
            "provider": selected[-1][0] if selected else "?",
            "model": selected[-1][1] if selected else "?",
            "task": task,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "retries": retries, "fallback_used": fallback_used,
            "fallback_reason": fallback_reason, "skipped": skipped,
            "usage": None, "prompt_chars": prompt_chars, "response_chars": 0,
            "parsed_ok": False,
            "error": f"exhausted: {last_error}",
        })
        raise RouterError(
            f"All model candidates failed for task '{task}': {last_error}"
        ) from last_error

    def run_direct(self, provider, model, task, messages, expect="any",
                 max_tokens=None, route=None):
        """Run one call against an explicit provider+model with no fallback.

        Eval and ops use only: production paths go through run() so the task
        policy selects the model. Retries, circuit breaking and recording
        still apply.
        """
        if task not in TASK_POLICY:
            raise RouterError(f"Unknown task '{task}'.")
        if not (model or "").strip():
            raise RouterError("Refusing to call with an empty model id.")
        started = time.monotonic()
        prompt_chars = sum(len(str(m.get("content", ""))) for m in messages)
        key = f"{provider}:{model}"
        if not self.breaker.allow(key):
            raise RouterError(f"Circuit open for {key}.")
        retries = 0
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                text, usage = self.transport(
                    provider, model, messages, max_tokens, route)
                self.breaker.record_success(key)
                response = ModelResponse(
                    provider=provider, model=model, task=task, text=text,
                    parsed=(llm.extract_json(text, expect=expect)
                            if expect in ("any", "object", "array") else None),
                    latency_ms=round((time.monotonic() - started) * 1000, 1),
                    retries=retries,
                    usage=usage, prompt_chars=prompt_chars,
                    response_chars=len(str(text or "")),
                    timestamp=datetime.now(timezone.utc).isoformat())
                self._record({**response.to_dict(), "error": "", "direct": True})
                return response
            except Exception as exc:  # noqa: BLE001 - classified below
                if classify_error(exc) == "retryable" and attempt < self.max_retries:
                    self.breaker.record_failure(key)
                    last_error = exc
                    retries += 1
                    time.sleep(self.backoff_base_s * (2 ** attempt))
                    continue
                if classify_error(exc) == "retryable":
                    self.breaker.record_failure(key)
                self._record({
                    "provider": provider, "model": model, "task": task,
                    "latency_ms": round((time.monotonic() - started) * 1000, 1),
                    "retries": retries, "fallback_used": False,
                    "fallback_reason": "", "skipped": [], "usage": None,
                    "prompt_chars": prompt_chars, "response_chars": 0,
                    "parsed_ok": False, "direct": True,
                    "error": str(exc),
                })
                raise RouterError(f"Direct call failed: {exc}") from exc

    def run_stream(self, task, messages, max_tokens=None, route=None):
        """Yield {"delta": str} chunks, then a final {"response": dict}.

        Streams are single-attempt by design (no retry/fallback mid-stream);
        use run() for guarded calls.
        """
        started = time.monotonic()
        prompt_chars = sum(len(str(m.get("content", ""))) for m in messages)
        selected, skipped = self.candidates(task)
        provider, model = selected[0]
        key = f"{provider}:{model}"
        if not self.breaker.allow(key):
            raise RouterError(
                f"Circuit open for {key}; streaming refused.")
        try:
            parts = []
            for delta in self.stream_transport(
                    provider, model, messages, max_tokens, route):
                if delta:
                    parts.append(delta)
                    yield {"delta": delta}
            self.breaker.record_success(key)
            text = "".join(parts)
            response = ModelResponse(
                provider=provider, model=model, task=task, text=text,
                latency_ms=round((time.monotonic() - started) * 1000, 1),
                skipped=skipped, prompt_chars=prompt_chars,
                response_chars=len(text),
                timestamp=datetime.now(timezone.utc).isoformat())
            self._record({**response.to_dict(), "error": "", "stream": True})
            yield {"response": response.to_dict()}
        except Exception as exc:  # noqa: BLE001 - recorded, then raised
            if classify_error(exc) == "retryable":
                self.breaker.record_failure(key)
            self._record({
                "provider": provider, "model": model, "task": task,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "retries": 0, "fallback_used": False, "fallback_reason": "",
                "skipped": skipped, "usage": None, "prompt_chars": prompt_chars,
                "response_chars": 0, "parsed_ok": False, "stream": True,
                "error": str(exc),
            })
            raise


_default_router: Optional[Router] = None


def get_router():
    global _default_router
    if _default_router is None:
        _default_router = Router()
    return _default_router


def run(task, messages, **kwargs):
    return get_router().run(task, messages, **kwargs)


def get_call_log(limit=None):
    return get_router().get_call_log(limit)


def clear_call_log():
    return get_router().clear_call_log()
