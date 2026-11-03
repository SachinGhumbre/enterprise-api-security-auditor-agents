"""
===============================================================================
 File Name   : common/llm.py
 Description : Chat-completion access. Meta Model API (Muse Spark) is the
               reasoning provider; Kong AI Gateway remains as an optional route.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import json
import re

import requests

from . import config

_meta_client = None


def _get_meta_client():
    """Meta Model API client.

    Meta Model API exposes an OpenAI-compatible /chat/completions surface, so the
    stock openai SDK works once base_url points at https://api.meta.ai/v1.
    """
    global _meta_client
    if _meta_client is None:
        from openai import OpenAI
        _meta_client = OpenAI(
            base_url=config.META_BASE_URL,
            api_key=config.META_API_KEY,
            timeout=config.LLM_TIMEOUT,
        )
    return _meta_client


def provider():
    return config.resolve_llm_provider()


def model_name():
    return config.active_model()


def check_config():
    """Return a list of human-readable configuration problems (empty when OK)."""
    active = provider()

    if active == "meta":
        if not config.META_API_KEY:
            return [
                "META_API_KEY is not set in backend/.env. Add the key issued by the "
                "Meta Model API console (https://dev.meta.ai/products/meta-model-api)."
            ]
        if not config.META_MODEL:
            return ["META_MODEL is not set in backend/.env (e.g. muse-spark-1.3)."]
        return []

    if active == "kong":
        missing = [n for n, v in (
            ("KONG_AI_PROXY_HOSTNAME", config.KONG_AI_PROXY_HOSTNAME),
            ("KONG_API_KEY", config.KONG_API_KEY),
        ) if not v]
        if missing:
            return [f"Missing environment variable(s) in backend/.env: {', '.join(missing)}."]
        return []

    return [f"Unknown LLM provider '{active}' in backend/.env. Use meta or kong."]


_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def extract_json(text, expect="any"):
    """Best-effort parse of JSON out of an LLM response.

    Models wrap JSON in prose or markdown fences often enough that a bare
    json.loads() is not reliable here.
    """
    if isinstance(text, (dict, list)):
        return text
    if not isinstance(text, str):
        return None

    candidate = _FENCE_RE.sub("", text.strip())
    try:
        return json.loads(candidate)
    except (TypeError, ValueError):
        pass

    openers = ["[", "{"] if expect == "array" else ["{", "["]
    for opener in openers:
        closer = "]" if opener == "[" else "}"
        start, end = candidate.find(opener), candidate.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(candidate[start:end + 1])
            except (TypeError, ValueError):
                continue
    return None


def _unwrap_openai_envelope(payload):
    """Kong's ai-response-transformer may return bare JSON instead of an
    OpenAI envelope. Accept either."""
    if isinstance(payload, dict) and "choices" in payload:
        try:
            return payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return None
    return payload


def chat(messages, route=None, max_tokens=None, temperature=None):
    """Send a chat completion and return the raw response content.

    `route` is the Kong AI Gateway path (e.g. /api/v1/agents/auditor) and is
    only used when the Kong provider is active.
    """
    active = provider()

    if active == "meta":
        # Meta Model API follows the OpenAI chat-completions contract, including
        # the standard max_tokens parameter.
        kwargs = {
            "model": config.META_MODEL,
            "messages": messages,
            "max_tokens": max_tokens or config.LLM_MAX_TOKENS,
        }
        if temperature is not None:
            kwargs["temperature"] = temperature

        try:
            response = _get_meta_client().chat.completions.create(**kwargs)
        except Exception as exc:
            message = str(exc)
            # Some deployments expect max_completion_tokens instead.
            if "max_tokens" in message and "max_completion_tokens" in message:
                kwargs["max_completion_tokens"] = kwargs.pop("max_tokens")
                response = _get_meta_client().chat.completions.create(**kwargs)
            elif "temperature" in message and temperature is not None:
                kwargs.pop("temperature")
                response = _get_meta_client().chat.completions.create(**kwargs)
            elif "model_not_found" in message or "model was not found" in message.lower():
                # The key is valid and the request reached Meta - only the model
                # id is wrong. Point at the authoritative list rather than guessing.
                raise RuntimeError(
                    f"Meta Model API rejected the model id '{config.META_MODEL}' "
                    f"(model_not_found). The key is valid and the request reached Meta; "
                    f"only META_MODEL is wrong. List the ids your key can actually use:\n"
                    f"  curl -H 'Authorization: Bearer $META_API_KEY' {config.META_BASE_URL}/models\n"
                    f"or GET /api/v1/ai-agents/models on this service, then set META_MODEL "
                    f"in backend/.env to one of them."
                ) from exc
            else:
                raise RuntimeError(f"Meta Model API call failed: {message}") from exc

        return response.choices[0].message.content

    if active == "kong":
        url = f"{config.KONG_AI_PROXY_HOSTNAME}{route or ''}"
        response = requests.post(
            url,
            headers={"Content-Type": "application/json", "x-api-key": config.KONG_API_KEY},
            json={"messages": messages},
            timeout=config.LLM_TIMEOUT,
        )
        response.raise_for_status()
        try:
            return _unwrap_openai_envelope(response.json())
        except ValueError:
            return response.text

    raise RuntimeError(
        f"Unknown LLM provider '{active}' in backend/.env. Use meta or kong."
    )


def _usage_of(response):
    """Token usage from an OpenAI-compatible response, or None when absent."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return None
    out = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = getattr(usage, key, None)
        if value is not None:
            out[key] = value
    return out or None


def complete_meta(model, messages, max_tokens=None, temperature=None):
    """Meta Model API completion with an explicit model id.

    Returns (content, usage|None). Never falls back to any default model:
    an empty id raises instead of guessing.
    """
    if not model:
        raise RuntimeError(
            "Meta model id is not configured (META_MODEL is empty). Refusing "
            "to rely on an API default; set META_MODEL in backend/.env.")
    kwargs = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens or config.LLM_MAX_TOKENS,
    }
    if temperature is not None:
        kwargs["temperature"] = temperature

    try:
        response = _get_meta_client().chat.completions.create(**kwargs)
    except Exception as exc:
        message = str(exc)
        # Some deployments expect max_completion_tokens instead.
        if "max_tokens" in message and "max_completion_tokens" in message:
            kwargs["max_completion_tokens"] = kwargs.pop("max_tokens")
            response = _get_meta_client().chat.completions.create(**kwargs)
        elif "temperature" in message and temperature is not None:
            kwargs.pop("temperature")
            response = _get_meta_client().chat.completions.create(**kwargs)
        elif "model_not_found" in message or "model was not found" in message.lower():
            raise RuntimeError(
                f"Meta Model API rejected the model id '{model}' "
                f"(model_not_found). The key is valid and the request reached Meta; "
                f"only the model id is wrong. List the ids your key can actually use:\n"
                f"  curl -H 'Authorization: Bearer $META_API_KEY' {config.META_BASE_URL}/models\n"
                f"or GET /api/v1/ai-agents/models on this service, then set META_MODEL "
                f"in backend/.env to one of them."
            ) from exc
        else:
            raise RuntimeError(f"Meta Model API call failed: {message}") from exc

    return response.choices[0].message.content, _usage_of(response)


def complete_kong(messages, route=None, max_tokens=None):
    """Kong AI Gateway completion. Returns (content, usage|None)."""
    url = f"{config.KONG_AI_PROXY_HOSTNAME}{route or ''}"
    response = requests.post(
        url,
        headers={"Content-Type": "application/json", "x-api-key": config.KONG_API_KEY},
        json={"messages": messages},
        timeout=config.LLM_TIMEOUT,
    )
    response.raise_for_status()
    try:
        payload = response.json()
    except ValueError:
        return response.text, None
    usage = payload.get("usage") if isinstance(payload, dict) else None
    return _unwrap_openai_envelope(payload), (usage if isinstance(usage, dict) else None)


def _iter_deltas(stream):
    for chunk in stream:
        try:
            delta = chunk.choices[0].delta.content
        except (AttributeError, IndexError, TypeError):
            continue
        if delta:
            yield delta


def stream_meta(model, messages, max_tokens=None):
    """Yield text deltas from a streaming Meta completion (OpenAI-compatible)."""
    if not model:
        raise RuntimeError("Meta model id is not configured (META_MODEL is empty).")
    stream = _get_meta_client().chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=max_tokens or config.LLM_MAX_TOKENS,
        stream=True,
    )
    return _iter_deltas(stream)


def list_models():
    """Model ids the configured Meta key can actually use.

    This is the authoritative answer to a `model_not_found` error - the id in
    META_MODEL must appear in this list.
    """
    if provider() != "meta":
        raise RuntimeError(
            f"Model listing is only supported for the Meta provider "
            f"(current provider: {provider()})."
        )
    if not config.META_API_KEY:
        raise RuntimeError("META_API_KEY is not set in backend/.env")

    response = requests.get(
        f"{config.META_BASE_URL}/models",
        headers={"Authorization": f"Bearer {config.META_API_KEY}"},
        timeout=config.LLM_TIMEOUT,
    )

    body = response.text or ""
    if body.lstrip().startswith("<"):
        raise RuntimeError(
            "A network proxy returned an HTML page instead of Meta's response, so the "
            "request never reached Meta. The API key is not the problem. Allowlist "
            "api.meta.ai or run off the corporate network."
        )

    response.raise_for_status()
    payload = response.json()
    entries = payload.get("data", payload if isinstance(payload, list) else [])
    return [m.get("id") for m in entries if isinstance(m, dict) and m.get("id")]


def chat_json(messages, route=None, expect="any", max_tokens=None):
    """chat() plus JSON extraction. Returns (parsed_or_None, raw_text)."""
    raw = chat(messages, route=route, max_tokens=max_tokens)
    return extract_json(raw, expect=expect), raw
