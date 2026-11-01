"""
===============================================================================
 File Name   : scripts/probe_meta_models.py
 Description : Find which Meta Model API model id + endpoint combination this
               key can actually invoke.

               GET /v1/models can list a model that POST /v1/chat/completions
               then rejects with model_not_found - the listing and the
               invocation namespaces are not guaranteed to match, and keys are
               entitled per model. This probes every plausible combination and
               prints a matrix.

                   python backend/scripts/probe_meta_models.py

               Reads META_API_KEY / META_BASE_URL from backend/.env.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config  # noqa: E402

# Prefix forms seen across Meta/OpenRouter/Vercel docs and the hackathon brief.
PREFIXES = ["", "meta-models/", "meta/", "meta-models/meta/"]

ENDPOINTS = [
    ("/chat/completions", "chat"),
    ("/responses", "responses"),
]

PROMPT = "Reply with exactly this JSON and nothing else: {\"ok\":true}"


def _request(path, payload):
    """Returns (http_status, parsed_or_text, is_proxy_block)."""
    url = f"{config.META_BASE_URL}{path}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.META_API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, _maybe_json(body), False
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, _maybe_json(body), body.lstrip().startswith("<")
    except Exception as exc:
        return 0, {"_transport_error": f"{type(exc).__name__}: {exc}"}, False


def _maybe_json(body):
    try:
        return json.loads(body)
    except (TypeError, ValueError):
        return {"_raw": body[:200]}


def discover_models():
    url = f"{config.META_BASE_URL}/models"
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {config.META_API_KEY}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read())
        return [m["id"] for m in body.get("data", []) if m.get("id")]
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        if body.lstrip().startswith("<"):
            print("  A network proxy returned HTML - the request never reached Meta.")
            print("  Allowlist api.meta.ai or run off the corporate network.")
            raise SystemExit(1)
        print(f"  HTTP {exc.code}: {body[:200]}")
        raise SystemExit(1)
    except Exception as exc:
        print(f"  {type(exc).__name__}: {exc}")
        raise SystemExit(1)


def classify(status, body):
    """Short verdict for the matrix."""
    if isinstance(body, dict):
        err = body.get("error") or {}
        code = err.get("code") or ""
        message = err.get("message") or ""
        if body.get("_transport_error"):
            return "TRANSPORT", body["_transport_error"][:60]
        if code == "model_not_found" or "was not found" in message.lower():
            return "NO_MODEL", ""
        if status in (401, 403):
            return "AUTH", message[:60]
        if code or (400 <= status < 600):
            return f"ERR {status}", (code or message)[:60]
    if status == 200:
        return "OK", ""
    return f"HTTP {status}", ""


def extract_reply(body):
    if not isinstance(body, dict):
        return ""
    try:  # chat/completions
        return body["choices"][0]["message"]["content"][:80]
    except (KeyError, IndexError, TypeError):
        pass
    try:  # responses
        out = body.get("output") or body.get("output_text")
        if isinstance(out, str):
            return out[:80]
        if isinstance(out, list) and out:
            first = out[0]
            if isinstance(first, dict):
                content = first.get("content")
                if isinstance(content, list) and content:
                    return str(content[0].get("text", ""))[:80]
        return str(out)[:80] if out else ""
    except Exception:
        return ""


def main():
    if not config.META_API_KEY:
        print("META_API_KEY is not set in backend/.env")
        return 1

    print("=" * 78)
    print(" Meta Model API - model id / endpoint probe")
    print("=" * 78)
    print(f" base_url : {config.META_BASE_URL}")
    print(f" key      : set, {len(config.META_API_KEY)} chars")

    print("\n1. GET /models")
    listed = discover_models()
    for model_id in listed:
        print(f"     {model_id}")

    # Probe the chat-capable models only; image/voice/sam need other surfaces.
    candidates = [m for m in listed if "spark" in m.lower() or "wonder" in m.lower()]
    if not candidates:
        candidates = listed

    print(f"\n2. Probing {len(candidates)} model(s) x {len(PREFIXES)} prefix form(s) "
          f"x {len(ENDPOINTS)} endpoint(s)")
    print(f"   {'model id sent':<46} {'endpoint':<11} {'result':<12} detail")
    print(f"   {'-' * 46} {'-' * 11} {'-' * 12} {'-' * 22}")

    winners = []
    for base_model in candidates:
        for prefix in PREFIXES:
            model_id = f"{prefix}{base_model}"
            for path, kind in ENDPOINTS:
                if kind == "chat":
                    payload = {
                        "model": model_id,
                        "messages": [{"role": "user", "content": PROMPT}],
                        "max_tokens": 64,
                    }
                else:
                    payload = {"model": model_id, "input": PROMPT, "max_output_tokens": 64}

                status, body, proxy = _request(path, payload)
                if proxy:
                    print("\n   PROXY BLOCK - requests are not reaching Meta. Stopping.")
                    return 1

                verdict, detail = classify(status, body)
                print(f"   {model_id:<46} {kind:<11} {verdict:<12} {detail}")

                if verdict == "OK":
                    winners.append((model_id, kind, path, extract_reply(body)))

    print("\n" + "=" * 78)
    if winners:
        print(" WORKING COMBINATIONS")
        for model_id, kind, path, reply in winners:
            print(f"   model={model_id}   endpoint={path}")
            if reply:
                print(f"      reply: {reply!r}")
        best = winners[0]
        print("\n Set in backend/.env:")
        print(f"   META_MODEL = {best[0]}")
        if best[1] != "chat":
            print(f"   (NOTE: only the {best[2]} endpoint worked, not /chat/completions;")
            print("    tell Claude so common/llm.py can be switched to that surface.)")
    else:
        print(" NO WORKING COMBINATION.")
        print(" Every model id was rejected. GET /models lists models the *platform*")
        print(" offers, but invocation requires your key/team to be entitled to them.")
        print(" This is an account provisioning issue, not a code or model-id issue.")
        print(" Ask the Meta hackathon team to enable Muse Spark inference for this key,")
        print(" quoting the model_not_found response above.")
    print("=" * 78)
    return 0 if winners else 2


if __name__ == "__main__":
    raise SystemExit(main())
