"""
===============================================================================
 File Name   : scripts/verify_meta.py
 Description : One-command check that the Meta Model API integration is live.
               Run this after pasting META_API_KEY into backend/.env.

                   python backend/scripts/verify_meta.py

 Project     : Enterprise API Security Auditor
===============================================================================
"""

import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import config, llm  # noqa: E402


OK = "[ OK ]"
FAIL = "[FAIL]"
WARN = "[WARN]"


def check_config_values():
    print("\n1. Configuration")
    print(f"   env file      : {config.ENV_PATH}")
    print(f"   provider      : {llm.provider()}")
    print(f"   model         : {config.META_MODEL}")
    print(f"   base url      : {config.META_BASE_URL}")
    print(f"   key present   : {bool(config.META_API_KEY)}")

    if llm.provider() != "meta":
        print(f"   {WARN} LLM_PROVIDER resolves to '{llm.provider()}', not 'meta'. "
              "Set LLM_PROVIDER=meta in backend/.env.")
        return False

    problems = llm.check_config()
    if problems:
        print(f"   {FAIL} {problems[0]}")
        return False

    print(f"   {OK} configuration complete")
    return True


def check_network():
    """A corporate proxy blocking api.meta.ai is the most common failure here,
    and it looks nothing like an auth error, so test it separately."""
    print("\n2. Network reachability")
    host = config.META_BASE_URL.split("//", 1)[-1].split("/", 1)[0]
    try:
        sock = socket.create_connection((host, 443), timeout=12)
        sock.close()
        print(f"   {OK} TCP {host}:443 reachable")
    except Exception as exc:
        print(f"   {FAIL} cannot open {host}:443 -> {type(exc).__name__}: {exc}")
        return False

    import urllib.error
    import urllib.request
    try:
        request = urllib.request.Request(f"{config.META_BASE_URL}/models")
        with urllib.request.urlopen(request, timeout=15) as response:
            print(f"   {OK} HTTPS reachable (HTTP {response.status})")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        if "zscaler" in body.lower() or "<html" in body[:200].lower():
            print(f"   {FAIL} HTTP {exc.code} from a corporate proxy, not from Meta.")
            print("          api.meta.ai is blocked on this network. Ask IT to allowlist")
            print("          api.meta.ai and dev.meta.ai, or run off the corporate VPN.")
            return False
        # 401/403 with a JSON body just means the probe was unauthenticated.
        print(f"   {OK} endpoint responded (HTTP {exc.code}, unauthenticated probe)")
    except Exception as exc:
        print(f"   {FAIL} {type(exc).__name__}: {exc}")
        return False
    return True


def check_chat():
    print("\n3. Chat completion")
    try:
        reply = llm.chat(
            [{"role": "user", "content": "Reply with exactly this JSON and nothing else: {\"ok\":true}"}],
            max_tokens=200,
        )
        print(f"   response      : {reply!r}")
        parsed = llm.extract_json(reply)
        if parsed and parsed.get("ok") is True:
            print(f"   {OK} model returned valid JSON")
        else:
            print(f"   {WARN} responded but did not return the requested JSON")
        return True
    except Exception as exc:
        print(f"   {FAIL} {type(exc).__name__}: {str(exc)[:400]}")
        return False


def check_structured_audit():
    """The audit agent depends on strict-JSON output, so exercise that shape."""
    print("\n4. Structured audit output")
    messages = [
        {"role": "system", "content":
            'You are an API security auditor. Respond with STRICT JSON only: '
            '{"serviceName": "<name>", "policies": [{"policy_name": "<p>", '
            '"comply": true|false, "missing_plugins": ["<plugin>"], "details": "<why>"}]}'},
        {"role": "user", "content":
            "Kong service 'PaymentService' has plugins ['key-auth']. The Authentication "
            "Policy requires one of key-auth, jwt or oauth2. Audit it."},
    ]
    try:
        parsed, raw = llm.chat_json(messages, expect="object", max_tokens=1200)
        if isinstance(parsed, dict) and parsed.get("policies") is not None:
            print(f"   {OK} parsed structured audit JSON")
            print("   " + json.dumps(parsed, indent=2)[:400].replace("\n", "\n   "))
            return True
        print(f"   {FAIL} could not parse JSON. Raw response:\n   {str(raw)[:300]}")
        return False
    except Exception as exc:
        print(f"   {FAIL} {type(exc).__name__}: {str(exc)[:300]}")
        return False


def main():
    print("=" * 72)
    print(" Meta Model API verification - Enterprise API Security Auditor")
    print("=" * 72)

    steps = [check_config_values, check_network, check_chat, check_structured_audit]
    for step in steps:
        if not step():
            print("\n" + "=" * 72)
            print(" RESULT: not ready. Fix the [FAIL] above and re-run.")
            print("=" * 72)
            return 1

    print("\n" + "=" * 72)
    print(" RESULT: Meta Model API is live. The agents will run on "
          f"{config.META_MODEL}.")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
