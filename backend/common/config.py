"""
===============================================================================
 File Name   : common/config.py
 Description : Single source of truth for configuration. Loads backend/.env
               regardless of which directory a service is started from.
 Project     : Enterprise API Security Auditor
===============================================================================
"""

import os

from dotenv import load_dotenv

# Corporate TLS-inspection proxies re-sign traffic with an internal root CA that
# lives in the OS trust store but not in certifi's bundle, so `requests` fails
# with SSLError against endpoints that curl/urllib reach fine. truststore makes
# Python use the OS store instead, keeping verification enabled.
TRUSTSTORE_ACTIVE = False
try:
    import truststore

    truststore.inject_into_ssl()
    TRUSTSTORE_ACTIVE = True
except Exception:  # pragma: no cover - optional dependency
    pass

# backend/common/config.py -> backend/
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
ENV_PATH = os.getenv("ENV_FILE") or os.path.join(BACKEND_DIR, ".env")

# A plain load_dotenv() only walks *up* from the current working directory, so a
# service started from backend/agents/ or from the repo root would silently miss
# backend/.env and fall back to None for every setting.
load_dotenv(ENV_PATH if os.path.exists(ENV_PATH) else None)


def _clean(value):
    """Strip whitespace and stray quotes left by hand-edited .env files."""
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1].strip()
    return value or None


def get(name, default=None):
    value = _clean(os.getenv(name))
    return value if value is not None else default


def get_int(name, default):
    try:
        return int(get(name, default))
    except (TypeError, ValueError):
        return int(default)


# --- Redis -------------------------------------------------------------------
REDIS_HOST = get("REDIS_HOST", "localhost")
REDIS_PORT = get_int("REDIS_PORT", 6379)
REDIS_PASSWORD = get("REDIS_PASSWORD")
VECTOR_DIMENSIONS = get_int("VECTOR_DIMENSIONS", 1536)
INDEX_NAME = get("INDEX_NAME", "security_auditor_index")
KEY_PREFIX = get("KEY_PREFIX", "embedding:")

# --- Knowledge base ----------------------------------------------------------
_kb = get("KNOWLEDGE_BASE_DIR", "knowledge_base")
KNOWLEDGE_DIR = _kb if os.path.isabs(_kb) else os.path.join(BACKEND_DIR, _kb)
CHUNK_SIZE = get_int("CHUNK_SIZE", 900)
CHUNK_OVERLAP = get_int("CHUNK_OVERLAP", 120)

# --- Meta Model API ----------------------------------------------------------
# Meta Model API is OpenAI-compatible: the openai SDK works against it by simply
# pointing base_url at https://api.meta.ai/v1 and passing the Meta key.
# Docs: https://developer.meta.com/ai/resources/blog/build-with-muse-spark/
META_API_KEY = get("META_API_KEY") or get("MODEL_API_KEY")
META_BASE_URL = (get("META_BASE_URL", "https://api.meta.ai/v1") or "").rstrip("/")
META_MODEL = get("META_MODEL", "muse-spark-1.3")

# --- Azure OpenAI ------------------------------------------------------------
AZURE_OPENAI_API_KEY = get("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_ENDPOINT = get("AZURE_OPENAI_ENDPOINT")
AZURE_API_VERSION = get("AZURE_API_VERSION", "2024-12-01-preview")
AZURE_OPENAI_DEPLOYMENT_NAME = get("AZURE_OPENAI_DEPLOYMENT_NAME")
AZURE_OPENAI_EMBEDDING_DEPLOYMENT = get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT")

# --- Kong --------------------------------------------------------------------
# Trailing slashes produce "//services" once joined, which some gateways 404 on.
KONG_ADMIN_API = (get("KONG_ADMIN_API") or "").rstrip("/") or None
KONG_ADMIN_TOKEN = get("KONG_ADMIN_TOKEN")
KONG_HTTP_TIMEOUT = get_int("KONG_HTTP_TIMEOUT", 30)
KONG_PAGE_SIZE = get_int("KONG_PAGE_SIZE", 1000)
# Live remediation writes are off unless explicitly enabled. Simulation and
# proposal validation always work; only execute() consults this flag.
KONG_WRITE_ENABLED = (get("KONG_WRITE_ENABLED", "false") or "").lower() == "true"


def _key_list(name):
    return [k.strip() for k in (get(name) or "").split(",") if k.strip()]


# API-key auth (common/auth.py). Empty everywhere = single-user mode.
ADMIN_API_KEYS = _key_list("ADMIN_API_KEYS")
OPERATOR_API_KEYS = _key_list("OPERATOR_API_KEYS")
VIEWER_API_KEYS = _key_list("VIEWER_API_KEYS")
ALLOWED_ORIGINS = [o.strip() for o in (get("ALLOWED_ORIGINS") or "").split(",")
                   if o.strip()]
REDIS_USERNAME = get("REDIS_USERNAME")
# Resilient discovery: bounded retries for transient failures, capped
# rate-limit waits, and the Redis snapshot cache with its staleness horizon.
KONG_MAX_RETRIES = get_int("KONG_MAX_RETRIES", 2)
KONG_RETRY_BACKOFF_S = get_int("KONG_RETRY_BACKOFF_S", 1)
KONG_RETRY_MAX_WAIT_S = get_int("KONG_RETRY_MAX_WAIT_S", 5)
KONG_SNAPSHOT_KEY = get("KONG_SNAPSHOT_KEY", "kong:snapshot:latest")
KONG_SNAPSHOT_STALE_S = get_int("KONG_SNAPSHOT_STALE_S", 3600)
KONG_AI_PROXY_HOSTNAME = (get("KONG_AI_PROXY_HOSTNAME") or "").rstrip("/") or None
KONG_API_KEY = get("KONG_API_KEY")

# Kong Konnect and self-managed Kong differ in three ways that matter here:
#   auth header : Authorization: Bearer <PAT>   vs  kong-admin-token: <token>
#   entity path : /core-entities/services       vs  /services
#   TLS         : valid public cert             vs  usually self-signed
# "auto" detects Konnect from the hostname; override with konnect | onprem.
KONG_ADMIN_MODE = (get("KONG_ADMIN_MODE", "auto") or "auto").lower()


def resolve_kong_mode():
    if KONG_ADMIN_MODE in ("konnect", "onprem"):
        return KONG_ADMIN_MODE
    host = (KONG_ADMIN_API or "").lower()
    return "konnect" if ("api.konghq.com" in host or "/control-planes/" in host) else "onprem"


def kong_is_konnect():
    return resolve_kong_mode() == "konnect"


# Konnect serves a valid public certificate, so verification should stay on.
# Self-managed admin APIs are usually fronted by a self-signed cert in a lab.
_verify_raw = get("KONG_ADMIN_VERIFY_SSL")
if _verify_raw is None:
    KONG_ADMIN_VERIFY_SSL = kong_is_konnect()
else:
    KONG_ADMIN_VERIFY_SSL = _verify_raw.lower() == "true"


def kong_auth_headers():
    """Auth header appropriate to the configured Kong flavour."""
    token = KONG_ADMIN_TOKEN or ""
    if kong_is_konnect():
        # Konnect personal access tokens (kpat_...) are Bearer credentials;
        # sending them as kong-admin-token returns 401.
        return {"Authorization": f"Bearer {token}"}
    return {"kong-admin-token": token}


def kong_entity_path(entity):
    """Map a logical entity path to the configured Kong flavour.

    Konnect nests gateway entities under core-entities/ on the control plane,
    so a bare /services returns 404 there.
    """
    entity = entity.lstrip("/")
    if kong_is_konnect() and not entity.startswith("core-entities/"):
        return f"core-entities/{entity}"
    return entity

# --- Provider selection ------------------------------------------------------
# "meta"  -> Meta Model API (Muse Spark) - the hackathon target
# "kong"  -> route LLM calls through Kong AI Gateway
# "azure" -> call Azure OpenAI directly
# "auto"  -> prefer Meta when META_API_KEY is set, then Kong, then Azure
LLM_PROVIDER = (get("LLM_PROVIDER", "auto") or "auto").lower()

# "azure" -> Azure embeddings deployment
# "local" -> deterministic hashed bag-of-words, for offline/demo use only
EMBEDDING_PROVIDER = (get("EMBEDDING_PROVIDER", "auto") or "auto").lower()

# Hackathon lock: when true, any attempt to serve a request from a non-Meta
# provider raises instead of silently succeeding. Guards against an
# accidental Azure/Kong call counting as hackathon usage.
META_ONLY = (get("META_ONLY", "true") or "true").lower() == "true"

LLM_TIMEOUT = get_int("LLM_TIMEOUT", 120)

# --- Model router ------------------------------------------------------------
# Ordered fallback providers tried after the primary fails on a retryable
# error (timeout, connection, 5xx, 429). Space/comma separated, e.g. "azure"
# or "azure,kong"; "none" (default) disables fallback. Auth failures,
# malformed requests and unknown-model errors never fall back.
LLM_FALLBACK_ORDER = [p for p in (
    (get("LLM_FALLBACK_ORDER", "none") or "").lower().replace(",", " ").split()
) if p in ("azure", "kong")]
ROUTER_MAX_RETRIES = get_int("ROUTER_MAX_RETRIES", 2)
CIRCUIT_THRESHOLD = get_int("CIRCUIT_THRESHOLD", 5)
CIRCUIT_COOLDOWN_S = get_int("CIRCUIT_COOLDOWN_S", 60)
LLM_MAX_TOKENS = get_int("LLM_MAX_TOKENS", 8000)
# Findings per remediation LLM call. Keeps each response inside the token cap
# regardless of how many Kong services were audited.
REMEDIATION_BATCH_SIZE = get_int("REMEDIATION_BATCH_SIZE", 5)

# --- Artifacts ---------------------------------------------------------------
ARTIFACT_DIR = get("ARTIFACT_DIR", os.path.join(BACKEND_DIR, "artifacts"))


def resolve_llm_provider():
    if LLM_PROVIDER in ("meta", "kong", "azure"):
        return LLM_PROVIDER
    if META_API_KEY:
        return "meta"
    if KONG_AI_PROXY_HOSTNAME and KONG_API_KEY:
        return "kong"
    return "azure"


def active_model():
    """Model identifier for the resolved provider, for display and logging."""
    provider = resolve_llm_provider()
    if provider == "meta":
        return META_MODEL
    if provider == "kong":
        return f"via Kong AI Gateway ({KONG_AI_PROXY_HOSTNAME})"
    return AZURE_OPENAI_DEPLOYMENT_NAME


def resolve_embedding_provider():
    if EMBEDDING_PROVIDER in ("azure", "local"):
        return EMBEDDING_PROVIDER
    return "azure" if (AZURE_OPENAI_API_KEY and AZURE_OPENAI_EMBEDDING_DEPLOYMENT) else "local"


def summary():
    """Non-secret snapshot of effective configuration, safe to return over HTTP."""
    return {
        "env_file": ENV_PATH if os.path.exists(ENV_PATH) else None,
        "redis": {"host": REDIS_HOST, "port": REDIS_PORT,
                  "index_name": INDEX_NAME, "vector_dimensions": VECTOR_DIMENSIONS},
        "knowledge_dir": KNOWLEDGE_DIR,
        "llm": {"provider": resolve_llm_provider(),
                "model": active_model(),
                "meta_base_url": META_BASE_URL,
                "meta_model": META_MODEL,
                "meta_key_configured": bool(META_API_KEY),
                "meta_only_enforced": META_ONLY,
                "azure_endpoint": AZURE_OPENAI_ENDPOINT,
                "azure_deployment": AZURE_OPENAI_DEPLOYMENT_NAME,
                "kong_ai_proxy": KONG_AI_PROXY_HOSTNAME},
        "embeddings": {"provider": resolve_embedding_provider(),
                       "azure_deployment": AZURE_OPENAI_EMBEDDING_DEPLOYMENT},
        "kong": {
            "admin_api": KONG_ADMIN_API,
            "mode": resolve_kong_mode(),
            "auth_header": "Authorization: Bearer" if kong_is_konnect() else "kong-admin-token",
            "verify_ssl": KONG_ADMIN_VERIFY_SSL,
            "token_configured": bool(KONG_ADMIN_TOKEN),
        },
        "tls": {"system_trust_store": TRUSTSTORE_ACTIVE},
    }
