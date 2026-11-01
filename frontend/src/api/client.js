/**
 * Central API client for the Enterprise API Security Auditor dashboard.
 *
 * Every backend call goes through here so hosts and paths live in one place.
 * Override the defaults with a frontend/.env file:
 *   REACT_APP_AGENTS_URL=http://localhost:5000
 *   REACT_APP_KNOWLEDGE_URL=http://localhost:5001
 *   REACT_APP_REDIS_TEST_URL=http://localhost:5002
 */

const env = (typeof process !== 'undefined' && process.env) || {};

export const AGENTS_URL = env.REACT_APP_AGENTS_URL || 'http://localhost:5000';
export const KNOWLEDGE_URL = env.REACT_APP_KNOWLEDGE_URL || 'http://localhost:5001';
export const REDIS_TEST_URL = env.REACT_APP_REDIS_TEST_URL || 'http://localhost:5002';

/** Audit and remediation invoke an LLM per service, so they need a long ceiling. */
const DEFAULT_TIMEOUT_MS = 300000;

class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

async function request(url, { method = 'GET', body, timeout = DEFAULT_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      method,
      headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    const text = await response.text();
    let payload = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch (err) {
        payload = { raw: text };
      }
    }

    if (!response.ok) {
      const detail =
        (payload && (payload.error || payload.message)) || `Request failed (${response.status})`;
      throw new ApiError(detail, response.status, payload);
    }
    return payload;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new ApiError(`Request timed out after ${Math.round(timeout / 1000)}s`, 0, null);
    }
    if (err instanceof ApiError) throw err;
    // fetch() rejects with a bare TypeError when the service is not running.
    throw new ApiError(
      `Cannot reach ${new URL(url).host}. Is the service running?`,
      0,
      null
    );
  } finally {
    clearTimeout(timer);
  }
}

/* --- Health ---------------------------------------------------------------- */

export const health = {
  agents: () => request(`${AGENTS_URL}/api/v1/ai-agents/health`, { timeout: 60000 }),
  knowledge: () => request(`${KNOWLEDGE_URL}/api/v1/knowledge/health`, { timeout: 60000 }),
  redisTest: () => request(`${REDIS_TEST_URL}/redis/index_info`, { timeout: 30000 }),
};

/* --- Knowledge base / RAG --------------------------------------------------- */

export const knowledge = {
  createIndex: (options = {}) =>
    request(`${KNOWLEDGE_URL}/api/v1/knowledge/index`, { method: 'POST', body: options }),

  ingest: ({ reset = true } = {}) =>
    request(`${KNOWLEDGE_URL}/api/v1/knowledge/ingest`, { method: 'POST', body: { reset } }),

  search: (query, topK = 5) =>
    request(`${KNOWLEDGE_URL}/api/v1/knowledge/search`, {
      method: 'POST',
      body: { query, top_k: topK },
      timeout: 60000,
    }),

  listEmbeddings: ({ limit = 50 } = {}) =>
    request(
      `${KNOWLEDGE_URL}/api/v1/knowledge/get_all_embeddings?limit=${limit}&include_vector=false`,
      { timeout: 60000 }
    ),

  stats: () => request(`${KNOWLEDGE_URL}/api/v1/knowledge/stats`, { timeout: 30000 }),

  deleteAll: () =>
    request(`${KNOWLEDGE_URL}/api/v1/knowledge/embeddings`, { method: 'DELETE', timeout: 60000 }),
};

/* --- AI agents -------------------------------------------------------------- */

export const agents = {
  kongServices: () =>
    request(`${AGENTS_URL}/api/v1/ai-agents/kong/services`, { timeout: 60000 }),

  audit: ({ selectedStandards = [], topK = 4, kongData } = {}) =>
    request(`${AGENTS_URL}/api/v1/ai-agents/audit`, {
      method: 'POST',
      body: {
        selected_standards: selectedStandards.length ? selectedStandards : ['All Security Standards'],
        top_k: topK,
        ...(kongData ? { kong_data: kongData } : {}),
      },
    }),

  remediate: (auditReport) =>
    request(`${AGENTS_URL}/api/v1/ai-agents/remediate?envelope=true`, {
      method: 'POST',
      body: auditReport ? { audit_report: auditReport } : {},
    }),

  lastAuditReport: () =>
    request(`${AGENTS_URL}/api/v1/ai-agents/audit/report`, { timeout: 30000 }),

  lastRemediationPlan: () =>
    request(`${AGENTS_URL}/api/v1/ai-agents/remediate/plan`, { timeout: 30000 }),
};

export { ApiError };
