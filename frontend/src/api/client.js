/**
 * Central API client for the Enterprise API Security Auditor dashboard.
 *
 * Every backend call goes through here so hosts and paths live in one place.
 * Override the defaults with a frontend/.env file:
 *   REACT_APP_AGENTS_URL=http://localhost:5000
 *   REACT_APP_KNOWLEDGE_URL=http://localhost:5001
 *   REACT_APP_REDIS_TEST_URL=http://localhost:5002
 *   REACT_APP_API_KEY=<operator or admin key>  (only when the backends
 *     enforce API-key auth; baked in at build time, so prefer sign-in)
 *
 * The sign-in screen stores the key in sessionStorage (cleared with the
 * tab); every request below attaches it as X-API-Key when present.
 */

// Guard on `process.env`, never on bare `process`: webpack's DefinePlugin
// inlines `process.env` as an object literal, but `process` itself does not
// exist in the browser bundle (see readEnv in components/Login.jsx).
const env = (typeof process.env !== 'undefined' && process.env) || {};

// Docker runtime config: /runtime-config.js is rewritten from .env at
// container startup, so URLs can change without rebuilding the image.
// Local dev has no such file and falls back to REACT_APP_* below.
const runtime =
  (typeof window !== 'undefined' && window.__RUNTIME_CONFIG__) || {};

function pickUrl(name, fallback) {
  const fromRuntime = runtime[name];
  if (fromRuntime !== undefined && fromRuntime !== null
      && String(fromRuntime).trim() !== '') {
    return String(fromRuntime).trim();
  }
  return env[name] || fallback;
}

export const AGENTS_URL = pickUrl('REACT_APP_AGENTS_URL', 'http://localhost:5000');
export const KNOWLEDGE_URL = pickUrl('REACT_APP_KNOWLEDGE_URL', 'http://localhost:5001');
export const REDIS_TEST_URL = pickUrl('REACT_APP_REDIS_TEST_URL', 'http://localhost:5002');

const API_KEY_STORAGE = 'easa.api_key';

export function getApiKey() {
  const bakedKey = runtime.REACT_APP_API_KEY || env.REACT_APP_API_KEY || '';
  try {
    return sessionStorage.getItem(API_KEY_STORAGE) || bakedKey;
  } catch (err) {
    return bakedKey;
  }
}

export function setApiKey(key) {
  try {
    if (key) {
      sessionStorage.setItem(API_KEY_STORAGE, key);
    } else {
      sessionStorage.removeItem(API_KEY_STORAGE);
    }
  } catch (err) {
    // Private browsing etc: the app still works, the key just won't persist.
  }
}

let onUnauthorized = null;

/** App-level hook (sign-out + notice) fired on HTTP 401. */
export function setOnUnauthorized(handler) {
  onUnauthorized = handler;
}

/** Lightweight auth probe used by sign-in; never fires the hook itself. */
export async function probeAuth(baseUrl, key, timeout = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const headers = key ? { 'X-API-Key': key } : undefined;
    const response = await fetch(`${baseUrl}/api/v1/ai-agents/llm/calls?limit=1`, {
      headers,
      signal: controller.signal,
    });
    return response.status;
  } finally {
    clearTimeout(timer);
  }
}

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
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const apiKey = getApiKey();
    if (apiKey) headers['X-API-Key'] = apiKey;
    const response = await fetch(url, {
      method,
      headers,
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
      const error = new ApiError(detail, response.status, payload);
      if (response.status === 401 && typeof onUnauthorized === 'function') {
        try {
          onUnauthorized(error);
        } catch (hookErr) {
          // Never let the hook mask the original failure.
        }
      }
      throw error;
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

/* --- Multi-agent assessments -------------------------------------------------- */

const ASSESS = `${AGENTS_URL}/api/v1/ai-agents/assess`;

export const assess = {
  list: () => request(ASSESS, { timeout: 30000 }),

  start: (payload) =>
    request(`${ASSESS}?async=true`, { method: 'POST', body: payload || {} }),

  status: (id) => request(`${ASSESS}/${id}`, { timeout: 30000 }),

  details: (id) => request(`${ASSESS}/${id}/details`, { timeout: 30000 }),

  resume: (id, { decision, reviewer, note } = {}) =>
    request(`${ASSESS}/${id}/resume`, {
      method: 'POST',
      body: { decision, reviewer, note },
    }),

  executiveSummary: (id) =>
    request(`${ASSESS}/${id}/executive-summary`, { method: 'POST', body: {} }),

  changes: (id) => request(`${ASSESS}/${id}/changes`, { timeout: 30000 }),

  approveChange: (id, changeId, reviewer, note) =>
    request(`${ASSESS}/${id}/changes/${changeId}/approve`, {
      method: 'POST',
      body: { reviewer, note },
    }),

  executeChange: (id, changeId, mode) =>
    request(`${ASSESS}/${id}/changes/${changeId}/execute`, {
      method: 'POST',
      body: { mode },
    }),

  transitionRisk: (id, entryId, toState, actor, note) =>
    request(`${ASSESS}/${id}/risk/${entryId}/transition`, {
      method: 'POST',
      body: { to_state: toState, actor, note },
    }),
};

/* --- AI Security Assistant ---------------------------------------------------- */

const ASSISTANT = `${AGENTS_URL}/api/v1/ai-agents/assistant`;

export const assistant = {
  prompts: () => request(`${ASSISTANT}/prompts`, { timeout: 30000 }),

  listConversations: (limit = 50) =>
    request(`${ASSISTANT}/conversations?limit=${limit}`, { timeout: 30000 }),

  createConversation: ({ title, assessmentId } = {}) =>
    request(`${ASSISTANT}/conversations`, {
      method: 'POST',
      body: {
        ...(title ? { title } : {}),
        ...(assessmentId ? { assessment_id: assessmentId } : {}),
      },
      timeout: 30000,
    }),

  getConversation: (id, { messages = true, limit = 100 } = {}) =>
    request(
      `${ASSISTANT}/conversations/${encodeURIComponent(id)}?messages=${messages}&limit=${limit}`,
      { timeout: 30000 }
    ),

  deleteConversation: (id) =>
    request(`${ASSISTANT}/conversations/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      timeout: 30000,
    }),

  sendMessage: (id, message, assessmentId) =>
    request(`${ASSISTANT}/conversations/${encodeURIComponent(id)}/messages`, {
      method: 'POST',
      body: {
        message,
        ...(assessmentId ? { assessment_id: assessmentId } : {}),
      },
    }),

  task: (taskId) =>
    request(`${ASSISTANT}/tasks/${encodeURIComponent(taskId)}`, { timeout: 30000 }),

  /**
   * Streaming chat turn. Calls onHeader once (intent, cards, task), onDelta
   * per text chunk, and resolves with the done payload. Same auth and
   * error semantics as request().
   */
  sendMessageStream: async (id, { message, assessmentId } = {}, { onHeader, onDelta } = {}) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
    try {
      const headers = { 'Content-Type': 'application/json' };
      const apiKey = getApiKey();
      if (apiKey) headers['X-API-Key'] = apiKey;
      const response = await fetch(
        `${ASSISTANT}/conversations/${encodeURIComponent(id)}/messages/stream`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({
            message,
            ...(assessmentId ? { assessment_id: assessmentId } : {}),
          }),
          signal: controller.signal,
        }
      );
      if (!response.ok) {
        const text = await response.text();
        let payload = null;
        try {
          payload = text ? JSON.parse(text) : null;
        } catch (err) {
          payload = { raw: text };
        }
        const detail =
          (payload && (payload.error || payload.message)) ||
          `Request failed (${response.status})`;
        const error = new ApiError(detail, response.status, payload);
        if (response.status === 401 && typeof onUnauthorized === 'function') {
          try {
            onUnauthorized(error);
          } catch (hookErr) {
            // Never let the hook mask the original failure.
          }
        }
        throw error;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let done = null;
      for (;;) {
        const { value, done: finished } = await reader.read();
        if (finished) break;
        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split('\n\n');
        buffer = frames.pop();
        for (const frame of frames) {
          for (const line of frame.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed.startsWith('data:')) continue;
            let event = null;
            try {
              event = JSON.parse(trimmed.slice(5).trim());
            } catch (err) {
              continue;
            }
            if (event.delta && typeof onDelta === 'function') onDelta(event.delta);
            else if (event.type === 'header' && typeof onHeader === 'function') onHeader(event);
            else if (event.type === 'done') done = event;
            else if (event.error) throw new ApiError(event.error, 0, event);
          }
        }
      }
      return done;
    } catch (err) {
      if (err.name === 'AbortError') {
        throw new ApiError(
          `Request timed out after ${Math.round(DEFAULT_TIMEOUT_MS / 1000)}s`, 0, null
        );
      }
      if (err instanceof ApiError) throw err;
      throw new ApiError(`Cannot reach ${new URL(ASSISTANT).host}. Is the service running?`, 0, null);
    } finally {
      clearTimeout(timer);
    }
  },
};

/* --- Model usage & evaluation ----------------------------------------------- */

export const models = {
  calls: (limit = 100) =>
    request(`${AGENTS_URL}/api/v1/ai-agents/llm/calls?limit=${limit}`, { timeout: 30000 }),

  policy: () => request(`${AGENTS_URL}/api/v1/ai-agents/llm/policy`, { timeout: 30000 }),

  retrievalEval: (store = 'fake') =>
    request(
      `${AGENTS_URL}/api/v1/ai-agents/eval/retrieval?store=${store}`,
      { timeout: 120000 }
    ),
};

export function rememberAssessment(id) {
  try {
    if (id) sessionStorage.setItem('easa.last_assessment', id);
  } catch (err) {
    // ignore
  }
}

export function lastAssessment() {
  try {
    return sessionStorage.getItem('easa.last_assessment') || '';
  } catch (err) {
    return '';
  }
}

export { ApiError };
