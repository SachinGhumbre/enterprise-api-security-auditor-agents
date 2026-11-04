import React, { useState } from 'react';
import { KeyRound, Loader2, ShieldCheck } from 'lucide-react';

import { AGENTS_URL, probeAuth, setApiKey } from '../api/client';

// Demo accounts for the hackathon login page. Usernames are fixed; passwords
// and the role API keys they map to come from frontend/.env (gitignored).
// Passwords are displayed on this page; keys never are. The password check is
// demo UX only — the backend still enforces the role via the mapped API key.
const DEMO_ACCOUNTS = [
  { username: 'admin', blurb: 'full access', passwordEnv: 'REACT_APP_ADMIN_PASSWORD', keyEnv: 'REACT_APP_ADMIN_KEY' },
  { username: 'operator', blurb: 'run & approve', passwordEnv: 'REACT_APP_OPERATOR_PASSWORD', keyEnv: 'REACT_APP_OPERATOR_KEY' },
  { username: 'viewer', blurb: 'read-only', passwordEnv: 'REACT_APP_VIEWER_PASSWORD', keyEnv: 'REACT_APP_VIEWER_KEY' },
];

function readEnv(name) {
  // Docker runtime config first: /runtime-config.js is rewritten from .env at
  // container startup. Local dev has no such file and falls through to the
  // REACT_APP_* values baked in from frontend/.env.
  const runtime = (typeof window !== 'undefined' && window.__RUNTIME_CONFIG__) || {};
  const fromRuntime = runtime[name];
  if (fromRuntime !== undefined && fromRuntime !== null
      && String(fromRuntime).trim() !== '') {
    return String(fromRuntime).trim();
  }
  // Guard on `process.env`, never on bare `process`: webpack's DefinePlugin
  // inlines `process.env` as an object literal, but `process` itself does not
  // exist in the browser bundle, so a bare-process check is always false there
  // and would silently discard every value.
  const env = typeof process.env !== 'undefined' ? process.env : undefined;
  const raw = (env && env[name]) || '';
  // Hand-edited .env lines often carry stray spaces (KEY = value); dotenv
  // trims them, but a value injected via the shell may not be trimmed.
  return String(raw).trim();
}

function Login({ onLogin }) {
  // React bakes REACT_APP_* vars in when the dev server (or build) starts, so
  // editing frontend/.env afterwards leaves every password empty until the
  // server is restarted — the page must say so instead of failing silently.
  const passwordsConfigured = DEMO_ACCOUNTS.some((a) => readEnv(a.passwordEnv));
  if (!passwordsConfigured && typeof console !== 'undefined') {
    console.warn('Demo passwords missing: restart `npm start` so it picks up frontend/.env.');
  }
  const [username, setUsername] = useState('operator');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const account = DEMO_ACCOUNTS.find((a) => a.username === username);
      const expected = account ? readEnv(account.passwordEnv) : '';
      // Demo UX only: ignore accidental whitespace around a pasted password.
      if (!account || !expected || password.trim() !== expected) {
        setError('Incorrect password.');
        setLoading(false);
        return;
      }
      const key = readEnv(account.keyEnv);
      const status = await probeAuth(AGENTS_URL, key);
      if (status === 401) {
        setError(
          key
            ? 'Key rejected by the server. Make sure frontend/.env matches backend/.env.'
            : `No ${username} key configured in frontend/.env, and the server requires auth.`
        );
        setLoading(false);
        return;
      }
      if (status < 200 || status >= 300) {
        setError(`Sign-in probe failed (HTTP ${status}). Is the agents service running?`);
        setLoading(false);
        return;
      }
      setApiKey(key);
      onLogin(username);
    } catch (err) {
      setError('Cannot reach the agents service. Is it running?');
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-b from-brand-100 via-surface-page to-surface-page px-4">
      <div className="w-full max-w-md animate-fade-up">
        <div className="mb-8 text-center">
          <span className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-brand-600 shadow-raised">
            <ShieldCheck className="h-7 w-7 text-white" aria-hidden="true" />
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-ink-primary">
            Enterprise API Security Auditor
          </h1>
          <p className="mt-1.5 text-sm text-ink-secondary">
            Agentic AI compliance auditing for API Gateway
          </p>
        </div>

        {!passwordsConfigured ? (
          <div
            role="alert"
            className="mb-5 rounded-lg border border-[#ecd9a8] bg-[#fdf3dc] px-4 py-2.5
                       text-sm font-medium text-[#7a5b12]"
          >
            Demo passwords not loaded. Restart `npm start` after creating
            frontend/.env — or rebuild if serving a production build.
          </div>
        ) : null}

        <form
          onSubmit={handleSubmit}
          className="rounded-2xl border border-ink-hairline bg-surface-raised p-7 shadow-raised"
        >
          {error ? (
            <div
              role="alert"
              className="mb-5 rounded-lg border border-[#f0c2c2] bg-[#fbeaea] px-4 py-2.5
                         text-sm font-medium text-[#8f2727]"
            >
              {error}
            </div>
          ) : null}

          <label className="block">
            <span className="mb-1.5 block text-sm font-medium text-ink-secondary">Username</span>
            <select
              className="field"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            >
              {DEMO_ACCOUNTS.map((a) => (
                <option key={a.username} value={a.username}>
                  {a.username} — {a.blurb}
                </option>
              ))}
            </select>
          </label>

          <label className="mt-4 block">
            <span className="mb-1.5 block text-sm font-medium text-ink-secondary">Password</span>
            <div className="relative">
              <KeyRound
                className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted"
                aria-hidden="true"
              />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="Demo password (see below)"
                className="field pl-10"
              />
            </div>
          </label>

          <button type="submit" disabled={loading} className="btn-primary mt-7 w-full">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : null}
            {loading ? 'Signing in...' : 'Sign in'}
          </button>

          <div className="mt-5 rounded-lg bg-brand-50 px-4 py-3 ring-1 ring-inset ring-brand-100">
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-secondary">
              Demo credentials
            </p>
            <dl className="mt-2 space-y-1.5">
              {DEMO_ACCOUNTS.map((a) => {
                const configured = Boolean(readEnv(a.passwordEnv));
                return (
                  <div key={a.username} className="flex items-center justify-between gap-3 text-sm">
                    <dt className="font-mono text-ink-primary">{a.username}</dt>
                    <dd className="font-mono text-ink-secondary">
                      {configured ? readEnv(a.passwordEnv) : '(not set)'}
                    </dd>
                  </div>
                );
              })}
            </dl>
          </div>
        </form>
      </div>
    </div>
  );
}

export default Login;
