import React, { useState } from 'react';
import { KeyRound, Loader2, ShieldCheck, User } from 'lucide-react';

// Demo-only credential gate. There is no backend auth in this project, so this
// is presentation scaffolding, not a security boundary.
const DEMO_USERNAME = 'ai_champion';
const DEMO_PASSWORD = 'Meta@123';

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setTimeout(() => {
      if (username === DEMO_USERNAME && password === DEMO_PASSWORD) {
        onLogin(username);
      } else {
        setError('Invalid credentials.');
        setLoading(false);
      }
    }, 600);
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
            <div className="relative">
              <User
                className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted"
                aria-hidden="true"
              />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                placeholder="Enter username"
                className="field pl-10"
              />
            </div>
          </label>

          <label className="mt-5 block">
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
                autoComplete="current-password"
                placeholder="Enter password"
                className="field pl-10"
              />
            </div>
          </label>

          <button type="submit" disabled={loading} className="btn-primary mt-7 w-full">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : null}
            {loading ? 'Signing in...' : 'Sign in'}
          </button>

          <p className="mt-5 rounded-lg bg-brand-50 px-3 py-2 text-center text-xs text-ink-secondary ring-1 ring-inset ring-brand-100">
            Demo credentials:{' '}
            <code className="font-mono font-semibold text-brand-800">
              {DEMO_USERNAME} / {DEMO_PASSWORD}
            </code>
          </p>
        </form>
      </div>
    </div>
  );
}

export default Login;
