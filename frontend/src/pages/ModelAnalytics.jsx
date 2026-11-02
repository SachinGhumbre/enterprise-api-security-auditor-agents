import React, { useCallback, useEffect, useState } from 'react';
import { BarChart3, FlaskConical, RotateCcw } from 'lucide-react';

import { models } from '../api/client';
import { Banner, Card, EmptyState, Spinner, StatTile } from '../components/ui';

export default function ModelAnalytics({ notify }) {
  const [calls, setCalls] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [limit, setLimit] = useState(100);
  const [evalStore, setEvalStore] = useState('fake');
  const [evalResult, setEvalResult] = useState(null);
  const [evalBusy, setEvalBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [callData, policyData] = await Promise.all([
        models.calls(limit),
        models.policy(),
      ]);
      setCalls(callData.calls || []);
      setPolicy(policyData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [limit]);

  useEffect(() => {
    load();
  }, [load]);

  const runEval = async () => {
    setEvalBusy(true);
    try {
      const result = await models.retrievalEval(evalStore);
      setEvalResult(result);
    } catch (err) {
      notify(err.message, 'error');
    } finally {
      setEvalBusy(false);
    }
  };

  const list = calls || [];
  const modelsUsed = [...new Set(list.map((c) => c.model).filter(Boolean))];
  const fallbacks = list.filter((c) => c.fallback_used).length;
  const latencies = list.map((c) => c.latency_ms).filter((v) => typeof v === 'number');
  const avgLatency = latencies.length
    ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
    : null;
  const byTask = list.reduce((acc, c) => {
    acc[c.task || '?'] = (acc[c.task || '?'] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-ink-primary">AI Model &amp; Evaluation Analytics</h2>
          <p className="mt-1 text-sm text-ink-muted">
            Measured model usage and retrieval relevance. Prompt and response bodies are never logged.
          </p>
        </div>
        <button className="btn-ghost" onClick={load} disabled={loading}>
          {loading ? <Spinner /> : <RotateCcw className="h-4 w-4" />} Refresh
        </button>
      </header>

      {error ? <Banner tone="error" title="Request failed">{error}</Banner> : null}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Model calls" value={list.length} hint={`last ${limit}`} icon={BarChart3} />
        <StatTile label="Models used" value={modelsUsed.length} hint={modelsUsed.slice(0, 2).join(', ') || '—'} />
        <StatTile label="Fallbacks" value={fallbacks} tone={fallbacks ? 'warn' : 'good'} hint="non-silent by design" />
        <StatTile label="Avg latency" value={avgLatency !== null ? `${avgLatency}ms` : '—'} hint="per call" />
      </div>

      {policy ? (
        <Card
          title="Routing policy"
          subtitle={`Active: ${policy.provider} / ${policy.model}${policy.meta_only_enforced ? ' · Meta-only enforced' : ''}`}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-ink-hairline text-xs uppercase tracking-wider text-ink-muted">
                  <th className="pb-2 pr-4 font-semibold">Task</th>
                  <th className="pb-2 pr-4 font-semibold">Provider</th>
                  <th className="pb-2 pr-4 font-semibold">Model</th>
                  <th className="pb-2 font-semibold">Fallback</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(policy.tasks || {}).map(([task, rule]) => (
                  <tr key={task} className="border-b border-ink-hairline last:border-0">
                    <td className="py-2 pr-4 font-mono text-xs">{task}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{rule.provider}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{rule.model}</td>
                    <td className="py-2 font-mono text-xs text-ink-muted">
                      {rule.fallback ? `${rule.fallback.provider}/${rule.fallback.model}` : 'none'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}

      <Card
        title={`Model calls (${list.length})`}
        subtitle="Newest first. No prompt or response content is stored."
        actions={
          <label className="flex items-center gap-2 text-xs text-ink-muted">
            Limit
            <input
              type="number"
              min={1}
              max={500}
              className="field w-20"
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value) || 100)}
            />
          </label>
        }
      >
        {list.length === 0 ? (
          <EmptyState icon={BarChart3} title="No model calls recorded">
            Run an investigation or audit first. Calls appear here with model, task and latency.
          </EmptyState>
        ) : (
          <div className="max-h-[480px] overflow-auto">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-surface-raised">
                <tr className="border-b border-ink-hairline text-xs uppercase tracking-wider text-ink-muted">
                  <th className="pb-2 pr-3 font-semibold">Task</th>
                  <th className="pb-2 pr-3 font-semibold">Model</th>
                  <th className="pb-2 pr-3 font-semibold">Latency</th>
                  <th className="pb-2 pr-3 font-semibold">Tokens</th>
                  <th className="pb-2 pr-3 font-semibold">Retries</th>
                  <th className="pb-2 font-semibold">Fallback</th>
                </tr>
              </thead>
              <tbody>
                {list.map((c, i) => (
                  <tr key={i} className="border-b border-ink-hairline last:border-0">
                    <td className="py-2 pr-3 font-mono text-xs">{c.task}</td>
                    <td className="py-2 pr-3 font-mono text-xs">{c.model}</td>
                    <td className="py-2 pr-3 font-mono text-xs">{c.latency_ms}ms</td>
                    <td className="py-2 pr-3 font-mono text-xs text-ink-muted">
                      {c.usage ? `${c.usage.prompt_tokens ?? '?'}/${c.usage.completion_tokens ?? '?'}` : '—'}
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs">{c.retries}</td>
                    <td className="py-2 text-xs">
                      {c.fallback_used ? <span className="chip-warning">yes</span> : <span className="text-ink-muted">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {Object.keys(byTask).length ? (
          <p className="mt-3 text-xs text-ink-muted">
            By task: {Object.entries(byTask).map(([t, n]) => `${t} ${n}`).join(' · ')}
          </p>
        ) : null}
      </Card>

      <Card
        title="Retrieval relevance"
        subtitle="hit@k and MRR over the curated policy dataset. Fake store is offline; redis scores the live index."
        actions={
          <>
            <select className="field w-28" value={evalStore} onChange={(e) => setEvalStore(e.target.value)}>
              <option value="fake">fake</option>
              <option value="redis">redis</option>
            </select>
            <button className="btn-primary" disabled={evalBusy} onClick={runEval}>
              {evalBusy ? <Spinner /> : <FlaskConical className="h-4 w-4" />} Run eval
            </button>
          </>
        }
      >
        {!evalResult ? (
          <p className="text-sm text-ink-muted">Not run yet in this session.</p>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-ink-secondary">
              Store <span className="font-mono text-xs">{evalResult.store}</span> ·
              hit rate <span className="font-mono font-semibold">{evalResult.hit_rate}</span> ·
              MRR <span className="font-mono font-semibold">{evalResult.mrr}</span> ·
              {evalResult.tasks} tasks
            </p>
            <ul className="space-y-1">
              {(evalResult.rows || []).map((row) => (
                <li key={row.id} className="flex flex-wrap items-center gap-2 font-mono text-xs">
                  {row.hit ? <span className="chip-good">HIT</span> : <span className="chip-critical">MISS</span>}
                  <span className="text-ink-secondary">{row.id}</span>
                  <span className="text-ink-muted">rank {row.rank ?? '—'} · {(row.sources || []).join(', ')}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>
    </div>
  );
}
