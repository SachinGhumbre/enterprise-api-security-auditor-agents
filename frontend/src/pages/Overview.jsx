import React, { useCallback, useEffect, useState } from 'react';
import { Boxes, Cpu, Database, Radar, RotateCcw, Server, ShieldCheck } from 'lucide-react';

import { AGENTS_URL, KNOWLEDGE_URL, REDIS_TEST_URL, assess, health, rememberAssessment } from '../api/client';
import { Banner, Card, Spinner, StatusDot } from '../components/ui';

const PIPELINE = [
  { step: '1', name: 'Perceive', detail: 'Fetch Kong services, routes and plugin bindings' },
  { step: '2', name: 'Retrieve', detail: 'Vector-search the policy corpus in Redis (RAG)' },
  { step: '3', name: 'Reason', detail: 'LLM judges compliance against retrieved policy excerpts' },
  { step: '4', name: 'Plan', detail: 'Score, summarise and prioritise the findings' },
  { step: '5', name: 'Verify', detail: 'Deterministically check verdicts against Kong inventory' },
  { step: '6', name: 'Act', detail: 'Persist the audit report / remediation plan' },
];

const RUN_CHIP = {
  complete: 'chip-good',
  failed: 'chip-critical',
  awaiting_approval: 'chip-warning',
  running: 'chip-info',
};

export default function Overview({ onNavigate }) {
  const [state, setState] = useState({ loading: true });

  const probe = useCallback(async () => {
    setState({ loading: true });
    const [agentsRes, knowledgeRes, redisRes, runsRes] = await Promise.allSettled([
      health.agents(),
      health.knowledge(),
      health.redisTest(),
      assess.list(),
    ]);
    setState({
      loading: false,
      agents: agentsRes.status === 'fulfilled' ? agentsRes.value : { _error: agentsRes.reason?.message },
      knowledge:
        knowledgeRes.status === 'fulfilled' ? knowledgeRes.value : { _error: knowledgeRes.reason?.message },
      redis: redisRes.status === 'fulfilled' ? redisRes.value : { _error: redisRes.reason?.message },
      runs: runsRes.status === 'fulfilled' ? runsRes.value.assessments || [] : null,
    });
  }, []);

  useEffect(() => {
    probe();
  }, [probe]);

  const { loading, agents: ag, knowledge: kb, redis: rd, runs } = state;

  const openRun = (id) => {
    rememberAssessment(id);
    onNavigate('investigation');
  };

  const services = [
    {
      key: 'agents',
      name: 'AI Agents',
      port: 5000,
      url: AGENTS_URL,
      icon: Cpu,
      entry: 'backend/agents/init_auditor.py',
      data: ag,
      up: ag && !ag._error,
    },
    {
      key: 'knowledge',
      name: 'Knowledge Ingestor (RAG)',
      port: 5001,
      url: KNOWLEDGE_URL,
      icon: Boxes,
      entry: 'backend/rag/knowledge_ingestor.py',
      data: kb,
      up: kb && !kb._error,
    },
    {
      key: 'redis',
      name: 'Redis Test Harness',
      port: 5002,
      url: REDIS_TEST_URL,
      icon: Database,
      entry: 'redis-test.py',
      data: rd,
      up: rd && !rd._error,
    },
  ];

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-ink-primary">System Overview</h2>
          <p className="mt-1 text-sm text-ink-muted">
            Live health of every backend service and the agent pipeline they power.
          </p>
        </div>
        <button className="btn-ghost" onClick={probe} disabled={loading}>
          {loading ? <Spinner /> : <RotateCcw className="h-4 w-4" />} Refresh
        </button>
      </header>

      <div className="grid gap-4 lg:grid-cols-3">
        {services.map((svc) => {
          const Icon = svc.icon;
          return (
            <div key={svc.key} className="card animate-fade-up p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span
                    className={`flex h-10 w-10 items-center justify-center rounded-lg ${
                      svc.up ? 'bg-brand-50 text-brand-600' : 'bg-[#fbeaea] text-[#8f2727]'
                    }`}
                  >
                    <Icon className="h-5 w-5" aria-hidden="true" />
                  </span>
                  <div>
                    <p className="font-semibold text-ink-primary">{svc.name}</p>
                    <p className="font-mono text-xs text-ink-muted">:{svc.port}</p>
                  </div>
                </div>
                <StatusDot
                  state={loading ? 'idle' : svc.up ? 'ok' : 'bad'}
                  label={loading ? 'checking' : svc.up ? 'online' : 'offline'}
                />
              </div>

              <p className="mt-3 font-mono text-xs text-ink-muted">{svc.entry}</p>

              {!loading && svc.data && svc.data._error ? (
                <p className="mt-3 text-xs text-[#8f2727]">{svc.data._error}</p>
              ) : null}

              {!loading && svc.key === 'agents' && svc.up ? (
                <dl className="mt-4 space-y-1.5 border-t border-ink-hairline pt-3 text-xs">
                  <div className="flex justify-between gap-2">
                    <dt className="text-ink-muted">LLM provider</dt>
                    <dd className="font-mono font-semibold text-ink-secondary">
                      {svc.data.dependencies?.llm_provider}
                    </dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-ink-muted">Model</dt>
                    <dd
                      className="max-w-[55%] truncate font-mono font-semibold text-ink-secondary"
                      title={svc.data.dependencies?.llm_model}
                    >
                      {svc.data.dependencies?.llm_model}
                    </dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-ink-muted">Policy chunks</dt>
                    <dd className="font-mono font-semibold text-ink-secondary">
                      {svc.data.dependencies?.policy_chunks}
                    </dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-ink-muted">Kong admin</dt>
                    <dd
                      className={`font-mono font-semibold ${
                        svc.data.dependencies?.kong_admin_reachable
                          ? 'text-[#09660a]'
                          : 'text-[#845a06]'
                      }`}
                    >
                      {svc.data.dependencies?.kong_admin_reachable ? 'reachable' : 'fallback'}
                    </dd>
                  </div>
                </dl>
              ) : null}

              {!loading && svc.key === 'knowledge' && svc.up ? (
                <dl className="mt-4 space-y-1.5 border-t border-ink-hairline pt-3 text-xs">
                  <div className="flex justify-between gap-2">
                    <dt className="text-ink-muted">Status</dt>
                    <dd
                      className={`font-mono font-semibold ${
                        svc.data.status === 'ok' ? 'text-[#09660a]' : 'text-[#845a06]'
                      }`}
                    >
                      {svc.data.status}
                    </dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-ink-muted">Embeddings</dt>
                    <dd className="font-mono font-semibold text-ink-secondary">
                      {svc.data.config?.embeddings?.provider}
                    </dd>
                  </div>
                </dl>
              ) : null}

              {!loading && svc.key === 'redis' && svc.up ? (
                <dl className="mt-4 space-y-1.5 border-t border-ink-hairline pt-3 text-xs">
                  <div className="flex justify-between gap-2">
                    <dt className="text-ink-muted">Index</dt>
                    <dd
                      className={`font-mono font-semibold ${
                        svc.data.exists ? 'text-[#09660a]' : 'text-[#845a06]'
                      }`}
                    >
                      {svc.data.exists ? 'present' : 'missing'}
                    </dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-ink-muted">Documents</dt>
                    <dd className="font-mono font-semibold text-ink-secondary">{svc.data.num_docs}</dd>
                  </div>
                </dl>
              ) : null}
            </div>
          );
        })}
      </div>

      {!loading && runs ? (
        <Card
          title="Recent investigations"
          subtitle="Newest first. Open any run to follow or review its agents."
        >
          {runs.length === 0 ? (
            <p className="text-sm text-ink-muted">No assessments yet this session.</p>
          ) : (
            <ul className="divide-y divide-ink-hairline">
              {runs.slice(0, 8).map((run) => (
                <li key={run.assessment_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
                  <button
                    type="button"
                    className="font-mono text-xs text-brand-700 hover:underline"
                    onClick={() => openRun(run.assessment_id)}
                  >
                    {run.assessment_id}
                  </button>
                  <span className={RUN_CHIP[run.status] || 'chip-info'}>{run.status}</span>
                  <span className="text-xs text-ink-muted">{run.started_at || ''}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      ) : null}

      {!loading && ag && !ag._error && (ag.warnings || []).length ? (
        <div className="space-y-3">
          {ag.warnings.map((w) => (
            <Banner key={w} tone="warn" title="Degraded dependency">{w}</Banner>
          ))}
        </div>
      ) : null}

      {!loading && ag && !ag._error && ag.dependencies?.llm_provider === 'meta' ? (
        <div className="animate-fade-up rounded-xl border border-brand-200 bg-gradient-to-r from-brand-50 to-white px-5 py-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className="chip bg-brand-600 text-white">Meta Model API</span>
            <p className="text-sm text-ink-secondary">
              Both agents reason on{' '}
              <code className="rounded bg-surface-raised px-1.5 py-0.5 font-mono text-xs text-brand-800 ring-1 ring-brand-200">
                {ag.dependencies.llm_model}
              </code>
            </p>
          </div>
        </div>
      ) : null}

      <Card
        title="Agent pipeline"
        subtitle="Both the Audit and Remediate agents run this LangGraph loop."
      >
        <ol className="grid gap-3 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
          {PIPELINE.map((p) => (
            <li key={p.step} className="rounded-lg border border-ink-hairline bg-surface-sunken p-4">
              <span className="chip bg-brand-600 text-white">{p.step}</span>
              <p className="mt-2 font-semibold text-ink-primary">{p.name}</p>
              <p className="mt-1 text-xs leading-relaxed text-ink-muted">{p.detail}</p>
            </li>
          ))}
        </ol>
      </Card>

      <Card title="Quick start">
        <div className="flex flex-wrap gap-3">
          <button className="btn-primary" onClick={() => onNavigate('investigation')}>
            <Radar className="h-4 w-4" /> Run agentic investigation
          </button>
          <button className="btn-ghost" onClick={() => onNavigate('knowledge')}>
            <Boxes className="h-4 w-4" /> Ingest policies
          </button>
          <button className="btn-ghost" onClick={() => onNavigate('audit')}>
            <ShieldCheck className="h-4 w-4" /> Single-agent audit
          </button>
          <button className="btn-ghost" onClick={() => onNavigate('remediation')}>
            <Server className="h-4 w-4" /> Generate remediation
          </button>
        </div>
      </Card>
    </div>
  );
}
