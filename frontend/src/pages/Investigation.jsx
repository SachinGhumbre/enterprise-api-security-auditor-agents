import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Bot,
  CheckCircle2,
  ChevronRight,
  FlaskConical,
  PauseCircle,
  Play,
  RotateCcw,
  Square,
  XCircle,
} from 'lucide-react';

import { agents as agentsApi, assess, lastAssessment, rememberAssessment } from '../api/client';
import { Banner, Card, Collapsible, EmptyState, MultiSelect, ProgressBar, Spinner } from '../components/ui';
import { SECURITY_STANDARDS } from './AuditView';

const POLL_MS = 2000;

// Canonical pipeline order. Investigators run in parallel; followup loops.
const AGENT_ORDER = [
  'supervisor',
  'discovery',
  'security_analysis',
  'compliance',
  'threat_model',
  'aggregate',
  'followup',
  'risk',
  'remediation',
  'validation',
  'governance',
  'finalize',
];

const PARALLEL = new Set(['security_analysis', 'compliance', 'threat_model']);

const STATUS_CHIP = {
  ok: 'chip-good',
  degraded: 'chip-warning',
  failed: 'chip-critical',
  pending: 'chip-info',
};

function AgentChip({ status }) {
  const key = STATUS_CHIP[status] ? status : 'pending';
  const label = { ok: 'Completed', degraded: 'Degraded', failed: 'Failed', pending: 'Pending' }[key];
  return <span className={STATUS_CHIP[key]}>{label}</span>;
}

function RunChip({ status }) {
  if (status === 'complete') return <span className="chip-good">Completed</span>;
  if (status === 'failed') return <span className="chip-critical">Failed</span>;
  if (status === 'awaiting_approval') return <span className="chip-warning">Paused · approval needed</span>;
  return (
    <span className="chip-info">
      <Spinner className="h-3 w-3" /> Running
    </span>
  );
}

function fmtTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleTimeString();
  } catch (err) {
    return String(iso);
  }
}

function durationSecs(record) {
  if (!record || !record.started_at || !record.finished_at) return null;
  const ms = new Date(record.finished_at) - new Date(record.started_at);
  return Number.isFinite(ms) && ms >= 0 ? (ms / 1000).toFixed(1) : null;
}

function asList(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function AgentCard({ name, record, running }) {
  const status = record ? record.status : running ? 'pending' : 'pending';
  const secs = durationSecs(record);
  const decisions = record ? asList(record.decisions) : [];
  const toolCalls = record ? asList(record.tool_calls) : [];
  const summary = (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="font-semibold text-ink-primary">{name}</span>
      <AgentChip status={status} />
      {PARALLEL.has(name) ? <span className="chip">parallel</span> : null}
      {record && record.model ? (
        <span className="font-mono text-xs text-ink-muted">{record.model}</span>
      ) : null}
      {secs !== null ? <span className="text-xs text-ink-muted">{secs}s</span> : null}
      {record && record.retries > 0 ? (
        <span className="text-xs text-ink-muted">retries {record.retries}</span>
      ) : null}
    </span>
  );
  return (
    <Collapsible summary={summary}>
      {!record ? (
        <p className="text-sm text-ink-muted">Not started yet.</p>
      ) : (
        <div className="space-y-4 text-sm">
          <dl className="grid gap-x-8 gap-y-1.5 text-xs sm:grid-cols-2">
            <div className="flex justify-between gap-2">
              <dt className="text-ink-muted">Started</dt>
              <dd className="font-mono">{fmtTime(record.started_at)}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-ink-muted">Finished</dt>
              <dd className="font-mono">{fmtTime(record.finished_at)}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-ink-muted">Timeout budget</dt>
              <dd className="font-mono">{record.timeout_s ?? '—'}s</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-ink-muted">Evidence ids</dt>
              <dd className="font-mono">{asList(record.evidence_ids).length}</dd>
            </div>
          </dl>

          {record.input_summary ? (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">Input</p>
              <pre className="overflow-x-auto rounded-lg bg-surface-sunken p-3 font-mono text-xs text-ink-secondary">
                {JSON.stringify(record.input_summary, null, 2)}
              </pre>
            </div>
          ) : null}

          {record.output_summary ? (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">Output</p>
              <pre className="overflow-x-auto rounded-lg bg-surface-sunken p-3 font-mono text-xs text-ink-secondary">
                {JSON.stringify(record.output_summary, null, 2)}
              </pre>
            </div>
          ) : null}

          {decisions.length ? (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
                Decisions ({decisions.length})
              </p>
              <ul className="space-y-1">
                {decisions.map((d, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-ink-secondary">
                    <ChevronRight className="mt-0.5 h-3 w-3 shrink-0 text-brand-400" aria-hidden="true" />
                    <span className="font-mono">{d.decision || JSON.stringify(d)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {toolCalls.length ? (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
                Tool calls ({toolCalls.length})
              </p>
              <ul className="space-y-1">
                {toolCalls.map((t, i) => (
                  <li key={i} className="flex items-center gap-2 font-mono text-xs text-ink-secondary">
                    {t.ok ? (
                      <CheckCircle2 className="h-3 w-3 text-[#09660a]" aria-hidden="true" />
                    ) : (
                      <XCircle className="h-3 w-3 text-[#8f2727]" aria-hidden="true" />
                    )}
                    {t.tool}
                    <span className="text-ink-muted">{t.ms}ms · {fmtTime(t.at)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="text-xs text-ink-muted">No tool calls (reasoning only).</p>
          )}

          {record.error ? (
            <Banner tone="error" title="Agent error">
              <span className="font-mono text-xs">{record.error}</span>
            </Banner>
          ) : null}
        </div>
      )}
    </Collapsible>
  );
}

export default function Investigation({ notify }) {
  const [form, setForm] = useState({
    selected_standards: ['OWASP API Top 10'],
    depth: 'standard',
    objective: '',
    service_names: [],
  });
  const [serviceOptions, setServiceOptions] = useState([]);
  const [servicesLoading, setServicesLoading] = useState(false);
  const [servicesError, setServicesError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [attachId, setAttachId] = useState('');
  const [trackingId, setTrackingId] = useState(() => lastAssessment());
  const [polling, setPolling] = useState(false);
  const [details, setDetails] = useState(null);
  const [error, setError] = useState('');
  const [actionBusy, setActionBusy] = useState(false);
  const [reviewer, setReviewer] = useState('');
  const timer = useRef(null);

  const fetchDetails = useCallback(async (id) => {
    const payload = await assess.details(id);
    setDetails(payload);
    return payload;
  }, []);

  const stopPolling = useCallback(() => {
    setPolling(false);
    if (timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
  }, []);

  useEffect(() => () => stopPolling(), [stopPolling]);

  // Kong service names for the scope picker. Loaded when the start form opens;
  // a failure leaves the picker empty (full estate) rather than blocking.
  useEffect(() => {
    if (!showForm) return undefined;
    let cancelled = false;
    setServicesLoading(true);
    setServicesError('');
    agentsApi
      .kongServices()
      .then((inv) => {
        if (cancelled) return;
        setServiceOptions(
          (inv.services || []).map((s) => s.service_name).filter(Boolean)
        );
      })
      .catch((err) => {
        if (!cancelled) setServicesError(err.message);
      })
      .finally(() => {
        if (!cancelled) setServicesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [showForm]);

  const beginTracking = useCallback((id, poll) => {
    setTrackingId(id);
    rememberAssessment(id);
    setError('');
    setDetails(null);
    stopPolling();
    fetchDetails(id)
      .then((payload) => {
        const state = payload.state || {};
        const paused = (payload.pending_interrupts || []).length > 0;
        const done = state.status === 'complete' || state.status === 'failed';
        if (poll && !paused && !done) {
          setPolling(true);
          timer.current = setInterval(() => {
            fetchDetails(id)
              .then((next) => {
                const st = next.state || {};
                const isPaused = (next.pending_interrupts || []).length > 0;
                if (st.status === 'complete' || st.status === 'failed' || isPaused) {
                  stopPolling();
                }
              })
              .catch(() => stopPolling());
          }, POLL_MS);
        }
      })
      .catch((err) => setError(err.message));
  }, [fetchDetails, stopPolling]);

  const startRun = async (e) => {
    e.preventDefault();
    setActionBusy(true);
    setError('');
    try {
      const payload = {
        selected_standards: form.selected_standards,
        depth: form.depth,
      };
      if (form.objective.trim()) payload.objective = form.objective.trim();
      if (form.service_names.length) payload.service_names = form.service_names;
      const started = await assess.start(payload);
      setShowForm(false);
      beginTracking(started.assessment_id, true);
      notify(`Investigation ${started.assessment_id} started.`, 'info');
    } catch (err) {
      setError(err.message);
    } finally {
      setActionBusy(false);
    }
  };

  const answerApproval = async (decision) => {
    if (!trackingId) return;
    setActionBusy(true);
    setError('');
    try {
      await assess.resume(trackingId, { decision, reviewer: reviewer.trim() || undefined });
      notify(`Approval ${decision}d.`, decision === 'approve' ? 'success' : 'info');
      beginTracking(trackingId, true);
    } catch (err) {
      setError(err.message);
    } finally {
      setActionBusy(false);
    }
  };

  const state = (details && details.state) || {};
  const agents = state.agents || {};
  const paused = (details && details.pending_interrupts.length > 0) || false;
  const approval = paused ? details.pending_interrupts[0] : null;
  const done = state.status === 'complete' || state.status === 'failed';
  const ranCount = AGENT_ORDER.filter((a) => agents[a]).length;
  const progress = Math.round((ranCount / AGENT_ORDER.length) * 100);
  const budgets = state.budgets || {};
  const plan = state.plan || {};
  const stopping = state.stopping || {};
  const tiers = state.tiers || {};
  const kongSource = state.kong_source;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-ink-primary">Agentic Investigation</h2>
          <p className="mt-1 text-sm text-ink-muted">
            Live supervisor-led execution. Every event below comes from the backend trace.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button className="btn-primary" onClick={() => setShowForm((v) => !v)}>
            <Play className="h-4 w-4" /> New investigation
          </button>
        </div>
      </header>

      {showForm ? (
        <Card
          title="Start investigation"
          subtitle="Runs asynchronously; this page polls for progress."
          className="relative z-10"
        >
          <form onSubmit={startRun} className="grid gap-4 sm:grid-cols-2">
            <div className="block">
              <span className="mb-1.5 block text-sm font-medium text-ink-secondary">Standards</span>
              <MultiSelect
                options={SECURITY_STANDARDS}
                selected={form.selected_standards}
                onChange={(selected_standards) => setForm({ ...form, selected_standards })}
                placeholder="Select standards…"
                ariaLabel="Standards in scope"
              />
            </div>
            <label className="block">
              <span className="mb-1.5 block text-sm font-medium text-ink-secondary">Depth</span>
              <select
                className="field"
                value={form.depth}
                onChange={(e) => setForm({ ...form, depth: e.target.value })}
              >
                <option value="quick">quick</option>
                <option value="standard">standard</option>
                <option value="deep">deep</option>
              </select>
            </label>
            <label className="block sm:col-span-2">
              <span className="mb-1.5 block text-sm font-medium text-ink-secondary">Objective (optional)</span>
              <textarea
                className="field"
                rows={2}
                value={form.objective}
                onChange={(e) => setForm({ ...form, objective: e.target.value })}
                placeholder="e.g. Assess internet-facing payment APIs before launch"
              />
            </label>
            <div className="block sm:col-span-2">
              <span className="mb-1.5 block text-sm font-medium text-ink-secondary">Kong services (optional)</span>
              <MultiSelect
                options={serviceOptions}
                selected={form.service_names}
                onChange={(service_names) => setForm({ ...form, service_names })}
                placeholder={servicesLoading ? 'Loading Kong inventory…' : 'All services (full estate)'}
                disabled={servicesLoading}
                emptyHint={
                  servicesError
                    ? `Inventory unavailable (${servicesError}); run anyway for the full estate.`
                    : 'No Kong services found; run anyway for the full estate.'
                }
                ariaLabel="Kong services in scope"
              />
              <p className="mt-1 text-xs text-ink-muted">
                Kong service names from live inventory. Leave empty to assess the full estate.
              </p>
            </div>
            <div className="sm:col-span-2">
              <button type="submit" disabled={actionBusy} className="btn-primary">
                {actionBusy ? <Spinner /> : <FlaskConical className="h-4 w-4" />}
                {actionBusy ? 'Starting…' : 'Start run'}
              </button>
            </div>
          </form>
        </Card>
      ) : null}

      <Card
        title="Attach to a run"
        subtitle="Polling is per assessment, so long runs survive navigation. Paste any assessment id."
      >
        <div className="flex flex-wrap gap-2">
          <input
            className="field max-w-md flex-1"
            value={attachId}
            onChange={(e) => setAttachId(e.target.value)}
            placeholder="e.g. asm-9f3c2a1b4d5e"
            spellCheck={false}
          />
          <button className="btn-ghost" onClick={() => attachId.trim() && beginTracking(attachId.trim(), true)}>
            Attach &amp; follow
          </button>
        </div>
      </Card>

      {error ? <Banner tone="error" title="Request failed">{error}</Banner> : null}

      {!trackingId ? (
        <EmptyState icon={Bot} title="No investigation selected">
          Start a new investigation or attach to an existing assessment id to watch agents work.
        </EmptyState>
      ) : null}

      {trackingId && !details && !error ? (
        <Card><p className="flex items-center gap-2 text-sm text-ink-secondary"><Spinner /> Loading execution trace…</p></Card>
      ) : null}

      {details ? (
        <>
          <Card
            title={
              <span className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-sm">{trackingId}</span>
                <RunChip status={paused ? 'awaiting_approval' : state.status || 'running'} />
                {polling ? (
                  <span className="flex items-center gap-1.5 text-xs font-normal text-ink-muted">
                    <Spinner className="h-3 w-3" /> live
                  </span>
                ) : null}
              </span>
            }
            actions={
              <>
                <button className="btn-ghost" onClick={() => beginTracking(trackingId, !done && !paused)}>
                  <RotateCcw className="h-4 w-4" /> Refresh
                </button>
                {polling ? (
                  <button className="btn-ghost" onClick={stopPolling}>
                    <Square className="h-4 w-4" /> Stop
                  </button>
                ) : null}
              </>
            }
          >
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-ink-muted">
                <span>Pipeline progress · {ranCount}/{AGENT_ORDER.length} agents reported</span>
                {kongSource ? <span className="font-mono">inventory: {kongSource}{state.kong_live === false ? ' (cached)' : ''}</span> : null}
              </div>
              <ProgressBar value={progress} tone={state.status === 'failed' ? 'bad' : 'brand'} />
              {budgets && budgets.max_llm_calls ? (
                <p className="text-xs text-ink-muted">
                  LLM calls {budgets.llm_calls_used ?? 0}/{budgets.max_llm_calls} ·
                  tool calls {budgets.tool_calls_used ?? 0}/{budgets.max_tool_calls} ·
                  rounds {budgets.rounds_used ?? 0}/{budgets.max_rounds}
                </p>
              ) : null}
            </div>
          </Card>

          {paused && approval ? (
            <Banner tone="warn" title="Human approval required">
              <div className="space-y-3">
                <p>
                  {approval.actions} planned action(s) await export approval.
                  {approval.risk ? ` Risk: ${JSON.stringify(approval.risk)}.` : ''}
                  {approval.validation_passed === false ? ' Validation did not pass.' : ''}
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    className="field max-w-xs"
                    value={reviewer}
                    onChange={(e) => setReviewer(e.target.value)}
                    placeholder="Reviewer name (optional)"
                  />
                  <button className="btn-primary" disabled={actionBusy} onClick={() => answerApproval('approve')}>
                    Approve
                  </button>
                  <button className="btn-ghost" disabled={actionBusy} onClick={() => answerApproval('reject')}>
                    <PauseCircle className="h-4 w-4" /> Reject
                  </button>
                </div>
              </div>
            </Banner>
          ) : null}

          {plan && plan.dispatched ? (
            <Card title="Supervisor plan" subtitle={plan.objective || 'Security assessment'}>
              <div className="space-y-2 text-sm">
                <p className="text-ink-secondary">
                  Dispatched: <span className="font-mono text-xs">{(plan.dispatched || []).join(', ')}</span>
                </p>
                {plan.rationale ? <p className="text-ink-secondary">{plan.rationale}</p> : null}
                {stopping && stopping.decision ? (
                  <p className="text-ink-secondary">
                    Stopping decision: <span className="font-mono text-xs">{stopping.decision}</span>
                    {stopping.reason ? ` — ${stopping.reason}` : ''}
                  </p>
                ) : null}
                {Object.keys(tiers).length ? (
                  <p className="text-xs text-ink-muted">
                    Tiers: {Object.entries(tiers).map(([k, v]) => `${k} ${(v || []).length}`).join(' · ')}
                  </p>
                ) : null}
              </div>
            </Card>
          ) : null}

          <Card
            title="Agent timeline"
            subtitle="Activation order with model, duration, decisions and tool calls. Expand any agent."
          >
            <div className="space-y-2">
              {AGENT_ORDER.map((name) => (
                <AgentCard key={name} name={name} record={agents[name]} running={!done} />
              ))}
            </div>
          </Card>

          {state.warnings && state.warnings.length ? (
            <Banner tone="warn" title={`${state.warnings.length} warning(s)`}>
              <ul className="list-disc pl-5">
                {state.warnings.slice(0, 8).map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </Banner>
          ) : null}

          {state.trace && state.trace.length ? (
            <Collapsible summary={`Raw trace (${state.trace.length} entries)`}>
              <pre className="max-h-96 overflow-auto rounded-lg bg-surface-sunken p-3 font-mono text-xs text-ink-secondary">
                {JSON.stringify(state.trace.slice(-50), null, 2)}
              </pre>
            </Collapsible>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
