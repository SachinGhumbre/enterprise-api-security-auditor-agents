import React, { useState } from 'react';
import { CheckCircle2, FlaskConical, RotateCcw, ShieldAlert, Wrench, Zap } from 'lucide-react';

import { assess, lastAssessment, rememberAssessment } from '../api/client';
import { Banner, Card, Collapsible, EmptyState, Spinner, StatTile } from '../components/ui';

const STATUS_CHIP = {
  proposed: 'chip-info',
  approved: 'chip-warning',
  executed: 'chip-serious',
  validated: 'chip-good',
  failed: 'chip-critical',
};

function ChangeCard({ change, assessmentId, reviewer, notify, onChanged }) {
  const [busy, setBusy] = useState(false);
  const diff = change.diff || [];
  const residual = change.residual_risk || {};
  const simulation = change.simulation || {};
  const execution = change.execution || {};
  const post = change.post_validation || {};

  const act = async (fn, label) => {
    setBusy(true);
    try {
      await fn();
      notify(`${change.change_id}: ${label}.`, 'success');
      onChanged();
    } catch (err) {
      notify(err.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const summary = (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="font-mono text-xs text-ink-muted">{change.change_id}</span>
      <span className="font-semibold text-ink-primary">
        {change.op} {change.plugin} → {(change.target || {}).service}
      </span>
      <span className={STATUS_CHIP[change.status] || 'chip-info'}>{change.status}</span>
    </span>
  );

  return (
    <Collapsible summary={summary}>
      <div className="space-y-4 text-sm">
        <p className="text-ink-secondary">{change.rationale}</p>

        {diff.length ? (
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">Configuration diff</p>
            {diff.map((d, i) => (
              <div key={i} className="grid gap-2 font-mono text-xs sm:grid-cols-2">
                <div className="rounded-lg bg-[#fbeaea] p-3">
                  <p className="font-semibold text-[#8f2727]">− current</p>
                  <p className="mt-1 break-words text-ink-secondary">{JSON.stringify(d.before)}</p>
                </div>
                <div className="rounded-lg bg-[#e7f6e7] p-3">
                  <p className="font-semibold text-[#09660a]">+ proposed</p>
                  <p className="mt-1 break-words text-ink-secondary">{JSON.stringify(d.after)}</p>
                </div>
              </div>
            ))}
          </div>
        ) : null}

        <dl className="grid gap-x-8 gap-y-2 text-xs sm:grid-cols-2">
          <div>
            <dt className="font-semibold uppercase tracking-wider text-ink-muted">Preconditions</dt>
            <dd className="mt-0.5 text-ink-secondary">{(change.preconditions || []).join(' · ') || '—'}</dd>
          </div>
          <div>
            <dt className="font-semibold uppercase tracking-wider text-ink-muted">Consumer impact</dt>
            <dd className="mt-0.5 text-ink-secondary">{change.consumer_impact || '—'}</dd>
          </div>
          <div>
            <dt className="font-semibold uppercase tracking-wider text-ink-muted">Breaking changes</dt>
            <dd className="mt-0.5 text-ink-secondary">{(change.breaking_changes || []).join(' · ') || '—'}</dd>
          </div>
          <div>
            <dt className="font-semibold uppercase tracking-wider text-ink-muted">Validation plan</dt>
            <dd className="mt-0.5 text-ink-secondary">{(change.validation_plan || []).join(' · ') || '—'}</dd>
          </div>
        </dl>

        {residual.before !== undefined ? (
          <p className="text-xs text-ink-secondary">
            Residual risk: <span className="font-mono font-semibold">{residual.before} → {residual.after}</span>
            {' '}({residual.level_before} → {residual.level_after})
          </p>
        ) : null}

        {simulation.effect ? (
          <p className="text-xs text-ink-muted">
            Simulation: {simulation.effect} · {simulation.note}
          </p>
        ) : null}

        {change.rollback ? (
          <p className="text-xs text-ink-muted">
            Rollback: {change.rollback.op} {change.rollback.plugin} — {change.rollback.note}
          </p>
        ) : null}

        {(change.approvals || []).length ? (
          <p className="text-xs text-ink-muted">
            Approvals: {change.approvals.map((a) => `${a.reviewer} (${a.at})`).join(', ')}
          </p>
        ) : null}

        {execution && (execution.ops || execution.error) ? (
          <div className="text-xs">
            {execution.error ? (
              <p className="text-[#8f2727]">Execution failed: {execution.error}</p>
            ) : (
              <p className="text-ink-secondary">
                Executed {execution.mode} by {execution.approver} · ops {(execution.ops || []).length}
              </p>
            )}
          </div>
        ) : null}

        {post && post.checks ? (
          <p className="text-xs text-ink-secondary">
            Post-change validation: {post.passed ? 'passed' : 'FAILED'} ({(post.checks || []).length} checks)
          </p>
        ) : null}

        <div className="flex flex-wrap items-center gap-2 border-t border-ink-hairline pt-3">
          {change.status === 'proposed' ? (
            <button
              type="button"
              disabled={busy}
              className="btn-primary"
              onClick={() => act(
                () => assess.approveChange(assessmentId, change.change_id, reviewer || 'reviewer', ''),
                'approved'
              )}
            >
              <CheckCircle2 className="h-4 w-4" /> Approve
            </button>
          ) : null}
          <button
            type="button"
            disabled={busy}
            className="btn-ghost"
            onClick={() => act(
              () => assess.executeChange(assessmentId, change.change_id, 'simulate'),
              'simulated'
            )}
          >
            <FlaskConical className="h-4 w-4" /> Simulate
          </button>
          <button
            type="button"
            disabled={busy || change.status !== 'approved'}
            className="btn-ghost"
            title={change.status !== 'approved' ? 'Approve first' : 'Requires admin role + server flag'}
            onClick={() => {
              if (window.confirm(`Execute ${change.change_id} against live Kong?`)) {
                act(() => assess.executeChange(assessmentId, change.change_id, 'live'), 'executed');
              }
            }}
          >
            <Zap className="h-4 w-4" /> Execute live
          </button>
        </div>
      </div>
    </Collapsible>
  );
}

export default function RemediationCentre({ notify }) {
  const [idInput, setIdInput] = useState(() => lastAssessment());
  const [assessmentId, setAssessmentId] = useState(() => lastAssessment());
  const [changes, setChanges] = useState(null);
  const [plan, setPlan] = useState(null);
  const [approval, setApproval] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reviewer, setReviewer] = useState('');

  const load = async (id) => {
    if (!id) return;
    setLoading(true);
    setError('');
    try {
      const [changeList, details] = await Promise.all([
        assess.changes(id),
        assess.details(id),
      ]);
      setChanges(changeList.change_proposals || []);
      setPlan(details.state.remediation_plan || []);
      setApproval(details.state.approval || null);
      setAssessmentId(id);
      rememberAssessment(id);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const byStatus = (changes || []).reduce((acc, c) => {
    acc[c.status] = (acc[c.status] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-bold text-ink-primary">Remediation &amp; Approval Centre</h2>
        <p className="mt-1 text-sm text-ink-muted">
          Structured change proposals with simulation, human approval and a gated live path.
        </p>
      </header>

      <Card title="Assessment" subtitle="Proposals, plan and approval state for one assessment id.">
        <div className="flex flex-wrap gap-2">
          <input
            className="field max-w-md flex-1"
            value={idInput}
            onChange={(e) => setIdInput(e.target.value)}
            placeholder="e.g. asm-9f3c2a1b4d5e"
            spellCheck={false}
          />
          <button className="btn-primary" disabled={loading || !idInput.trim()} onClick={() => load(idInput.trim())}>
            {loading ? <Spinner /> : <Wrench className="h-4 w-4" />} Load
          </button>
          {assessmentId ? (
            <button className="btn-ghost" disabled={loading} onClick={() => load(assessmentId)}>
              <RotateCcw className="h-4 w-4" /> Refresh
            </button>
          ) : null}
        </div>
        <div className="mt-3 flex max-w-md flex-wrap items-center gap-2">
          <span className="text-xs text-ink-muted">Reviewer:</span>
          <input
            className="field"
            value={reviewer}
            onChange={(e) => setReviewer(e.target.value)}
            placeholder="e.g. sec-lead"
          />
        </div>
      </Card>

      {error ? <Banner tone="error" title="Request failed">{error}</Banner> : null}

      {!changes && !error ? (
        <EmptyState icon={Wrench} title="No assessment loaded">
          Enter an assessment id above. Proposals appear after the remediation agent runs.
        </EmptyState>
      ) : null}

      {changes ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile label="Proposals" value={changes.length} hint="structured changes" />
            <StatTile label="Validated" value={byStatus.validated || 0} tone="good" hint="executed + verified" />
            <StatTile label="Awaiting approval" value={byStatus.proposed || 0} tone="warn" hint="proposed only" />
            <StatTile label="Failed" value={byStatus.failed || 0} tone={byStatus.failed ? 'bad' : 'default'} hint="see execution record" />
          </div>

          {approval ? (
            <Banner
              tone={approval.decision === 'approve' ? 'success' : approval.decision === 'reject' ? 'error' : 'info'}
              title={`Plan export: ${approval.decision}`}
            >
              <span className="text-sm">
                Reviewer {approval.reviewer || '—'} · {approval.decided_at || ''} · {approval.note || ''}
              </span>
            </Banner>
          ) : null}

          <div className="space-y-2">
            <h3 className="flex items-center gap-2 text-base font-semibold text-ink-primary">
              <ShieldAlert className="h-4 w-4" /> Change proposals ({changes.length})
            </h3>
            {changes.length === 0 ? <p className="text-sm text-ink-muted">No proposals for this run.</p> : null}
            {changes.map((change) => (
              <ChangeCard
                key={change.change_id}
                change={change}
                assessmentId={assessmentId}
                reviewer={reviewer}
                notify={notify}
                onChanged={() => load(assessmentId)}
              />
            ))}
          </div>

          {(plan || []).length ? (
            <Card title={`Remediation plan (${plan.length})`} subtitle="Model-drafted actions for eligible findings.">
              <ul className="space-y-3">
                {plan.map((item, i) => (
                  <li key={i} className="rounded-lg border border-ink-hairline p-3 text-sm">
                    <p className="font-mono text-xs text-ink-muted">{item.finding_id}</p>
                    <p className="mt-1 font-semibold text-ink-primary">
                      {item.action || item.recommendation || item.title || 'Action'}
                    </p>
                    {item.rationale ? <p className="mt-1 text-ink-secondary">{item.rationale}</p> : null}
                    {!item.action && !item.rationale ? (
                      <pre className="mt-1 overflow-x-auto font-mono text-xs text-ink-secondary">
                        {JSON.stringify(item, null, 2)}
                      </pre>
                    ) : null}
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
