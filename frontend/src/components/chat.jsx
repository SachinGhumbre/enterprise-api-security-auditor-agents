import React, { useCallback, useEffect, useState } from 'react';
import {
  Bot,
  CheckCircle2,
  FlaskConical,
  ShieldAlert,
  Wrench,
  XCircle,
} from 'lucide-react';

import { assistant as assistantApi, rememberAssessment } from '../api/client';
import { Collapsible, SeverityBadge, Spinner } from './ui';

/* --- Origin + citations -----------------------------------------------------
 * Every assistant message says what it is: verified tool output rendered
 * with evidence, or AI-generated wording that must not be mistaken for a
 * deterministically verified finding.
 */

export function OriginBadge({ verified, model }) {
  if (verified) {
    return (
      <span className="chip-good" title={model || ''}>
        <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
        Verified findings
      </span>
    );
  }
  return (
    <span className="chip-warning" title={model || ''}>
      <Bot className="h-3 w-3" aria-hidden="true" />
      AI-generated
    </span>
  );
}

export function CitationList({ citations }) {
  if (!citations || !citations.length) return null;
  return (
    <p className="mt-2 text-xs text-ink-muted">
      Evidence:{' '}
      {citations.map((c, i) => (
        <span key={i} className="mr-2 font-mono">
          [{c.kind}] {c.ref}
        </span>
      ))}
    </p>
  );
}

/* --- Structured cards (all derived from tool output, never invented) -------- */

function goToAssessment(assessmentId, page, onNavigate) {
  if (assessmentId) rememberAssessment(assessmentId);
  if (onNavigate) onNavigate(page);
}

export function FindingCard({ finding, assessmentId, onNavigate }) {
  const summary = (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="font-mono text-xs text-ink-muted">{finding.entry_id}</span>
      <span className="font-semibold text-ink-primary">{finding.title}</span>
      <SeverityBadge severity={finding.level} />
      {finding.verified ? (
        <span className="chip-good">verified</span>
      ) : (
        <span className="chip-warning">unverified</span>
      )}
    </span>
  );
  return (
    <Collapsible summary={summary}>
      <div className="space-y-2 text-sm text-ink-secondary">
        <p>
          Service <span className="font-mono text-xs">{finding.service}</span> ·
          score <span className="font-mono">{finding.score}</span> ·
          severity {finding.severity} · confidence {finding.confidence} ·
          state {finding.state}
        </p>
        {(finding.evidence || []).length ? (
          <ul className="space-y-1">
            {finding.evidence.slice(0, 6).map((e, i) => (
              <li key={i} className="font-mono text-xs">
                [{e.kind}] {e.ref} — {e.detail}
              </li>
            ))}
          </ul>
        ) : null}
        <div>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => goToAssessment(assessmentId, 'findings', onNavigate)}
          >
            View in Findings
          </button>
        </div>
      </div>
    </Collapsible>
  );
}

export function ProposalCard({ proposal, source, assessmentId, simulation, onNavigate }) {
  const summary = (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="font-mono text-xs text-ink-muted">{proposal.change_id}</span>
      <span className="font-semibold text-ink-primary">
        {proposal.op} {proposal.plugin} → {(proposal.target || {}).service}
      </span>
      <span className={source === 'existing' ? 'chip-info' : 'chip-warning'}>
        {source === 'existing' ? 'in approval workflow' : 'preview · not proposed yet'}
      </span>
    </span>
  );
  const residual = proposal.residual_risk || {};
  return (
    <Collapsible summary={summary}>
      <div className="space-y-2 text-sm text-ink-secondary">
        <p>{proposal.rationale}</p>
        {residual.before !== undefined && !residual.error ? (
          <p className="text-xs">
            Residual risk:{' '}
            <span className="font-mono font-semibold">
              {residual.before} → {residual.after}
            </span>{' '}
            ({residual.level_before} → {residual.level_after})
          </p>
        ) : null}
        {simulation && simulation.effect ? (
          <p className="text-xs text-ink-muted">Simulation: {simulation.effect}</p>
        ) : null}
        <p className="text-xs text-ink-muted">
          Preconditions: {(proposal.preconditions || []).join(' · ') || '—'}
        </p>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="btn-ghost"
            onClick={() => goToAssessment(assessmentId, 'centre', onNavigate)}
          >
            <Wrench className="h-4 w-4" /> Open in Remediation Centre
          </button>
        </div>
        <p className="text-xs text-ink-muted">
          AI-generated preview. Nothing is approved or executed from chat.
        </p>
      </div>
    </Collapsible>
  );
}

export function TaskCard({ task, onNavigate }) {
  const [status, setStatus] = useState(task);
  const [error, setError] = useState('');

  const terminal = ['complete', 'failed', 'awaiting_approval'].includes(status.status);

  const poll = useCallback(async () => {
    try {
      const next = await assistantApi.task(task.task_id);
      setStatus(next);
    } catch (err) {
      setError(err.message);
    }
  }, [task.task_id]);

  useEffect(() => {
    if (terminal) return undefined;
    poll();
    const timer = setInterval(poll, 2000);
    return () => clearInterval(timer);
  }, [terminal, poll]);

  const chip =
    status.status === 'complete' ? (
      <span className="chip-good">Completed</span>
    ) : status.status === 'failed' ? (
      <span className="chip-critical">Failed</span>
    ) : status.status === 'awaiting_approval' ? (
      <span className="chip-warning">Paused · approval needed</span>
    ) : (
      <span className="chip-info">
        <Spinner className="h-3 w-3" /> Running
      </span>
    );

  return (
    <div className="rounded-lg border border-ink-hairline p-3">
      <div className="flex flex-wrap items-center gap-3">
        <FlaskConical className="h-4 w-4 text-brand-500" aria-hidden="true" />
        <span className="font-mono text-xs text-ink-muted">{status.task_id}</span>
        {chip}
      </div>
      <p className="mt-1 text-sm text-ink-secondary">
        Assessment <span className="font-mono text-xs">{status.assessment_id}</span>
        {status.agents_reported !== undefined
          ? ` · ${status.agents_reported} agents reported`
          : null}
        {status.budgets && status.budgets.max_llm_calls
          ? ` · LLM ${status.budgets.llm_calls_used ?? 0}/${status.budgets.max_llm_calls}`
          : null}
      </p>
      {status.error ? <p className="mt-1 text-xs text-[#8f2727]">{status.error}</p> : null}
      {error ? <p className="mt-1 text-xs text-[#8f2727]">{error}</p> : null}
      <div className="mt-2 flex flex-wrap gap-2">
        <button
          type="button"
          className="btn-ghost"
          onClick={() => goToAssessment(status.assessment_id, 'investigation', onNavigate)}
        >
          Watch live
        </button>
        <button
          type="button"
          className="btn-ghost"
          onClick={() => goToAssessment(status.assessment_id, 'findings', onNavigate)}
        >
          View findings
        </button>
      </div>
    </div>
  );
}

export function ThreatCard({ threat }) {
  return (
    <Collapsible
      summary={
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="font-semibold text-ink-primary">{threat.title}</span>
          <SeverityBadge severity={threat.severity_hint} />
          <span className="chip-warning">suspected</span>
        </span>
      }
    >
      <div className="space-y-1 text-sm text-ink-secondary">
        <p className="text-xs text-ink-muted">
          {threat.threat_id} · {threat.category} · {threat.owasp_ref}
        </p>
        {threat.model_explanation ? <p>{threat.model_explanation}</p> : null}
        {(threat.preconditions || []).length ? (
          <p className="text-xs">Preconditions: {threat.preconditions.join(' · ')}</p>
        ) : null}
        {(threat.recommended_tests || []).length ? (
          <p className="text-xs">Tests: {threat.recommended_tests.join(' · ')}</p>
        ) : null}
      </div>
    </Collapsible>
  );
}

export function InventoryCard({ card }) {
  return (
    <div className="rounded-lg border border-ink-hairline p-3 text-sm">
      <p className="text-ink-secondary">
        Inventory from <span className="font-mono text-xs">{card.source}</span>{' '}
        (live {String(card.live)}, stale {String(card.stale)}):{' '}
        <strong className="text-ink-primary">{card.count}</strong> service(s)
      </p>
      <ul className="mt-2 space-y-1">
        {(card.services || []).slice(0, 20).map((s) => (
          <li key={s.service_name} className="text-xs text-ink-secondary">
            <span className="font-mono font-semibold">{s.service_name}</span>{' '}
            <span className="font-mono text-ink-muted">
              [{(s.service_plugins || []).join(', ') || 'no plugins'}]
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ComparisonCard({ card }) {
  const delta = card.delta_by_level || {};
  return (
    <div className="rounded-lg border border-ink-hairline p-3 text-sm">
      <p className="text-ink-secondary">
        Posture delta:{' '}
        {Object.keys(delta).length ? (
          <span className="font-mono text-xs">{JSON.stringify(delta)}</span>
        ) : (
          'no change'
        )}
      </p>
      <p className="mt-1 font-mono text-xs text-ink-muted">
        before {(card.before || {}).assessment_id}:{' '}
        {JSON.stringify((card.before || {}).by_level)} → after{' '}
        {(card.after || {}).assessment_id}: {JSON.stringify((card.after || {}).by_level)}
      </p>
    </div>
  );
}

export function BriefCard({ card, assessmentId, onNavigate }) {
  const top = card.top_entries || [];
  return (
    <div className="rounded-lg border border-ink-hairline p-3 text-sm">
      <p className="text-ink-secondary">
        Assessment <span className="font-mono text-xs">{card.assessment_id}</span> (
        {card.status}) · by level{' '}
        <span className="font-mono text-xs">{JSON.stringify(card.by_level)}</span>
      </p>
      {top.length ? (
        <ul className="mt-2 space-y-1">
          {top.slice(0, 5).map((e) => (
            <li key={e.entry_id} className="flex flex-wrap items-center gap-2 text-xs">
              <span className="font-mono text-ink-muted">{e.entry_id}</span>
              <span className="text-ink-secondary">{e.title}</span>
              <SeverityBadge severity={e.level} />
            </li>
          ))}
        </ul>
      ) : null}
      <div className="mt-2">
        <button
          type="button"
          className="btn-ghost"
          onClick={() => goToAssessment(assessmentId || card.assessment_id, 'findings', onNavigate)}
        >
          View in Findings
        </button>
      </div>
    </div>
  );
}

export function AssessmentCard({ card, assessmentId, onNavigate }) {
  const counts = card.counts || {};
  return (
    <div className="rounded-lg border border-ink-hairline p-3 text-sm">
      <p className="text-ink-secondary">
        Assessment <span className="font-mono text-xs">{card.assessment_id}</span> ·{' '}
        {card.status} · services {(card.kong || {}).services} · findings{' '}
        {counts.findings} · threats {counts.threats} · proposals{' '}
        {counts.change_proposals}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        <button
          type="button"
          className="btn-ghost"
          onClick={() => goToAssessment(assessmentId || card.assessment_id, 'investigation', onNavigate)}
        >
          Open investigation
        </button>
        <button
          type="button"
          className="btn-ghost"
          onClick={() => goToAssessment(assessmentId || card.assessment_id, 'centre', onNavigate)}
        >
          Open approvals
        </button>
      </div>
    </div>
  );
}

export function CardView({ card, onNavigate }) {
  if (!card || typeof card !== 'object') return null;
  switch (card.kind) {
    case 'finding':
      return (
        <FindingCard finding={card.finding} assessmentId={card.assessment_id} onNavigate={onNavigate} />
      );
    case 'proposal':
      return (
        <ProposalCard
          proposal={card.proposal}
          source={card.source}
          simulation={card.simulation}
          assessmentId={card.assessment_id}
          onNavigate={onNavigate}
        />
      );
    case 'task':
      return <TaskCard task={card} onNavigate={onNavigate} />;
    case 'threat':
      return <ThreatCard threat={card.threat} />;
    case 'inventory':
      return <InventoryCard card={card} />;
    case 'comparison':
      return <ComparisonCard card={card} />;
    case 'brief':
      return <BriefCard card={card} assessmentId={card.assessment_id} onNavigate={onNavigate} />;
    case 'assessment':
      return <AssessmentCard card={card} assessmentId={card.assessment_id} onNavigate={onNavigate} />;
    default:
      return null;
  }
}

export function ToolResultIcon({ ok }) {
  return ok ? (
    <CheckCircle2 className="h-3 w-3 text-[#09660a]" aria-hidden="true" />
  ) : (
    <XCircle className="h-3 w-3 text-[#8f2727]" aria-hidden="true" />
  );
}

export function NoUnsafeContent() {
  return (
    <p className="flex items-center gap-2 text-xs text-ink-muted">
      <ShieldAlert className="h-3 w-3" aria-hidden="true" />
      The assistant explains and proposes; approvals and execution stay human-gated.
    </p>
  );
}
