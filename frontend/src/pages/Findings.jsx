import React, { useState } from 'react';
import { FileSearch, RotateCcw, ScrollText } from 'lucide-react';

import { assess, lastAssessment, rememberAssessment } from '../api/client';
import {
  Banner,
  Card,
  Collapsible,
  EmptyState,
  SeverityBadge,
  Spinner,
  StatTile,
  VerificationBadge,
} from '../components/ui';

const NEXT_STATES = {
  open: ['accepted', 'mitigated', 'remediated'],
  accepted: ['open', 'mitigated', 'remediated'],
  mitigated: ['open', 'remediated'],
  remediated: ['open'],
};

function LevelChip({ level, score }) {
  const map = { Critical: 'chip-critical', High: 'chip-serious', Medium: 'chip-warning', Low: 'chip-info' };
  return (
    <span className={map[level] || 'chip-info'}>
      {level} · {score}
    </span>
  );
}

function StateChip({ state }) {
  const map = { open: 'chip-info', accepted: 'chip-warning', mitigated: 'chip-serious', remediated: 'chip-good' };
  return <span className={map[state] || 'chip-info'}>{state}</span>;
}

function EntryCard({ entry, assessmentId, actor, onChanged, notify }) {
  const [busy, setBusy] = useState(false);
  const factors = entry.factors || {};
  const evidence = entry.evidence || [];
  const sources = entry.sources || [];

  const move = async (toState) => {
    setBusy(true);
    try {
      await assess.transitionRisk(assessmentId, entry.entry_id, toState, actor || undefined, '');
      notify(`${entry.entry_id} → ${toState}.`, 'success');
      onChanged();
    } catch (err) {
      notify(err.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const summary = (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="font-mono text-xs text-ink-muted">{entry.entry_id}</span>
      <span className="font-semibold text-ink-primary">{entry.title}</span>
      <LevelChip level={entry.level} score={entry.score} />
      <StateChip state={entry.state} />
      {entry.verified ? <span className="chip-good">verified</span> : <span className="chip-warning">unverified</span>}
    </span>
  );

  return (
    <Collapsible summary={summary}>
      <div className="space-y-4 text-sm">
        <p className="text-ink-secondary">
          Severity {entry.severity} · confidence {entry.confidence} ·
          capability <span className="font-mono text-xs">{entry.capability}</span> ·
          model <span className="font-mono text-xs">{entry.scoring_model}</span>
        </p>

        {Object.keys(factors).length ? (
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">Risk factors</p>
            <ul className="space-y-1">
              {Object.entries(factors).map(([name, f]) => (
                <li key={name} className="flex flex-wrap gap-x-2 text-xs text-ink-secondary">
                  <span className="font-mono font-semibold">{name} {f.score}</span>
                  <span className="text-ink-muted">— {f.rationale}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {evidence.length ? (
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              Evidence ({evidence.length})
            </p>
            <ul className="space-y-1">
              {evidence.slice(0, 12).map((e, i) => (
                <li key={i} className="font-mono text-xs text-ink-secondary">
                  [{e.kind}] {e.ref} — {e.detail}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {sources.length ? (
          <p className="text-xs text-ink-muted">
            Merged from: {sources.map((s) => `${s.stream}:${s.finding_id}`).join(', ')}
          </p>
        ) : null}

        {(entry.severity_conflicts || []).length ? (
          <p className="text-xs text-[#845a06]">{entry.severity_conflicts.join(' ')}</p>
        ) : null}

        {(entry.linked_controls || []).length ? (
          <p className="text-xs text-ink-muted">Controls: {entry.linked_controls.join(', ')}</p>
        ) : null}

        <div className="flex flex-wrap items-center gap-2 border-t border-ink-hairline pt-3">
          <span className="text-xs text-ink-muted">Lifecycle:</span>
          {(NEXT_STATES[entry.state] || []).map((next) => (
            <button key={next} type="button" disabled={busy} className="btn-ghost" onClick={() => move(next)}>
              → {next}
            </button>
          ))}
        </div>
      </div>
    </Collapsible>
  );
}

export default function Findings({ notify }) {
  const [idInput, setIdInput] = useState(() => lastAssessment());
  const [assessmentId, setAssessmentId] = useState(() => lastAssessment());
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [actor, setActor] = useState('');
  const [execSummary, setExecSummary] = useState(null);
  const [execBusy, setExecBusy] = useState(false);

  const load = async (id) => {
    if (!id) return;
    setLoading(true);
    setError('');
    try {
      const payload = await assess.details(id);
      setData(payload);
      setAssessmentId(id);
      rememberAssessment(id);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const runExecutiveSummary = async () => {
    setExecBusy(true);
    try {
      const result = await assess.executiveSummary(assessmentId);
      setExecSummary(result);
    } catch (err) {
      notify(err.message, 'error');
    } finally {
      setExecBusy(false);
    }
  };

  const state = (data && data.state) || {};
  const register = ((state.risk || {}).register) || [];
  const llmFindings = [...(state.enriched_findings || []), ...(state.recovered_findings || [])];
  const policyFindings = state.policy_findings || [];
  const threats = state.threats || [];
  const quarantined = state.quarantined || [];
  const byLevel = ((state.risk || {}).summary || {}).by_level || {};

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-bold text-ink-primary">Security Findings &amp; Evidence</h2>
        <p className="mt-1 text-sm text-ink-muted">
          The deduplicated risk register plus every underlying finding stream. Nothing here is sampled.
        </p>
      </header>

      <Card title="Assessment" subtitle="Loads the full execution snapshot for one assessment id.">
        <div className="flex flex-wrap gap-2">
          <input
            className="field max-w-md flex-1"
            value={idInput}
            onChange={(e) => setIdInput(e.target.value)}
            placeholder="e.g. asm-9f3c2a1b4d5e"
            spellCheck={false}
          />
          <button className="btn-primary" disabled={loading || !idInput.trim()} onClick={() => load(idInput.trim())}>
            {loading ? <Spinner /> : <FileSearch className="h-4 w-4" />} Load findings
          </button>
          {assessmentId ? (
            <button className="btn-ghost" disabled={loading} onClick={() => load(assessmentId)}>
              <RotateCcw className="h-4 w-4" /> Refresh
            </button>
          ) : null}
        </div>
        <div className="mt-3 flex max-w-md flex-wrap items-center gap-2">
          <span className="text-xs text-ink-muted">Acting as (for lifecycle moves):</span>
          <input
            className="field"
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            placeholder="e.g. sec-lead"
          />
        </div>
      </Card>

      {error ? <Banner tone="error" title="Request failed">{error}</Banner> : null}

      {!data && !error ? (
        <EmptyState icon={FileSearch} title="No assessment loaded">
          Enter an assessment id above. Run one from the Investigation dashboard first.
        </EmptyState>
      ) : null}

      {data ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile label="Register entries" value={register.length} hint={`model ${((state.risk || {}).scoring_model) || '?'}`} />
            <StatTile label="Critical / High" value={`${byLevel.Critical || 0} / ${byLevel.High || 0}`} tone="bad" hint="by risk level" />
            <StatTile label="Security findings" value={llmFindings.length} hint={`${policyFindings.length} policy findings`} />
            <StatTile label="Threat scenarios" value={threats.length} hint={`${quarantined.length} quarantined`} tone="warn" />
          </div>

          <Card
            title="Executive summary"
            subtitle="Two budgeted model calls over verified findings. Deterministic data stays untouched."
            actions={
              <button className="btn-ghost" disabled={execBusy} onClick={runExecutiveSummary}>
                {execBusy ? <Spinner /> : <ScrollText className="h-4 w-4" />} Generate
              </button>
            }
          >
            {execSummary ? (
              <div className="space-y-3 text-sm text-ink-secondary">
                <p className="whitespace-pre-wrap">{execSummary.executive_summary}</p>
                <Collapsible summary="Risk narrative (model reasoning)">
                  <p className="whitespace-pre-wrap text-sm">{execSummary.risk_narrative}</p>
                </Collapsible>
              </div>
            ) : (
              <p className="text-sm text-ink-muted">Not generated yet for this view.</p>
            )}
          </Card>

          <div className="space-y-2">
            <h3 className="text-base font-semibold text-ink-primary">Risk register ({register.length})</h3>
            {register.length === 0 ? <p className="text-sm text-ink-muted">No entries.</p> : null}
            {register.map((entry) => (
              <EntryCard
                key={entry.entry_id}
                entry={entry}
                assessmentId={assessmentId}
                actor={actor}
                notify={notify}
                onChanged={() => load(assessmentId)}
              />
            ))}
          </div>

          <div className="space-y-2">
            <h3 className="text-base font-semibold text-ink-primary">Security findings ({llmFindings.length})</h3>
            {llmFindings.map((f) => (
              <Collapsible
                key={f.finding_id}
                summary={
                  <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="font-mono text-xs text-ink-muted">{f.finding_id}</span>
                    <span className="font-semibold text-ink-primary">{f.policy_name}</span>
                    <SeverityBadge severity={f.severity} />
                    <VerificationBadge status={(f.verification || {}).status} />
                    <span className="chip">{f.tier}</span>
                  </span>
                }
              >
                <div className="space-y-2 text-sm text-ink-secondary">
                  <p>{f.details}</p>
                  <p className="text-xs text-ink-muted">
                    Service <span className="font-mono">{f.service}</span> ·
                    missing <span className="font-mono">{(f.missing_plugins || []).join(', ') || '—'}</span> ·
                    evidence <span className="font-mono">{(f.evidence_ids || []).join(', ') || '—'}</span>
                  </p>
                  {(f.verification || {}).confidence_basis ? (
                    <p className="text-xs">Confidence basis: {f.verification.confidence_basis}</p>
                  ) : null}
                </div>
              </Collapsible>
            ))}
          </div>

          {policyFindings.length ? (
            <div className="space-y-2">
              <h3 className="text-base font-semibold text-ink-primary">Policy findings ({policyFindings.length})</h3>
              {policyFindings.map((f) => (
                <Collapsible
                  key={f.finding_id}
                  summary={
                    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="font-mono text-xs text-ink-muted">{f.finding_id}</span>
                      <span className="font-semibold text-ink-primary">
                        {(f.applicable_standard || {}).control || f.category}
                      </span>
                      <SeverityBadge severity={f.severity} />
                      <span className="chip">{f.tier}</span>
                    </span>
                  }
                >
                  <pre className="overflow-x-auto rounded-lg bg-surface-sunken p-3 font-mono text-xs text-ink-secondary">
                    {JSON.stringify(f, null, 2)}
                  </pre>
                </Collapsible>
              ))}
            </div>
          ) : null}

          {threats.length ? (
            <div className="space-y-2">
              <h3 className="text-base font-semibold text-ink-primary">
                Threat scenarios ({threats.length}) · suspected, not confirmed
              </h3>
              {threats.map((t, i) => (
                <Collapsible
                  key={i}
                  summary={
                    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="font-semibold text-ink-primary">{t.title}</span>
                      <SeverityBadge severity={t.severity_hint} />
                      <span className="chip-warning">suspected</span>
                    </span>
                  }
                >
                  <div className="space-y-2 text-sm text-ink-secondary">
                    {t.description ? <p>{t.description}</p> : null}
                    {(t.preconditions || []).length ? (
                      <p className="text-xs">Preconditions: {t.preconditions.join(' · ')}</p>
                    ) : null}
                    {(t.evidence_refs || []).length ? (
                      <p className="font-mono text-xs">Refs: {t.evidence_refs.join(', ')}</p>
                    ) : null}
                  </div>
                </Collapsible>
              ))}
            </div>
          ) : null}

          {quarantined.length ? (
            <Banner tone="warn" title={`${quarantined.length} finding(s) quarantined (insufficient evidence)`}>
              <ul className="list-disc pl-5 text-sm">
                {quarantined.slice(0, 10).map((q, i) => (
                  <li key={i}>
                    <span className="font-mono text-xs">{q.finding_id}</span> — {q.quarantine_reason}
                  </li>
                ))}
              </ul>
            </Banner>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
