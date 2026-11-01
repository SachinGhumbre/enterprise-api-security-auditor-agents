import React, { useMemo, useState } from 'react';
import { Download, ListChecks, Sparkles, Wrench } from 'lucide-react';

import { agents } from '../api/client';
import { Banner, Card, EmptyState, SeverityBadge, Spinner, StatTile } from '../components/ui';

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low'];

export default function RemediationView({ notify, auditReport, plan, setPlan }) {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);
  const [note, setNote] = useState(null);

  const run = async () => {
    setRunning(true);
    setError(null);
    setNote(null);
    try {
      // With no audit report in state the backend falls back to the last report
      // it saved to disk, so this still works after a page refresh.
      const data = await agents.remediate(auditReport);
      setPlan(data.remediation_plan || []);
      setSummary(data.summary || null);
      if (data.note) setNote(data.note);
      if (data.error) setError(data.error);
      notify(
        `Remediation plan generated: ${(data.remediation_plan || []).length} action(s).`,
        'success'
      );
    } catch (err) {
      setError(err.message);
      notify('Remediation failed.', 'error');
    } finally {
      setRunning(false);
    }
  };

  const download = () => {
    if (!plan || !plan.length) return;
    const blob = new Blob([JSON.stringify(plan, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'remediation_plan.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const counts = useMemo(() => {
    const out = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    (plan || []).forEach((item) => {
      const key = String(item.severity || 'Medium').trim();
      const match = SEVERITY_ORDER.find((s) => s.toLowerCase() === key.toLowerCase());
      if (match) out[match] += 1;
    });
    return out;
  }, [plan]);

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-bold text-ink-primary">Remediation Plan</h2>
        <p className="mt-1 text-sm text-ink-muted">
          The Remediation Agent takes the non-compliant findings, retrieves supporting policy
          excerpts, and produces prioritised, standard-referenced actions.
        </p>
      </header>

      {error ? <Banner tone="error" title="Remediation problem">{error}</Banner> : null}
      {note ? <Banner tone="info" title="Nothing to remediate">{note}</Banner> : null}
      {!auditReport ? (
        <Banner tone="info" title="No audit in this session">
          Run an audit first for the freshest results. Running now will use the last audit report
          saved on the server.
        </Banner>
      ) : null}

      <Card title="Generate plan">
        <div className="flex flex-wrap items-center gap-3">
          <button className="btn-primary" onClick={run} disabled={running}>
            {running ? <Spinner /> : <Sparkles className="h-4 w-4" />}
            {running ? 'Generating...' : 'Generate remediation plan'}
          </button>
          <button className="btn-ghost" onClick={download} disabled={!plan || !plan.length}>
            <Download className="h-4 w-4" /> Download plan
          </button>
        </div>
        {running ? (
          <p className="mt-4 flex items-center gap-2 text-sm text-brand-700">
            <Spinner /> Perceive &rarr; Retrieve &rarr; Reason &rarr; Plan &rarr; Act.
          </p>
        ) : null}
      </Card>

      {plan && plan.length ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <StatTile
              label="Total actions"
              value={plan.length}
              tone="brand"
              icon={ListChecks}
              hint={summary ? `provider: ${summary.llm_provider}` : undefined}
            />
            {SEVERITY_ORDER.map((sev) => (
              <StatTile
                key={sev}
                label={sev}
                value={counts[sev]}
                tone={sev === 'Critical' || sev === 'High' ? 'bad' : 'warn'}
              />
            ))}
          </div>

          <Card title="Prioritised actions" subtitle="Sorted Critical first.">
            <div className="space-y-4">
              {plan.map((item, i) => (
                <article
                  key={`${item.serviceName}-${item.policyName}-${i}`}
                  className="animate-fade-up rounded-xl border border-ink-hairline bg-surface-raised p-5 shadow-card"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h4 className="text-base font-semibold text-ink-primary">
                        {item.serviceName}
                      </h4>
                      <p className="mt-0.5 text-sm text-ink-muted">{item.policyName}</p>
                    </div>
                    <SeverityBadge severity={item.severity} />
                  </div>

                  <dl className="mt-4 grid gap-4 md:grid-cols-2">
                    <div>
                      <dt className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                        Issue
                      </dt>
                      <dd className="mt-1 text-sm text-ink-secondary">{item.issue}</dd>
                    </div>
                    <div>
                      <dt className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                        Missing plugin
                      </dt>
                      <dd className="mt-1">
                        <code className="rounded bg-[#fbeaea] px-2 py-0.5 font-mono text-xs text-[#8f2727] ring-1 ring-[#f0c2c2]">
                          {item.missingPlugin || '--'}
                        </code>
                      </dd>
                    </div>
                    <div className="md:col-span-2">
                      <dt className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                        Recommended action
                      </dt>
                      <dd className="mt-1 text-sm leading-relaxed text-ink-secondary">
                        {item.recommendedAction}
                      </dd>
                    </div>
                    <div className="md:col-span-2">
                      <dt className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                        Impact if unresolved
                      </dt>
                      <dd className="mt-1 text-sm leading-relaxed text-ink-secondary">{item.impact}</dd>
                    </div>
                  </dl>

                  <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-ink-hairline pt-4">
                    <span className="chip bg-surface-page text-ink-secondary">Owner: {item.owner}</span>
                    <span className="chip bg-surface-page text-ink-secondary">
                      Effort: {item.estimatedEffort}
                    </span>
                    <span className="chip bg-brand-50 text-brand-700 ring-1 ring-brand-200">
                      {item.securityStandardReference}
                    </span>
                  </div>
                </article>
              ))}
            </div>
          </Card>
        </>
      ) : (
        <Card>
          <EmptyState icon={Wrench} title="No remediation plan yet">
            Generate a plan from the latest audit findings. If every policy is compliant, the plan
            will come back empty.
          </EmptyState>
        </Card>
      )}
    </div>
  );
}
