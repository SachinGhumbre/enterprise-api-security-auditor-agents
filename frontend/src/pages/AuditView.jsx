import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Download,
  PlayCircle,
  RotateCcw,
  Server,
  ShieldCheck,
  XCircle,
} from 'lucide-react';

import { agents } from '../api/client';
import {
  Banner,
  Card,
  ComplianceBadge,
  EmptyState,
  ProgressBar,
  Spinner,
  StatTile,
  VerificationBadge,
} from '../components/ui';

export const SECURITY_STANDARDS = [
  'GDPR',
  'HIPAA',
  'PCI-DSS',
  'ISO 27001',
  'OWASP API Top 10',
  'PSD2/SCA',
  'PIPEDA',
  'NIST',
  'SOC 2',
];

// The backend prefixes deliberate no-Kong notes with "Sample inventory:" —
// those render as info (expected demo path), everything else stays a warning.
function isSampleNote(text) {
  return (text || '').startsWith('Sample inventory:');
}

export default function AuditView({ notify, auditReport, setAuditReport, onGoToRemediation }) {
  const [selected, setSelected] = useState(['OWASP API Top 10', 'GDPR']);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);
  const [warnings, setWarnings] = useState([]);
  const [inventory, setInventory] = useState(null);

  const allSelected = selected.length === SECURITY_STANDARDS.length;

  const loadInventory = useCallback(async () => {
    try {
      setInventory(await agents.kongServices());
    } catch (err) {
      setInventory({ error: err.message, services: [], count: 0 });
    }
  }, []);

  useEffect(() => {
    loadInventory();
  }, [loadInventory]);

  const toggle = (standard) =>
    setSelected((prev) =>
      prev.includes(standard) ? prev.filter((s) => s !== standard) : [...prev, standard]
    );

  const toggleAll = () => setSelected(allSelected ? [] : [...SECURITY_STANDARDS]);

  const runAudit = async () => {
    setRunning(true);
    setError(null);
    setWarnings([]);
    try {
      const data = await agents.audit({ selectedStandards: selected, topK: 4 });
      setAuditReport(data.audit_report || {});
      setSummary(data.summary || null);
      setWarnings(data.warnings || []);
      notify('Security audit completed.', 'success');
    } catch (err) {
      setError(err.message);
      notify('Audit failed.', 'error');
    } finally {
      setRunning(false);
    }
  };

  const reset = () => {
    setAuditReport(null);
    setSummary(null);
    setWarnings([]);
    setError(null);
  };

  const download = () => {
    if (!auditReport) return;
    const blob = new Blob([JSON.stringify({ audit_report: auditReport }, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'audit_report.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Non-compliant findings first - that is what a reviewer needs to see.
  const rows = useMemo(() => {
    if (!auditReport) return [];
    const flat = [];
    Object.values(auditReport).forEach((service) => {
      (service.policies || []).forEach((policy) => {
        flat.push({
          serviceName: service.serviceName,
          servicePlugins: service.service_plugins || [],
          policySources: service.policy_sources || [],
          serviceEvidence: service.policy_evidence || null,
          // Chunk-level citations with retrieval scores when the report has
          // them, otherwise the legacy filename list (old reports).
          groundedBy: (service.policy_evidence?.chunks?.length
            ? service.policy_evidence.chunks.map((c) => `${c.source} (${c.score})`)
            : service.policy_sources) || [],
          verification: policy.verification || null,
          policyName: policy.policy_name,
          comply: !!policy.comply,
          missingPlugins: policy.missing_plugins || [],
          details: policy.details || '',
        });
      });
      if (service.error) {
        flat.push({
          serviceName: service.serviceName,
          servicePlugins: service.service_plugins || [],
          policySources: [],
          groundedBy: [],
          verification: null,
          policyName: 'Audit error',
          comply: false,
          missingPlugins: [],
          details: service.error,
          isError: true,
        });
      }
    });
    return flat.sort((a, b) => Number(a.comply) - Number(b.comply));
  }, [auditReport]);

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-xl font-bold text-ink-primary">Security Audit</h2>
        <p className="mt-1 text-sm text-ink-muted">
          The Audit Agent perceives Kong configuration, retrieves the matching policy excerpts from
          the vector store, and reasons over both to produce a compliance verdict per policy.
        </p>
      </header>

      {error ? <Banner tone="error" title="Audit failed">{error}</Banner> : null}
      {warnings.map((w) => (
        <Banner key={w} tone={isSampleNote(w) ? 'info' : 'warn'} title={isSampleNote(w) ? 'Sample inventory' : 'Degraded input'}>{w}</Banner>
      ))}

      <Card
        title="Kong service inventory"
        subtitle={
          inventory
            ? `${inventory.count} service(s) - source: ${inventory.source || 'unknown'}`
            : 'Loading...'
        }
        actions={
          <button className="btn-ghost" onClick={loadInventory}>
            <RotateCcw className="h-4 w-4" /> Refresh
          </button>
        }
      >
        {inventory && inventory.warning ? (
          <Banner tone={isSampleNote(inventory.warning) ? 'info' : 'warn'} title={isSampleNote(inventory.warning) ? 'Sample inventory' : 'Using cached inventory'}>{inventory.warning}</Banner>
        ) : null}
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {(inventory?.services || []).map((s) => (
            <div key={s.service_id} className="rounded-lg border border-ink-hairline bg-surface-sunken p-4">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-brand-600" aria-hidden="true" />
                <p className="font-semibold text-ink-primary">{s.service_name}</p>
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {(s.service_plugins || []).length ? (
                  s.service_plugins.map((p) => (
                    <span key={p} className="chip-neutral">
                      {p}
                    </span>
                  ))
                ) : (
                  <span className="chip-critical">no plugins</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card
        title="Security standards in scope"
        subtitle="Selected standards are passed to the agent and shape which policies it evaluates."
        actions={
          <button className="btn-ghost" onClick={toggleAll}>
            {allSelected ? 'Clear all' : 'Select all'}
          </button>
        }
      >
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
          {SECURITY_STANDARDS.map((standard) => {
            const active = selected.includes(standard);
            return (
              <button
                key={standard}
                type="button"
                onClick={() => toggle(standard)}
                aria-pressed={active}
                className={`flex items-center justify-between gap-2 rounded-lg border px-3 py-2.5 text-left text-sm font-medium transition-all
                  ${
                    active
                      ? 'border-brand-500 bg-brand-600 text-white shadow-glow'
                      : 'border-ink-hairline bg-surface-raised text-ink-secondary hover:border-brand-300 hover:bg-brand-50'
                  }`}
              >
                <span className="truncate">{standard}</span>
                {active ? <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden="true" /> : null}
              </button>
            );
          })}
        </div>

        <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-ink-hairline pt-5">
          <button className="btn-primary" onClick={runAudit} disabled={running}>
            {running ? <Spinner /> : <PlayCircle className="h-4 w-4" />}
            {running ? 'Running audit...' : 'Start security audit'}
          </button>
          <button className="btn-ghost" onClick={download} disabled={!auditReport}>
            <Download className="h-4 w-4" /> Download report
          </button>
          <button className="btn-ghost" onClick={reset} disabled={!auditReport && !error}>
            <RotateCcw className="h-4 w-4" /> Reset
          </button>
          {auditReport ? (
            <button className="btn-accent ml-auto" onClick={onGoToRemediation}>
              <ShieldCheck className="h-4 w-4" /> Generate remediation plan
            </button>
          ) : null}
        </div>

        {running ? (
          <p className="mt-4 flex items-center gap-2 text-sm text-brand-700">
            <Spinner /> Perceive &rarr; Retrieve &rarr; Reason &rarr; Verify &rarr; Plan &rarr; Act. One LLM call
            per service, typically 30-60s.
          </p>
        ) : null}
      </Card>

      {summary ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <StatTile label="Services audited" value={summary.services_audited} icon={Server} />
          <StatTile label="Policies evaluated" value={summary.policies_evaluated} icon={Activity} />
          <StatTile label="Compliant" value={summary.compliant} tone="good" icon={CheckCircle2} />
          <StatTile label="Non-compliant" value={summary.non_compliant} tone="bad" icon={XCircle} />
          <div className="card animate-fade-up p-5">
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
              Compliance rate
            </p>
            <p className="mt-2 text-3xl font-bold tabular-nums text-ink-primary">
              {summary.compliance_rate}%
            </p>
            <div className="mt-3">
              <ProgressBar
                value={summary.compliance_rate}
                tone={
                  summary.compliance_rate >= 80
                    ? 'good'
                    : summary.compliance_rate >= 50
                    ? 'warn'
                    : 'bad'
                }
              />
            </div>
            <p className="mt-2 text-xs text-ink-muted">
              {summary.retrieved_policy_chunks} policy chunks retrieved &middot; {summary.llm_provider}
            </p>
          </div>
        </div>
      ) : null}

      <Card
        title="Audit findings"
        subtitle={rows.length ? 'Non-compliant findings are listed first.' : undefined}
      >
        {rows.length ? (
          <div className="table-wrap">
            <table className="min-w-full">
              <thead>
                <tr>
                  <th className="th">Status</th>
                  <th className="th">Verification</th>
                  <th className="th">Service</th>
                  <th className="th">Policy</th>
                  <th className="th">Missing plugins</th>
                  <th className="th">Details</th>
                  <th className="th">Grounded by</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, i) => (
                  <tr key={`${row.serviceName}-${row.policyName}-${i}`} className="hover:bg-brand-50">
                    <td className="td"><ComplianceBadge comply={row.comply} /></td>
                    <td className="td">
                      {row.verification ? (
                        <div
                          className="flex flex-col items-start gap-1"
                          title={row.verification.confidence_basis || ''}
                        >
                          <VerificationBadge status={row.verification.status} />
                          <span className="text-xs text-ink-muted">
                            confidence: {row.verification.confidence || '--'}
                          </span>
                        </div>
                      ) : (
                        <span className="text-ink-muted">&mdash;</span>
                      )}
                    </td>
                    <td className="td font-semibold text-ink-primary">{row.serviceName}</td>
                    <td className="td">
                      {row.policyName}
                      {row.verification?.evidence?.standards_in_scope?.length ? (
                        <div className="mt-1 text-xs text-ink-muted">
                          scope: {row.verification.evidence.standards_in_scope.join(', ')}
                        </div>
                      ) : null}
                    </td>
                    <td className="td">
                      {row.missingPlugins.length ? (
                        <div className="flex flex-wrap gap-1">
                          {row.missingPlugins.map((p) => (
                            <span key={p} className="chip bg-[#fbeaea] font-mono text-[#8f2727] ring-1 ring-[#f0c2c2]">
                              {p}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-ink-muted">&mdash;</span>
                      )}
                    </td>
                    <td className="td max-w-md">
                      <span className={row.isError ? 'text-[#8f2727]' : ''}>
                        {row.details || <span className="text-ink-muted">&mdash;</span>}
                      </span>
                    </td>
                    <td className="td">
                      <div className="flex flex-col gap-0.5">
                        {row.groundedBy.length ? (
                          row.groundedBy.map((s) => (
                            <span key={s} className="font-mono text-xs text-ink-muted">{s}</span>
                          ))
                        ) : (
                          <span className="text-ink-muted">&mdash;</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon={ShieldCheck} title="No audit has run yet">
            Pick the standards in scope and click <strong>Start security audit</strong>.
          </EmptyState>
        )}
      </Card>
    </div>
  );
}
