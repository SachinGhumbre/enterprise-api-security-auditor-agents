import React from 'react';
import {
  BarChart3,
  Boxes,
  ClipboardCheck,
  FileSearch,
  LayoutDashboard,
  Radar,
  ShieldCheck,
  Wrench,
} from 'lucide-react';

const GROUPS = [
  {
    // Top-level landing page; rendered without a section header.
    label: null,
    items: [
      { key: 'overview', label: 'Overview', icon: LayoutDashboard, hint: 'Service health' },
    ],
  },
  {
    label: 'Guided Audit',
    items: [
      { key: 'investigation', label: 'Investigation', icon: Radar, hint: 'Live agent runs' },
      { key: 'findings', label: 'Findings & Evidence', icon: FileSearch, hint: 'Risk register' },
      { key: 'centre', label: 'Remediation Centre', icon: ClipboardCheck, hint: 'Approve & execute' },
      { key: 'models', label: 'Model Analytics', icon: BarChart3, hint: 'Usage & evals' },
    ],
  },
  {
    label: 'Express Audit',
    items: [
      { key: 'knowledge', label: 'Knowledge Base', icon: Boxes, hint: 'Ingest & search' },
      { key: 'audit', label: 'Security Audit', icon: ShieldCheck, hint: 'Audit agent' },
      { key: 'remediation', label: 'Remediation', icon: Wrench, hint: 'Remediate agent' },
    ],
  },
];

function Sidebar({ activePage, setActivePage, open, onClose }) {
  const handleSelect = (key) => {
    setActivePage(key);
    if (onClose) onClose();
  };

  return (
    <>
      {/* Mobile backdrop - a soft brand scrim rather than a black overlay. */}
      {open ? (
        <div
          className="fixed inset-0 z-30 bg-brand-900/25 backdrop-blur-sm lg:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      ) : null}

      <nav
        aria-label="Main navigation"
        className={`fixed inset-y-0 left-0 z-40 flex w-64 shrink-0 flex-col border-r
                    border-ink-hairline bg-surface-rail pt-20 transition-transform
                    duration-200 lg:static lg:z-auto lg:translate-x-0 lg:pt-0
                    ${open ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <div className="flex-1 overflow-y-auto px-3 py-5">
          {GROUPS.map((group) => (
            <div key={group.label || 'top'} className="mb-4 last:mb-0">
              {group.label ? (
                <p className="mb-2 rounded-md bg-brand-600 px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-white">
                  {group.label}
                </p>
              ) : null}
              <ul className="space-y-1">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const active = activePage === item.key;
                  return (
                    <li key={item.key}>
                      <button
                        type="button"
                        onClick={() => handleSelect(item.key)}
                        aria-current={active ? 'page' : undefined}
                        className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2.5
                                    text-left text-sm font-medium transition
                                    ${
                                      active
                                        ? 'bg-brand-600 text-white shadow-card'
                                        : 'text-ink-secondary hover:bg-brand-50 hover:text-brand-800'
                                    }`}
                      >
                        <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                        <span className="min-w-0 flex-1 truncate">{item.label}</span>
                      </button>
                      <p
                        className={`px-3 pb-1 pl-10 text-xs ${
                          active ? 'text-brand-600' : 'text-ink-muted'
                        }`}
                      >
                        {item.hint}
                      </p>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>

        <div className="mt-auto border-t border-ink-hairline px-6 py-5">
          <p className="text-xs font-semibold text-ink-secondary">Enterprise API Security Auditor</p>
          <p className="mt-0.5 font-mono text-xs text-ink-muted">v1.0.0</p>
        </div>
      </nav>
    </>
  );
}

export default Sidebar;
