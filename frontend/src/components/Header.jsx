import React from 'react';
import { LogOut, Menu, ShieldCheck } from 'lucide-react';

function Header({ onLogout, onToggleSidebar, user }) {
  return (
    <header className="sticky top-0 z-40 border-b border-ink-hairline bg-surface-header/95 backdrop-blur">
      {/* Thin brand rule keeps the light header anchored without a dark plane. */}
      <div className="h-1 bg-gradient-to-r from-brand-400 via-brand-500 to-brand-300" />

      <div className="flex items-center justify-between gap-4 px-4 py-3 sm:px-6">
        <div className="flex min-w-0 items-center gap-3">
          {onToggleSidebar ? (
            <button
              type="button"
              onClick={onToggleSidebar}
              aria-label="Toggle navigation"
              className="rounded-lg p-2 text-ink-secondary hover:bg-brand-50 hover:text-brand-700 lg:hidden"
            >
              <Menu className="h-5 w-5" aria-hidden="true" />
            </button>
          ) : null}

          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-brand-600 shadow-card">
            <ShieldCheck className="h-5 w-5 text-white" aria-hidden="true" />
          </span>

          <div className="min-w-0">
            <h1 className="truncate text-base font-bold tracking-tight text-ink-primary sm:text-lg">
              Enterprise API Security Auditor
            </h1>
            <p className="hidden text-xs text-ink-muted sm:block">
              Agentic AI compliance auditing for API Gateway
            </p>
          </div>
        </div>

        {onLogout ? (
          <div className="flex items-center gap-3">
            {user ? (
              <span className="hidden text-sm text-ink-secondary sm:inline">
                Signed in as <span className="font-semibold text-ink-primary">{user}</span>
              </span>
            ) : null}
            <button
              type="button"
              onClick={onLogout}
              className="inline-flex items-center gap-2 rounded-lg border border-ink-hairline px-3 py-2
                         text-sm font-medium text-ink-secondary transition
                         hover:border-brand-300 hover:bg-brand-50 hover:text-brand-800"
            >
              <LogOut className="h-4 w-4" aria-hidden="true" />
              <span className="hidden sm:inline">Sign out</span>
            </button>
          </div>
        ) : null}
      </div>
    </header>
  );
}

export default Header;
