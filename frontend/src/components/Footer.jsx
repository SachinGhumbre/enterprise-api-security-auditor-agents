import React from 'react';

function Footer() {
  return (
    <footer className="border-t border-ink-hairline bg-surface-header px-6 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-ink-muted">
        <p>
          <span className="font-semibold text-ink-secondary">Enterprise API Security Auditor</span>
          {' '}&middot; Meta Global AI Developer Hackathon
        </p>
        <p className="font-mono">Meta Model API &middot; AI Gateway &middot; API Gateway &middot; Kong Konnect &middot; LangGraph &middot; Redis Stack</p>
      </div>
    </footer>
  );
}

export default Footer;
