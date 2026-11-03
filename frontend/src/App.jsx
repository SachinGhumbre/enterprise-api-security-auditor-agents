import React, { useCallback, useEffect, useState } from 'react';
import { Bot, X } from 'lucide-react';

import { setApiKey, setOnUnauthorized } from './api/client';
import Footer from './components/Footer';
import Header from './components/Header';
import Login from './components/Login';
import Sidebar from './components/Sidebar';
import Assistant from './pages/Assistant';
import AuditView from './pages/AuditView';
import Findings from './pages/Findings';
import Investigation from './pages/Investigation';
import KnowledgeBase from './pages/KnowledgeBase';
import ModelAnalytics from './pages/ModelAnalytics';
import Overview from './pages/Overview';
import RemediationCentre from './pages/RemediationCentre';
import RemediationView from './pages/RemediationView';
import Toast from './pages/Toast';
import './App.css';

function App() {
  const [user, setUser] = useState(null);
  const [activePage, setActivePage] = useState('overview');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [toast, setToast] = useState(null);
  const [assistantOpen, setAssistantOpen] = useState(false);

  // Shared across pages so the audit result flows straight into remediation.
  const [auditReport, setAuditReport] = useState(null);
  const [remediationPlan, setRemediationPlan] = useState(null);

  const notify = useCallback((message, type = 'success') => {
    setToast({ message, type });
  }, []);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(timer);
  }, [toast]);

  const handleLogout = useCallback(() => {
    setUser(null);
    setApiKey('');
    setActivePage('overview');
    setAuditReport(null);
    setRemediationPlan(null);
    setToast(null);
    setAssistantOpen(false);
  }, []);

  // A rejected key mid-session signs the user out instead of failing pages.
  useEffect(() => {
    setOnUnauthorized(() => {
      handleLogout();
      setToast({ message: 'Session expired or key rejected (401). Signed out.', type: 'error' });
    });
    return () => setOnUnauthorized(null);
  }, [handleLogout]);

  if (!user) {
    return <Login onLogin={setUser} />;
  }

  const pages = {
    overview: <Overview onNavigate={setActivePage} />,
    investigation: <Investigation notify={notify} />,
    findings: <Findings notify={notify} />,
    centre: <RemediationCentre notify={notify} />,
    models: <ModelAnalytics notify={notify} />,
    knowledge: <KnowledgeBase notify={notify} />,
    audit: (
      <AuditView
        notify={notify}
        auditReport={auditReport}
        setAuditReport={setAuditReport}
        onGoToRemediation={() => setActivePage('remediation')}
      />
    ),
    remediation: (
      <RemediationView
        notify={notify}
        auditReport={auditReport}
        plan={remediationPlan}
        setPlan={setRemediationPlan}
      />
    ),
  };

  return (
    <div className="flex min-h-screen flex-col bg-surface-page">
      <Header
        user={user}
        onLogout={handleLogout}
        onToggleSidebar={() => setSidebarOpen((v) => !v)}
      />

      {toast ? <Toast message={toast.message} type={toast.type} /> : null}

      <div className="flex flex-1">
        <Sidebar
          activePage={activePage}
          setActivePage={setActivePage}
          open={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />

        <main className="min-w-0 flex-1">
          <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
            {pages[activePage] || <Overview onNavigate={setActivePage} />}
          </div>
        </main>
      </div>

      {assistantOpen ? (
        <div
          role="dialog"
          aria-label="AI Security Assistant"
          className="fixed bottom-24 right-4 z-50 flex max-h-[calc(100vh-8rem)]
                     w-[min(440px,calc(100vw-2rem))] flex-col overflow-hidden
                     rounded-xl border border-ink-hairline bg-surface-raised shadow-raised"
        >
          <div className="flex items-center justify-between gap-2 border-b border-ink-hairline px-4 py-3">
            <p className="flex items-center gap-2 text-sm font-semibold text-ink-primary">
              <Bot className="h-4 w-4 text-brand-500" aria-hidden="true" />
              AI Security Assistant
            </p>
            <button
              type="button"
              onClick={() => setAssistantOpen(false)}
              aria-label="Close assistant"
              className="rounded-lg p-1.5 text-ink-secondary hover:bg-brand-50 hover:text-brand-800"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
          <div className="flex-1 overflow-y-auto p-4">
            <Assistant
              notify={notify}
              compact
              onNavigate={(page) => {
                setAssistantOpen(false);
                setActivePage(page);
              }}
            />
          </div>
        </div>
      ) : null}

      <button
        type="button"
        onClick={() => setAssistantOpen((v) => !v)}
        aria-label={assistantOpen ? 'Close assistant' : 'Open assistant'}
        title="AI Security Assistant"
        className="fixed bottom-6 right-4 z-50 flex h-14 w-14 items-center justify-center
                   rounded-full bg-brand-600 text-white shadow-raised transition
                   hover:bg-brand-700 focus:outline-none
                   focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
      >
        {assistantOpen ? (
          <X className="h-6 w-6" aria-hidden="true" />
        ) : (
          <Bot className="h-6 w-6" aria-hidden="true" />
        )}
      </button>

      <Footer />
    </div>
  );
}

export default App;
