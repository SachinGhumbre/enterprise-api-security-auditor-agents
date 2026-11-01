import React, { useCallback, useEffect, useState } from 'react';

import Footer from './components/Footer';
import Header from './components/Header';
import Login from './components/Login';
import Sidebar from './components/Sidebar';
import AuditView from './pages/AuditView';
import KnowledgeBase from './pages/KnowledgeBase';
import Overview from './pages/Overview';
import RemediationView from './pages/RemediationView';
import Toast from './pages/Toast';
import './App.css';

function App() {
  const [user, setUser] = useState(null);
  const [activePage, setActivePage] = useState('overview');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [toast, setToast] = useState(null);

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

  const handleLogout = () => {
    setUser(null);
    setActivePage('overview');
    setAuditReport(null);
    setRemediationPlan(null);
    setToast(null);
  };

  if (!user) {
    return <Login onLogin={setUser} />;
  }

  const pages = {
    overview: <Overview onNavigate={setActivePage} />,
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

      <Footer />
    </div>
  );
}

export default App;
