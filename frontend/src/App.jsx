import React, { useState, useEffect, useRef, useCallback } from 'react';
import { InvestigationProvider, useInvestigation } from './context/InvestigationContext';
import WorkspaceTools from './components/common/WorkspaceTools';
import AuthGate from './components/common/AuthGate';
import Header from './components/common/Header';
import UploadPage from './pages/UploadPage';
import DashboardPage from './pages/DashboardPage';
import HistoryPage from './pages/HistoryPage';
import SocChatDrawer from './components/chat/SocChatDrawer';
import { fetchInvestigation } from './api/analyze';

function AppContent() {
  const { status, data, setData, setStatus, setError, setActiveFile, persistInvestigation } = useInvestigation();
  const [currentView, setCurrentView] = useState('upload'); // 'upload' | 'dashboard' | 'history'
  const deepLinkHandled = useRef(false);

  // If status transitions to success, jump to dashboard
  useEffect(() => {
    if (status === 'success' && data) {
      setCurrentView('dashboard');
    }
  }, [status, data]);

  // Check for deep link on initial mount ONLY ONCE
  useEffect(() => {
    if (deepLinkHandled.current) return;
    const params = new URLSearchParams(window.location.search);
    const dossierId = params.get('dossier');
    if (!dossierId) return;

    deepLinkHandled.current = true;
    // Clean URL immediately
    window.history.replaceState({}, document.title, window.location.pathname);

    // Fetch the report directly
    (async () => {
      try {
        const report = await fetchInvestigation(dossierId);
        if (report && (report.risk_score || report.verdict)) {
          setData(report);
          setActiveFile({
            name: report.email?.subject || 'Network Ingest',
            size: 0,
            lastModified: Date.now(),
          });
          setStatus('success');
          setError(null);
          persistInvestigation(report, 'Network Ingest');
        }
      } catch (err) {
        console.error('Deep link fetch failed:', err);
        setStatus('error');
        setError('Failed to fetch investigation report.');
      }
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="app-shell">
      <Header currentView={currentView} setCurrentView={setCurrentView} />
      <WorkspaceTools />

      {currentView === 'upload' && (
        <UploadPage onAnalysisComplete={() => setCurrentView('dashboard')} />
      )}

      {currentView === 'dashboard' && <DashboardPage />}

      {currentView === 'history' && (
        <HistoryPage onSelectDossier={() => setCurrentView('dashboard')} />
      )}

      <SocChatDrawer />
    </div>
  );
}

export function App() {
  return (
    <AuthGate><InvestigationProvider>
      <AppContent />
    </InvestigationProvider></AuthGate>
  );
}

export default App;

