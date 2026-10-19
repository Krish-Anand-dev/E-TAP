import React, { useState, useEffect, useRef } from 'react';
import { InvestigationProvider, useInvestigation } from './context/InvestigationContext';
import OverviewPage from './pages/OverviewPage';
import SettingsPage from './pages/SettingsPage';
import Header from './components/common/Header';
import UploadPage from './pages/UploadPage';
import DashboardPage from './pages/DashboardPage';
import HistoryPage from './pages/HistoryPage';
import SocChatDrawer from './components/chat/SocChatDrawer';
import { fetchInvestigation } from './api/analyze';

function AppContent() {
  const { setData, setStatus, setError, setActiveFile, persistInvestigation } = useInvestigation();
  const [currentView, setCurrentView] = useState('overview');
  const deepLinkHandled = useRef(false);

  // Scroll to the top whenever the user switches page.
  useEffect(() => { window.scrollTo({ top: 0 }); }, [currentView]);

  // ?dossier=<email_id> deep link (used by the Gmail extension), handled once.
  useEffect(() => {
    if (deepLinkHandled.current) return;
    const params = new URLSearchParams(window.location.search);
    const dossierId = params.get('dossier');
    if (!dossierId) return;

    deepLinkHandled.current = true;
    window.history.replaceState({}, document.title, window.location.pathname);

    (async () => {
      try {
        const report = await fetchInvestigation(dossierId);
        if (report && (report.risk_score != null || report.verdict)) {
          setData(report);
          setActiveFile({ name: report.email?.subject || 'Gmail message', size: 0, lastModified: Date.now() });
          setStatus('success');
          setError(null);
          persistInvestigation(report, 'Gmail message');
          setCurrentView('dashboard');
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
      <div className="workspace-main" id="main-content">
        {currentView === 'overview' && <OverviewPage navigate={setCurrentView} />}
        {currentView === 'upload' && <UploadPage onOpenReport={() => setCurrentView('dashboard')} />}
        {currentView === 'dashboard' && <DashboardPage navigate={setCurrentView} />}
        {currentView === 'history' && <HistoryPage onOpenReport={() => setCurrentView('dashboard')} navigate={setCurrentView} />}
        {currentView === 'settings' && <SettingsPage />}
      </div>
      <SocChatDrawer />
    </div>
  );
}

export function App() {
  return (
    <InvestigationProvider>
      <AppContent />
    </InvestigationProvider>
  );
}

export default App;
