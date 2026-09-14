import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';

export function Header({ currentView, setCurrentView }) {
  const { data, backendOnline, lastHealthCheck, resetInvestigation, history } = useInvestigation();

  return (
    <header className="top-console-header">
      <div className="brand-section">
        <span className="brand-tag">SIH // FORENSICS</span>
        <span className="brand-title">PHISHGUARD</span>
        <span className="brand-subtitle">Automated Email Threat Forensics</span>
      </div>

      <div className="header-actions">
        <div
          className="backend-indicator"
          title={
            backendOnline
              ? `Forensic Analysis Engine Online — Health verified (Last: ${
                  lastHealthCheck ? lastHealthCheck.toLocaleTimeString() : 'just now'
                })`
              : 'Backend engine unreachable — verify cloud service or network status'
          }
        >
          <span className={`indicator-dot ${backendOnline === false ? 'offline' : ''}`} />
          <span>{backendOnline === null ? 'Checking API...' : backendOnline ? 'ENGINE ONLINE' : 'ENGINE OFFLINE'}</span>
        </div>

        <button
          type="button"
          className={`nav-button ${currentView === 'upload' ? 'active' : ''}`}
          onClick={() => {
            resetInvestigation();
            setCurrentView('upload');
          }}
        >
          + Ingest Email
        </button>

        {data && (
          <button
            type="button"
            className={`nav-button ${currentView === 'dashboard' ? 'active' : ''}`}
            onClick={() => setCurrentView('dashboard')}
          >
            Dossier View
          </button>
        )}

        <button
          type="button"
          className={`nav-button ${currentView === 'history' ? 'active' : ''}`}
          onClick={() => setCurrentView('history')}
        >
          History ({history.length})
        </button>
      </div>
    </header>
  );
}

export default Header;
