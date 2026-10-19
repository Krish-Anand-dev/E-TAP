import React, { useState } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import Icon from './Icon';

const TITLES = { overview: 'Dashboard', upload: 'Analyze email', dashboard: 'Investigation', history: 'Reports', settings: 'Trusted domains' };

export function Header({ currentView, setCurrentView }) {
  const { data, status, backendOnline, lastHealthCheck, resetInvestigation, history } = useInvestigation();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const busy = status === 'uploading' || status === 'analyzing';

  function navigate(view) {
    setCurrentView(view);
    setMobileOpen(false);
  }

  const nav = (view, icon, label, badge) => (
    <button
      type="button"
      className={`side-link ${currentView === view ? 'selected' : ''}`}
      onClick={() => navigate(view)}
      disabled={view === 'dashboard' && !data}
      title={view === 'dashboard' && !data ? 'Analyze or open an email first' : label}
      aria-current={currentView === view ? 'page' : undefined}
    >
      <Icon name={icon} />
      <span>{label}</span>
      {badge != null && <small>{badge}</small>}
    </button>
  );

  return <>
    <aside className={`app-sidebar ${collapsed ? 'is-collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
      <div className="sidebar-brand">
        <span className="brand-mark"><Icon name="shield" size={22} /></span>
        <span className="sidebar-wordmark">E-TAP<span>EMAIL THREAT ANALYSIS</span></span>
        <button className="icon-button collapse-toggle" title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} onClick={() => setCollapsed(!collapsed)}><Icon name="menu" size={17} /></button>
      </div>
      <nav aria-label="Main navigation">
        <p className="nav-group-label">WORKSPACE</p>
        {nav('overview', 'dashboard', 'Dashboard')}
        {nav('upload', 'mail', 'Analyze email')}
        {nav('history', 'file', 'Reports', history.length || null)}
        {nav('dashboard', 'search', 'Current investigation')}
        <div className="sidebar-divider" />
        <p className="nav-group-label">PREFERENCES</p>
        {nav('settings', 'settings', 'Trusted domains')}
      </nav>
    </aside>
    {mobileOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <header className={`workspace-topbar ${collapsed ? 'sidebar-small' : ''}`}>
      <div className="breadcrumb">
        <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(!mobileOpen)}><Icon name="menu" /></button>
        <Icon name="dashboard" size={17} /><span className="breadcrumb-root">E-TAP</span><span className="breadcrumb-chevron">/</span><strong>{TITLES[currentView]}</strong>
      </div>
      <div className="topbar-tools">
        <span className="engine-pill" title={lastHealthCheck ? `Last check: ${lastHealthCheck.toLocaleTimeString()}` : 'Checking the analysis engine'}>
          <span className="connection-dot" data-online={backendOnline} />
          {backendOnline === null ? 'Connecting' : backendOnline ? 'Engine online' : 'Engine offline'}
        </span>
        {busy && <span className="running-pill"><Icon name="activity" size={15} /><span>Analyzing</span></span>}
        <button className="new-analysis-button" onClick={() => { if (!busy) resetInvestigation(); navigate('upload'); }}><Icon name="plus" size={16} /><span>New analysis</span></button>
      </div>
    </header>
  </>;
}
export default Header;
