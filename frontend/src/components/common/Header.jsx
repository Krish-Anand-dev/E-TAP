import React, { useState } from 'react';
import { useInvestigation } from '../../context/InvestigationContext';
import Icon from './Icon';

export function Header({ currentView, setCurrentView }) {
  const { data, status, backendOnline, lastHealthCheck, resetInvestigation, history } = useInvestigation();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const busy = status === 'uploading' || status === 'analyzing';
  const titles = { overview:'Dashboard', upload:'Analyze email', dashboard:'Investigation', history:'Reports', workspace:'Workspace settings' };
  function navigate(view, anchor) {
    setCurrentView(view); setMobileOpen(false);
    if (anchor) window.setTimeout(() => document.getElementById(anchor)?.scrollIntoView({ behavior:'smooth' }), 50);
  }
  const nav = (view, name, label, badge, anchor) => <button type="button" className={`side-link ${currentView === view && !anchor ? 'selected' : ''}`} onClick={() => navigate(view, anchor)} disabled={view === 'dashboard' && !data} title={label} aria-current={currentView === view && !anchor ? 'page' : undefined}><Icon name={name}/><span>{label}</span>{badge != null && <small>{badge}</small>}</button>;
  return <>
    <aside className={`app-sidebar ${collapsed ? 'is-collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
      <div className="sidebar-brand"><span className="brand-mark"><Icon name="shield" size={22}/></span><span className="sidebar-wordmark">E-TAP<span>SECURITY WORKSPACE</span></span><button className="icon-button collapse-toggle" title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} onClick={() => setCollapsed(!collapsed)}><Icon name="menu" size={17}/></button></div>
      <nav aria-label="Main navigation"><p className="nav-group-label">WORKSPACE</p>{nav('overview','dashboard','Dashboard')}{nav('upload','mail','Analyze email')}{nav('history','file','Reports',history.length)}<div className="sidebar-divider"/><p className="nav-group-label">THREAT INVESTIGATION</p>{nav('dashboard','search','Investigation')}<div className="side-subnav">{nav('dashboard','shield','Evidence ledger',null,'sec-evidence')}{nav('dashboard','layers','MITRE ATT&CK',null,'sec-mitre')}{nav('dashboard','activity','Campaign lens',null,'sec-correlation')}</div><div className="sidebar-divider"/>{nav('workspace','settings','Workspace settings')}</nav>
      <div className="sidebar-bottom"><div className="workspace-avatar">ET</div><div className="workspace-name">Email intelligence<span>Your investigation workspace</span></div><span className="connection-dot" data-online={backendOnline}/></div>
    </aside>
    {mobileOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)}/>}
    <header className={`workspace-topbar ${collapsed ? 'sidebar-small' : ''}`}><div className="breadcrumb"><button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(!mobileOpen)}><Icon name="menu"/></button><Icon name="dashboard" size={17}/><span className="breadcrumb-root">Workspace</span><span className="breadcrumb-chevron">/</span><strong>{titles[currentView]}</strong></div><div className="topbar-tools"><span className="engine-pill" title={lastHealthCheck ? `Last health check: ${lastHealthCheck.toLocaleTimeString()}` : 'Checking backend connectivity'}><span className="connection-dot" data-online={backendOnline}/>{backendOnline === null ? 'Connecting' : backendOnline ? 'Engine online' : 'Engine offline'}</span><span className="running-pill"><Icon name="activity" size={15}/><span>Running</span><b>{busy ? 1 : 0}</b></span><button className="new-analysis-button" onClick={() => { resetInvestigation(); navigate('upload'); }}><Icon name="plus" size={16}/><span>New analysis</span></button></div></header>
  </>;
}
export default Header;
