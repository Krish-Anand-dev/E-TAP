import React from 'react';
import { useInvestigation } from '../../context/InvestigationContext';

export default function LocalWorkspaceTools() {
  const { history, clearHistory } = useInvestigation();
  const sandboxReports = history.filter(record => record.report?.sandbox?.mode === 'virtualbox');
  const complete = sandboxReports.filter(record => record.report.sandbox.status === 'done');
  return <section className="forensic-panel" style={{ padding: 24 }}>
    <h2>Your local workspace</h2>
    <p>Analysis uses your local backend and its configured providers. Eligible attachments run in your VirtualBox sandbox.</p>
    <div className="metadata-grid">
      <div className="meta-field"><div className="meta-field-label">REPORTS THIS SESSION</div><strong>{history.length}</strong></div>
      <div className="meta-field"><div className="meta-field-label">SANDBOX REPORTS</div><strong>{sandboxReports.length}</strong></div>
      <div className="meta-field"><div className="meta-field-label">SANDBOX JOBS COMPLETED</div><strong>{complete.length}</strong></div>
    </div>
    <p>These counts cover this browser session. Server analytics, retention controls and vendor baselines are not available in this local version.</p>
    <button type="button" className="btn-ghost" onClick={clearHistory} disabled={!history.length}>Clear session history</button>
    <p className="muted">Clearing this list leaves stored investigations on the backend.</p>
  </section>;
}
