import React, { useEffect, useState } from 'react';
import apiClient from '../api/client';
import { useInvestigation } from '../context/InvestigationContext';

export function HistoryPage({ onSelectDossier }) {
  const { history, loadFromHistory, clearHistory } = useInvestigation();

  const [stored, setStored] = useState([]);
  const [storedError, setStoredError] = useState('');
  useEffect(() => { apiClient.get('/investigations?limit=100').then(r => setStored(r.data)).catch(() => setStoredError('Stored reports unavailable.')); }, []);
  const handleSelect = (record) => {
    loadFromHistory(record);
    if (onSelectDossier) onSelectDossier();
  };

  const getVerdictClass = (verdict, score) => {
    if (score >= 70 || verdict.includes('HIGH') || verdict.includes('PHISH')) return 'danger';
    if (score >= 40 || verdict.includes('SUSPICIOUS')) return 'caution';
    return 'safe';
  };

  return (
    <div className="upload-container" style={{ maxWidth: '1000px' }}>
      <div className="ingest-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <span className="ingest-badge">AUDIT TRAIL // CASE ARCHIVE</span>
          <h1 className="ingest-title">Past Forensic Investigations</h1>
          <p className="ingest-desc">
            Historical log of email artifacts processed through the analysis pipeline.
          </p>
        </div>

        {history.length > 0 && (
          <button
            type="button"
            className="btn-ghost"
            style={{ color: 'var(--verdict-danger)' }}
            onClick={clearHistory}
          >
            Clear History
          </button>
        )}
      </div>

      <section className="forensic-panel" style={{padding:16}}>
        <h2>Stored reports and review queue</h2><p>Your 100 most recent stored reports. Other owners' reports are not included.</p>
        <p role="status">{storedError}</p>
        <ul>{stored.map(r => <li key={r.email_id}><button onClick={() => handleSelect(r.email_id)}>{r.subject || r.email_id} — {r.review_state} — {r.verdict || 'Unknown'}</button></li>)}</ul>
      </section>
      {/* Backend endpoint notice */}
      <div
        style={{
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-hairline)',
          borderRadius: 'var(--radius-xs)',
          padding: '12px 16px',
          marginBottom: '20px',
          fontSize: 'var(--fs-xs)',
          color: 'var(--text-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}
      >
        <span style={{ color: 'var(--accent-amber)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
          [NOTICE]
        </span>
        <span>
          This list is a browser-local convenience history; it is not a shared server-side investigations feed. Individual stored dossiers can be fetched by ID via{' '}
          <code className="mono-val" style={{ color: 'var(--accent-amber)' }}>GET /investigations/{'{id}'}</code>. Clearing this list does not delete server-side analysis records.
        </span>
      </div>

      {history.length === 0 ? (
        <div className="forensic-panel" style={{ textAlign: 'center', padding: '48px' }}>
          <div style={{ color: 'var(--text-muted)', marginBottom: '12px' }}>
            No email investigations recorded yet.
          </div>
          <span style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-secondary)' }}>
            Upload an email artifact via the Ingest Terminal to begin logging.
          </span>
        </div>
      ) : (
        <div className="forensic-table-container">
          <table className="forensic-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>CASE / ARTIFACT</th>
                <th>FROM SENDER</th>
                <th>SUBJECT</th>
                <th>RISK SCORE</th>
                <th>VERDICT</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {history.map((record) => {
                const verdictClass = getVerdictClass(record.verdict, record.risk_score);
                return (
                  <tr key={record.id}>
                    <td className="mono-val" style={{ whiteSpace: 'nowrap', fontSize: 'var(--fs-micro)' }}>
                      {new Date(record.analyzed_at).toLocaleString()}
                    </td>
                    <td className="mono-val" style={{ fontWeight: 600 }}>
                      {record.filename}
                    </td>
                    <td className="mono-val" style={{ maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {record.from}
                    </td>
                    <td style={{ maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {record.subject}
                    </td>
                    <td>
                      <span className="mono-val" style={{ fontWeight: 700, color: verdictClass === 'danger' ? 'var(--verdict-danger)' : verdictClass === 'caution' ? 'var(--accent-amber)' : 'var(--verdict-safe)' }}>
                        {record.risk_score}/100
                      </span>
                    </td>
                    <td>
                      <span className={`status-pill ${verdictClass}`}>
                        {record.verdict}
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-primary-action"
                        style={{ padding: '4px 10px', fontSize: 'var(--fs-micro)' }}
                        onClick={() => handleSelect(record)}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default HistoryPage;
