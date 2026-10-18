import React from 'react';

const STATUS_LABELS = {
  always: 'Processed by E-TAP backend',
  stored: 'Stored in database',
  sent: 'Remote request made',
  partial: 'Partial / mixed outcomes',
  cached: 'Cached result reused',
  not_configured: 'Not configured; not sent',
  off: 'External lookups disabled',
  skipped_by_triage: 'Skipped by triage',
  nothing_to_send: 'No applicable indicators',
  skipped: 'Skipped',
  skipped_by_policy: 'Skipped by policy/limit',
  skipped_for_privacy: 'Skipped for privacy',
  unavailable: 'Unavailable',
};

function FlowCard({ flow }) {
  return (
    <details className="privacy-flow-card">
      <summary>
        <span className="privacy-flow-name">{flow.name}</span>
        <span className="privacy-flow-status">{STATUS_LABELS[flow.status] || String(flow.status || 'Unknown').replaceAll('_', ' ')}</span>
      </summary>
      {Array.isArray(flow.sends) && flow.sends.length > 0 && (
        <div className="privacy-flow-section">
          <strong>Data involved</strong>
          <ul>{flow.sends.map((item, i) => <li key={i}>{item}</li>)}</ul>
        </div>
      )}
      {Array.isArray(flow.notes) && flow.notes.length > 0 && (
        <div className="privacy-flow-section">
          <strong>Notes</strong>
          <ul>{flow.notes.map((item, i) => <li key={i}>{item}</li>)}</ul>
        </div>
      )}
    </details>
  );
}

export function PrivacyDataPanel({ report }) {
  if (!report) return null;
  const lookups = report.url_lookups || {};
  const flows = report.flows || [];
  return (
    <section className="forensic-panel privacy-data-panel" aria-label="Privacy and data flows">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Privacy & Data Flow</span>
          <span className="panel-subtitle">What was processed, stored, sent or deliberately skipped.</span>
        </div>
        <span className={`provider-status-badge ${report.external_lookups_enabled ? 'provider-status-caution' : 'provider-status-neutral'}`}>
          {report.external_lookups_enabled ? 'External lookups enabled' : 'External lookups off'}
        </span>
      </div>
      <div className="privacy-url-summary">
        <div><span>URLs found</span><strong>{lookups.total_urls ?? 0}</strong></div>
        <div><span>Full-URL requests</span><strong>{lookups.sent_in_full ?? 0}</strong></div>
        <div><span>Query/fragment trimmed requests</span><strong>{lookups.sent_trimmed ?? 0}</strong></div>
        <div><span>Cached results reused</span><strong>{(lookups.cached_full ?? 0) + (lookups.cached_trimmed ?? 0)}</strong></div>
        <div><span>Skipped for privacy</span><strong>{lookups.skipped_for_privacy?.length ?? 0}</strong></div>
        <div><span>Not sent (policy/limit)</span><strong>{lookups.skipped_by_policy?.length ?? 0}</strong></div>
        <div><span>Not sent (missing key)</span><strong>{lookups.not_sent_missing_key ?? 0}</strong></div>
      </div>
      {lookups.note && <p className="privacy-flow-note">{lookups.note}</p>}
      {Array.isArray(lookups.skipped_by_policy) && lookups.skipped_by_policy.length > 0 && (
        <details className="privacy-flow-card">
          <summary><span className="privacy-flow-name">URLs not queried because of provider policy/limits</span><span className="privacy-flow-status">{lookups.skipped_by_policy.length} skipped</span></summary>
          <ul className="privacy-skipped-list">
            {lookups.skipped_by_policy.map((item, i) => (
              <li key={`${item.url || 'url'}-${i}`}>
                <code>{item.url || '(destination hidden)'}</code>
                <span>{String(item.status || 'skipped').replaceAll('_', ' ')}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
      {Array.isArray(lookups.skipped_for_privacy) && lookups.skipped_for_privacy.length > 0 && (
        <details className="privacy-flow-card">
          <summary><span className="privacy-flow-name">URLs not sent to VirusTotal</span><span className="privacy-flow-status">{lookups.skipped_for_privacy.length} skipped</span></summary>
          <ul className="privacy-skipped-list">
            {lookups.skipped_for_privacy.map((item, i) => (
              <li key={`${item.url || 'url'}-${i}`}>
                <code>{item.url || '(destination hidden)'}</code>
                <span>{item.why || (item.reasons || []).join(', ')}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
      <div className="privacy-flow-list">{flows.map((flow) => <FlowCard key={flow.id} flow={flow} />)}</div>
      {Number(lookups.not_sent_internal_throttle || 0) > 0 && (
        <p className="privacy-flow-note">VirusTotal's local request limiter prevented {lookups.not_sent_internal_throttle} additional remote request(s); no query was sent for those indicators.</p>
      )}
      {Array.isArray(report.caveats) && report.caveats.length > 0 && (
        <ul className="privacy-caveats">{report.caveats.map((item, i) => <li key={i}>{item}</li>)}</ul>
      )}
    </section>
  );
}

export default PrivacyDataPanel;
