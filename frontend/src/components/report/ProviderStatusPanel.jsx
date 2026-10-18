import React from 'react';
import { visibleProviders } from '../../utils/geo.js';

const LABELS = {
  available: 'Available',
  fallback_model_used: 'Fallback model used',
  partial: 'Partial coverage',
  unavailable: 'Unavailable',
  not_configured: 'Not configured',
  timeout: 'Timed out',
  rate_limited: 'Rate limited',
  disabled: 'Disabled by configuration',
  not_needed: 'Not needed for this email',
  skipped_by_triage: 'Skipped by triage',
  skipped_for_privacy: 'Skipped for privacy',
  skipped_by_policy: 'Skipped by policy',
  unknown: 'Unknown',
};

function tone(status) {
  if (['available', 'fallback_model_used'].includes(status)) return 'ok';
  if (['unavailable', 'not_configured', 'timeout', 'rate_limited'].includes(status)) return 'danger';
  if (['partial', 'skipped_for_privacy', 'skipped_by_policy'].includes(status)) return 'caution';
  return 'neutral';
}

function ProviderRow({ id, provider }) {
  const status = provider?.status || 'unknown';
  const counts = [];
  if (Number.isFinite(provider?.succeeded) && provider.succeeded > 0) counts.push(`${provider.succeeded} answered`);
  if (Number.isFinite(provider?.failed) && provider.failed > 0) counts.push(`${provider.failed} failed`);
  if (Number.isFinite(provider?.not_configured) && provider.not_configured > 0) counts.push(`${provider.not_configured} not configured`);
  if (Number.isFinite(provider?.skipped) && provider.skipped > 0) counts.push(`${provider.skipped} skipped`);
  if (Number.isFinite(provider?.timed_out) && provider.timed_out > 0) counts.push(`${provider.timed_out} timed out`);

  return (
    <div className="provider-status-row" key={id}>
      <div className="provider-status-row-head">
        <strong>{provider?.name || id}</strong>
        <span className={`provider-status-badge provider-status-${tone(status)}`}>
          {LABELS[status] || status.replaceAll('_', ' ')}
        </span>
      </div>
      <p>{provider?.summary || 'The backend did not provide details for this provider.'}</p>
      {provider?.model_used && <div className="provider-status-meta">Model used: <code>{provider.model_used}</code></div>}
      {counts.length > 0 && <div className="provider-status-meta">{counts.join(' · ')}</div>}
    </div>
  );
}

export function ProviderStatusPanel({ status }) {
  if (!status) {
    return (
      <section className="forensic-panel provider-status-panel" aria-label="Provider status">
        <div className="forensic-panel-header"><div className="panel-title-group"><span className="panel-title">Provider Status</span><span className="panel-subtitle">B11 · Analysis coverage</span></div></div>
        <p className="provider-status-muted">This stored report predates provider-status reporting. Re-analyze the artifact to capture per-provider health.</p>
      </section>
    );
  }

  const providers = status.providers || {};
  return (
    <section className="forensic-panel provider-status-panel" aria-label="Provider status">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Provider Status & Analysis Coverage</span>
          <span className="panel-subtitle">Provider health is separate from the email threat verdict.</span>
        </div>
        <span className={`provider-status-badge provider-status-${status.coverage_status === 'complete' ? 'ok' : 'caution'}`}>
          {status.coverage_status === 'complete' ? 'Coverage complete' : 'Partial coverage'}
        </span>
      </div>
      <p className="provider-status-summary">{status.summary || 'Analysis status available.'}</p>
      <div className="provider-status-grid">
        {visibleProviders(providers).map(([id, provider]) => <ProviderRow key={id} id={id} provider={provider} />)}
      </div>
      <p className="provider-status-footnote">Unavailable or skipped checks mean evidence is missing. They must not be interpreted as a clean result.</p>
    </section>
  );
}

export default ProviderStatusPanel;
