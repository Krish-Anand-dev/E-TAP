import React from 'react';

export function HeaderAnalysis({ headers = {} }) {
  const {
    sender_email = 'N/A',
    display_name = 'N/A',
    reply_to = 'N/A',
    spf = 'none',
    dkim = 'none',
    dmarc = 'none',
    available = true,
    unavailable_reason = null,
    originating_ip = 'N/A',
    received_chain = [],
    red_flags = [],
  } = headers;

  const renderStatusLight = (proto, value) => {
    const v = String(value || 'none').toLowerCase();
    let statusClass = 'neutral';
    let ledColor = 'var(--text-muted)';
    let statusLabel = 'NONE';

    if (v === 'not_available') {
      statusLabel = 'NOT AVAILABLE';
    } else if (v === 'pass') {
      statusClass = 'safe';
      ledColor = 'var(--verdict-safe)';
      statusLabel = 'PASS';
    } else if (v === 'fail') {
      statusClass = 'danger';
      ledColor = 'var(--verdict-danger)';
      statusLabel = 'FAIL';
    } else if (v === 'softfail' || v === 'neutral') {
      statusClass = 'caution';
      ledColor = 'var(--verdict-caution)';
      statusLabel = v.toUpperCase();
    }

    return (
      <div className="auth-status-box">
        <span className="auth-proto-title">{proto}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              backgroundColor: ledColor,
              boxShadow: `0 0 6px ${ledColor}`,
              display: 'inline-block',
            }}
          />
          <span
            className="mono-val"
            style={{
              fontSize: 'var(--fs-micro)',
              fontWeight: 700,
              letterSpacing: '0.04em',
              color: statusClass === 'safe' ? 'var(--verdict-safe)' : statusClass === 'danger' ? 'var(--verdict-danger)' : statusClass === 'caution' ? 'var(--verdict-caution)' : 'var(--text-muted)',
            }}
          >
            {statusLabel}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div className="forensic-panel">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Header Authentication & Routing</span>
          <span className="panel-subtitle">Stage A & Stage B Hygiene Analysis</span>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <span className="rail-item-badge">RFC 5322 / RFC 822</span>
        </div>
      </div>

      {available === false && (
        <div className="headers-unavailable-note">
          <strong>Headers not available.</strong>{' '}
          {unavailable_reason || 'The original message headers were not provided, so SPF, DKIM, DMARC and routing were not evaluated.'}{' '}
          Upload the original .eml/.msg file for full header forensics.
        </div>
      )}

      {/* Protocol Authentication Instrument Lights */}
      <div className="auth-status-grid">
        {renderStatusLight('SPF', spf)}
        {renderStatusLight('DKIM', dkim)}
        {renderStatusLight('DMARC', dmarc)}
      </div>

      {/* Originating IP & Addressing Table */}
      <div className="metadata-grid" style={{ marginBottom: '16px' }}>
        <div className="meta-field">
          <div className="meta-field-label">FROM (RFC 5322)</div>
          <div className="meta-field-value mono-val">
            {display_name ? `"${display_name}" ` : ''}&lt;{sender_email || 'N/A'}&gt;
          </div>
        </div>
        <div className="meta-field">
          <div className="meta-field-label">REPLY-TO</div>
          <div className="meta-field-value mono-val">
            {reply_to ? `<${reply_to}>` : '(Aligned with From address)'}
          </div>
        </div>
        <div className="meta-field">
          <div className="meta-field-label">ORIGINATING IP</div>
          <div className="meta-field-value mono-val">
            {available === false ? 'Not available' : (originating_ip || 'None detected (Internal/Relay)')}
          </div>
        </div>
        <div className="meta-field">
          <div className="meta-field-label">MTA HOPS DETECTED</div>
          <div className="meta-field-value mono-val">
            {available === false ? 'Not available' : `${received_chain.length} Relay Nodes`}
          </div>
        </div>
      </div>

      {/* Red Flags Alert */}
      {red_flags && red_flags.length > 0 && (
        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--verdict-danger)', fontFamily: 'var(--font-mono)', fontWeight: 600, marginBottom: '6px' }}>
            ANOMALIES & RED FLAGS IDENTIFIED ({red_flags.length})
          </div>
          <ul className="red-flags-list">
            {red_flags.map((flag, idx) => (
              <li key={idx} className="red-flag-item">
                {flag}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Received Chain Hop List */}
      <div>
        <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 600, marginBottom: '6px' }}>
          RECEIVED HEADERS ROUTING CHAIN
        </div>
        {received_chain.length === 0 ? (
          <div style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', padding: '8px' }}>
            {available === false ? 'Not available — original headers were not provided.' : 'No intermediate received hops logged.'}
          </div>
        ) : (
          <ul className="hop-list">
            {received_chain.map((hop, index) => (
              <li key={index} className="hop-item">
                <span className="hop-index">HOP 0{index + 1}</span>
                <span>{hop}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default HeaderAnalysis;
