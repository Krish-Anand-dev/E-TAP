import React, { useState, useMemo } from 'react';

export function IocTable({ iocs = {}, threatIntel = {}, historicalCorrelation = null }) {
  const [activeFilter, setActiveFilter] = useState('all');
  const [copiedVal, setCopiedVal] = useState(null);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedVal(text);
    setTimeout(() => setCopiedVal(null), 1800);
  };

  const histMap = useMemo(() => {
    const map = {};
    (historicalCorrelation?.indicators || []).forEach((ind) => {
      map[ind.value] = ind;
    });
    return map;
  }, [historicalCorrelation]);

  const rows = useMemo(() => {
    const list = [];

    // IPs
    (iocs.ips || []).forEach((ip) => {
      const rep = threatIntel.ip_reputation?.[ip];
      let status = 'neutral';
      let statusText = 'UNCHECKED';
      let details = 'No threat reports';

      if (rep) {
        if (rep.malicious === true) {
          status = 'danger';
          statusText = 'MALICIOUS';
          details = `Reports: ${rep.reports || 'Flagged'} | Country: ${rep.country || 'N/A'}`;
        } else if (rep.malicious === false) {
          status = 'safe';
          statusText = 'CLEAN';
          details = `0 reports | Country: ${rep.country || 'N/A'}`;
        } else if (rep.status === 'not_checked') {
          status = 'neutral';
          statusText = 'OFFLINE / NOT CHECKED';
          details = rep.reason || 'Live intel query disabled';
        }
      }

      list.push({
        type: 'IP',
        value: ip,
        status,
        statusText,
        details,
      });
    });

    // Domains
    (iocs.domains || []).forEach((domain) => {
      const info = threatIntel.domain_info?.[domain];
      let status = 'neutral';
      let statusText = 'UNRATED';
      let details = 'Domain record noted';

      if (info) {
        const hasValidAge = typeof info.age_days === 'number' && !isNaN(info.age_days);
        if (info.malicious === true) {
          status = 'danger';
          statusText = 'MALICIOUS';
          details = info.reason || 'Blacklisted domain';
        } else if (hasValidAge && info.age_days < 30) {
          status = 'caution';
          statusText = 'NEWLY REGISTERED';
          details = `Age: ${info.age_days} days | Registrar: ${info.registrar || 'N/A'}`;
        } else if (hasValidAge) {
          status = 'safe';
          statusText = 'ESTABLISHED';
          details = `Age: ${info.age_days} days | Registrar: ${info.registrar || 'N/A'}`;
        } else if (info.status === 'not_checked') {
          status = 'neutral';
          statusText = 'OFFLINE / NOT CHECKED';
          details = info.reason || 'Live WHOIS query disabled';
        } else if (info.error) {
          status = 'neutral';
          statusText = 'WHOIS UNRESOLVED';
          details = info.error;
        } else if (info.registrar) {
          status = 'neutral';
          statusText = 'REGISTERED';
          details = `Age: Unknown | Registrar: ${info.registrar}`;
        } else {
          status = 'neutral';
          statusText = 'UNRATED';
          details = 'Age: Unknown | Domain record noted';
        }
      }

      list.push({
        type: 'DOMAIN',
        value: domain,
        status,
        statusText,
        details,
      });
    });

    // URLs
    (iocs.urls || []).forEach((url) => {
      const rep = threatIntel.url_reputation?.[url];
      const meta = iocs.ioc_metadata?.[url];
      const isQr = meta?.source === 'qr_code';
      let status = 'neutral';
      let statusText = 'UNCHECKED';
      let details = isQr ? `[CONCEALED IN QR: ${meta.attachment || 'attachment'}] ` : 'URL observed in payload';

      if (rep) {
        if (rep.malicious === true) {
          status = 'danger';
          statusText = 'MALICIOUS';
          const count = rep.malicious_engine_count ?? rep.positives;
          const total = rep.total_engines;
          const repMsg = count != null ? `Flagged by ${count}${total ? `/${total}` : ''} security engines (VirusTotal)` : 'Flagged by security engines';
          details = isQr ? `[CONCEALED IN QR: ${meta.attachment || 'attachment'}] ${repMsg}` : repMsg;
        } else if (rep.malicious === false) {
          status = 'safe';
          statusText = 'CLEAN';
          const cleanMsg = rep.total_engines ? `0/${rep.total_engines} vendor detections (VirusTotal)` : '0 vendor detections (Clean)';
          details = isQr ? `[CONCEALED IN QR: ${meta.attachment || 'attachment'}] ${cleanMsg}` : cleanMsg;
        } else if (rep.status === 'rate_limited_internal' || rep.error?.toLowerCase().includes('rate limit') || rep.error?.toLowerCase().includes('quota')) {
          status = 'caution';
          statusText = 'THROTTLED (VT 4/MIN)';
          details = rep.error || 'VirusTotal free-tier rate limit active — query throttled to preserve quota';
        } else if (rep.status === 'not previously scanned by VirusTotal' || rep.status === 'not_found') {
          status = 'neutral';
          statusText = 'NOT IN VT DATABASE';
          details = 'URL not previously submitted to or indexed by VirusTotal';
        } else if (rep.status === 'not_checked') {
          status = 'neutral';
          statusText = 'OFFLINE / NOT CHECKED';
          details = rep.reason || 'Live intel query disabled';
        } else if (rep.error) {
          status = 'caution';
          statusText = 'LOOKUP FAILED';
          details = rep.error;
        }
      }

      list.push({
        type: isQr ? 'QR-URL' : 'URL',
        value: url,
        status,
        statusText,
        details,
        isQr,
        attachmentName: meta?.attachment,
      });
    });

    // Hashes
    (iocs.hashes || []).forEach((hash) => {
      const rep = threatIntel.hash_reputation?.[hash];
      let status = 'neutral';
      let statusText = 'DIGEST';
      let details = 'SHA-256 Payload Hash';

      if (rep) {
        if (rep.malicious === true) {
          status = 'danger';
          statusText = 'MALICIOUS';
          const count = rep.malicious_engine_count ?? rep.positives;
          const total = rep.total_engines;
          details = count != null ? `Flagged by ${count}${total ? `/${total}` : ''} AV engines (VirusTotal)` : 'Flagged by AV engines';
        } else if (rep.malicious === false) {
          status = 'safe';
          statusText = 'CLEAN';
          details = rep.total_engines ? `0/${rep.total_engines} AV detections (VirusTotal)` : '0 AV detections (Clean)';
        } else if (rep.status === 'rate_limited_internal' || rep.error?.toLowerCase().includes('rate limit') || rep.error?.toLowerCase().includes('quota')) {
          status = 'caution';
          statusText = 'THROTTLED (VT 4/MIN)';
          details = rep.error || 'VirusTotal free-tier rate limit active — query throttled to preserve quota';
        } else if (rep.status === 'not previously scanned by VirusTotal' || rep.status === 'not_found') {
          status = 'neutral';
          statusText = 'NOT IN VT DATABASE';
          details = 'Hash not previously seen in VirusTotal dataset';
        } else if (rep.status === 'not_checked') {
          status = 'neutral';
          statusText = 'OFFLINE / NOT CHECKED';
          details = rep.reason || 'Live intel query disabled';
        } else if (rep.error) {
          status = 'caution';
          statusText = 'LOOKUP FAILED';
          details = rep.error;
        }
      }

      list.push({
        type: 'HASH',
        value: hash,
        status,
        statusText,
        details,
      });
    });

    return list;
  }, [iocs, threatIntel]);

  const filteredRows = useMemo(() => {
    if (activeFilter === 'all') return rows;
    return rows.filter((r) => r.type.toLowerCase().includes(activeFilter));
  }, [rows, activeFilter]);

  return (
    <div className="forensic-panel">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Extracted Indicators of Compromise (IOCs)</span>
          <span className="panel-subtitle">Stage B Threat Intel Correlation &bull; Database Recurrence</span>
        </div>
        <div style={{ display: 'flex', gap: '6px' }}>
          {['all', 'ip', 'domain', 'url', 'hash'].map((tab) => (
            <button
              key={tab}
              type="button"
              className={`btn-ghost ${activeFilter === tab ? 'active' : ''}`}
              onClick={() => setActiveFilter(tab)}
              style={{ textTransform: 'uppercase', fontSize: 'var(--fs-micro)' }}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {filteredRows.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          No IOCs found for the selected category.
        </div>
      ) : (
        <div className="forensic-table-container">
          <table className="forensic-table">
            <thead>
              <tr>
                <th>TYPE</th>
                <th>INDICATOR VALUE</th>
                <th>REPUTATION STATUS</th>
                <th>DB RECURRENCE</th>
                <th>OSINT / INTEL DETAILS</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row, idx) => {
                const hist = histMap[row.value];
                return (
                  <tr key={idx} className={row.status === 'danger' ? 'row-suspicious' : ''}>
                    <td>
                      <span
                        className="rail-item-badge"
                        style={row.isQr ? { backgroundColor: 'rgba(239, 68, 68, 0.16)', color: '#EF4444', border: '1px solid rgba(239, 68, 68, 0.4)' } : undefined}
                      >
                        {row.type}
                      </span>
                    </td>
                    <td className="mono-val" style={{ maxWidth: '380px', wordBreak: 'break-all' }}>
                      {row.value}
                    </td>
                    <td>
                      <span className={`status-pill ${row.status}`}>
                        {row.statusText}
                      </span>
                    </td>
                    <td>
                      {hist ? (
                        hist.all_time > 0 ? (
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: 'var(--fs-micro)',
                              padding: '2px 7px',
                              borderRadius: 'var(--radius-xs)',
                              backgroundColor: hist.this_week > 0 ? 'rgba(239, 68, 68, 0.16)' : 'rgba(232, 162, 61, 0.16)',
                              color: hist.this_week > 0 ? '#EF4444' : '#E8A23D',
                              border: '1px solid currentColor',
                              fontWeight: 600,
                              whiteSpace: 'nowrap',
                            }}
                            title={`Seen ${hist.this_week}x this week, ${hist.this_month}x this month, ${hist.all_time} total`}
                          >
                            {hist.this_week > 0 ? `${hist.this_week}x THIS WEEK` : `${hist.this_month}x THIS MONTH`}
                          </span>
                        ) : (
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: 'var(--fs-micro)',
                              padding: '2px 7px',
                              borderRadius: 'var(--radius-xs)',
                              backgroundColor: 'rgba(16, 185, 129, 0.12)',
                              color: '#10B981',
                              border: '1px solid rgba(16, 185, 129, 0.3)',
                              fontWeight: 600,
                              whiteSpace: 'nowrap',
                            }}
                          >
                            FIRST SEEN (NEW)
                          </span>
                        )
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--fs-micro)', fontFamily: 'var(--font-mono)' }}>
                          —
                        </span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{row.details}</td>
                    <td>
                      <button
                        type="button"
                        className="btn-copy-mono"
                        onClick={() => copyToClipboard(row.value)}
                      >
                        {copiedVal === row.value ? 'COPIED' : 'COPY'}
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

export default IocTable;
