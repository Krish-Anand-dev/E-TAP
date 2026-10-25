import React, { useState } from 'react';

export function AttachmentTable({ attachments = [] }) {
  const [copiedHash, setCopiedHash] = useState(null);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 1800);
  };

  return (
    <div className="forensic-panel">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Attachment Forensics & Magic Byte Analysis</span>
          <span className="panel-subtitle">Stage D Static Decomposition</span>
        </div>
        <span className="rail-item-badge">{attachments.length} Payloads</span>
      </div>

      {attachments.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          No file attachments encapsulated in this email message.
        </div>
      ) : (
        <div className="forensic-table-container">
          <table className="forensic-table">
            <thead>
              <tr>
                <th>FILENAME</th>
                <th>DECLARED MIME</th>
                <th>ACTUAL MIME (LIBMAGIC)</th>
                <th>MISMATCH</th>
                <th>MACROS</th>
                <th>THREAT STATUS</th>
                <th>SHA-256 DIGEST</th>
              </tr>
            </thead>
            <tbody>
              {attachments.map((att, idx) => {
                const isSuspicious = att.suspicious || att.type_mismatch || att.has_macro || (att.qr_urls && att.qr_urls.length > 0);
                const hasHiddenContent = Boolean((att.qr_urls && att.qr_urls.length > 0) || (att.ocr_text && att.ocr_text.trim().length > 0));
                const hasMacroBehavior = Boolean(
                  att.macro_behavior &&
                  (att.macro_behavior.autoexec_triggers?.length > 0 ||
                   att.macro_behavior.suspicious_actions?.length > 0 ||
                   att.macro_behavior.referenced_iocs?.length > 0 ||
                   att.macro_behavior.flags?.length > 0)
                );

                return (
                  <React.Fragment key={idx}>
                    <tr className={isSuspicious ? 'row-suspicious' : ''}>
                      <td className="mono-val" style={{ fontWeight: 600 }}>{att.filename}</td>
                      <td className="mono-val">{att.declared_type || 'unknown'}</td>
                      <td className="mono-val">
                        <span style={{ color: att.type_mismatch ? 'var(--verdict-danger)' : 'inherit' }}>
                          {att.actual_type || 'unknown'}
                        </span>
                      </td>
                      <td>
                        {att.type_mismatch ? (
                          <span className="status-pill danger">MISMATCH</span>
                        ) : (
                          <span className="status-pill safe">VERIFIED</span>
                        )}
                      </td>
                      <td>
                        {att.has_macro ? (
                          <span className="status-pill danger">MACRO DETECTED</span>
                        ) : (
                          <span className="status-pill neutral">NONE</span>
                        )}
                      </td>
                      <td>
                        {hasHiddenContent ? (
                          <span className="status-pill danger">HIDDEN CONTENT</span>
                        ) : att.suspicious ? (
                          <span className="status-pill danger">SUSPICIOUS</span>
                        ) : (
                          <span className="status-pill safe">BENIGN</span>
                        )}
                      </td>
                      <td>
                        <span className="mono-val" style={{ fontSize: 'var(--fs-micro)' }}>
                          {att.sha256 ? `${att.sha256.substring(0, 16)}...` : 'N/A'}
                        </span>
                        {att.sha256 && (
                          <button
                            type="button"
                            className="btn-copy-mono"
                            onClick={() => copyToClipboard(att.sha256)}
                            title="Copy full SHA-256 hash"
                          >
                            {copiedHash === att.sha256 ? 'COPIED' : 'COPY'}
                          </button>
                        )}
                      </td>
                    </tr>
                    {hasHiddenContent && (
                      <tr className="row-hidden-content-detail">
                        <td colSpan={7} style={{ background: 'rgba(239, 68, 68, 0.05)', padding: '10px 16px', borderBottom: '1px solid var(--border-hairline)' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <span className="status-pill danger" style={{ fontSize: '10px' }}>HIDDEN IMAGE CONTENT DETECTED</span>
                              {att.qr_urls?.length > 0 && (
                                <span style={{ fontSize: '11px', color: 'var(--verdict-danger)', fontWeight: 600 }}>
                                  QR Code Payload: {att.qr_urls.length} link(s)
                                </span>
                              )}
                              {att.ocr_text && (
                                <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                                  OCR Text Extracted ({att.ocr_text.length} characters)
                                </span>
                              )}
                            </div>
                            {att.qr_urls?.length > 0 && (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Concealed QR URLs:</span>
                                {att.qr_urls.map((qUrl, qIdx) => (
                                  <div key={qIdx} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <span className="mono-val" style={{ color: '#F87171', fontSize: '11px' }}>{qUrl}</span>
                                    <button
                                      type="button"
                                      className="btn-copy-mono"
                                      onClick={() => copyToClipboard(qUrl)}
                                      title="Copy QR URL"
                                    >
                                      {copiedHash === qUrl ? 'COPIED' : 'COPY'}
                                    </button>
                                  </div>
                                ))}
                              </div>
                            )}
                            {att.ocr_text && (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>OCR Text Preview:</span>
                                <div className="mono-val" style={{ fontSize: '11px', background: 'rgba(0,0,0,0.3)', padding: '8px 12px', borderRadius: '4px', whiteSpace: 'pre-wrap', maxHeight: '120px', overflowY: 'auto' }}>
                                  {att.ocr_text}
                                </div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                    {/* Stage B2 Static Sandbox & Forensics Detail Row */}
                    {(hasMacroBehavior || (att.flags && att.flags.length > 0)) && (
                      <tr className="row-macro-sandbox-detail">
                        <td colSpan={7} style={{ background: 'rgba(239, 68, 68, 0.06)', padding: '12px 16px', borderBottom: '1px solid var(--border-hairline)' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                              <span className="status-pill danger" style={{ fontSize: '10px', fontWeight: 700 }}>
                                {hasMacroBehavior ? 'STATIC SANDBOX V2 — VBA DECOMPOSITION' : 'STAGE B2 — STATIC ATTACHMENT SANDBOX'}
                              </span>
                              {att.type_mismatch && (
                                <span style={{ fontSize: '11px', color: '#F87171', fontWeight: 600 }}>
                                  Type Spoofing Detected: {att.declared_type} → {att.actual_type}
                                </span>
                              )}
                              {att.macro_behavior?.autoexec_triggers?.length > 0 && (
                                <span style={{ fontSize: '11px', color: '#F87171', fontWeight: 600 }}>
                                  Auto-Exec Triggers: {att.macro_behavior.autoexec_triggers.join(', ')}
                                </span>
                              )}
                              {att.macro_behavior?.suspicious_actions?.length > 0 && (
                                <span style={{ fontSize: '11px', color: '#FBBF24', fontWeight: 600 }}>
                                  Suspicious APIs: {att.macro_behavior.suspicious_actions.join(', ')}
                                </span>
                              )}
                            </div>

                            {/* Referenced IOCs (from Macro decompilation) */}
                            {att.macro_behavior?.referenced_iocs?.length > 0 && (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                  Macro Referenced IOCs:
                                </span>
                                {att.macro_behavior.referenced_iocs.map((ioc, iocIdx) => (
                                  <span key={iocIdx} className="mono-val" style={{ color: '#FCA5A5', background: 'rgba(0,0,0,0.4)', padding: '2px 6px', borderRadius: '3px', fontSize: '11px' }}>
                                    {ioc}
                                  </span>
                                ))}
                              </div>
                            )}

                            {/* Forensic Sandbox Flags (Double extension, disguised PE, macro flags) */}
                            {att.flags?.length > 0 && (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '2px' }}>
                                <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                  Sandbox Analysis Flags & Behavioral Evidence:
                                </span>
                                {att.flags.map((flag, fIdx) => (
                                  <div key={fIdx} style={{ fontSize: '11px', color: '#E2E8F0', paddingLeft: '8px', borderLeft: '2px solid #EF4444', lineHeight: 1.4 }}>
                                    {flag}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default AttachmentTable;
