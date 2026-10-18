import React, { useState } from 'react';

export function ContentAnalysis({ aiAnalysis = {}, email = {} }) {
  const [viewMode, setViewMode] = useState('summary'); // 'summary' | 'body_text' | 'body_html'
  const content = aiAnalysis.content_classification || {};

  const {
    content_verdict = 'N/A',
    confidence = 0,
    attack_type = 'N/A',
    categories = [],
    reasons = [],
    suspicious_indicators = [],
  } = content;

  let verdictClass = 'neutral';
  if (content_verdict.includes('Malicious') || content_verdict.includes('Phish')) {
    verdictClass = 'danger';
  } else if (content_verdict.includes('Suspicious')) {
    verdictClass = 'caution';
  } else if (
    content_verdict.includes('Clean') ||
    content_verdict.includes('Safe') ||
    content_verdict.includes('Legitimate')
  ) {
    verdictClass = 'safe';
  }

  const finalAssessment = aiAnalysis.final_assessment || {};
  const providerName = content.provider === 'gemini' ? (content.model || finalAssessment.model || 'Gemini') : (content.provider === 'xgboost_triage' ? 'XGBoost Triage' : 'Deterministic Fallback');

  return (
    <div className="forensic-panel">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">AI Content & Behavioral Classification</span>
          <span className="panel-subtitle">Stage G Linguistic & Intent Extraction ({providerName})</span>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            className={`btn-ghost ${viewMode === 'summary' ? 'active' : ''}`}
            onClick={() => setViewMode('summary')}
          >
            Forensic Findings
          </button>
          <button
            type="button"
            className={`btn-ghost ${viewMode === 'body_text' ? 'active' : ''}`}
            onClick={() => setViewMode('body_text')}
          >
            Raw Body Text
          </button>
          {email.body_html && (
            <button
              type="button"
              className={`btn-ghost ${viewMode === 'body_html' ? 'active' : ''}`}
              onClick={() => setViewMode('body_html')}
            >
              Sanitized HTML
            </button>
          )}
        </div>
      </div>

      {viewMode === 'summary' && (
        <div>
          {/* Classification Banner Strip */}
          <div className="metadata-grid" style={{ marginBottom: '16px' }}>
            <div className="meta-field">
              <div className="meta-field-label">CONTENT CLASSIFICATION</div>
              <div style={{ marginTop: '4px' }}>
                <span className={`status-pill ${verdictClass}`}>{content_verdict}</span>
              </div>
            </div>
            <div className="meta-field">
              <div className="meta-field-label">ATTACK VECTOR / TYPE</div>
              <div className="meta-field-value" style={{ fontWeight: 600, color: 'var(--accent-amber)' }}>
                {attack_type}
              </div>
            </div>
            <div className="meta-field">
              <div className="meta-field-label">AI CONFIDENCE INDEX</div>
              <div className="meta-field-value mono-val">
                {Math.round((confidence || 0) * 100)}% Match
              </div>
            </div>
            <div className="meta-field">
              <div className="meta-field-label">INTENT CATEGORIES</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                {categories.length > 0 ? (
                  categories.map((c, i) => (
                    <span key={i} className="rail-item-badge">
                      {c.name} ({c.weight}%)
                    </span>
                  ))
                ) : (
                  <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)' }}>None classified</span>
                )}
              </div>
            </div>
          </div>

          {/* Reasons & Behavioral Indicators Grid */}
          <div className="grid-2-col">
            <div style={{ background: 'var(--bg-base)', border: '1px solid var(--border-hairline)', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
              <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 600, marginBottom: '8px' }}>
                EXPLAINABLE HEURISTIC REASONS ({reasons.length})
              </div>
              {reasons.length === 0 ? (
                <div style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)' }}>No explicit threat reasons flagged.</div>
              ) : (
                <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {reasons.map((r, idx) => (
                    <li key={idx} style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-primary)', display: 'flex', gap: '8px' }}>
                      <span style={{ color: 'var(--accent-amber)' }}>&bull;</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div style={{ background: 'var(--bg-base)', border: '1px solid var(--border-hairline)', borderRadius: 'var(--radius-xs)', padding: '14px' }}>
              <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--verdict-danger)', fontFamily: 'var(--font-mono)', fontWeight: 600, marginBottom: '8px' }}>
                SUSPICIOUS LINGUISTIC INDICATORS ({suspicious_indicators.length})
              </div>
              {suspicious_indicators.length === 0 ? (
                <div style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)' }}>No behavioral anomalies detected in body.</div>
              ) : (
                <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {suspicious_indicators.map((ind, idx) => (
                    <li key={idx} style={{ fontSize: 'var(--fs-xs)', color: '#F8B4B4', display: 'flex', gap: '8px' }}>
                      <span style={{ color: 'var(--verdict-danger)' }}>&times;</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}

      {viewMode === 'body_text' && (
        <pre
          className="mono-val"
          style={{
            background: 'var(--bg-base)',
            padding: '16px',
            border: '1px solid var(--border-hairline)',
            borderRadius: 'var(--radius-xs)',
            whiteSpace: 'pre-wrap',
            maxHeight: '380px',
            overflowY: 'auto',
            fontSize: 'var(--fs-xs)',
            color: 'var(--text-primary)',
          }}
        >
          {email.body_text || 'No plain text body content extracted from message.'}
        </pre>
      )}

      {viewMode === 'body_html' && (
        <div>
          {/* Analyst Security Warning Banner */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '10px 14px',
              backgroundColor: 'rgba(217, 83, 79, 0.15)',
              border: '1px solid rgba(217, 83, 79, 0.4)',
              borderBottom: 'none',
              borderRadius: 'var(--radius-xs) var(--radius-xs) 0 0',
              color: '#F87171',
              fontSize: 'var(--fs-xs)',
              fontFamily: 'var(--font-mono)',
              fontWeight: 600,
            }}
          >
            <span style={{ fontSize: '15px' }}>⚠️</span>
            <span>
              CAUTION: Sandboxed preview — do not click links or enter credentials. Visual lure may simulate trusted corporate or banking login interfaces.
            </span>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '8px 12px',
              backgroundColor: 'var(--bg-surface-elevated)',
              borderTop: '1px solid var(--border-hairline)',
              borderLeft: '1px solid var(--border-hairline)',
              borderRight: '1px solid var(--border-hairline)',
              fontSize: 'var(--fs-micro)',
              fontFamily: 'var(--font-mono)',
              color: 'var(--text-secondary)',
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#10B981' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#10B981' }} />
              SANDBOXED IFRAME ISOLATION &bull; SCRIPT EXECUTION &amp; FORM SUBMISSION BLOCKED
            </span>
            <span>sandbox="allow-same-origin"</span>
          </div>

          {/* 
            SECURITY CRITICAL:
            NEVER add "allow-scripts" to this element.
            Combining "allow-scripts" with "allow-same-origin" completely defeats
            the sandbox by allowing the framed document to escape and execute code 
            directly in the parent origin context.
          */}
          <iframe
            title="Sandboxed Email HTML Preview"
            sandbox="allow-same-origin"
            srcDoc={email.body_html}
            style={{
              width: '100%',
              height: '380px',
              border: '1px solid var(--border-hairline)',
              borderRadius: '0 0 var(--radius-xs) var(--radius-xs)',
              backgroundColor: '#FFFFFF',
              display: 'block',
            }}
          />
        </div>
      )}
    </div>
  );
}

export default ContentAnalysis;
