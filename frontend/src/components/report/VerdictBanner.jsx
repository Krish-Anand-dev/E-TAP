import React from 'react';
import RiskGauge from './RiskGauge';

export function VerdictBanner({ verdict = 'UNKNOWN', riskScore = 0, confidence = 0, explanation = '', triage = null }) {
  let statusClass = 'safe';
  if (riskScore >= 70 || verdict.includes('HIGH') || verdict.includes('PHISH') || verdict.includes('MALICIOUS')) {
    statusClass = 'danger';
  } else if (riskScore >= 40 || verdict.includes('SUSPICIOUS')) {
    statusClass = 'caution';
  }

  const confidencePct = Math.round((confidence || 0) * 100);

  return (
    <div className="verdict-banner-container">
      <div className={`verdict-accent-strip ${statusClass}`} />
      <div className="verdict-main-content">
        <div className="verdict-text-group">
          <div className="verdict-classification-tag" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span>FORENSIC VERDICT &bull; CONFIDENCE: {confidencePct}% &bull; {triage?.gemini_skipped ? "STAGE C' EVALUATION" : "STAGE G EVALUATION"}</span>
            {triage?.gemini_skipped && (
              <span
                style={{
                  backgroundColor: 'rgba(16, 185, 129, 0.18)',
                  color: '#10B981',
                  border: '1px solid rgba(16, 185, 129, 0.4)',
                  padding: '2px 8px',
                  borderRadius: '12px',
                  fontWeight: 600,
                  fontSize: '10px',
                  letterSpacing: '0.04em',
                }}
              >
                ⚡ Fast-triaged — Gemini skipped
              </span>
            )}
          </div>
          <h2 className={`verdict-headline ${statusClass}`}>{verdict}</h2>
          <p className="verdict-summary-p">
            {explanation || 'Forensic analysis completed across header hygiene, attachment decomposition, threat reputation feeds, and behavioral AI synthesis.'}
          </p>
        </div>

        <RiskGauge score={riskScore} verdict={verdict} />
      </div>
    </div>
  );
}

export default VerdictBanner;
