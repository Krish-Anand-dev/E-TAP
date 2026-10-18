import React from 'react';
import RiskGauge from './RiskGauge';
import { bandFor, displayLabel, provenanceChips } from '../../utils/verdict';

const CHIP_COLORS = {
  ok: { bg: 'rgba(16, 185, 129, 0.15)', fg: '#10B981', border: 'rgba(16, 185, 129, 0.4)' },
  caution: { bg: 'rgba(232, 162, 61, 0.16)', fg: '#E8A23D', border: 'rgba(232, 162, 61, 0.45)' },
  neutral: { bg: 'rgba(148, 163, 184, 0.14)', fg: 'var(--text-muted)', border: 'rgba(148, 163, 184, 0.35)' },
};

export function VerdictBanner({
  verdict = 'UNKNOWN',
  riskScore = 0,
  confidence = 0,
  confidenceLevel = null,
  explanation = '',
  triage = null,
  band = null,
  provenance = null,
  stageStatus = null,
}) {
  // Backend decides the band (verdict_band); local logic only covers old records.
  const statusClass = bandFor({ verdictBand: band, verdict, riskScore });
  const label = displayLabel(verdict, riskScore);
  const chips = provenanceChips(provenance, stageStatus);

  const confidencePct = Math.round((confidence || 0) * 100);

  return (
    <div className="verdict-banner-container">
      <div className={`verdict-accent-strip ${statusClass}`} />
      <div className="verdict-main-content">
        <div className="verdict-text-group">
          <div className="verdict-classification-tag" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span>FORENSIC VERDICT &bull; {confidenceLevel ? `EVIDENCE CONFIDENCE: ${String(confidenceLevel).toUpperCase()}` : `CONFIDENCE: ${confidencePct}%`} &bull; {triage?.gemini_skipped ? "STAGE C' EVALUATION" : 'STAGE G EVALUATION'}</span>
          </div>
          <h2 className={`verdict-headline ${statusClass}`}>{label}</h2>
          <p className="verdict-summary-p">
            {explanation || 'Forensic analysis completed across header hygiene, attachment decomposition, threat reputation feeds, and behavioral AI synthesis.'}
          </p>
          <div className="verdict-provenance" role="list" aria-label="How this verdict was produced">
            {chips.map((chip) => {
              const c = CHIP_COLORS[chip.tone] || CHIP_COLORS.neutral;
              return (
                <span
                  key={chip.key}
                  role="listitem"
                  className="verdict-provenance-chip"
                  style={{ backgroundColor: c.bg, color: c.fg, border: `1px solid ${c.border}` }}
                >
                  {chip.text}
                </span>
              );
            })}
          </div>
        </div>

        <RiskGauge score={riskScore} verdict={label} band={statusClass} />
      </div>
    </div>
  );
}

export default VerdictBanner;
