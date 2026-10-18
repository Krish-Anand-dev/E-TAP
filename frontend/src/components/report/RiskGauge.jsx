import React, { useEffect, useState } from 'react';
import { bandFor } from '../../utils/verdict';

/**
 * RiskGauge: Single deliberate 0-100 arc fill on load.
 * Band comes from the backend's `verdict_band` (see backend/verdicts.py):
 * safe <40, caution 40-64, danger >=65.
 */
export function RiskGauge({ score = 0, verdict = '', band = null }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Single deliberate fill animation on load
    const timeout = setTimeout(() => {
      setAnimatedScore(Math.min(100, Math.max(0, score)));
    }, 100);
    return () => clearTimeout(timeout);
  }, [score]);

  const radius = 45;
  const circumference = Math.PI * radius; // Half-circle arc
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  const bandClass = bandFor({ verdictBand: band, verdict, riskScore: score });

  return (
    <div className="risk-gauge-container">
      <svg width="120" height="75" viewBox="0 0 120 75" className="gauge-svg">
        {/* Background track */}
        <path
          d="M 15 65 A 45 45 0 0 1 105 65"
          className="gauge-track"
        />
        {/* Filled score arc */}
        <path
          d="M 15 65 A 45 45 0 0 1 105 65"
          className={`gauge-fill ${bandClass}`}
          style={{
            strokeDasharray: circumference,
            strokeDashoffset,
          }}
        />
        {/* Score display */}
        <text x="60" y="52" className="gauge-score-text">
          {score}
        </text>
        <text x="60" y="66" className="gauge-label-text">
          SCORE / 100
        </text>
      </svg>
    </div>
  );
}

export default RiskGauge;
