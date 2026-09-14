import React, { useEffect, useState } from 'react';

/**
 * RiskGauge: Single deliberate 0-100 arc fill on load.
 * Semantics: Safe (<40: #4CAF7D), Caution (40-70: #E8A23D), Danger (>70: #D9534F)
 */
export function RiskGauge({ score = 0, verdict = '' }) {
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

  let bandClass = 'safe';
  if (score >= 70 || verdict.includes('HIGH') || verdict.includes('PHISH')) {
    bandClass = 'danger';
  } else if (score >= 40 || verdict.includes('SUSPICIOUS')) {
    bandClass = 'caution';
  }

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
