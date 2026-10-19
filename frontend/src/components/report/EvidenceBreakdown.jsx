import React from 'react';
import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip } from 'recharts';

const NAMES = {
  content_classification: 'Message wording',
  header_forensics: 'Sender & headers',
  attachment_forensics: 'Attachments',
  ioc_extraction: 'Links & indicators',
  threat_intelligence: 'Reputation',
  correlation: 'Past emails',
};

const nameOf = (src = '') => NAMES[src] || src.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
const toneOf = (score) => (score >= 65 ? 'danger' : score >= 40 ? 'caution' : 'safe');

/** Multi-vector analysis: how each part of the analysis scored the email (0-100). */
export function EvidenceBreakdown({ evidenceAssessments = [] }) {
  const rows = evidenceAssessments.map((item) => ({
    name: nameOf(item.source),
    score: Math.max(0, Math.min(100, Number(item.risk_score) || 0)),
    summary: item.summary || '',
  }));
  const highest = rows.reduce((best, r) => (r.score > (best?.score ?? -1) ? r : best), null);

  return (
    <div className="v2-card vector-card">
      <div className="v2-card-head">
        <div><h3>Multi-vector analysis</h3><p>Risk from each angle of the investigation, 0 to 100</p></div>
        {highest && <span className={`verdict-chip ${toneOf(highest.score)}`}>Highest: {highest.name}</span>}
      </div>
      {rows.length === 0 ? (
        <p className="v2-empty-line">This email passed metadata screening, so the per-angle breakdown was not needed.</p>
      ) : (
        <>
          <div className="vector-radar">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={rows} outerRadius="72%">
                <PolarGrid stroke="#e2e1d9" />
                <PolarAngleAxis dataKey="name" tick={{ fontSize: 11, fill: '#3d4559', fontWeight: 600 }} />
                <Tooltip contentStyle={{ background: '#fffef7', border: '1px solid #e2e1d9', borderRadius: 12 }} formatter={(v) => [`${v}/100`, 'Risk']} />
                <Radar dataKey="score" stroke="#d93a45" fill="#d93a45" fillOpacity={0.22} strokeWidth={2} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
          <ul className="vector-list">
            {rows.map((r) => (
              <li key={r.name} className={`tone-${toneOf(r.score)}`}>
                <div className="vector-row"><strong>{r.name}</strong><b>{r.score}</b></div>
                <div className="vector-bar"><i style={{ width: `${r.score}%` }} /></div>
                {r.summary && <p>{r.summary}</p>}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

export default EvidenceBreakdown;
