import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

export function EvidenceBreakdown({ evidenceAssessments = [] }) {
  const formatSourceName = (src = '') => {
    const map = {
      content_classification: 'Content AI Intent',
      header_forensics: 'Header Forensics',
      attachment_forensics: 'Attachment Static',
      ioc_extraction: 'IOC Extraction',
      threat_intelligence: 'Threat Intelligence',
      correlation: 'Campaign Correlation',
    };
    return map[src] || src.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  };

  const chartData = evidenceAssessments.map((item) => ({
    name: formatSourceName(item.source),
    rawSource: item.source,
    score: item.risk_score || 0,
    summary: item.summary || '',
    evidence: item.evidence || [],
  }));

  const getBarColor = (score) => {
    if (score >= 70) return '#D9534F'; // danger
    if (score >= 40) return '#E8A23D'; // caution
    return '#4CAF7D'; // safe
  };

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div
          style={{
            backgroundColor: '#1B1F2A',
            border: '1px solid #2A2F3D',
            padding: '8px 12px',
            borderRadius: '2px',
            fontSize: '12px',
            fontFamily: 'Inter, sans-serif',
          }}
        >
          <div style={{ fontWeight: 600, color: '#E8EAF0' }}>{data.name}</div>
          <div style={{ color: getBarColor(data.score), fontFamily: 'JetBrains Mono', marginTop: '2px' }}>
            Risk Score: {data.score} / 100
          </div>
          <div style={{ color: '#8B92A5', fontSize: '11px', marginTop: '4px', maxWidth: '240px' }}>
            {data.summary}
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="forensic-panel">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Multi-Vector Evidence Risk Breakdown</span>
          <span className="panel-subtitle">Weighted Severity Across 6 Detection Vectors</span>
        </div>
        <span className="rail-item-badge">Explainability Vector</span>
      </div>

      {chartData.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          No granular vector assessments recorded for this dossier.
        </div>
      ) : (
        <div>
          <div style={{ width: '100%', height: 220, marginTop: '8px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                layout="vertical"
                data={chartData}
                margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
              >
                <XAxis
                  type="number"
                  domain={[0, 100]}
                  stroke="#5E667E"
                  tick={{ fontSize: 11, fill: '#8B92A5', fontFamily: 'JetBrains Mono' }}
                />
                <YAxis
                  dataKey="name"
                  type="category"
                  stroke="#5E667E"
                  tick={{ fontSize: 11, fill: '#E8EAF0' }}
                  width={140}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="score" barSize={14} radius={[0, 2, 2, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={getBarColor(entry.score)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Evidence Details Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '10px', marginTop: '16px' }}>
            {evidenceAssessments.map((item, idx) => (
              <div
                key={idx}
                style={{
                  backgroundColor: 'var(--bg-base)',
                  border: '1px solid var(--border-hairline)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '10px 12px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontSize: 'var(--fs-xs)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {item.source}
                  </span>
                  <span
                    className="mono-val"
                    style={{
                      fontSize: 'var(--fs-micro)',
                      fontWeight: 600,
                      color: getBarColor(item.risk_score),
                    }}
                  >
                    {item.risk_score}/100
                  </span>
                </div>
                <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {item.summary}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default EvidenceBreakdown;
