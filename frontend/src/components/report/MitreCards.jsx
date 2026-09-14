import React from 'react';

export function MitreCards({ mitreAttack = [], recommendedActions = [] }) {
  // Group techniques by tactic
  const grouped = mitreAttack.reduce((acc, item) => {
    const tactic = item.tactic || 'General / Uncategorized';
    if (!acc[tactic]) acc[tactic] = [];
    acc[tactic].push(item);
    return acc;
  }, {});

  return (
    <div className="forensic-panel">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">MITRE ATT&CK Matrix Alignment</span>
          <span className="panel-subtitle">Adversary Tactics, Techniques & Procedures (TTPs)</span>
        </div>
        <span className="rail-item-badge">Enterprise v14</span>
      </div>

      {mitreAttack.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          No MITRE ATT&CK techniques matched for this threat pattern.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {Object.entries(grouped).map(([tactic, techniques]) => (
            <div key={tactic} className="mitre-tactic-group">
              <div className="tactic-heading">TACTIC // {tactic}</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '10px' }}>
                {techniques.map((tech, idx) => (
                  <div key={idx} className="technique-card">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span className="technique-id">{tech.technique}</span>
                        <span className="technique-name">{tech.name}</span>
                      </div>
                      {tech.confidence && (
                        <span className="mono-val" style={{ fontSize: 'var(--fs-micro)', color: 'var(--accent-amber)' }}>
                          {Math.round(tech.confidence * 100)}%
                        </span>
                      )}
                    </div>
                    {tech.evidence && tech.evidence.length > 0 && (
                      <div className="technique-evidence">
                        {tech.evidence.map((ev, i) => (
                          <div key={i} style={{ display: 'flex', gap: '6px', marginTop: '3px' }}>
                            <span style={{ color: 'var(--text-muted)' }}>&bull;</span>
                            <span>{ev}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Recommended Mitigations / Actions */}
      {recommendedActions && recommendedActions.length > 0 && (
        <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--border-hairline)' }}>
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--accent-amber)', fontFamily: 'var(--font-mono)', fontWeight: 600, marginBottom: '8px' }}>
            RECOMMENDED SOC REMEDIATION PROTOCOLS ({recommendedActions.length})
          </div>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {recommendedActions.map((action, idx) => (
              <li
                key={idx}
                style={{
                  fontSize: 'var(--fs-xs)',
                  color: 'var(--text-primary)',
                  backgroundColor: 'var(--bg-base)',
                  border: '1px solid var(--border-hairline)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '8px 12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                <span className="mono-val" style={{ color: 'var(--accent-amber)', fontSize: 'var(--fs-micro)', fontWeight: 600 }}>
                  [{String(idx + 1).padStart(2, '0')}]
                </span>
                <span>{action}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default MitreCards;
