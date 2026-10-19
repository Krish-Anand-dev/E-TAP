import React from 'react';
import Icon from '../common/Icon';

export default function Remediation({ data }) {
  const todo = data.evidence_report?.what_to_do || {};
  const fallback = data.ai_analysis?.final_assessment?.recommended_actions || [];
  const steps = todo.steps?.length ? todo.steps : fallback.map((text) => ({ text, basis: 'policy' }));
  const specific = steps.filter((s) => s.basis === 'evidence');
  const general = steps.filter((s) => s.basis !== 'evidence');
  const ai = todo.ai_suggestions || [];

  return (
    <section id="sec-remediation" className="report-section">
      <div className="report-section-head"><h2>Remediation</h2><p>What to do about this email, most important first.</p></div>
      <div className="remediation-grid">
        {specific.length > 0 && (
          <div className="remediation-card urgent">
            <h3><Icon name="alert" size={17} />Do this now</h3>
            <ol>{specific.map((s, i) => <li key={i}>{s.text}</li>)}</ol>
          </div>
        )}
        <div className="remediation-card">
          <h3><Icon name="shield" size={17} />Recommended steps</h3>
          <ol>{general.map((s, i) => <li key={i}>{s.text}</li>)}</ol>
        </div>
        {ai.length > 0 && (
          <div className="remediation-card ai">
            <h3><Icon name="sparkle" size={17} />AI suggestions</h3>
            <ul>{ai.map((t, i) => <li key={i}>{t}</li>)}</ul>
          </div>
        )}
      </div>
    </section>
  );
}
