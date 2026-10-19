import React, { useEffect, useState } from 'react';
import Icon from '../common/Icon';
import ExportButton from './ExportButton';
import { keyStats, riskCategories, riskTags, verdictOf } from '../../utils/reportSummary';

const BAND_TEXT = {
  danger: 'This email is dangerous',
  caution: 'This email is suspicious',
  safe: 'No high-risk signs found',
};

function ScoreRing({ score, band }) {
  const [shown, setShown] = useState(0);
  useEffect(() => { const t = setTimeout(() => setShown(score), 80); return () => clearTimeout(t); }, [score]);
  const r = 54;
  const c = 2 * Math.PI * r;
  return (
    <div className={`score-ring band-${band}`}>
      <svg viewBox="0 0 128 128" aria-hidden="true">
        <circle cx="64" cy="64" r={r} className="ring-track" />
        <circle cx="64" cy="64" r={r} className="ring-fill" strokeDasharray={c} strokeDashoffset={c - (c * shown) / 100} />
      </svg>
      <div className="score-ring-value"><strong>{score}</strong><span>/ 100 risk</span></div>
    </div>
  );
}

export default function VerdictHero({ data, onJump }) {
  const v = verdictOf(data);
  const tags = riskTags(data);
  const s = keyStats(data);
  const email = data.email || {};
  const headline = data.evidence_report?.headline || data.ai_analysis?.final_assessment?.explanation || '';
  const trusted = data.baseline_context?.trusted_sender;

  // Same counts as the "Why it was flagged" cards, so the numbers always agree.
  const tone = (c) => (c.severity === 'high' ? 'bad' : c.severity === 'medium' ? 'warn' : 'ok');
  const numbers = riskCategories(data).map((c) => {
    const off = c.key === 'reputation' && !s.reputationLive && !c.count;
    return [c.label, off ? 'off' : c.count, off ? 'muted' : tone(c), `cat-${c.key}`];
  });

  return (
    <section id="sec-summary" className={`verdict-hero band-${v.band}`}>
      <div className="verdict-hero-main">
        <ScoreRing score={v.score} band={v.band} />
        <div className="verdict-hero-text">
          <span className="eyebrow">{BAND_TEXT[v.band]}</span>
          <h1>{v.label}</h1>
          {headline && <p className="verdict-headline-text">{headline}</p>}
          <div className="risk-tags" aria-label="Why it was risky">
            {tags.length ? tags.map((t) => (
              <button key={t.key} type="button" className={`risk-tag sev-${t.severity}`} onClick={() => onJump(`cat-${t.key}`)}>
                <Icon name={t.icon} size={15} /><span>{t.label}</span><b>{t.count}</b>
              </button>
            )) : <span className="risk-tag sev-none"><Icon name="check" size={15} /><span>No risk signs found</span></span>}
          </div>
        </div>
        <div className="verdict-hero-side">
          <dl className="mail-meta">
            <div><dt>Subject</dt><dd>{email.subject || '(no subject)'}</dd></div>
            <div><dt>From</dt><dd className="mono-val">{email.from_email || email.from_raw || 'unknown'}</dd></div>
            <div><dt>Received</dt><dd>{email.date || 'not stated'}</dd></div>
          </dl>
          <ExportButton data={data} />
        </div>
      </div>
      {trusted && trusted.status !== 'not_trusted' && (
        <div className={`trusted-note ${trusted.applied ? 'ok' : 'warn'}`}>
          <Icon name={trusted.applied ? 'check' : 'alert'} size={16} />{trusted.explanation}
        </div>
      )}
      <div className="hero-numbers">
        {numbers.map(([label, value, tone, target]) => (
          <button type="button" key={label} className={`hero-number tone-${tone}`} onClick={() => onJump(target)}>
            <strong>{value}</strong><span>{label}</span>
          </button>
        ))}
      </div>
    </section>
  );
}
