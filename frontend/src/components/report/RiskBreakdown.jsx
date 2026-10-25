import React, { useState } from 'react';
import Icon from '../common/Icon';
import { riskCategories } from '../../utils/reportSummary';

const SEVERITY_TEXT = { high: 'High concern', medium: 'Worth checking', none: 'No issues' };
const KIND_TEXT = { observed: 'Found in the email', reputation: 'Reputation service', ai_inferred: 'AI reading' };

function Finding({ item }) {
  return (
    <li className={`finding weight-${item.weight}`}>
      <span className="finding-dot" />
      <div>
        <strong>{item.title}</strong>
        {(item.why || item.detail) && <p>{item.why || item.detail}</p>}
        {item.kind && <em>{KIND_TEXT[item.kind] || item.kind}</em>}
      </div>
    </li>
  );
}

function CategoryCard({ cat }) {
  const [open, setOpen] = useState(false);
  const shown = open ? cat.raises : cat.raises.slice(0, 3);
  const hidden = cat.raises.length - shown.length;
  return (
    <article id={`cat-${cat.key}`} className={`cat-card sev-${cat.severity}`}>
      <header>
        <span className="cat-icon"><Icon name={cat.icon} size={19} /></span>
        <div><h3>{cat.title}</h3><span className="cat-sev">{SEVERITY_TEXT[cat.severity]}</span></div>
        <b className="cat-count">{cat.count}</b>
      </header>
      {cat.count ? (
        <ul className="finding-list">{shown.map((it) => <Finding key={it.id} item={it} />)}</ul>
      ) : (
        <p className="cat-clear"><Icon name="check" size={15} />Nothing suspicious found here.</p>
      )}
      {hidden > 0 && <button type="button" className="text-button" onClick={() => setOpen(true)}>Show {hidden} more</button>}
      {(cat.lowers.length > 0 || cat.unavailable.length > 0) && (
        <footer>
          {cat.lowers.length > 0 && <span className="cat-foot ok"><Icon name="check" size={14} />{cat.lowers.length} reassuring sign{cat.lowers.length > 1 ? 's' : ''}</span>}
          {cat.unavailable.length > 0 && <span className="cat-foot muted" title={cat.unavailable.map((u) => u.title).join('\n')}><Icon name="clock" size={14} />{cat.unavailable.length} not checked</span>}
        </footer>
      )}
    </article>
  );
}

export default function RiskBreakdown({ data }) {
  const cats = riskCategories(data);
  const ordered = [...cats].sort((a, b) => b.strong - a.strong || b.count - a.count);
  const total = cats.reduce((n, c) => n + c.count, 0);
  const strong = cats.reduce((n, c) => n + c.strong, 0);
  const max = Math.max(1, ...cats.map((c) => c.count));
  return (
    <section id="sec-why" className="report-section">
      <div className="report-section-head">
        <h2>Why it was flagged</h2>
        <p><b>{total}</b> warning sign{total === 1 ? '' : 's'} found, <b>{strong}</b> of them serious.</p>
      </div>
      <div className="cat-bars" aria-hidden="true">
        {cats.map((c) => (
          <div key={c.key} className={`cat-bar sev-${c.severity}`}>
            <span>{c.title}</span><div><i style={{ width: `${(c.count / max) * 100}%` }} /></div><b>{c.count}</b>
          </div>
        ))}
      </div>
      <div className="cat-grid">{ordered.map((c) => <CategoryCard key={c.key} cat={c} />)}</div>
    </section>
  );
}
