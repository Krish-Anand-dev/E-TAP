import React, { useEffect, useMemo, useState } from 'react';
import apiClient from '../api/client';
import { fetchInvestigation } from '../api/analyze';
import { useInvestigation } from '../context/InvestigationContext';
import { bandFor, displayLabel } from '../utils/verdict';
import { stageSummaries, verdictOf, riskTags } from '../utils/reportSummary';
import Icon from '../components/common/Icon';
import { needsSandboxRefresh } from '../utils/sandbox';

const STATUS_TEXT = { good: 'Clear', warn: 'Check', bad: 'Problem', skipped: 'Skipped', not_run: 'Not run' };
const FILTERS = [['all', 'All'], ['danger', 'High risk'], ['caution', 'Suspicious'], ['safe', 'Low risk']];

function rowsFrom(stored, history) {
  const seen = new Set();
  const rows = [];
  const add = (r, local) => {
    const id = r.email_id || r.id;
    if (!id || seen.has(id)) return;
    seen.add(id);
    const score = Math.round(Number(r.risk_score) || 0);
    rows.push({
      id, local, report: r.report || null,
      subject: r.subject || r.filename || 'Untitled email',
      from: r.from_email || r.from || '',
      score, label: displayLabel(r.verdict, score),
      band: bandFor({ verdictBand: r.verdict_band, verdict: r.verdict, riskScore: score }),
      at: r.analyzed_at ? new Date(r.analyzed_at) : null,
    });
  };
  history.forEach((r) => add(r, true));
  (stored || []).forEach((r) => add(r, false));
  return rows.sort((a, b) => (b.at?.getTime() || 0) - (a.at?.getTime() || 0));
}

function StageCard({ stage, index }) {
  return (
    <article className={`stage-card st-${stage.status}`}>
      <header>
        <span className="stage-icon"><Icon name={stage.icon} size={18} /></span>
        <div><span className="stage-num">STAGE {String(index + 1).padStart(2, '0')}</span><h3>{stage.title}</h3></div>
        <span className="stage-status">{STATUS_TEXT[stage.status]}</span>
      </header>
      <p>{stage.summary}</p>
      {stage.metrics.length > 0 && (
        <dl className="stage-metrics">
          {stage.metrics.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{String(v)}</dd></div>)}
        </dl>
      )}
    </article>
  );
}

export function HistoryPage({ onOpenReport, navigate }) {
  const { history, loadFromHistory, clearHistory } = useInvestigation();
  const [stored, setStored] = useState(null);
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    apiClient.get('/investigations?limit=100').then((r) => setStored(r.data)).catch(() => setStored([]));
  }, []);

  const rows = useMemo(() => rowsFrom(stored, history), [stored, history]);
  const visible = rows.filter((r) => (filter === 'all' || r.band === filter)
    && (!query || `${r.subject} ${r.from}`.toLowerCase().includes(query.toLowerCase())));

  useEffect(() => {
    if (!selectedId && rows.length) setSelectedId(rows[0].id);
  }, [rows, selectedId]);

  useEffect(() => {
    if (!selectedId) return;
    const row = rows.find((r) => r.id === selectedId);
    // Session copies made before the sandbox finished only hold its short status.
    if (row?.report && !needsSandboxRefresh(row.report.sandbox)) { setSelected(row.report); setLoadError(''); return; }
    let active = true;
    setLoading(true);
    setLoadError('');
    fetchInvestigation(selectedId)
      .then((rep) => active && setSelected(rep))
      .catch(() => active && (setSelected(null), setLoadError('This report could not be loaded. It may have expired or been deleted.')))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [selectedId]); // eslint-disable-line react-hooks/exhaustive-deps

  const openFull = () => {
    const row = rows.find((r) => r.id === selectedId);
    loadFromHistory(row?.report && !needsSandboxRefresh(row.report.sandbox) ? { id: row.id, report: row.report } : selectedId);
    onOpenReport();
  };

  const counts = rows.reduce((acc, r) => ({ ...acc, [r.band]: (acc[r.band] || 0) + 1 }), {});
  const v = selected ? verdictOf(selected) : null;
  const stages = selected ? stageSummaries(selected) : [];
  const tags = selected ? riskTags(selected) : [];

  return (
    <div className="v2-page reports-page">
      <div className="v2-section-head">
        <div><h1 className="page-title">Reports</h1><p className="page-sub">Every email you have analysed, broken down stage by stage.</p></div>
        {history.length > 0 && <button type="button" className="btn-ghost" onClick={clearHistory}>Clear session list</button>}
      </div>

      <div className="reports-layout">
        <aside className="reports-list v2-card">
          <div className="reports-tools">
            <label className="search-box"><Icon name="search" size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search subject or sender" aria-label="Search reports" /></label>
            <div className="filter-chips">
              {FILTERS.map(([key, label]) => (
                <button key={key} type="button" className={filter === key ? 'active' : ''} onClick={() => setFilter(key)}>
                  {label}<b>{key === 'all' ? rows.length : counts[key] || 0}</b>
                </button>
              ))}
            </div>
          </div>
          {visible.length ? (
            <ul>
              {visible.map((r) => (
                <li key={r.id}>
                  <button type="button" className={`report-row ${selectedId === r.id ? 'active' : ''}`} onClick={() => setSelectedId(r.id)}>
                    <span className={`row-score score-${r.band}`}>{r.score}</span>
                    <span className="row-text"><strong>{r.subject}</strong><span>{r.from || r.label}</span></span>
                    <span className="row-date">{r.at ? r.at.toLocaleDateString() : ''}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <div className="reports-empty"><Icon name="file" size={24} /><p>{rows.length ? 'No reports match this filter.' : 'No reports yet.'}</p>
              {!rows.length && <button type="button" className="btn-primary-action" onClick={() => navigate('upload')}>Analyze an email</button>}</div>
          )}
        </aside>

        <section className="report-detail">
          {loading && <div className="v2-card report-loading">Loading report…</div>}
          {loadError && <div className="v2-card report-loading">{loadError}</div>}
          {!loading && selected && v && (
            <>
              <div className={`report-summary-card band-${v.band}`}>
                <div className="rs-score"><strong>{v.score}</strong><span>/100</span></div>
                <div className="rs-text">
                  <span className="eyebrow">{v.label}</span>
                  <h2>{selected.email?.subject || '(no subject)'}</h2>
                  <p>{selected.email?.from_email || ''}</p>
                  <div className="risk-tags small">
                    {tags.length ? tags.map((t) => <span key={t.key} className={`risk-tag sev-${t.severity}`}><Icon name={t.icon} size={14} />{t.label}<b>{t.count}</b></span>)
                      : <span className="risk-tag sev-none"><Icon name="check" size={14} />No risk signs</span>}
                  </div>
                </div>
                <button type="button" className="btn-primary-action" onClick={openFull}>Open full investigation <Icon name="arrow" size={16} /></button>
              </div>
              <div className="stage-grid">{stages.map((st, i) => <StageCard key={st.key} stage={st} index={i} />)}</div>
            </>
          )}
          {!loading && !selected && !loadError && rows.length > 0 && <div className="v2-card report-loading">Select a report to see its breakdown.</div>}
        </section>
      </div>
    </div>
  );
}

export default HistoryPage;
