import React, { useEffect, useMemo, useState } from 'react';
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import apiClient from '../api/client';
import { useInvestigation } from '../context/InvestigationContext';
import { bandFor, displayLabel } from '../utils/verdict';
import Icon from '../components/common/Icon';

const BAND_COLORS = { danger: '#d93a45', caution: '#e3a33a', safe: '#2e9e6b' };
const BAND_NAMES = { danger: 'High risk', caution: 'Suspicious', safe: 'Low risk' };

function normalise(records) {
  return records.map((r) => {
    const score = Math.round(Number(r.risk_score) || 0);
    return {
      id: r.email_id || r.id,
      subject: r.subject || r.filename || 'Untitled email',
      from: r.from_email || r.from || '',
      score,
      label: displayLabel(r.verdict, score),
      band: bandFor({ verdictBand: r.verdict_band, verdict: r.verdict, riskScore: score }),
      at: r.analyzed_at ? new Date(r.analyzed_at) : null,
      type: r.attack_type || r.report?.ai_analysis?.content_classification?.attack_type || null,
      record: r,
    };
  });
}

function Stat({ label, value, detail, icon, tone }) {
  return (
    <div className={`stat-tile tone-${tone}`}>
      <div className="stat-tile-head"><span>{label}</span><span className="stat-tile-icon"><Icon name={icon} size={18} /></span></div>
      <strong>{value}</strong>
      <p>{detail}</p>
    </div>
  );
}

export default function OverviewPage({ navigate }) {
  const { history, backendOnline, loadFromHistory } = useInvestigation();
  const [stored, setStored] = useState(null);

  useEffect(() => {
    let active = true;
    apiClient.get('/investigations?limit=100').then((r) => active && setStored(r.data)).catch(() => active && setStored(null));
    return () => { active = false; };
  }, [history.length]);

  const fromServer = Array.isArray(stored) && stored.length > 0;
  const rows = useMemo(() => normalise(fromServer ? stored : history), [fromServer, stored, history]);

  const counts = { danger: 0, caution: 0, safe: 0 };
  rows.forEach((r) => { counts[r.band] += 1; });
  const avg = rows.length ? Math.round(rows.reduce((n, r) => n + r.score, 0) / rows.length) : 0;
  const weekAgo = Date.now() - 7 * 864e5;
  const lastWeek = rows.filter((r) => r.at && r.at.getTime() >= weekAgo).length;
  const trend = rows.slice(0, 15).reverse().map((r, i) => ({ name: `${i + 1}`, score: r.score, subject: r.subject }));
  const pie = Object.entries(counts).filter(([, n]) => n > 0).map(([band, n]) => ({ band, name: BAND_NAMES[band], value: n }));
  const types = Object.entries(rows.reduce((acc, r) => {
    if (r.type && r.band !== 'safe') acc[r.type] = (acc[r.type] || 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const maxType = types.length ? types[0][1] : 1;
  const pad = (n) => String(n).padStart(2, '0');

  const open = (r) => { loadFromHistory(r.record.report ? r.record : r.id); navigate('dashboard'); };

  return (
    <div className="overview-page v2-page">
      <section className="v2-hero">
        <div>
          <div className="eyebrow">E-TAP / EMAIL THREAT ANALYSIS</div>
          <h1>Clarity in every investigation<span>.</span></h1>
          <p>Upload a suspicious email and see in under a minute whether it is safe, why, and what to do next.</p>
        </div>
        <div className="v2-hero-actions">
          <button className="new-analysis-button" onClick={() => navigate('upload')}>Analyze an email <Icon name="arrow" size={18} /></button>
          <button className="hero-text-link" onClick={() => navigate('history')}>View all reports <Icon name="arrow" size={16} /></button>
        </div>
      </section>

      <div className="v2-section-head">
        <h2>Your security overview</h2>
        <span className="period-label"><Icon name="history" size={16} />{fromServer ? 'All stored investigations' : 'This browser session'}</span>
      </div>

      <div className="stat-grid">
        <Stat label="Emails analysed" value={pad(rows.length)} detail={`${lastWeek} in the last 7 days`} icon="mail" tone="neutral" />
        <Stat label="High risk" value={pad(counts.danger)} detail="Likely or high-risk phishing" icon="alert" tone="danger" />
        <Stat label="Suspicious" value={pad(counts.caution)} detail="Verify before acting" icon="activity" tone="caution" />
        <Stat label="Low risk" value={pad(counts.safe)} detail="Not a guarantee of safety" icon="check" tone="safe" />
        <Stat label="Average risk" value={rows.length ? avg : '—'} detail="Score out of 100" icon="chart" tone={avg >= 65 ? 'danger' : avg >= 40 ? 'caution' : 'neutral'} />
      </div>

      <div className="v2-grid-3">
        <section className="v2-card span-2">
          <div className="v2-card-head"><div><h3>Risk over time</h3><p>Risk score of your most recent analyses, oldest to newest</p></div></div>
          <div className="v2-chart">
            {trend.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trend} margin={{ top: 16, right: 12, left: -22, bottom: 0 }}>
                  <defs><linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#d93a45" stopOpacity={0.28} /><stop offset="100%" stopColor="#d93a45" stopOpacity={0} /></linearGradient></defs>
                  <CartesianGrid stroke="#e4e3db" strokeDasharray="3 5" vertical={false} />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: '#6b7180' }} />
                  <YAxis domain={[0, 100]} ticks={[0, 40, 65, 100]} tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: '#6b7180' }} />
                  <Tooltip contentStyle={{ background: '#fffef7', border: '1px solid #e4e3db', borderRadius: 12 }} labelFormatter={(_, v) => v?.[0]?.payload?.subject || ''} />
                  <Area type="monotone" dataKey="score" name="Risk score" stroke="#d93a45" strokeWidth={2.2} fill="url(#trend-fill)" dot={{ r: 3.5, fill: '#d93a45' }} />
                </AreaChart>
              </ResponsiveContainer>
            ) : <EmptyChart navigate={navigate} />}
          </div>
        </section>

        <section className="v2-card">
          <div className="v2-card-head"><div><h3>Verdict breakdown</h3><p>How your emails were classified</p></div></div>
          {pie.length ? (
            <div className="donut-wrap">
              <div className="donut">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart><Pie data={pie} dataKey="value" innerRadius="62%" outerRadius="92%" paddingAngle={2} stroke="none">
                    {pie.map((p) => <Cell key={p.band} fill={BAND_COLORS[p.band]} />)}
                  </Pie></PieChart>
                </ResponsiveContainer>
                <div className="donut-center"><strong>{rows.length}</strong><span>emails</span></div>
              </div>
              <ul className="legend-list">
                {['danger', 'caution', 'safe'].map((b) => (
                  <li key={b}><i style={{ background: BAND_COLORS[b] }} /><span>{BAND_NAMES[b]}</span><b>{counts[b]}</b><em>{rows.length ? Math.round((counts[b] / rows.length) * 100) : 0}%</em></li>
                ))}
              </ul>
            </div>
          ) : <p className="v2-empty-line">No analyses yet.</p>}
        </section>
      </div>

      <div className="v2-grid-3">
        <section className="v2-card">
          <div className="v2-card-head"><div><h3>Top threat types</h3><p>What the risky emails were trying to do</p></div></div>
          {types.length ? (
            <ul className="bar-list">
              {types.map(([name, n]) => <li key={name}><span>{name}</span><div><i style={{ width: `${(n / maxType) * 100}%` }} /></div><b>{n}</b></li>)}
            </ul>
          ) : <p className="v2-empty-line">No risky emails yet.</p>}
        </section>

        <section className="v2-card span-2">
          <div className="v2-card-head">
            <div><h3>Recent investigations</h3><p>Click a row to open its full report</p></div>
            <button className="text-button" onClick={() => navigate('history')}>All reports <Icon name="arrow" size={16} /></button>
          </div>
          {rows.length ? (
            <table className="v2-table">
              <thead><tr><th>Email</th><th>Verdict</th><th className="num">Risk</th><th>When</th></tr></thead>
              <tbody>
                {rows.slice(0, 6).map((r) => (
                  <tr key={r.id} onClick={() => open(r)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && open(r)}>
                    <td><strong>{r.subject}</strong><span>{r.from}</span></td>
                    <td><span className={`verdict-chip ${r.band}`}>{r.label}</span></td>
                    <td className="num"><b className={`score-${r.band}`}>{r.score}</b><span className="muted">/100</span></td>
                    <td className="muted">{r.at ? r.at.toLocaleDateString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="recent-empty"><Icon name="mail" size={25} /><div><strong>No investigations yet</strong><p>Analyze an email to see it here.</p></div><button className="subtle-button" onClick={() => navigate('upload')}>Analyze email</button></div>
          )}
        </section>
      </div>

      <footer className="overview-footer"><span><span className="connection-dot" data-online={backendOnline} />{backendOnline ? 'Connected to analysis engine' : 'Analysis engine connection pending'}</span><span>Scores support triage, not certainty</span></footer>
    </div>
  );
}

function EmptyChart({ navigate }) {
  return (
    <div className="chart-empty">
      <span className="empty-chart-icon"><Icon name="chart" size={25} /></span>
      <strong>Your investigations start here</strong>
      <span>Analyze an email to see its risk score in context.</span>
      <button onClick={() => navigate('upload')}>Analyze your first email <Icon name="arrow" size={15} /></button>
    </div>
  );
}
