import React, { useEffect, useState } from 'react';
import { useInvestigation } from '../context/InvestigationContext';

import VerdictHero from '../components/report/VerdictHero';
import RiskBreakdown from '../components/report/RiskBreakdown';
import Remediation from '../components/report/Remediation';
import HeaderAnalysis from '../components/report/HeaderAnalysis';
import AttachmentTable from '../components/report/AttachmentTable';
import ContentAnalysis from '../components/report/ContentAnalysis';
import IocTable from '../components/report/IocTable';
import ThreatGraph from '../components/report/ThreatGraph';
import GeoMap from '../components/report/GeoMap';
import MitreCards from '../components/report/MitreCards';
import EvidenceBreakdown from '../components/report/EvidenceBreakdown';
import HistoricalCorrelationCard from '../components/report/HistoricalCorrelationCard';
import ResponseWorkflow from '../components/report/ResponseWorkflow';
import TrustControls from '../components/report/TrustControls';
import SandboxPanel from '../components/report/SandboxPanel';
import Icon from '../components/common/Icon';
import { fetchInvestigation } from '../api/analyze';
import { getGeoMapData } from '../utils/geo.js';
import { keyStats, hasSandbox } from '../utils/reportSummary';
import { TERMINAL_SANDBOX_STATUSES, mergeSandboxReport, sandboxSummary, sandboxOutcome, sandboxPlace, needsSandboxRefresh } from '../utils/sandbox';

const SECTIONS = [
  ['sec-summary', 'Summary'],
  ['sec-why', 'Why it was flagged'],
  ['sec-remediation', 'Remediation'],
  ['sec-sandbox', 'Sandbox'],
  ['sec-map', 'Sender route'],
  ['sec-analysis', 'Threat analysis'],
  ['sec-details', 'Technical details'],
  ['sec-history', 'Past emails'],
  ['sec-tools', 'Analyst tools'],
];

function jump(id) {
  const el = document.getElementById(id);
  if (!el) return;
  if (el.tagName === 'DETAILS') el.open = true;
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function Detail({ id, icon, title, count, children }) {
  return (
    <details id={id} className="detail-block">
      <summary><Icon name={icon} size={18} /><strong>{title}</strong>{count != null && <b className="detail-count">{count}</b>}<Icon name="chevron" size={16} /></summary>
      <div className="detail-body">{children}</div>
    </details>
  );
}

export function DashboardPage({ navigate }) {
  const { getSourceFile, requestReanalysis } = useInvestigation();
  const { data, setData, persistInvestigation, activeFile } = useInvestigation();
  const [active, setActive] = useState('sec-summary');

  // While attachments run in a sandbox, refresh the result every 4 s; the
  // score and verdict follow when the run finishes.
  useEffect(() => {
    if (!data?.email_id || !needsSandboxRefresh(data.sandbox)) return undefined;
    let cancelled = false;
    let inFlight = false;
    const poll = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const updated = await fetchInvestigation(data.email_id);
        if (!cancelled) setData((current) => mergeSandboxReport(current, updated));
      } catch { /* a temporary failure does not end an active job */ }
      finally { inFlight = false; }
    };
    poll();
    const interval = setInterval(poll, 4000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [data?.email_id, data?.sandbox?.status, Array.isArray(data?.sandbox?.items), setData]); // eslint-disable-line react-hooks/exhaustive-deps

  // Save the finished sandbox result into this session's report list.
  useEffect(() => {
    if (data?.email_id && TERMINAL_SANDBOX_STATUSES.has(data.sandbox?.status)) persistInvestigation(data, activeFile?.name);
  }, [data?.email_id, data?.sandbox?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const onScroll = () => {
      let current = SECTIONS[0][0];
      for (const [id] of SECTIONS) {
        const el = document.getElementById(id);
        if (el && el.getBoundingClientRect().top <= 140) current = id;
      }
      setActive(current);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  if (!data) {
    return (
      <div className="v2-page v2-empty-page">
        <Icon name="search" size={30} />
        <h2>No investigation open</h2>
        <p>Analyze an email or open one from your reports.</p>
        <div><button type="button" className="btn-primary-action" onClick={() => navigate('upload')}>Analyze an email</button>
          <button type="button" className="btn-ghost" onClick={() => navigate('history')}>Open a report</button></div>
      </div>
    );
  }

  const {
    email_id = 'N/A', email = {}, headers = {}, attachments = [], iocs = {}, threat_intel = {},
    correlation = {}, graph_diffusion = {}, ai_analysis = {},
  } = data;
  const historical = data.historical_correlation || correlation.historical_stats || {};
  const fa = ai_analysis.final_assessment || {};
  const mitre = fa.mitre_attack?.length ? fa.mitre_attack : data.mitre_attack || [];
  const geo = getGeoMapData(headers.hops, threat_intel.geo);
  const s = keyStats(data);
  const origin = headers.origin_analysis || {};

  return (
    <div className="v2-page report-page">
      <nav className="report-tabs" aria-label="Report sections">
        {SECTIONS.filter(([id]) => id !== 'sec-sandbox' || hasSandbox(data)).map(([id, label]) => (
          <button key={id} type="button" className={active === id ? 'active' : ''} onClick={() => jump(id)}>{label}</button>
        ))}
      </nav>

      <VerdictHero data={data} onJump={jump} canReanalyze={Boolean(getSourceFile(data.email_id))}
        onReanalyze={() => { const file = getSourceFile(data.email_id); if (file) { requestReanalysis(file); navigate('upload'); } }} />
      <RiskBreakdown data={data} />
      <Remediation data={data} />

      {hasSandbox(data) && (
        <section id="sec-sandbox" className="report-section">
          <div className="report-section-head"><h2>Sandbox behaviour</h2><p>What happened when the attachments were opened inside {sandboxPlace(data.sandbox)}, an isolated virtual machine.</p></div>
          {(() => {
            const sb = sandboxSummary(data.sandbox);
            const outcome = sandboxOutcome(data.sandbox);
            return (
              <div className="hero-numbers sandbox-numbers">
                <div className={`hero-number tone-${outcome.tone}`} title={outcome.note}><strong>{outcome.label}</strong><span>VM result</span></div>
                <div className="hero-number tone-muted"><strong>{sb.items}</strong><span>Files opened</span></div>
                <div className={`hero-number ${sb.matches ? 'tone-bad' : 'tone-ok'}`}><strong>{sb.matches}</strong><span>Detection rules matched</span></div>
                {data.sandbox.defender_checked === false && !sb.blocked
                  ? <div className="hero-number tone-muted" title={data.sandbox.defender_note}><strong>Not checked</strong><span>Blocked by Defender</span></div>
                  : <div className={`hero-number ${sb.blocked ? 'tone-bad' : 'tone-ok'}`}><strong>{sb.blocked}</strong><span>Blocked by Defender</span></div>}
              </div>
            );
          })()}
          {['Not tested', 'Waiting'].includes(sandboxOutcome(data.sandbox).label) && (
            <div className="trusted-note warn sandbox-note"><Icon name="alert" size={16} />{sandboxOutcome(data.sandbox).note}{sandboxOutcome(data.sandbox).label === 'Not tested' ? '. The file was copied into the VM but not opened, so this is not a result either way.' : ''}</div>
          )}
          <SandboxPanel sandbox={data.sandbox} />
        </section>
      )}

      <section id="sec-map" className="report-section">
        <div className="report-section-head"><h2>Sender route</h2><p>Where the mail servers that handled this email are located.</p></div>
        {geo.pointCount > 0 ? (
          <GeoMap hops={headers.hops || []} origin={origin} geoPoints={threat_intel.geo || []} />
        ) : (
          <div className="v2-card map-empty">
            <Icon name="map" size={26} />
            <div>
              <strong>No locations to plot</strong>
              <p>
                {!s.headersAvailable ? 'Original headers were not available for this email, so its route cannot be traced.'
                  : threat_intel.lookup_mode !== 'live'
                    ? `${origin.true_origin_ip || headers.originating_ip ? `The email was first handed on by ${origin.true_origin_ip || headers.originating_ip}, but` : 'Live'} location lookups are turned off for this analysis, so it cannot be placed on the map.`
                    : origin.explanation || 'No public mail-server addresses with a known location were found in this email.'}
              </p>
            </div>
          </div>
        )}
      </section>

      <section id="sec-analysis" className="report-section">
        <div className="report-section-head"><h2>Threat analysis</h2><p>How each part of the analysis scored this email, and the attacker techniques it matches.</p></div>
        <div className="analysis-grid">
          <EvidenceBreakdown evidenceAssessments={fa.evidence_assessments || []} />
          <MitreCards mitreAttack={mitre} recommendedActions={[]} />
        </div>
      </section>

      <section id="sec-details" className="report-section">
        <div className="report-section-head"><h2>Technical details</h2><p>The full findings from every check, for anyone who wants to dig in.</p></div>
        <Detail id="det-headers" icon="user" title="Sender & headers" count={s.headerFlags}><HeaderAnalysis headers={headers} /></Detail>
        <Detail id="det-attachments" icon="paperclip" title="Attachments" count={attachments.length}><AttachmentTable attachments={attachments} /></Detail>
        <Detail id="det-content" icon="message" title="Message content (AI reading)"><ContentAnalysis aiAnalysis={ai_analysis} email={email} /></Detail>
        <Detail id="det-iocs" icon="link" title="Links, domains, IPs & file hashes" count={s.indicators}><IocTable iocs={iocs} threatIntel={threat_intel} historicalCorrelation={historical} /></Detail>
      </section>

      <section id="sec-history" className="report-section">
        <div className="report-section-head"><h2>Past emails</h2><p>Whether this email's senders, links or files appeared in earlier investigations.</p></div>
        <HistoricalCorrelationCard correlation={correlation} historicalCorrelation={historical} />
        <ThreatGraph emailId={email_id} correlation={correlation} iocs={iocs} threatIntel={threat_intel} graphDiffusion={graph_diffusion} />
      </section>

      <section id="sec-tools" className="report-section">
        <div className="report-section-head"><h2>Analyst tools</h2><p>Review status, case notes, sharing and retention, for security teams.</p></div>
        <Detail id="det-review" icon="check" title="Review, case & feedback"><ResponseWorkflow emailId={data.email_id} band={data.verdict_band} baseline={data.baseline_context} /></Detail>
        <Detail id="det-retention" icon="lock" title="Sharing, retention & deletion"><TrustControls data={data} onDeleted={() => window.location.reload()} /></Detail>
      </section>
    </div>
  );
}

export default DashboardPage;
