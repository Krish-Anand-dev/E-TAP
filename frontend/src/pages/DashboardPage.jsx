import React, { useState, useEffect } from 'react';
import { useInvestigation } from '../context/InvestigationContext';

import VerdictBanner from '../components/report/VerdictBanner';
import HeaderAnalysis from '../components/report/HeaderAnalysis';
import AttachmentTable from '../components/report/AttachmentTable';
import ContentAnalysis from '../components/report/ContentAnalysis';
import IocTable from '../components/report/IocTable';
import ThreatGraph from '../components/report/ThreatGraph';
import GeoMap from '../components/report/GeoMap';
import MitreCards from '../components/report/MitreCards';
import EvidenceBreakdown from '../components/report/EvidenceBreakdown';
import HistoricalCorrelationCard from '../components/report/HistoricalCorrelationCard';
import ExportButton from '../components/report/ExportButton';

export function DashboardPage() {
  const { data, activeFile, resetInvestigation } = useInvestigation();
  const [activeSection, setActiveSection] = useState('sec-overview');

  if (!data) {
    return (
      <div style={{ padding: '60px', textAlign: 'center' }}>
        <h3 style={{ color: 'var(--text-secondary)', marginBottom: '16px' }}>
          No active email dossier loaded.
        </h3>
        <button
          type="button"
          className="btn-primary-action"
          onClick={resetInvestigation}
        >
          Ingest an Email Artifact
        </button>
      </div>
    );
  }

  const {
    email_id = 'N/A',
    risk_score = 0,
    verdict = 'UNKNOWN',
    email = {},
    headers = {},
    attachments = [],
    iocs = {},
    threat_intel = {},
    correlation = {},
    graph_diffusion = data.graph_diffusion || {},
    ai_analysis = {},
    historical_correlation = data.historical_correlation || correlation.historical_stats || {},
  } = data;

  const finalAssessment = ai_analysis.final_assessment || {};
  const evidenceAssessments = finalAssessment.evidence_assessments || [];
  const mitreAttack =
    finalAssessment.mitre_attack && finalAssessment.mitre_attack.length > 0
      ? finalAssessment.mitre_attack
      : data.mitre_attack || [];
  const recommendedActions = finalAssessment.recommended_actions || [];

  // Track active scroll section for left rail highlighting
  useEffect(() => {
    const handleScroll = () => {
      const sections = [
        'sec-overview',
        'sec-headers',
        'sec-attachments',
        'sec-content',
        'sec-iocs',
        'sec-evidence',
        'sec-mitre',
        'sec-correlation',
        'sec-graph',
        'sec-geo',
      ];
      for (const id of sections) {
        const el = document.getElementById(id);
        if (el) {
          const rect = el.getBoundingClientRect();
          if (rect.top <= 120 && rect.bottom >= 120) {
            setActiveSection(id);
            break;
          }
        }
      }
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const totalIocs =
    (iocs.ips?.length || 0) +
    (iocs.domains?.length || 0) +
    (iocs.urls?.length || 0) +
    (iocs.hashes?.length || 0);

  return (
    <div className="dashboard-layout">
      {/* Left Navigation Rail (Anchor Links) */}
      <aside className="dossier-rail">
        <div>
          <div className="rail-section-title">CASE IDENTIFIER</div>
          <div className="rail-meta-card">
            <div className="rail-meta-row">
              <div className="rail-meta-label">DOSSIER REF</div>
              <div className="rail-meta-value mono-val">
                {String(email_id).substring(0, 18)}...
              </div>
            </div>
            <div className="rail-meta-row">
              <div className="rail-meta-label">FILE ARTIFACT</div>
              <div className="rail-meta-value" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                {activeFile?.name || email.message_id || 'email.eml'}
              </div>
            </div>
            <div className="rail-meta-row">
              <div className="rail-meta-label">FORMAT</div>
              <div className="rail-meta-value mono-val">
                {email.source_format?.toUpperCase() || 'RFC 822'}
              </div>
            </div>
          </div>

          <div className="rail-section-title">REPORT SECTIONS</div>
          <ul className="rail-nav-list">
            <li className="rail-nav-item">
              <a
                href="#sec-overview"
                className={activeSection === 'sec-overview' ? 'active' : ''}
              >
                <span>Overview & Verdict</span>
                <span className="rail-item-badge">{risk_score}/100</span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-headers"
                className={activeSection === 'sec-headers' ? 'active' : ''}
              >
                <span>Headers & Routing</span>
                <span className="rail-item-badge">
                  {headers.red_flags?.length || 0} flags
                </span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-attachments"
                className={activeSection === 'sec-attachments' ? 'active' : ''}
              >
                <span>Attachments</span>
                <span className="rail-item-badge">{attachments.length}</span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-content"
                className={activeSection === 'sec-content' ? 'active' : ''}
              >
                <span>AI Content Analysis</span>
                <span className="rail-item-badge">Gemini</span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-iocs"
                className={activeSection === 'sec-iocs' ? 'active' : ''}
              >
                <span>Extracted IOCs</span>
                <span className="rail-item-badge">{totalIocs}</span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-evidence"
                className={activeSection === 'sec-evidence' ? 'active' : ''}
              >
                <span>Evidence Breakdown</span>
                <span className="rail-item-badge">{evidenceAssessments.length}</span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-mitre"
                className={activeSection === 'sec-mitre' ? 'active' : ''}
              >
                <span>MITRE ATT&CK</span>
                <span className="rail-item-badge">{mitreAttack.length}</span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-correlation"
                className={activeSection === 'sec-correlation' ? 'active' : ''}
              >
                <span>DB Correlation</span>
                <span
                  className="rail-item-badge"
                  style={{
                    color:
                      (historical_correlation.metrics_summary?.max_repetition_this_week > 0)
                        ? '#EF4444'
                        : '#10B981',
                  }}
                >
                  {historical_correlation.metrics_summary?.max_repetition_this_week > 0
                    ? `${historical_correlation.metrics_summary.max_repetition_this_week}x RECUR`
                    : 'NEW'}
                </span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-graph"
                className={activeSection === 'sec-graph' ? 'active' : ''}
              >
                <span>Threat Graph</span>
                <span className="rail-item-badge">2D</span>
              </a>
            </li>
            <li className="rail-nav-item">
              <a
                href="#sec-geo"
                className={activeSection === 'sec-geo' ? 'active' : ''}
              >
                <span>Geo Footprint</span>
                <span className="rail-item-badge">
                  {threat_intel.geo?.length || 0}
                </span>
              </a>
            </li>
          </ul>
        </div>

        <div style={{ marginTop: '20px' }}>
          <div className="rail-section-title">DOSSIER EXPORTS</div>
          <ExportButton data={data} />
        </div>
      </aside>

      {/* Main Single-Scroll Dossier Canvas */}
      <main className="dossier-canvas">
        {/* Section: Overview & Primary Verdict */}
        <section id="sec-overview" className="dossier-section">
          <VerdictBanner
            verdict={verdict}
            riskScore={risk_score}
            confidence={finalAssessment.confidence}
            explanation={finalAssessment.explanation}
            triage={data.triage}
          />

          {/* Core Envelope Header Metadata Card */}
          <div className="forensic-panel">
            <div className="forensic-panel-header">
              <div className="panel-title-group">
                <span className="panel-title">Message Envelope Identity</span>
                <span className="panel-subtitle">Extracted MIME Header Properties</span>
              </div>
              <span className="mono-val" style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)' }}>
                {email.date || 'Timestamp not declared'}
              </span>
            </div>

            <div className="metadata-grid">
              <div className="meta-field">
                <div className="meta-field-label">SUBJECT</div>
                <div className="meta-field-value" style={{ fontWeight: 600 }}>
                  {email.subject || '(No Subject Header)'}
                </div>
              </div>
              <div className="meta-field">
                <div className="meta-field-label">RECIPIENT (TO)</div>
                <div className="meta-field-value mono-val">
                  {email.to || 'Undisclosed Recipients'}
                </div>
              </div>
              <div className="meta-field">
                <div className="meta-field-label">RFC 5322 SENDER</div>
                <div className="meta-field-value mono-val">
                  {email.from_raw || email.from_email || 'N/A'}
                </div>
              </div>
              <div className="meta-field">
                <div className="meta-field-label">INTERNET MESSAGE-ID</div>
                <div className="meta-field-value mono-val" style={{ fontSize: '11px' }}>
                  {email.message_id || 'N/A'}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Section: Headers & Authentication */}
        <section id="sec-headers" className="dossier-section">
          <HeaderAnalysis headers={headers} />
        </section>

        {/* Section: Attachments */}
        <section id="sec-attachments" className="dossier-section">
          <AttachmentTable attachments={attachments} />
        </section>

        {/* Section: AI Content Analysis */}
        <section id="sec-content" className="dossier-section">
          <ContentAnalysis aiAnalysis={ai_analysis} email={email} />
        </section>

        {/* Section: Indicators of Compromise */}
        <section id="sec-iocs" className="dossier-section">
          <IocTable
            iocs={iocs}
            threatIntel={threat_intel}
            historicalCorrelation={historical_correlation}
          />
        </section>

        {/* Section: Multi-vector Evidence Breakdown */}
        <section id="sec-evidence" className="dossier-section">
          <EvidenceBreakdown evidenceAssessments={evidenceAssessments} />
        </section>

        {/* Section: MITRE ATT&CK Matrix */}
        <section id="sec-mitre" className="dossier-section">
          <MitreCards
            mitreAttack={mitreAttack}
            recommendedActions={recommendedActions}
          />
        </section>

        {/* Section: Database Correlation & Indicator Repetition */}
        <section id="sec-correlation" className="dossier-section">
          <HistoricalCorrelationCard
            correlation={correlation}
            historicalCorrelation={historical_correlation}
          />
        </section>

        {/* Section: 2D Threat Topology Graph */}
        <section id="sec-graph" className="dossier-section">
          <ThreatGraph
            emailId={email_id}
            correlation={correlation}
            iocs={iocs}
            threatIntel={threat_intel}
            graphDiffusion={graph_diffusion}
          />
        </section>

        {/* Section: Geo Footprint */}
        <section id="sec-geo" className="dossier-section">
          <GeoMap geoPoints={threat_intel.geo || []} />
        </section>
      </main>
    </div>
  );
}

export default DashboardPage;
