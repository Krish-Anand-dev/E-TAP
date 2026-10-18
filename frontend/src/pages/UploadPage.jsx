import React, { useState, useRef } from 'react';
import { useInvestigation } from '../context/InvestigationContext';

const REAL_SAMPLE_PHISHING_EML = `From: IT Helpdesk <support@northfield-logisitcs-helpdesk.com>
To: priya.nair@northfield-logistics.com
Subject: URGENT: Your mailbox password expires in 2 hours
Date: Wed, 26 Aug 2026 03:11:47 +0000
Message-ID: <8271-urgent-reset@mail-relay-09.ru>
Reply-To: itsupport-noreply@webmail-free-inbox.com
Authentication-Results: mx1.northfield-logistics.com; spf=fail
 smtp.mailfrom=northfield-logisitcs-helpdesk.com; dkim=fail; dmarc=fail
Received: from mail-relay-09.ru (unknown [185.220.101.47]) by
 mx1.northfield-logistics.com with SMTP id 91fa; Wed, 26 Aug 2026 03:11:40
 +0000
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0

Dear User,

Our system detected that your mailbox password will EXPIRE in 2 HOURS. To avoid permanent loss of access, verify your account IMMEDIATELY:

hxxp-decoded-for-testing://secure-login.northfield-logisitcs-helpdesk.com/verify?id=3D88213

Failure to verify within the time limit will result in your mailbox being permanently deleted per company policy.

IT Helpdesk Team
`;

const REAL_SAMPLE_CLEAN_EML = `From: Priya Nair <priya.nair@northfield-logistics.com>
To: team-ops@northfield-logistics.com
Subject: Team standup moved to 10:30 tomorrow
Date: Mon, 24 Aug 2026 14:02:11 +0000
Message-ID: <c8f1a2e0-standup@northfield-logistics.com>
Authentication-Results: mx1.northfield-logistics.com; spf=pass
 smtp.mailfrom=northfield-logistics.com; dkim=pass
 header.d=northfield-logistics.com; dmarc=pass
Received: from mail.northfield-logistics.com (mail.northfield-logistics.com
 [10.20.4.11]) by mx1.northfield-logistics.com with ESMTPS id 7a1b; Mon, 24
 Aug 2026 14:02:10 +0000
Received: from smtp-relay.gmail.com (smtp-relay.gmail.com [209.85.220.41]) by
 mail.northfield-logistics.com with ESMTPS id 3c9d; Mon, 24 Aug 2026 14:02:05
 +0000
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0

Hi all,

Quick note - tomorrow's standup is moving from 10:00 to 10:30 so Marcus can join after his dentist appointment. Same link as usual.

Thanks,
Priya
`;

export function UploadPage({ onAnalysisComplete }) {
  const {
    status,
    error,
    startAnalysis,
    loadDemoSample,
    backendOnline,
  } = useInvestigation();

  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateAndStageFile = (file) => {
    if (!file) return;
    const name = file.name.toLowerCase();
    if (!name.endsWith('.eml') && !name.endsWith('.msg')) {
      alert('Forensic ingest restricted to RFC 822 (.eml) or Outlook OLE (.msg) email files.');
      return;
    }
    setSelectedFile(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndStageFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndStageFile(e.target.files[0]);
    }
  };

  const handleSubmit = async () => {
    if (!selectedFile) return;
    await startAnalysis(selectedFile);
    if (onAnalysisComplete) {
      onAnalysisComplete();
    }
  };

  const isBusy = status === 'uploading' || status === 'analyzing';

  const handleTestRealPipeline = async (rawContent, filename) => {
    const file = new File([rawContent], filename, { type: 'message/rfc822' });
    setSelectedFile(file);
    await startAnalysis(file);
    if (onAnalysisComplete) onAnalysisComplete();
  };

  return (
    <div className="upload-container">
      <div className="ingest-header">
        <span className="ingest-badge">NEW INVESTIGATION</span>
        <h1 className="ingest-title">Every investigation starts with an email.</h1>
        <p className="ingest-desc">
          Drop a raw email artifact to trigger automated header verification (SPF/DKIM/DMARC),
          static attachment inspection, reputation correlation, and Gemini-assisted threat verdict generation.
        </p>
      </div>

      {/* Drag & Drop Area */}
      <div
        className={`dropzone-panel ${dragActive ? 'drag-over' : ''} ${isBusy ? 'disabled' : ''}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => !isBusy && fileInputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            fileInputRef.current?.click();
          }
        }}
      >
        <input
          ref={fileInputRef}
          id="email-file-input"
          type="file"
          accept=".eml,.msg"
          style={{ display: 'none' }}
          onChange={handleFileChange}
          disabled={isBusy}
        />

        <div className="dropzone-icon-box">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="12" y1="18" x2="12" y2="12" />
            <line x1="9" y1="15" x2="12" y2="12" />
            <line x1="15" y1="15" x2="12" y2="12" />
          </svg>
        </div>

        <div className="dropzone-title">
          {selectedFile ? 'Selected for Triage' : 'Drop raw email file here or click to browse'}
        </div>
        <div className="dropzone-subtitle">
          Accepts forensic email formats: <strong>.eml</strong> (MIME / RFC 822) or <strong>.msg</strong> (Outlook MSG OLE)
        </div>

        <div className="dropzone-specs">
          <div className="spec-item">
            <span className="spec-dot" />
            <span>SHA-256 Hashing</span>
          </div>
          <div className="spec-item">
            <span className="spec-dot" />
            <span>MIME Extraction</span>
          </div>
          <div className="spec-item">
            <span className="spec-dot" />
            <span>Visible Data Flows</span>
          </div>
        </div>
      </div>

      {/* Selected File Inspection Strip */}
      {selectedFile && !isBusy && (
        <div className="staged-file-card">
          <div className="file-meta-left">
            <span className="file-tag">{selectedFile.name.split('.').pop()?.toUpperCase()}</span>
            <div>
              <div className="file-name">{selectedFile.name}</div>
              <div className="file-size">
                {(selectedFile.size / 1024).toFixed(1)} KB &bull; Last Modified:{' '}
                {new Date(selectedFile.lastModified).toLocaleDateString()}
              </div>
            </div>
          </div>
          <div className="staged-actions">
            <button
              type="button"
              className="btn-ghost"
              onClick={(e) => {
                e.stopPropagation();
                setSelectedFile(null);
              }}
            >
              Clear
            </button>
            <button
              type="button"
              id="execute-pipeline-btn"
              className="btn-primary-action"
              onClick={(e) => {
                e.stopPropagation();
                handleSubmit();
              }}
            >
              Analyze email
            </button>
          </div>
        </div>
      )}

      {/* Live Pipeline Execution Progress */}
      {isBusy && (
        <div className="pipeline-progress-box">
          <div className="pipeline-header">
            <div className="pipeline-status-title">
              <span className="pulse-indicator" />
              <span>Analyzing File Artifact: {selectedFile?.name || 'In Progress'}</span>
            </div>
            <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              PIPELINE EXECUTION ACTIVE
            </span>
          </div>

          <div className="pipeline-steps-grid">
            <div className="pipeline-step">
              <div className="step-label">STAGE A</div>
              <div className="step-name">MIME & Headers</div>
            </div>
            <div className="pipeline-step">
              <div className="step-label">STAGE B / B2</div>
              <div className="step-name">Threat Intel & Geo</div>
            </div>
            <div className="pipeline-step">
              <div className="step-label">STAGE D / F</div>
              <div className="step-name">Attachment Static</div>
            </div>
            <div className="pipeline-step">
              <div className="step-label">STAGE G</div>
              <div className="step-name">Gemini AI Synthesis</div>
            </div>
          </div>
        </div>
      )}

      {/* Error Diagnostics Panel */}
      {error && (
        <div className="forensic-error-box">
          <div className="error-title-row">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <span>Forensic Ingest Error</span>
          </div>
          <div className="error-message">{error}</div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              type="button"
              className="btn-ghost"
              onClick={() => {
                setSelectedFile(null);
                handleSubmit();
              }}
            >
              Retry
            </button>
            <button
              type="button"
              className="btn-ghost"
              onClick={() => {
                loadDemoSample();
                if (onAnalysisComplete) onAnalysisComplete();
              }}
            >
              Load Sample Case Dossier
            </button>
          </div>
        </div>
      )}

      {/* Live Pipeline Test Strip (uses the configured E-TAP API base URL) */}
      <div className="demo-strip" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '12px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="demo-text">
            <strong>Try a sample investigation:</strong> Explore the workflow with a sample email, or preview a report without running an analysis.
          </div>
          <span className="rail-item-badge">SAMPLE EMAILS</span>
        </div>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn-primary-action"
            style={{ fontSize: 'var(--fs-xs)', padding: '6px 14px' }}
            onClick={() => handleTestRealPipeline(REAL_SAMPLE_PHISHING_EML, 'set01_002.eml')}
            disabled={isBusy}
          >
            Analyze phishing sample
          </button>
          <button
            type="button"
            className="btn-ghost"
            style={{ fontSize: 'var(--fs-xs)', padding: '6px 14px' }}
            onClick={() => handleTestRealPipeline(REAL_SAMPLE_CLEAN_EML, 'set01_001.eml')}
            disabled={isBusy}
          >
            Analyze benign sample
          </button>
          <button
            type="button"
            className="btn-ghost"
            style={{ fontSize: 'var(--fs-xs)', padding: '6px 14px', marginLeft: 'auto' }}
            onClick={() => {
              loadDemoSample();
              if (onAnalysisComplete) onAnalysisComplete();
            }}
            disabled={isBusy}
          >
            Preview sample report
          </button>
        </div>
      </div>
    </div>
  );
}

export default UploadPage;
