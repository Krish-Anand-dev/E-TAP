import React, { useState, useRef, useEffect } from 'react';
import { useInvestigation } from '../context/InvestigationContext';
import Icon from '../components/common/Icon';
import { verdictOf } from '../utils/reportSummary';

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

const STAGE_ICONS = {
  parse: 'mail', headers: 'user', static_attachments: 'paperclip', sandbox: 'box', indicators: 'link',
  reputation: 'globe', history: 'history', ai: 'sparkle', verdict: 'shield',
};
const DEFAULT_STAGES = [
  ['parse', 'Reading the email'], ['headers', 'Checking sender & headers'], ['static_attachments', 'Static attachment analysis'],
  ['sandbox', 'Dynamic attachment analysis'], ['indicators', 'Extracting links & indicators'], ['reputation', 'Threat reputation lookups'],
  ['history', 'Comparing with past emails'], ['ai', 'AI threat assessment'], ['verdict', 'Final verdict'],
].map(([key, label]) => ({ key, label, state: 'pending', detail: null }));
const STATE_TEXT = { pending: 'Waiting', running: 'In progress', done: 'Done', skipped: 'Skipped', not_available: 'Not in this version', error: 'Failed' };

// Minimum time each stage stays "in progress" on screen, in ms. Locally (no API
// keys) the backend finishes in about a second, which reads as nothing
// happening. The timeline still shows the real backend state and order; it just
// reveals each finished stage no faster than this. A stage that is genuinely
// slower (live reputation lookups, Gemini) is never held back beyond its real
// time. Set VITE_TIMELINE_PACING=off to show raw backend timing.
const MIN_STAGE_MS = {
  parse: 700, headers: 1300, static_attachments: 1500, sandbox: 1100, indicators: 1000,
  reputation: 1700, history: 1200, ai: 2300, verdict: 900,
};
const FINAL_STATES = new Set(['done', 'skipped', 'not_available', 'error']);
const PACING_ON = import.meta.env.VITE_TIMELINE_PACING !== 'off';

function jitteredDwell() {
  // 70%-130% of each minimum, so stages do not tick at a fixed rhythm.
  return Object.fromEntries(Object.entries(MIN_STAGE_MS).map(([k, ms]) => [k, Math.round(ms * (0.7 + Math.random() * 0.6))]));
}

/** Reveal real stage progress one stage at a time, each for at least its minimum time. */
function usePacedStages(rawStages, runId) {
  const [shown, setShown] = useState([]);
  const rawRef = useRef(rawStages);
  rawRef.current = rawStages;

  useEffect(() => {
    setShown([]);
    if (!runId) return undefined;
    const state = { index: 0, since: 0, dwell: jitteredDwell(), list: [] };
    const tick = setInterval(() => {
      const raw = rawRef.current;
      if (!raw || !raw.length) return;
      if (!PACING_ON) { setShown(raw); return; }
      if (!state.list.length) state.list = raw.map((s) => ({ ...s, state: 'pending', detail: null }));
      if (state.index >= state.list.length) return;

      const current = state.list[state.index];
      const real = raw[state.index] || current;
      const now = Date.now();
      if (real.state === 'error') {
        state.list[state.index] = { ...real };
        state.index = state.list.length; // stop: later stages never ran
      } else if (current.state === 'pending' && real.state !== 'pending') {
        state.list[state.index] = { ...current, state: 'running' };
        state.since = now;
      } else if (current.state === 'running' && FINAL_STATES.has(real.state)
        && now - state.since >= (state.dwell[real.key] ?? 900)) {
        state.list[state.index] = { ...real };
        state.index += 1;
      } else {
        return;
      }
      setShown([...state.list]);
    }, 110);
    return () => clearInterval(tick);
  }, [runId]);

  return {
    shown,
    done: shown.length > 0 && shown.every((s) => FINAL_STATES.has(s.state)),
    stopped: shown.some((s) => s.state === 'error'),
  };
}

function useElapsed(active) {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    if (!active) return undefined;
    setSeconds(0);
    const started = Date.now();
    const t = setInterval(() => setSeconds(Math.floor((Date.now() - started) / 1000)), 250);
    return () => clearInterval(t);
  }, [active]);
  return seconds;
}

export function PipelineTimeline({ stages, finished, failed }) {
  const list = stages && stages.length ? stages : DEFAULT_STAGES;
  const completed = list.filter((s) => ['done', 'skipped', 'not_available'].includes(s.state)).length;
  const pct = Math.round((completed / list.length) * 100);
  return (
    <div className={`timeline ${finished ? 'finished' : ''} ${failed ? 'failed' : ''}`}>
      <div className="timeline-progress" aria-hidden="true"><i style={{ width: `${pct}%` }} /></div>
      <ol>
        {list.map((stage, i) => (
          <li key={stage.key} className={`tl-step state-${stage.state} ${stage.key === 'sandbox' ? 'is-sandbox' : ''}`}>
            <span className="tl-node">
              {stage.state === 'done' ? <Icon name="check" size={16} strokeWidth={2.4} />
                : stage.state === 'error' ? <Icon name="x" size={16} strokeWidth={2.4} />
                  : <Icon name={STAGE_ICONS[stage.key] || 'shield'} size={16} />}
            </span>
            <div className="tl-body">
              <div className="tl-title"><span className="tl-index">{String(i + 1).padStart(2, '0')}</span><strong>{stage.label}</strong></div>
              <span className="tl-detail">{stage.detail || STATE_TEXT[stage.state]}</span>
            </div>
            <span className="tl-state">{STATE_TEXT[stage.state]}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function UploadPage({ onOpenReport }) {
  const { status, error, data, startAnalysis, loadDemoSample, backendOnline, jobStages } = useInvestigation();
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [runFinished, setRunFinished] = useState(false);
  const [runId, setRunId] = useState(0);
  const fileInputRef = useRef(null);
  const isBusy = status === 'uploading' || status === 'analyzing';
  const paced = usePacedStages(jobStages, runId);
  // Still "working" on screen until the paced timeline has shown every stage.
  const isWorking = isBusy || (runFinished && !paced.done);
  const elapsed = useElapsed(isWorking);
  const showTimeline = isWorking || runFinished || (status === 'error' && jobStages.length > 0);
  const showError = Boolean(error) && !isBusy && (!jobStages.length || paced.stopped || !PACING_ON);

  const stage = (file) => {
    if (!file) return;
    const name = file.name.toLowerCase();
    if (!name.endsWith('.eml') && !name.endsWith('.msg')) {
      alert('Please choose an email file (.eml or .msg).');
      return;
    }
    setRunFinished(false);
    setSelectedFile(file);
  };

  const run = async (file) => {
    setRunFinished(false);
    setRunId((n) => n + 1);
    const report = await startAnalysis(file);
    if (report) setRunFinished(true);
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(e.type === 'dragenter' || e.type === 'dragover');
  };

  const runSample = (raw, filename) => {
    const file = new File([raw], filename, { type: 'message/rfc822' });
    setSelectedFile(file);
    run(file);
  };

  const result = runFinished && paced.done && data ? verdictOf(data) : null;

  return (
    <div className="upload-container v2-upload">
      <div className="ingest-header">
        <span className="ingest-badge">NEW INVESTIGATION</span>
        <h1 className="ingest-title">Every investigation starts with an email.</h1>
        <p className="ingest-desc">Drop the email file and watch each check run: sender, attachments, links, reputation, history and AI, ending in a clear verdict.</p>
      </div>

      {!showTimeline && (
        <div
          className={`dropzone-panel ${dragActive ? 'drag-over' : ''}`}
          onDragEnter={handleDrag} onDragLeave={handleDrag} onDragOver={handleDrag}
          onDrop={(e) => { handleDrag(e); setDragActive(false); stage(e.dataTransfer.files?.[0]); }}
          onClick={() => fileInputRef.current?.click()}
          role="button" tabIndex={0}
          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && fileInputRef.current?.click()}
        >
          <input ref={fileInputRef} id="email-file-input" type="file" accept=".eml,.msg" style={{ display: 'none' }} onChange={(e) => stage(e.target.files?.[0])} />
          <div className="dropzone-icon-box"><Icon name="file" size={24} /></div>
          <div className="dropzone-title">{selectedFile ? selectedFile.name : 'Drop an email file here or click to browse'}</div>
          <div className="dropzone-subtitle">Accepts <strong>.eml</strong> and Outlook <strong>.msg</strong> files up to 25 MB</div>
        </div>
      )}

      {selectedFile && !showTimeline && (
        <div className="staged-file-card">
          <div className="file-meta-left">
            <span className="file-tag">{selectedFile.name.split('.').pop()?.toUpperCase()}</span>
            <div><div className="file-name">{selectedFile.name}</div><div className="file-size">{(selectedFile.size / 1024).toFixed(1)} KB</div></div>
          </div>
          <div className="staged-actions">
            <button type="button" className="btn-ghost" onClick={() => setSelectedFile(null)}>Clear</button>
            <button type="button" id="execute-pipeline-btn" className="btn-primary-action" onClick={() => run(selectedFile)} disabled={backendOnline === false}>Analyze email</button>
          </div>
        </div>
      )}

      {showTimeline && (
        <section className="v2-card analysis-run">
          <div className="analysis-run-head">
            <div>
              <span className="eyebrow">{isWorking ? 'ANALYSIS IN PROGRESS' : status === 'error' ? 'ANALYSIS STOPPED' : 'ANALYSIS COMPLETE'}</span>
              <h2>{selectedFile?.name || 'Email analysis'}</h2>
            </div>
            {isWorking && <span className="elapsed"><Icon name="clock" size={16} />{elapsed}s</span>}
          </div>
          <PipelineTimeline stages={paced.shown.length ? paced.shown : (PACING_ON ? [] : jobStages)} finished={Boolean(result)} failed={paced.stopped} />
          {result && (
            <div className={`run-result band-${result.band}`}>
              <div className="run-score"><strong>{result.score}</strong><span>/100</span></div>
              <div><span className="eyebrow">VERDICT</span><h3>{result.label}</h3></div>
              <button type="button" className="btn-primary-action" onClick={onOpenReport}>Open full report <Icon name="arrow" size={16} /></button>
              <button type="button" className="btn-ghost" onClick={() => { setRunFinished(false); setSelectedFile(null); }}>Analyze another</button>
            </div>
          )}
        </section>
      )}

      {showError && (
        <div className="forensic-error-box">
          <div className="error-title-row"><Icon name="alert" size={18} /><span>The analysis could not finish</span></div>
          <div className="error-message">{error}</div>
          <div style={{ display: 'flex', gap: '10px' }}>
            {selectedFile && <button type="button" className="btn-ghost" onClick={() => run(selectedFile)}>Retry</button>}
            <button type="button" className="btn-ghost" onClick={() => { setRunFinished(false); setSelectedFile(null); }}>Choose another file</button>
          </div>
        </div>
      )}

      {!isWorking && (
        <div className="demo-strip v2-samples">
          <div className="demo-text"><strong>No email handy?</strong> Run one of our sample emails through the full analysis, or preview a finished report.</div>
          <div className="v2-sample-buttons">
            <button type="button" className="btn-primary-action" onClick={() => runSample(REAL_SAMPLE_PHISHING_EML, 'sample_phishing.eml')} disabled={backendOnline === false}>Analyze phishing sample</button>
            <button type="button" className="btn-ghost" onClick={() => runSample(REAL_SAMPLE_CLEAN_EML, 'sample_benign.eml')} disabled={backendOnline === false}>Analyze benign sample</button>
            <button type="button" className="btn-ghost" onClick={() => { loadDemoSample(); onOpenReport(); }}>Preview sample report</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default UploadPage;
