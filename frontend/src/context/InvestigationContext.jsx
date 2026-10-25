import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import { checkBackendHealth, fetchInvestigation, startAnalysisJob, getAnalysisJob } from '../api/analyze';

const InvestigationContext = createContext(null);

const STORAGE_KEY = 'E-TAP_investigations_history_v1';

// Exact schema reference sample for testing & fallback demos
export const SAMPLE_REPORT = {
  email_id: "urn:uuid:7f3b0e12-4c21-482a-9e23-74b8c9d01234",
  risk_score: 91,
  verdict: "HIGH-RISK PHISHING",
  email: {
    subject: "URGENT: Payroll Account Verification Required Immediately",
    from_raw: "Finance Support <service@payro11-internal.com>",
    from_display_name: "Finance Support",
    from_email: "service@payro11-internal.com",
    to: "victim.employee@enterprise-target.org",
    reply_to: "recovery-desk@external-relay-box.ru",
    date: "Mon, 07 Sep 2026 02:45:12 +0530",
    message_id: "<20260907024512.4382.91023@payro11-internal.com>",
    source_format: "eml",
    body_text: "Dear Employee,\n\nWe detected unauthorized access attempts on your corporate payroll profile. If you do not re-authenticate your banking credentials within 24 hours, direct deposit will be frozen.\n\nPlease review the attached secure invoice document and click the link below to verify your identity:\nhttp://payro11-internal.com/login/auth-session?token=94821a\n\nIT Security & Payroll Operations",
    body_html: "<p>Dear Employee,</p><p>We detected unauthorized access attempts on your corporate payroll profile. If you do not re-authenticate your banking credentials within 24 hours, direct deposit will be frozen.</p><p>Please review the attached secure invoice document and verify your identity.</p>",
    parse_warnings: []
  },
  headers: {
    sender_email: "service@payro11-internal.com",
    display_name: "Finance Support",
    reply_to: "recovery-desk@external-relay-box.ru",
    spf: "fail",
    dkim: "none",
    dmarc: "fail",
    originating_ip: "185.220.101.5",
    received_chain: [
      "from mail.external-relay-box.ru (185.220.101.5) by edge-mx01.target.org with ESMTP",
      "from internal-sender.local ([10.4.1.99]) by mail.external-relay-box.ru with SMTP"
    ],
    red_flags: [
      "SPF failure: IP 185.220.101.5 is not authorized for domain payro11-internal.com",
      "DMARC failure: policy is reject but message bypassed gateway",
      "Severe Reply-To mismatch: Sender is payro11-internal.com but replies route to external-relay-box.ru",
      "Punycode / Lookalike domain permutation detected (payro11 vs payroll)"
    ]
  },
  attachments: [
    {
      filename: "DirectDeposit_Update_Form.pdf.exe",
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      declared_type: "application/pdf",
      actual_type: "application/x-msdownload",
      type_mismatch: true,
      has_macro: false,
      suspicious: true
    }
  ],
  iocs: {
    ips: ["185.220.101.5", "91.240.118.17"],
    domains: ["payro11-internal.com", "external-relay-box.ru"],
    urls: ["http://payro11-internal.com/login/auth-session?token=94821a"],
    hashes: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
  },
  threat_intel: {
    ip_reputation: {
      "185.220.101.5": { malicious: true, reports: 68, country: "RU" },
      "91.240.118.17": { malicious: true, reports: 34, country: "MD" }
    },
    domain_info: {
      "payro11-internal.com": { age_days: 2, registrar: "NiceNIC International Group Ltd" },
      "external-relay-box.ru": { age_days: 14, registrar: "Reg.ru LLC" }
    },
    url_reputation: {
      "http://payro11-internal.com/login/auth-session?token=94821a": { malicious: true }
    },
    geo: [
      { ip: "185.220.101.5", lat: 55.7558, lon: 37.6173, country: "RU" },
      { ip: "91.240.118.17", lat: 47.0105, lon: 28.8638, country: "MD" }
    ]
  },
  correlation: {
    email_id: "urn:uuid:7f3b0e12-4c21-482a-9e23-74b8c9d01234",
    related_emails: ["msg-campaign-fin-001", "msg-campaign-fin-004"],
    campaign_id: "CAMPAIGN-FIN-HARVEST-2026",
    shared_infrastructure: ["185.220.101.5", "payro11-internal.com"]
  },
  graph_diffusion: {
    available: true,
    diffusion_score: 0.7425,
    hops_used: 3,
    nearest_seed_distance: 1,
    contributing_seeds: ["185.220.101.5", "payro11-internal.com"],
    node_scores: {
      "urn:uuid:7f3b0e12-4c21-482a-9e23-74b8c9d01234": 0.7425,
      "185.220.101.5": 1.0,
      "91.240.118.17": 1.0,
      "payro11-internal.com": 0.825,
      "external-relay-box.ru": 0.584,
      "http://payro11-internal.com/login/auth-session?token=94821a": 0.875,
      "CAMPAIGN-FIN-HARVEST-2026": 0.912,
      "msg-campaign-fin-001": 0.684,
      "msg-campaign-fin-004": 0.651,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": 0.62
    },
    explanation: "1 hop(s) from flagged malicious seed '185.220.101.5' via [communicates_with_ip]"
  },
  ai_analysis: {
    content_classification: {
      content_verdict: "Likely Malicious",
      confidence: 0.96,
      attack_type: "Credential Phishing / BEC",
      categories: [
        { name: "Credential Phishing", weight: 92 },
        { name: "Executive/Authority Impersonation", weight: 85 },
        { name: "Urgency / Financial Coercion", weight: 88 }
      ],
      reasons: [
        "Strong psychological urgency demanding banking verification within 24 hours under threat of frozen payroll",
        "Executive identity spoofing mimicking internal finance operations",
        "Call to action routes to a newly-registered typo-squatted domain"
      ],
      suspicious_indicators: [
        "Unregistered lookalike domain 'payro11-internal.com'",
        "High urgency language ('Immediately', 'within 24 hours', 'frozen')",
        "Executable masked with double extension .pdf.exe"
      ]
    },
    final_assessment: {
      verdict: "HIGH-RISK PHISHING",
      risk_score: 91,
      confidence: 0.94,
      explanation: "This email constitutes an active targeted credential harvesting attack combined with a high-threat executable payload. SPF, DKIM, and DMARC authentication all failed or were missing, and the reply-to header points to an anomalous Russian bulletproof relay host. The domain was registered fewer than 3 days ago. The attached file masks a Windows PE executable behind a deceptive .pdf.exe double extension.",
      evidence_assessments: [
        { source: "Header Authentication", risk_score: 95, summary: "SPF fail, DMARC fail, and severe Reply-To mismatch", evidence: ["SPF fail", "Reply-To mismatch"] },
        { source: "Attachment Forensics", risk_score: 98, summary: "Executable binary masked as a PDF document", evidence: ["application/x-msdownload", "double extension"] },
        { source: "Domain & WHOIS Intel", risk_score: 89, summary: "Domain registered 2 days ago via privacy proxy", evidence: ["age_days: 2"] },
        { source: "IP Reputation & Geo", risk_score: 84, summary: "Originating IP flagged in 68 malicious threat feeds", evidence: ["185.220.101.5 reported"] },
        { source: "Content & Behavioral AI", risk_score: 92, summary: "High urgency payroll coercion and credential link", evidence: ["Credential harvest intent"] },
        { source: "Campaign Correlation", risk_score: 80, summary: "Infrastructure overlaps with CAMPAIGN-FIN-HARVEST", evidence: ["Shared IP and domain"] }
      ],
      supporting_evidence: [
        "Authentication failure across all standard RFC email hygiene protocols",
        "Hostile payload: SHA256 matches malware distribution cluster",
        "Lookalike domain permutation impersonating internal infrastructure"
      ],
      mitre_attack: [
        {
          technique: "T1566.002",
          name: "Phishing: Spearphishing Link",
          tactic: "Initial Access",
          confidence: 0.94,
          evidence: ["Credential harvesting link in email body directing to malicious domain"]
        },
        {
          technique: "T1566.001",
          name: "Phishing: Spearphishing Attachment",
          tactic: "Initial Access",
          confidence: 0.96,
          evidence: ["Disguised executable attachment DirectDeposit_Update_Form.pdf.exe"]
        },
        {
          technique: "T1036.007",
          name: "Masquerading: Double Extension",
          tactic: "Defense Evasion",
          confidence: 0.98,
          evidence: ["Attachment uses .pdf.exe extension to deceive end users"]
        }
      ],
      recommended_actions: [
        "Block domain 'payro11-internal.com' and IP '185.220.101.5' at perimeter firewall and DNS resolver",
        "Purge message ID '<20260907024512.4382.91023@payro11-internal.com>' from all enterprise mailboxes",
        "Quarantine recipient host 'victim.employee@enterprise-target.org' and verify if attachment was executed",
        "Revoke existing Active Directory session tokens for affected recipient"
      ]
    }
  },
  stage_status: {
    A: "complete",
    B: "complete",
    B2: "complete",
    D: "complete",
    E: "live",
    F: "complete",
    G: "gemini",
    H: "complete"
  }
};

export function InvestigationProvider({ children }) {
  // Status: 'idle' | 'uploading' | 'analyzing' | 'success' | 'error'
  const [status, setStatus] = useState('idle');
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [activeFile, setActiveFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [jobStages, setJobStages] = useState([]);
  // Bumped by resetInvestigation so the Analyze page remounts fresh (New analysis).
  const [resetToken, setResetToken] = useState(0);
  // Files uploaded in this tab, by email_id, so a report can be re-analyzed
  // without uploading again. Memory only: gone after a page reload.
  const sourceFiles = useRef(new Map());
  const [rerunRequest, setRerunRequest] = useState(null);
  const [backendOnline, setBackendOnline] = useState(null);
  const [lastHealthCheck, setLastHealthCheck] = useState(null);
  const [history, setHistory] = useState(() => {
    try {
      const saved = sessionStorage.getItem(STORAGE_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  // Check backend connectivity on mount and recurring timer every 15s with jitter debounce
  useEffect(() => {
    let mounted = true;
    let failCount = 0;

    const runCheck = async () => {
      const isUp = await checkBackendHealth();
      if (!mounted) return;

      if (isUp) {
        failCount = 0;
        setBackendOnline(true);
        setLastHealthCheck(new Date());
      } else {
        failCount += 1;
        // Require 2 consecutive failed pings before marking offline to avoid transient network jitter
        if (failCount >= 2) {
          setBackendOnline(false);
          setLastHealthCheck(new Date());
        }
      }
    };

    runCheck();
    const interval = setInterval(runCheck, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  // Save successful analyses to history
  const persistInvestigation = (report, filename) => {
    try {
      const record = {
        id: report.email_id || `rec_${Date.now()}`,
        filename: filename || 'suspicious_sample.eml',
        subject: report.email?.subject || 'Unknown Subject',
        from: report.email?.from_email || report.headers?.sender_email || 'Unknown',
        risk_score: report.risk_score ?? 0,
        verdict: report.verdict || 'UNKNOWN',
        analyzed_at: new Date().toISOString(),
        report,
      };

      setHistory((prev) => {
        const updated = [record, ...prev.filter((item) => item.id !== record.id)].slice(0, 50);
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
        return updated;
      });
    } catch (err) {
      console.warn('Failed to save to local history:', err);
    }
  };

  /**
   * Upload and execute investigation pipeline on the backend
   */
  const startAnalysis = async (file, options = {}) => {
    if (!file) return null;

    setStatus('uploading');
    setError(null);
    setData(null);
    setJobStages([]);
    setActiveFile({ name: file.name, size: file.size, lastModified: file.lastModified });
    setUploadProgress(0);

    try {
      const job = await startAnalysisJob(file, undefined, options);
      setJobStages(job.stages || []);
      setStatus('analyzing');
      // Follow live stage progress until the backend finishes the job.
      let current = job;
      let failures = 0;
      while (current.status === 'running') {
        await new Promise((resolve) => setTimeout(resolve, 600));
        try {
          current = await getAnalysisJob(job.job_id);
          failures = 0;
          setJobStages(current.stages || []);
        } catch (pollErr) {
          failures += 1;
          if (failures >= 5) throw pollErr;
        }
      }
      if (current.status !== 'done' || !current.report) {
        throw Object.assign(new Error(current.error || 'Analysis failed.'), { jobError: true });
      }
      setData(current.report);
      setStatus('success');
      if (current.report.email_id) sourceFiles.current.set(current.report.email_id, file);
      persistInvestigation(current.report, file.name);
      return current.report;
    } catch (err) {
      console.error('Analysis failed:', err);
      setStatus('error');
      let message = err.jobError ? err.message : err.response?.data?.detail;
      if (!message) {
        if (err.message === 'Network Error' || !err.response || err.response?.status === 502) {
          message = 'Unable to reach the analysis engine. The cloud service may be waking up (about 30-50 seconds on the free tier). Please retry in a moment.';
        } else {
          message = err.message || 'Failed to connect to the analysis engine.';
        }
      }
      setError(message);
      return null;
    }
  };

  /**
   * Load predefined sample report (for rapid evaluation & UI demonstrations)
   */
  const loadDemoSample = (sample = SAMPLE_REPORT) => {
    setStatus('success');
    setError(null);
    setActiveFile({
      name: 'sample_phishing_payroll.eml',
      size: 42104,
      lastModified: Date.now(),
    });
    setData(sample);
    persistInvestigation(sample, 'sample_phishing_payroll.eml');
  };

  /**
   * Load report from history record or ID
   */
  const loadFromHistory = async (record) => {
    const id = typeof record === 'string' ? record : record.id;
    if (!id) return;

    setStatus('uploading');
    
    try {
      let reportToLoad = null;

      // 1. Check if it's already a full report object (like Demo Sample)
      if (typeof record === 'object' && record.report) {
        reportToLoad = record.report;
      } else {
        // Revalidate retention and deletion on every stored report open.
        reportToLoad = await fetchInvestigation(id);
        persistInvestigation(reportToLoad, 'Network Ingest');
      }

      if (reportToLoad) {
        setData(reportToLoad);
        setActiveFile({
          name: reportToLoad.email?.subject || 'Network Ingest',
          size: 0,
          lastModified: Date.now(),
        });
        setStatus('success');
        setError(null);
      }
    } catch (err) {
      console.error('Failed to load investigation:', err);
      setStatus('error');
      setError('Failed to fetch full investigation report from backend.');
    }
  };

  /**
   * Reset context to upload state
   */
  const resetInvestigation = () => {
    setStatus('idle');
    setData(null);
    setError(null);
    setActiveFile(null);
    setUploadProgress(0);
    setJobStages([]);
    setResetToken((n) => n + 1);
  };

  const getSourceFile = useCallback((emailId) => (emailId ? sourceFiles.current.get(emailId) || null : null), []);
  /** Ask the Analyze page to run this file again (it shows the live timeline). */
  const requestReanalysis = useCallback((file) => { if (file) setRerunRequest({ file, at: Date.now() }); }, []);
  const consumeRerunRequest = useCallback(() => setRerunRequest(null), []);

  const clearHistory = () => {
    sessionStorage.removeItem(STORAGE_KEY);
    setHistory([]);
  };

  return (
    <InvestigationContext.Provider
      value={{
        status,
        data,
        error,
        activeFile,
        uploadProgress,
        jobStages,
        resetToken,
        getSourceFile,
        rerunRequest,
        requestReanalysis,
        consumeRerunRequest,
        backendOnline,
        lastHealthCheck,
        history,
        startAnalysis,
        loadDemoSample,
        loadFromHistory,
        resetInvestigation,
        clearHistory,
        setData,
        setStatus,
        setError,
        setActiveFile,
        persistInvestigation,
      }}
    >
      {children}
    </InvestigationContext.Provider>
  );
}

export function useInvestigation() {
  const ctx = useContext(InvestigationContext);
  if (!ctx) {
    throw new Error('useInvestigation must be used within an InvestigationProvider');
  }
  return ctx;
}
