/**
 * Turns a backend report into the plain-language pieces the UI shows:
 * risk categories ("Header issues", "Attachment issues", ...), headline
 * numbers, and one summary per pipeline stage. Pure functions; no fetching.
 *
 * Source of truth is `evidence_report.evidence` (backend/evidence.py). Older
 * stored reports without it fall back to the raw stage fields.
 */
import { bandFor, displayLabel } from './verdict.js';
import { SANDBOX_RUN_MODES, sandboxPlace } from './sandbox.js';

export const CATEGORY_META = {
  headers: { label: 'Header issues', title: 'Sender & headers', icon: 'mail' },
  attachments: { label: 'Attachment issues', title: 'Attachments', icon: 'paperclip' },
  links: { label: 'Suspicious links', title: 'Links', icon: 'link' },
  reputation: { label: 'Bad reputation', title: 'Reputation', icon: 'globe' },
  history: { label: 'Seen before', title: 'Past emails', icon: 'history' },
  content: { label: 'Suspicious wording', title: 'Message content', icon: 'message' },
  sandbox: { label: 'Malicious behaviour', title: 'Sandbox behaviour', icon: 'box' },
};
export const CATEGORY_ORDER = ['headers', 'attachments', 'links', 'reputation', 'history', 'content'];

export function categoryOf(id = '') {
  if (id.startsWith('hdr.')) return 'headers';
  if (id.startsWith('att.') || id.startsWith('qr.')) return 'attachments';
  if (id.startsWith('link.')) return 'links';
  if (id.startsWith('rep.')) return 'reputation';
  if (id.startsWith('corr.')) return 'history';
  if (id.startsWith('ai.content') || id.startsWith('ai.finding')) return 'content';
  return null;
}

const humanize = (code = '') =>
  String(code).replace(/_/g, ' ').replace(/\s+/g, ' ').trim().replace(/^./, (c) => c.toUpperCase());

function fallbackItems(report) {
  const items = [];
  const push = (cat, title, weight = 'weak', why = '') =>
    items.push({ id: `${cat}.${items.length}`, category: cat, title, weight, why, status: 'present', direction: 'raises_risk', kind: 'observed' });
  const headers = report.headers || {};
  (headers.red_flags || []).forEach((f) => push('headers', humanize(f), /fail|lookalike|homograph|claims/.test(f) ? 'strong' : 'weak'));
  (report.attachments || []).filter((a) => a.suspicious).forEach((a) =>
    push('attachments', `${a.filename || 'Attachment'} looks dangerous`, 'strong', (a.flags || []).join('; ')));
  const ti = report.threat_intel || {};
  ['ip_reputation', 'domain_info', 'url_reputation', 'hash_reputation'].forEach((sec) =>
    Object.entries(ti[sec] || {}).forEach(([k, v]) => v && v.malicious === true && push('reputation', `${k} is flagged as malicious`, 'strong')));
  const related = (report.correlation || {}).related_emails || [];
  if (related.length) push('history', `Shares infrastructure with ${related.length} earlier email(s)`, 'weak');
  const reasons = ((report.ai_analysis || {}).content_classification || {}).reasons || [];
  reasons.slice(0, 4).forEach((r) => push('content', r, 'weak'));
  return items;
}

/** True when attachments were (or are being) opened in a sandbox for this report. */
export function hasSandbox(report = {}) {
  const sb = report.sandbox;
  return Boolean(sb) && SANDBOX_RUN_MODES.has(sb.mode) && !['not_requested', 'unavailable'].includes(sb.status);
}

/** What the VirtualBox sandbox observed, as evidence items (category "sandbox"). */
export function sandboxItems(report = {}) {
  if (!hasSandbox(report)) return [];
  const items = [];
  (Array.isArray(report.sandbox.items) ? report.sandbox.items : []).forEach((it, n) => {
    const file = it.filename || 'attachment';
    (it.matches || []).forEach((m, k) => items.push({
      id: `sbx.${n}.${k}`, cat: 'sandbox', kind: 'observed', status: 'present', direction: 'raises_risk',
      weight: m.prevention_grade ? 'strong' : 'weak',
      title: m.rule || m.rule_id || 'Detection rule matched',
      why: `Seen when ${file} was opened in ${sandboxPlace(report.sandbox)}${(m.mitre || []).length ? ` (MITRE ${m.mitre.map((t) => t.technique).filter(Boolean).join(', ')})` : ''}.`,
    }));
    if (it.verdict === 'blocked_by_security_control') items.push({
      id: `sbx.${n}.blocked`, cat: 'sandbox', kind: 'observed', status: 'present', direction: 'raises_risk', weight: 'strong',
      title: `Windows Defender blocked ${file}`,
      why: it.note || 'Windows security stopped this attachment from running inside the VM.',
    });
    if (['inspection_incomplete', 'error'].includes(it.verdict)) items.push({
      id: `sbx.${n}.incomplete`, cat: 'sandbox', kind: 'observed', status: 'unavailable', direction: 'neutral', weight: 'weak',
      title: `${file} could not be fully tested`, why: it.note || it.launch_error || '',
    });
  });
  return items;
}

/** Evidence items, normalised so every one has a `cat`. */
export function evidenceItems(report = {}) {
  const raw = report.evidence_report?.evidence;
  const items = Array.isArray(raw) && raw.length ? raw : fallbackItems(report);
  return items.map((it) => ({ ...it, cat: it.cat || categoryOf(it.id) || it.category }))
    .concat(sandboxItems(report))
    .filter((it) => CATEGORY_META[it.cat]);
}

/** One entry per category with what raised risk, what lowered it, and what was not checked. */
export function riskCategories(report = {}) {
  const items = evidenceItems(report);
  const order = hasSandbox(report) ? [...CATEGORY_ORDER, 'sandbox'] : CATEGORY_ORDER;
  return order.map((key) => {
    const mine = items.filter((it) => it.cat === key);
    const raises = mine.filter((it) => it.status === 'present' && it.direction === 'raises_risk' && it.grounding !== 'ungrounded');
    raises.sort((a, b) => (a.weight === 'strong' ? 0 : 1) - (b.weight === 'strong' ? 0 : 1));
    return {
      key,
      ...CATEGORY_META[key],
      raises,
      lowers: mine.filter((it) => it.status === 'present' && it.direction === 'lowers_risk'),
      unavailable: mine.filter((it) => it.status === 'unavailable'),
      strong: raises.filter((it) => it.weight === 'strong').length,
      count: raises.length,
      severity: raises.some((it) => it.weight === 'strong') ? 'high' : raises.length ? 'medium' : 'none',
    };
  });
}

/** Categories that actually raised risk, most serious first (for the "why" tags). */
export function riskTags(report = {}) {
  return riskCategories(report)
    .filter((c) => c.count > 0)
    .sort((a, b) => b.strong - a.strong || b.count - a.count);
}

const sectionValues = (obj) => Object.values(obj || {}).filter((v) => v && typeof v === 'object');

/** Headline numbers for the report. */
export function keyStats(report = {}) {
  const headers = report.headers || {};
  const attachments = report.attachments || [];
  const iocs = report.iocs || {};
  const links = report.link_analysis?.summary || {};
  const ti = report.threat_intel || {};
  const lookups = ['ip_reputation', 'domain_info', 'url_reputation', 'hash_reputation'].flatMap((s) => sectionValues(ti[s]));
  const checked = lookups.filter((v) => ['available', 'not_found'].includes(v.status) || v.malicious != null);
  const corr = report.correlation || {};
  const hist = report.historical_correlation || corr.historical_stats || {};
  return {
    headerFlags: (headers.red_flags || []).length,
    auth: { spf: headers.spf, dkim: headers.dkim, dmarc: headers.dmarc },
    headersAvailable: headers.available !== false,
    attachments: attachments.length,
    suspiciousAttachments: attachments.filter((a) => a.suspicious).length,
    macros: attachments.filter((a) => a.has_macro).length,
    qrCodes: attachments.reduce((n, a) => n + (a.qr_urls || []).length, 0),
    links: Math.max(links.total || 0, (iocs.urls || []).length),
    flaggedLinks: links.with_flags ?? 0,
    mismatchedLinks: links.text_mismatch ?? 0,
    indicators: ['ips', 'domains', 'urls', 'hashes'].reduce((n, k) => n + (iocs[k] || []).length, 0),
    indicatorBreakdown: { IPs: (iocs.ips || []).length, Domains: (iocs.domains || []).length, URLs: (iocs.urls || []).length, Hashes: (iocs.hashes || []).length },
    reputationLive: ti.lookup_mode === 'live',
    reputationChecked: checked.length,
    reputationFlagged: lookups.filter((v) => v.malicious === true).length,
    relatedEmails: (corr.related_emails || []).length,
    campaignId: corr.campaign_id || null,
    recurring: hist.category_status === 'RECURRING_ADVERSARY_ACTIVITY',
    mitre: (report.mitre_attack || report.ai_analysis?.final_assessment?.mitre_attack || []).length,
  };
}

export function verdictOf(report = {}) {
  const score = Math.round(Number(report.risk_score) || 0);
  return {
    score,
    label: displayLabel(report.verdict, score),
    band: bandFor({ verdictBand: report.verdict_band, verdict: report.verdict, riskScore: score }),
  };
}

const authText = (v) => (v ? String(v).replace(/_/g, ' ') : 'n/a');
const isPass = (v) => String(v || '').toLowerCase() === 'pass';

const SANDBOX_RUNNING = new Set(['queued', 'starting', 'interacting', 'collecting', 'evaluating', 'restoring', 'pending', 'submitted']);

function sandboxStage(report, s) {
  const sb = report.sandbox || {};
  const items = Array.isArray(sb.items) ? sb.items : [];
  const matches = items.reduce((n, i) => n + (i.matches || []).length, 0);
  const blocked = items.filter((i) => i.verdict === 'blocked_by_security_control').length;
  const base = { key: 'sandbox', title: 'Dynamic attachment analysis', icon: 'box' };
  const metrics = [['Files opened', items.length], ['Rules matched', matches], ['Blocked by Defender', blocked]];
  if (!hasSandbox(report)) {
    // A standard analysis has nothing to say here unless attachments were left unopened.
    if (!s.attachments || sb.status === 'not_applicable') return null;
    return { ...base, status: 'not_run', metrics: [],
      summary: 'Standard analysis: the attachments were inspected without being opened.' };
  }
  if (sb.status === 'not_applicable') return { ...base, status: 'skipped', metrics: [], summary: 'No attachment type that needs dynamic analysis.' };
  if (sb.status === 'queued' && sb.mode === 'agent') return { ...base, status: 'warn', metrics, summary: 'Waiting for your sandbox to pick up the attachments.' };
  if (SANDBOX_RUNNING.has(sb.status)) return { ...base, status: 'warn', metrics, summary: `Running in ${sandboxPlace(sb)} (${sb.status}).` };
  if (items.length && items.every((i) => ['inspection_incomplete', 'error'].includes(i.verdict)) && !matches && !blocked && !sb.error) {
    const reason = items.map((i) => i.launch_error || i.note).find(Boolean);
    return { ...base, status: 'skipped', metrics, summary: `Could not be opened in the VM${reason ? ` (${reason})` : ''}; not tested.` };
  }
  return {
    ...base, metrics,
    status: matches || blocked ? 'bad' : sb.status === 'error' ? 'warn' : 'good',
    summary: matches || blocked
      ? `Malicious behaviour seen in ${sandboxPlace(sb)}: ${matches} rule match(es)${blocked ? `, ${blocked} blocked by Windows Defender` : ''}.`
      : sb.status === 'error' ? 'The sandbox run did not complete; see the report for details.'
        : `Opened in ${sandboxPlace(sb)} with no malicious behaviour observed (inconclusive, not proof of safety).`,
  };
}

/**
 * One summary per pipeline stage, in pipeline order. `status`:
 * good | warn | bad | skipped | not_run.
 */
export function stageSummaries(report = {}) {
  const s = keyStats(report);
  const email = report.email || {};
  const ai = report.ai_analysis || {};
  const content = ai.content_classification || {};
  const fa = ai.final_assessment || {};
  const provider = report.analysis_provenance?.assessment_provider || fa.provider;
  const v = verdictOf(report);
  const authFails = ['spf', 'dkim', 'dmarc'].filter((k) => ['fail', 'softfail', 'misaligned', 'key_not_found'].includes(String(s.auth[k] || '').toLowerCase()));

  return [
    {
      key: 'parse', title: 'Reading the email', icon: 'mail', status: 'good',
      summary: `“${email.subject || '(no subject)'}” from ${email.from_email || 'an unknown sender'}`,
      metrics: [['Format', String(email.source_format || 'eml').toUpperCase()], ['Attachments', s.attachments]],
    },
    {
      key: 'headers', title: 'Sender & headers', icon: 'user',
      status: !s.headersAvailable ? 'skipped' : authFails.length ? 'bad' : s.headerFlags ? 'warn' : 'good',
      summary: !s.headersAvailable ? 'Original headers were not available, so the sender could not be verified.'
        : authFails.length ? `Sender authentication failed (${authFails.map((k) => k.toUpperCase()).join(', ')}).`
          : s.headerFlags ? `${s.headerFlags} warning sign(s) in the sender details.` : 'Sender checks passed with no warning signs.',
      metrics: [['SPF', authText(s.auth.spf)], ['DKIM', authText(s.auth.dkim)], ['DMARC', authText(s.auth.dmarc)], ['Red flags', s.headerFlags]],
      good: ['spf', 'dkim', 'dmarc'].filter((k) => isPass(s.auth[k])).length,
    },
    {
      key: 'static_attachments', title: 'Static attachment analysis', icon: 'paperclip',
      status: !s.attachments ? 'skipped' : s.suspiciousAttachments ? 'bad' : 'good',
      summary: !s.attachments ? 'No attachments in this email.'
        : s.suspiciousAttachments ? `${s.suspiciousAttachments} of ${s.attachments} attachment(s) look dangerous.` : `${s.attachments} attachment(s) checked, none look dangerous.`,
      metrics: [['Files', s.attachments], ['Suspicious', s.suspiciousAttachments], ['Macros', s.macros], ['QR codes', s.qrCodes]],
    },
    sandboxStage(report, s),
    {
      key: 'indicators', title: 'Links & indicators', icon: 'link',
      status: s.mismatchedLinks || s.flaggedLinks > 2 ? 'bad' : s.flaggedLinks ? 'warn' : 'good',
      summary: `${s.links ? `${s.links} link(s) found${s.flaggedLinks ? `, ${s.flaggedLinks} with warning signs` : ', none suspicious'}` : 'No links found'}; ${s.indicators} indicator(s) extracted in total.`,
      metrics: [['Links', s.links], ['Flagged', s.flaggedLinks], ...Object.entries(s.indicatorBreakdown)],
    },
    {
      key: 'reputation', title: 'Threat reputation', icon: 'globe',
      status: !s.reputationLive ? 'skipped' : s.reputationFlagged ? 'bad' : 'good',
      summary: !s.reputationLive ? 'Reputation lookups were turned off for this analysis.'
        : s.reputationFlagged ? `${s.reputationFlagged} indicator(s) are known to be malicious.` : `${s.reputationChecked} indicator(s) checked, none known to be malicious.`,
      metrics: [['Checked', s.reputationChecked], ['Malicious', s.reputationFlagged]],
    },
    {
      key: 'history', title: 'Comparison with past emails', icon: 'history',
      status: s.recurring || s.relatedEmails ? 'warn' : 'good',
      summary: s.relatedEmails ? `Linked to ${s.relatedEmails} earlier email(s)${s.campaignId ? ` in ${s.campaignId}` : ''}.` : 'Not seen before.',
      metrics: [['Related emails', s.relatedEmails], ['Campaign', s.campaignId || 'new']],
    },
    {
      key: 'ai', title: 'AI threat assessment', icon: 'sparkle',
      status: provider === 'xgboost_triage' ? 'good' : bandFor({ verdict: content.verdict || content.content_verdict, riskScore: content.content_risk_score }) === 'safe' ? 'good' : 'warn',
      summary: provider === 'xgboost_triage' ? 'Metadata screening found it clearly benign; full AI review not needed.'
        : `${content.attack_type || content.verdict || 'Content reviewed'}${provider === 'offline_fallback' ? ' (offline assessment)' : ''}.`,
      metrics: [['Categories', (content.categories || []).length], ['MITRE techniques', s.mitre]],
    },
    {
      key: 'verdict', title: 'Final verdict', icon: 'shield',
      status: v.band === 'danger' ? 'bad' : v.band === 'caution' ? 'warn' : 'good',
      summary: `${v.label}, ${v.score}/100.`,
      metrics: [['Risk score', `${v.score}/100`]],
    },
  ].filter(Boolean);
}
