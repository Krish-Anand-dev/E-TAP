export const ACTIVE_SANDBOX_STATUSES = new Set([
  'queued', 'starting', 'interacting', 'collecting', 'evaluating', 'restoring', 'pending', 'submitted',
]);
export const TERMINAL_SANDBOX_STATUSES = new Set(['done', 'partial', 'error']);

/** Modes that actually open attachments (agent: the user's paired sandbox). */
export const SANDBOX_RUN_MODES = new Set(['agent', 'virtualbox', 'replay']);

/** Where the attachments were opened, in plain words. */
export function sandboxPlace(sandbox) {
  if (sandbox?.mode === 'agent') return sandbox.agent?.vm_name ? `your sandbox (${sandbox.agent.vm_name})` : 'your sandbox';
  if (sandbox?.mode === 'replay') return 'a recorded sandbox trace';
  return 'the Windows 11 VM';
}

/**
 * Fold a polled report into the open one. Only sandbox-driven fields change
 * (the stored record does not keep the original body/HTML, so everything else
 * is preserved). A late response for another email is ignored.
 */
export function mergeSandboxReport(current, updated) {
  if (!current || current.email_id !== updated?.email_id || !updated.sandbox) return current;
  return {
    ...current,
    sandbox: updated.sandbox,
    risk_score: updated.risk_score ?? current.risk_score,
    verdict: updated.verdict || current.verdict,
    verdict_band: updated.verdict_band || current.verdict_band,
    evidence_report: updated.evidence_report || current.evidence_report,
    share_card: updated.share_card ?? current.share_card,
    ai_analysis: { ...current.ai_analysis, ...updated.ai_analysis },
    mitre_attack: updated.mitre_attack ?? current.mitre_attack,
    stage_status: { ...current.stage_status, S: updated.sandbox.status },
  };
}

/**
 * True when the report only holds the short status returned by /analyze
 * (where `items`/`candidates` are counts) and the stored result should be fetched.
 */
export function needsSandboxRefresh(sandbox) {
  if (!sandbox || ['none', undefined].includes(sandbox.mode)) return false;
  if (ACTIVE_SANDBOX_STATUSES.has(sandbox.status)) return true;
  return TERMINAL_SANDBOX_STATUSES.has(sandbox.status) && !Array.isArray(sandbox.items);
}

/** The steps of a run, in the order the agent reports them, in plain words. */
export const SANDBOX_STEPS = [
  { key: 'starting', title: 'Opening the virtual machine', detail: 'Restoring a clean snapshot and starting it.' },
  { key: 'interacting', title: 'Opening the attachment', detail: 'Launching the file inside the VM, away from your PC.' },
  { key: 'collecting', title: 'Recording what it does', detail: 'Collecting Sysmon activity and Windows Defender events.' },
  { key: 'restoring', title: 'Cleaning up', detail: 'Putting the VM back to its clean snapshot.' },
  { key: 'evaluating', title: 'Checking the behaviour', detail: 'Matching what happened against detection rules.' },
];

/**
 * Where a run is right now. `waiting` is true until the agent has picked the job up;
 * each step is `done`, `active` or `pending`.
 */
export function sandboxProgress(status) {
  const at = SANDBOX_STEPS.findIndex((step) => step.key === status);
  return {
    waiting: at < 0,
    steps: SANDBOX_STEPS.map((step, i) => ({ ...step, state: at < 0 ? 'pending' : i < at ? 'done' : i === at ? 'active' : 'pending' })),
  };
}

/** Plain-language summary of a sandbox result for timelines and cards. */
export function sandboxSummary(sandbox) {
  const s = sandbox || {};
  const items = Array.isArray(s.items) ? s.items : [];
  const matches = items.reduce((n, i) => n + (i.matches || []).length, 0);
  const blocked = items.filter((i) => i.verdict === 'blocked_by_security_control').length;
  const observed = items.filter((i) => i.verdict === 'behavior_observed').length;
  return { status: s.status || 'unknown', mode: s.mode || 'none', items: items.length, matches, blocked, observed };
}

/**
 * Headline for the VM status tile: what the run means for the user.
 * A job whose every file could not be opened is "Not tested" (amber), not a crash.
 */
export function sandboxOutcome(sandbox) {
  const s = sandbox || {};
  const items = Array.isArray(s.items) ? s.items : [];
  const matches = items.reduce((n, i) => n + (i.matches || []).length, 0);
  const blocked = items.some((i) => i.verdict === 'blocked_by_security_control');
  const allIncomplete = items.length > 0 && items.every((i) => ['inspection_incomplete', 'error'].includes(i.verdict));
  if (s.status === 'queued' && s.mode === 'agent') return { label: 'Waiting', tone: 'warn', note: 'Waiting for your sandbox to pick this up. Keep the E-TAP Sandbox Agent running.' };
  if (ACTIVE_SANDBOX_STATUSES.has(s.status)) return { label: 'Running', tone: 'warn', note: `Attachments are being opened in ${sandboxPlace(s)}.` };
  if (matches || blocked) return { label: 'Threat seen', tone: 'bad', note: 'Malicious behaviour was observed in the VM.' };
  if (allIncomplete && !s.error) {
    const reason = items.map((i) => i.launch_error || i.note).find(Boolean);
    return { label: 'Not tested', tone: 'warn', note: reason || 'The attachment could not be opened in the VM.' };
  }
  if (s.status === 'error') return { label: 'Failed', tone: 'bad', note: s.error || 'The sandbox run failed.' };
  if (s.status === 'partial') return { label: 'Partly tested', tone: 'warn', note: 'Some attachments could not be opened.' };
  if (s.status === 'done') return { label: 'Nothing seen', tone: 'ok', note: 'No malicious behaviour observed (inconclusive, not proof of safety).' };
  return { label: String(s.status || 'unknown').replace(/_/g, ' '), tone: 'muted', note: s.message || '' };
}
