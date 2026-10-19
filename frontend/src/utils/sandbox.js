export const ACTIVE_SANDBOX_STATUSES = new Set([
  'queued', 'starting', 'interacting', 'collecting', 'evaluating', 'restoring', 'pending', 'submitted',
]);
export const TERMINAL_SANDBOX_STATUSES = new Set(['done', 'partial', 'error']);

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

/** Plain-language summary of a sandbox result for timelines and cards. */
export function sandboxSummary(sandbox) {
  const s = sandbox || {};
  const items = Array.isArray(s.items) ? s.items : [];
  const matches = items.reduce((n, i) => n + (i.matches || []).length, 0);
  const blocked = items.filter((i) => i.verdict === 'blocked_by_security_control').length;
  const observed = items.filter((i) => i.verdict === 'behavior_observed').length;
  return { status: s.status || 'unknown', mode: s.mode || 'none', items: items.length, matches, blocked, observed };
}
