export const ACTIVE_SANDBOX_STATUSES = new Set([
  'queued', 'starting', 'interacting', 'collecting', 'evaluating', 'restoring', 'pending', 'submitted',
]);
export const TERMINAL_SANDBOX_STATUSES = new Set(['done', 'partial', 'error']);

export function mergeSandboxReport(current, updated) {
  if (!current || current.email_id !== updated?.email_id || !updated.sandbox) return current;
  return {
    ...current,
    sandbox: updated.sandbox,
    risk_score: updated.risk_score ?? current.risk_score,
    verdict: updated.verdict || current.verdict,
    ai_analysis: { ...current.ai_analysis, ...updated.ai_analysis },
    mitre_attack: updated.mitre_attack ?? current.mitre_attack,
    stage_status: { ...current.stage_status, S: updated.sandbox.status },
  };
}
