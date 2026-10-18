import test from 'node:test';
import assert from 'node:assert/strict';
import { capabilitiesFromSpec } from '../src/utils/backendCapabilities.js';
import { ACTIVE_SANDBOX_STATUSES, TERMINAL_SANDBOX_STATUSES, mergeSandboxReport } from '../src/utils/sandbox.js';

test('sandbox polling preserves original email content and unrelated forensic evidence', () => {
  const original = {
    email_id: 'local-email',
    email: { body_text: 'original body', body_html: '<p>original HTML</p>' },
    attachments: [{ filename: 'invoice.zip' }],
    headers: { spf: 'fail' },
    ai_analysis: { content_classification: { provider: 'gemini' } },
    stage_status: { A: 'complete', S: 'queued' },
  };
  const updated = {
    email_id: 'local-email', email: { subject: 'stored envelope only' },
    sandbox: { status: 'done', items: [{ verdict: 'blocked_by_security_control' }] },
    risk_score: 95, verdict: 'Likely Malicious',
    ai_analysis: { final_assessment: { risk_score: 95 } },
    mitre_attack: [{ technique: 'T1059.007' }],
  };
  const merged = mergeSandboxReport(original, updated);
  assert.equal(merged.email.body_text, 'original body');
  assert.equal(merged.email.body_html, '<p>original HTML</p>');
  assert.equal(merged.attachments, original.attachments);
  assert.equal(merged.headers, original.headers);
  assert.equal(merged.ai_analysis.content_classification.provider, 'gemini');
  assert.equal(merged.risk_score, 95);
  assert.equal(merged.sandbox.items[0].verdict, 'blocked_by_security_control');
  assert.deepEqual(merged.stage_status, { A: 'complete', S: 'done' });
  assert.equal(original.stage_status.S, 'queued');
});

test('late polling responses cannot overwrite a different investigation', () => {
  const current = { email_id: 'new-email' };
  assert.equal(mergeSandboxReport(current, { email_id: 'old-email', sandbox: { status: 'done' } }), current);
  assert.equal(mergeSandboxReport(current, { email_id: 'new-email' }), current);
});

test('polling continues through VM restoration and stops at terminal outcomes', () => {
  for (const phase of ['queued', 'starting', 'interacting', 'collecting', 'evaluating', 'restoring']) {
    assert.ok(ACTIVE_SANDBOX_STATUSES.has(phase));
    assert.ok(!TERMINAL_SANDBOX_STATUSES.has(phase));
  }
  for (const phase of ['done', 'partial', 'error']) {
    assert.ok(!ACTIVE_SANDBOX_STATUSES.has(phase));
    assert.ok(TERMINAL_SANDBOX_STATUSES.has(phase));
  }
});

test('local API does not advertise unsupported hosted actions', () => {
  const capabilities = capabilitiesFromSpec({ paths: {
    '/health': { get: {} }, '/analyze': { post: {} }, '/chat': { post: {} },
    '/investigations/{email_id}': { get: {} }, '/sandbox/{email_id}': { get: {} },
  } });
  assert.deepEqual(capabilities, { storedReports: false, workspace: false, workflow: false, retention: false });
});

test('hosted controls require the full set of routes they use', () => {
  const paths = {
    '/analytics': { get: {} }, '/baselines': { get: {}, put: {} },
    '/investigations': { get: {}, delete: {} },
    '/investigations/{id}': { get: {}, delete: {} },
    '/preferences': { put: {} }, '/investigations/{id}/share': { get: {} },
  };
  assert.deepEqual(capabilitiesFromSpec({ paths }), { storedReports: true, workspace: true, workflow: false, retention: true });
  delete paths['/baselines'].put;
  assert.equal(capabilitiesFromSpec({ paths }).workspace, false);
});
