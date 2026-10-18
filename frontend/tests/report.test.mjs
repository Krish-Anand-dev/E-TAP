import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePdfDocument } from '../src/utils/pdfGenerator.js';
import { plainSummary } from '../src/utils/plainSummary.js';

export const syntheticReport = {
  email_id:'synthetic-report', verdict:'SUSPICIOUS', verdict_band:'caution', risk_score:50,
  email:{subject:'Synthetic <script>alert(1)</script>',from_email:'sender@example.test'},
  evidence_report:{schema_version:2,evidence:[{id:'header.spf',source:'parser',source_type:'static',kind:'observed',provenance_type:'observed',confidence:'not_calibrated',raw_observation:'<script>alert(1)</script>',normalized_explanation:'Untrusted text is printed as evidence.',supports:[],contradicts:[]}]},
};
test('PDF renders ledger text without executable PDF actions', () => {
  const doc=generatePdfDocument(syntheticReport);
  const pdf=doc.output();
  assert.ok(pdf.startsWith('%PDF-'));
  assert.ok(pdf.includes('Evidence Ledger v2'));
  assert.ok(pdf.includes('header.spf'));
  assert.ok(!pdf.includes('/JavaScript'));
  assert.ok(!pdf.includes('/Launch'));
  assert.ok(!pdf.includes('aligned with From address'));
  assert.ok(pdf.includes('UNAVAILABLE'));
});
test('fixed summaries translate explanations without mutating verdict/evidence', () => {
  const before=JSON.stringify(syntheticReport);
  for (const language of ['en','es','hi']) assert.ok(plainSummary('caution',language).length>20);
  assert.equal(JSON.stringify(syntheticReport),before);
  assert.equal(plainSummary('invalid','unknown'),plainSummary('caution','en'));
});

test('PDF retains local sandbox findings and Defender evidence', () => {
  const report = { ...syntheticReport, sandbox: {
    mode: 'virtualbox', status: 'done', job_id: 'job_test', coverage: { rules_loaded: 36 },
    items: [{ filename: 'invoice.zip / invoice.js', verdict: 'blocked_by_security_control', event_count: 13,
      matches: [{ rule_id: 'etap-004', rule: 'Script host observed' }] }],
    security_events: [{ event_id: 1116, message: 'Defender blocked certutil' }],
  } };
  const pdf = generatePdfDocument(report).output();
  for (const evidence of ['Sandbox Analysis', 'job_test', 'invoice.zip', 'etap-004', 'Defender blocked certutil']) {
    assert.ok(pdf.includes(evidence), evidence);
  }
  assert.ok(!pdf.includes('/JavaScript'));
  assert.ok(!pdf.includes('/Launch'));
});
