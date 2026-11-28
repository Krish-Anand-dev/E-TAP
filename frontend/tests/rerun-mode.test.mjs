import test from 'node:test';
import assert from 'node:assert/strict';
import { wasDeepRun } from '../src/utils/sandbox.js';

test('a report from a deeper analysis is re-analyzed deeply', () => {
  for (const status of ['queued', 'interacting', 'done', 'partial', 'error']) {
    assert.equal(wasDeepRun({ sandbox: { status, mode: 'agent' } }), true, status);
  }
});

test('a standard report stays standard', () => {
  assert.equal(wasDeepRun(null), false);
  assert.equal(wasDeepRun({}), false);
  for (const status of ['not_requested', 'not_applicable', 'unavailable']) {
    assert.equal(wasDeepRun({ sandbox: { status, mode: 'agent' } }), false, status);
  }
});
