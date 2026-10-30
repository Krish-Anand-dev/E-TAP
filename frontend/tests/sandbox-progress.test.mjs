import test from 'node:test';
import assert from 'node:assert/strict';
import { SANDBOX_STEPS, sandboxProgress } from '../src/utils/sandbox.js';

const states = (status) => sandboxProgress(status).steps.map((s) => s.state);

test('a queued job is waiting and no step has started', () => {
  const p = sandboxProgress('queued');
  assert.equal(p.waiting, true);
  assert.deepEqual(states('queued'), ['pending', 'pending', 'pending', 'pending', 'pending']);
});

test('each agent status marks earlier steps done and itself active', () => {
  assert.deepEqual(states('starting'), ['active', 'pending', 'pending', 'pending', 'pending']);
  assert.deepEqual(states('collecting'), ['done', 'done', 'active', 'pending', 'pending']);
  assert.deepEqual(states('evaluating'), ['done', 'done', 'done', 'done', 'active']);
  assert.equal(sandboxProgress('collecting').waiting, false);
});

test('every status the agent reports has a step, in the order the runner sends them', () => {
  assert.deepEqual(SANDBOX_STEPS.slice(0, 4).map((s) => s.key), ['starting', 'interacting', 'collecting', 'restoring']);
  assert.ok(SANDBOX_STEPS.every((s) => s.title && s.detail));
});
